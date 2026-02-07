use std::time::{SystemTime, UNIX_EPOCH};
use rusqlite::Connection;

use crate::crypto::{event_id_to_base64, event_id_from_base64, EventId};
use crate::events::{self, ParsedEvent, registry};
use super::decision::ProjectionDecision;
use super::encrypted::project_encrypted;
use super::projectors::{project_message, project_reaction, project_peer_key, project_secret_key, project_signed_memo};
use super::signer::{resolve_signer_key, verify_ed25519_signature, SignerResolution};

/// Record a rejected event durably so it is not re-processed on replay or cascade.
fn record_rejection(conn: &Connection, recorded_by: &str, event_id_b64: &str, reason: &str) {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let _ = conn.execute(
        "INSERT OR IGNORE INTO rejected_events (peer_id, event_id, reason, rejected_at)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![recorded_by, event_id_b64, reason, now_ms],
    );
}

/// Shared projection helper: verify signer (if required), dispatch to per-event
/// projector, return Valid or Reject. Caller is responsible for dep checks.
fn apply_projection(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    blob: &[u8],
    parsed: &ParsedEvent,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    let meta = registry().lookup(parsed.event_type_code())
        .ok_or_else(|| format!("unknown type code {}", parsed.event_type_code()))?;

    // Signer verification (if required)
    if meta.signer_required {
        let (signer_event_id, signer_type) = parsed.signer_fields()
            .ok_or("signer_required but no signer_fields")?;
        let resolution = resolve_signer_key(conn, recorded_by, signer_type, &signer_event_id)?;
        match resolution {
            SignerResolution::NotFound => {
                return Ok(ProjectionDecision::Reject {
                    reason: "signer key not found".to_string(),
                });
            }
            SignerResolution::Invalid(msg) => {
                return Ok(ProjectionDecision::Reject {
                    reason: format!("signer resolution invalid: {}", msg),
                });
            }
            SignerResolution::Found(key) => {
                let sig_len = meta.signature_byte_len;
                if blob.len() < sig_len {
                    return Ok(ProjectionDecision::Reject {
                        reason: "blob too short for signature".to_string(),
                    });
                }
                let signing_bytes = &blob[..blob.len() - sig_len];
                let sig_bytes = &blob[blob.len() - sig_len..];
                if !verify_ed25519_signature(&key, signing_bytes, sig_bytes) {
                    return Ok(ProjectionDecision::Reject {
                        reason: "invalid signature".to_string(),
                    });
                }
            }
        }
    }

    // Per-event projector dispatch
    match parsed {
        ParsedEvent::Message(msg) => {
            project_message(conn, recorded_by, event_id_b64, msg)?;
        }
        ParsedEvent::Reaction(rxn) => {
            project_reaction(conn, recorded_by, event_id_b64, rxn)?;
        }
        ParsedEvent::PeerKey(pk) => {
            project_peer_key(conn, recorded_by, event_id_b64, pk)?;
        }
        ParsedEvent::SignedMemo(memo) => {
            project_signed_memo(conn, recorded_by, event_id_b64, memo)?;
        }
        ParsedEvent::Encrypted(enc) => {
            return project_encrypted(conn, recorded_by, event_id_b64, enc);
        }
        ParsedEvent::SecretKey(sk) => {
            project_secret_key(conn, recorded_by, event_id_b64, sk)?;
        }
    }

    Ok(ProjectionDecision::Valid)
}

/// Central projection entrypoint. Given an event_id that is already stored in the
/// `events` table, parse it, check dependencies, project into terminal tables,
/// and cascade-unblock any dependents.
pub fn project_one(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    let event_id_b64 = event_id_to_base64(event_id);

    // 1. Check terminal state — already processed (valid)?
    let already: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &event_id_b64],
        |row| row.get(0),
    )?;
    if already {
        return Ok(ProjectionDecision::AlreadyProcessed);
    }

    // 1b. Check terminal state — already rejected?
    let already_rejected: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &event_id_b64],
        |row| row.get(0),
    )?;
    if already_rejected {
        return Ok(ProjectionDecision::AlreadyProcessed);
    }

    // 2. Load blob from events table
    let blob: Vec<u8> = match conn.query_row(
        "SELECT blob FROM events WHERE event_id = ?1",
        rusqlite::params![&event_id_b64],
        |row| row.get(0),
    ) {
        Ok(b) => b,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            let reason = format!("event {} not found in events table", event_id_b64);
            record_rejection(conn, recorded_by, &event_id_b64, &reason);
            return Ok(ProjectionDecision::Reject { reason });
        }
        Err(e) => return Err(e.into()),
    };

    // 3. Parse via registry
    let parsed = match events::parse_event(&blob) {
        Ok(p) => p,
        Err(e) => {
            let reason = format!("parse error: {}", e);
            record_rejection(conn, recorded_by, &event_id_b64, &reason);
            return Ok(ProjectionDecision::Reject { reason });
        }
    };

    // 4. Extract deps and check them
    let deps = parsed.dep_field_values();
    let mut missing = Vec::new();
    for (_field_name, dep_id) in &deps {
        let dep_b64 = event_id_to_base64(dep_id);
        let dep_valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &dep_b64],
            |row| row.get(0),
        )?;
        if !dep_valid {
            missing.push(*dep_id);
        }
    }

    // 5. If missing deps — write to blocked_event_deps
    if !missing.is_empty() {
        for dep_id in &missing {
            let dep_b64 = event_id_to_base64(dep_id);
            conn.execute(
                "INSERT OR IGNORE INTO blocked_event_deps (peer_id, event_id, blocker_event_id)
                 VALUES (?1, ?2, ?3)",
                rusqlite::params![recorded_by, &event_id_b64, &dep_b64],
            )?;
        }
        return Ok(ProjectionDecision::Block { missing });
    }

    // 6. Apply projection (signer verification + projector dispatch)
    let decision = apply_projection(conn, recorded_by, &event_id_b64, &blob, &parsed)?;
    match &decision {
        ProjectionDecision::Reject { ref reason } => {
            record_rejection(conn, recorded_by, &event_id_b64, reason);
            return Ok(decision);
        }
        ProjectionDecision::Block { .. } => {
            // Inner deps missing (encrypted events); don't mark valid
            return Ok(decision);
        }
        _ => {}
    }

    // 7. Write terminal state
    conn.execute(
        "INSERT OR IGNORE INTO valid_events (peer_id, event_id) VALUES (?1, ?2)",
        rusqlite::params![recorded_by, &event_id_b64],
    )?;

    // 8. Unblock dependents (iterative to avoid stack overflow)
    unblock_dependents(conn, recorded_by, &event_id_b64)?;

    Ok(ProjectionDecision::Valid)
}

/// After projecting an event, find and cascade-project any events that were
/// blocked waiting on it. Uses an iterative worklist to avoid stack overflow.
fn unblock_dependents(
    conn: &Connection,
    recorded_by: &str,
    blocker_b64: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut worklist = vec![blocker_b64.to_string()];

    while let Some(blocker) = worklist.pop() {
        // Remove all blocked_event_deps rows where this event was the blocker
        conn.execute(
            "DELETE FROM blocked_event_deps WHERE peer_id = ?1 AND blocker_event_id = ?2",
            rusqlite::params![recorded_by, &blocker],
        )?;

        // Find events that now have zero remaining blockers
        let mut stmt = conn.prepare(
            "SELECT DISTINCT e.event_id FROM events e
             WHERE e.event_id NOT IN (
                 SELECT event_id FROM blocked_event_deps WHERE peer_id = ?1
             )
             AND e.event_id NOT IN (
                 SELECT event_id FROM valid_events WHERE peer_id = ?1
             )
             AND e.event_id NOT IN (
                 SELECT event_id FROM rejected_events WHERE peer_id = ?1
             )
             AND e.event_id IN (
                 SELECT event_id FROM recorded_events WHERE peer_id = ?1
             )"
        )?;
        let unblocked: Vec<String> = stmt.query_map(
            rusqlite::params![recorded_by],
            |row| row.get::<_, String>(0),
        )?.collect::<Result<Vec<_>, _>>()?;

        for eid_b64 in unblocked {
            if event_id_from_base64(&eid_b64).is_some() {
                // Check not already valid
                let already: bool = conn.query_row(
                    "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                    rusqlite::params![recorded_by, &eid_b64],
                    |row| row.get(0),
                )?;
                if already {
                    continue;
                }

                let blob: Vec<u8> = conn.query_row(
                    "SELECT blob FROM events WHERE event_id = ?1",
                    rusqlite::params![&eid_b64],
                    |row| row.get(0),
                )?;

                match events::parse_event(&blob) {
                    Err(e) => {
                        let reason = format!("parse error: {}", e);
                        record_rejection(conn, recorded_by, &eid_b64, &reason);
                        continue;
                    }
                    Ok(parsed) => {
                    // Check deps are satisfied (should be, but verify)
                    let deps = parsed.dep_field_values();
                    let mut still_missing = false;
                    for (_field, dep_id) in &deps {
                        let dep_b64 = event_id_to_base64(dep_id);
                        let dep_valid: bool = conn.query_row(
                            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                            rusqlite::params![recorded_by, &dep_b64],
                            |row| row.get(0),
                        )?;
                        if !dep_valid {
                            still_missing = true;
                            break;
                        }
                    }
                    if still_missing {
                        continue;
                    }

                    // Apply projection (signer verification + projector dispatch)
                    let decision = apply_projection(conn, recorded_by, &eid_b64, &blob, &parsed)?;
                    match &decision {
                        ProjectionDecision::Reject { ref reason } => {
                            record_rejection(conn, recorded_by, &eid_b64, reason);
                            continue;
                        }
                        ProjectionDecision::Block { .. } => {
                            // Inner deps still missing; leave event blocked, don't cascade
                            continue;
                        }
                        _ => {}
                    }

                    conn.execute(
                        "INSERT OR IGNORE INTO valid_events (peer_id, event_id) VALUES (?1, ?2)",
                        rusqlite::params![recorded_by, &eid_b64],
                    )?;

                    // This newly projected event may unblock further events
                    worklist.push(eid_b64);
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_event;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::events::{self, MessageEvent, ReactionEvent, PeerKeyEvent, SecretKeyEvent, SignedMemoEvent, EncryptedEvent, ParsedEvent, EVENT_TYPE_MESSAGE, EVENT_TYPE_ENCRYPTED};
    use crate::projection::encrypted::encrypt_event_blob;
    use crate::projection::signer::sign_event_bytes;
    use ed25519_dalek::SigningKey;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    /// Insert a blob into events + neg_items + recorded_events (simulating what
    /// batch_writer or create_event_sync does before calling project_one).
    fn insert_event_raw(conn: &Connection, recorded_by: &str, blob: &[u8]) -> EventId {
        let event_id = hash_event(blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let ts = now_ms();
        let type_code = blob[0];
        let type_name = registry().lookup(type_code)
            .map(|m| m.type_name)
            .unwrap_or("unknown");

        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, 'shared', ?4, ?5)",
            rusqlite::params![&event_id_b64, type_name, blob, ts as i64, ts as i64],
        ).unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)",
            rusqlite::params![ts as i64, event_id.as_slice()],
        ).unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, 'test')",
            rusqlite::params![recorded_by, &event_id_b64, ts as i64],
        ).unwrap();

        event_id
    }

    fn make_message(content: &str) -> (ParsedEvent, Vec<u8>) {
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            channel_id: [1u8; 32],
            author_id: [2u8; 32],
            content: content.to_string(),
        });
        let blob = events::encode_event(&msg).unwrap();
        (msg, blob)
    }

    fn make_reaction(target: &EventId, emoji: &str) -> (ParsedEvent, Vec<u8>) {
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: *target,
            author_id: [3u8; 32],
            emoji: emoji.to_string(),
        });
        let blob = events::encode_event(&rxn).unwrap();
        (rxn, blob)
    }

    fn make_peer_key(public_key: [u8; 32]) -> (ParsedEvent, Vec<u8>) {
        let pk = ParsedEvent::PeerKey(PeerKeyEvent {
            created_at_ms: now_ms(),
            public_key,
        });
        let blob = events::encode_event(&pk).unwrap();
        (pk, blob)
    }

    fn make_signed_memo(signing_key: &SigningKey, signer_event_id: &EventId, content: &str) -> (ParsedEvent, Vec<u8>) {
        let memo = SignedMemoEvent {
            created_at_ms: now_ms(),
            signed_by: *signer_event_id,
            signer_type: 0,
            content: content.to_string(),
            signature: [0u8; 64], // placeholder
        };
        let event = ParsedEvent::SignedMemo(memo);
        let mut blob = events::encode_event(&event).unwrap();

        // Sign: signing_bytes = blob[..len-64], overwrite last 64 bytes
        let sig_len = 64;
        let blob_len = blob.len();
        let signing_bytes = &blob[..blob_len - sig_len];
        let sig = sign_event_bytes(signing_key, signing_bytes);
        blob[blob_len - sig_len..].copy_from_slice(&sig);

        // Re-parse to get the event with correct signature
        let parsed = events::parse_event(&blob).unwrap();
        (parsed, blob)
    }

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn test_project_message_valid() {
        let conn = setup();
        let recorded_by = "peer1";
        let (_msg, blob) = make_message("hello");
        let eid = insert_event_raw(&conn, recorded_by, &blob);

        let result = project_one(&conn, recorded_by, &eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Verify in messages table
        let eid_b64 = event_id_to_base64(&eid);
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&eid_b64, recorded_by],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);

        // Verify in valid_events
        let valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &eid_b64],
            |row| row.get(0),
        ).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_project_reaction_valid() {
        let conn = setup();
        let recorded_by = "peer1";

        // Create target message first
        let (_msg, msg_blob) = make_message("target");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        project_one(&conn, recorded_by, &msg_eid).unwrap();

        // Create reaction targeting it
        let (_rxn, rxn_blob) = make_reaction(&msg_eid, "\u{1f44d}");
        let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);

        let result = project_one(&conn, recorded_by, &rxn_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        let rxn_b64 = event_id_to_base64(&rxn_eid);
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM reactions WHERE event_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&rxn_b64, recorded_by],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_project_reaction_blocked() {
        let conn = setup();
        let recorded_by = "peer1";

        // Create reaction with a target that doesn't exist
        let fake_target = [99u8; 32];
        let (_rxn, rxn_blob) = make_reaction(&fake_target, "\u{1f44d}");
        let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);

        let result = project_one(&conn, recorded_by, &rxn_eid).unwrap();
        match result {
            ProjectionDecision::Block { missing } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], fake_target);
            }
            other => panic!("expected Block, got {:?}", other),
        }

        // Verify in blocked_event_deps
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);

        // Verify NOT in valid_events
        let rxn_b64 = event_id_to_base64(&rxn_eid);
        let valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn_b64],
            |row| row.get(0),
        ).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_project_unblock_cascade() {
        let conn = setup();
        let recorded_by = "peer1";

        // Create message blob but don't insert yet
        let (_msg, msg_blob) = make_message("target");
        let msg_eid = hash_event(&msg_blob);

        // Create reaction targeting it — insert reaction first (out of order)
        let (_rxn, rxn_blob) = make_reaction(&msg_eid, "\u{2764}\u{fe0f}");
        let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);

        // Project reaction — should block
        let result = project_one(&conn, recorded_by, &rxn_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));

        // Now insert and project the message
        let msg_eid2 = insert_event_raw(&conn, recorded_by, &msg_blob);
        assert_eq!(msg_eid, msg_eid2);
        let result = project_one(&conn, recorded_by, &msg_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Reaction should have been auto-unblocked
        let rxn_b64 = event_id_to_base64(&rxn_eid);
        let valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn_b64],
            |row| row.get(0),
        ).unwrap();
        assert!(valid, "reaction should be auto-projected after target arrives");

        // No remaining blocked deps
        let blocked: i64 = conn.query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(blocked, 0);
    }

    #[test]
    fn test_already_processed() {
        let conn = setup();
        let recorded_by = "peer1";
        let (_msg, blob) = make_message("hello");
        let eid = insert_event_raw(&conn, recorded_by, &blob);

        let r1 = project_one(&conn, recorded_by, &eid).unwrap();
        assert_eq!(r1, ProjectionDecision::Valid);

        let r2 = project_one(&conn, recorded_by, &eid).unwrap();
        assert_eq!(r2, ProjectionDecision::AlreadyProcessed);
    }

    #[test]
    fn test_multi_blocker() {
        let conn = setup();
        let recorded_by = "peer1";

        // Create two messages (targets)
        let (_msg1, msg1_blob) = make_message("target1");
        let msg1_eid = hash_event(&msg1_blob);
        let (_msg2, msg2_blob) = make_message("target2");
        let msg2_eid = hash_event(&msg2_blob);

        // Create reaction targeting msg1 — insert without msg1 in events
        let (_rxn1, rxn1_blob) = make_reaction(&msg1_eid, "\u{1f44d}");
        let rxn1_eid = insert_event_raw(&conn, recorded_by, &rxn1_blob);

        // Create reaction targeting msg2 — insert without msg2 in events
        let (_rxn2, rxn2_blob) = make_reaction(&msg2_eid, "\u{2764}\u{fe0f}");
        let rxn2_eid = insert_event_raw(&conn, recorded_by, &rxn2_blob);

        // Both should block
        assert!(matches!(project_one(&conn, recorded_by, &rxn1_eid).unwrap(), ProjectionDecision::Block { .. }));
        assert!(matches!(project_one(&conn, recorded_by, &rxn2_eid).unwrap(), ProjectionDecision::Block { .. }));

        // Insert msg1 — rxn1 unblocks, rxn2 stays blocked
        insert_event_raw(&conn, recorded_by, &msg1_blob);
        project_one(&conn, recorded_by, &msg1_eid).unwrap();

        let rxn1_b64 = event_id_to_base64(&rxn1_eid);
        let rxn2_b64 = event_id_to_base64(&rxn2_eid);
        let r1_valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn1_b64], |row| row.get(0),
        ).unwrap();
        assert!(r1_valid);

        let r2_valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn2_b64], |row| row.get(0),
        ).unwrap();
        assert!(!r2_valid);

        // Insert msg2 — rxn2 unblocks
        insert_event_raw(&conn, recorded_by, &msg2_blob);
        project_one(&conn, recorded_by, &msg2_eid).unwrap();

        let r2_valid2: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &rxn2_b64], |row| row.get(0),
        ).unwrap();
        assert!(r2_valid2);
    }

    #[test]
    fn test_project_peer_key_valid() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();

        let (_pk, blob) = make_peer_key(public_key);
        let eid = insert_event_raw(&conn, recorded_by, &blob);

        let result = project_one(&conn, recorded_by, &eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Verify in peer_keys table
        let eid_b64 = event_id_to_base64(&eid);
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM peer_keys WHERE event_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&eid_b64, recorded_by],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_project_signed_memo_valid() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();

        // First create and project the PeerKey event
        let (_pk, pk_blob) = make_peer_key(public_key);
        let pk_eid = insert_event_raw(&conn, recorded_by, &pk_blob);
        let pk_result = project_one(&conn, recorded_by, &pk_eid).unwrap();
        assert_eq!(pk_result, ProjectionDecision::Valid);

        // Now create a signed memo referencing the PeerKey
        let (_memo, memo_blob) = make_signed_memo(&signing_key, &pk_eid, "hello signed");
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        let result = project_one(&conn, recorded_by, &memo_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Verify in signed_memos table
        let memo_b64 = event_id_to_base64(&memo_eid);
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM signed_memos WHERE event_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&memo_b64, recorded_by],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_signed_memo_blocks_on_missing_signer() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);

        // Create a memo referencing a non-existent PeerKey
        let fake_signer_id = [99u8; 32];
        let (_memo, memo_blob) = make_signed_memo(&signing_key, &fake_signer_id, "blocked memo");
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        let result = project_one(&conn, recorded_by, &memo_eid).unwrap();
        match result {
            ProjectionDecision::Block { missing } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], fake_signer_id);
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_signed_memo_unblocks_when_signer_arrives() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();

        // Pre-compute the PeerKey event_id without inserting
        let (_pk, pk_blob) = make_peer_key(public_key);
        let pk_eid = hash_event(&pk_blob);

        // Create and insert signed memo (before signer arrives)
        let (_memo, memo_blob) = make_signed_memo(&signing_key, &pk_eid, "out of order");
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        // Project memo — should block on missing signer
        let result = project_one(&conn, recorded_by, &memo_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));

        // Now insert and project the signer PeerKey
        insert_event_raw(&conn, recorded_by, &pk_blob);
        let pk_result = project_one(&conn, recorded_by, &pk_eid).unwrap();
        assert_eq!(pk_result, ProjectionDecision::Valid);

        // Memo should have been auto-unblocked via cascade
        let memo_b64 = event_id_to_base64(&memo_eid);
        let valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &memo_b64],
            |row| row.get(0),
        ).unwrap();
        assert!(valid, "signed memo should be auto-projected after signer key arrives");

        // Verify in signed_memos table
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM signed_memos WHERE event_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&memo_b64, recorded_by],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_signed_memo_invalid_signature_rejects() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let wrong_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();

        // Create PeerKey with signing_key's public key
        let (_pk, pk_blob) = make_peer_key(public_key);
        let pk_eid = insert_event_raw(&conn, recorded_by, &pk_blob);
        project_one(&conn, recorded_by, &pk_eid).unwrap();

        // Sign the memo with the WRONG key
        let (_memo, memo_blob) = make_signed_memo(&wrong_key, &pk_eid, "bad signature");
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        let result = project_one(&conn, recorded_by, &memo_eid).unwrap();
        match result {
            ProjectionDecision::Reject { reason } => {
                assert!(reason.contains("invalid signature"), "reason: {}", reason);
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    #[test]
    fn test_unsigned_types_skip_signer_check() {
        // Regression: ensure Message and Reaction still project normally
        let conn = setup();
        let recorded_by = "peer1";

        let (_msg, msg_blob) = make_message("no signer needed");
        let msg_eid = insert_event_raw(&conn, recorded_by, &msg_blob);
        let r1 = project_one(&conn, recorded_by, &msg_eid).unwrap();
        assert_eq!(r1, ProjectionDecision::Valid);

        let (_rxn, rxn_blob) = make_reaction(&msg_eid, "\u{1f44d}");
        let rxn_eid = insert_event_raw(&conn, recorded_by, &rxn_blob);
        let r2 = project_one(&conn, recorded_by, &rxn_eid).unwrap();
        assert_eq!(r2, ProjectionDecision::Valid);
    }

    #[test]
    fn test_dep_global_existence_not_sufficient() {
        // A dep existing globally (for tenant_a) must NOT satisfy tenant_b's dep check
        let conn = setup();
        let tenant_a = "tenant_a";
        let tenant_b = "tenant_b";

        // Tenant A creates and projects a message
        let (_msg, msg_blob) = make_message("target for A");
        let msg_eid = insert_event_raw(&conn, tenant_a, &msg_blob);
        let r = project_one(&conn, tenant_a, &msg_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);

        // Tenant B creates a reaction targeting A's message
        let (_rxn, rxn_blob) = make_reaction(&msg_eid, "\u{1f44d}");
        let rxn_eid = insert_event_raw(&conn, tenant_b, &rxn_blob);

        // Tenant B projects the reaction — should BLOCK because the message is not
        // in valid_events for tenant_b, even though the blob exists in global events table
        let r2 = project_one(&conn, tenant_b, &rxn_eid).unwrap();
        match r2 {
            ProjectionDecision::Block { missing } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], msg_eid);
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_cross_tenant_projection_isolation() {
        // Both tenants project the same message blob — each gets independent valid_events
        let conn = setup();
        let tenant_a = "tenant_a";
        let tenant_b = "tenant_b";

        let (_msg, msg_blob) = make_message("shared message");
        let msg_eid = insert_event_raw(&conn, tenant_a, &msg_blob);
        // Also record for tenant_b
        let eid_b64 = event_id_to_base64(&msg_eid);
        conn.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, 'test')",
            rusqlite::params![tenant_b, &eid_b64, now_ms() as i64],
        ).unwrap();

        // Project for both tenants
        let r_a = project_one(&conn, tenant_a, &msg_eid).unwrap();
        assert_eq!(r_a, ProjectionDecision::Valid);
        let r_b = project_one(&conn, tenant_b, &msg_eid).unwrap();
        assert_eq!(r_b, ProjectionDecision::Valid);

        // 2 rows in messages (one per tenant), 1 row in events (shared blob)
        let msg_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE message_id = ?1",
            rusqlite::params![&eid_b64],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(msg_count, 2);

        let event_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE event_id = ?1",
            rusqlite::params![&eid_b64],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(event_count, 1);

        // Each tenant has independent valid_events entry
        for tenant in [tenant_a, tenant_b] {
            let valid: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![tenant, &eid_b64],
                |row| row.get(0),
            ).unwrap();
            assert!(valid, "tenant {} should have valid_events entry", tenant);
        }
    }

    #[test]
    fn test_cross_tenant_signer_isolation() {
        // PeerKey projected for tenant_a only; signed memo should block for tenant_b
        let conn = setup();
        let tenant_a = "tenant_a";
        let tenant_b = "tenant_b";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();

        // Create and project PeerKey for tenant_a only
        let (_pk, pk_blob) = make_peer_key(public_key);
        let pk_eid = insert_event_raw(&conn, tenant_a, &pk_blob);
        let r = project_one(&conn, tenant_a, &pk_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);

        // Create signed memo (correct signature)
        let (_memo, memo_blob) = make_signed_memo(&signing_key, &pk_eid, "tenant isolation test");
        let memo_eid = insert_event_raw(&conn, tenant_a, &memo_blob);

        // Project for tenant_a — should be Valid
        let r_a = project_one(&conn, tenant_a, &memo_eid).unwrap();
        assert_eq!(r_a, ProjectionDecision::Valid);

        // Also record the memo + pk for tenant_b
        let memo_b64 = event_id_to_base64(&memo_eid);
        let pk_b64 = event_id_to_base64(&pk_eid);
        conn.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
            rusqlite::params![tenant_b, &memo_b64, now_ms() as i64],
        ).unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
            rusqlite::params![tenant_b, &pk_b64, now_ms() as i64],
        ).unwrap();

        // Project memo for tenant_b — should BLOCK (signer dep not valid for B)
        let r_b = project_one(&conn, tenant_b, &memo_eid).unwrap();
        match r_b {
            ProjectionDecision::Block { missing } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], pk_eid);
            }
            other => panic!("expected Block for tenant_b, got {:?}", other),
        }

        // Verify: signed_memos has 1 row for A, 0 for B
        let sm_a: i64 = conn.query_row(
            "SELECT COUNT(*) FROM signed_memos WHERE recorded_by = ?1",
            rusqlite::params![tenant_a], |row| row.get(0),
        ).unwrap();
        let sm_b: i64 = conn.query_row(
            "SELECT COUNT(*) FROM signed_memos WHERE recorded_by = ?1",
            rusqlite::params![tenant_b], |row| row.get(0),
        ).unwrap();
        assert_eq!(sm_a, 1);
        assert_eq!(sm_b, 0);
    }

    #[test]
    fn test_rejection_recorded_durably() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let wrong_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();

        // Create PeerKey with signing_key's public key
        let (_pk, pk_blob) = make_peer_key(public_key);
        let pk_eid = insert_event_raw(&conn, recorded_by, &pk_blob);
        project_one(&conn, recorded_by, &pk_eid).unwrap();

        // Sign memo with wrong key
        let (_memo, memo_blob) = make_signed_memo(&wrong_key, &pk_eid, "bad sig");
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        let result = project_one(&conn, recorded_by, &memo_eid).unwrap();
        match result {
            ProjectionDecision::Reject { ref reason } => {
                assert!(reason.contains("invalid signature"), "reason: {}", reason);
            }
            other => panic!("expected Reject, got {:?}", other),
        }

        // Verify row exists in rejected_events
        let memo_b64 = event_id_to_base64(&memo_eid);
        let rej_reason: String = conn.query_row(
            "SELECT reason FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &memo_b64],
            |row| row.get(0),
        ).unwrap();
        assert!(rej_reason.contains("invalid signature"));
    }

    #[test]
    fn test_rejected_event_not_retried() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let wrong_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();

        // Create PeerKey, sign memo with wrong key
        let (_pk, pk_blob) = make_peer_key(public_key);
        let pk_eid = insert_event_raw(&conn, recorded_by, &pk_blob);
        project_one(&conn, recorded_by, &pk_eid).unwrap();

        let (_memo, memo_blob) = make_signed_memo(&wrong_key, &pk_eid, "bad sig again");
        let memo_eid = insert_event_raw(&conn, recorded_by, &memo_blob);

        // First call: Reject
        let r1 = project_one(&conn, recorded_by, &memo_eid).unwrap();
        assert!(matches!(r1, ProjectionDecision::Reject { .. }));

        // Second call: AlreadyProcessed (not Reject again)
        let r2 = project_one(&conn, recorded_by, &memo_eid).unwrap();
        assert_eq!(r2, ProjectionDecision::AlreadyProcessed);
    }

    #[test]
    fn test_two_tenant_contexts_single_db() {
        let conn = setup();
        let tenant_a = "tenant_a";
        let tenant_b = "tenant_b";

        // Each tenant creates a message
        let (_msg_a, msg_a_blob) = make_message("hello from A");
        let msg_a_eid = insert_event_raw(&conn, tenant_a, &msg_a_blob);
        let (_msg_b, msg_b_blob) = make_message("hello from B");
        let msg_b_eid = insert_event_raw(&conn, tenant_b, &msg_b_blob);

        // Project each for their tenant
        let r_a = project_one(&conn, tenant_a, &msg_a_eid).unwrap();
        assert_eq!(r_a, ProjectionDecision::Valid);
        let r_b = project_one(&conn, tenant_b, &msg_b_eid).unwrap();
        assert_eq!(r_b, ProjectionDecision::Valid);

        // Each sees only 1 message (isolated)
        let count_a: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![tenant_a], |row| row.get(0),
        ).unwrap();
        let count_b: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![tenant_b], |row| row.get(0),
        ).unwrap();
        assert_eq!(count_a, 1);
        assert_eq!(count_b, 1);

        // Tenant B reacts to tenant A's message — blocks (dep not valid for B)
        let (_rxn, rxn_blob) = make_reaction(&msg_a_eid, "\u{1f44d}");
        let rxn_eid = insert_event_raw(&conn, tenant_b, &rxn_blob);
        let r_rxn = project_one(&conn, tenant_b, &rxn_eid).unwrap();
        assert!(matches!(r_rxn, ProjectionDecision::Block { .. }));

        // Now record and project tenant_a's message for tenant_b
        let msg_a_b64 = event_id_to_base64(&msg_a_eid);
        conn.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
            rusqlite::params![tenant_b, &msg_a_b64, now_ms() as i64],
        ).unwrap();
        let r_msg_for_b = project_one(&conn, tenant_b, &msg_a_eid).unwrap();
        assert_eq!(r_msg_for_b, ProjectionDecision::Valid);

        // Cascade should have unblocked the reaction for tenant_b
        let rxn_b64 = event_id_to_base64(&rxn_eid);
        let rxn_valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![tenant_b, &rxn_b64],
            |row| row.get(0),
        ).unwrap();
        assert!(rxn_valid, "reaction should be auto-projected after dep arrives for tenant_b");

        // Tenant B now has 2 messages + 1 reaction
        let count_b_msgs: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![tenant_b], |row| row.get(0),
        ).unwrap();
        let count_b_rxns: i64 = conn.query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![tenant_b], |row| row.get(0),
        ).unwrap();
        assert_eq!(count_b_msgs, 2);
        assert_eq!(count_b_rxns, 1);
    }

    // ===== Encrypted event helpers =====

    fn make_secret_key(key_bytes: [u8; 32]) -> (ParsedEvent, Vec<u8>) {
        let sk = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: now_ms(),
            key_bytes,
        });
        let blob = events::encode_event(&sk).unwrap();
        (sk, blob)
    }

    fn make_encrypted_event(key_bytes: &[u8; 32], inner_blob: &[u8], inner_type_code: u8, key_event_id: &EventId) -> (ParsedEvent, Vec<u8>) {
        let (nonce, ciphertext, auth_tag) = encrypt_event_blob(key_bytes, inner_blob).unwrap();
        let enc = ParsedEvent::Encrypted(EncryptedEvent {
            created_at_ms: now_ms(),
            key_event_id: *key_event_id,
            inner_type_code,
            nonce,
            ciphertext,
            auth_tag,
        });
        let blob = events::encode_event(&enc).unwrap();
        (enc, blob)
    }

    #[test]
    fn test_project_secret_key_valid() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();
        let (_sk, blob) = make_secret_key(key_bytes);
        let eid = insert_event_raw(&conn, recorded_by, &blob);

        let result = project_one(&conn, recorded_by, &eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Verify in secret_keys table
        let eid_b64 = event_id_to_base64(&eid);
        let stored_key: Vec<u8> = conn.query_row(
            "SELECT key_bytes FROM secret_keys WHERE event_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&eid_b64, recorded_by],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(stored_key, key_bytes.as_slice());
    }

    #[test]
    fn test_encrypted_message_valid() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();

        // Create and project secret key
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        let r = project_one(&conn, recorded_by, &sk_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);

        // Create inner message
        let (_msg, msg_blob) = make_message("encrypted hello");

        // Encrypt it
        let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        assert_eq!(result, ProjectionDecision::Valid);

        // Verify inner message is in messages table (using encrypted event_id)
        let enc_b64 = event_id_to_base64(&enc_eid);
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&enc_b64, recorded_by],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_encrypted_blocks_on_missing_key() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();

        // Pre-compute key event_id without inserting
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = hash_event(&sk_blob);

        // Create encrypted event referencing the missing key
        let (_msg, msg_blob) = make_message("blocked encrypted");
        let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        match result {
            ProjectionDecision::Block { missing } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], sk_eid);
            }
            other => panic!("expected Block, got {:?}", other),
        }
    }

    #[test]
    fn test_encrypted_unblocks_when_key_arrives() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();

        // Pre-compute key event_id
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = hash_event(&sk_blob);

        // Insert encrypted event first (before key)
        let (_msg, msg_blob) = make_message("out of order encrypted");
        let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        // Project → Block
        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));

        // Now insert and project the secret key
        insert_event_raw(&conn, recorded_by, &sk_blob);
        let r = project_one(&conn, recorded_by, &sk_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);

        // Encrypted event should have been cascade-unblocked
        let enc_b64 = event_id_to_base64(&enc_eid);
        let valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        ).unwrap();
        assert!(valid, "encrypted event should be auto-projected after key arrives");

        // Verify inner message was projected
        let msg_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&enc_b64, recorded_by],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(msg_count, 1);
    }

    #[test]
    fn test_encrypted_wrong_key_rejects() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_a: [u8; 32] = rand::random();
        let key_b: [u8; 32] = rand::random();

        // Create and project key B
        let (_sk_b, sk_b_blob) = make_secret_key(key_b);
        let sk_b_eid = insert_event_raw(&conn, recorded_by, &sk_b_blob);
        project_one(&conn, recorded_by, &sk_b_eid).unwrap();

        // Encrypt with key A but reference key B
        let (_msg, msg_blob) = make_message("wrong key test");
        let (_enc, enc_blob) = make_encrypted_event(&key_a, &msg_blob, EVENT_TYPE_MESSAGE, &sk_b_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        match result {
            ProjectionDecision::Reject { reason } => {
                assert!(reason.contains("decryption failed"), "reason: {}", reason);
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    #[test]
    fn test_encrypted_inner_type_mismatch_rejects() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();

        // Create and project key
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        // Create a message but declare inner_type_code=2 (reaction)
        let (_msg, msg_blob) = make_message("type mismatch");
        let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &msg_blob, 2, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        match result {
            ProjectionDecision::Reject { reason } => {
                assert!(reason.contains("inner type mismatch"), "reason: {}", reason);
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    #[test]
    fn test_encrypted_nested_rejects() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();

        // Create and project key
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        // Create inner encrypted event
        let (_msg, msg_blob) = make_message("nested inner");
        let (_inner_enc, inner_enc_blob) = make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);

        // Encrypt the encrypted event
        let (_outer_enc, outer_enc_blob) = make_encrypted_event(&key_bytes, &inner_enc_blob, EVENT_TYPE_ENCRYPTED, &sk_eid);
        let outer_eid = insert_event_raw(&conn, recorded_by, &outer_enc_blob);

        let result = project_one(&conn, recorded_by, &outer_eid).unwrap();
        match result {
            ProjectionDecision::Reject { reason } => {
                assert!(reason.contains("nested encryption"), "reason: {}", reason);
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    #[test]
    fn test_encrypted_inner_dep_blocks() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();

        // Create and project key
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        // Create encrypted reaction with missing target
        let fake_target = [88u8; 32];
        let (_rxn, rxn_blob) = make_reaction(&fake_target, "\u{1f44d}");
        let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &rxn_blob, 2, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        match result {
            ProjectionDecision::Block { missing } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], fake_target);
            }
            other => panic!("expected Block on inner dep, got {:?}", other),
        }

        // Verify NOT in valid_events
        let enc_b64 = event_id_to_base64(&enc_eid);
        let valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        ).unwrap();
        assert!(!valid);
    }

    #[test]
    fn test_encrypted_inner_dep_unblocks() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_bytes: [u8; 32] = rand::random();

        // Create and project key
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, recorded_by, &sk_blob);
        project_one(&conn, recorded_by, &sk_eid).unwrap();

        // Create target message (pre-compute but don't insert yet)
        let (_msg, msg_blob) = make_message("target for encrypted rxn");
        let msg_eid = hash_event(&msg_blob);

        // Create encrypted reaction targeting the message
        let (_rxn, rxn_blob) = make_reaction(&msg_eid, "\u{2764}\u{fe0f}");
        let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &rxn_blob, 2, &sk_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        // Project → Block on inner dep (message)
        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Block { .. }));

        // Now insert and project the message
        insert_event_raw(&conn, recorded_by, &msg_blob);
        let r = project_one(&conn, recorded_by, &msg_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);

        // Encrypted reaction should have been cascade-unblocked
        let enc_b64 = event_id_to_base64(&enc_eid);
        let valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        ).unwrap();
        assert!(valid, "encrypted reaction should be auto-projected after target message arrives");
    }

    #[test]
    fn test_encrypted_rejection_recorded_durably() {
        let conn = setup();
        let recorded_by = "peer1";
        let key_a: [u8; 32] = rand::random();
        let key_b: [u8; 32] = rand::random();

        // Create and project key B
        let (_sk_b, sk_b_blob) = make_secret_key(key_b);
        let sk_b_eid = insert_event_raw(&conn, recorded_by, &sk_b_blob);
        project_one(&conn, recorded_by, &sk_b_eid).unwrap();

        // Encrypt with key A, reference key B → decryption fails
        let (_msg, msg_blob) = make_message("will be rejected");
        let (_enc, enc_blob) = make_encrypted_event(&key_a, &msg_blob, EVENT_TYPE_MESSAGE, &sk_b_eid);
        let enc_eid = insert_event_raw(&conn, recorded_by, &enc_blob);

        let result = project_one(&conn, recorded_by, &enc_eid).unwrap();
        assert!(matches!(result, ProjectionDecision::Reject { .. }));

        // Verify in rejected_events
        let enc_b64 = event_id_to_base64(&enc_eid);
        let reason: String = conn.query_row(
            "SELECT reason FROM rejected_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &enc_b64],
            |row| row.get(0),
        ).unwrap();
        assert!(reason.contains("decryption failed"));
    }

    #[test]
    fn test_encrypted_cross_tenant_isolation() {
        let conn = setup();
        let tenant_a = "tenant_a";
        let tenant_b = "tenant_b";
        let key_bytes: [u8; 32] = rand::random();

        // Create and project key for tenant_a only
        let (_sk, sk_blob) = make_secret_key(key_bytes);
        let sk_eid = insert_event_raw(&conn, tenant_a, &sk_blob);
        let r = project_one(&conn, tenant_a, &sk_eid).unwrap();
        assert_eq!(r, ProjectionDecision::Valid);

        // Create encrypted message referencing that key
        let (_msg, msg_blob) = make_message("tenant-scoped encryption");
        let (_enc, enc_blob) = make_encrypted_event(&key_bytes, &msg_blob, EVENT_TYPE_MESSAGE, &sk_eid);
        let enc_eid = insert_event_raw(&conn, tenant_a, &enc_blob);

        // Project for tenant_a → Valid
        let r_a = project_one(&conn, tenant_a, &enc_eid).unwrap();
        assert_eq!(r_a, ProjectionDecision::Valid);

        // Record for tenant_b (also record the sk_blob event)
        let enc_b64 = event_id_to_base64(&enc_eid);
        let sk_b64 = event_id_to_base64(&sk_eid);
        conn.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
            rusqlite::params![tenant_b, &enc_b64, now_ms() as i64],
        ).unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES (?1, ?2, ?3, 'test')",
            rusqlite::params![tenant_b, &sk_b64, now_ms() as i64],
        ).unwrap();

        // Project encrypted event for tenant_b → Block (key not valid for B)
        let r_b = project_one(&conn, tenant_b, &enc_eid).unwrap();
        match r_b {
            ProjectionDecision::Block { missing } => {
                assert_eq!(missing.len(), 1);
                assert_eq!(missing[0], sk_eid);
            }
            other => panic!("expected Block for tenant_b, got {:?}", other),
        }
    }
}
