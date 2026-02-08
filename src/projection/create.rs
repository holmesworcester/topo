use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{hash_event, event_id_to_base64, EventId};
use crate::events::{self, ParsedEvent, registry, ShareScope};
use crate::events::EncryptedEvent;
use crate::projection::encrypted::encrypt_event_blob;
use crate::projection::signer::sign_event_bytes;
use super::decision::ProjectionDecision;
use super::identity::capture_invite_network_binding;
use super::pipeline::project_one;

#[derive(Debug)]
pub enum CreateEventError {
    EncodeError(String),
    DbError(String),
    Blocked { event_id: EventId, missing: Vec<[u8; 32]> },
    Rejected { event_id: EventId, reason: String },
}

impl std::fmt::Display for CreateEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CreateEventError::EncodeError(e) => write!(f, "encode error: {}", e),
            CreateEventError::DbError(e) => write!(f, "db error: {}", e),
            CreateEventError::Blocked { event_id, missing } => {
                write!(f, "event {} blocked on {} deps", event_id_to_base64(event_id), missing.len())
            }
            CreateEventError::Rejected { event_id, reason } => {
                write!(f, "event {} rejected: {}", event_id_to_base64(event_id), reason)
            }
        }
    }
}

impl std::error::Error for CreateEventError {}

/// Shared helper: hash blob, write to events/neg_items/recorded_events, project via project_one.
fn store_blob_and_project(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
    meta: &events::EventTypeMeta,
    created_at_ms: i64,
) -> Result<EventId, CreateEventError> {
    let event_id = hash_event(blob);
    let event_id_b64 = event_id_to_base64(&event_id);

    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // Write to events table
    conn.execute(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            &event_id_b64,
            meta.type_name,
            blob,
            meta.share_scope.as_str(),
            created_at_ms,
            now_ms
        ],
    ).map_err(|e| CreateEventError::DbError(e.to_string()))?;

    // Write to neg_items (only for shared events — local events must not sync)
    if meta.share_scope == ShareScope::Shared {
        conn.execute(
            "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)",
            rusqlite::params![created_at_ms, event_id.as_slice()],
        ).map_err(|e| CreateEventError::DbError(e.to_string()))?;
    }

    // Write to recorded_events
    conn.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![recorded_by, &event_id_b64, now_ms, "local_create"],
    ).map_err(|e| CreateEventError::DbError(e.to_string()))?;

    // Capture invite_network_bindings from invite blobs (before projection)
    capture_invite_network_binding(conn, recorded_by, blob)
        .map_err(|e| CreateEventError::DbError(e.to_string()))?;

    // Project
    let decision = project_one(conn, recorded_by, &event_id)
        .map_err(|e| CreateEventError::DbError(e.to_string()))?;

    match decision {
        ProjectionDecision::Valid
        | ProjectionDecision::AlreadyProcessed
        | ProjectionDecision::Block { .. } => Ok(event_id),
        ProjectionDecision::Reject { reason } => {
            Err(CreateEventError::Rejected { event_id, reason })
        }
    }
}

/// Create a new event: encode, hash, write to events/neg_items/recorded_events,
/// then project via `project_one`. Returns the event_id on success.
pub fn create_event_sync(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
) -> Result<EventId, CreateEventError> {
    let blob = events::encode_event(event)
        .map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    let type_code = event.event_type_code();
    let reg = registry();
    let meta = reg.lookup(type_code)
        .ok_or_else(|| CreateEventError::EncodeError(format!("unknown type code {}", type_code)))?;

    let created_at_ms = event.created_at_ms() as i64;
    store_blob_and_project(conn, recorded_by, &blob, meta, created_at_ms)
}

/// Create a signed event: encode with zero-placeholder signature, sign the
/// canonical bytes, overwrite signature, then store and project.
pub fn create_signed_event_sync(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<EventId, CreateEventError> {
    let mut blob = events::encode_event(event)
        .map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    let type_code = event.event_type_code();
    let reg = registry();
    let meta = reg.lookup(type_code)
        .ok_or_else(|| CreateEventError::EncodeError(format!("unknown type code {}", type_code)))?;

    if meta.signature_byte_len == 0 {
        return Err(CreateEventError::EncodeError(
            "create_signed_event_sync called for unsigned type".to_string(),
        ));
    }

    let sig_len = meta.signature_byte_len;
    let blob_len = blob.len();
    let signing_bytes = &blob[..blob_len - sig_len];
    let sig = sign_event_bytes(signing_key, signing_bytes);
    blob[blob_len - sig_len..].copy_from_slice(&sig);

    let created_at_ms = event.created_at_ms() as i64;
    store_blob_and_project(conn, recorded_by, &blob, meta, created_at_ms)
}

/// Create an encrypted event: resolve key from secret_keys, encode inner event,
/// encrypt, build EncryptedEvent wrapper, then store and project.
pub fn create_encrypted_event_sync(
    conn: &Connection,
    recorded_by: &str,
    key_event_id: &EventId,
    inner_event: &ParsedEvent,
) -> Result<EventId, CreateEventError> {
    // 1. Resolve key from secret_keys table
    let key_b64 = event_id_to_base64(key_event_id);
    let key_bytes: Vec<u8> = conn.query_row(
        "SELECT key_bytes FROM secret_keys WHERE recorded_by = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &key_b64],
        |row| row.get(0),
    ).map_err(|e| CreateEventError::DbError(format!("key lookup: {}", e)))?;

    if key_bytes.len() != 32 {
        return Err(CreateEventError::EncodeError(
            format!("secret key wrong length: {}", key_bytes.len()),
        ));
    }
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);

    // 2. Encode inner event
    let inner_blob = events::encode_event(inner_event)
        .map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    // 3. Encrypt
    let (nonce, ciphertext, auth_tag) = encrypt_event_blob(&key_arr, &inner_blob)
        .map_err(|e| CreateEventError::EncodeError(e.to_string()))?;

    // 4. Build EncryptedEvent wrapper
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let wrapper = ParsedEvent::Encrypted(EncryptedEvent {
        created_at_ms: now_ms,
        key_event_id: *key_event_id,
        inner_type_code: inner_event.event_type_code(),
        nonce,
        ciphertext,
        auth_tag,
    });

    // 5. Use existing create_event_sync for the wrapper
    create_event_sync(conn, recorded_by, &wrapper)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::events::{MessageEvent, ReactionEvent, PeerKeyEvent, SignedMemoEvent};
    use ed25519_dalek::SigningKey;

    fn now_ms() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
    }

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn test_create_message_sync() {
        let conn = setup();
        let recorded_by = "peer1";

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            channel_id: [1u8; 32],
            author_id: [2u8; 32],
            content: "hello".to_string(),
        });

        let eid = create_event_sync(&conn, recorded_by, &msg).unwrap();
        let eid_b64 = event_id_to_base64(&eid);

        // events table
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM events WHERE event_id = ?1",
            rusqlite::params![&eid_b64], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);

        // messages table
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE message_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&eid_b64, recorded_by], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);

        // valid_events
        let valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &eid_b64], |row| row.get(0),
        ).unwrap();
        assert!(valid);

        // neg_items
        let neg: i64 = conn.query_row(
            "SELECT COUNT(*) FROM neg_items", [], |row| row.get(0),
        ).unwrap();
        assert_eq!(neg, 1);

        // recorded_events
        let rec: i64 = conn.query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by], |row| row.get(0),
        ).unwrap();
        assert_eq!(rec, 1);
    }

    #[test]
    fn test_create_reaction_chain() {
        let conn = setup();
        let recorded_by = "peer1";

        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: now_ms(),
            channel_id: [1u8; 32],
            author_id: [2u8; 32],
            content: "target".to_string(),
        });
        let msg_eid = create_event_sync(&conn, recorded_by, &msg).unwrap();

        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: msg_eid,
            author_id: [3u8; 32],
            emoji: "\u{1f44d}".to_string(),
        });
        let rxn_eid = create_event_sync(&conn, recorded_by, &rxn).unwrap();

        // Both valid
        let msg_b64 = event_id_to_base64(&msg_eid);
        let rxn_b64 = event_id_to_base64(&rxn_eid);
        for b64 in [&msg_b64, &rxn_b64] {
            let valid: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, b64], |row| row.get(0),
            ).unwrap();
            assert!(valid);
        }
    }

    #[test]
    fn test_create_reaction_before_target() {
        let conn = setup();
        let recorded_by = "peer1";

        let fake_target = [99u8; 32];
        let rxn = ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: now_ms(),
            target_event_id: fake_target,
            author_id: [3u8; 32],
            emoji: "\u{1f44d}".to_string(),
        });

        // Event is created (stored) but blocked — returns Ok with event_id
        let eid = create_event_sync(&conn, recorded_by, &rxn).unwrap();
        let eid_b64 = event_id_to_base64(&eid);

        // Should be in events table but NOT in valid_events
        let in_events: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
            rusqlite::params![&eid_b64], |row| row.get(0),
        ).unwrap();
        assert!(in_events);

        let in_valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &eid_b64], |row| row.get(0),
        ).unwrap();
        assert!(!in_valid);

        // Should be in blocked_event_deps
        let blocked: i64 = conn.query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &eid_b64], |row| row.get(0),
        ).unwrap();
        assert_eq!(blocked, 1);
    }

    #[test]
    fn test_create_signed_event_sync() {
        let conn = setup();
        let recorded_by = "peer1";
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let public_key = signing_key.verifying_key().to_bytes();

        // Create PeerKey first
        let pk_event = ParsedEvent::PeerKey(PeerKeyEvent {
            created_at_ms: now_ms(),
            public_key,
        });
        let pk_eid = create_event_sync(&conn, recorded_by, &pk_event).unwrap();

        // Create signed memo
        let memo = ParsedEvent::SignedMemo(SignedMemoEvent {
            created_at_ms: now_ms(),
            signed_by: pk_eid,
            signer_type: 0,
            content: "signed content".to_string(),
            signature: [0u8; 64], // placeholder, will be overwritten
        });

        let memo_eid = create_signed_event_sync(&conn, recorded_by, &memo, &signing_key).unwrap();
        let memo_b64 = event_id_to_base64(&memo_eid);

        // Should be valid
        let valid: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &memo_b64], |row| row.get(0),
        ).unwrap();
        assert!(valid);

        // Should be in signed_memos table
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM signed_memos WHERE event_id = ?1 AND recorded_by = ?2",
            rusqlite::params![&memo_b64, recorded_by], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }
}
