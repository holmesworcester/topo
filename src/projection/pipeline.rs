use rusqlite::Connection;

use crate::crypto::{event_id_to_base64, event_id_from_base64, EventId};
use crate::events::{self, ParsedEvent};
use super::decision::ProjectionDecision;
use super::projectors::{project_message, project_reaction};

/// Central projection entrypoint. Given an event_id that is already stored in the
/// `events` table, parse it, check dependencies, project into terminal tables,
/// and cascade-unblock any dependents.
pub fn project_one(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    let event_id_b64 = event_id_to_base64(event_id);

    // 1. Check terminal state — already processed?
    let already: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &event_id_b64],
        |row| row.get(0),
    )?;
    if already {
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
            return Ok(ProjectionDecision::Reject {
                reason: format!("event {} not found in events table", event_id_b64),
            });
        }
        Err(e) => return Err(e.into()),
    };

    // 3. Parse via registry
    let parsed = match events::parse_event(&blob) {
        Ok(p) => p,
        Err(e) => {
            return Ok(ProjectionDecision::Reject {
                reason: format!("parse error: {}", e),
            });
        }
    };

    // 4. Extract deps and check them
    let deps = parsed.dep_field_values();
    let mut missing = Vec::new();
    for (_field_name, dep_id) in &deps {
        let dep_b64 = event_id_to_base64(dep_id);
        let dep_exists: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
            rusqlite::params![&dep_b64],
            |row| row.get(0),
        )?;
        if !dep_exists {
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

    // 6. Call per-event projector
    match &parsed {
        ParsedEvent::Message(msg) => {
            project_message(conn, recorded_by, &event_id_b64, msg)?;
        }
        ParsedEvent::Reaction(rxn) => {
            project_reaction(conn, recorded_by, &event_id_b64, rxn)?;
        }
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
                // Project inline (no recursion) — just the core projection logic
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

                if let Ok(parsed) = events::parse_event(&blob) {
                    // Check deps are satisfied (should be, but verify)
                    let deps = parsed.dep_field_values();
                    let mut still_missing = false;
                    for (_field, dep_id) in &deps {
                        let dep_b64 = event_id_to_base64(dep_id);
                        let exists: bool = conn.query_row(
                            "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
                            rusqlite::params![&dep_b64],
                            |row| row.get(0),
                        )?;
                        if !exists {
                            still_missing = true;
                            break;
                        }
                    }
                    if still_missing {
                        continue;
                    }

                    match &parsed {
                        ParsedEvent::Message(msg) => {
                            project_message(conn, recorded_by, &eid_b64, msg)?;
                        }
                        ParsedEvent::Reaction(rxn) => {
                            project_reaction(conn, recorded_by, &eid_b64, rxn)?;
                        }
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_event;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::events::{self, MessageEvent, ReactionEvent, ParsedEvent};
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
        let type_name = if type_code == 1 { "message" } else { "reaction" };

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
}
