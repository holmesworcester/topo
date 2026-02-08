use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{hash_event, event_id_to_base64, EventId};
use crate::events::{self, ParsedEvent, registry};
use super::pipeline::project_one;

/// Emit a deterministic event: compute blob, hash to event_id, check if already
/// exists, if not: store in events/neg_items/recorded_events and project via project_one.
/// Returns the event_id regardless of whether it was newly created or already existed.
///
/// This follows the emitted-event rule: "emit canonical event X only (to events +
/// normal queue flow), let X project through X's own projector."
pub fn emit_deterministic_event(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
) -> Result<EventId, Box<dyn std::error::Error>> {
    let blob = events::encode_event(event)
        .map_err(|e| format!("encode error: {}", e))?;

    let event_id = hash_event(&blob);
    let event_id_b64 = event_id_to_base64(&event_id);

    // Check if already exists
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
        rusqlite::params![&event_id_b64],
        |row| row.get(0),
    )?;

    if exists {
        return Ok(event_id);
    }

    let type_code = event.event_type_code();
    let meta = registry().lookup(type_code)
        .ok_or_else(|| format!("unknown type code {}", type_code))?;

    let created_at_ms = event.created_at_ms() as i64;
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
            blob.as_slice(),
            meta.share_scope.as_str(),
            created_at_ms,
            now_ms
        ],
    )?;

    // Write to neg_items
    conn.execute(
        "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)",
        rusqlite::params![created_at_ms, event_id.as_slice()],
    )?;

    // Write to recorded_events
    conn.execute(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![recorded_by, &event_id_b64, now_ms, "emitted"],
    )?;

    // Project via project_one
    let _ = project_one(conn, recorded_by, &event_id);

    Ok(event_id)
}
