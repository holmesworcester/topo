use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use super::apply::project_one;
use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::store::{
    insert_event, insert_neg_item_if_shared, insert_recorded_event, lookup_workspace_id,
};
use crate::event_modules::{self as events, registry, ParsedEvent};

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
    let blob = events::encode_event(event).map_err(|e| format!("encode error: {}", e))?;

    let event_id = hash_event(&blob);
    let event_id_b64 = event_id_to_base64(&event_id);

    let type_code = event.event_type_code();
    let meta = registry()
        .lookup(type_code)
        .ok_or_else(|| format!("unknown type code {}", type_code))?;

    let created_at_ms = event.created_at_ms() as i64;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // Check if already exists globally
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM events WHERE event_id = ?1",
        rusqlite::params![&event_id_b64],
        |row| row.get(0),
    )?;

    if !exists {
        insert_event(
            conn,
            &event_id,
            meta.type_name,
            blob.as_slice(),
            meta.share_scope,
            created_at_ms,
            now_ms,
        )?;
        let ws_id = lookup_workspace_id(conn, recorded_by);
        insert_neg_item_if_shared(conn, meta.share_scope, created_at_ms, &event_id, &ws_id)?;
    }

    // Always record for this tenant and project (even if event already existed globally)
    insert_recorded_event(conn, recorded_by, &event_id, now_ms, "emitted")?;

    let _ = project_one(conn, recorded_by, &event_id);

    Ok(event_id)
}
