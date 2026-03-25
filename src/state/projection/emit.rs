use rusqlite::Connection;
use std::time::{SystemTime, UNIX_EPOCH};

use super::apply::project_one;
use super::decision::ProjectionDecision;
use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::store::{
    insert_event, insert_recorded_event_checked, insert_shared_event_index_entry_if_shared,
    lookup_workspace_id,
};
use crate::event_modules::{self as events, registry, ParsedEvent};
use crate::state::live_hints::{self, LiveHintEvent};
use crate::state::shared_workspace_fanout::fanout_stored_shared_event_immediate;

struct EmitOutcome {
    event_id: EventId,
    live_hints: Vec<LiveHintEvent>,
}

/// Emit a deterministic event: compute blob, hash to event_id, check if already
/// exists, if not: store in events/shared_event_index/recorded_events and project via project_one.
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
    emit_deterministic_blob(conn, recorded_by, &blob)
}

/// Emit a deterministic canonical blob through the normal event pipeline.
pub fn emit_deterministic_blob(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
) -> Result<EventId, Box<dyn std::error::Error>> {
    let publish_after_commit = conn.is_autocommit();
    let emitted = if publish_after_commit {
        crate::state::db::queue::with_immediate_tx_result(conn, || {
            emit_deterministic_blob_in_tx(conn, recorded_by, blob)
        })?
    } else {
        emit_deterministic_blob_in_tx(conn, recorded_by, blob)?
    };
    if publish_after_commit {
        live_hints::publish_from_connection(conn, &emitted.live_hints);
    }
    Ok(emitted.event_id)
}

fn emit_deterministic_blob_in_tx(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
) -> Result<EmitOutcome, Box<dyn std::error::Error>> {
    if blob.is_empty() {
        return Err("deterministic blob cannot be empty".into());
    }
    let event_id = hash_event(blob);
    let event_id_b64 = event_id_to_base64(&event_id);

    let type_code = blob[0];
    let meta = registry()
        .lookup(type_code)
        .ok_or_else(|| format!("unknown type code {}", type_code))?;

    let created_at_ms = events::extract_created_at_ms(blob)
        .ok_or("deterministic blob too short to contain created_at_ms")?
        as i64;
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
            blob,
            meta.share_scope,
            created_at_ms,
            now_ms,
        )?;
        let ws_id_for_neg = if meta.type_name == "workspace" {
            Some(crate::crypto::event_id_to_base64(&event_id))
        } else {
            lookup_workspace_id(conn, recorded_by)
        };
        if let Some(ws_id) = ws_id_for_neg {
            insert_shared_event_index_entry_if_shared(
                conn,
                meta.share_scope,
                created_at_ms,
                &event_id,
                &ws_id,
            )?;
        } else if meta.share_scope == crate::event_modules::registry::ShareScope::Shared {
            tracing::warn!(
                "no accepted workspace binding for {}, shared event {} missing from shared_event_index",
                recorded_by,
                crate::crypto::event_id_to_base64(&event_id)
            );
        }
    }

    // Always record for this tenant and project (even if event already existed globally)
    let recorded_inserted =
        insert_recorded_event_checked(conn, recorded_by, &event_id, now_ms, "emitted")?;
    let mut live_hints = Vec::new();
    if recorded_inserted && meta.share_scope == crate::event_modules::registry::ShareScope::Shared {
        live_hints.push(LiveHintEvent {
            tenant_id: recorded_by.to_string(),
            event_id,
            source_peer_id: None,
        });
    }

    match project_one(conn, recorded_by, &event_id) {
        Ok(ProjectionDecision::Valid | ProjectionDecision::AlreadyProcessed) => {
            fanout_stored_shared_event_immediate(conn, recorded_by, &event_id)
                .map_err(|e| format!("same-workspace fanout failed: {}", e))?;
        }
        Ok(_) => {}
        Err(e) => {
            tracing::warn!(
                "emit_deterministic_blob projection error for {}: {}",
                event_id_b64,
                e
            );
        }
    }

    Ok(EmitOutcome {
        event_id,
        live_hints,
    })
}
