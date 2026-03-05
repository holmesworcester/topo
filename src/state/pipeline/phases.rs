use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{event_id_to_base64, EventId};
use crate::db::store::lookup_workspace_id;
use crate::event_modules::{self as events, registry::EventRegistry, ShareScope};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct PersistPhaseOutput {
    pub persisted_event_ids: Vec<EventId>,
    pub tenants_seen: HashSet<String>,
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

pub(super) fn run_persist_phase(
    db: &Connection,
    batch: &[IngestItem],
    reg: &'static EventRegistry,
    workspace_cache: &mut HashMap<String, String>,
    neg_items_stmt: &mut rusqlite::Statement<'_>,
    recorded_stmt: &mut rusqlite::Statement<'_>,
    events_stmt: &mut rusqlite::Statement<'_>,
    enqueue_stmt: &mut rusqlite::Statement<'_>,
) -> PersistPhaseOutput {
    let mut persist_output = PersistPhaseOutput {
        persisted_event_ids: Vec::with_capacity(batch.len()),
        tenants_seen: HashSet::new(),
    };

    for (event_id, blob, recorded_by, source_tag) in batch {
        let event_id_b64 = event_id_to_base64(event_id);

        if let Some(created_at_ms) = events::extract_created_at_ms(blob) {
            if let Some(type_code) = events::extract_event_type(blob) {
                if let Some(meta) = reg.lookup(type_code) {
                    // Only insert into neg_items for shared events (defense-in-depth)
                    if meta.share_scope == ShareScope::Shared {
                        // Look up workspace_id from cache or trust_anchors table.
                        // Skip neg_items insert if trust anchor is missing — this
                        // should not happen after bootstrap.
                        let ws_id = if let Some(cached) = workspace_cache.get(recorded_by) {
                            Some(cached.clone())
                        } else if let Some(ws) = lookup_workspace_id(db, recorded_by) {
                            workspace_cache.insert(recorded_by.clone(), ws.clone());
                            Some(ws)
                        } else {
                            tracing::warn!(
                                "no trust anchor for {}, skipping neg_items for {}",
                                recorded_by,
                                event_id_b64
                            );
                            None
                        };
                        if let Some(ws_id) = ws_id {
                            if let Err(e) = neg_items_stmt.execute(rusqlite::params![
                                &ws_id,
                                created_at_ms as i64,
                                event_id.as_slice()
                            ]) {
                                // Non-fatal: neg_items is a reconciliation cache;
                                // event will be re-added on next sync session.
                                tracing::warn!(
                                    "neg_items insert error for {}: {}",
                                    event_id_b64,
                                    e
                                );
                            }
                        }
                    }

                    if let Err(e) = events_stmt.execute(rusqlite::params![
                        &event_id_b64,
                        meta.type_name,
                        blob.as_slice(),
                        meta.share_scope.as_str(),
                        created_at_ms as i64,
                        current_timestamp_ms()
                    ]) {
                        tracing::warn!("events insert error for {}: {}", event_id_b64, e);
                        continue;
                    }

                    let recorded_at = current_timestamp_ms();
                    if let Err(e) = recorded_stmt.execute(rusqlite::params![
                        recorded_by,
                        &event_id_b64,
                        recorded_at,
                        source_tag
                    ]) {
                        tracing::warn!("recorded_events insert error for {}: {}", event_id_b64, e);
                        continue;
                    }

                    // Enqueue for durable projection (atomicity boundary 1)
                    if let Err(e) = enqueue_stmt.execute(rusqlite::params![
                        recorded_by,
                        &event_id_b64,
                        current_timestamp_ms()
                    ]) {
                        tracing::warn!("project_queue enqueue error for {}: {}", event_id_b64, e);
                    }

                    persist_output.tenants_seen.insert(recorded_by.clone());
                    persist_output.persisted_event_ids.push(*event_id);
                } else {
                }
            } else {
            }
        } else {
        }
    }

    persist_output
}
