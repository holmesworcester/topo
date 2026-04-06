use std::collections::{HashMap, HashSet};

use rusqlite::Connection;

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{event_id_to_base64, EventId};
use crate::db::queue::current_timestamp_ms;
use crate::db::store::lookup_workspace_id;
use crate::db::timeline::EventTimeline;
use crate::event_modules::{self as events, registry::EventRegistry, ShareScope};
use crate::state::live_hints::{source_peer_id_from_source_tag, LiveHintEvent};
use crate::state::shared_workspace_fanout::SharedEventFanout;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct PersistPhaseOutput {
    pub persisted_event_ids: Vec<EventId>,
    pub tenants_seen: HashSet<String>,
    pub live_hints: Vec<LiveHintEvent>,
    pub shared_event_fanouts: Vec<SharedEventFanout>,
}

fn ingest_recorded_by_for_blob(recorded_by: &str, blob: &[u8]) -> String {
    match crate::event_modules::parse_event(blob) {
        Ok(crate::event_modules::ParsedEvent::EndpointShared(event)) => {
            crate::event_modules::endpoint_shared::endpoint_id_from_public_key_bytes(
                &event.public_key,
            )
        }
        _ => recorded_by.to_string(),
    }
}

pub(super) fn run_persist_phase(
    db: &Connection,
    batch: &[IngestItem],
    reg: &'static EventRegistry,
    workspace_cache: &mut HashMap<String, String>,
    shared_event_index_stmt: &mut rusqlite::Statement<'_>,
    recorded_stmt: &mut rusqlite::Statement<'_>,
    events_stmt: &mut rusqlite::Statement<'_>,
    enqueue_stmt: &mut rusqlite::Statement<'_>,
) -> PersistPhaseOutput {
    let timeline = EventTimeline::new(db);
    let mut shared_index_inserts: HashMap<String, Vec<(i64, EventId)>> = HashMap::new();
    let mut persist_output = PersistPhaseOutput {
        persisted_event_ids: Vec::with_capacity(batch.len()),
        tenants_seen: HashSet::new(),
        live_hints: Vec::new(),
        shared_event_fanouts: Vec::new(),
    };

    for (event_id, blob, recorded_by, source_tag, received_at_ms, first_stored_at_ms) in batch {
        let effective_recorded_by = ingest_recorded_by_for_blob(recorded_by, blob);
        let event_id_b64 = event_id_to_base64(event_id);
        let _ = timeline.mark_received_and_stored_b64(
            &event_id_b64,
            *received_at_ms,
            *first_stored_at_ms,
        );

        if let Some(created_at_ms) = events::extract_created_at_ms(blob) {
            if let Some(type_code) = events::extract_event_type(blob) {
                if let Some(meta) = reg.lookup(type_code) {
                    // Only insert into shared_event_index for shared events (defense-in-depth)
                    if meta.share_scope == ShareScope::Shared {
                        // Look up workspace_id from cache or invites_accepted projection.
                        // For shared workspace events themselves, workspace_id is the
                        // event_id and may exist before invite_accepted projects.
                        let ws_id = if let Some(cached) = workspace_cache.get(recorded_by) {
                            Some(cached.clone())
                        } else if meta.type_name == "workspace" {
                            Some(event_id_b64.clone())
                        } else if meta.type_name == "endpoint_shared" {
                            None
                        } else if let Some(ws) = lookup_workspace_id(db, &effective_recorded_by) {
                            workspace_cache.insert(effective_recorded_by.clone(), ws.clone());
                            Some(ws)
                        } else {
                            tracing::warn!(
                                "no accepted workspace binding for {}, skipping shared_event_index for {}",
                                effective_recorded_by,
                                event_id_b64
                            );
                            None
                        };
                        if let Some(ws_id) = ws_id {
                            match shared_event_index_stmt.execute(rusqlite::params![
                                &ws_id,
                                created_at_ms as i64,
                                event_id.as_slice()
                            ]) {
                                Ok(rows) => {
                                    if rows > 0 {
                                        shared_index_inserts
                                            .entry(ws_id.clone())
                                            .or_default()
                                            .push((created_at_ms as i64, *event_id));
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(
                                        "shared_event_index insert error for {}: {}",
                                        event_id_b64,
                                        e
                                    );
                                }
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
                    let recorded_inserted = match recorded_stmt.execute(rusqlite::params![
                        &effective_recorded_by,
                        &event_id_b64,
                        recorded_at,
                        source_tag
                    ]) {
                        Ok(rows) => rows > 0,
                        Err(e) => {
                            tracing::warn!(
                                "recorded_events insert error for {}: {}",
                                event_id_b64,
                                e
                            );
                            continue;
                        }
                    };
                    // Enqueue for durable projection (atomicity boundary 1)
                    let priority_lane = if events::outer_semantic_type_code(blob)
                        == Some(events::EVENT_TYPE_FILE_SLICE)
                    {
                        2
                    } else {
                        1
                    };
                    if let Err(e) = enqueue_stmt.execute(rusqlite::params![
                        &effective_recorded_by,
                        &event_id_b64,
                        current_timestamp_ms(),
                        priority_lane,
                        created_at_ms as i64
                    ]) {
                        tracing::warn!("project_queue enqueue error for {}: {}", event_id_b64, e);
                    }

                    persist_output
                        .tenants_seen
                        .insert(effective_recorded_by.clone());
                    persist_output.persisted_event_ids.push(*event_id);
                    if recorded_inserted
                        && meta.share_scope == ShareScope::Shared
                        && meta.type_name != "endpoint_shared"
                    {
                        persist_output.live_hints.push(LiveHintEvent {
                            tenant_id: effective_recorded_by.clone(),
                            event_id: *event_id,
                            source_peer_id: source_peer_id_from_source_tag(source_tag),
                        });
                    }
                    if meta.share_scope == ShareScope::Shared && meta.type_name != "endpoint_shared"
                    {
                        if let Some(workspace_id) = if meta.type_name == "workspace" {
                            Some(event_id_b64.clone())
                        } else {
                            lookup_workspace_id(db, &effective_recorded_by)
                        } {
                            persist_output.shared_event_fanouts.push(SharedEventFanout {
                                origin_peer_id: effective_recorded_by.clone(),
                                workspace_id,
                                event_id: *event_id,
                            });
                        }
                    }
                } else {
                }
            } else {
            }
        } else {
        }
    }

    // Persist fanout entries durably inside this transaction so they
    // survive a crash between COMMIT and post-commit effects.
    if !persist_output.shared_event_fanouts.is_empty() {
        if let Err(e) = crate::state::shared_workspace_fanout::persist_pending_fanouts(
            db,
            &persist_output.shared_event_fanouts,
        ) {
            tracing::warn!("persist_pending_fanouts error: {}", e);
        }
    }

    for (workspace_id, items) in shared_index_inserts {
        if let Err(e) = crate::state::db::shared_event_merkle::enqueue_pending_inserts(
            db,
            &workspace_id,
            &items,
        ) {
            tracing::warn!(
                "shared_event_merkle pending insert error for workspace {}: {}",
                workspace_id,
                e
            );
        }
    }

    persist_output
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::crypto::{event_id_to_base64, hash_event};
    use crate::db::{
        open_in_memory,
        schema::create_tables,
        store::{SQL_INSERT_EVENT, SQL_INSERT_RECORDED_EVENT, SQL_INSERT_SHARED_EVENT_INDEX_ENTRY},
    };
    use crate::event_modules::{self, EncryptedEvent, ParsedEvent, EVENT_TYPE_FILE_SLICE};

    #[test]
    fn run_persist_phase_enqueues_encrypted_file_slice_as_bulk() {
        let db = open_in_memory().unwrap();
        create_tables(&db).unwrap();

        let mut shared_event_index_stmt = db.prepare(SQL_INSERT_SHARED_EVENT_INDEX_ENTRY).unwrap();
        let mut recorded_stmt = db.prepare(SQL_INSERT_RECORDED_EVENT).unwrap();
        let mut events_stmt = db.prepare(SQL_INSERT_EVENT).unwrap();
        let mut enqueue_stmt = db
            .prepare(
                "INSERT OR IGNORE INTO project_queue
                 (peer_id, event_id, available_at, priority_lane, priority_ts)
                 SELECT ?1, ?2, ?3, ?4, ?5
                 WHERE NOT EXISTS (SELECT 1 FROM valid_events WHERE peer_id=?1 AND event_id=?2)
                 AND NOT EXISTS (SELECT 1 FROM rejected_events WHERE peer_id=?1 AND event_id=?2)
                 AND NOT EXISTS (SELECT 1 FROM blocked_event_deps WHERE peer_id=?1 AND event_id=?2)",
            )
            .unwrap();
        let mut workspace_cache = HashMap::new();
        let blob = event_modules::encode_event(&ParsedEvent::Encrypted(EncryptedEvent {
            created_at_ms: 123,
            key_event_id: [7u8; 32],
            owner_event_id: event_modules::encrypted::NO_OWNER_EVENT_ID,
            inner_type_code: EVENT_TYPE_FILE_SLICE,
            nonce: [8u8; 12],
            ciphertext: vec![0u8; event_modules::file_slice::FILE_SLICE_WIRE_SIZE],
            auth_tag: [9u8; 16],
        }))
        .unwrap();
        let event_id = hash_event(&blob);
        let batch = vec![(
            event_id,
            blob,
            "peer-alpha".to_string(),
            "sync".to_string(),
            0,
            0,
        )];

        let output = run_persist_phase(
            &db,
            &batch,
            event_modules::registry(),
            &mut workspace_cache,
            &mut shared_event_index_stmt,
            &mut recorded_stmt,
            &mut events_stmt,
            &mut enqueue_stmt,
        );

        assert_eq!(output.persisted_event_ids, vec![event_id]);
        let priority_lane: i64 = db
            .query_row(
                "SELECT priority_lane
                 FROM project_queue
                 WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params!["peer-alpha", event_id_to_base64(&event_id)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(priority_lane, 2);
        assert_eq!(
            output.live_hints,
            vec![LiveHintEvent {
                tenant_id: "peer-alpha".to_string(),
                event_id,
                source_peer_id: None,
            }]
        );
    }
}
