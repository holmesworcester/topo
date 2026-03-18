use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{event_id_to_base64, EventId};
use crate::db::store::lookup_workspace_id;
use crate::db::timeline::EventTimeline;
use crate::event_modules::{self as events, registry::EventRegistry, ShareScope};
use crate::state::live_hints::{source_peer_id_from_source_tag, LiveHintEvent};
use crate::state::shared_workspace_fanout::SharedEventFanout;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct PersistPhaseOutput {
    pub persisted_event_ids: Vec<EventId>,
    pub tenants_seen: HashSet<String>,
    /// Tenant → event_id_b64 for direct batch projection (bypasses project_queue).
    pub tenant_event_ids: HashMap<String, Vec<String>>,
    pub live_hints: Vec<LiveHintEvent>,
    pub shared_event_fanouts: Vec<SharedEventFanout>,
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Max rows per multi-row INSERT (stay under SQLite's 999 param limit).
/// events has 6 cols → 166 rows max. neg_items has 3 cols → 333. recorded 4 → 249. enqueue 5 → 199.
const MULTI_ROW_CHUNK_EVENTS: usize = 150;
const MULTI_ROW_CHUNK_NEG: usize = 300;
const MULTI_ROW_CHUNK_RECORDED: usize = 200;

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
    let now = current_timestamp_ms();
    let mut persist_output = PersistPhaseOutput {
        persisted_event_ids: Vec::with_capacity(batch.len()),
        tenants_seen: HashSet::new(),
        tenant_event_ids: HashMap::new(),
        live_hints: Vec::new(),
        shared_event_fanouts: Vec::new(),
    };

    // ── Accumulate rows ──
    // (event_id_b64, type_name, blob, share_scope, created_at, inserted_at)
    let mut ev_rows: Vec<(String, &str, &[u8], &str, i64, i64)> = Vec::with_capacity(batch.len());
    // (workspace_id, ts, id_bytes)
    let mut neg_rows: Vec<(String, i64, &[u8])> = Vec::new();
    // (peer_id, event_id_b64, recorded_at, source)
    let mut rec_rows: Vec<(&str, String, i64, &str)> = Vec::with_capacity(batch.len());
    // (peer_id, event_id_b64, available_at, priority_lane, priority_ts)
    let mut enq_rows: Vec<(&str, String, i64, i64, i64)> = Vec::with_capacity(batch.len());

    for (event_id, blob, recorded_by, source_tag, _received_at_ms) in batch {
        let event_id_b64 = event_id_to_base64(event_id);

        let Some(created_at_ms) = events::extract_created_at_ms(blob) else { continue };
        let Some(type_code) = events::extract_event_type(blob) else { continue };
        let Some(meta) = reg.lookup(type_code) else { continue };

        // neg_items for shared events
        if meta.share_scope == ShareScope::Shared {
            let ws_id = if let Some(cached) = workspace_cache.get(recorded_by) {
                Some(cached.clone())
            } else if meta.type_name == "workspace" {
                Some(event_id_b64.clone())
            } else if let Some(ws) = lookup_workspace_id(db, recorded_by) {
                workspace_cache.insert(recorded_by.clone(), ws.clone());
                Some(ws)
            } else {
                None
            };
            if let Some(ws_id) = ws_id {
                neg_rows.push((ws_id, created_at_ms as i64, event_id.as_slice()));
            }
        }

        ev_rows.push((
            event_id_b64.clone(),
            meta.type_name,
            blob.as_slice(),
            meta.share_scope.as_str(),
            created_at_ms as i64,
            now,
        ));

        rec_rows.push((recorded_by.as_str(), event_id_b64.clone(), now, source_tag.as_str()));

        let priority_lane: i64 = if events::outer_semantic_type_code(blob) == Some(events::EVENT_TYPE_FILE_SLICE) { 2 } else { 1 };
        enq_rows.push((recorded_by.as_str(), event_id_b64.clone(), now, priority_lane, created_at_ms as i64));

        persist_output.tenants_seen.insert(recorded_by.clone());
        persist_output.persisted_event_ids.push(*event_id);
        persist_output.tenant_event_ids.entry(recorded_by.clone()).or_default().push(event_id_b64.clone());

        if meta.share_scope == ShareScope::Shared {
            persist_output.live_hints.push(LiveHintEvent {
                tenant_id: recorded_by.clone(),
                event_id: *event_id,
                source_peer_id: source_peer_id_from_source_tag(source_tag),
            });
            if let Some(workspace_id) = if meta.type_name == "workspace" {
                Some(event_id_b64.clone())
            } else {
                lookup_workspace_id(db, recorded_by)
            } {
                persist_output.shared_event_fanouts.push(SharedEventFanout {
                    origin_peer_id: recorded_by.clone(),
                    workspace_id,
                    event_id: *event_id,
                });
            }
        }
    }

    // ── Flush: multi-row INSERT for events ──
    for chunk in ev_rows.chunks(MULTI_ROW_CHUNK_EVENTS) {
        let vals: String = (0..chunk.len()).map(|i| { let b = i*6+1; format!("(?{},?{},?{},?{},?{},?{})", b,b+1,b+2,b+3,b+4,b+5) }).collect::<Vec<_>>().join(",");
        let sql = format!("INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at) VALUES {}", vals);
        if let Ok(mut s) = db.prepare(&sql) {
            let mut idx = 1;
            for r in chunk {
                let _ = s.raw_bind_parameter(idx, r.0.as_str());
                let _ = s.raw_bind_parameter(idx+1, r.1);
                let _ = s.raw_bind_parameter(idx+2, r.2);
                let _ = s.raw_bind_parameter(idx+3, r.3);
                let _ = s.raw_bind_parameter(idx+4, r.4);
                let _ = s.raw_bind_parameter(idx+5, r.5);
                idx += 6;
            }
            if let Err(e) = s.raw_execute() { tracing::warn!("multi-row events: {}", e); }
        }
    }

    // ── Flush: multi-row INSERT for neg_items ──
    for chunk in neg_rows.chunks(MULTI_ROW_CHUNK_NEG) {
        let vals: String = (0..chunk.len()).map(|i| { let b = i*3+1; format!("(?{},?{},?{})", b,b+1,b+2) }).collect::<Vec<_>>().join(",");
        let sql = format!("INSERT OR IGNORE INTO neg_items (workspace_id, ts, id) VALUES {}", vals);
        if let Ok(mut s) = db.prepare(&sql) {
            let mut idx = 1;
            for r in chunk {
                let _ = s.raw_bind_parameter(idx, r.0.as_str());
                let _ = s.raw_bind_parameter(idx+1, r.1);
                let _ = s.raw_bind_parameter(idx+2, r.2);
                idx += 3;
            }
            if let Err(e) = s.raw_execute() { tracing::warn!("multi-row neg_items: {}", e); }
        }
    }

    // ── Flush: multi-row INSERT for recorded_events ──
    for chunk in rec_rows.chunks(MULTI_ROW_CHUNK_RECORDED) {
        let vals: String = (0..chunk.len()).map(|i| { let b = i*4+1; format!("(?{},?{},?{},?{})", b,b+1,b+2,b+3) }).collect::<Vec<_>>().join(",");
        let sql = format!("INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source) VALUES {}", vals);
        if let Ok(mut s) = db.prepare(&sql) {
            let mut idx = 1;
            for r in chunk {
                let _ = s.raw_bind_parameter(idx, r.0);
                let _ = s.raw_bind_parameter(idx+1, r.1.as_str());
                let _ = s.raw_bind_parameter(idx+2, r.2);
                let _ = s.raw_bind_parameter(idx+3, r.3);
                idx += 4;
            }
            if let Err(e) = s.raw_execute() { tracing::warn!("multi-row recorded: {}", e); }
        }
    }

    // Project queue enqueue skipped — projection handled directly in
    // post-commit effects via project_batch. The queue still handles
    // startup recovery and fanout retries.

    // Persist fanout entries durably inside this transaction
    if !persist_output.shared_event_fanouts.is_empty() {
        if let Err(e) = crate::state::shared_workspace_fanout::persist_pending_fanouts(
            db,
            &persist_output.shared_event_fanouts,
        ) {
            tracing::warn!("persist_pending_fanouts error: {}", e);
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
        store::{SQL_INSERT_EVENT, SQL_INSERT_NEG_ITEM, SQL_INSERT_RECORDED_EVENT},
    };
    use crate::event_modules::{self, EncryptedEvent, ParsedEvent, EVENT_TYPE_FILE_SLICE};

    #[test]
    fn run_persist_phase_enqueues_encrypted_file_slice_as_bulk() {
        let db = open_in_memory().unwrap();
        create_tables(&db).unwrap();

        let mut neg_items_stmt = db.prepare(SQL_INSERT_NEG_ITEM).unwrap();
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
        )];

        let output = run_persist_phase(
            &db,
            &batch,
            event_modules::registry(),
            &mut workspace_cache,
            &mut neg_items_stmt,
            &mut recorded_stmt,
            &mut events_stmt,
            &mut enqueue_stmt,
        );

        assert_eq!(output.persisted_event_ids, vec![event_id]);
        // Projection is now handled directly via project_batch in post-commit
        // effects, not via project_queue enqueue.
        let tenant_eids = output.tenant_event_ids.get("peer-alpha").expect("tenant events");
        assert!(tenant_eids.contains(&event_id_to_base64(&event_id)));
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
