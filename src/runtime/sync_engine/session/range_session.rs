use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use negentropy::{Id, NegentropyStorageVector};
use rusqlite::Connection;

use crate::crypto::{EventId, event_id_to_base64, hash_event};
use crate::db::hot_week_deps::{
    list_hot_week_dep_entries, should_include_week_deps, week_starts_for_window,
};
use crate::db::store::Store;
use crate::protocol::neg_id_to_event_id;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::receive_log::ReceiveLogWriter;
use crate::sync::session::windowing::{SyncWindow, SyncWindowKind};
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};

const RANGE_DATA_RECORD_PREFIX_LEN: usize = 4;

pub struct RangeReceiveResult {
    pub events_received: u64,
    pub bytes_received: u64,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharedSendOrderPolicy {
    PreserveInput,
    NewestFirst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedSyncEntryDecisionContext {
    window_kind: SyncWindowKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedSyncEntryRawRows {
    window_kind: SyncWindowKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedSyncEntryPlan {
    include_hot_week_deps: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelectedDepOrderRawRows {
    dep_is_selected: bool,
    dep_already_emitted: bool,
    dep_currently_visiting: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelectedDepOrderDecisionContext {
    dep_is_selected: bool,
    dep_already_emitted: bool,
    dep_currently_visiting: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectedDepOrderPlan {
    EmitDepBeforeRoot,
    SkipDepEdge,
}

fn decide_shared_send_order_policy(kind: SyncWindowKind) -> SharedSendOrderPolicy {
    match kind {
        SyncWindowKind::LastDay => SharedSendOrderPolicy::NewestFirst,
        SyncWindowKind::Full | SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks => {
            SharedSendOrderPolicy::PreserveInput
        }
    }
}

fn normalize_shared_sync_entry_context(
    raw_rows: SharedSyncEntryRawRows,
) -> SharedSyncEntryDecisionContext {
    SharedSyncEntryDecisionContext {
        window_kind: raw_rows.window_kind,
    }
}

fn decide_shared_sync_entry_plan(context: &SharedSyncEntryDecisionContext) -> SharedSyncEntryPlan {
    SharedSyncEntryPlan {
        include_hot_week_deps: should_include_week_deps(context.window_kind),
    }
}

fn normalize_selected_dep_order_context(
    raw_rows: SelectedDepOrderRawRows,
) -> SelectedDepOrderDecisionContext {
    SelectedDepOrderDecisionContext {
        dep_is_selected: raw_rows.dep_is_selected,
        dep_already_emitted: raw_rows.dep_already_emitted,
        dep_currently_visiting: raw_rows.dep_currently_visiting,
    }
}

fn decide_selected_dep_order_plan(
    context: &SelectedDepOrderDecisionContext,
) -> SelectedDepOrderPlan {
    if context.dep_is_selected && !context.dep_already_emitted && !context.dep_currently_visiting {
        SelectedDepOrderPlan::EmitDepBeforeRoot
    } else {
        SelectedDepOrderPlan::SkipDepEdge
    }
}

fn load_shared_index_entries(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<Vec<(i64, EventId)>, String> {
    let mut entries = Vec::new();

    let mut stmt = conn
        .prepare(
            "SELECT ts, id
             FROM shared_event_index
             WHERE workspace_id = ?1
               AND (?2 IS NULL OR ts >= ?2)
               AND (?3 IS NULL OR ts < ?3)
             ORDER BY ts, id",
        )
        .map_err(|e| format!("prepare shared index query: {e}"))?;
    let mut rows = stmt
        .query(rusqlite::params![
            workspace_id,
            range.ts_min(),
            range.ts_max_exclusive()
        ])
        .map_err(|e| format!("query shared index rows: {e}"))?;
    while let Some(row) = rows
        .next()
        .map_err(|e| format!("iterate shared index rows: {e}"))?
    {
        let ts: i64 = row
            .get(0)
            .map_err(|e| format!("read shared index ts: {e}"))?;
        let id_blob: Vec<u8> = row
            .get(1)
            .map_err(|e| format!("read shared index id: {e}"))?;
        if id_blob.len() != 32 {
            continue;
        }
        let mut event_id = [0u8; 32];
        event_id.copy_from_slice(&id_blob);
        entries.push((ts, event_id));
    }
    Ok(entries)
}

fn load_shared_sync_entries(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<Vec<(i64, EventId)>, String> {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();

    for (created_at_ms, event_id) in load_shared_index_entries(conn, workspace_id, range)? {
        if seen.insert(event_id) {
            entries.push((created_at_ms, event_id));
        }
    }

    let sync_entry_plan = decide_shared_sync_entry_plan(&normalize_shared_sync_entry_context(
        SharedSyncEntryRawRows {
            window_kind: range.kind,
        },
    ));
    if sync_entry_plan.include_hot_week_deps {
        let now_ms = range
            .ts_max_exclusive()
            .unwrap_or_else(crate::db::queue::current_timestamp_ms);
        let week_starts = week_starts_for_window(range, now_ms);
        for (created_at_ms, event_id) in list_hot_week_dep_entries(conn, workspace_id, &week_starts)
            .map_err(|e| format!("load hot week dep entries: {e}"))?
        {
            if seen.insert(event_id) {
                entries.push((created_at_ms, event_id));
            }
        }
    }

    entries.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(entries)
}

pub fn load_shared_event_index_slice(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<NegentropyStorageVector, String> {
    let mut storage = NegentropyStorageVector::new();
    for (ts, event_id) in load_shared_sync_entries(conn, workspace_id, range)? {
        storage
            .insert(ts.max(0) as u64, Id::from_byte_array(event_id))
            .map_err(|e| format!("insert negentropy vector item: {e}"))?;
    }
    storage
        .seal()
        .map_err(|e| format!("seal negentropy vector storage: {e}"))?;
    Ok(storage)
}

pub fn load_shared_send_batch(
    store: &Store<'_>,
    ids: &[EventId],
) -> Result<Vec<(EventId, Vec<u8>)>, String> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let base_blobs = store
        .get_shared_batch(ids)
        .map_err(|e| format!("load shared batch: {e}"))?;
    let mut ordered = Vec::with_capacity(ids.len());

    for event_id in ids {
        let Some(blob) = base_blobs.get(event_id) else {
            continue;
        };
        ordered.push((*event_id, blob.clone()));
    }

    Ok(ordered)
}

fn prioritize_send_order(
    store: &Store<'_>,
    range: SyncWindow,
    ids: &[EventId],
) -> Result<Vec<EventId>, String> {
    let order_policy = decide_shared_send_order_policy(range.kind);
    if matches!(order_policy, SharedSendOrderPolicy::PreserveInput) {
        return Ok(ids.to_vec());
    }

    let created_at_by_id = store
        .get_shared_created_at_batch(ids)
        .map_err(|e| format!("load shared created_at batch: {e}"))?;
    let mut ordered: Vec<EventId> = ids
        .iter()
        .filter(|event_id| created_at_by_id.contains_key(*event_id))
        .copied()
        .collect();
    ordered.sort_by(|left, right| {
        let left_ts = created_at_by_id.get(left).copied().unwrap_or_default();
        let right_ts = created_at_by_id.get(right).copied().unwrap_or_default();
        match order_policy {
            SharedSendOrderPolicy::NewestFirst => {
                right_ts.cmp(&left_ts).then_with(|| right.cmp(left))
            }
            SharedSendOrderPolicy::PreserveInput => left.cmp(right),
        }
    });
    Ok(ordered)
}

fn load_selected_direct_deps(
    conn: &Connection,
    workspace_id: &str,
    event_id: &EventId,
    selected_ids: &HashSet<EventId>,
    created_at_by_id: &HashMap<EventId, i64>,
    dep_cache: &mut HashMap<EventId, Vec<EventId>>,
) -> Result<Vec<EventId>, String> {
    if let Some(dep_ids) = dep_cache.get(event_id) {
        return Ok(dep_ids.clone());
    }

    let mut dep_ids = crate::db::dep_index::list_shared_event_deps(conn, workspace_id, event_id)
        .map_err(|e| format!("load shared event deps: {e}"))?
        .into_iter()
        .filter(|dep_id| selected_ids.contains(dep_id))
        .collect::<Vec<_>>();
    dep_ids.sort_by(|left, right| {
        let left_ts = created_at_by_id.get(left).copied().unwrap_or_default();
        let right_ts = created_at_by_id.get(right).copied().unwrap_or_default();
        left_ts.cmp(&right_ts).then_with(|| left.cmp(right))
    });
    dep_cache.insert(*event_id, dep_ids.clone());
    Ok(dep_ids)
}

fn visit_selected_send_order(
    conn: &Connection,
    workspace_id: &str,
    event_id: EventId,
    selected_ids: &HashSet<EventId>,
    created_at_by_id: &HashMap<EventId, i64>,
    dep_cache: &mut HashMap<EventId, Vec<EventId>>,
    emitted: &mut HashSet<EventId>,
    visiting: &mut HashSet<EventId>,
    ordered: &mut Vec<EventId>,
) -> Result<(), String> {
    if emitted.contains(&event_id) {
        return Ok(());
    }
    if !visiting.insert(event_id) {
        return Ok(());
    }

    for dep_id in load_selected_direct_deps(
        conn,
        workspace_id,
        &event_id,
        selected_ids,
        created_at_by_id,
        dep_cache,
    )? {
        let dep_plan = decide_selected_dep_order_plan(&normalize_selected_dep_order_context(
            SelectedDepOrderRawRows {
                dep_is_selected: selected_ids.contains(&dep_id),
                dep_already_emitted: emitted.contains(&dep_id),
                dep_currently_visiting: visiting.contains(&dep_id),
            },
        ));
        match dep_plan {
            SelectedDepOrderPlan::EmitDepBeforeRoot => {
                visit_selected_send_order(
                    conn,
                    workspace_id,
                    dep_id,
                    selected_ids,
                    created_at_by_id,
                    dep_cache,
                    emitted,
                    visiting,
                    ordered,
                )?;
            }
            SelectedDepOrderPlan::SkipDepEdge => continue,
        }
    }

    visiting.remove(&event_id);
    emitted.insert(event_id);
    ordered.push(event_id);
    Ok(())
}

fn order_requested_ids_for_send(
    conn: &Connection,
    store: &Store<'_>,
    workspace_id: &str,
    range: SyncWindow,
    requested_ids: &[EventId],
) -> Result<Vec<EventId>, String> {
    if requested_ids.is_empty() {
        return Ok(Vec::new());
    }

    let ordered_roots = prioritize_send_order(store, range, requested_ids)?;
    let selected_ids: HashSet<EventId> = requested_ids.iter().copied().collect();
    let selected_vec = requested_ids.to_vec();
    let created_at_by_id = store
        .get_shared_created_at_batch(&selected_vec)
        .map_err(|e| format!("load selected created_at batch: {e}"))?;

    let mut ordered = Vec::new();
    let mut emitted = HashSet::new();
    let mut visiting = HashSet::new();
    let mut dep_cache = HashMap::new();

    for event_id in ordered_roots {
        visit_selected_send_order(
            conn,
            workspace_id,
            event_id,
            &selected_ids,
            &created_at_by_id,
            &mut dep_cache,
            &mut emitted,
            &mut visiting,
            &mut ordered,
        )?;
    }

    Ok(ordered)
}

pub async fn send_have_events<S>(
    conn: &Connection,
    store: &Store<'_>,
    data_send: &mut S,
    have_ids: &[Id],
    _recorded_by: &str,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<(u64, u64), String>
where
    S: StreamSend,
{
    if have_ids.is_empty() {
        return Ok((0, 0));
    }

    let mut events_sent = 0u64;
    let mut bytes_sent = 0u64;
    let event_ids: Vec<EventId> = have_ids.iter().map(neg_id_to_event_id).collect();
    let event_ids = order_requested_ids_for_send(conn, store, workspace_id, range, &event_ids)?;
    for chunk in event_ids.chunks(64) {
        let ordered = load_shared_send_batch(store, chunk)?;
        let mut payload = Vec::new();
        for (_event_id, blob) in ordered {
            let blob_len = u32::try_from(blob.len())
                .map_err(|_| format!("range event too large: {} bytes", blob.len()))?;
            payload.extend_from_slice(&blob_len.to_le_bytes());
            payload.extend_from_slice(&blob);
            events_sent += 1;
            bytes_sent += blob.len() as u64;
        }
        if payload.is_empty() {
            continue;
        }
        data_send
            .send_bytes(&payload)
            .await
            .map_err(|e| format!("send range data chunk: {e}"))?;
    }
    data_send
        .flush()
        .await
        .map_err(|e| format!("flush range data stream: {e}"))?;
    Ok((events_sent, bytes_sent))
}

fn parse_next_blob_record(buffer: &[u8], offset: &mut usize) -> Result<Option<Vec<u8>>, String> {
    if *offset >= buffer.len() {
        return Ok(None);
    }
    if buffer.len() - *offset < RANGE_DATA_RECORD_PREFIX_LEN {
        return Ok(None);
    }
    let blob_len = u32::from_le_bytes(
        buffer[*offset..*offset + RANGE_DATA_RECORD_PREFIX_LEN]
            .try_into()
            .map_err(|_| "range data record length truncated".to_string())?,
    ) as usize;
    let record_len = RANGE_DATA_RECORD_PREFIX_LEN.saturating_add(blob_len);
    if buffer.len() - *offset < record_len {
        return Ok(None);
    }
    let blob_start = *offset + RANGE_DATA_RECORD_PREFIX_LEN;
    let blob_end = blob_start + blob_len;
    let blob = buffer[blob_start..blob_end].to_vec();
    *offset += record_len;
    Ok(Some(blob))
}

pub fn spawn_receive_log_task<R>(
    data_recv: R,
    db_path: String,
    recorded_by: String,
    session_id: u64,
    source_tag: String,
    idle_timeout: Duration,
    rx_capture: Option<SyncRunRxCapture>,
) -> tokio::task::JoinHandle<Result<RangeReceiveResult, String>>
where
    R: StreamRecv + Send + 'static,
{
    tokio::spawn(async move {
        let mut data_recv = data_recv;
        let mut writer = ReceiveLogWriter::open(&db_path, &recorded_by, session_id, &source_tag)?;
        let mut events_received = 0u64;
        let mut bytes_received = 0u64;
        let mut buffer = Vec::<u8>::with_capacity(64 * 1024);

        loop {
            let next = tokio::time::timeout(idle_timeout, data_recv.recv_chunk()).await;
            match next {
                Ok(Ok(chunk)) => {
                    buffer.extend_from_slice(&chunk);
                    let mut offset = 0usize;
                    while let Some(blob) = parse_next_blob_record(&buffer, &mut offset)? {
                        if let Some(capture) = &rx_capture {
                            capture.record_event_id_b64(event_id_to_base64(&hash_event(&blob)));
                        }
                        bytes_received += blob.len() as u64;
                        events_received += 1;
                        writer.append_blob(&blob)?;
                    }
                    if offset > 0 {
                        buffer.drain(..offset);
                    }
                }
                Ok(Err(ConnectionError::Closed)) => break,
                Ok(Err(_)) => break,
                Err(_) => break,
            }
        }

        Ok(RangeReceiveResult {
            events_received,
            bytes_received,
            path: writer.finish()?,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::event_pipeline_contract::IngestItem;
    use crate::crypto::hash_event;
    use crate::db::dep_index::replace_shared_event_deps;
    use crate::db::queue::current_timestamp_ms;
    use crate::db::schema::create_tables;
    use crate::db::store::{insert_event, insert_shared_event_index_entry_if_shared};
    use crate::db::{open_connection, open_in_memory};
    use crate::event_modules::{
        BenchDepEvent, MessageEvent, ParsedEvent, PeerSharedEvent, encode_event, endpoint_shared,
        registry::ShareScope,
    };
    use crate::state::pipeline::ingest_now;

    fn insert_shared_bench_dep(
        conn: &Connection,
        workspace_id: &str,
        created_at_ms: i64,
        dep_ids: Vec<EventId>,
        marker: u8,
    ) -> EventId {
        let blob = encode_event(&ParsedEvent::BenchDep(BenchDepEvent {
            created_at_ms: created_at_ms as u64,
            dep_ids,
            payload: [marker; 16],
        }))
        .unwrap();
        let event_id = hash_event(&blob);
        insert_event(
            conn,
            &event_id,
            "bench_dep_perf_testing",
            &blob,
            ShareScope::Shared,
            created_at_ms,
            created_at_ms,
        )
        .unwrap();
        insert_shared_event_index_entry_if_shared(
            conn,
            ShareScope::Shared,
            created_at_ms,
            &event_id,
            workspace_id,
            &blob,
        )
        .unwrap();
        event_id
    }

    fn make_ingest_batch(
        recorded_by: &str,
        source_tag: &str,
        ordered: &[(EventId, Vec<u8>)],
    ) -> Vec<IngestItem> {
        ordered
            .iter()
            .enumerate()
            .map(|(idx, (event_id, blob))| {
                (
                    *event_id,
                    blob.clone(),
                    recorded_by.to_string(),
                    source_tag.to_string(),
                    idx as i64,
                    idx as i64,
                )
            })
            .collect()
    }

    fn valid_event_count(conn: &Connection, recorded_by: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn is_valid(conn: &Connection, recorded_by: &str, event_id: &EventId) -> bool {
        conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, crate::crypto::event_id_to_base64(event_id)],
            |row| row.get(0),
        )
        .unwrap()
    }

    #[test]
    fn shared_send_batch_returns_requested_events_only() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let endpoint_event = endpoint_shared::deterministic_endpoint_shared_event([0x11; 32]);
        let endpoint_blob = encode_event(&endpoint_event).unwrap();
        let endpoint_event_id = hash_event(&endpoint_blob);
        insert_event(
            &conn,
            &endpoint_event_id,
            "endpoint_shared",
            &endpoint_blob,
            ShareScope::Shared,
            1,
            1,
        )
        .unwrap();

        let peer_shared_event = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: 2,
            public_key: [0x22; 32],
            user_event_id: [0x33; 32],
            endpoint_shared_event_id: endpoint_event_id,
            device_name: "device".to_string(),
        });
        let peer_shared_blob = encode_event(&peer_shared_event).unwrap();
        let peer_shared_event_id = hash_event(&peer_shared_blob);
        insert_event(
            &conn,
            &peer_shared_event_id,
            "peer_shared",
            &peer_shared_blob,
            ShareScope::Shared,
            2,
            2,
        )
        .unwrap();

        let store = Store::new(&conn);
        let ordered = load_shared_send_batch(&store, &[peer_shared_event_id]).unwrap();

        assert_eq!(ordered.len(), 1);
        assert_eq!(ordered[0].0, peer_shared_event_id);
    }

    #[test]
    fn shared_send_batch_preserves_requested_order_without_extra_deps() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let endpoint_event = endpoint_shared::deterministic_endpoint_shared_event([0x55; 32]);
        let endpoint_blob = encode_event(&endpoint_event).unwrap();
        let endpoint_event_id = hash_event(&endpoint_blob);
        insert_event(
            &conn,
            &endpoint_event_id,
            "endpoint_shared",
            &endpoint_blob,
            ShareScope::Shared,
            1,
            1,
        )
        .unwrap();

        let peer_shared_event = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: 2,
            public_key: [0x66; 32],
            user_event_id: [0x77; 32],
            endpoint_shared_event_id: endpoint_event_id,
            device_name: "device".to_string(),
        });
        let peer_shared_blob = encode_event(&peer_shared_event).unwrap();
        let peer_shared_event_id = hash_event(&peer_shared_blob);
        insert_event(
            &conn,
            &peer_shared_event_id,
            "peer_shared",
            &peer_shared_blob,
            ShareScope::Shared,
            2,
            2,
        )
        .unwrap();

        let store = Store::new(&conn);
        let ordered =
            load_shared_send_batch(&store, &[endpoint_event_id, peer_shared_event_id]).unwrap();

        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].0, endpoint_event_id);
        assert_eq!(ordered[1].0, peer_shared_event_id);
    }

    #[test]
    fn prioritize_send_order_matches_lane_policy() {
        assert_eq!(
            decide_shared_send_order_policy(SyncWindowKind::LastDay),
            SharedSendOrderPolicy::NewestFirst
        );
        assert_eq!(
            decide_shared_send_order_policy(SyncWindowKind::Full),
            SharedSendOrderPolicy::PreserveInput
        );

        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let first = ParsedEvent::Message(MessageEvent {
            created_at_ms: 10,
            workspace_id: [0x41; 32],
            author_id: [0x42; 32],
            content: "first".to_string(),
        });
        let second = ParsedEvent::Message(MessageEvent {
            created_at_ms: 20,
            workspace_id: [0x41; 32],
            author_id: [0x42; 32],
            content: "second".to_string(),
        });
        let first_blob = encode_event(&first).unwrap();
        let second_blob = encode_event(&second).unwrap();
        let first_id = hash_event(&first_blob);
        let second_id = hash_event(&second_blob);
        insert_event(
            &conn,
            &first_id,
            "message",
            &first_blob,
            ShareScope::Shared,
            10,
            10,
        )
        .unwrap();
        insert_event(
            &conn,
            &second_id,
            "message",
            &second_blob,
            ShareScope::Shared,
            20,
            20,
        )
        .unwrap();

        let store = Store::new(&conn);
        let hot_order = prioritize_send_order(
            &store,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(0),
                ts_max_exclusive_ms: None,
            },
            &[first_id, second_id],
        )
        .unwrap();

        assert_eq!(hot_order, vec![second_id, first_id]);
    }

    #[test]
    fn shared_sync_entry_plan_matches_hot_week_dep_policy() {
        assert_eq!(
            decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
                window_kind: SyncWindowKind::Full,
            }),
            SharedSyncEntryPlan {
                include_hot_week_deps: false,
            }
        );
        assert_eq!(
            decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
                window_kind: SyncWindowKind::LastDay,
            }),
            SharedSyncEntryPlan {
                include_hot_week_deps: true,
            }
        );
        assert_eq!(
            decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
                window_kind: SyncWindowKind::LastWeek,
            }),
            SharedSyncEntryPlan {
                include_hot_week_deps: true,
            }
        );
    }

    #[test]
    fn shared_sync_entry_normalizer_preserves_raw_rows_for_planner() {
        let raw = SharedSyncEntryRawRows {
            window_kind: SyncWindowKind::LastDay,
        };
        let context = normalize_shared_sync_entry_context(raw);
        assert_eq!(
            context,
            SharedSyncEntryDecisionContext {
                window_kind: SyncWindowKind::LastDay,
            }
        );
        assert_eq!(
            decide_shared_sync_entry_plan(&context),
            SharedSyncEntryPlan {
                include_hot_week_deps: true,
            }
        );
    }

    #[test]
    fn selected_dep_order_plan_emits_only_selected_unvisited_deps() {
        assert_eq!(
            decide_selected_dep_order_plan(&SelectedDepOrderDecisionContext {
                dep_is_selected: true,
                dep_already_emitted: false,
                dep_currently_visiting: false,
            }),
            SelectedDepOrderPlan::EmitDepBeforeRoot
        );
        assert_eq!(
            decide_selected_dep_order_plan(&SelectedDepOrderDecisionContext {
                dep_is_selected: false,
                dep_already_emitted: false,
                dep_currently_visiting: false,
            }),
            SelectedDepOrderPlan::SkipDepEdge
        );
        assert_eq!(
            decide_selected_dep_order_plan(&SelectedDepOrderDecisionContext {
                dep_is_selected: true,
                dep_already_emitted: true,
                dep_currently_visiting: false,
            }),
            SelectedDepOrderPlan::SkipDepEdge
        );
        assert_eq!(
            decide_selected_dep_order_plan(&SelectedDepOrderDecisionContext {
                dep_is_selected: true,
                dep_already_emitted: false,
                dep_currently_visiting: true,
            }),
            SelectedDepOrderPlan::SkipDepEdge
        );
    }

    #[test]
    fn selected_dep_order_plan_matches_all_boolean_cases() {
        for dep_is_selected in [false, true] {
            for dep_already_emitted in [false, true] {
                for dep_currently_visiting in [false, true] {
                    let context = SelectedDepOrderDecisionContext {
                        dep_is_selected,
                        dep_already_emitted,
                        dep_currently_visiting,
                    };
                    let expected = if dep_is_selected
                        && !dep_already_emitted
                        && !dep_currently_visiting
                    {
                        SelectedDepOrderPlan::EmitDepBeforeRoot
                    } else {
                        SelectedDepOrderPlan::SkipDepEdge
                    };
                    assert_eq!(decide_selected_dep_order_plan(&context), expected);
                }
            }
        }
    }

    #[test]
    fn selected_dep_order_normalizer_preserves_raw_rows_for_planner() {
        let raw = SelectedDepOrderRawRows {
            dep_is_selected: true,
            dep_already_emitted: false,
            dep_currently_visiting: false,
        };
        let context = normalize_selected_dep_order_context(raw);
        assert_eq!(
            context,
            SelectedDepOrderDecisionContext {
                dep_is_selected: true,
                dep_already_emitted: false,
                dep_currently_visiting: false,
            }
        );
        assert_eq!(
            decide_selected_dep_order_plan(&context),
            SelectedDepOrderPlan::EmitDepBeforeRoot
        );
    }

    #[test]
    fn load_shared_sync_entries_includes_hot_week_deps_for_last_day() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "workspace-bench-chain";
        let now_ms = current_timestamp_ms();
        let hot_created_at_ms = now_ms - 1_000;

        let root = insert_shared_bench_dep(&conn, workspace_id, 1, vec![], 1);
        let mid = insert_shared_bench_dep(&conn, workspace_id, 2, vec![root], 2);
        let leaf = insert_shared_bench_dep(&conn, workspace_id, hot_created_at_ms, vec![mid], 3);
        replace_shared_event_deps(&conn, workspace_id, &mid, &[root]).unwrap();
        replace_shared_event_deps(&conn, workspace_id, &leaf, &[mid]).unwrap();
        crate::db::hot_week_deps::track_valid_shared_event_deps(
            &conn,
            workspace_id,
            &leaf,
            hot_created_at_ms,
            now_ms,
        )
        .unwrap();

        let entries = load_shared_sync_entries(
            &conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(now_ms - (24 * 60 * 60 * 1000)),
                ts_max_exclusive_ms: Some(now_ms),
            },
        )
        .unwrap();
        let selected_ids = entries
            .into_iter()
            .map(|(_, event_id)| event_id)
            .collect::<Vec<_>>();
        assert_eq!(selected_ids, vec![root, mid, leaf]);

        let store = Store::new(&conn);
        let ordered = order_requested_ids_for_send(
            &conn,
            &store,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(now_ms - (24 * 60 * 60 * 1000)),
                ts_max_exclusive_ms: Some(now_ms),
            },
            &selected_ids,
        )
        .unwrap();

        assert_eq!(ordered, vec![root, mid, leaf]);
    }

    #[test]
    fn full_window_sync_entries_do_not_include_week_deps() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "workspace-full-no-deps";
        let now_ms = current_timestamp_ms();

        let root = insert_shared_bench_dep(&conn, workspace_id, 1, vec![], 1);
        let leaf = insert_shared_bench_dep(&conn, workspace_id, now_ms - 1_000, vec![root], 2);
        replace_shared_event_deps(&conn, workspace_id, &leaf, &[root]).unwrap();
        crate::db::hot_week_deps::track_valid_shared_event_deps(
            &conn,
            workspace_id,
            &leaf,
            now_ms - 1_000,
            now_ms,
        )
        .unwrap();

        let entries = load_shared_sync_entries(
            &conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::Full,
                ts_min_inclusive_ms: Some(0),
                ts_max_exclusive_ms: Some(now_ms - (12 * 7 * 24 * 60 * 60 * 1000)),
            },
        )
        .unwrap();

        let selected_ids = entries
            .into_iter()
            .map(|(_, event_id)| event_id)
            .collect::<Vec<_>>();
        assert_eq!(selected_ids, vec![root]);
    }

    #[test]
    fn order_requested_ids_sends_week_deps_before_root() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "workspace-bench-order";
        let now_ms = current_timestamp_ms();
        let hot_created_at_ms = now_ms - 1_000;

        let root = insert_shared_bench_dep(&conn, workspace_id, 1, vec![], 1);
        let mid = insert_shared_bench_dep(&conn, workspace_id, 2, vec![root], 2);
        let leaf = insert_shared_bench_dep(&conn, workspace_id, hot_created_at_ms, vec![mid], 3);
        replace_shared_event_deps(&conn, workspace_id, &mid, &[root]).unwrap();
        replace_shared_event_deps(&conn, workspace_id, &leaf, &[mid]).unwrap();
        crate::db::hot_week_deps::track_valid_shared_event_deps(
            &conn,
            workspace_id,
            &leaf,
            hot_created_at_ms,
            now_ms,
        )
        .unwrap();

        let selected_ids = load_shared_sync_entries(
            &conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(now_ms - (24 * 60 * 60 * 1000)),
                ts_max_exclusive_ms: Some(now_ms),
            },
        )
        .unwrap()
        .into_iter()
        .map(|(_, event_id)| event_id)
        .collect::<Vec<_>>();
        let store = Store::new(&conn);
        let ordered = order_requested_ids_for_send(
            &conn,
            &store,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(now_ms - (24 * 60 * 60 * 1000)),
                ts_max_exclusive_ms: Some(now_ms),
            },
            &selected_ids,
        )
        .unwrap();

        assert_eq!(ordered, vec![root, mid, leaf]);
    }

    #[test]
    fn week_dep_sync_entries_project_full_chain_in_one_round() {
        let dir = tempfile::tempdir().unwrap();
        let source_db_path = dir.path().join("source.db");
        let dest_db_path = dir.path().join("dest.db");

        let source_conn = open_connection(&source_db_path).unwrap();
        let dest_conn = open_connection(&dest_db_path).unwrap();
        create_tables(&source_conn).unwrap();
        create_tables(&dest_conn).unwrap();

        let workspace_id = "workspace-one-round";
        let now_ms = current_timestamp_ms();
        let mut all_ids = Vec::new();
        let mut prior = None;
        for idx in 0..128i64 {
            let dep_ids = prior.into_iter().collect::<Vec<_>>();
            let created_at_ms = if idx == 127 { now_ms - 1_000 } else { idx + 1 };
            let event_id = insert_shared_bench_dep(
                &source_conn,
                workspace_id,
                created_at_ms,
                dep_ids.clone(),
                (idx % 251) as u8,
            );
            if let Some(dep_id) = dep_ids.first() {
                replace_shared_event_deps(&source_conn, workspace_id, &event_id, &[*dep_id])
                    .unwrap();
            }
            all_ids.push(event_id);
            prior = Some(event_id);
        }
        let leaf = *all_ids.last().unwrap();
        crate::db::hot_week_deps::track_valid_shared_event_deps(
            &source_conn,
            workspace_id,
            &leaf,
            now_ms - 1_000,
            now_ms,
        )
        .unwrap();

        let selected_ids = load_shared_sync_entries(
            &source_conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(now_ms - (24 * 60 * 60 * 1000)),
                ts_max_exclusive_ms: Some(now_ms),
            },
        )
        .unwrap()
        .into_iter()
        .map(|(_, event_id)| event_id)
        .collect::<Vec<_>>();
        let store = Store::new(&source_conn);
        let ordered_ids = order_requested_ids_for_send(
            &source_conn,
            &store,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(now_ms - (24 * 60 * 60 * 1000)),
                ts_max_exclusive_ms: Some(now_ms),
            },
            &selected_ids,
        )
        .unwrap();
        assert_eq!(ordered_ids.len(), all_ids.len());

        let ordered = load_shared_send_batch(&store, &ordered_ids).unwrap();
        let dest_path = dest_db_path.to_string_lossy().to_string();
        let persisted = ingest_now(
            &dest_path,
            make_ingest_batch("tenant-a", "quic_recv:peer-z@test", &ordered),
        )
        .unwrap();

        assert_eq!(persisted, all_ids.len());
        assert_eq!(
            valid_event_count(&dest_conn, "tenant-a"),
            all_ids.len() as i64
        );
        assert!(is_valid(&dest_conn, "tenant-a", &leaf));
    }
}
