use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use negentropy::{Id, NegentropyStorageVector};
use rusqlite::Connection;

use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::store::{SharedEventSummary, Store};
use crate::event_modules::{parse_event, ParsedEvent};
use crate::protocol::neg_id_to_event_id;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::receive_log::ReceiveLogWriter;
use crate::sync::session::windowing::SyncWindow;
use crate::tuning::{sync_dep_send_byte_cap, sync_dep_send_event_cap};
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};

const RANGE_DATA_RECORD_PREFIX_LEN: usize = 4;

pub struct RangeReceiveResult {
    pub events_received: u64,
    pub bytes_received: u64,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy)]
struct SharedDepSendBudget {
    remaining_dep_events: usize,
    remaining_dep_bytes: usize,
}

impl SharedDepSendBudget {
    fn new() -> Self {
        Self {
            remaining_dep_events: sync_dep_send_event_cap(),
            remaining_dep_bytes: sync_dep_send_byte_cap(),
        }
    }

    fn try_take_dep(&mut self, summary: SharedEventSummary) -> bool {
        let encoded_size = summary.encoded_size_bytes as usize;
        if self.remaining_dep_events == 0 || encoded_size > self.remaining_dep_bytes {
            return false;
        }
        self.remaining_dep_events -= 1;
        self.remaining_dep_bytes -= encoded_size;
        true
    }

    #[cfg(test)]
    fn new_for_tests(remaining_dep_events: usize, remaining_dep_bytes: usize) -> Self {
        Self {
            remaining_dep_events,
            remaining_dep_bytes,
        }
    }
}
pub fn load_shared_event_index_slice(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<NegentropyStorageVector, String> {
    let mut stmt = conn
        .prepare(
            "SELECT ts, id
             FROM shared_event_index
             WHERE workspace_id = :workspace_id
               AND (:ts_min IS NULL OR ts >= :ts_min)
               AND (:ts_max IS NULL OR ts < :ts_max)
             ORDER BY ts, id",
        )
        .map_err(|e| format!("prepare shared_event_index range query: {e}"))?;
    let mut rows = stmt
        .query(rusqlite::named_params! {
            ":workspace_id": workspace_id,
            ":ts_min": range.ts_min(),
            ":ts_max": range.ts_max_exclusive(),
        })
        .map_err(|e| format!("query shared_event_index range rows: {e}"))?;

    let mut storage = NegentropyStorageVector::new();
    while let Some(row) = rows
        .next()
        .map_err(|e| format!("iterate shared_event_index range rows: {e}"))?
    {
        let ts: i64 = row
            .get(0)
            .map_err(|e| format!("read shared_event_index ts: {e}"))?;
        let id_blob: Vec<u8> = row
            .get(1)
            .map_err(|e| format!("read shared_event_index id: {e}"))?;
        if id_blob.len() != 32 {
            continue;
        }
        let mut event_id = [0u8; 32];
        event_id.copy_from_slice(&id_blob);
        storage
            .insert(ts.max(0) as u64, Id::from_byte_array(event_id))
            .map_err(|e| format!("insert negentropy vector item: {e}"))?;
    }
    storage
        .seal()
        .map_err(|e| format!("seal negentropy vector storage: {e}"))?;
    Ok(storage)
}

fn parse_peer_shared_endpoint_dep(blob: &[u8]) -> Result<Option<EventId>, String> {
    match parse_event(blob).map_err(|e| format!("parse shared batch event: {e}"))? {
        ParsedEvent::PeerShared(peer_shared) => Ok(Some(peer_shared.endpoint_shared_event_id)),
        ParsedEvent::Signed(signed) => {
            let inner = parse_event(&signed.payload)
                .map_err(|e| format!("parse signed shared batch payload: {e}"))?;
            match inner {
                ParsedEvent::PeerShared(peer_shared) => {
                    Ok(Some(peer_shared.endpoint_shared_event_id))
                }
                _ => Ok(None),
            }
        }
        _ => Ok(None),
    }
}

pub fn load_shared_send_batch_with_endpoint_deps(
    store: &Store<'_>,
    ids: &[EventId],
) -> Result<Vec<(EventId, Vec<u8>)>, String> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let base_blobs = store
        .get_shared_batch(ids)
        .map_err(|e| format!("load shared batch: {e}"))?;

    let mut endpoint_dep_ids = Vec::new();
    let mut requested = std::collections::HashSet::with_capacity(ids.len());
    for event_id in ids {
        requested.insert(*event_id);
        let Some(blob) = base_blobs.get(event_id) else {
            continue;
        };
        if let Some(endpoint_dep_id) = parse_peer_shared_endpoint_dep(blob)? {
            if !requested.contains(&endpoint_dep_id) {
                endpoint_dep_ids.push(endpoint_dep_id);
            }
        }
    }
    endpoint_dep_ids.sort_unstable();
    endpoint_dep_ids.dedup();

    let dep_blobs = store
        .get_shared_batch(&endpoint_dep_ids)
        .map_err(|e| format!("load peer_shared endpoint dep batch: {e}"))?;

    let mut emitted = std::collections::HashSet::with_capacity(ids.len() + dep_blobs.len());
    let mut ordered = Vec::with_capacity(ids.len() + dep_blobs.len());

    for event_id in ids {
        let Some(blob) = base_blobs.get(event_id) else {
            continue;
        };
        if let Some(endpoint_dep_id) = parse_peer_shared_endpoint_dep(blob)? {
            if let Some(dep_blob) = dep_blobs.get(&endpoint_dep_id) {
                if emitted.insert(endpoint_dep_id) {
                    ordered.push((endpoint_dep_id, dep_blob.clone()));
                }
            }
        }
        if emitted.insert(*event_id) {
            ordered.push((*event_id, blob.clone()));
        }
    }

    Ok(ordered)
}

fn load_shared_summary_cached(
    store: &Store<'_>,
    event_id: &EventId,
    summary_cache: &mut HashMap<EventId, Option<SharedEventSummary>>,
) -> Result<Option<SharedEventSummary>, String> {
    if let Some(summary) = summary_cache.get(event_id) {
        return Ok(*summary);
    }
    let summary = store
        .get_shared_summary(event_id)
        .map_err(|e| format!("load shared summary: {e}"))?;
    summary_cache.insert(*event_id, summary);
    Ok(summary)
}

fn encrypted_wrapper_key_event_id(
    store: &Store<'_>,
    event_id: &EventId,
) -> Result<Option<EventId>, String> {
    let Some(blob) = store
        .get_shared(event_id)
        .map_err(|e| format!("load shared wrapper blob: {e}"))?
    else {
        return Ok(None);
    };
    let outer = parse_event(&blob).map_err(|e| format!("parse shared wrapper blob: {e}"))?;
    match outer {
        ParsedEvent::Encrypted(encrypted) => Ok(Some(encrypted.key_event_id)),
        ParsedEvent::Signed(signed) => {
            let inner = parse_event(&signed.payload)
                .map_err(|e| format!("parse signed inner wrapper blob: {e}"))?;
            match inner {
                ParsedEvent::Encrypted(encrypted) => Ok(Some(encrypted.key_event_id)),
                _ => Ok(None),
            }
        }
        _ => Ok(None),
    }
}

fn load_associated_shared_key_event_ids(
    conn: &Connection,
    recorded_by: &str,
    store: &Store<'_>,
    event_id: &EventId,
) -> Result<Vec<EventId>, String> {
    let Some(key_event_id) = encrypted_wrapper_key_event_id(store, event_id)? else {
        return Ok(Vec::new());
    };
    let mut stmt = conn
        .prepare(
            "SELECT ks.event_id
             FROM key_shared ks
             JOIN events e ON e.event_id = ks.event_id
             WHERE ks.recorded_by = ?1
               AND ks.key_event_id = ?2
               AND e.share_scope = 'shared'
             ORDER BY e.created_at, ks.event_id",
        )
        .map_err(|e| format!("prepare associated key_shared query: {e}"))?;
    let rows = stmt
        .query_map(
            rusqlite::params![recorded_by, crate::crypto::event_id_to_base64(&key_event_id)],
            |row| row.get::<_, String>(0),
        )
        .map_err(|e| format!("query associated key_shared rows: {e}"))?;
    let mut dep_ids = Vec::new();
    for row in rows {
        let event_id_b64 = row.map_err(|e| format!("read associated key_shared row: {e}"))?;
        if let Some(dep_id) = crate::crypto::event_id_from_base64(&event_id_b64) {
            dep_ids.push(dep_id);
        }
    }
    Ok(dep_ids)
}

fn load_ordered_shared_dep_ids(
    conn: &Connection,
    store: &Store<'_>,
    recorded_by: &str,
    workspace_id: &str,
    event_id: &EventId,
    dep_cache: &mut HashMap<EventId, Vec<EventId>>,
    summary_cache: &mut HashMap<EventId, Option<SharedEventSummary>>,
) -> Result<Vec<EventId>, String> {
    if let Some(dep_ids) = dep_cache.get(event_id) {
        return Ok(dep_ids.clone());
    }

    let mut dep_ids = crate::db::dep_index::list_shared_event_deps(conn, workspace_id, event_id)
        .map_err(|e| format!("load shared event deps: {e}"))?;
    dep_ids.extend(load_associated_shared_key_event_ids(
        conn,
        recorded_by,
        store,
        event_id,
    )?);
    dep_ids.sort_unstable();
    dep_ids.dedup();
    dep_ids.retain(|dep_id| {
        matches!(
            load_shared_summary_cached(store, dep_id, summary_cache),
            Ok(Some(_))
        )
    });
    dep_ids.sort_by(|left, right| {
        let left_ts = load_shared_summary_cached(store, left, summary_cache)
            .ok()
            .flatten()
            .map(|summary| summary.created_at_ms)
            .unwrap_or_default();
        let right_ts = load_shared_summary_cached(store, right, summary_cache)
            .ok()
            .flatten()
            .map(|summary| summary.created_at_ms)
            .unwrap_or_default();
        left_ts.cmp(&right_ts).then_with(|| left.cmp(right))
    });
    dep_cache.insert(*event_id, dep_ids.clone());
    Ok(dep_ids)
}

#[allow(clippy::too_many_arguments)]
fn visit_send_closure(
    conn: &Connection,
    store: &Store<'_>,
    recorded_by: &str,
    workspace_id: &str,
    event_id: EventId,
    root_ids: &HashSet<EventId>,
    emitted: &mut HashSet<EventId>,
    visiting: &mut HashSet<EventId>,
    ordered: &mut Vec<EventId>,
    dep_cache: &mut HashMap<EventId, Vec<EventId>>,
    summary_cache: &mut HashMap<EventId, Option<SharedEventSummary>>,
    budget: &mut SharedDepSendBudget,
) -> Result<(), String> {
    if emitted.contains(&event_id) {
        return Ok(());
    }
    if !visiting.insert(event_id) {
        return Ok(());
    }

    for dep_id in load_ordered_shared_dep_ids(
        conn,
        store,
        recorded_by,
        workspace_id,
        &event_id,
        dep_cache,
        summary_cache,
    )? {
        if emitted.contains(&dep_id) || visiting.contains(&dep_id) {
            continue;
        }
        if !root_ids.contains(&dep_id) {
            let Some(summary) = load_shared_summary_cached(store, &dep_id, summary_cache)? else {
                continue;
            };
            if !budget.try_take_dep(summary) {
                continue;
            }
        }
        visit_send_closure(
            conn,
            store,
            recorded_by,
            workspace_id,
            dep_id,
            root_ids,
            emitted,
            visiting,
            ordered,
            dep_cache,
            summary_cache,
            budget,
        )?;
    }

    visiting.remove(&event_id);
    emitted.insert(event_id);
    ordered.push(event_id);
    Ok(())
}

fn expand_requested_ids_with_shared_deps(
    conn: &Connection,
    store: &Store<'_>,
    recorded_by: &str,
    workspace_id: &str,
    requested_ids: &[EventId],
) -> Result<Vec<EventId>, String> {
    expand_requested_ids_with_shared_deps_and_budget(
        conn,
        store,
        recorded_by,
        workspace_id,
        requested_ids,
        SharedDepSendBudget::new(),
    )
}

fn expand_requested_ids_with_shared_deps_and_budget(
    conn: &Connection,
    store: &Store<'_>,
    recorded_by: &str,
    workspace_id: &str,
    requested_ids: &[EventId],
    mut budget: SharedDepSendBudget,
) -> Result<Vec<EventId>, String> {
    if requested_ids.is_empty() {
        return Ok(Vec::new());
    }

    let root_ids: HashSet<EventId> = requested_ids.iter().copied().collect();
    let mut ordered = Vec::new();
    let mut emitted = HashSet::new();
    let mut visiting = HashSet::new();
    let mut dep_cache = HashMap::new();
    let mut summary_cache = HashMap::new();

    for event_id in requested_ids.iter().copied() {
        visit_send_closure(
            conn,
            store,
            recorded_by,
            workspace_id,
            event_id,
            &root_ids,
            &mut emitted,
            &mut visiting,
            &mut ordered,
            &mut dep_cache,
            &mut summary_cache,
            &mut budget,
        )?;
    }
    Ok(ordered)
}

pub async fn send_have_events<S>(
    conn: &Connection,
    store: &Store<'_>,
    data_send: &mut S,
    have_ids: &[Id],
    recorded_by: &str,
    workspace_id: &str,
) -> Result<(u64, u64), String>
where
    S: StreamSend,
{
    if have_ids.is_empty() {
        return Ok((0, 0));
    }

    let mut events_sent = 0u64;
    let mut bytes_sent = 0u64;
    let requested_ids: Vec<EventId> = have_ids.iter().map(neg_id_to_event_id).collect();
    let event_ids =
        expand_requested_ids_with_shared_deps(conn, store, recorded_by, workspace_id, &requested_ids)?;
    for chunk in event_ids.chunks(64) {
        let ordered = load_shared_send_batch_with_endpoint_deps(store, chunk)?;
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
    use crate::db::{open_connection, open_in_memory};
    use crate::db::schema::create_tables;
    use crate::db::store::{insert_event, insert_shared_event_index_entry_if_shared};
    use crate::event_modules::{
        encode_event, endpoint_shared, registry::ShareScope, removal::frontier_hash_from_refs,
        BenchDepEvent, EncryptedEvent, KeySharedEvent, MessageEvent, ParsedEvent, PeerSharedEvent,
    };
    use crate::projection::encrypted::encrypt_event_blob;
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
    fn shared_send_batch_includes_endpoint_shared_before_peer_shared() {
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
        let ordered =
            load_shared_send_batch_with_endpoint_deps(&store, &[peer_shared_event_id]).unwrap();

        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].0, endpoint_event_id);
        assert_eq!(ordered[1].0, peer_shared_event_id);
    }

    #[test]
    fn shared_send_batch_dedupes_requested_endpoint_shared() {
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
        let ordered = load_shared_send_batch_with_endpoint_deps(
            &store,
            &[endpoint_event_id, peer_shared_event_id],
        )
        .unwrap();

        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].0, endpoint_event_id);
        assert_eq!(ordered[1].0, peer_shared_event_id);
    }

    #[test]
    fn expand_requested_ids_includes_recursive_shared_deps_before_root() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let recorded_by = "tenant-a";
        let workspace_id = "workspace-bench-chain";

        let root = insert_shared_bench_dep(&conn, workspace_id, 1, vec![], 1);
        let mid = insert_shared_bench_dep(&conn, workspace_id, 2, vec![root], 2);
        let leaf = insert_shared_bench_dep(&conn, workspace_id, 3, vec![mid], 3);
        replace_shared_event_deps(&conn, workspace_id, &mid, &[root]).unwrap();
        replace_shared_event_deps(&conn, workspace_id, &leaf, &[mid]).unwrap();

        let store = Store::new(&conn);
        let ordered = expand_requested_ids_with_shared_deps(
            &conn,
            &store,
            recorded_by,
            workspace_id,
            &[leaf],
        )
        .unwrap();

        assert_eq!(ordered, vec![root, mid, leaf]);
    }

    #[test]
    fn expand_requested_ids_respects_dep_send_event_cap() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let recorded_by = "tenant-a";
        let workspace_id = "workspace-bench-cap";

        let root = insert_shared_bench_dep(&conn, workspace_id, 1, vec![], 1);
        let dep_2 = insert_shared_bench_dep(&conn, workspace_id, 2, vec![root], 2);
        let dep_3 = insert_shared_bench_dep(&conn, workspace_id, 3, vec![dep_2], 3);
        let leaf = insert_shared_bench_dep(&conn, workspace_id, 4, vec![dep_3], 4);
        replace_shared_event_deps(&conn, workspace_id, &dep_2, &[root]).unwrap();
        replace_shared_event_deps(&conn, workspace_id, &dep_3, &[dep_2]).unwrap();
        replace_shared_event_deps(&conn, workspace_id, &leaf, &[dep_3]).unwrap();

        let store = Store::new(&conn);
        let ordered = expand_requested_ids_with_shared_deps_and_budget(
            &conn,
            &store,
            recorded_by,
            workspace_id,
            &[leaf],
            SharedDepSendBudget::new_for_tests(2, 1024 * 1024),
        )
        .unwrap();

        assert_eq!(ordered, vec![dep_2, dep_3, leaf]);
    }

    #[test]
    fn expand_requested_ids_includes_associated_key_shared_events() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let recorded_by = "tenant-a";
        let workspace_id = "workspace-associated-keys";

        let key_event_id = [0x44; 32];
        let message = ParsedEvent::Message(MessageEvent {
            created_at_ms: 10,
            workspace_id: [0x55; 32],
            author_id: [0x66; 32],
            content: "hello".to_string(),
        });
        let inner_blob = encode_event(&message).unwrap();
        let (nonce, ciphertext, auth_tag) = encrypt_event_blob(&[0x77; 32], &inner_blob).unwrap();
        let encrypted_blob = encode_event(&ParsedEvent::Encrypted(EncryptedEvent {
            created_at_ms: 10,
            key_event_id,
            inner_type_code: message.event_type_code(),
            nonce,
            ciphertext,
            auth_tag,
        }))
        .unwrap();
        let encrypted_event_id = hash_event(&encrypted_blob);
        insert_event(
            &conn,
            &encrypted_event_id,
            "encrypted",
            &encrypted_blob,
            ShareScope::Shared,
            10,
            10,
        )
        .unwrap();
        insert_shared_event_index_entry_if_shared(
            &conn,
            ShareScope::Shared,
            10,
            &encrypted_event_id,
            workspace_id,
        )
        .unwrap();

        let key_shared = ParsedEvent::KeyShared(KeySharedEvent {
            created_at_ms: 5,
            key_event_id,
            frontier_count: 0,
            frontier_ref_1: [0; 32],
            frontier_ref_2: [0; 32],
            frontier_ref_3: [0; 32],
            frontier_ref_4: [0; 32],
            frontier_hash: frontier_hash_from_refs(&[]),
            delivery_target_id: [0x88; 32],
            recipient_event_id: [0x99; 32],
            unwrap_key_event_id: [0xAA; 32],
            wrapped_key: [0xBB; 32],
        });
        let key_shared_blob = encode_event(&key_shared).unwrap();
        let key_shared_event_id = hash_event(&key_shared_blob);
        insert_event(
            &conn,
            &key_shared_event_id,
            "key_shared",
            &key_shared_blob,
            ShareScope::Shared,
            5,
            5,
        )
        .unwrap();
        insert_shared_event_index_entry_if_shared(
            &conn,
            ShareScope::Shared,
            5,
            &key_shared_event_id,
            workspace_id,
        )
        .unwrap();
        conn.execute(
            "INSERT INTO key_shared
             (recorded_by, event_id, key_event_id, frontier_count, frontier_ref_1, frontier_ref_2, frontier_ref_3, frontier_ref_4, frontier_hash, delivery_target_id, recipient_event_id, wrapped_key)
             VALUES (?1, ?2, ?3, 0, ?4, ?4, ?4, ?4, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                recorded_by,
                crate::crypto::event_id_to_base64(&key_shared_event_id),
                crate::crypto::event_id_to_base64(&key_event_id),
                crate::crypto::event_id_to_base64(&[0u8; 32]),
                crate::crypto::event_id_to_base64(&[0x88; 32]),
                crate::crypto::event_id_to_base64(&[0x99; 32]),
                vec![0xBBu8; 32],
            ],
        )
        .unwrap();

        let store = Store::new(&conn);
        let ordered = expand_requested_ids_with_shared_deps(
            &conn,
            &store,
            recorded_by,
            workspace_id,
            &[encrypted_event_id],
        )
        .unwrap();

        assert_eq!(ordered, vec![key_shared_event_id, encrypted_event_id]);
    }

    #[test]
    fn expanded_dep_send_projects_full_chain_in_one_round() {
        let dir = tempfile::tempdir().unwrap();
        let source_db_path = dir.path().join("source.db");
        let dest_db_path = dir.path().join("dest.db");

        let source_conn = open_connection(&source_db_path).unwrap();
        let dest_conn = open_connection(&dest_db_path).unwrap();
        create_tables(&source_conn).unwrap();
        create_tables(&dest_conn).unwrap();

        let workspace_id = "workspace-one-round";
        let mut all_ids = Vec::new();
        let mut prior = None;
        for idx in 0..128i64 {
            let dep_ids = prior.into_iter().collect::<Vec<_>>();
            let event_id = insert_shared_bench_dep(
                &source_conn,
                workspace_id,
                idx + 1,
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

        let store = Store::new(&source_conn);
        let ordered_ids = expand_requested_ids_with_shared_deps(
            &source_conn,
            &store,
            "tenant-a",
            workspace_id,
            &[leaf],
        )
        .unwrap();
        assert_eq!(ordered_ids.len(), all_ids.len());

        let ordered = load_shared_send_batch_with_endpoint_deps(&store, &ordered_ids).unwrap();
        let dest_path = dest_db_path.to_string_lossy().to_string();
        let persisted = ingest_now(
            &dest_path,
            make_ingest_batch("tenant-a", "quic_recv:peer-z@test", &ordered),
        )
        .unwrap();

        assert_eq!(persisted, all_ids.len());
        assert_eq!(valid_event_count(&dest_conn, "tenant-a"), all_ids.len() as i64);
        assert!(is_valid(&dest_conn, "tenant-a", &leaf));
    }
}
