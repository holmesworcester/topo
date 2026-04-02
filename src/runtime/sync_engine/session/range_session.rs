use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

use negentropy::{Id, NegentropyStorageVector};
use rusqlite::Connection;

use crate::crypto::{event_id_from_base64, event_id_to_base64, hash_event, EventId};
use crate::db::store::Store;
use crate::event_modules::parse_event;
use crate::protocol::neg_id_to_event_id;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::receive_log::ReceiveLogWriter;
use crate::sync::session::windowing::SyncWindow;
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};
use crate::tuning::{sync_dep_prefetch_byte_cap, sync_dep_prefetch_event_cap};

const RANGE_DATA_RECORD_PREFIX_LEN: usize = 4;
const SEND_HAVE_ROOT_BATCH_SIZE: usize = 64;

pub struct RangeReceiveResult {
    pub events_received: u64,
    pub bytes_received: u64,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct SharedSendRecord {
    blob: Vec<u8>,
    created_at_ms: u64,
    dep_ids: Vec<EventId>,
}

impl SharedSendRecord {
    fn from_blob(blob: Vec<u8>) -> Result<Self, String> {
        let parsed = parse_event(&blob).map_err(|e| format!("parse shared batch event: {e}"))?;
        let created_at_ms = parsed.created_at_ms();
        let dep_ids = parsed
            .dep_field_values()
            .into_iter()
            .map(|(_, dep_id)| dep_id)
            .filter(|dep_id| !is_zero_event_id(dep_id))
            .collect();
        Ok(Self {
            blob,
            created_at_ms,
            dep_ids,
        })
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SharedSendBudget {
    remaining_dep_events: usize,
    remaining_dep_bytes: usize,
}

impl SharedSendBudget {
    pub(crate) fn from_tuning() -> Self {
        Self {
            remaining_dep_events: sync_dep_prefetch_event_cap(),
            remaining_dep_bytes: sync_dep_prefetch_byte_cap(),
        }
    }

    #[cfg(test)]
    fn new_for_tests(dep_events: usize, dep_bytes: usize) -> Self {
        Self {
            remaining_dep_events: dep_events,
            remaining_dep_bytes: dep_bytes,
        }
    }

    fn try_take_prefetch(&mut self, blob_len: usize) -> bool {
        if self.remaining_dep_events == 0 || self.remaining_dep_bytes < blob_len {
            return false;
        }
        self.remaining_dep_events -= 1;
        self.remaining_dep_bytes -= blob_len;
        true
    }
}

#[derive(Debug, Default)]
pub(crate) struct SharedSendBatch {
    pub(crate) ordered: Vec<(EventId, Vec<u8>)>,
    prefetched_dep_events: usize,
    prefetched_dep_bytes: u64,
}

fn is_zero_event_id(event_id: &EventId) -> bool {
    event_id.iter().all(|byte| *byte == 0)
}

fn sort_ids_by_recency(ids: &mut [EventId], cache: &HashMap<EventId, SharedSendRecord>) {
    ids.sort_by(|left, right| {
        let left_created_at = cache
            .get(left)
            .map(|record| record.created_at_ms)
            .unwrap_or(0);
        let right_created_at = cache
            .get(right)
            .map(|record| record.created_at_ms)
            .unwrap_or(0);
        right_created_at
            .cmp(&left_created_at)
            .then_with(|| right.cmp(left))
    });
}

fn cache_shared_records(
    store: &Store<'_>,
    cache: &mut HashMap<EventId, SharedSendRecord>,
    ids: &[EventId],
) -> Result<(), String> {
    let mut missing = Vec::new();
    let mut queued = HashSet::new();
    for event_id in ids {
        if cache.contains_key(event_id) || !queued.insert(*event_id) {
            continue;
        }
        missing.push(*event_id);
    }
    if missing.is_empty() {
        return Ok(());
    }

    let blobs = store
        .get_shared_batch(&missing)
        .map_err(|e| format!("load shared batch: {e}"))?;
    for (event_id, blob) in blobs {
        cache.insert(event_id, SharedSendRecord::from_blob(blob)?);
    }
    Ok(())
}

fn append_shared_event_with_prefetched_deps(
    store: &Store<'_>,
    event_id: EventId,
    cache: &mut HashMap<EventId, SharedSendRecord>,
    emitted: &mut HashSet<EventId>,
    visiting: &mut HashSet<EventId>,
    budget: &mut SharedSendBudget,
    batch: &mut SharedSendBatch,
    requested_root: bool,
) -> Result<(), String> {
    if emitted.contains(&event_id) {
        return Ok(());
    }
    if !visiting.insert(event_id) {
        return Ok(());
    }

    cache_shared_records(store, cache, &[event_id])?;
    let Some(record) = cache.get(&event_id).cloned() else {
        visiting.remove(&event_id);
        return Ok(());
    };

    if !requested_root && !budget.try_take_prefetch(record.blob.len()) {
        visiting.remove(&event_id);
        return Ok(());
    }
    if !requested_root {
        batch.prefetched_dep_events = batch.prefetched_dep_events.saturating_add(1);
        batch.prefetched_dep_bytes = batch
            .prefetched_dep_bytes
            .saturating_add(record.blob.len() as u64);
    }

    let mut dep_ids = record
        .dep_ids
        .iter()
        .copied()
        .filter(|dep_id| !emitted.contains(dep_id))
        .collect::<Vec<_>>();
    cache_shared_records(store, cache, &dep_ids)?;
    dep_ids.retain(|dep_id| cache.contains_key(dep_id) && !emitted.contains(dep_id));
    sort_ids_by_recency(&mut dep_ids, cache);
    for dep_id in dep_ids {
        append_shared_event_with_prefetched_deps(
            store, dep_id, cache, emitted, visiting, budget, batch, false,
        )?;
    }

    if emitted.insert(event_id) {
        batch.ordered.push((event_id, record.blob));
    }
    visiting.remove(&event_id);
    Ok(())
}

pub(crate) fn load_shared_send_batch_with_prefetched_deps(
    store: &Store<'_>,
    ids: &[EventId],
    emitted: &mut HashSet<EventId>,
    budget: &mut SharedSendBudget,
) -> Result<SharedSendBatch, String> {
    if ids.is_empty() {
        return Ok(SharedSendBatch::default());
    }

    let mut cache = HashMap::new();
    cache_shared_records(store, &mut cache, ids)?;

    let mut requested_ids = ids
        .iter()
        .copied()
        .filter(|event_id| cache.contains_key(event_id) && !emitted.contains(event_id))
        .collect::<Vec<_>>();
    sort_ids_by_recency(&mut requested_ids, &cache);

    let mut visiting = HashSet::new();
    let mut batch = SharedSendBatch::default();
    for event_id in requested_ids {
        append_shared_event_with_prefetched_deps(
            store,
            event_id,
            &mut cache,
            emitted,
            &mut visiting,
            budget,
            &mut batch,
            true,
        )?;
    }

    Ok(batch)
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

pub fn load_claim_index_slice(
    conn: &Connection,
    workspace_id: &str,
    shard_start_ms: i64,
    now_ms: i64,
) -> Result<NegentropyStorageVector, String> {
    let claim_ids =
        crate::db::dep_claims::list_live_claim_ids(conn, workspace_id, shard_start_ms, now_ms)
            .map_err(|e| format!("load dep_claims shard rows: {e}"))?;
    let mut storage = NegentropyStorageVector::new();
    for event_id in claim_ids {
        storage
            .insert(0, Id::from_byte_array(event_id))
            .map_err(|e| format!("insert dep claim negentropy item: {e}"))?;
    }
    storage
        .seal()
        .map_err(|e| format!("seal dep claim negentropy storage: {e}"))?;
    Ok(storage)
}

pub fn load_shared_object_index_slice(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
    claim_shard_starts: &[i64],
    now_ms: i64,
) -> Result<NegentropyStorageVector, String> {
    let mut entries = Vec::<(u64, EventId)>::new();
    let mut seen = HashSet::<EventId>::new();

    let mut base_stmt = conn
        .prepare(
            "SELECT ts, id
             FROM shared_event_index
             WHERE workspace_id = :workspace_id
               AND (:ts_min IS NULL OR ts >= :ts_min)
               AND (:ts_max IS NULL OR ts < :ts_max)
             ORDER BY ts, id",
        )
        .map_err(|e| format!("prepare shared object range query: {e}"))?;
    let mut base_rows = base_stmt
        .query(rusqlite::named_params! {
            ":workspace_id": workspace_id,
            ":ts_min": range.ts_min(),
            ":ts_max": range.ts_max_exclusive(),
        })
        .map_err(|e| format!("query shared object range rows: {e}"))?;
    while let Some(row) = base_rows
        .next()
        .map_err(|e| format!("iterate shared object range rows: {e}"))?
    {
        let ts: i64 = row
            .get(0)
            .map_err(|e| format!("read shared object ts: {e}"))?;
        let id_blob: Vec<u8> = row
            .get(1)
            .map_err(|e| format!("read shared object id: {e}"))?;
        if id_blob.len() != 32 {
            continue;
        }
        let mut event_id = [0u8; 32];
        event_id.copy_from_slice(&id_blob);
        if seen.insert(event_id) {
            entries.push((ts.max(0) as u64, event_id));
        }
    }

    let mut claim_stmt = conn
        .prepare(
            "SELECT e.created_at, dc.event_id
             FROM dep_claims dc
             JOIN events e ON e.event_id = dc.event_id
             WHERE dc.workspace_id = ?1
               AND dc.shard_start_ms = ?2
               AND (dc.strength >= 2 OR dc.expires_at_ms IS NULL OR dc.expires_at_ms > ?3)
               AND e.share_scope = 'shared'
             ORDER BY e.created_at, dc.event_id",
        )
        .map_err(|e| format!("prepare dep-claimed object query: {e}"))?;
    for shard_start_ms in claim_shard_starts {
        let mut claim_rows = claim_stmt
            .query(rusqlite::params![workspace_id, shard_start_ms, now_ms])
            .map_err(|e| format!("query dep-claimed object rows: {e}"))?;
        while let Some(row) = claim_rows
            .next()
            .map_err(|e| format!("iterate dep-claimed object rows: {e}"))?
        {
            let ts: i64 = row
                .get(0)
                .map_err(|e| format!("read dep-claimed object ts: {e}"))?;
            let event_id_b64: String = row
                .get(1)
                .map_err(|e| format!("read dep-claimed object id: {e}"))?;
            let Some(event_id) = event_id_from_base64(&event_id_b64) else {
                continue;
            };
            if seen.insert(event_id) {
                entries.push((ts.max(0) as u64, event_id));
            }
        }
    }

    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let mut storage = NegentropyStorageVector::new();
    for (ts, event_id) in entries {
        storage
            .insert(ts, Id::from_byte_array(event_id))
            .map_err(|e| format!("insert shared object negentropy item: {e}"))?;
    }
    storage
        .seal()
        .map_err(|e| format!("seal shared object negentropy storage: {e}"))?;
    Ok(storage)
}

pub async fn send_have_events<S>(
    store: &Store<'_>,
    data_send: &mut S,
    have_ids: &[Id],
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
    let mut emitted = HashSet::new();
    let mut budget = SharedSendBudget::from_tuning();
    for chunk in event_ids.chunks(SEND_HAVE_ROOT_BATCH_SIZE) {
        let batch =
            load_shared_send_batch_with_prefetched_deps(store, chunk, &mut emitted, &mut budget)?;
        let mut payload = Vec::new();
        for (_event_id, blob) in batch.ordered {
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
    use crate::db::schema::create_tables;
    use crate::db::store::{insert_event, insert_shared_event_index_entry_if_shared};
    use crate::db::{open_connection, open_in_memory};
    use crate::event_modules::bench_dep::BenchDepEvent;
    use crate::event_modules::{encode_event, registry::ShareScope, ParsedEvent};
    use crate::state::{dependency_fetch, pipeline::ingest_now};
    use negentropy::NegentropyStorageBase;

    fn insert_shared_blob(conn: &Connection, blob: &[u8], created_at_ms: i64) -> EventId {
        let event_id = hash_event(blob);
        insert_event(
            conn,
            &event_id,
            "bench_dep_perf_testing",
            blob,
            ShareScope::Shared,
            created_at_ms,
            created_at_ms,
        )
        .unwrap();
        event_id
    }

    fn insert_indexed_shared_blob(
        conn: &Connection,
        workspace_id: &str,
        blob: &[u8],
        created_at_ms: i64,
    ) -> EventId {
        let event_id = insert_shared_blob(conn, blob, created_at_ms);
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

    fn storage_ids(storage: &NegentropyStorageVector) -> Vec<EventId> {
        let mut ids = Vec::new();
        let size = storage.size().unwrap();
        for idx in 0..size {
            let item = storage.get_item(idx).unwrap().expect("storage item");
            ids.push(*item.get_id().as_bytes());
        }
        ids
    }

    fn make_bench_dep_blob(created_at_ms: u64, dep_ids: Vec<EventId>, marker: u8) -> Vec<u8> {
        encode_event(&ParsedEvent::BenchDep(BenchDepEvent {
            created_at_ms,
            dep_ids,
            payload: [marker; 16],
        }))
        .unwrap()
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
    fn shared_send_batch_includes_direct_dependency_before_root() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let dep_event_id = insert_shared_blob(&conn, &make_bench_dep_blob(1, vec![], 1), 1);
        let root_event_id =
            insert_shared_blob(&conn, &make_bench_dep_blob(2, vec![dep_event_id], 2), 2);

        let store = Store::new(&conn);
        let mut emitted = HashSet::new();
        let mut budget = SharedSendBudget::new_for_tests(8, 1024 * 1024);
        let ordered = load_shared_send_batch_with_prefetched_deps(
            &store,
            &[root_event_id],
            &mut emitted,
            &mut budget,
        )
        .unwrap()
        .ordered;

        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].0, dep_event_id);
        assert_eq!(ordered[1].0, root_event_id);
    }

    #[test]
    fn shared_send_batch_dedupes_requested_dependency() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let dep_event_id = insert_shared_blob(&conn, &make_bench_dep_blob(1, vec![], 1), 1);
        let root_event_id =
            insert_shared_blob(&conn, &make_bench_dep_blob(2, vec![dep_event_id], 2), 2);

        let store = Store::new(&conn);
        let mut emitted = HashSet::new();
        let mut budget = SharedSendBudget::new_for_tests(8, 1024 * 1024);
        let ordered = load_shared_send_batch_with_prefetched_deps(
            &store,
            &[dep_event_id, root_event_id],
            &mut emitted,
            &mut budget,
        )
        .unwrap()
        .ordered;

        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].0, dep_event_id);
        assert_eq!(ordered[1].0, root_event_id);
    }

    #[test]
    fn shared_send_batch_prefetches_recursive_bench_dep_chain() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let root = insert_shared_blob(&conn, &make_bench_dep_blob(1, vec![], 1), 1);
        let mid = insert_shared_blob(&conn, &make_bench_dep_blob(2, vec![root], 2), 2);
        let leaf = insert_shared_blob(&conn, &make_bench_dep_blob(3, vec![mid], 3), 3);

        let store = Store::new(&conn);
        let mut emitted = HashSet::new();
        let mut budget = SharedSendBudget::new_for_tests(8, 1024 * 1024);
        let batch =
            load_shared_send_batch_with_prefetched_deps(&store, &[leaf], &mut emitted, &mut budget)
                .unwrap();

        assert_eq!(batch.prefetched_dep_events, 2);
        assert_eq!(
            batch
                .ordered
                .iter()
                .map(|(event_id, _)| *event_id)
                .collect::<Vec<_>>(),
            vec![root, mid, leaf]
        );
    }

    #[test]
    fn shared_send_batch_respects_prefetch_event_cap() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let root = insert_shared_blob(&conn, &make_bench_dep_blob(1, vec![], 1), 1);
        let dep_2 = insert_shared_blob(&conn, &make_bench_dep_blob(2, vec![root], 2), 2);
        let dep_3 = insert_shared_blob(&conn, &make_bench_dep_blob(3, vec![dep_2], 3), 3);
        let leaf = insert_shared_blob(&conn, &make_bench_dep_blob(4, vec![dep_3], 4), 4);

        let store = Store::new(&conn);
        let mut emitted = HashSet::new();
        let mut budget = SharedSendBudget::new_for_tests(2, 1024 * 1024);
        let batch =
            load_shared_send_batch_with_prefetched_deps(&store, &[leaf], &mut emitted, &mut budget)
                .unwrap();

        assert_eq!(batch.prefetched_dep_events, 2);
        assert_eq!(
            batch
                .ordered
                .iter()
                .map(|(event_id, _)| *event_id)
                .collect::<Vec<_>>(),
            vec![dep_2, dep_3, leaf]
        );
    }

    #[test]
    fn claim_index_slice_skips_expired_soft_claims() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "ws";
        let shard_start_ms = crate::db::dep_claims::utc_day_start_ms(2 * 24 * 60 * 60 * 1000);
        let live_soft = [1u8; 32];
        let expired_soft = [2u8; 32];
        let hard = [3u8; 32];
        crate::db::dep_claims::upsert_soft_claims(
            &conn,
            workspace_id,
            shard_start_ms,
            &[live_soft],
            Some("peer-a"),
            100,
            1_000,
        )
        .unwrap();
        crate::db::dep_claims::upsert_soft_claims(
            &conn,
            workspace_id,
            shard_start_ms,
            &[expired_soft],
            Some("peer-a"),
            100,
            150,
        )
        .unwrap();
        crate::db::dep_claims::upsert_hard_claims(
            &conn,
            workspace_id,
            shard_start_ms,
            &[hard],
            100,
        )
        .unwrap();

        let storage = load_claim_index_slice(&conn, workspace_id, shard_start_ms, 500).unwrap();
        assert_eq!(storage_ids(&storage), vec![live_soft, hard]);
    }

    #[test]
    fn object_index_includes_locally_present_claimed_object_outside_root_range() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "ws";
        let shard_start_ms = crate::db::dep_claims::utc_day_start_ms(5 * 24 * 60 * 60 * 1000);
        let dep = insert_indexed_shared_blob(
            &conn,
            workspace_id,
            &make_bench_dep_blob(100, vec![], 1),
            100,
        );
        let root_created_at = shard_start_ms + 500;
        let root = insert_indexed_shared_blob(
            &conn,
            workspace_id,
            &make_bench_dep_blob(root_created_at as u64, vec![dep], 2),
            root_created_at,
        );
        crate::db::dep_claims::upsert_hard_claims(&conn, workspace_id, shard_start_ms, &[dep], 100)
            .unwrap();

        let range = SyncWindow {
            kind: crate::sync::session::windowing::SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(shard_start_ms),
            ts_max_exclusive_ms: Some(shard_start_ms + (24 * 60 * 60 * 1000)),
        };
        let base_storage = load_shared_event_index_slice(&conn, workspace_id, range).unwrap();
        let object_storage =
            load_shared_object_index_slice(&conn, workspace_id, range, &[shard_start_ms], 1_000)
                .unwrap();

        assert_eq!(storage_ids(&base_storage), vec![root]);
        assert_eq!(storage_ids(&object_storage), vec![dep, root]);
    }

    #[tokio::test]
    async fn prefetched_long_chain_projects_in_one_round_without_dependency_requests() {
        let dir = tempfile::tempdir().unwrap();
        let source_db_path = dir.path().join("source.db");
        let dest_db_path = dir.path().join("dest.db");

        let source_conn = open_connection(&source_db_path).unwrap();
        let dest_conn = open_connection(&dest_db_path).unwrap();
        create_tables(&source_conn).unwrap();
        create_tables(&dest_conn).unwrap();

        let mut prior = None;
        for idx in 0..1000u64 {
            let dep_ids = prior.into_iter().collect::<Vec<_>>();
            let blob = make_bench_dep_blob(idx + 1, dep_ids, (idx % 251) as u8);
            prior = Some(insert_shared_blob(&source_conn, &blob, (idx + 1) as i64));
        }
        let leaf = prior.expect("leaf");

        let store = Store::new(&source_conn);
        let mut emitted = HashSet::new();
        let mut budget = SharedSendBudget::new_for_tests(1_500, 4 * 1024 * 1024);
        let batch =
            load_shared_send_batch_with_prefetched_deps(&store, &[leaf], &mut emitted, &mut budget)
                .unwrap();

        assert_eq!(batch.ordered.len(), 1000);

        let dest_path = dest_db_path.to_string_lossy().to_string();
        let (mut rx, _guard) = dependency_fetch::register(&dest_path, "tenant-a", "peer-z");
        let persisted = ingest_now(
            &dest_path,
            make_ingest_batch("tenant-a", "quic_recv:peer-z@sim", &batch.ordered),
        )
        .unwrap();
        assert_eq!(persisted, 1000);
        assert_eq!(valid_event_count(&dest_conn, "tenant-a"), 1000);
        assert!(is_valid(&dest_conn, "tenant-a", &leaf));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), rx.recv())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn capped_prefetch_converges_in_frontier_rounds_without_duplicate_requests() {
        let dir = tempfile::tempdir().unwrap();
        let source_db_path = dir.path().join("source-capped.db");
        let dest_db_path = dir.path().join("dest-capped.db");

        let source_conn = open_connection(&source_db_path).unwrap();
        let dest_conn = open_connection(&dest_db_path).unwrap();
        create_tables(&source_conn).unwrap();
        create_tables(&dest_conn).unwrap();

        let chain_len = 32usize;
        let cap = 4usize;
        let mut all_ids = Vec::with_capacity(chain_len);
        let mut prior = None;
        for idx in 0..chain_len {
            let dep_ids = prior.into_iter().collect::<Vec<_>>();
            let blob = make_bench_dep_blob((idx + 1) as u64, dep_ids, (idx % 251) as u8);
            let event_id = insert_shared_blob(&source_conn, &blob, (idx + 1) as i64);
            all_ids.push(event_id);
            prior = Some(event_id);
        }
        let leaf = *all_ids.last().unwrap();

        let dest_path = dest_db_path.to_string_lossy().to_string();
        let store = Store::new(&source_conn);
        let (mut rx, _guard) = dependency_fetch::register(&dest_path, "tenant-a", "peer-z");
        let mut requested_frontiers = Vec::new();
        let mut frontier = vec![leaf];

        loop {
            let mut emitted = HashSet::new();
            let mut budget = SharedSendBudget::new_for_tests(cap, 4 * 1024 * 1024);
            let batch = load_shared_send_batch_with_prefetched_deps(
                &store,
                &frontier,
                &mut emitted,
                &mut budget,
            )
            .unwrap();
            ingest_now(
                &dest_path,
                make_ingest_batch("tenant-a", "quic_recv:peer-z@sim", &batch.ordered),
            )
            .unwrap();

            if is_valid(&dest_conn, "tenant-a", &leaf) {
                break;
            }

            let next_frontier =
                tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv())
                    .await
                    .expect("expected frontier dep request")
                    .expect("dependency request payload");
            assert_eq!(
                next_frontier.len(),
                1,
                "expected one unresolved frontier id"
            );
            requested_frontiers.push(next_frontier[0]);
            frontier = next_frontier;
        }

        let unique_frontiers = requested_frontiers.iter().copied().collect::<HashSet<_>>();
        assert_eq!(unique_frontiers.len(), requested_frontiers.len());
        let expected_follow_up_rounds = (chain_len - 1) / (cap + 1);
        assert_eq!(requested_frontiers.len(), expected_follow_up_rounds);
        assert_eq!(valid_event_count(&dest_conn, "tenant-a"), chain_len as i64);
        assert!(is_valid(&dest_conn, "tenant-a", &leaf));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), rx.recv())
                .await
                .is_err()
        );
    }
}
