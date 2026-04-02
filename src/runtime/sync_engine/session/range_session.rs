use std::collections::HashSet;
use std::path::PathBuf;
use std::time::Duration;

use negentropy::{Id, NegentropyStorageVector};
use rusqlite::Connection;

use crate::crypto::{event_id_from_base64, event_id_to_base64, hash_event, EventId};
use crate::db::store::Store;
use crate::protocol::neg_id_to_event_id;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::receive_log::ReceiveLogWriter;
use crate::sync::session::windowing::SyncWindow;
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};

const RANGE_DATA_RECORD_PREFIX_LEN: usize = 4;
const SEND_HAVE_ROOT_BATCH_SIZE: usize = 64;

pub struct RangeReceiveResult {
    pub events_received: u64,
    pub bytes_received: u64,
    pub path: Option<PathBuf>,
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
    for chunk in event_ids.chunks(SEND_HAVE_ROOT_BATCH_SIZE) {
        let blobs = store
            .get_shared_batch(chunk)
            .map_err(|e| format!("load shared batch: {e}"))?;
        let mut payload = Vec::new();
        for event_id in chunk {
            let Some(blob) = blobs.get(event_id) else {
                continue;
            };
            let blob_len = u32::try_from(blob.len())
                .map_err(|_| format!("range event too large: {} bytes", blob.len()))?;
            payload.extend_from_slice(&blob_len.to_le_bytes());
            payload.extend_from_slice(blob);
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
    use crate::crypto::hash_event;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::db::store::{insert_event, insert_shared_event_index_entry_if_shared};
    use crate::event_modules::bench_dep::BenchDepEvent;
    use crate::event_modules::{encode_event, registry::ShareScope, ParsedEvent};
    use crate::transport::connection::ConnectionError;
    use async_trait::async_trait;
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

    #[derive(Default)]
    struct MockDataSend {
        sent: Vec<Vec<u8>>,
        flushes: usize,
    }

    #[async_trait]
    impl StreamSend for MockDataSend {
        async fn send(&mut self, _msg: &crate::protocol::Frame) -> Result<(), ConnectionError> {
            unreachable!("send_have_events uses send_bytes only")
        }

        async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), ConnectionError> {
            self.sent.push(bytes.to_vec());
            Ok(())
        }

        async fn flush(&mut self) -> Result<(), ConnectionError> {
            self.flushes += 1;
            Ok(())
        }
    }

    #[tokio::test]
    async fn send_have_events_sends_exact_negotiated_ids_without_recursive_deps() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let root = insert_shared_blob(&conn, &make_bench_dep_blob(1, vec![], 1), 1);
        let mid = insert_shared_blob(&conn, &make_bench_dep_blob(2, vec![root], 2), 2);
        let leaf = insert_shared_blob(&conn, &make_bench_dep_blob(3, vec![mid], 3), 3);

        let store = Store::new(&conn);
        let mut send = MockDataSend::default();
        let have_ids = vec![Id::from_byte_array(leaf)];
        let (events_sent, _bytes_sent) = send_have_events(&store, &mut send, &have_ids)
            .await
            .unwrap();

        assert_eq!(events_sent, 1);
        assert_eq!(send.flushes, 1);
        assert_eq!(send.sent.len(), 1);

        let payload = &send.sent[0];
        let mut offset = 0usize;
        let blob = parse_next_blob_record(payload, &mut offset)
            .unwrap()
            .expect("range blob record");
        let ParsedEvent::BenchDep(event) = crate::event_modules::parse_event(&blob).unwrap() else {
            panic!("expected bench_dep")
        };
        assert_eq!(event.dep_ids, vec![mid]);
        assert_eq!(parse_next_blob_record(payload, &mut offset).unwrap(), None);
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
}
