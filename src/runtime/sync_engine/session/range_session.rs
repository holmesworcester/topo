use std::path::PathBuf;
use std::time::Duration;

use negentropy::{Bound, Id, Item, NegentropyStorageBase, NegentropyStorageVector};
use rusqlite::Connection;

use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::store::Store;
use crate::protocol::neg_id_to_event_id;
use crate::runtime::sync_engine::NegentropyStorageSqlite;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::receive_log::ReceiveLogWriter;
use crate::sync::session::windowing::{SyncWindow, SyncWindowKind};
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};
use crate::tuning::low_mem_mode;

const RANGE_DATA_RECORD_PREFIX_LEN: usize = 4;

pub struct RangeReceiveResult {
    pub events_received: u64,
    pub bytes_received: u64,
    pub path: Option<PathBuf>,
}

pub enum RangeStorage<'a> {
    InMemory(NegentropyStorageVector),
    Sqlite(NegentropyStorageSqlite<'a>),
}

impl NegentropyStorageBase for RangeStorage<'_> {
    fn size(&self) -> Result<usize, negentropy::Error> {
        match self {
            Self::InMemory(storage) => storage.size(),
            Self::Sqlite(storage) => storage.size(),
        }
    }

    fn get_item(&self, i: usize) -> Result<Option<Item>, negentropy::Error> {
        match self {
            Self::InMemory(storage) => storage.get_item(i),
            Self::Sqlite(storage) => storage.get_item(i),
        }
    }

    fn iterate(
        &self,
        begin: usize,
        end: usize,
        cb: &mut dyn FnMut(Item, usize) -> Result<bool, negentropy::Error>,
    ) -> Result<(), negentropy::Error> {
        match self {
            Self::InMemory(storage) => storage.iterate(begin, end, cb),
            Self::Sqlite(storage) => storage.iterate(begin, end, cb),
        }
    }

    fn find_lower_bound(&self, first: usize, last: usize, value: &Bound) -> usize {
        match self {
            Self::InMemory(storage) => storage.find_lower_bound(first, last, value),
            Self::Sqlite(storage) => storage.find_lower_bound(first, last, value),
        }
    }
}

fn use_sqlite_storage(range: SyncWindow) -> bool {
    low_mem_mode()
        && matches!(
            range.kind,
            SyncWindowKind::LastTwelveWeeks | SyncWindowKind::Full
        )
}

pub fn load_range_storage<'a>(
    conn: &'a Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<RangeStorage<'a>, String> {
    if use_sqlite_storage(range) {
        let storage = NegentropyStorageSqlite::new_with_range(
            conn,
            workspace_id,
            range.ts_min(),
            range.ts_max_exclusive(),
        );
        storage
            .rebuild_blocks()
            .map_err(|e| format!("rebuild sqlite negentropy blocks: {e}"))?;
        return Ok(RangeStorage::Sqlite(storage));
    }

    let mut stmt = conn
        .prepare(
            "SELECT ts, id
             FROM neg_items
             WHERE workspace_id = :workspace_id
               AND (:ts_min IS NULL OR ts >= :ts_min)
               AND (:ts_max IS NULL OR ts < :ts_max)
             ORDER BY ts, id",
        )
        .map_err(|e| format!("prepare neg_items range query: {e}"))?;
    let mut rows = stmt
        .query(rusqlite::named_params! {
            ":workspace_id": workspace_id,
            ":ts_min": range.ts_min(),
            ":ts_max": range.ts_max_exclusive(),
        })
        .map_err(|e| format!("query neg_items range rows: {e}"))?;

    let mut storage = NegentropyStorageVector::new();
    while let Some(row) = rows
        .next()
        .map_err(|e| format!("iterate neg_items range rows: {e}"))?
    {
        let ts: i64 = row.get(0).map_err(|e| format!("read neg_items ts: {e}"))?;
        let id_blob: Vec<u8> = row.get(1).map_err(|e| format!("read neg_items id: {e}"))?;
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
    Ok(RangeStorage::InMemory(storage))
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
    for chunk in event_ids.chunks(64) {
        let blobs = store
            .get_shared_batch(chunk)
            .map_err(|e| format!("load shared batch for range send: {e}"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowmem_large_windows_use_sqlite_storage() {
        std::env::set_var("LOW_MEM_IOS", "1");
        assert!(use_sqlite_storage(SyncWindow {
            kind: SyncWindowKind::LastTwelveWeeks,
            ts_min_inclusive_ms: Some(1),
            ts_max_exclusive_ms: Some(2),
        }));
        assert!(use_sqlite_storage(SyncWindow {
            kind: SyncWindowKind::Full,
            ts_min_inclusive_ms: Some(1),
            ts_max_exclusive_ms: Some(2),
        }));
        assert!(!use_sqlite_storage(SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(1),
            ts_max_exclusive_ms: Some(2),
        }));
        assert!(!use_sqlite_storage(SyncWindow {
            kind: SyncWindowKind::LastWeek,
            ts_min_inclusive_ms: Some(1),
            ts_max_exclusive_ms: Some(2),
        }));
        std::env::remove_var("LOW_MEM_IOS");
    }
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
