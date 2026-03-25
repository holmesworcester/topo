use std::path::PathBuf;
use std::time::Duration;

use negentropy::{Id, NegentropyStorageVector};
use rusqlite::Connection;

use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::store::Store;
use crate::protocol::neg_id_to_event_id;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::receive_log::ReceiveLogWriter;
use crate::sync::session::windowing::SyncWindow;
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};

const RANGE_DATA_RECORD_PREFIX_LEN: usize = 4;

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
