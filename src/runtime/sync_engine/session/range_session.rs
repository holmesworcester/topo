use std::path::PathBuf;
use std::time::Duration;

use negentropy::{Id, NegentropyStorageVector};
use rusqlite::Connection;

use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::store::Store;
use crate::event_modules::{parse_event, ParsedEvent};
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
    use crate::crypto::hash_event;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::db::store::insert_event;
    use crate::event_modules::{
        encode_event, endpoint_shared, registry::ShareScope, ParsedEvent, PeerSharedEvent,
    };

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
}
