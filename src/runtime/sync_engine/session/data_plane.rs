//! Data-plane helpers for sync sessions.
//!
//! Owns data-stream and blob-movement concerns:
//! - inbound event receiver task (`Event` / `DataDone`)
//! - egress queue draining to data stream (`Event`)
//! - completion marker emission on data stream (`DataDone`)

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::timeline::EventTimeline;
use crate::db::{egress_queue::EgressQueue, queue::current_timestamp_ms, store::Store};
use crate::protocol::Frame;
use crate::runtime::memtrace;
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};
use crate::tuning::{egress_send_quantum_bytes, low_mem_memtrace};

use super::connection_scope::ConnectionResponseState;
use super::logging::SyncRunRxCapture;
use super::{
    egress_claim_count, enqueue_batch, have_chunk, DATA_SEND_STALL_TIMEOUT, EGRESS_LEASE_MS,
};

pub struct DataPlaneSendStats {
    pub events_sent_delta: u64,
    pub bytes_sent_delta: u64,
}

#[derive(Debug, Default)]
pub struct PendingResponseQueue {
    ids: VecDeque<EventId>,
}

impl PendingResponseQueue {
    pub fn enqueue_many(&mut self, ids: &[EventId]) -> usize {
        self.ids.extend(ids.iter().copied());
        ids.len()
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    pub fn pop_front(&mut self) -> Option<EventId> {
        self.ids.pop_front()
    }

    pub fn push_front(&mut self, event_id: EventId) {
        self.ids.push_front(event_id);
    }
}

fn should_treat_as_startup_data_abort(events_ingested: u64, bytes_received: &AtomicU64) -> bool {
    events_ingested == 0 && bytes_received.load(Ordering::Relaxed) == 0
}

fn should_capture_rx_event_link(blob: &[u8]) -> bool {
    crate::event_modules::outer_semantic_type_code(blob)
        == Some(crate::event_modules::EVENT_TYPE_FILE_SLICE)
}

pub fn enqueue_pending_have_to_egress(
    session_id: u64,
    egress: &EgressQueue<'_>,
    peer_id: &str,
    pending_have: &mut Vec<EventId>,
) -> Result<usize, rusqlite::Error> {
    if pending_have.is_empty() {
        return Ok(0);
    }

    let drain_count = pending_have.len().min(enqueue_batch());
    let to_enqueue: Vec<EventId> = pending_have.drain(..drain_count).collect();
    let mut inserted = 0usize;
    for chunk in to_enqueue.chunks(have_chunk()) {
        inserted += egress.enqueue_events(peer_id, chunk)?;
    }
    if inserted > 0 {
        info!(
            "Session {} queued {} data events for peer={} (remaining_pending_have={})",
            session_id,
            inserted,
            peer_id,
            pending_have.len()
        );
    }
    Ok(inserted)
}

pub async fn drain_egress_to_data_stream<S>(
    egress: &EgressQueue<'_>,
    store: &Store<'_>,
    peer_id: &str,
    lease_owner: &str,
    data_send: &mut S,
) -> DataPlaneSendStats
where
    S: StreamSend,
{
    let mut events_sent_delta = 0u64;
    let mut bytes_sent_delta = 0u64;
    let mut sent_any = false;
    let mut missing_count = 0u64;
    let send_quantum_bytes = egress_send_quantum_bytes() as u64;
    let mut sent_rowids: Vec<i64> = Vec::new();
    let mut stop_after_flush = false;

    while bytes_sent_delta < send_quantum_bytes {
        let batch =
            match egress.claim_batch(peer_id, lease_owner, egress_claim_count(), EGRESS_LEASE_MS) {
                Ok(batch) => batch,
                Err(err) => {
                    warn!(
                        "failed to claim egress batch peer={} owner={} error={}",
                        peer_id, lease_owner, err
                    );
                    Vec::new()
                }
            };
        if batch.is_empty() {
            break;
        }

        let mut unsent_rowids: Vec<i64> = Vec::new();
        let mut batch_made_progress = false;
        for (idx, (rowid, event_id)) in batch.iter().enumerate() {
            if let Ok(Some(blob)) = store.get_shared(event_id) {
                let blob_len = blob.len() as u64;
                match tokio::time::timeout(
                    DATA_SEND_STALL_TIMEOUT,
                    data_send.send(&Frame::Event { blob }),
                )
                .await
                {
                    Ok(Ok(())) => {
                        events_sent_delta += 1;
                        bytes_sent_delta += blob_len;
                        sent_any = true;
                        batch_made_progress = true;
                        sent_rowids.push(*rowid);
                    }
                    Ok(Err(err)) => {
                        warn!(
                            "data send failed peer={} event={} error={}",
                            peer_id,
                            event_id_to_base64(event_id),
                            err
                        );
                        unsent_rowids
                            .extend(batch[idx..].iter().map(|(pending_rowid, _)| *pending_rowid));
                        stop_after_flush = true;
                        break;
                    }
                    Err(_) => {
                        warn!(
                            "data send stalled peer={} event={} timeout_ms={}",
                            peer_id,
                            event_id_to_base64(event_id),
                            DATA_SEND_STALL_TIMEOUT.as_millis()
                        );
                        unsent_rowids
                            .extend(batch[idx..].iter().map(|(pending_rowid, _)| *pending_rowid));
                        stop_after_flush = true;
                        break;
                    }
                }
            } else {
                missing_count += 1;
                batch_made_progress = true;
                sent_rowids.push(*rowid);
            }
        }

        if !unsent_rowids.is_empty() {
            let _ = egress.release_rows(lease_owner, &unsent_rowids);
        }

        if stop_after_flush || !batch_made_progress {
            break;
        }
    }
    if missing_count > 0 {
        tracing::debug!("{} events missing from store (not shared?)", missing_count);
    }
    let _ = egress.mark_sent(lease_owner, &sent_rowids);

    if sent_any {
        match tokio::time::timeout(DATA_SEND_STALL_TIMEOUT, data_send.flush()).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => warn!("data flush failed peer={} error={}", peer_id, err),
            Err(_) => warn!(
                "data flush stalled peer={} timeout_ms={}",
                peer_id,
                DATA_SEND_STALL_TIMEOUT.as_millis()
            ),
        }
    }

    DataPlaneSendStats {
        events_sent_delta,
        bytes_sent_delta,
    }
}

pub async fn drain_pending_responses_to_data_stream<S>(
    response_state: &ConnectionResponseState,
    timeline: &EventTimeline<'_>,
    store: &Store<'_>,
    data_send: &mut S,
) -> DataPlaneSendStats
where
    S: StreamSend,
{
    let mut events_sent_delta = 0u64;
    let mut bytes_sent_delta = 0u64;
    let send_quantum_bytes = egress_send_quantum_bytes() as u64;
    let mut sent_any = false;

    while bytes_sent_delta < send_quantum_bytes {
        let Some(event_id) = response_state.pop_next_response() else {
            break;
        };

        let Ok(Some(blob)) = store.get_shared(&event_id) else {
            continue;
        };
        let blob_len = blob.len() as u64;
        match tokio::time::timeout(
            DATA_SEND_STALL_TIMEOUT,
            data_send.send(&Frame::Event { blob }),
        )
        .await
        {
            Ok(Ok(())) => {
                events_sent_delta += 1;
                bytes_sent_delta += blob_len;
                sent_any = true;
                let _ = timeline.mark_response_sent(&event_id, current_timestamp_ms());
            }
            Ok(Err(err)) => {
                warn!(
                    "data send failed for requested response event={} error={}",
                    event_id_to_base64(&event_id),
                    err
                );
                response_state.requeue_front(event_id);
                break;
            }
            Err(_) => {
                warn!(
                    "data send stalled for requested response event={} timeout_ms={}",
                    event_id_to_base64(&event_id),
                    DATA_SEND_STALL_TIMEOUT.as_millis()
                );
                response_state.requeue_front(event_id);
                break;
            }
        }
    }

    if sent_any {
        match tokio::time::timeout(DATA_SEND_STALL_TIMEOUT, data_send.flush()).await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => warn!("data flush failed for requested responses: {}", err),
            Err(_) => warn!(
                "data flush stalled for requested responses timeout_ms={}",
                DATA_SEND_STALL_TIMEOUT.as_millis()
            ),
        }
    }

    DataPlaneSendStats {
        events_sent_delta,
        bytes_sent_delta,
    }
}

pub async fn send_data_done<S>(data_send: &mut S) -> Result<(), ConnectionError>
where
    S: StreamSend,
{
    let _ = data_send.flush().await;
    data_send.send(&Frame::DataDone).await?;
    data_send.flush().await?;
    Ok(())
}

/// Spawn data receiver task. Returns:
/// - `shutdown_tx`: forced shutdown (timeout fallback only)
/// - `data_drained_rx`: signals when peer's DataDone marker is received (all data consumed)
/// - `JoinHandle`: task handle
///
/// Each received event is tagged with `recorded_by` before being sent to the
/// ingest channel, so the batch_writer can route it to the correct tenant.
pub fn spawn_data_receiver<R>(
    mut data_recv: R,
    ingest_tx: mpsc::Sender<IngestItem>,
    events_received: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    recorded_by: String,
    source_tag: String,
    rx_capture: Option<SyncRunRxCapture>,
) -> (
    oneshot::Sender<()>,
    oneshot::Receiver<()>,
    tokio::task::JoinHandle<()>,
)
where
    R: StreamRecv + Send + 'static,
{
    let memtrace_enabled = low_mem_memtrace();
    let memtrace_file = std::env::var("LOW_MEM_MEMTRACE_FILE").ok();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let (data_done_tx, data_done_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let mut data_done_tx = Some(data_done_tx);
        let mut events_ingested: u64 = 0;
        let mut max_blob_size: usize = 0;
        let memtrace_interval = Duration::from_secs(2);
        let mut last_memtrace = Instant::now();
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                msg = data_recv.recv() => {
                    match msg {
                        Ok(Frame::Event { blob }) => {
                            events_received.fetch_add(1, Ordering::Relaxed);
                            bytes_received.fetch_add(blob.len() as u64, Ordering::Relaxed);
                            events_received.fetch_add(1, Ordering::Relaxed);
                            max_blob_size = max_blob_size.max(blob.len());
                            let event_id = hash_event(&blob);
                            if should_capture_rx_event_link(&blob) {
                                if let Some(capture) = &rx_capture {
                                    capture.record_event_id_b64(crate::crypto::event_id_to_base64(&event_id));
                                }
                            }
                            if ingest_tx
                                .send((
                                    event_id,
                                    blob,
                                    recorded_by.clone(),
                                    source_tag.clone(),
                                    current_timestamp_ms(),
                                ))
                                .await
                                .is_err()
                            {
                                warn!("Ingest channel closed");
                                break;
                            }
                            events_ingested += 1;
                            if memtrace_enabled && last_memtrace.elapsed() >= memtrace_interval {
                                let ingest_cap = ingest_tx.max_capacity();
                                let ingest_used = ingest_cap.saturating_sub(ingest_tx.capacity());
                                let line = format!(
                                    "LOWMEM_MEMTRACE data_rx source={} events_ingested={} max_blob={} ingest_used={}/{} bytes_rx={}",
                                    source_tag,
                                    events_ingested,
                                    max_blob_size,
                                    ingest_used,
                                    ingest_cap,
                                    bytes_received.load(Ordering::Relaxed),
                                );
                                memtrace::emit(&line, memtrace_file.as_deref());
                                last_memtrace = Instant::now();
                            }
                        }
                        Ok(Frame::DataDone) => {
                            info!("Received DataDone from peer — all data consumed");
                            if let Some(tx) = data_done_tx.take() {
                                let _ = tx.send(());
                            }
                            break;
                        }
                        Ok(_) => {}
                        Err(ConnectionError::Closed) => {
                            info!("Data stream closed by peer");
                            break;
                        }
                        Err(e) => {
                            if should_treat_as_startup_data_abort(events_ingested, &bytes_received)
                            {
                                info!(
                                    "Data stream closed before sync started source={} error={}",
                                    source_tag, e
                                );
                            } else {
                                warn!("Data stream error: {}", e);
                            }
                            break;
                        }
                    }
                }
            }
        }
    });

    (shutdown_tx, data_done_rx, handle)
}

#[cfg(test)]
mod tests {
    use super::{
        drain_egress_to_data_stream, drain_pending_responses_to_data_stream,
        should_capture_rx_event_link,
    };
    use crate::crypto::{event_id_to_base64, hash_event};
    use crate::db::timeline::EventTimeline;
    use crate::db::{
        egress_queue::EgressQueue, open_connection, schema::create_tables, store::insert_event,
        store::Store,
    };
    use crate::event_modules::ShareScope;
    use crate::protocol::Frame;
    use crate::sync::session::ConnectionResponseState;
    use crate::transport::connection::ConnectionError;
    use crate::transport::StreamSend;
    use async_trait::async_trait;
    use rusqlite::Connection;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Clone, Default)]
    struct RecordingSend {
        frames: Arc<Mutex<Vec<Frame>>>,
    }

    #[async_trait]
    impl StreamSend for RecordingSend {
        async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
            self.frames.lock().unwrap().push(msg.clone());
            Ok(())
        }

        async fn flush(&mut self) -> Result<(), ConnectionError> {
            Ok(())
        }
    }

    fn setup_file_db() -> (tempfile::TempDir, std::path::PathBuf, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data-plane.db");
        let conn = open_connection(&path).unwrap();
        conn.busy_timeout(Duration::from_millis(20)).unwrap();
        create_tables(&conn).unwrap();
        (dir, path, conn)
    }

    #[test]
    fn should_capture_only_file_slice_events() {
        assert!(should_capture_rx_event_link(&[
            crate::event_modules::EVENT_TYPE_FILE_SLICE,
            0,
            1,
        ]));
        assert!(!should_capture_rx_event_link(&[
            crate::event_modules::EVENT_TYPE_MESSAGE,
            0,
            1,
        ]));
        assert!(!should_capture_rx_event_link(&[
            crate::event_modules::EVENT_TYPE_FILE,
            0,
            1,
        ]));
        assert!(!should_capture_rx_event_link(&[]));
    }

    #[tokio::test]
    async fn drain_egress_to_data_stream_retries_transient_mark_sent_busy() {
        let (_dir, path, conn) = setup_file_db();
        let blob = b"hello busy retry".to_vec();
        let event_id = hash_event(&blob);
        let now_ms = 1_700_000_000_000i64;

        insert_event(
            &conn,
            &event_id,
            "message",
            &blob,
            ShareScope::Shared,
            now_ms,
            now_ms,
        )
        .unwrap();
        let egress = EgressQueue::new(&conn);
        egress.enqueue_events("peer-a", &[event_id]).unwrap();
        drop(conn);

        let path_for_lock = path.clone();
        let (lock_ready_tx, lock_ready_rx) = std::sync::mpsc::channel();
        let lock_thread = std::thread::spawn(move || {
            let lock_conn = open_connection(&path_for_lock).unwrap();
            lock_conn.busy_timeout(Duration::from_millis(20)).unwrap();
            lock_conn.execute("BEGIN IMMEDIATE", []).unwrap();
            lock_ready_tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(80));
            lock_conn.execute("COMMIT", []).unwrap();
        });
        lock_ready_rx.recv().unwrap();

        let path_for_task = path.clone();
        let sender = RecordingSend::default();
        let sender_state = sender.frames.clone();
        let conn = open_connection(&path_for_task).unwrap();
        conn.busy_timeout(Duration::from_millis(20)).unwrap();
        let egress = EgressQueue::new(&conn);
        let store = Store::new(&conn);
        let mut send = sender;
        let stats =
            drain_egress_to_data_stream(&egress, &store, "peer-a", "sess-a", &mut send).await;
        lock_thread.join().unwrap();
        assert_eq!(stats.events_sent_delta, 1);
        assert_eq!(
            sender_state.lock().unwrap().as_slice(),
            &[Frame::Event { blob }]
        );

        let verify = open_connection(&path).unwrap();
        verify.busy_timeout(Duration::from_millis(20)).unwrap();
        let egress = EgressQueue::new(&verify);
        assert_eq!(egress.count_pending("peer-a").unwrap(), 0);
    }

    #[tokio::test]
    async fn drain_egress_to_data_stream_claims_multiple_batches_per_quantum() {
        let (_dir, _path, conn) = setup_file_db();
        let now_ms = 1_700_000_000_000i64;
        let mut event_ids = Vec::new();
        for idx in 0..80u8 {
            let blob = format!("msg-{idx:03}").into_bytes();
            let event_id = hash_event(&blob);
            insert_event(
                &conn,
                &event_id,
                "message",
                &blob,
                ShareScope::Shared,
                now_ms + idx as i64,
                now_ms + idx as i64,
            )
            .unwrap();
            event_ids.push(event_id);
        }

        let egress = EgressQueue::new(&conn);
        egress.enqueue_events("peer-a", &event_ids).unwrap();

        let store = Store::new(&conn);
        let sender = RecordingSend::default();
        let sender_state = sender.frames.clone();
        let mut send = sender;
        let stats =
            drain_egress_to_data_stream(&egress, &store, "peer-a", "sess-a", &mut send).await;

        assert_eq!(
            stats.events_sent_delta, 80,
            "one drain quantum should span multiple queue claims"
        );
        assert_eq!(sender_state.lock().unwrap().len(), 80);
        assert_eq!(egress.count_pending("peer-a").unwrap(), 0);
        assert_eq!(egress.count_outstanding("peer-a", "sess-a").unwrap(), 0);
    }

    #[tokio::test]
    async fn drain_pending_responses_to_data_stream_sends_from_memory_queue() {
        let (_dir, _path, conn) = setup_file_db();
        let blob = b"memory queue payload".to_vec();
        let event_id = hash_event(&blob);
        let now_ms = 1_700_000_000_000i64;
        insert_event(
            &conn,
            &event_id,
            "message",
            &blob,
            ShareScope::Shared,
            now_ms,
            now_ms,
        )
        .unwrap();

        let store = Store::new(&conn);
        let sender = RecordingSend::default();
        let sender_state = sender.frames.clone();
        let mut send = sender;
        let pending = ConnectionResponseState::default();
        let timeline = EventTimeline::new(&conn);
        pending.consume_requests(&[event_id]);

        let stats =
            drain_pending_responses_to_data_stream(&pending, &timeline, &store, &mut send).await;
        assert_eq!(stats.events_sent_delta, 1);
        assert!(pending.is_empty());
        assert_eq!(
            sender_state.lock().unwrap().as_slice(),
            &[Frame::Event { blob }]
        );
        let row = timeline
            .load(&event_id_to_base64(&event_id))
            .unwrap()
            .unwrap();
        assert!(row.response_sent_at.is_some());
    }
}
