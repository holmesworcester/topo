//! Data-plane helpers for long-lived sync connections.
//!
//! Owns data-stream and blob-movement concerns:
//! - inbound event receiver task (`Event`)
//! - draining requested response blobs to the data stream (`Event`)

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::timeline::EventTimeline;
use crate::db::{queue::current_timestamp_ms, store::Store};
use crate::protocol::Frame;
use crate::runtime::memtrace;
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};
use crate::tuning::{egress_send_quantum_bytes, low_mem_memtrace};

use super::connection_scope::ConnectionResponseState;
use super::logging::SyncRunRxCapture;
use super::DATA_SEND_STALL_TIMEOUT;

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

/// Spawn data receiver task. Returns:
/// - `shutdown_tx`: forced shutdown when the owning sync connection exits
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
) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>)
where
    R: StreamRecv + Send + 'static,
{
    let memtrace_enabled = low_mem_memtrace();
    let memtrace_file = std::env::var("LOW_MEM_MEMTRACE_FILE").ok();
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
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

    (shutdown_tx, handle)
}

#[cfg(test)]
mod tests {
    use super::{drain_pending_responses_to_data_stream, should_capture_rx_event_link};
    use crate::crypto::{event_id_to_base64, hash_event};
    use crate::db::timeline::EventTimeline;
    use crate::db::{open_connection, schema::create_tables, store::insert_event, store::Store};
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
