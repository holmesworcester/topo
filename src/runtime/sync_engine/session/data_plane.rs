//! Data-plane helpers for sync sessions.
//!
//! Owns data-stream and blob-movement concerns:
//! - inbound event receiver task (`Event` / `DataDone`)
//! - egress queue draining to data stream (`Event`)
//! - completion marker emission on data stream (`DataDone`)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{hash_event, EventId};
use crate::db::{egress_queue::EgressQueue, store::Store};
use crate::protocol::Frame;
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};

use super::{EGRESS_CLAIM_COUNT, ENQUEUE_BATCH, HAVE_CHUNK};

pub struct DataPlaneSendStats {
    pub events_sent_delta: u64,
    pub bytes_sent_delta: u64,
}

pub fn enqueue_pending_have_to_egress(
    egress: &EgressQueue<'_>,
    peer_id: &str,
    pending_have: &mut Vec<EventId>,
) {
    if pending_have.is_empty() {
        return;
    }

    let drain_count = pending_have.len().min(ENQUEUE_BATCH);
    let to_enqueue: Vec<EventId> = pending_have.drain(..drain_count).collect();
    for chunk in to_enqueue.chunks(HAVE_CHUNK) {
        let _ = egress.enqueue_events(peer_id, chunk);
    }
}

pub async fn drain_egress_to_data_stream<S>(
    egress: &EgressQueue<'_>,
    store: &Store<'_>,
    peer_id: &str,
    data_send: &mut S,
) -> DataPlaneSendStats
where
    S: StreamSend,
{
    let mut events_sent_delta = 0u64;
    let mut bytes_sent_delta = 0u64;
    let mut sent_any = false;
    let mut blocked = false;

    while !blocked {
        let batch = egress
            .claim_batch(peer_id, EGRESS_CLAIM_COUNT)
            .unwrap_or_default();
        if batch.is_empty() {
            break;
        }

        let mut sent_rowids: Vec<i64> = Vec::with_capacity(batch.len());
        for (rowid, event_id) in batch {
            if let Ok(Some(blob)) = store.get_shared(&event_id) {
                let blob_len = blob.len() as u64;
                if data_send.send(&Frame::Event { blob }).await.is_ok() {
                    events_sent_delta += 1;
                    bytes_sent_delta += blob_len;
                    sent_any = true;
                    sent_rowids.push(rowid);
                } else {
                    blocked = true;
                    break;
                }
            } else {
                sent_rowids.push(rowid);
            }
        }
        let _ = egress.mark_sent(&sent_rowids);
    }

    if sent_any {
        let _ = data_send.flush().await;
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
    bytes_received: Arc<AtomicU64>,
    recorded_by: String,
) -> (
    oneshot::Sender<()>,
    oneshot::Receiver<()>,
    tokio::task::JoinHandle<()>,
)
where
    R: StreamRecv + Send + 'static,
{
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let (data_done_tx, data_done_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let mut data_done_tx = Some(data_done_tx);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                msg = data_recv.recv() => {
                    match msg {
                        Ok(Frame::Event { blob }) => {
                            bytes_received.fetch_add(blob.len() as u64, Ordering::Relaxed);
                            let event_id = hash_event(&blob);
                            if ingest_tx.send((event_id, blob, recorded_by.clone())).await.is_err() {
                                warn!("Ingest channel closed");
                                break;
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
                            warn!("Data stream error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    (shutdown_tx, data_done_rx, handle)
}
