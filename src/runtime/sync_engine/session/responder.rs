//! Sync responder (server role) with dual-stream transport.
//!
//! Handles incoming negentropy reconciliation, serves requested events
//! from the egress queue, and follows the shutdown protocol (DataDone / DoneAck).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use negentropy::{Negentropy, NegentropyStorageBase, Storage};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::db::{
    egress_queue::EgressQueue,
    open_connection,
    store::{lookup_workspace_id, Store},
};
use crate::protocol::Frame;
use crate::runtime::SyncStats;
use crate::sync::negentropy_sqlite::NegentropyStorageSqlite;
use crate::transport::connection::ConnectionError;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};

use super::control_plane::send_done_ack;
use super::data_plane::{drain_egress_to_data_stream, send_data_done, spawn_data_receiver};
use super::{CONTROL_POLL_TIMEOUT, DATA_DRAIN_TIMEOUT, EGRESS_SENT_TTL_MS, NEGENTROPY_FRAME_SIZE};

/// Run sync as the responder (server role) with dual streams.
///
/// Callers must provide a `shared_ingest` sender connected to a shared
/// batch_writer. The session never spawns its own writer thread.
/// This eliminates SQLite write contention when multiple sources sync
/// concurrently.
pub async fn run_sync_responder<C, S, R>(
    conn: DualConnection<C, S, R>,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
    recorded_by: &str,
    shared_ingest: mpsc::Sender<IngestItem>,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>>
where
    C: StreamConn,
    S: StreamSend,
    R: StreamRecv + Send + 'static,
{
    let DualConnection {
        mut control,
        mut data_send,
        data_recv,
    } = conn;
    let start = Instant::now();
    let activity_timeout = Duration::from_secs(timeout_secs);
    let mut last_activity = Instant::now();

    info!(
        "Starting negentropy sync (responder, dual-stream), activity timeout {}s",
        timeout_secs
    );

    let db = open_connection(db_path)?;
    let neg_db = open_connection(db_path)?;

    let egress = EgressQueue::new(&db);
    let _ = egress.clear_connection(peer_id);

    let ws_id = lookup_workspace_id(&db, recorded_by);
    let neg_storage = NegentropyStorageSqlite::new(&neg_db, &ws_id);

    neg_db
        .execute("BEGIN", [])
        .map_err(|e| format!("Failed to begin snapshot: {}", e))?;
    neg_storage
        .rebuild_blocks()
        .map_err(|e| format!("Failed to rebuild blocks: {}", e))?;

    let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), NEGENTROPY_FRAME_SIZE)?;

    let store = Store::new(&db);

    let events_received = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));

    let ingest_tx = shared_ingest;

    let (shutdown_tx, data_drained_rx, recv_handle) = spawn_data_receiver(
        data_recv,
        ingest_tx.clone(),
        bytes_received.clone(),
        recorded_by.to_string(),
    );

    let neg_item_count = neg_storage.size().unwrap_or(0);
    info!("Negentropy storage has {} items (responder)", neg_item_count);

    let mut events_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let mut rounds = 0;
    let mut peer_done = false;
    let mut completed = false;
    let sync_start = Instant::now();
    let reconcile_start = Instant::now();
    let mut last_bytes_received = 0u64;

    loop {
        // Data receiver runs in a separate task — check if it received data
        let current_bytes = bytes_received.load(Ordering::Relaxed);
        if current_bytes > last_bytes_received {
            last_activity = Instant::now();
            last_bytes_received = current_bytes;
        }
        if last_activity.elapsed() >= activity_timeout {
            warn!(
                "Activity timeout ({}s idle, {}s total)",
                activity_timeout.as_secs(),
                start.elapsed().as_secs()
            );
            break;
        }

        match tokio::time::timeout(CONTROL_POLL_TIMEOUT, control.recv()).await {
            Ok(Ok(Frame::NegOpen { msg })) | Ok(Ok(Frame::NegMsg { msg })) => {
                last_activity = Instant::now();
                rounds += 1;

                let response = neg.reconcile(&msg)?;
                if response.is_empty() {
                    info!(
                        "Reconciliation complete: {} rounds, {}ms",
                        rounds, reconcile_start.elapsed().as_millis()
                    );
                } else {
                    control.send(&Frame::NegMsg { msg: response }).await?;
                    control.flush().await?;
                }
            }
            Ok(Ok(Frame::HaveList { ids })) => {
                last_activity = Instant::now();
                if ids.is_empty() {
                    continue;
                }

                let _ = egress.enqueue_events(peer_id, &ids);
            }
            Ok(Ok(Frame::Done)) => {
                last_activity = Instant::now();
                info!("Received Done from initiator");
                peer_done = true;
            }
            Ok(Ok(_)) => {}
            Ok(Err(ConnectionError::Closed)) => {
                info!("Control stream closed by peer");
                break;
            }
            Ok(Err(e)) => {
                warn!("Control stream error: {}", e);
                break;
            }
            Err(_) => {}
        }

        let send_stats =
            drain_egress_to_data_stream(&egress, &store, peer_id, &mut data_send).await;
        events_sent += send_stats.events_sent_delta;
        bytes_sent += send_stats.bytes_sent_delta;
        if send_stats.events_sent_delta > 0 {
            last_activity = Instant::now();
        }

        // After peer signalled Done and our egress queue is drained:
        // 1. Send DataDone on data stream (signals peer's data receiver)
        // 2. Wait for peer's DataDone to be consumed by our data receiver
        // 3. Only then send DoneAck on control
        if peer_done {
            let pending_out = egress.count_pending(peer_id).unwrap_or(0);
            if pending_out == 0 {
                send_data_done(&mut data_send).await?;

                let drain_timeout = DATA_DRAIN_TIMEOUT;
                match tokio::time::timeout(drain_timeout, data_drained_rx).await {
                    Ok(Ok(())) => info!("Inbound data fully drained"),
                    Ok(Err(_)) => info!("Data drain channel dropped (receiver already exited)"),
                    Err(_) => warn!("Timed out waiting for inbound data drain"),
                }

                send_done_ack(&mut control).await?;
                info!(
                    "Sent DoneAck (sent {}, received {})",
                    events_sent,
                    events_received.load(Ordering::Relaxed)
                );
                completed = true;
                break;
            }
        }
    }

    if completed {
        let _ = egress.clear_connection(peer_id);
        let _ = egress.cleanup_sent(EGRESS_SENT_TTL_MS);
    }
    let _ = neg_db.execute("COMMIT", []);
    let _ = shutdown_tx.send(());
    let _ = recv_handle.await;
    drop(ingest_tx);

    let stats = SyncStats {
        events_sent,
        events_received: events_received.load(Ordering::Relaxed),
        neg_rounds: rounds,
        bytes_sent,
        bytes_received: bytes_received.load(Ordering::Relaxed),
        duration_ms: sync_start.elapsed().as_millis(),
    };
    info!("Sync stats (responder): {:?}", stats);
    Ok(stats)
}
