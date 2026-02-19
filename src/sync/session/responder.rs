//! Sync responder (server role) with dual-stream transport.
//!
//! Handles incoming negentropy reconciliation, serves requested events
//! from the egress queue, and follows the shutdown protocol (DataDone / DoneAck).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use negentropy::{Negentropy, Storage};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::contracts::event_runtime_contract::{BatchWriterFn, IngestItem};
use crate::db::{
    egress_queue::EgressQueue,
    open_connection,
    store::{lookup_workspace_id, Store},
};
use crate::runtime::SyncStats;
use crate::protocol::{NegentropyStorageSqlite, SyncMessage};
use crate::transport::connection::ConnectionError;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};

use super::receiver::spawn_data_receiver;
use super::{
    session_ingest_cap, CONTROL_POLL_TIMEOUT, DATA_DRAIN_TIMEOUT, EGRESS_CLAIM_COUNT,
    EGRESS_CLAIM_LEASE_MS, EGRESS_SENT_TTL_MS, NEGENTROPY_FRAME_SIZE,
};

/// Run sync as the responder (server role) with dual streams.
///
/// When `shared_ingest` is provided, events are sent to the shared channel
/// instead of spawning a per-session batch_writer. This eliminates SQLite
/// write contention when multiple sources sync concurrently.
pub async fn run_sync_responder_dual<C, S, R>(
    conn: DualConnection<C, S, R>,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
    recorded_by: &str,
    shared_ingest: Option<mpsc::Sender<IngestItem>>,
    batch_writer_fn: BatchWriterFn,
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
    let timeout = Duration::from_secs(timeout_secs);

    info!(
        "Starting negentropy sync (responder, dual-stream) for {} seconds",
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

    // Use shared ingest channel if provided, otherwise create per-session batch_writer
    let (ingest_tx, writer_handle) = if let Some(shared_tx) = shared_ingest {
        (shared_tx, None)
    } else {
        let ingest_cap = session_ingest_cap();
        let (tx, rx) = mpsc::channel::<IngestItem>(ingest_cap);
        let events_received_writer = events_received.clone();
        let db_path_owned = db_path.to_string();
        let bw = batch_writer_fn;
        let handle = tokio::task::spawn_blocking(move || {
            bw(db_path_owned, rx, events_received_writer)
        });
        (tx, Some(handle))
    };

    let (shutdown_tx, data_drained_rx, recv_handle) = spawn_data_receiver(
        data_recv,
        ingest_tx.clone(),
        bytes_received.clone(),
        recorded_by.to_string(),
    );

    let mut events_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let mut rounds = 0;
    let mut peer_done = false;
    let mut completed = false;
    let sync_start = Instant::now();

    loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }

        match tokio::time::timeout(CONTROL_POLL_TIMEOUT, control.recv()).await {
            Ok(Ok(SyncMessage::NegOpen { msg })) | Ok(Ok(SyncMessage::NegMsg { msg })) => {
                rounds += 1;

                let response = neg.reconcile(&msg)?;
                if response.is_empty() {
                    info!("Reconciliation complete in {} rounds", rounds);
                } else {
                    control.send(&SyncMessage::NegMsg { msg: response }).await?;
                    control.flush().await?;
                }
            }
            Ok(Ok(SyncMessage::HaveList { ids })) => {
                if ids.is_empty() {
                    continue;
                }

                let _ = egress.enqueue_events(peer_id, &ids);
            }
            Ok(Ok(SyncMessage::Done)) => {
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

        let mut sent_this_round = 0;
        let mut blocked = false;
        while !blocked {
            let batch = egress
                .claim_batch(peer_id, EGRESS_CLAIM_COUNT, EGRESS_CLAIM_LEASE_MS)
                .unwrap_or_default();
            if batch.is_empty() {
                break;
            }

            let mut sent_rowids: Vec<i64> = Vec::with_capacity(batch.len());
            for (rowid, event_id) in batch {
                if let Ok(Some(blob)) = store.get_shared(&event_id) {
                    let blob_len = blob.len() as u64;
                    if data_send.send(&SyncMessage::Event { blob }).await.is_ok() {
                        events_sent += 1;
                        bytes_sent += blob_len;
                        sent_this_round += 1;
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

        if sent_this_round > 0 {
            let _ = data_send.flush().await;
        }

        // After peer signalled Done and our egress queue is drained:
        // 1. Send DataDone on data stream (signals peer's data receiver)
        // 2. Wait for peer's DataDone to be consumed by our data receiver
        // 3. Only then send DoneAck on control
        if peer_done {
            let pending_out = egress.count_pending(peer_id).unwrap_or(0);
            if pending_out == 0 {
                let _ = data_send.flush().await;
                data_send.send(&SyncMessage::DataDone).await?;
                data_send.flush().await?;

                let drain_timeout = DATA_DRAIN_TIMEOUT;
                match tokio::time::timeout(drain_timeout, data_drained_rx).await {
                    Ok(Ok(())) => info!("Inbound data fully drained"),
                    Ok(Err(_)) => info!("Data drain channel dropped (receiver already exited)"),
                    Err(_) => warn!("Timed out waiting for inbound data drain"),
                }

                control.send(&SyncMessage::DoneAck).await?;
                control.flush().await?;
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
    if let Some(handle) = writer_handle {
        let _ = handle.await;
    }

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
