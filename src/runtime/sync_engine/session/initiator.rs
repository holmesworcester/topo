//! Sync initiator (client role) with dual-stream transport.
//!
//! Drives negentropy reconciliation, pushes events the peer needs, and
//! coordinates pull work with a multi-source coordinator.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use negentropy::{Id, Negentropy, NegentropyStorageBase, Storage};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::EventId;
use crate::db::{
    egress_queue::EgressQueue,
    open_connection,
    store::{lookup_workspace_id, Store},
    wanted::WantedEvents,
};
use crate::protocol::Frame;
use crate::runtime::SyncStats;
use crate::sync::negentropy_sqlite::NegentropyStorageSqlite;
use crate::transport::connection::ConnectionError;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};

use super::control_plane::{
    append_have_ids_to_pending, dispatch_need_ids_after_reconcile,
    maybe_report_coordination_need_ids, maybe_take_coordination_assignment, send_done,
    send_initial_neg_open, CoordinationAssignment,
};
use super::coordinator::PeerCoord;
use super::data_plane::{
    drain_egress_to_data_stream, enqueue_pending_have_to_egress, send_data_done,
    spawn_data_receiver,
};
use super::{CONTROL_POLL_TIMEOUT, DATA_DRAIN_TIMEOUT, EGRESS_SENT_TTL_MS, NEGENTROPY_FRAME_SIZE};

/// Run sync as the initiator (client role) with dual streams.
/// Control stream: NegOpen, NegMsg, HaveList
/// Data stream: Event blobs
///
/// Push (have_ids): always sends everything the peer needs.
/// Pull (need_ids): buffers need_ids and sends them to the coordinator for
/// load-balanced assignment across peers.
///
/// Callers must provide a `shared_ingest` sender connected to a shared
/// batch_writer. The session never spawns its own writer thread.
pub async fn run_sync_initiator<C, S, R>(
    conn: DualConnection<C, S, R>,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
    recorded_by: &str,
    coordination: &PeerCoord,
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
        "Starting negentropy sync (initiator, dual-stream), activity timeout {}s",
        timeout_secs
    );

    let db = open_connection(db_path)?;
    let neg_db = open_connection(db_path)?;

    let egress = EgressQueue::new(&db);
    let wanted = WantedEvents::new(&db);
    let _ = egress.clear_connection(peer_id);
    let _ = wanted.clear();

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

    let mut have_ids: Vec<Id> = Vec::new();
    let mut need_ids: Vec<Id> = Vec::new();
    let mut events_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let (shutdown_tx, data_drained_rx, recv_handle) = spawn_data_receiver(
        data_recv,
        ingest_tx.clone(),
        bytes_received.clone(),
        recorded_by.to_string(),
    );

    let neg_item_count = neg_storage.size().unwrap_or(0);
    info!("Negentropy storage has {} items (initiator)", neg_item_count);

    let initial_msg = neg.initiate()?;
    send_initial_neg_open(&mut control, initial_msg).await?;

    let mut reconciliation_done = false;
    let mut rounds = 0;

    let mut completed = false;
    let mut done_sent = false;
    let sync_start = Instant::now();
    let reconcile_start = Instant::now();
    // Pending have_ids buffer: populated by reconciliation, drained incrementally
    let mut pending_have: Vec<EventId> = Vec::new();

    // Coordination state: buffer need_ids during reconciliation, send to coordinator after
    let mut coordinated_need_ids: Vec<EventId> = Vec::new();
    let mut coordination_pending = true;
    let mut coordination_reported = false;
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
            Ok(Ok(Frame::NegMsg { msg })) => {
                last_activity = Instant::now();
                rounds += 1;
                match neg.reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)? {
                    Some(next_msg) => {
                        control.send(&Frame::NegMsg { msg: next_msg }).await?;
                        control.flush().await?;
                    }
                    None => {
                        info!(
                            "Reconciliation complete: {} rounds, {}ms, have={} need={}",
                            rounds, reconcile_start.elapsed().as_millis(),
                            have_ids.len(), need_ids.len()
                        );
                        reconciliation_done = true;
                    }
                }

                append_have_ids_to_pending(&mut have_ids, &mut pending_have);
                dispatch_need_ids_after_reconcile(
                    &mut control,
                    &wanted,
                    &mut need_ids,
                    &mut coordinated_need_ids,
                )
                .await?;
            }
            Ok(Ok(Frame::DoneAck)) => {
                info!("Received DoneAck from responder");
                completed = true;
                break;
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

        // Coordination: after reconciliation, send need_ids to coordinator
        maybe_report_coordination_need_ids(
            coordination,
            reconciliation_done,
            &mut coordination_reported,
            &mut coordinated_need_ids,
        )?;
        match maybe_take_coordination_assignment(
            coordination,
            coordination_pending,
            coordination_reported,
        ) {
            CoordinationAssignment::Assigned(assigned) => {
                // HaveList frames were already streamed during reconciliation,
                // so the coordinator assignment is informational only — all
                // assigned events are already in the wanted table and were
                // sent to the responder. Skip the redundant dispatch.
                info!(
                    "Coordinator assigned {} events (peer {})",
                    assigned.len(), coordination.peer_idx
                );
                coordination_pending = false;
            }
            CoordinationAssignment::Disconnected => {
                warn!(
                    "Coordinator assignment channel disconnected for peer {}",
                    coordination.peer_idx
                );
                // No direct/non-coordinated need dispatch is performed here.
                // This session proceeds without pull assignments; subsequent
                // sessions re-register coordination handles and recover.
                coordinated_need_ids.clear();
                coordination_pending = false;
            }
            CoordinationAssignment::Pending | CoordinationAssignment::NotReady => {}
        }

        enqueue_pending_have_to_egress(&egress, peer_id, &mut pending_have);
        let send_stats =
            drain_egress_to_data_stream(&egress, &store, peer_id, &mut data_send).await;
        events_sent += send_stats.events_sent_delta;
        bytes_sent += send_stats.bytes_sent_delta;
        if send_stats.events_sent_delta > 0 {
            last_activity = Instant::now();
        }

        // Once reconciliation is done, coordination resolved, pending_have drained,
        // and egress queue empty, send DataDone on data stream then Done on control.
        if reconciliation_done && !coordination_pending && pending_have.is_empty() && !done_sent {
            let pending_out = egress.count_pending(peer_id).unwrap_or(0);
            if pending_out > 0 && start.elapsed().as_secs() % 5 == 0 {
                info!("Draining egress: {} pending, {} sent so far", pending_out, events_sent);
            }
            if pending_out == 0 {
                send_data_done(&mut data_send).await?;
                send_done(&mut control).await?;
                done_sent = true;
                info!(
                    "Sent DataDone+Done, waiting for DoneAck (sent {}, received {})",
                    events_sent,
                    events_received.load(Ordering::Relaxed)
                );
            }
        }
    }

    if completed {
        let _ = egress.clear_connection(peer_id);
        let _ = wanted.clear();
        let _ = egress.cleanup_sent(EGRESS_SENT_TTL_MS);
    }
    let _ = neg_db.execute("COMMIT", []);

    // Wait for inbound data drain: data receiver exits on peer's DataDone.
    if completed {
        let drain_timeout = DATA_DRAIN_TIMEOUT;
        match tokio::time::timeout(drain_timeout, data_drained_rx).await {
            Ok(Ok(())) => info!("Inbound data fully drained"),
            Ok(Err(_)) => info!("Data drain channel dropped (receiver already exited)"),
            Err(_) => warn!("Timed out waiting for inbound data drain"),
        }
    }
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
    info!("Sync stats: {:?}", stats);
    Ok(stats)
}
