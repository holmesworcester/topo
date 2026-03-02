//! Sync initiator (client role) with dual-stream transport.
//!
//! Drives negentropy reconciliation, pushes events the peer needs, and
//! uses deterministic ownership for multi-source pull work division.

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
use crate::runtime::memtrace;
use crate::runtime::SyncStats;
use crate::sync::negentropy_sqlite::NegentropyStorageSqlite;
use crate::transport::connection::ConnectionError;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};
use crate::tuning::{low_mem_memtrace, low_mem_mode};

use super::control_plane::{
    append_have_ids_to_pending, dispatch_assigned_events, dispatch_owned_need_ids,
    report_fallback_need_ids, send_done, send_initial_neg_open, try_poll_coordinator_assignment,
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
/// Pull (need_ids): dispatched immediately during reconciliation using
/// deterministic ownership. Each event is owned by exactly one peer
/// (hash-based split), so multi-source sessions naturally divide work
/// without a coordinator barrier.
///
/// Callers must provide a `shared_ingest` sender connected to a shared
/// batch_writer. The session never spawns its own writer thread.
pub async fn run_sync_initiator<C, S, R>(
    conn: DualConnection<C, S, R>,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
    recorded_by: &str,
    ingress_source_tag: &str,
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
    let use_snapshot = !low_mem_mode();

    let egress = EgressQueue::new(&db);
    let wanted = WantedEvents::new(&db);
    let _ = egress.clear_connection(peer_id);
    let _ = wanted.clear();

    let ws_id = lookup_workspace_id(&db, recorded_by)
        .ok_or_else(|| format!("no trust anchor for peer_id={}, cannot start sync", recorded_by))?;
    let neg_storage = NegentropyStorageSqlite::new(&neg_db, &ws_id);

    if use_snapshot {
        neg_db
            .execute("BEGIN", [])
            .map_err(|e| format!("Failed to begin snapshot: {}", e))?;
    }
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
        ingress_source_tag.to_string(),
    );

    let neg_item_count = neg_storage.size().unwrap_or(0);
    info!(
        "Negentropy storage has {} items (initiator)",
        neg_item_count
    );

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

    // Fallback buffer: non-owned need_ids reported to coordinator after reconciliation
    let mut fallback_need_ids: Vec<EventId> = Vec::new();
    let mut fallback_reported = false;
    let mut fallback_dispatched = false;
    let mut fallback_report_time: Option<Instant> = None;

    let mut last_bytes_received = 0u64;
    let mut last_egress_log = Instant::now();
    let memtrace_enabled = low_mem_memtrace();
    let memtrace_interval = Duration::from_secs(2);
    let memtrace_file = std::env::var("LOW_MEM_MEMTRACE_FILE").ok();
    let mut last_memtrace = Instant::now();

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
                            rounds,
                            reconcile_start.elapsed().as_millis(),
                            have_ids.len(),
                            need_ids.len()
                        );
                        reconciliation_done = true;
                    }
                }

                append_have_ids_to_pending(&mut have_ids, &mut pending_have);

                // Streaming ownership dispatch: owned events get HaveList
                // immediately, non-owned buffer for fallback.
                dispatch_owned_need_ids(
                    &mut control,
                    &wanted,
                    &mut need_ids,
                    &mut fallback_need_ids,
                    coordination,
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

        // After reconciliation, report non-owned events to coordinator for
        // reassignment instead of discarding them.
        if reconciliation_done && !fallback_reported {
            if fallback_need_ids.is_empty() {
                // No fallback events — nothing to report or wait for.
                fallback_reported = true;
                fallback_dispatched = true;
            } else {
                report_fallback_need_ids(&mut fallback_need_ids, coordination);
                fallback_reported = true;
                fallback_report_time = Some(Instant::now());
            }
        }

        // Poll for coordinator assignment (non-blocking)
        if fallback_reported && !fallback_dispatched {
            if let Some(assigned) = try_poll_coordinator_assignment(coordination) {
                let dispatched =
                    dispatch_assigned_events(&mut control, &wanted, assigned).await?;
                info!("Coordinator assigned {} events to this session", dispatched);
                fallback_dispatched = true;
            } else if fallback_report_time
                .map(|t| t.elapsed() > super::FALLBACK_ASSIGNMENT_TIMEOUT)
                .unwrap_or(false)
            {
                info!("Coordinator assignment timeout, proceeding without fallback");
                fallback_dispatched = true;
            }
        }

        enqueue_pending_have_to_egress(&egress, peer_id, &mut pending_have);
        let send_stats =
            drain_egress_to_data_stream(&egress, &store, peer_id, &mut data_send).await;
        events_sent += send_stats.events_sent_delta;
        bytes_sent += send_stats.bytes_sent_delta;
        if send_stats.events_sent_delta > 0 {
            last_activity = Instant::now();
        }

        if memtrace_enabled && last_memtrace.elapsed() >= memtrace_interval {
            let egress_pending = egress.count_pending(peer_id).unwrap_or(-1);
            let wanted_pending = wanted.count().unwrap_or(-1);
            let ingest_cap = ingest_tx.max_capacity();
            let ingest_used = ingest_cap.saturating_sub(ingest_tx.capacity());
            let line = format!(
                "LOWMEM_MEMTRACE initiator peer={} rounds={} have={} need={} pending_have={} fallback_need={} wanted={} egress_pending={} ingest_used={}/{} bytes_rx={} bytes_tx={}",
                peer_id,
                rounds,
                have_ids.len(),
                need_ids.len(),
                pending_have.len(),
                fallback_need_ids.len(),
                wanted_pending,
                egress_pending,
                ingest_used,
                ingest_cap,
                bytes_received.load(Ordering::Relaxed),
                bytes_sent,
            );
            memtrace::emit(&line, memtrace_file.as_deref());
            last_memtrace = Instant::now();
        }

        // Once reconciliation is done, fallback is dispatched, pending_have
        // is drained, and egress queue is empty, send DataDone+Done.
        if reconciliation_done && fallback_dispatched && pending_have.is_empty() && !done_sent {
            let pending_out = egress.count_pending(peer_id).unwrap_or(0);
            if pending_out > 0 && last_egress_log.elapsed() >= Duration::from_secs(5) {
                info!(
                    "Draining egress: {} pending, {} sent so far",
                    pending_out, events_sent
                );
                last_egress_log = Instant::now();
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
    if use_snapshot {
        let _ = neg_db.execute("COMMIT", []);
    }

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
