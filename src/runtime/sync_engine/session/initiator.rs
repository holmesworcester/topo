//! Sync initiator (client role) with dual-stream transport.
//!
//! Drives negentropy reconciliation, pushes events the peer needs, and
//! uses sink-driven `wanted` scheduling for multi-source pull work division.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use negentropy::{Id, Negentropy, NegentropyStorageBase, Storage};
use serde_json::json;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::EventId;
use crate::db::{
    egress_queue::EgressQueue,
    open_connection,
    queue::current_timestamp_ms,
    store::{lookup_workspace_id, Store},
    wanted::WantedEvents,
};
use crate::protocol::Frame;
use crate::runtime::build_mismatch::recent_build_mismatch_reason;
use crate::runtime::memtrace;
use crate::runtime::repeated_warning::should_emit_globally;
use crate::runtime::SyncStats;
use crate::sync::negentropy_sqlite::NegentropyStorageSqlite;
use crate::transport::connection::ConnectionError;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};
use crate::tuning::{low_mem_memtrace, low_mem_mode};

use super::connection_scope::ConnectionRequestState;
use super::control_plane::{
    append_have_ids_to_pending, observe_need_ids_for_peer, refill_wanted_requests, send_done,
    send_initial_neg_open,
};
use super::coordinator::PeerCoord;
use super::data_plane::{
    drain_egress_to_data_stream, enqueue_pending_have_to_egress, send_data_done,
    spawn_data_receiver,
};
use super::logging::{SyncRunCapture, SyncRunRxCapture};
use super::windowing::{
    encode_initial_neg_open, mark_outbound_full_completed, select_outbound_window, SyncWindowKind,
};
use super::{
    negentropy_frame_size, send_idle_capture_enabled, CONTROL_POLL_TIMEOUT, DATA_DRAIN_TIMEOUT,
    EGRESS_QUIET_WINDOW, EGRESS_SENT_TTL_MS, INITIAL_CONTROL_PROGRESS_TIMEOUT,
};

fn should_treat_as_startup_control_abort(
    rounds: u64,
    events_sent: u64,
    bytes_received: &AtomicU64,
) -> bool {
    rounds == 0 && events_sent == 0 && bytes_received.load(Ordering::Relaxed) == 0
}

/// Run sync as the initiator (client role) with dual streams.
/// Control stream: NegOpen, NegMsg, HaveList
/// Data stream: Event blobs
///
/// Push (have_ids): always sends everything the peer needs.
/// Pull (need_ids): recorded into sink-side SQL `wanted` state during
/// reconciliation. A per-peer request window then drains that durable state
/// into `HaveList` requests, so balancing happens at the sink instead of
/// inside negentropy.
///
/// Callers must provide a `shared_ingest` sender connected to a shared
/// batch_writer. The session never spawns its own writer thread.
pub async fn run_sync_initiator<C, S, R>(
    conn: DualConnection<C, S, R>,
    session_id: u64,
    db_path: &str,
    timeout_secs: u64,
    session_owner: &str,
    peer_id: &str,
    recorded_by: &str,
    ingress_source_tag: &str,
    coordination: &PeerCoord,
    request_state: &ConnectionRequestState,
    shared_ingest: mpsc::Sender<IngestItem>,
    capture: Option<SyncRunCapture>,
    rx_capture: Option<SyncRunRxCapture>,
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
    let ws_id = lookup_workspace_id(&db, recorded_by).ok_or_else(|| {
        format!(
            "no accepted workspace binding for peer_id={}, cannot start sync",
            recorded_by
        )
    })?;
    let sync_window = select_outbound_window(db_path, peer_id, current_timestamp_ms());
    let neg_storage = NegentropyStorageSqlite::new_with_range(
        &neg_db,
        &ws_id,
        sync_window.ts_min(),
        sync_window.ts_max_exclusive(),
    );

    if use_snapshot {
        neg_db
            .execute("BEGIN", [])
            .map_err(|e| format!("Failed to begin snapshot: {}", e))?;
    }
    neg_storage
        .rebuild_blocks()
        .map_err(|e| format!("Failed to rebuild blocks: {}", e))?;

    let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), negentropy_frame_size())?;

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
        events_received.clone(),
        bytes_received.clone(),
        recorded_by.to_string(),
        ingress_source_tag.to_string(),
        rx_capture,
    );

    let neg_item_count = neg_storage.size().unwrap_or(0);
    info!(
        "Negentropy storage has {} items (initiator)",
        neg_item_count
    );

    let initial_msg = neg.initiate()?;
    let initial_msg = encode_initial_neg_open(sync_window, initial_msg);
    send_initial_neg_open(&mut control, initial_msg).await?;
    info!(
        "Initiator sent initial NegOpen to peer={} remote_source={}",
        peer_id, ingress_source_tag
    );

    let mut reconciliation_done = false;
    let mut rounds = 0;

    let mut completed = false;
    let mut done_sent = false;
    let sync_start = Instant::now();
    let reconcile_start = Instant::now();
    // Pending have_ids buffer: populated by reconciliation, drained incrementally
    let mut pending_have: Vec<EventId> = Vec::new();
    let mut last_bytes_received = 0u64;
    let mut last_egress_log = Instant::now();
    let memtrace_enabled = low_mem_memtrace();
    let memtrace_interval = Duration::from_secs(2);
    let memtrace_file = std::env::var("LOW_MEM_MEMTRACE_FILE").ok();
    let mut last_memtrace = Instant::now();
    let mut last_alloc_trim = Instant::now();
    let mut egress_quiet_since: Option<Instant> = None;
    let idle_capture_enabled = send_idle_capture_enabled() && capture.is_some();
    let mut last_send_progress = Instant::now();
    let mut last_idle_marker = Instant::now();

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
        if rounds == 0 && sync_start.elapsed() >= INITIAL_CONTROL_PROGRESS_TIMEOUT {
            warn!(
                "Initial control progress timeout after {}ms (peer={}, pending_have={})",
                sync_start.elapsed().as_millis(),
                peer_id,
                pending_have.len()
            );
            if let Some(capture) = capture.as_ref() {
                capture.record_marker(
                    "meta",
                    "state",
                    "InitialControlTimeout",
                    serde_json::to_string(&json!({
                        "peer_id": peer_id,
                        "elapsed_ms": sync_start.elapsed().as_millis(),
                        "pending_have": pending_have.len(),
                        "need_ids": need_ids.len(),
                    }))
                    .ok(),
                );
            }
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
            }
            Ok(Ok(Frame::DoneAck)) => {
                info!("Received DoneAck from responder");
                completed = true;
                break;
            }
            Ok(Ok(Frame::RequestCredit { credits })) => {
                last_activity = Instant::now();
                request_state.add_credit(credits as usize);
            }
            Ok(Ok(_)) => {}
            Ok(Err(ConnectionError::Closed)) => {
                if should_treat_as_startup_control_abort(rounds, events_sent, &bytes_received) {
                    if let Some(reason) = recent_build_mismatch_reason(peer_id) {
                        let key = format!("outbound-build-mismatch:{peer_id}");
                        if should_emit_globally(key) {
                            warn!(
                                "Outbound sync to peer {} rejected: {}",
                                &peer_id[..16.min(peer_id.len())],
                                reason
                            );
                        }
                    } else {
                        info!("Control stream closed before sync started by peer");
                    }
                } else {
                    info!("Control stream closed by peer");
                }
                break;
            }
            Ok(Err(e)) => {
                if should_treat_as_startup_control_abort(rounds, events_sent, &bytes_received) {
                    if let Some(reason) = recent_build_mismatch_reason(peer_id) {
                        let key = format!("outbound-build-mismatch:{peer_id}");
                        if should_emit_globally(key) {
                            warn!(
                                "Outbound sync to peer {} rejected: {}",
                                &peer_id[..16.min(peer_id.len())],
                                reason
                            );
                        }
                    } else {
                        info!("Control stream closed before sync started: {}", e);
                    }
                } else {
                    warn!("Control stream error: {}", e);
                }
                break;
            }
            Err(_) => {}
        }

        let observed_need_ids = observe_need_ids_for_peer(&wanted, peer_id, &mut need_ids)?;
        if observed_need_ids > 0 {
            info!(
                "Observed {} wanted IDs from peer {} during reconciliation",
                observed_need_ids, peer_id
            );
        }
        let requested_now =
            refill_wanted_requests(&mut control, &wanted, coordination, peer_id, request_state)
                .await?;
        if requested_now > 0 {
            last_activity = Instant::now();
        }

        if let Err(err) =
            enqueue_pending_have_to_egress(session_id, &egress, peer_id, &mut pending_have)
        {
            warn!(
                "Session {} failed to queue pending Have ids for peer {}: {}",
                session_id, peer_id, err
            );
        }
        let send_stats =
            drain_egress_to_data_stream(&egress, &store, peer_id, session_owner, &mut data_send)
                .await;
        events_sent += send_stats.events_sent_delta;
        bytes_sent += send_stats.bytes_sent_delta;
        if send_stats.events_sent_delta > 0 {
            last_activity = Instant::now();
            last_send_progress = Instant::now();
        }

        if low_mem_mode() && last_alloc_trim.elapsed() >= Duration::from_millis(100) {
            let _ = memtrace::allocator_trim();
            last_alloc_trim = Instant::now();
        }

        if memtrace_enabled && last_memtrace.elapsed() >= memtrace_interval {
            let egress_pending = egress
                .count_outstanding(peer_id, session_owner)
                .unwrap_or(-1);
            let wanted_pending = wanted.count().unwrap_or(-1);
            let wanted_peer_backlog = wanted.count_backlog_for_peer(peer_id).unwrap_or(-1);
            let request_stats = request_state.stats(current_timestamp_ms());
            let ingest_cap = ingest_tx.max_capacity();
            let ingest_used = ingest_cap.saturating_sub(ingest_tx.capacity());
            let sqlite_global = memtrace::sqlite_global_memory();
            let sqlite_main = memtrace::sqlite_db_memory(&db);
            let sqlite_neg = memtrace::sqlite_db_memory(&neg_db);
            let allocator = memtrace::allocator_memory();
            let line = format!(
                "LOWMEM_MEMTRACE initiator peer={} rounds={} have={} need={} have_cap={} need_cap={} pending_have={} pending_have_cap={} wanted_total={} wanted_peer_backlog={} request_inflight={} request_credit={} egress_pending={} ingest_used={}/{} sqlite_mem_cur={} sqlite_mem_high={} sqlite_pcache_ovfl_cur={} sqlite_pcache_ovfl_high={} db_main_cache={} db_main_schema={} db_main_stmt={} db_neg_cache={} db_neg_schema={} db_neg_stmt={} mall_arena={} mall_used={} mall_free={} mall_mmap={} bytes_rx={} bytes_tx={}",
                peer_id,
                rounds,
                have_ids.len(),
                need_ids.len(),
                have_ids.capacity(),
                need_ids.capacity(),
                pending_have.len(),
                pending_have.capacity(),
                wanted_pending,
                wanted_peer_backlog,
                request_stats.inflight_len,
                request_stats.remote_credit,
                egress_pending,
                ingest_used,
                ingest_cap,
                sqlite_global.map(|s| s.memory_used_bytes).unwrap_or(-1),
                sqlite_global.map(|s| s.memory_high_bytes).unwrap_or(-1),
                sqlite_global
                    .map(|s| s.pagecache_overflow_bytes)
                    .unwrap_or(-1),
                sqlite_global
                    .map(|s| s.pagecache_overflow_high_bytes)
                    .unwrap_or(-1),
                sqlite_main.map(|s| s.cache_used_bytes).unwrap_or(-1),
                sqlite_main.map(|s| s.schema_used_bytes).unwrap_or(-1),
                sqlite_main.map(|s| s.stmt_used_bytes).unwrap_or(-1),
                sqlite_neg.map(|s| s.cache_used_bytes).unwrap_or(-1),
                sqlite_neg.map(|s| s.schema_used_bytes).unwrap_or(-1),
                sqlite_neg.map(|s| s.stmt_used_bytes).unwrap_or(-1),
                allocator.map(|s| s.arena_bytes).unwrap_or(-1),
                allocator.map(|s| s.used_bytes).unwrap_or(-1),
                allocator.map(|s| s.free_bytes).unwrap_or(-1),
                allocator.map(|s| s.mmap_bytes).unwrap_or(-1),
                bytes_received.load(Ordering::Relaxed),
                bytes_sent,
            );
            memtrace::emit(&line, memtrace_file.as_deref());
            last_memtrace = Instant::now();
        }

        let pending_wanted_backlog = wanted.count_backlog_for_peer(peer_id).unwrap_or(0);
        let egress_pending = egress
            .count_outstanding(peer_id, session_owner)
            .unwrap_or(0);
        let request_stats = request_state.stats(current_timestamp_ms());

        if idle_capture_enabled
            && !done_sent
            && last_send_progress.elapsed() >= Duration::from_secs(1)
            && last_idle_marker.elapsed() >= Duration::from_secs(1)
        {
            if let Some(capture) = capture.as_ref() {
                let idle_state = if egress_pending > 0 || !pending_have.is_empty() {
                    "queued_not_sending"
                } else if !reconciliation_done || !need_ids.is_empty() || pending_wanted_backlog > 0
                {
                    "waiting_on_control"
                } else {
                    "no_ready_work"
                };
                capture.record_marker(
                    "meta",
                    "state",
                    "SendIdle",
                    serde_json::to_string(&json!({
                        "peer_id": peer_id,
                        "state": idle_state,
                        "idle_ms": last_send_progress.elapsed().as_millis(),
                        "reconciliation_done": reconciliation_done,
                        "pending_have": pending_have.len(),
                        "need_ids": need_ids.len(),
                        "wanted_peer_backlog": pending_wanted_backlog,
                        "request_inflight": request_stats.inflight_len,
                        "request_credit": request_stats.remote_credit,
                        "egress_pending": egress_pending,
                        "wanted_pending": wanted.count().unwrap_or(-1),
                    }))
                    .ok(),
                );
            }
            last_idle_marker = Instant::now();
        }

        // Once reconciliation is done, this peer has no remaining wanted
        // backlog, pending_have is drained, and egress queue is empty, send
        // DataDone+Done.
        if reconciliation_done
            && need_ids.is_empty()
            && pending_wanted_backlog == 0
            && pending_have.is_empty()
            && !done_sent
        {
            if egress_pending > 0 && last_egress_log.elapsed() >= Duration::from_secs(5) {
                info!(
                    "Draining egress: {} pending, {} sent so far",
                    egress_pending, events_sent
                );
                last_egress_log = Instant::now();
            }
            if egress_pending == 0 {
                let quiet_since = egress_quiet_since.get_or_insert_with(Instant::now);
                if quiet_since.elapsed() >= EGRESS_QUIET_WINDOW {
                    send_data_done(&mut data_send).await?;
                    send_done(&mut control).await?;
                    done_sent = true;
                    info!(
                        "Sent DataDone+Done, waiting for DoneAck (sent {}, received {})",
                        events_sent,
                        events_received.load(Ordering::Relaxed)
                    );
                }
            } else {
                egress_quiet_since = None;
            }
        }
    }

    let _ = egress.release_leases(peer_id, session_owner);
    let _ = egress.cleanup_sent_for_connection(peer_id, 0);
    if completed {
        if sync_window.kind == SyncWindowKind::Full {
            mark_outbound_full_completed(db_path, peer_id, current_timestamp_ms());
        }
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
