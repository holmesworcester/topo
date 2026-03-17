//! Sync responder (server role) with dual-stream transport.
//!
//! Handles incoming negentropy reconciliation, serves requested events from a
//! bounded in-memory queue, issues sink-side requests under advertised credit,
//! and keeps those request/response lanes alive across repeated discovery
//! rounds on the same transport session.
//!
//! Reconciliation runs on a dedicated OS thread so the main loop can
//! continue draining requested responses during the 100-400ms reconcile() calls.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use negentropy::{Negentropy, NegentropyStorageBase, Storage};
use serde_json::json;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::db::timeline::EventTimeline;
use crate::db::{
    open_connection,
    queue::current_timestamp_ms,
    store::{lookup_workspace_id, Store},
    wanted::WantedEvents,
};
use crate::protocol::Frame;
use crate::runtime::memtrace;
use crate::runtime::SyncStats;
use crate::state::live_hints;
use crate::sync::negentropy_sqlite::NegentropyStorageSqlite;
use crate::transport::connection::ConnectionError;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};
use crate::tuning::{
    low_mem_memtrace, low_mem_mode, request_credit_high_watermark, request_credit_low_watermark,
};

use super::connection_scope::{ConnectionRequestState, ConnectionResponseState};
use super::control_plane::{
    observe_event_ids_for_peer, refill_wanted_requests, send_forward_on_have_hints,
    send_request_credit,
};
use super::coordinator::PeerCoord;
use super::data_plane::{drain_pending_responses_to_data_stream, spawn_data_receiver};
use super::logging::{SyncRunCapture, SyncRunRxCapture};
use super::windowing::{decode_initial_neg_open, SyncWindow, SyncWindowKind};
use super::{
    forward_on_have_enabled, negentropy_frame_size, send_idle_capture_enabled,
    CONTROL_POLL_TIMEOUT, INITIAL_CONTROL_PROGRESS_TIMEOUT,
};

fn should_treat_as_startup_control_abort(
    rounds: u64,
    events_sent: u64,
    bytes_received: &AtomicU64,
) -> bool {
    rounds == 0 && events_sent == 0 && bytes_received.load(Ordering::Relaxed) == 0
}

/// Run sync as the responder (server role) with dual streams.
///
/// Callers must provide a `shared_ingest` sender connected to a shared
/// batch_writer. The session never spawns its own writer thread.
/// This eliminates SQLite write contention when multiple sources sync
/// concurrently.
pub async fn run_sync_responder<C, S, R>(
    conn: DualConnection<C, S, R>,
    _session_id: u64,
    db_path: &str,
    timeout_secs: u64,
    _session_owner: &str,
    peer_id: &str,
    recorded_by: &str,
    ingress_source_tag: &str,
    coordination: &PeerCoord,
    request_state: &ConnectionRequestState,
    response_state: &ConnectionResponseState,
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
        "Starting negentropy sync (responder, dual-stream), activity timeout {}s",
        timeout_secs
    );

    let db = open_connection(db_path)?;
    let use_snapshot = !low_mem_mode();

    let ws_id = lookup_workspace_id(&db, recorded_by).ok_or_else(|| {
        format!(
            "no accepted workspace binding for peer_id={}, cannot start sync",
            recorded_by
        )
    })?;

    let db_path_for_neg = db_path.to_string();
    let ws_id_for_neg = ws_id.clone();
    let mut neg_req_tx: Option<std::sync::mpsc::Sender<Vec<u8>>> = None;
    let mut neg_resp_rx: Option<std::sync::mpsc::Receiver<Result<Vec<u8>, String>>> = None;
    let mut neg_worker: Option<std::thread::JoinHandle<()>> = None;
    let spawn_neg_worker = |window: SyncWindow| {
        let (req_tx, req_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let (resp_tx, resp_rx) = std::sync::mpsc::channel::<Result<Vec<u8>, String>>();
        let db_path = db_path_for_neg.clone();
        let ws_id = ws_id_for_neg.clone();
        let handle = std::thread::spawn(move || {
            let neg_db = open_connection(&db_path).expect("neg worker: open_connection");
            let neg_storage = match window.kind {
                SyncWindowKind::Full => NegentropyStorageSqlite::new(&neg_db, &ws_id),
                _ => NegentropyStorageSqlite::new_with_range(
                    &neg_db,
                    &ws_id,
                    window.ts_min(),
                    window.ts_max_exclusive(),
                ),
            };
            if use_snapshot {
                neg_db.execute("BEGIN", []).expect("neg worker: BEGIN");
            }
            neg_storage
                .rebuild_blocks()
                .expect("neg worker: rebuild_blocks");

            let item_count = neg_storage.size().unwrap_or(0);
            info!("Negentropy storage has {} items (responder)", item_count);

            let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), negentropy_frame_size())
                .expect("neg worker: Negentropy::new");

            while let Ok(msg) = req_rx.recv() {
                let result = neg.reconcile(&msg).map_err(|e| format!("{}", e));
                if resp_tx.send(result).is_err() {
                    break;
                }
            }

            if use_snapshot {
                let _ = neg_db.execute("COMMIT", []);
            }
        });
        (req_tx, resp_rx, handle)
    };

    let store = Store::new(&db);
    let timeline = EventTimeline::new(&db);
    let wanted = WantedEvents::new(&db);

    let events_received = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));

    let ingest_tx = shared_ingest;

    let (shutdown_tx, recv_handle) = spawn_data_receiver(
        data_recv,
        ingest_tx.clone(),
        events_received.clone(),
        bytes_received.clone(),
        recorded_by.to_string(),
        ingress_source_tag.to_string(),
        rx_capture,
    );

    let mut events_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let mut rounds = 0;
    let mut round_observed_ids: Vec<crate::crypto::EventId> = Vec::new();
    let mut round_open = false;
    let sync_start = Instant::now();
    let reconcile_start = Instant::now();
    let mut last_bytes_received = 0u64;
    let mut reconciling = false;
    let memtrace_enabled = low_mem_memtrace();
    let memtrace_interval = Duration::from_secs(2);
    let memtrace_file = std::env::var("LOW_MEM_MEMTRACE_FILE").ok();
    let mut last_memtrace = Instant::now();
    let mut last_alloc_trim = Instant::now();
    let idle_capture_enabled = send_idle_capture_enabled() && capture.is_some();
    let mut last_send_progress = Instant::now();
    let mut last_idle_marker = Instant::now();
    let forward_on_have = forward_on_have_enabled();
    let mut forward_hint_rx = forward_on_have.then(|| live_hints::subscribe(db_path, recorded_by));

    let credit_high = request_credit_high_watermark().max(1);
    let credit_low = request_credit_low_watermark().min(credit_high.saturating_sub(1));

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
                "Initial control progress timeout after {}ms (peer={})",
                sync_start.elapsed().as_millis(),
                peer_id
            );
            if let Some(capture) = capture.as_ref() {
                capture.record_marker(
                    "meta",
                    "state",
                    "InitialControlTimeout",
                    serde_json::to_string(&json!({
                        "peer_id": peer_id,
                        "elapsed_ms": sync_start.elapsed().as_millis(),
                        "reconciling": reconciling,
                    }))
                    .ok(),
                );
            }
            break;
        }

        // Check for reconciliation response from worker thread
        if reconciling {
            match neg_resp_rx
                .as_ref()
                .expect("neg responder worker missing")
                .try_recv()
            {
                Ok(Ok(response)) => {
                    reconciling = false;
                    last_activity = Instant::now();
                    if response.is_empty() {
                        info!(
                            "Reconciliation locally quiescent: {} rounds, {}ms",
                            rounds,
                            reconcile_start.elapsed().as_millis()
                        );
                    } else {
                        control.send(&Frame::NegMsg { msg: response }).await?;
                        control.flush().await?;
                    }
                }
                Ok(Err(e)) => {
                    return Err(e.into());
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    // Worker still processing — continue draining egress
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err("neg worker disconnected".into());
                }
            }
        }

        match tokio::time::timeout(CONTROL_POLL_TIMEOUT, control.recv()).await {
            Ok(Ok(Frame::NegOpen { msg })) => {
                last_activity = Instant::now();
                rounds += 1;
                let (window, inner_msg) =
                    decode_initial_neg_open(&msg).map_err(|e| format!("bad NegOpen: {e}"))?;
                if reconciling {
                    return Err("received overlapping NegOpen before prior round completed".into());
                }
                if round_open {
                    let _ = timeline.mark_discovery_round_completed_many(
                        &round_observed_ids,
                        current_timestamp_ms(),
                    );
                    drop(neg_req_tx.take());
                    let _ = neg_resp_rx.take();
                    if let Some(handle) = neg_worker.take() {
                        let _ = handle.join();
                    }
                    round_observed_ids.clear();
                }
                round_observed_ids.clear();
                let (req_tx, resp_rx, handle) = spawn_neg_worker(window);
                neg_req_tx = Some(req_tx);
                neg_resp_rx = Some(resp_rx);
                neg_worker = Some(handle);
                neg_req_tx
                    .as_ref()
                    .expect("neg worker sender missing")
                    .send(inner_msg.to_vec())
                    .map_err(|_| "neg worker channel closed".to_string())?;
                reconciling = true;
                round_open = true;
            }
            Ok(Ok(Frame::NegMsg { msg })) => {
                last_activity = Instant::now();
                rounds += 1;
                neg_req_tx
                    .as_ref()
                    .ok_or_else(|| "received NegMsg before NegOpen".to_string())?
                    .send(msg)
                    .map_err(|_| "neg worker channel closed".to_string())?;
                reconciling = true;
            }
            Ok(Ok(Frame::HaveList { ids })) => {
                last_activity = Instant::now();
                if ids.is_empty() {
                    continue;
                }
                let _ = timeline.mark_request_received_many(&ids, current_timestamp_ms());
                response_state.consume_requests(&ids);
            }
            Ok(Ok(Frame::NeedList { ids })) => {
                last_activity = Instant::now();
                let need_received_at = current_timestamp_ms();
                let _ = timeline.mark_need_list_received_many(&ids, need_received_at);
                let observed = observe_event_ids_for_peer(
                    &wanted,
                    &timeline,
                    recorded_by,
                    peer_id,
                    need_received_at,
                    &ids,
                    &mut round_observed_ids,
                )?;
                if observed > 0 {
                    info!(
                        "Observed {} needed IDs from peer {} via NeedList",
                        observed, peer_id
                    );
                }
            }
            Ok(Ok(Frame::RequestCredit { credits })) => {
                last_activity = Instant::now();
                request_state.add_credit(credits as usize, current_timestamp_ms());
            }
            Ok(Ok(_)) => {}
            Ok(Err(ConnectionError::Closed)) => {
                if should_treat_as_startup_control_abort(rounds, events_sent, &bytes_received) {
                    info!("Control stream closed before sync started by peer");
                } else {
                    info!("Control stream closed by peer");
                }
                break;
            }
            Ok(Err(e)) => {
                if should_treat_as_startup_control_abort(rounds, events_sent, &bytes_received) {
                    info!("Control stream closed before sync started: {}", e);
                } else {
                    warn!("Control stream error: {}", e);
                }
                break;
            }
            Err(_) => {}
        }

        let requested_now = refill_wanted_requests(
            &mut control,
            &wanted,
            &timeline,
            coordination,
            peer_id,
            request_state,
        )
        .await?;
        if requested_now > 0 {
            last_activity = Instant::now();
        }

        if let Some(receiver) = forward_hint_rx.as_mut() {
            let hinted =
                send_forward_on_have_hints(&mut control, &timeline, peer_id, receiver).await?;
            if hinted > 0 {
                last_activity = Instant::now();
            }
        }

        // Drain requested responses to data stream — runs even while worker is reconciling
        let send_stats = drain_pending_responses_to_data_stream(
            response_state,
            &timeline,
            &store,
            &mut data_send,
        )
        .await;
        events_sent += send_stats.events_sent_delta;
        bytes_sent += send_stats.bytes_sent_delta;
        if send_stats.events_sent_delta > 0 {
            last_activity = Instant::now();
            last_send_progress = Instant::now();
        }

        if neg_req_tx.is_some() {
            let grant = response_state.desired_credit_grant(credit_high, credit_low);
            if grant > 0 {
                send_request_credit(&mut control, grant).await?;
                response_state.note_granted(grant);
            }
        }

        if low_mem_mode() && last_alloc_trim.elapsed() >= Duration::from_millis(100) {
            let _ = memtrace::allocator_trim();
            last_alloc_trim = Instant::now();
        }

        if memtrace_enabled && last_memtrace.elapsed() >= memtrace_interval {
            let response_stats = response_state.stats();
            let request_stats = request_state.stats(current_timestamp_ms());
            let wanted_peer_backlog = wanted.count_backlog_for_peer(peer_id).unwrap_or(-1);
            let ingest_cap = ingest_tx.max_capacity();
            let ingest_used = ingest_cap.saturating_sub(ingest_tx.capacity());
            let sqlite_global = memtrace::sqlite_global_memory();
            let sqlite_db = memtrace::sqlite_db_memory(&db);
            let allocator = memtrace::allocator_memory();
            let line = format!(
                "LOWMEM_MEMTRACE responder peer={} rounds={} reconciling={} pending_responses={} response_credit_available={} wanted_peer_backlog={} request_inflight={} request_credit={} ingest_used={}/{} sqlite_mem_cur={} sqlite_mem_high={} sqlite_pcache_ovfl_cur={} sqlite_pcache_ovfl_high={} db_cache={} db_schema={} db_stmt={} mall_arena={} mall_used={} mall_free={} mall_mmap={} bytes_rx={} bytes_tx={}",
                peer_id,
                rounds,
                reconciling,
                response_stats.pending_len,
                response_stats.available_credit,
                wanted_peer_backlog,
                request_stats.inflight_len,
                request_stats.remote_credit,
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
                sqlite_db.map(|s| s.cache_used_bytes).unwrap_or(-1),
                sqlite_db.map(|s| s.schema_used_bytes).unwrap_or(-1),
                sqlite_db.map(|s| s.stmt_used_bytes).unwrap_or(-1),
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

        if idle_capture_enabled
            && last_send_progress.elapsed() >= Duration::from_secs(1)
            && last_idle_marker.elapsed() >= Duration::from_secs(1)
        {
            let response_stats = response_state.stats();
            let request_stats = request_state.stats(current_timestamp_ms());
            let pending_wanted_backlog = wanted.count_backlog_for_peer(peer_id).unwrap_or(0);
            if let Some(capture) = capture.as_ref() {
                let idle_state = if response_stats.pending_len > 0 {
                    "queued_not_sending"
                } else if reconciling || pending_wanted_backlog > 0 {
                    "waiting_on_control"
                } else {
                    "between_rounds"
                };
                capture.record_marker(
                    "meta",
                    "state",
                    "SendIdle",
                    serde_json::to_string(&json!({
                        "peer_id": peer_id,
                        "state": idle_state,
                        "idle_ms": last_send_progress.elapsed().as_millis(),
                        "reconciling": reconciling,
                        "pending_responses": response_stats.pending_len,
                        "response_credit_available": response_stats.available_credit,
                        "wanted_peer_backlog": pending_wanted_backlog,
                        "request_inflight": request_stats.inflight_len,
                        "request_credit": request_stats.remote_credit,
                    }))
                    .ok(),
                );
            }
            last_idle_marker = Instant::now();
        }
    }
    if round_open {
        let _ = timeline
            .mark_discovery_round_completed_many(&round_observed_ids, current_timestamp_ms());
    }
    // Drop the request channel to signal the worker to exit
    drop(neg_req_tx);
    if let Some(handle) = neg_worker {
        let _ = handle.join();
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
    info!("Sync stats (responder): {:?}", stats);
    Ok(stats)
}
