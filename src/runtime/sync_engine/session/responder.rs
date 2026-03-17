//! Sync responder (server role) with dual-stream transport.
//!
//! Handles incoming negentropy reconciliation, serves requested events from a
//! bounded in-memory queue, issues sink-side requests under advertised credit,
//! and keeps those request/response lanes alive across repeated discovery
//! rounds on the same transport session.
//!
//! Reconciliation runs on a dedicated OS thread so the main loop can
//! continue draining requested responses during the 100-400ms reconcile() calls.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use negentropy::{Negentropy, NegentropyStorageBase, Storage};
use serde_json::json;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::EventId;
use crate::db::timeline::EventTimeline;
use crate::db::{
    open_connection,
    queue::current_timestamp_ms,
    store::{current_neg_visible_seq, lookup_workspace_id, Store},
    wanted::WantedEvents,
};
use crate::protocol::Frame;
use crate::runtime::memtrace;
use crate::runtime::SyncStats;
use crate::sync::negentropy_sqlite::NegentropyStorageSqlite;
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};
use crate::tuning::{
    low_mem_memtrace, low_mem_mode, request_credit_high_watermark, request_credit_low_watermark,
};

use super::connection_scope::{ConnectionRequestState, ConnectionResponseState};
use super::control_plane::{
    enqueue_recent_local_responses, observe_event_ids_for_peer, refill_wanted_requests,
    send_recent_local_need_hints, send_request_credit, NeedHintDedupe,
};
use super::coordinator::PeerCoord;
use super::data_plane::{drain_pending_responses_to_data_stream, spawn_data_receiver};
use super::logging::{SyncRunCapture, SyncRunRxCapture};
use super::windowing::{
    decode_initial_neg_open, decode_round_neg_msg, encode_round_neg_msg, SyncRound, SyncWindow,
    SyncWindowKind,
};
use super::{
    configure_sync_db_connection, control_loop_profile_enabled, control_loop_profile_threshold_ms,
    control_poll_timeout, hot_hint_interval, hot_hint_lookback, maybe_yield_after_control_send,
    negentropy_frame_size, send_idle_capture_enabled, spawn_control_receiver,
    INITIAL_CONTROL_PROGRESS_TIMEOUT,
};

fn should_treat_as_startup_control_abort(
    rounds: u64,
    events_sent: u64,
    bytes_received: &AtomicU64,
) -> bool {
    rounds == 0 && events_sent == 0 && bytes_received.load(Ordering::Relaxed) == 0
}

#[derive(Debug)]
struct ActiveInboundRound {
    round: SyncRound,
    kind: SyncWindowKind,
    started_at: Instant,
    request_tx: std::sync::mpsc::Sender<Vec<u8>>,
    response_rx: std::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
    handle: std::thread::JoinHandle<()>,
    observed_ids: Vec<EventId>,
}

fn spawn_inbound_round(
    db_path: &str,
    ws_id: &str,
    window: SyncWindow,
    round: SyncRound,
) -> ActiveInboundRound {
    let (request_tx, request_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (response_tx, response_rx) = std::sync::mpsc::channel::<Result<Vec<u8>, String>>();
    let db_path = db_path.to_string();
    let ws_id = ws_id.to_string();
    let handle = std::thread::spawn(move || {
        let neg_db = open_connection(&db_path).expect("neg worker: open_connection");
        configure_sync_db_connection(&neg_db);
        let neg_storage = NegentropyStorageSqlite::new_with_scope(
            &neg_db,
            &ws_id,
            window.ts_min(),
            window.ts_max_exclusive(),
            Some(round.snapshot_seq),
        );
        let rebuild_start = Instant::now();
        neg_storage
            .rebuild_blocks()
            .expect("neg worker: rebuild_blocks");
        let item_count = neg_storage.size().unwrap_or(0);
        info!(
            "Responder round {} storage has {} items (window={:?}, snapshot_seq={}, rebuild={}ms)",
            round.round_id,
            item_count,
            window.kind,
            round.snapshot_seq,
            rebuild_start.elapsed().as_millis()
        );

        let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), negentropy_frame_size())
            .expect("neg worker: Negentropy::new");

        while let Ok(msg) = request_rx.recv() {
            let reconcile_start = Instant::now();
            let result = neg.reconcile(&msg).map_err(|e| format!("{e}"));
            info!(
                "Responder worker processed negentropy message (round={}, window={:?}, req_bytes={}, elapsed={}ms, ok={})",
                round.round_id,
                window.kind,
                msg.len(),
                reconcile_start.elapsed().as_millis(),
                result.is_ok()
            );
            if response_tx.send(result).is_err() {
                break;
            }
        }
    });

    ActiveInboundRound {
        round,
        kind: window.kind,
        started_at: Instant::now(),
        request_tx,
        response_rx,
        handle,
        observed_ids: Vec::new(),
    }
}

fn finish_inbound_round(
    round: ActiveInboundRound,
    timeline: &EventTimeline<'_>,
) -> Result<(), String> {
    if !round.observed_ids.is_empty() {
        let _ = timeline
            .mark_discovery_round_completed_many(&round.observed_ids, current_timestamp_ms());
    }
    drop(round.request_tx);
    round
        .handle
        .join()
        .map_err(|_| "round worker panicked".to_string())?;
    Ok(())
}

/// Run sync as the responder (server role) with dual streams.
///
/// Callers must provide a `shared_ingest` sender connected to a shared
/// batch_writer. The session never spawns its own writer thread.
/// This eliminates SQLite write contention when multiple sources sync
/// concurrently.
pub async fn run_sync_responder<CS, CR, S, R>(
    mut control_send: CS,
    control_recv: CR,
    mut data_send: S,
    data_recv: R,
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
    CS: StreamSend,
    CR: StreamRecv + Send + 'static,
    S: StreamSend,
    R: StreamRecv + Send + 'static,
{
    let start = Instant::now();
    let activity_timeout = Duration::from_secs(timeout_secs);
    let mut last_activity = Instant::now();

    info!(
        "Starting negentropy sync (responder, dual-stream), activity timeout {}s",
        timeout_secs
    );

    let db = open_connection(db_path)?;
    configure_sync_db_connection(&db);

    let ws_id = lookup_workspace_id(&db, recorded_by).ok_or_else(|| {
        format!(
            "no accepted workspace binding for peer_id={}, cannot start sync",
            recorded_by
        )
    })?;

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
    let (control_shutdown_tx, mut control_rx, control_recv_handle) =
        spawn_control_receiver(control_recv);
    let mut rounds = 0;
    let sync_start = Instant::now();
    let mut last_bytes_received = 0u64;
    let memtrace_enabled = low_mem_memtrace();
    let memtrace_interval = Duration::from_secs(2);
    let memtrace_file = std::env::var("LOW_MEM_MEMTRACE_FILE").ok();
    let mut last_memtrace = Instant::now();
    let mut last_alloc_trim = Instant::now();
    let idle_capture_enabled = send_idle_capture_enabled() && capture.is_some();
    let mut last_send_progress = Instant::now();
    let mut last_idle_marker = Instant::now();
    let mut next_hot_hint_due = Instant::now();
    let mut active_rounds: HashMap<u64, ActiveInboundRound> = HashMap::new();
    let mut need_hint_dedupe = NeedHintDedupe::default();
    let profile_control_loop = control_loop_profile_enabled();
    let profile_threshold_ms = control_loop_profile_threshold_ms();

    let credit_high = request_credit_high_watermark().max(1);
    let credit_low = request_credit_low_watermark().min(credit_high.saturating_sub(1));

    loop {
        let loop_started_at = Instant::now();
        let mut profile_hot_hint_ms = 0u128;
        let mut profile_round_work_ms = 0u128;
        let mut profile_recv_ms = 0u128;
        let mut profile_refill_ms = 0u128;
        let mut profile_drain_ms = 0u128;
        let mut profile_grant_ms = 0u128;

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
                        "reconciling": !active_rounds.is_empty(),
                    }))
                    .ok(),
                );
            }
            break;
        }

        if Instant::now() >= next_hot_hint_due {
            let phase_started_at = Instant::now();
            let scan_until_ms = current_timestamp_ms();
            let scan_from_ms = scan_until_ms.saturating_sub(hot_hint_lookback().as_millis() as i64);
            let hinted = send_recent_local_need_hints(
                &mut control_send,
                &timeline,
                &db,
                recorded_by,
                scan_from_ms,
                scan_until_ms,
                &mut need_hint_dedupe,
            )
            .await?;
            if hinted > 0 {
                last_activity = Instant::now();
            }
            let pushed = enqueue_recent_local_responses(
                response_state,
                &db,
                recorded_by,
                scan_from_ms,
                scan_until_ms,
            )?;
            if pushed > 0 {
                last_activity = Instant::now();
            }
            next_hot_hint_due = Instant::now() + hot_hint_interval();
            profile_hot_hint_ms += phase_started_at.elapsed().as_millis();
        }

        let phase_started_at = Instant::now();
        let mut completed_round_ids = Vec::new();
        let active_round_ids: Vec<u64> = active_rounds.keys().copied().collect();
        for round_id in active_round_ids {
            let round_result = match active_rounds.get_mut(&round_id) {
                Some(round) => round.response_rx.try_recv(),
                None => continue,
            };
            match round_result {
                Ok(Ok(response)) => {
                    last_activity = Instant::now();
                    let round = active_rounds
                        .get(&round_id)
                        .expect("inbound round missing during response");
                    if response.is_empty() {
                        info!(
                            "Reconciliation complete for round {} (window={:?}, elapsed={}ms)",
                            round.round.round_id,
                            round.kind,
                            round.started_at.elapsed().as_millis()
                        );
                        completed_round_ids.push(round_id);
                    } else {
                        control_send
                            .send(&Frame::NegMsg {
                                msg: encode_round_neg_msg(round.round, response),
                            })
                            .await?;
                        control_send.flush().await?;
                        maybe_yield_after_control_send().await;
                    }
                }
                Ok(Err(err)) => return Err(err.into()),
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err(format!("neg worker disconnected for round {}", round_id).into());
                }
            }
        }
        for round_id in completed_round_ids.drain(..) {
            if let Some(round) = active_rounds.remove(&round_id) {
                finish_inbound_round(round, &timeline)
                    .map_err(|e| format!("Failed to finish inbound round {round_id}: {e}"))?;
            }
        }
        profile_round_work_ms += phase_started_at.elapsed().as_millis();

        let phase_started_at = Instant::now();
        match tokio::time::timeout(control_poll_timeout(), control_rx.recv()).await {
            Ok(Some(Ok(Frame::NegOpen { msg }))) => {
                last_activity = Instant::now();
                rounds += 1;
                let (open, inner_msg) =
                    decode_initial_neg_open(&msg).map_err(|e| format!("bad NegOpen: {e}"))?;
                if active_rounds.contains_key(&open.round.round_id) {
                    return Err(format!(
                        "received overlapping NegOpen for round {}",
                        open.round.round_id
                    )
                    .into());
                }
                let round = SyncRound {
                    round_id: open.round.round_id,
                    snapshot_seq: current_neg_visible_seq(&db)?,
                };
                let inbound_round = spawn_inbound_round(db_path, &ws_id, open.window, round);
                inbound_round
                    .request_tx
                    .send(inner_msg.to_vec())
                    .map_err(|_| "neg worker channel closed".to_string())?;
                info!(
                    "Responder accepted NegOpen for round {} (remote_snapshot_seq={}, local_snapshot_seq={}, window={:?})",
                    round.round_id,
                    open.round.snapshot_seq,
                    round.snapshot_seq,
                    open.window.kind
                );
                active_rounds.insert(round.round_id, inbound_round);
            }
            Ok(Some(Ok(Frame::NegMsg { msg }))) => {
                last_activity = Instant::now();
                rounds += 1;
                let (round, inner_msg) =
                    decode_round_neg_msg(&msg).map_err(|e| format!("bad NegMsg: {e}"))?;
                if let Some(active_round) = active_rounds.get(&round.round_id) {
                    active_round
                        .request_tx
                        .send(inner_msg.to_vec())
                        .map_err(|_| "neg worker channel closed".to_string())?;
                } else if round.round_id != 0 {
                    info!(
                        "Ignoring NegMsg for stale/unknown round {} from peer {}",
                        round.round_id, peer_id
                    );
                } else {
                    return Err("received NegMsg before NegOpen".into());
                }
            }
            Ok(Some(Ok(Frame::HaveList { ids }))) => {
                last_activity = Instant::now();
                if ids.is_empty() {
                    continue;
                }
                let mark_request_received_start = Instant::now();
                let _ = timeline.mark_request_received_many(&ids, current_timestamp_ms());
                let mark_request_received_elapsed = mark_request_received_start.elapsed();
                if mark_request_received_elapsed >= Duration::from_millis(50) {
                    info!(
                        "Responder mark_request_received_many took {}ms (ids={})",
                        mark_request_received_elapsed.as_millis(),
                        ids.len()
                    );
                }
                response_state.consume_requests(&ids);
            }
            Ok(Some(Ok(Frame::NeedList { ids }))) => {
                last_activity = Instant::now();
                let need_received_at = current_timestamp_ms();
                let mark_need_list_received_start = Instant::now();
                let _ = timeline.mark_need_list_received_many(&ids, need_received_at);
                let mark_need_list_received_elapsed = mark_need_list_received_start.elapsed();
                if mark_need_list_received_elapsed >= Duration::from_millis(50) {
                    info!(
                        "Responder mark_need_list_received_many took {}ms (ids={})",
                        mark_need_list_received_elapsed.as_millis(),
                        ids.len()
                    );
                }
                let observe_needed_start = Instant::now();
                let mut observed_ids = Vec::with_capacity(ids.len());
                let observed = observe_event_ids_for_peer(
                    &wanted,
                    &timeline,
                    recorded_by,
                    peer_id,
                    current_timestamp_ms(),
                    &ids,
                    &mut observed_ids,
                )?;
                let observe_needed_elapsed = observe_needed_start.elapsed();
                if observe_needed_elapsed >= Duration::from_millis(50) {
                    info!(
                        "Responder observe_event_ids_for_peer took {}ms (ids={}, observed={})",
                        observe_needed_elapsed.as_millis(),
                        ids.len(),
                        observed
                    );
                }
                if observed > 0 {
                    info!(
                        "Observed {} needed IDs from peer {} via NeedList",
                        observed, peer_id
                    );
                }
            }
            Ok(Some(Ok(Frame::RequestCredit { credits }))) => {
                last_activity = Instant::now();
                request_state.add_credit(credits as usize, current_timestamp_ms());
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(ConnectionError::Closed))) => {
                if should_treat_as_startup_control_abort(rounds, events_sent, &bytes_received) {
                    info!("Control stream closed before sync started by peer");
                } else {
                    info!("Control stream closed by peer");
                }
                break;
            }
            Ok(Some(Err(e))) => {
                if should_treat_as_startup_control_abort(rounds, events_sent, &bytes_received) {
                    info!("Control stream closed before sync started: {}", e);
                } else {
                    warn!("Control stream error: {}", e);
                }
                break;
            }
            Ok(None) => {
                info!("Control receiver task ended");
                break;
            }
            Err(_) => {}
        }
        profile_recv_ms += phase_started_at.elapsed().as_millis();

        let phase_started_at = Instant::now();
        let refill_start = Instant::now();
        let requested_now = refill_wanted_requests(
            &mut control_send,
            &wanted,
            &timeline,
            coordination,
            peer_id,
            request_state,
        )
        .await?;
        let refill_elapsed = refill_start.elapsed();
        if refill_elapsed >= Duration::from_millis(50) {
            info!(
                "Responder refill_wanted_requests took {}ms (requested_now={}, reconciling={})",
                refill_elapsed.as_millis(),
                requested_now,
                !active_rounds.is_empty()
            );
        }
        if requested_now > 0 {
            last_activity = Instant::now();
        }
        profile_refill_ms += phase_started_at.elapsed().as_millis();

        // Drain requested responses to data stream — runs even while worker is reconciling
        let phase_started_at = Instant::now();
        let drain_start = Instant::now();
        let send_stats = drain_pending_responses_to_data_stream(
            response_state,
            &timeline,
            &store,
            &mut data_send,
        )
        .await;
        let drain_elapsed = drain_start.elapsed();
        if drain_elapsed >= Duration::from_millis(50) {
            let response_stats = response_state.stats();
            info!(
                "Responder data drain took {}ms (events_sent_delta={}, bytes_sent_delta={}, pending_after={}, reconciling={})",
                drain_elapsed.as_millis(),
                send_stats.events_sent_delta,
                send_stats.bytes_sent_delta,
                response_stats.pending_len,
                !active_rounds.is_empty()
            );
        }
        events_sent += send_stats.events_sent_delta;
        bytes_sent += send_stats.bytes_sent_delta;
        if send_stats.events_sent_delta > 0 {
            last_activity = Instant::now();
            last_send_progress = Instant::now();
        }
        profile_drain_ms += phase_started_at.elapsed().as_millis();

        if !active_rounds.is_empty() {
            let phase_started_at = Instant::now();
            let grant = response_state.desired_credit_grant(credit_high, credit_low);
            if grant > 0 {
                send_request_credit(&mut control_send, grant).await?;
                response_state.note_granted(grant);
            }
            profile_grant_ms += phase_started_at.elapsed().as_millis();
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
                !active_rounds.is_empty(),
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
                } else if !active_rounds.is_empty() || pending_wanted_backlog > 0 {
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
                        "reconciling": !active_rounds.is_empty(),
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

        if profile_control_loop {
            let total_ms = loop_started_at.elapsed().as_millis();
            let slow = total_ms >= profile_threshold_ms
                || profile_hot_hint_ms >= profile_threshold_ms
                || profile_round_work_ms >= profile_threshold_ms
                || profile_recv_ms >= profile_threshold_ms
                || profile_refill_ms >= profile_threshold_ms
                || profile_drain_ms >= profile_threshold_ms
                || profile_grant_ms >= profile_threshold_ms;
            if slow {
                let request_stats = request_state.stats(current_timestamp_ms());
                let response_stats = response_state.stats();
                eprintln!(
                    "P7 loop responder peer={} total={}ms recv={}ms hot_hint={}ms rounds={}ms refill={}ms drain={}ms grant={}ms active_rounds={} wanted_backlog={} request_credit={} request_inflight={} pending_responses={}",
                    peer_id,
                    total_ms,
                    profile_recv_ms,
                    profile_hot_hint_ms,
                    profile_round_work_ms,
                    profile_refill_ms,
                    profile_drain_ms,
                    profile_grant_ms,
                    active_rounds.len(),
                    wanted.count_backlog_for_peer(peer_id).unwrap_or(-1),
                    request_stats.remote_credit,
                    request_stats.inflight_len,
                    response_stats.pending_len,
                );
            }
        }
    }
    for (_, round) in active_rounds.drain() {
        let _ = finish_inbound_round(round, &timeline);
    }
    let _ = control_shutdown_tx.send(());
    let _ = control_recv_handle.await;
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
