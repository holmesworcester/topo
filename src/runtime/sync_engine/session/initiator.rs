//! Sync initiator (client role) with dual-stream transport.
//!
//! Drives negentropy reconciliation and uses sink-driven `wanted` scheduling
//! for multi-source pull work division in both directions.

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
use crate::db::{
    open_connection,
    queue::current_timestamp_ms,
    store::{current_neg_visible_seq, lookup_workspace_id, Store},
    timeline::EventTimeline,
    wanted::WantedEvents,
};
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::runtime::build_mismatch::recent_build_mismatch_reason;
use crate::runtime::memtrace;
use crate::runtime::repeated_warning::should_emit_globally;
use crate::runtime::SyncStats;
use crate::sync::negentropy_sqlite::NegentropyStorageSqlite;
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};
use crate::tuning::{
    low_mem_memtrace, low_mem_mode, request_credit_high_watermark, request_credit_low_watermark,
};

use super::connection_scope::{ConnectionRequestState, ConnectionResponseState};
use super::control_plane::{
    enqueue_recent_local_responses, observe_need_ids_for_peer, refill_wanted_requests,
    send_initial_neg_open, send_need_list_from_have_ids, send_recent_local_need_hints,
    send_request_credit, NeedHintDedupe,
};
use super::coordinator::PeerCoord;
use super::data_plane::{drain_pending_responses_to_data_stream, spawn_data_receiver};
use super::logging::{SyncRunCapture, SyncRunRxCapture};
use super::windowing::{
    decode_round_neg_msg, encode_initial_neg_open, encode_round_neg_msg,
    mark_outbound_full_completed, select_outbound_window, SyncRound, SyncWindow, SyncWindowKind,
};
use super::{
    configure_sync_db_connection, control_loop_profile_enabled, control_loop_profile_threshold_ms,
    control_poll_timeout, discovery_round_gap, hot_hint_interval, hot_hint_lookback,
    hot_round_timeout, max_overlapping_hot_rounds, maybe_yield_after_control_send,
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
enum OutboundRoundEvent {
    Started {
        initial_msg: Vec<u8>,
        item_count: usize,
    },
    Progress {
        next_msg: Option<Vec<u8>>,
        have_ids: Vec<EventId>,
        need_ids: Vec<EventId>,
    },
}

#[derive(Debug)]
struct ActiveOutboundRound {
    round: SyncRound,
    kind: SyncWindowKind,
    started_at: Instant,
    started_at_ms: i64,
    request_tx: std::sync::mpsc::Sender<Vec<u8>>,
    response_rx: std::sync::mpsc::Receiver<Result<OutboundRoundEvent, String>>,
    handle: std::thread::JoinHandle<()>,
    observed_ids: Vec<EventId>,
    need_list_ids: Vec<EventId>,
}

fn spawn_outbound_round(
    db_path: &str,
    ws_id: &str,
    window: SyncWindow,
    round: SyncRound,
) -> Result<(ActiveOutboundRound, Vec<u8>), String> {
    let (request_tx, request_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (response_tx, response_rx) =
        std::sync::mpsc::channel::<Result<OutboundRoundEvent, String>>();
    let db_path = db_path.to_string();
    let ws_id = ws_id.to_string();
    let handle = std::thread::spawn(move || {
        let send_error =
            |response_tx: &std::sync::mpsc::Sender<Result<OutboundRoundEvent, String>>,
             err: String| {
                let _ = response_tx.send(Err(err));
            };

        let neg_db = match open_connection(&db_path) {
            Ok(conn) => conn,
            Err(err) => {
                send_error(&response_tx, format!("Failed to open round DB: {err}"));
                return;
            }
        };
        configure_sync_db_connection(&neg_db);
        let neg_storage = NegentropyStorageSqlite::new_with_scope(
            &neg_db,
            &ws_id,
            window.ts_min(),
            window.ts_max_exclusive(),
            Some(round.snapshot_seq),
        );
        let rebuild_start = Instant::now();
        if let Err(err) = neg_storage.rebuild_blocks() {
            send_error(&response_tx, format!("Failed to rebuild blocks: {err}"));
            return;
        }
        let item_count = neg_storage.size().unwrap_or(0);
        info!(
            "Initiator round {} storage has {} items (window={:?}, snapshot_seq={}, rebuild={}ms)",
            round.round_id,
            item_count,
            window.kind,
            round.snapshot_seq,
            rebuild_start.elapsed().as_millis()
        );

        let mut neg =
            match Negentropy::new(Storage::Borrowed(&neg_storage), negentropy_frame_size()) {
                Ok(neg) => neg,
                Err(err) => {
                    send_error(&response_tx, format!("Failed to init negentropy: {err}"));
                    return;
                }
            };
        let initial_msg = match neg.initiate() {
            Ok(msg) => msg,
            Err(err) => {
                send_error(
                    &response_tx,
                    format!("Failed to initiate negentropy: {err}"),
                );
                return;
            }
        };
        if response_tx
            .send(Ok(OutboundRoundEvent::Started {
                initial_msg,
                item_count,
            }))
            .is_err()
        {
            return;
        }

        while let Ok(msg) = request_rx.recv() {
            let mut have_ids = Vec::new();
            let mut need_ids = Vec::new();
            let next_msg = match neg.reconcile_with_ids(&msg, &mut have_ids, &mut need_ids) {
                Ok(next_msg) => next_msg,
                Err(err) => {
                    send_error(
                        &response_tx,
                        format!("Failed to reconcile negentropy: {err}"),
                    );
                    return;
                }
            };
            let event = OutboundRoundEvent::Progress {
                next_msg,
                have_ids: have_ids.iter().map(neg_id_to_event_id).collect(),
                need_ids: need_ids.iter().map(neg_id_to_event_id).collect(),
            };
            let is_done = matches!(&event, OutboundRoundEvent::Progress { next_msg: None, .. });
            if response_tx.send(Ok(event)).is_err() {
                return;
            }
            if is_done {
                return;
            }
        }
    });

    let initial_msg = match response_rx.recv() {
        Ok(Ok(OutboundRoundEvent::Started {
            initial_msg,
            item_count,
        })) => {
            info!(
                "Initiator round {} started (window={:?}, snapshot_seq={}, items={})",
                round.round_id, window.kind, round.snapshot_seq, item_count
            );
            initial_msg
        }
        Ok(Ok(_)) => return Err("round worker returned unexpected startup event".to_string()),
        Ok(Err(err)) => return Err(err),
        Err(_) => return Err("round worker disconnected before startup".to_string()),
    };

    Ok((
        ActiveOutboundRound {
            round,
            kind: window.kind,
            started_at: Instant::now(),
            started_at_ms: current_timestamp_ms(),
            request_tx,
            response_rx,
            handle,
            observed_ids: Vec::new(),
            need_list_ids: Vec::new(),
        },
        initial_msg,
    ))
}

fn finish_outbound_round(
    round: ActiveOutboundRound,
    timeline: &EventTimeline<'_>,
) -> Result<(), String> {
    let completed_at = current_timestamp_ms();
    if !round.observed_ids.is_empty() {
        let _ = timeline.mark_discovery_round_completed_many(&round.observed_ids, completed_at);
    }
    if !round.need_list_ids.is_empty() {
        let _ = timeline.mark_discovery_round_completed_many(&round.need_list_ids, completed_at);
    }
    drop(round.request_tx);
    round
        .handle
        .join()
        .map_err(|_| "round worker panicked".to_string())?;
    Ok(())
}

/// Run sync as the initiator (client role) with dual streams.
/// Control stream: NegOpen, NegMsg, HaveList, RequestCredit
/// Data stream: requested Event blobs
///
/// Discovery is still round-scoped, but all event-data transfer is pull-only:
/// both sides can request IDs under advertised credit and serve requested
/// responses from bounded in-memory connection state.
///
/// Callers must provide a `shared_ingest` sender connected to a shared
/// batch_writer. The session never spawns its own writer thread.
pub async fn run_sync_initiator<CS, CR, S, R>(
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
        "Starting negentropy sync (initiator, dual-stream), activity timeout {}s",
        timeout_secs
    );

    let db = open_connection(db_path)?;
    configure_sync_db_connection(&db);
    let wanted = WantedEvents::new(&db);
    let timeline = EventTimeline::new(&db);
    let ws_id = lookup_workspace_id(&db, recorded_by).ok_or_else(|| {
        format!(
            "no accepted workspace binding for peer_id={}, cannot start sync",
            recorded_by
        )
    })?;

    let store = Store::new(&db);

    let events_received = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));

    let ingest_tx = shared_ingest;

    let mut events_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let (control_shutdown_tx, mut control_rx, control_recv_handle) =
        spawn_control_receiver(control_recv);
    let (shutdown_tx, recv_handle) = spawn_data_receiver(
        data_recv,
        ingest_tx.clone(),
        events_received.clone(),
        bytes_received.clone(),
        recorded_by.to_string(),
        ingress_source_tag.to_string(),
        rx_capture,
    );

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
    let credit_high = request_credit_high_watermark().max(1);
    let credit_low = request_credit_low_watermark().min(credit_high.saturating_sub(1));
    let mut rounds_total = 0u64;
    let mut next_round_due = Instant::now();
    let mut next_hot_hint_due = Instant::now();
    let mut observed_initial_control_progress = false;
    let mut next_round_id = 1u64;
    let mut active_rounds: HashMap<u64, ActiveOutboundRound> = HashMap::new();
    let mut need_hint_dedupe = NeedHintDedupe::default();
    let profile_control_loop = control_loop_profile_enabled();
    let profile_threshold_ms = control_loop_profile_threshold_ms();

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
        if !observed_initial_control_progress
            && sync_start.elapsed() >= INITIAL_CONTROL_PROGRESS_TIMEOUT
        {
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
                        "need_ids": 0,
                    }))
                    .ok(),
                );
            }
            break;
        }

        if Instant::now() >= next_round_due {
            let reconcile_started_at_ms = current_timestamp_ms();
            let sync_window = select_outbound_window(db_path, peer_id, reconcile_started_at_ms);
            let active_full = active_rounds
                .values()
                .any(|round| round.kind == SyncWindowKind::Full);
            let active_cold = active_rounds
                .values()
                .any(|round| round.kind == SyncWindowKind::Cold);
            let active_hot = active_rounds
                .values()
                .filter(|round| round.kind == SyncWindowKind::Hot)
                .count();
            let can_start = match sync_window.kind {
                SyncWindowKind::Full => !active_full,
                SyncWindowKind::Cold => !active_cold,
                SyncWindowKind::Hot => active_hot < max_overlapping_hot_rounds(),
            };
            if can_start {
                let round = SyncRound {
                    round_id: next_round_id,
                    snapshot_seq: current_neg_visible_seq(&db)?,
                };
                next_round_id = next_round_id.saturating_add(1);
                let (active_round, initial_msg) =
                    spawn_outbound_round(db_path, &ws_id, sync_window, round)
                        .map_err(|e| format!("Failed to start outbound round: {e}"))?;
                let initial_msg = encode_initial_neg_open(sync_window, round, initial_msg);
                send_initial_neg_open(&mut control_send, initial_msg).await?;
                info!(
                    "Initiator sent NegOpen to peer={} remote_source={} window={:?} round_id={} snapshot_seq={}",
                    peer_id,
                    ingress_source_tag,
                    sync_window.kind,
                    round.round_id,
                    round.snapshot_seq
                );
                active_rounds.insert(round.round_id, active_round);
                observed_initial_control_progress = true;
                last_activity = Instant::now();
            }
            next_round_due = Instant::now() + discovery_round_gap();
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
            let timed_out = active_rounds
                .get(&round_id)
                .and_then(|round| {
                    if round.kind == SyncWindowKind::Hot {
                        hot_round_timeout().map(|timeout| round.started_at.elapsed() >= timeout)
                    } else {
                        None
                    }
                })
                .unwrap_or(false);
            if timed_out {
                if let Some(round) = active_rounds.get(&round_id) {
                    warn!(
                        "Hot reconciliation timeout after {}ms (peer={}, round_id={}, snapshot_seq={})",
                        round.started_at.elapsed().as_millis(),
                        peer_id,
                        round.round.round_id,
                        round.round.snapshot_seq
                    );
                }
                completed_round_ids.push(round_id);
                continue;
            }

            let round_event = match active_rounds.get_mut(&round_id) {
                Some(round) => round.response_rx.try_recv(),
                None => continue,
            };
            match round_event {
                Ok(Ok(OutboundRoundEvent::Progress {
                    next_msg,
                    mut have_ids,
                    mut need_ids,
                })) => {
                    let (round_meta, started_at_ms, kind) = {
                        let round = active_rounds
                            .get(&round_id)
                            .expect("active round missing during progress");
                        (round.round, round.started_at_ms, round.kind)
                    };
                    if let Some(round) = active_rounds.get_mut(&round_id) {
                        let observed_need_ids = observe_need_ids_for_peer(
                            &wanted,
                            &timeline,
                            recorded_by,
                            peer_id,
                            started_at_ms,
                            &mut need_ids,
                            &mut round.observed_ids,
                        )?;
                        if observed_need_ids > 0 {
                            info!(
                                "Observed {} wanted IDs from peer {} during round {}",
                                observed_need_ids, peer_id, round_meta.round_id
                            );
                        }
                        let sent_need_hints = send_need_list_from_have_ids(
                            &mut control_send,
                            &timeline,
                            &mut have_ids,
                            &mut round.need_list_ids,
                            &mut need_hint_dedupe,
                        )
                        .await?;
                        if sent_need_hints > 0 {
                            last_activity = Instant::now();
                        }
                    }
                    if let Some(ref next_msg) = next_msg {
                        control_send
                            .send(&Frame::NegMsg {
                                msg: encode_round_neg_msg(round_meta, next_msg.clone()),
                            })
                            .await?;
                        control_send.flush().await?;
                        maybe_yield_after_control_send().await;
                        last_activity = Instant::now();
                    }
                    if next_msg.is_none() {
                        info!(
                            "Reconciliation complete for round {} (window={:?}, elapsed={}ms)",
                            round_meta.round_id,
                            kind,
                            active_rounds
                                .get(&round_id)
                                .map(|round| round.started_at.elapsed().as_millis())
                                .unwrap_or_default()
                        );
                        if kind == SyncWindowKind::Full {
                            mark_outbound_full_completed(db_path, peer_id, current_timestamp_ms());
                        }
                        completed_round_ids.push(round_id);
                    }
                }
                Ok(Ok(OutboundRoundEvent::Started { .. })) => {}
                Ok(Err(err)) => return Err(err.into()),
                Err(std::sync::mpsc::TryRecvError::Empty) => {}
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err(format!("outbound round {} worker disconnected", round_id).into());
                }
            }
        }
        for round_id in completed_round_ids.drain(..) {
            if let Some(round) = active_rounds.remove(&round_id) {
                finish_outbound_round(round, &timeline)
                    .map_err(|e| format!("Failed to finish outbound round {round_id}: {e}"))?;
            }
        }
        profile_round_work_ms += phase_started_at.elapsed().as_millis();

        let phase_started_at = Instant::now();
        match tokio::time::timeout(control_poll_timeout(), control_rx.recv()).await {
            Ok(Some(Ok(Frame::NegMsg { msg }))) => {
                last_activity = Instant::now();
                rounds_total += 1;
                let (round_meta, inner_msg) =
                    decode_round_neg_msg(&msg).map_err(|e| format!("bad NegMsg: {e}"))?;
                if let Some(round) = active_rounds.get(&round_meta.round_id) {
                    round
                        .request_tx
                        .send(inner_msg.to_vec())
                        .map_err(|_| "round worker channel closed".to_string())?;
                } else if round_meta.round_id != 0 {
                    info!(
                        "Ignoring NegMsg for stale/unknown round {} from peer {}",
                        round_meta.round_id, peer_id
                    );
                }
            }
            Ok(Some(Ok(Frame::HaveList { ids }))) => {
                last_activity = Instant::now();
                if !ids.is_empty() {
                    let _ = timeline.mark_request_received_many(&ids, current_timestamp_ms());
                    response_state.consume_requests(&ids);
                }
            }
            Ok(Some(Ok(Frame::NeedList { ids }))) => {
                last_activity = Instant::now();
                if !ids.is_empty() {
                    let _ = timeline.mark_need_list_received_many(&ids, current_timestamp_ms());
                    let mut observed_ids = Vec::with_capacity(ids.len());
                    let observed = super::control_plane::observe_event_ids_for_peer(
                        &wanted,
                        &timeline,
                        recorded_by,
                        peer_id,
                        current_timestamp_ms(),
                        &ids,
                        &mut observed_ids,
                    )?;
                    if observed > 0 {
                        info!(
                            "Observed {} needed IDs from peer {} via NeedList",
                            observed, peer_id
                        );
                    }
                }
            }
            Ok(Some(Ok(Frame::RequestCredit { credits }))) => {
                last_activity = Instant::now();
                request_state.add_credit(credits as usize, current_timestamp_ms());
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(ConnectionError::Closed))) => {
                if should_treat_as_startup_control_abort(rounds_total, events_sent, &bytes_received)
                {
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
            Ok(Some(Err(e))) => {
                if should_treat_as_startup_control_abort(rounds_total, events_sent, &bytes_received)
                {
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
            Ok(None) => {
                info!("Control receiver task ended");
                break;
            }
            Err(_) => {}
        }
        profile_recv_ms += phase_started_at.elapsed().as_millis();

        let phase_started_at = Instant::now();
        let requested_now = refill_wanted_requests(
            &mut control_send,
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
        profile_refill_ms += phase_started_at.elapsed().as_millis();

        let phase_started_at = Instant::now();
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
        profile_drain_ms += phase_started_at.elapsed().as_millis();

        let phase_started_at = Instant::now();
        let grant = response_state.desired_credit_grant(credit_high, credit_low);
        if grant > 0 {
            send_request_credit(&mut control_send, grant).await?;
            response_state.note_granted(grant);
        }
        profile_grant_ms += phase_started_at.elapsed().as_millis();

        if low_mem_mode() && last_alloc_trim.elapsed() >= Duration::from_millis(100) {
            let _ = memtrace::allocator_trim();
            last_alloc_trim = Instant::now();
        }

        if memtrace_enabled && last_memtrace.elapsed() >= memtrace_interval {
            let wanted_pending = wanted.count().unwrap_or(-1);
            let wanted_peer_backlog = wanted.count_backlog_for_peer(peer_id).unwrap_or(-1);
            let request_stats = request_state.stats(current_timestamp_ms());
            let response_stats = response_state.stats();
            let ingest_cap = ingest_tx.max_capacity();
            let ingest_used = ingest_cap.saturating_sub(ingest_tx.capacity());
            let sqlite_global = memtrace::sqlite_global_memory();
            let sqlite_main = memtrace::sqlite_db_memory(&db);
            let allocator = memtrace::allocator_memory();
            let line = format!(
                "LOWMEM_MEMTRACE initiator peer={} rounds={} have={} need={} have_cap={} need_cap={} wanted_total={} wanted_peer_backlog={} request_inflight={} request_credit={} pending_responses={} response_credit_available={} ingest_used={}/{} sqlite_mem_cur={} sqlite_mem_high={} sqlite_pcache_ovfl_cur={} sqlite_pcache_ovfl_high={} db_main_cache={} db_main_schema={} db_main_stmt={} db_neg_cache={} db_neg_schema={} db_neg_stmt={} mall_arena={} mall_used={} mall_free={} mall_mmap={} bytes_rx={} bytes_tx={}",
                peer_id,
                rounds_total,
                0,
                0,
                0,
                0,
                wanted_pending,
                wanted_peer_backlog,
                request_stats.inflight_len,
                request_stats.remote_credit,
                response_stats.pending_len,
                response_stats.available_credit,
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
                -1,
                -1,
                -1,
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
        let request_stats = request_state.stats(current_timestamp_ms());
        let response_stats = response_state.stats();

        if idle_capture_enabled
            && last_send_progress.elapsed() >= Duration::from_secs(1)
            && last_idle_marker.elapsed() >= Duration::from_secs(1)
        {
            if let Some(capture) = capture.as_ref() {
                let idle_state = if response_stats.pending_len > 0 {
                    "queued_not_sending"
                } else if pending_wanted_backlog > 0 || !active_rounds.is_empty() {
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
                        "active_rounds": active_rounds.len(),
                        "wanted_peer_backlog": pending_wanted_backlog,
                        "request_inflight": request_stats.inflight_len,
                        "request_credit": request_stats.remote_credit,
                        "pending_responses": response_stats.pending_len,
                        "response_credit_available": response_stats.available_credit,
                        "wanted_pending": wanted.count().unwrap_or(-1),
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
                    "P7 loop initiator peer={} total={}ms recv={}ms hot_hint={}ms rounds={}ms refill={}ms drain={}ms grant={}ms active_rounds={} wanted_backlog={} request_credit={} request_inflight={} pending_responses={}",
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
        let _ = finish_outbound_round(round, &timeline);
    }
    let _ = control_shutdown_tx.send(());
    let _ = control_recv_handle.await;
    let _ = shutdown_tx.send(());
    let _ = recv_handle.await;
    drop(ingest_tx);

    let stats = SyncStats {
        events_sent,
        events_received: events_received.load(Ordering::Relaxed),
        neg_rounds: rounds_total,
        bytes_sent,
        bytes_received: bytes_received.load(Ordering::Relaxed),
        duration_ms: sync_start.elapsed().as_millis(),
    };
    info!("Sync stats: {:?}", stats);
    Ok(stats)
}
