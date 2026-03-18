//! Sync initiator (client role) with dual-stream transport.
//!
//! Drives negentropy reconciliation and uses sink-driven `wanted` scheduling
//! for multi-source pull work division in both directions.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use negentropy::{Id, Negentropy, NegentropyStorageBase, Storage};
use serde_json::json;
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::db::{
    open_connection,
    queue::current_timestamp_ms,
    store::{lookup_workspace_id, Store},
    timeline::EventTimeline,
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
use crate::tuning::{
    low_mem_memtrace, low_mem_mode, response_credit_high_watermark_bytes,
    response_credit_low_watermark_bytes,
};

use super::connection_scope::{ConnectionRequestState, ConnectionResponseState};
use crate::state::live_hints;

use super::control_plane::{
    observe_discovery_hints_for_peer, refill_wanted_requests, send_discovery_hints_from_have_ids,
    send_forward_on_have_hints, send_initial_neg_open, send_response_credit_bytes,
};
use super::coordinator::PeerCoord;
use super::data_plane::{drain_pending_responses_to_data_stream, spawn_data_receiver};
use super::logging::{SyncRunCapture, SyncRunRxCapture};
use super::windowing::{
    encode_initial_neg_open, mark_outbound_full_completed, select_outbound_window, SyncWindowKind,
};
use super::{
    discovery_round_gap, forward_on_have_enabled, negentropy_frame_size, send_idle_capture_enabled,
    CONTROL_POLL_TIMEOUT, INITIAL_CONTROL_PROGRESS_TIMEOUT,
};

fn should_treat_as_startup_control_abort(
    rounds: u64,
    events_sent: u64,
    bytes_received: &AtomicU64,
) -> bool {
    rounds == 0 && events_sent == 0 && bytes_received.load(Ordering::Relaxed) == 0
}

/// Run sync as the initiator (client role) with dual streams.
/// Control stream: NegOpen, NegMsg, DiscoveryHints, RequestIds, ResponseCredit
/// Data stream: requested Event blobs
///
/// Discovery is still round-scoped, but all event-data transfer is pull-only:
/// both sides can request IDs under advertised credit and serve requested
/// responses from bounded in-memory connection state.
///
/// Callers must provide a `shared_ingest` sender connected to a shared
/// batch_writer. The session never spawns its own writer thread.
pub async fn run_sync_initiator<C, S, R>(
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
    mut command_rx: Option<tokio::sync::mpsc::Receiver<crate::runtime::sync_control::SessionCommand>>,
    policy_rx: Option<tokio::sync::watch::Receiver<crate::shared::sync_control::TenantSyncPolicy>>,
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
    let wanted = WantedEvents::new(&db);
    let timeline = EventTimeline::new(&db);
    let ws_id = lookup_workspace_id(&db, recorded_by).ok_or_else(|| {
        format!(
            "no accepted workspace binding for peer_id={}, cannot start sync",
            recorded_by
        )
    })?;
    let neg_db = open_connection(db_path)?;
    let use_snapshot = !low_mem_mode();

    let store = Store::new(&db);

    let events_received = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));

    let ingest_tx = shared_ingest;

    let mut events_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
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
    let credit_high = response_credit_high_watermark_bytes().max(1);
    let credit_low = response_credit_low_watermark_bytes().min(credit_high.saturating_sub(1));
    let mut forward_hint_rx = live_hints::subscribe(db_path, recorded_by);
    let mut rounds_total = 0u64;
    let mut next_round_due = Instant::now();
    let mut observed_initial_control_progress = false;
    let mut pending_round_reply: Option<
        std::sync::mpsc::Sender<Result<crate::runtime::sync_control::ManualSyncRoundCapture, String>>,
    > = None;

    'session: loop {
        // Process manual commands from the sync control registry.
        if let Some(ref mut rx) = command_rx {
            while let Ok(cmd) = rx.try_recv() {
                use crate::runtime::sync_control::SessionCommand;
                match cmd {
                    SessionCommand::ForceRound { reply } => {
                        pending_round_reply = Some(reply);
                        next_round_due = Instant::now();
                    }
                    SessionCommand::ForceRequest { reply } => {
                        let (count, ids) = refill_wanted_requests(
                            &mut control,
                            &wanted,
                            &timeline,
                            coordination,
                            peer_id,
                            request_state,
                        )
                        .await?;
                        if count > 0 {
                            last_activity = Instant::now();
                        }
                        let id_hexes: Vec<String> =
                            ids.iter().map(|id| hex::encode(id)).collect();
                        let _ = reply.send(Ok(crate::runtime::sync_control::ManualSyncRequestResult {
                            peer_id: peer_id.to_string(),
                            requested_ids: id_hexes,
                            reason: None,
                        }));
                    }
                }
            }
        }

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
            let reconcile_start = Instant::now();
            let reconcile_started_at_ms = current_timestamp_ms();
            let sync_window = select_outbound_window(db_path, peer_id, reconcile_started_at_ms);
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
            let neg_item_count = neg_storage.size().unwrap_or(0);
            info!(
                "Negentropy storage has {} items (initiator, window={:?})",
                neg_item_count, sync_window.kind
            );

            let mut neg =
                Negentropy::new(Storage::Borrowed(&neg_storage), negentropy_frame_size())?;
            let initial_msg = neg.initiate()?;
            let initial_msg = encode_initial_neg_open(sync_window, initial_msg);
            send_initial_neg_open(&mut control, initial_msg).await?;
            info!(
                "Initiator sent NegOpen to peer={} remote_source={} window={:?}",
                peer_id, ingress_source_tag, sync_window.kind
            );
            observed_initial_control_progress = true;
            last_activity = Instant::now();

            let mut have_ids: Vec<Id> = Vec::new();
            let mut need_ids: Vec<Id> = Vec::new();
            let mut round_observed_ids: Vec<crate::crypto::EventId> = Vec::new();
            let mut round_need_list_ids: Vec<crate::crypto::EventId> = Vec::new();
            let mut reconciliation_done = false;
            let mut round_rounds = 0u64;

            while !reconciliation_done {
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
                    break 'session;
                }

                match tokio::time::timeout(CONTROL_POLL_TIMEOUT, control.recv()).await {
                    Ok(Ok(Frame::NegMsg { msg })) => {
                        last_activity = Instant::now();
                        round_rounds += 1;
                        rounds_total += 1;
                        match neg.reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)? {
                            Some(next_msg) => {
                                control.send(&Frame::NegMsg { msg: next_msg }).await?;
                                control.flush().await?;
                            }
                            None => {
                                info!(
                                    "Reconciliation complete: {} rounds, {}ms, have={} need={}",
                                    round_rounds,
                                    reconcile_start.elapsed().as_millis(),
                                    have_ids.len(),
                                    need_ids.len()
                                );
                                reconciliation_done = true;
                                let completed_at = current_timestamp_ms();
                                let _ = timeline.mark_discovery_round_completed_many(
                                    &round_observed_ids,
                                    completed_at,
                                );
                                let _ = timeline.mark_discovery_round_completed_many(
                                    &round_need_list_ids,
                                    completed_at,
                                );

                                // Reply to pending ForceRound command if one is waiting.
                                if let Some(reply) = pending_round_reply.take() {
                                    let newly_hex: Vec<String> = round_observed_ids
                                        .iter()
                                        .map(|eid| hex::encode(eid))
                                        .collect();
                                    let _ = reply.send(Ok(crate::runtime::sync_control::ManualSyncRoundCapture {
                                        peer_id: peer_id.to_string(),
                                        observed_ids: newly_hex,
                                    }));
                                }
                            }
                        }
                        let sent_need_hints = send_discovery_hints_from_have_ids(
                            &mut control,
                            &timeline,
                            &store,
                            &mut have_ids,
                            &mut round_need_list_ids,
                        )
                        .await?;
                        if sent_need_hints > 0 {
                            last_activity = Instant::now();
                        }
                    }
                    Ok(Ok(Frame::RequestIds { ids })) => {
                        last_activity = Instant::now();
                        if !ids.is_empty() {
                            let _ =
                                timeline.mark_request_received_many(&ids, current_timestamp_ms());
                            super::data_plane::queue_requested_responses(
                                response_state,
                                &timeline,
                                &store,
                                &ids,
                            );
                        }
                    }
                    Ok(Ok(Frame::DiscoveryHints { hints })) => {
                        last_activity = Instant::now();
                        let hint_ids: Vec<_> = hints.iter().map(|h| h.event_id).collect();
                        let _ = timeline.mark_need_list_received_many(
                            &hint_ids,
                            current_timestamp_ms(),
                        );
                        let observed = observe_discovery_hints_for_peer(
                            &wanted,
                            &timeline,
                            recorded_by,
                            peer_id,
                            reconcile_started_at_ms,
                            &hints,
                            &mut round_observed_ids,
                        )?;
                        if observed > 0 {
                            info!(
                                "Observed {} discovery hints from peer {} during reconciliation",
                                observed, peer_id
                            );
                        }
                    }
                    Ok(Ok(Frame::ResponseCredit { bytes })) => {
                        last_activity = Instant::now();
                        request_state.add_credit_bytes(bytes as usize, current_timestamp_ms());
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(ConnectionError::Closed)) => {
                        if should_treat_as_startup_control_abort(
                            rounds_total,
                            events_sent,
                            &bytes_received,
                        ) {
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
                        break 'session;
                    }
                    Ok(Err(e)) => {
                        if should_treat_as_startup_control_abort(
                            rounds_total,
                            events_sent,
                            &bytes_received,
                        ) {
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
                        break 'session;
                    }
                    Err(_) => {}
                }

                let need_hints: Vec<crate::protocol::DiscoveryHint> = need_ids
                    .drain(..)
                    .map(|neg_id| {
                        let event_id = crate::protocol::neg_id_to_event_id(&neg_id);
                        match store.get_shared_summary(&event_id) {
                            Ok(Some(summary)) => crate::protocol::DiscoveryHint {
                                event_id: summary.event_id,
                                semantic_type_code: summary.semantic_type_code,
                                encoded_size_bytes: summary.encoded_size_bytes,
                            },
                            _ => crate::protocol::DiscoveryHint {
                                event_id,
                                semantic_type_code: 0,
                                encoded_size_bytes: 0,
                            },
                        }
                    })
                    .collect();
                let observed_need_ids = observe_discovery_hints_for_peer(
                    &wanted,
                    &timeline,
                    recorded_by,
                    peer_id,
                    reconcile_started_at_ms,
                    &need_hints,
                    &mut round_observed_ids,
                )?;
                if observed_need_ids > 0 {
                    info!(
                        "Observed {} wanted IDs from peer {} during reconciliation",
                        observed_need_ids, peer_id
                    );
                }
                let auto_requests = policy_rx
                    .as_ref()
                    .map(|rx| rx.borrow().requests == crate::shared::sync_control::SyncPolicyMode::Auto)
                    .unwrap_or(true);
                if auto_requests {
                    let (requested_now, _) = refill_wanted_requests(
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
                }

                if forward_on_have_enabled() {
                    let hinted = send_forward_on_have_hints(
                        &mut control,
                        &timeline,
                        &store,
                        peer_id,
                        &mut forward_hint_rx,
                    )
                    .await?;
                    if hinted > 0 {
                        last_activity = Instant::now();
                    }
                }

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

                let grant = response_state.desired_credit_grant_bytes(credit_high, credit_low);
                if grant > 0 {
                    send_response_credit_bytes(&mut control, grant).await?;
                    response_state.note_granted_bytes(grant);
                }

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
                    let sqlite_neg = memtrace::sqlite_db_memory(&neg_db);
                    let allocator = memtrace::allocator_memory();
                    let line = format!(
                        "LOWMEM_MEMTRACE initiator peer={} rounds={} have={} need={} have_cap={} need_cap={} wanted_total={} wanted_peer_backlog={} request_inflight={} request_credit={} pending_responses={} response_credit_available={} ingest_used={}/{} sqlite_mem_cur={} sqlite_mem_high={} sqlite_pcache_ovfl_cur={} sqlite_pcache_ovfl_high={} db_main_cache={} db_main_schema={} db_main_stmt={} db_neg_cache={} db_neg_schema={} db_neg_stmt={} mall_arena={} mall_used={} mall_free={} mall_mmap={} bytes_rx={} bytes_tx={}",
                        peer_id,
                        rounds_total,
                        have_ids.len(),
                        need_ids.len(),
                        have_ids.capacity(),
                        need_ids.capacity(),
                        wanted_pending,
                        wanted_peer_backlog,
                        request_stats.inflight_len,
                        request_stats.remote_credit_bytes,
                        response_stats.pending_len,
                        response_stats.available_credit_bytes,
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
                let request_stats = request_state.stats(current_timestamp_ms());
                let response_stats = response_state.stats();

                if idle_capture_enabled
                    && last_send_progress.elapsed() >= Duration::from_secs(1)
                    && last_idle_marker.elapsed() >= Duration::from_secs(1)
                {
                    if let Some(capture) = capture.as_ref() {
                        let idle_state = if response_stats.pending_len > 0 {
                            "queued_not_sending"
                        } else if !reconciliation_done
                            || !need_ids.is_empty()
                            || pending_wanted_backlog > 0
                        {
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
                                "reconciliation_done": reconciliation_done,
                                "need_ids": need_ids.len(),
                                "wanted_peer_backlog": pending_wanted_backlog,
                                "request_inflight": request_stats.inflight_len,
                                "response_credit_bytes": request_stats.remote_credit_bytes,
                                "pending_responses": response_stats.pending_len,
                                "response_credit_available_bytes": response_stats.available_credit_bytes,
                                "wanted_pending": wanted.count().unwrap_or(-1),
                            }))
                            .ok(),
                        );
                    }
                    last_idle_marker = Instant::now();
                }
            }

            if sync_window.kind == SyncWindowKind::Full {
                mark_outbound_full_completed(db_path, peer_id, current_timestamp_ms());
            }
            if use_snapshot {
                let _ = neg_db.execute("COMMIT", []);
            }
            next_round_due = Instant::now() + discovery_round_gap();
            continue;
        }

        match tokio::time::timeout(CONTROL_POLL_TIMEOUT, control.recv()).await {
            Ok(Ok(Frame::RequestIds { ids })) => {
                last_activity = Instant::now();
                if !ids.is_empty() {
                    let _ = timeline.mark_request_received_many(&ids, current_timestamp_ms());
                    super::data_plane::queue_requested_responses(
                        response_state,
                        &timeline,
                        &store,
                        &ids,
                    );
                }
            }
            Ok(Ok(Frame::DiscoveryHints { hints })) => {
                last_activity = Instant::now();
                let hint_ids: Vec<_> = hints.iter().map(|h| h.event_id).collect();
                let _ =
                    timeline.mark_need_list_received_many(&hint_ids, current_timestamp_ms());
                let observed = observe_discovery_hints_for_peer(
                    &wanted,
                    &timeline,
                    recorded_by,
                    peer_id,
                    current_timestamp_ms(),
                    &hints,
                    &mut Vec::new(),
                )?;
                if observed > 0 {
                    info!(
                        "Observed {} discovery hints from peer {} between rounds",
                        observed, peer_id
                    );
                }
            }
            Ok(Ok(Frame::ResponseCredit { bytes })) => {
                last_activity = Instant::now();
                request_state.add_credit_bytes(bytes as usize, current_timestamp_ms());
            }
            Ok(Ok(_)) => {}
            Ok(Err(ConnectionError::Closed)) => {
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
            Ok(Err(e)) => {
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
            Err(_) => {}
        }

        let auto_requests = policy_rx
            .as_ref()
            .map(|rx| rx.borrow().requests == crate::shared::sync_control::SyncPolicyMode::Auto)
            .unwrap_or(true);
        if auto_requests {
            let (requested_now, _) = refill_wanted_requests(
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
        }

        if forward_on_have_enabled() {
            let hinted = send_forward_on_have_hints(
                &mut control,
                &timeline,
                &store,
                peer_id,
                &mut forward_hint_rx,
            )
            .await?;
            if hinted > 0 {
                last_activity = Instant::now();
            }
        }

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

        let grant = response_state.desired_credit_grant_bytes(credit_high, credit_low);
        if grant > 0 {
            send_response_credit_bytes(&mut control, grant).await?;
            response_state.note_granted_bytes(grant);
        }

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
                request_stats.remote_credit_bytes,
                response_stats.pending_len,
                response_stats.available_credit_bytes,
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
                } else if pending_wanted_backlog > 0 {
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
                        "reconciliation_done": false,
                        "need_ids": 0,
                        "wanted_peer_backlog": pending_wanted_backlog,
                        "request_inflight": request_stats.inflight_len,
                        "response_credit_bytes": request_stats.remote_credit_bytes,
                        "pending_responses": response_stats.pending_len,
                        "response_credit_available_bytes": response_stats.available_credit_bytes,
                        "wanted_pending": wanted.count().unwrap_or(-1),
                    }))
                    .ok(),
                );
            }
            last_idle_marker = Instant::now();
        }
    }
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
