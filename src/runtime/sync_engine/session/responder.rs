//! Sync responder: answer one range session on an established connection.

use std::time::{Duration, Instant};

use tracing::debug;

use crate::db::{open_connection, store::Store};
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::runtime::peering::loops::live_session_peer_ids;
use crate::runtime::sync_engine::session::admission::resolve_sync_admission;
use crate::runtime::sync_engine::session::depsync::{
    build_candidate_storage, build_range_dep_storage, decode_dep_sync_control,
    encode_dep_sync_control, DepSyncControlPayload,
};
use crate::runtime::SyncStats;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::range_session::{
    open_live_suppression_session, order_phase2_then_phase1_shared_event_ids_for_send_for_peer,
    send_selected_events, spawn_receive_task,
};
use crate::sync::session::receive::{acquire_peer_session_ingest_guard, wait_for_ingest_waiters};
use crate::sync::session::windowing::{
    decode_initial_neg_open, encode_sync_window_kind, is_low_mem_allowed_window, SyncWindowKind,
};
use crate::sync::session::{INITIAL_CONTROL_PROGRESS_TIMEOUT, NEGENTROPY_FRAME_SIZE_LIMIT};
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};
use crate::tuning::low_mem_mode;
use negentropy::{DepReconcileDiff, DepReconciler, Id, Negentropy};

type ManualRoundReply =
    std::sync::mpsc::Sender<Result<crate::runtime::sync_control::ManualSyncRoundCapture, String>>;

fn drain_manual_commands(
    command_rx: &mut Option<
        tokio::sync::mpsc::Receiver<crate::runtime::sync_control::SessionCommand>,
    >,
    pending_round_replies: &mut Vec<ManualRoundReply>,
) {
    let Some(rx) = command_rx.as_mut() else {
        return;
    };
    while let Ok(cmd) = rx.try_recv() {
        match cmd {
            crate::runtime::sync_control::SessionCommand::ForceRound { reply } => {
                pending_round_replies.push(reply);
            }
        }
    }
}

fn reply_manual_rounds(
    peer_id: &str,
    need_ids: &[crate::crypto::EventId],
    pending_round_replies: &mut Vec<ManualRoundReply>,
) {
    if pending_round_replies.is_empty() {
        return;
    }
    let observed_ids: Vec<String> = need_ids.iter().map(hex::encode).collect();
    for reply in pending_round_replies.drain(..) {
        let _ = reply.send(Ok(crate::runtime::sync_control::ManualSyncRoundCapture {
            peer_id: peer_id.to_string(),
            observed_ids: observed_ids.clone(),
        }));
    }
}

fn sort_dedup_ids(ids: &mut Vec<Id>) {
    ids.sort_unstable();
    ids.dedup();
}

fn sort_dedup_event_ids(ids: &mut Vec<crate::crypto::EventId>) {
    ids.sort_unstable();
    ids.dedup();
}

/// Run sync as the responder for one requested range.
#[allow(clippy::too_many_arguments)]
pub async fn run_sync_responder<C, S, R>(
    conn: DualConnection<C, S, R>,
    session_id: u64,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
    recorded_by: &str,
    ingress_source_tag: &str,
    rx_capture: Option<SyncRunRxCapture>,
    mut command_rx: Option<
        tokio::sync::mpsc::Receiver<crate::runtime::sync_control::SessionCommand>,
    >,
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

    let mut pending_round_replies = Vec::new();
    drain_manual_commands(&mut command_rx, &mut pending_round_replies);

    let initial = tokio::time::timeout(INITIAL_CONTROL_PROGRESS_TIMEOUT, control.recv()).await??;
    let Frame::NegOpen { msg } = initial else {
        return Err("responder expected NegOpen".into());
    };
    let (range, neg_msg) = decode_initial_neg_open(&msg)?;
    if low_mem_mode() && !is_low_mem_allowed_window(range.kind) {
        control
            .send(&Frame::RangePolicyReject {
                rejected_window_kind: encode_sync_window_kind(range.kind),
                oldest_allowed_window_kind: encode_sync_window_kind(SyncWindowKind::LastWeek),
            })
            .await?;
        control.flush().await?;
        return Ok(SyncStats {
            events_sent: 0,
            events_received: 0,
            neg_rounds: 0,
            bytes_sent: 0,
            bytes_received: 0,
            duration_ms: start.elapsed().as_millis(),
        });
    }

    let db = open_connection(db_path)?;
    let ws_id = resolve_sync_admission(&db, recorded_by)?;
    let _peer_session_ingest_guard = acquire_peer_session_ingest_guard(db_path, peer_id).await?;
    let phase1_storage = build_range_dep_storage(&db, db_path, &ws_id, range)?;
    let mut phase1 = DepReconciler::borrowed(phase1_storage.as_ref());

    let initial_payload = decode_dep_sync_control(neg_msg)
        .map_err(|e| format!("responder failed to decode initial phase1 payload: {e}"))?;
    let DepSyncControlPayload::Phase1(initial_phase1_query) = initial_payload else {
        return Err("responder expected initial phase1 query payload".into());
    };

    let mut phase1_diff = DepReconcileDiff::default();
    let mut next_query = Some(initial_phase1_query);
    loop {
        let query = if let Some(query) = next_query.take() {
            query
        } else {
            let next =
                tokio::time::timeout(INITIAL_CONTROL_PROGRESS_TIMEOUT, control.recv()).await??;
            let Frame::NegMsg { msg } = next else {
                return Err("responder expected follow-up NegMsg".into());
            };
            let payload = decode_dep_sync_control(&msg)
                .map_err(|e| format!("responder failed to decode phase1 payload: {e}"))?;
            match payload {
                DepSyncControlPayload::Phase1(msg) => msg,
                DepSyncControlPayload::Phase1Done => break,
                other => {
                    return Err(
                        format!("responder expected phase1 payload, got {:?}", other).into(),
                    )
                }
            }
        };
        let response = phase1.reconcile_with_diff(&query, &mut phase1_diff)?;
        control
            .send(&Frame::NegMsg {
                msg: encode_dep_sync_control(&DepSyncControlPayload::Phase1(response)),
            })
            .await?;
        control.flush().await?;
    }
    sort_dedup_ids(&mut phase1_diff.have_root_ids);
    sort_dedup_ids(&mut phase1_diff.need_root_ids);
    sort_dedup_ids(&mut phase1_diff.dep_probe_root_ids);
    debug!(
        target: "topo::sync_operation",
        session_id,
        peer = %&peer_id[..peer_id.len().min(16)],
        range = ?range.kind,
        have_root_count = phase1_diff.have_root_ids.len(),
        need_root_count = phase1_diff.need_root_ids.len(),
        dep_probe_root_count = phase1_diff.dep_probe_root_ids.len(),
        "responder phase1 dep reconciliation complete"
    );
    drain_manual_commands(&mut command_rx, &mut pending_round_replies);

    let mut phase1_candidate_root_ids = phase1_diff
        .have_root_ids
        .iter()
        .map(neg_id_to_event_id)
        .collect::<Vec<_>>();
    phase1_candidate_root_ids.extend(
        phase1_diff
            .dep_probe_root_ids
            .iter()
            .map(neg_id_to_event_id),
    );
    sort_dedup_event_ids(&mut phase1_candidate_root_ids);

    let local_dep_candidates =
        phase1_storage.dep_candidate_ids_for_roots(&phase1_candidate_root_ids);
    let mut candidate_universe = local_dep_candidates.clone();
    loop {
        let next = tokio::time::timeout(INITIAL_CONTROL_PROGRESS_TIMEOUT, control.recv()).await??;
        let Frame::NegMsg { msg } = next else {
            return Err("responder expected dep candidate payload".into());
        };
        match decode_dep_sync_control(&msg)
            .map_err(|e| format!("responder failed to decode dep candidate payload: {e}"))?
        {
            DepSyncControlPayload::DepCandidateChunk(ids) => candidate_universe.extend(ids),
            DepSyncControlPayload::DepCandidateDone => break,
            other => {
                return Err(
                    format!("responder expected dep candidate payload, got {:?}", other).into(),
                )
            }
        }
    }
    sort_dedup_event_ids(&mut candidate_universe);

    for chunk in crate::runtime::sync_engine::session::depsync::chunk_event_ids(
        &local_dep_candidates,
        crate::runtime::sync_engine::session::depsync::DEP_CANDIDATE_CHUNK_SIZE,
    ) {
        control
            .send(&Frame::NegMsg {
                msg: encode_dep_sync_control(&DepSyncControlPayload::DepCandidateChunk(chunk)),
            })
            .await?;
    }
    control
        .send(&Frame::NegMsg {
            msg: encode_dep_sync_control(&DepSyncControlPayload::DepCandidateDone),
        })
        .await?;
    control.flush().await?;

    let store = Store::new(&db);
    let mut phase2_have_ids = Vec::<Id>::new();
    let mut phase2_need_ids = Vec::<Id>::new();
    let phase2_used = !candidate_universe.is_empty();
    let mut phase2_storage_items = Vec::<String>::new();
    if phase2_used {
        let phase2_storage = build_candidate_storage(&store, &candidate_universe)?;
        if crate::runtime::sync_engine::session::range_session::trace_dep_send_ids_enabled() {
            phase2_storage_items =
                crate::runtime::sync_engine::session::range_session::trace_negentropy_storage_items(
                    &phase2_storage,
                )?;
        }
        let mut phase2 = Negentropy::borrowed(&phase2_storage, NEGENTROPY_FRAME_SIZE_LIMIT)?;
        let mut next_query = None::<Vec<u8>>;
        loop {
            let query = if let Some(query) = next_query.take() {
                query
            } else {
                let next = tokio::time::timeout(INITIAL_CONTROL_PROGRESS_TIMEOUT, control.recv())
                    .await??;
                let Frame::NegMsg { msg } = next else {
                    return Err("responder expected phase2 NegMsg".into());
                };
                let payload = decode_dep_sync_control(&msg)
                    .map_err(|e| format!("responder failed to decode phase2 payload: {e}"))?;
                match payload {
                    DepSyncControlPayload::Phase2(msg) => msg,
                    DepSyncControlPayload::Phase2Done => break,
                    other => {
                        return Err(
                            format!("responder expected phase2 payload, got {:?}", other).into(),
                        )
                    }
                }
            };
            let response =
                phase2.reconcile_with_diff(&query, &mut phase2_have_ids, &mut phase2_need_ids)?;
            control
                .send(&Frame::NegMsg {
                    msg: encode_dep_sync_control(&DepSyncControlPayload::Phase2(response)),
                })
                .await?;
            control.flush().await?;
        }
        sort_dedup_ids(&mut phase2_have_ids);
        sort_dedup_ids(&mut phase2_need_ids);
    } else {
        let next = tokio::time::timeout(INITIAL_CONTROL_PROGRESS_TIMEOUT, control.recv()).await??;
        let Frame::NegMsg { msg } = next else {
            return Err("responder expected phase2 terminator".into());
        };
        let payload = decode_dep_sync_control(&msg)
            .map_err(|e| format!("responder failed to decode phase2 terminator: {e}"))?;
        if !matches!(payload, DepSyncControlPayload::Phase2Done) {
            return Err("responder expected phase2 done payload".into());
        }
    }
    debug!(
        target: "topo::sync_operation",
        session_id,
        peer = %&peer_id[..peer_id.len().min(16)],
        range = ?range.kind,
        candidate_dep_count = candidate_universe.len(),
        confirmed_dep_have_count = phase2_have_ids.len(),
        confirmed_dep_need_count = phase2_need_ids.len(),
        "responder phase2 dependency negentropy complete"
    );

    let mut observed_need_ids = phase1_diff
        .need_root_ids
        .iter()
        .map(neg_id_to_event_id)
        .collect::<Vec<_>>();
    observed_need_ids.extend(phase2_need_ids.iter().map(neg_id_to_event_id));
    sort_dedup_event_ids(&mut observed_need_ids);
    drain_manual_commands(&mut command_rx, &mut pending_round_replies);
    reply_manual_rounds(peer_id, &observed_need_ids, &mut pending_round_replies);

    let mut phase1_send_event_ids = phase1_diff
        .have_root_ids
        .iter()
        .map(neg_id_to_event_id)
        .collect::<Vec<_>>();
    sort_dedup_event_ids(&mut phase1_send_event_ids);
    let mut phase2_send_event_ids = phase2_have_ids
        .iter()
        .map(neg_id_to_event_id)
        .collect::<Vec<_>>();
    sort_dedup_event_ids(&mut phase2_send_event_ids);
    let mut phase2_need_event_ids = phase2_need_ids
        .iter()
        .map(neg_id_to_event_id)
        .collect::<Vec<_>>();
    sort_dedup_event_ids(&mut phase2_need_event_ids);
    let ordered_send_event_ids = order_phase2_then_phase1_shared_event_ids_for_send_for_peer(
        &db,
        recorded_by,
        &ws_id,
        range,
        &phase2_send_event_ids,
        &phase1_send_event_ids,
    )?;
    if crate::runtime::sync_engine::session::range_session::trace_dep_send_ids_enabled() {
        debug!(
            target: "topo::sync_operation",
            session_id,
            peer = %peer_id,
            range = ?range.kind,
            phase1_candidate_root_ids = ?crate::runtime::sync_engine::session::range_session::trace_event_id_list(&phase1_candidate_root_ids),
            local_dep_candidates = ?crate::runtime::sync_engine::session::range_session::trace_event_id_list(&local_dep_candidates),
            candidate_universe = ?crate::runtime::sync_engine::session::range_session::trace_event_id_list(&candidate_universe),
            phase2_storage_items = ?phase2_storage_items,
            phase2_have_ids = ?crate::runtime::sync_engine::session::range_session::trace_event_id_list(&phase2_send_event_ids),
            phase2_need_ids = ?crate::runtime::sync_engine::session::range_session::trace_event_id_list(&phase2_need_event_ids),
            phase2_send_ids = ?crate::runtime::sync_engine::session::range_session::trace_event_id_list(&phase2_send_event_ids),
            phase1_send_ids = ?crate::runtime::sync_engine::session::range_session::trace_event_id_list(&phase1_send_event_ids),
            ordered_send_ids = ?crate::runtime::sync_engine::session::range_session::trace_event_id_list(&ordered_send_event_ids),
            "responder dep-send trace"
        );
    }

    let live_peer_ids = live_session_peer_ids(db_path, recorded_by);
    let settle_between_batches = live_peer_ids.len() > 1;
    let (mut live_suppression, receive_live_suppression) = if let Some((session, receive_state)) =
        open_live_suppression_session(
            db_path,
            recorded_by,
            &ws_id,
            peer_id,
            settle_between_batches,
            range,
            session_id,
        ) {
        (Some(session), Some(receive_state))
    } else {
        (None, None)
    };
    let receive_task = spawn_receive_task(
        data_recv,
        db_path.to_string(),
        recorded_by.to_string(),
        ws_id.clone(),
        range,
        session_id,
        ingress_source_tag.to_string(),
        activity_timeout,
        rx_capture,
        receive_live_suppression,
    );
    let (events_sent, bytes_sent) = send_selected_events(
        &store,
        &mut data_send,
        &ordered_send_event_ids,
        range,
        live_suppression.as_mut(),
    )
    .await?;
    drop(data_send);

    let received = match receive_task.await {
        Ok(result) => result.map_err(|e| format!("receive task: {e}"))?,
        Err(e) => return Err(format!("receive task join: {e}").into()),
    };
    if let Err(e) = wait_for_ingest_waiters(received.ingest_waiters).await {
        return Err(format!("direct ingest wait: {e}").into());
    }
    debug!(
        target: "topo::sync_operation",
        session_id,
        peer = %&peer_id[..peer_id.len().min(16)],
        range = ?range.kind,
        events_sent,
        events_received = received.events_received,
        bytes_sent,
        bytes_received = received.bytes_received,
        "responder sync session complete"
    );
    drain_manual_commands(&mut command_rx, &mut pending_round_replies);

    Ok(SyncStats {
        events_sent,
        events_received: received.events_received,
        neg_rounds: 1 + u64::from(phase2_used),
        bytes_sent,
        bytes_received: received.bytes_received,
        duration_ms: start.elapsed().as_millis(),
    })
}
