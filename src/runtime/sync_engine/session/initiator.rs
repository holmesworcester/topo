//! Sync initiator: run one range session on an established connection.

use std::time::{Duration, Instant};

use tracing::debug;

use crate::db::{open_connection, store::Store};
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::runtime::peering::loops::live_session_peer_ids;
use crate::runtime::sync_engine::session::admission::resolve_sync_admission;
use crate::runtime::sync_engine::session::data_plane::{
    drain_manual_commands, reply_manual_rounds, run_range_data_plane, sort_dedup_event_ids,
    sort_dedup_ids,
};
use crate::runtime::sync_engine::session::depsync::{
    build_candidate_storage, build_range_dep_storage, chunk_event_ids, decode_dep_sync_control,
    encode_dep_sync_control, DepSyncControlPayload, DEP_CANDIDATE_CHUNK_SIZE,
};
use crate::runtime::SyncStats;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::range_session::order_phase2_then_phase1_shared_event_ids_for_send_for_peer;
use crate::sync::session::receive::acquire_peer_session_ingest_guard;
use crate::sync::session::windowing::{
    decode_sync_window_kind, encode_initial_neg_open, is_low_mem_allowed_window,
    mark_outbound_window_completed, restrict_outbound_windows_to_last_week, select_outbound_window,
    SyncWindowKind,
};
use crate::sync::session::{INITIAL_CONTROL_PROGRESS_TIMEOUT, NEGENTROPY_FRAME_SIZE_LIMIT};
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};
use negentropy::{DepReconcileDiff, DepReconciler, Id, Negentropy};

/// Run sync as the initiator for one coordinator-selected range.
#[allow(clippy::too_many_arguments)]
pub async fn run_sync_initiator<C, S, R>(
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
        data_send,
        data_recv,
    } = conn;
    let start = Instant::now();
    let activity_timeout = Duration::from_secs(timeout_secs);

    let mut pending_round_replies = Vec::new();
    drain_manual_commands(&mut command_rx, &mut pending_round_replies);

    let db = open_connection(db_path)?;
    let ws_id = resolve_sync_admission(&db, recorded_by)?;
    let _peer_session_ingest_guard = acquire_peer_session_ingest_guard(db_path, peer_id).await?;
    let live_peer_ids = live_session_peer_ids(db_path, recorded_by);
    let range = select_outbound_window(
        db_path,
        recorded_by,
        peer_id,
        &live_peer_ids,
        crate::db::queue::current_timestamp_ms(),
    );
    let phase1_storage = build_range_dep_storage(&db, db_path, &ws_id, range)?;
    let mut phase1 = DepReconciler::borrowed(phase1_storage.as_ref());
    let initial_msg = encode_initial_neg_open(
        range,
        encode_dep_sync_control(&DepSyncControlPayload::Phase1(phase1.initiate()?)),
    );

    control.send(&Frame::NegOpen { msg: initial_msg }).await?;
    control.flush().await?;

    let mut phase1_diff = DepReconcileDiff::default();
    loop {
        let response =
            tokio::time::timeout(INITIAL_CONTROL_PROGRESS_TIMEOUT, control.recv()).await??;
        let control_payload = match response {
            Frame::NegMsg { msg } => decode_dep_sync_control(&msg)
                .map_err(|e| format!("initiator failed to decode phase1 control payload: {e}"))?,
            Frame::RangePolicyReject {
                rejected_window_kind,
                oldest_allowed_window_kind,
            } => {
                let rejected_kind = decode_sync_window_kind(rejected_window_kind)
                    .map_err(|e| format!("initiator received invalid rejected window kind: {e}"))?;
                let oldest_allowed_kind = decode_sync_window_kind(oldest_allowed_window_kind)
                    .map_err(|e| {
                        format!("initiator received invalid oldest allowed window kind: {e}")
                    })?;
                if rejected_kind == range.kind
                    && oldest_allowed_kind == SyncWindowKind::LastWeek
                    && !is_low_mem_allowed_window(range.kind)
                {
                    restrict_outbound_windows_to_last_week(db_path, recorded_by, peer_id);
                    return Ok(SyncStats {
                        events_sent: 0,
                        events_received: 0,
                        neg_rounds: 0,
                        bytes_sent: 0,
                        bytes_received: 0,
                        duration_ms: start.elapsed().as_millis(),
                    });
                }
                return Err(format!(
                    "initiator received unsupported range policy reject: rejected={rejected_kind:?} oldest_allowed={oldest_allowed_kind:?} current={:?}",
                    range.kind
                )
                .into());
            }
            _ => return Err("initiator expected NegMsg response".into()),
        };

        let DepSyncControlPayload::Phase1(msg) = control_payload else {
            return Err("initiator expected phase1 reconciliation payload".into());
        };

        match phase1.reconcile_with_ids(&msg, &mut phase1_diff)? {
            Some(next_msg) => {
                control
                    .send(&Frame::NegMsg {
                        msg: encode_dep_sync_control(&DepSyncControlPayload::Phase1(next_msg)),
                    })
                    .await?;
                control.flush().await?;
            }
            None => {
                control
                    .send(&Frame::NegMsg {
                        msg: encode_dep_sync_control(&DepSyncControlPayload::Phase1Done),
                    })
                    .await?;
                control.flush().await?;
                break;
            }
        }
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
        "initiator phase1 dep reconciliation complete"
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

    let mut local_dep_candidates =
        phase1_storage.dep_candidate_ids_for_roots(&phase1_candidate_root_ids);
    sort_dedup_event_ids(&mut local_dep_candidates);
    for chunk in chunk_event_ids(&local_dep_candidates, DEP_CANDIDATE_CHUNK_SIZE) {
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

    let mut candidate_universe = local_dep_candidates.clone();
    loop {
        let response =
            tokio::time::timeout(INITIAL_CONTROL_PROGRESS_TIMEOUT, control.recv()).await??;
        let Frame::NegMsg { msg } = response else {
            return Err("initiator expected dep candidate payload".into());
        };
        match decode_dep_sync_control(&msg)
            .map_err(|e| format!("initiator failed to decode dep candidate payload: {e}"))?
        {
            DepSyncControlPayload::DepCandidateChunk(ids) => candidate_universe.extend(ids),
            DepSyncControlPayload::DepCandidateDone => break,
            other => {
                return Err(
                    format!("initiator expected dep candidate payload, got {:?}", other).into(),
                )
            }
        }
    }
    sort_dedup_event_ids(&mut candidate_universe);

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
        control
            .send(&Frame::NegMsg {
                msg: encode_dep_sync_control(&DepSyncControlPayload::Phase2(phase2.initiate()?)),
            })
            .await?;
        control.flush().await?;

        loop {
            let response =
                tokio::time::timeout(INITIAL_CONTROL_PROGRESS_TIMEOUT, control.recv()).await??;
            let Frame::NegMsg { msg } = response else {
                return Err("initiator expected phase2 NegMsg payload".into());
            };
            let payload = decode_dep_sync_control(&msg)
                .map_err(|e| format!("initiator failed to decode phase2 payload: {e}"))?;
            let DepSyncControlPayload::Phase2(msg) = payload else {
                return Err("initiator expected phase2 reconciliation payload".into());
            };
            match phase2.reconcile_with_ids(&msg, &mut phase2_have_ids, &mut phase2_need_ids)? {
                Some(next_msg) => {
                    control
                        .send(&Frame::NegMsg {
                            msg: encode_dep_sync_control(&DepSyncControlPayload::Phase2(next_msg)),
                        })
                        .await?;
                    control.flush().await?;
                }
                None => {
                    control
                        .send(&Frame::NegMsg {
                            msg: encode_dep_sync_control(&DepSyncControlPayload::Phase2Done),
                        })
                        .await?;
                    control.flush().await?;
                    break;
                }
            }
        }
        sort_dedup_ids(&mut phase2_have_ids);
        sort_dedup_ids(&mut phase2_need_ids);
    } else {
        control
            .send(&Frame::NegMsg {
                msg: encode_dep_sync_control(&DepSyncControlPayload::Phase2Done),
            })
            .await?;
        control.flush().await?;
    }
    debug!(
        target: "topo::sync_operation",
        session_id,
        peer = %&peer_id[..peer_id.len().min(16)],
        range = ?range.kind,
        candidate_dep_count = candidate_universe.len(),
        confirmed_dep_have_count = phase2_have_ids.len(),
        confirmed_dep_need_count = phase2_need_ids.len(),
        "initiator phase2 dependency negentropy complete"
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
            "initiator dep-send trace"
        );
    }

    let data_plane = run_range_data_plane(
        &store,
        data_send,
        data_recv,
        db_path,
        recorded_by,
        &ws_id,
        peer_id,
        range,
        session_id,
        ingress_source_tag,
        activity_timeout,
        rx_capture,
        live_peer_ids.len(),
        &ordered_send_event_ids,
        "initiator sync session complete",
    )
    .await?;
    drain_manual_commands(&mut command_rx, &mut pending_round_replies);

    let _ = mark_outbound_window_completed(db_path, recorded_by, peer_id, range);

    Ok(SyncStats {
        events_sent: data_plane.events_sent,
        events_received: data_plane.events_received,
        neg_rounds: 1 + u64::from(phase2_used),
        bytes_sent: data_plane.bytes_sent,
        bytes_received: data_plane.bytes_received,
        duration_ms: start.elapsed().as_millis(),
    })
}
