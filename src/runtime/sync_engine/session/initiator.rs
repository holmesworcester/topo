//! Sync initiator: run one range session on an established connection.

use std::time::{Duration, Instant};

use crate::db::{
    open_connection,
    store::{lookup_workspace_id, Store},
};
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::runtime::peering::loops::live_session_peer_ids;
use crate::runtime::SyncStats;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::range_session::{
    load_claim_index_slice, load_shared_object_index_slice, send_have_events,
    spawn_receive_log_task,
};
use crate::sync::session::receive_log::{
    enqueue_receive_log_ingest, note_hot_receive_finished, note_hot_receive_started,
};
use crate::sync::session::windowing::{
    claim_shard_starts_for_window, decode_sync_window_kind, encode_initial_neg_open,
    encode_sync_window_kind, is_hot_window, is_low_mem_allowed_window,
    mark_outbound_window_completed, restrict_outbound_windows_to_last_week, select_outbound_window,
    SyncNegPhase, SyncWindowKind,
};
use crate::sync::session::{INITIAL_CONTROL_PROGRESS_TIMEOUT, NEGENTROPY_FRAME_SIZE_LIMIT};
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};
use crate::tuning::sync_dep_claim_soft_ttl_ms;
use negentropy::{Id, Negentropy};

type ManualRoundReply =
    std::sync::mpsc::Sender<Result<crate::runtime::sync_control::ManualSyncRoundCapture, String>>;
type ManualRequestReply =
    std::sync::mpsc::Sender<Result<crate::runtime::sync_control::ManualSyncRequestResult, String>>;

fn manual_request_not_supported(peer_id: &str, reply: ManualRequestReply) {
    let _ = reply.send(Ok(crate::runtime::sync_control::ManualSyncRequestResult {
        peer_id: peer_id.to_string(),
        requested_ids: Vec::new(),
        reason: None,
    }));
}

fn drain_manual_commands(
    peer_id: &str,
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
            crate::runtime::sync_control::SessionCommand::ForceRequest { reply } => {
                manual_request_not_supported(peer_id, reply);
            }
        }
    }
}

fn reply_manual_rounds(
    peer_id: &str,
    need_ids: &[Id],
    pending_round_replies: &mut Vec<ManualRoundReply>,
) {
    if pending_round_replies.is_empty() {
        return;
    }
    let observed_ids: Vec<String> = need_ids
        .iter()
        .map(|id| hex::encode(neg_id_to_event_id(id)))
        .collect();
    for reply in pending_round_replies.drain(..) {
        let _ = reply.send(Ok(crate::runtime::sync_control::ManualSyncRoundCapture {
            peer_id: peer_id.to_string(),
            observed_ids: observed_ids.clone(),
        }));
    }
}

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
        mut data_send,
        data_recv,
    } = conn;
    let start = Instant::now();
    let activity_timeout = Duration::from_secs(timeout_secs);

    let mut pending_round_replies = Vec::new();
    drain_manual_commands(peer_id, &mut command_rx, &mut pending_round_replies);

    let db = open_connection(db_path)?;
    let ws_id = lookup_workspace_id(&db, recorded_by).ok_or_else(|| {
        format!(
            "no accepted workspace binding for peer_id={}, cannot start sync",
            recorded_by
        )
    })?;
    let session_now_ms = crate::db::queue::current_timestamp_ms();
    let live_peer_ids = live_session_peer_ids(db_path, recorded_by);
    let range = select_outbound_window(
        db_path,
        recorded_by,
        peer_id,
        &live_peer_ids,
        session_now_ms,
    );
    let claim_shards = claim_shard_starts_for_window(range, session_now_ms);
    let soft_claim_expiry_ms = session_now_ms.saturating_add(sync_dep_claim_soft_ttl_ms());
    for shard_start_ms in &claim_shards {
        let storage = load_claim_index_slice(&db, &ws_id, *shard_start_ms, session_now_ms)?;
        let mut neg = Negentropy::borrowed(&storage, NEGENTROPY_FRAME_SIZE_LIMIT)?;
        let initial_msg = encode_initial_neg_open(
            SyncNegPhase::ClaimsDayShard {
                shard_start_ms: *shard_start_ms,
            },
            neg.initiate()?,
        );
        control.send(&Frame::NegOpen { msg: initial_msg }).await?;
        control.flush().await?;

        let mut learned_ids = Vec::<Id>::new();
        loop {
            let response =
                tokio::time::timeout(INITIAL_CONTROL_PROGRESS_TIMEOUT, control.recv()).await??;
            let Frame::NegMsg { msg } = response else {
                return Err("initiator expected claim NegMsg response".into());
            };
            let mut have_ids = Vec::<Id>::new();
            match neg.reconcile_with_ids(&msg, &mut have_ids, &mut learned_ids)? {
                Some(next_msg) => {
                    control.send(&Frame::NegMsg { msg: next_msg }).await?;
                    control.flush().await?;
                }
                None => {
                    control.send(&Frame::NegMsg { msg: Vec::new() }).await?;
                    control.flush().await?;
                    break;
                }
            }
        }
        learned_ids.sort_unstable();
        learned_ids.dedup();
        let learned_event_ids = learned_ids
            .iter()
            .map(neg_id_to_event_id)
            .collect::<Vec<_>>();
        crate::db::dep_claims::upsert_soft_claims(
            &db,
            &ws_id,
            *shard_start_ms,
            &learned_event_ids,
            Some(peer_id),
            session_now_ms,
            soft_claim_expiry_ms,
        )?;
    }

    let storage =
        load_shared_object_index_slice(&db, &ws_id, range, &claim_shards, session_now_ms)?;
    let mut neg = Negentropy::borrowed(&storage, NEGENTROPY_FRAME_SIZE_LIMIT)?;
    let initial_msg = encode_initial_neg_open(
        SyncNegPhase::ObjectsRange { window: range },
        neg.initiate()?,
    );

    control.send(&Frame::NegOpen { msg: initial_msg }).await?;
    control.flush().await?;

    let mut have_ids = Vec::<Id>::new();
    let mut need_ids = Vec::<Id>::new();
    loop {
        let response =
            tokio::time::timeout(INITIAL_CONTROL_PROGRESS_TIMEOUT, control.recv()).await??;
        let msg = match response {
            Frame::NegMsg { msg } => msg,
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

        match neg.reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)? {
            Some(next_msg) => {
                control.send(&Frame::NegMsg { msg: next_msg }).await?;
                control.flush().await?;
            }
            None => {
                control.send(&Frame::NegMsg { msg: Vec::new() }).await?;
                control.flush().await?;
                break;
            }
        }
    }
    have_ids.sort_unstable();
    have_ids.dedup();
    need_ids.sort_unstable();
    need_ids.dedup();
    drain_manual_commands(peer_id, &mut command_rx, &mut pending_round_replies);
    reply_manual_rounds(peer_id, &need_ids, &mut pending_round_replies);

    let hot_receive = is_hot_window(range.kind);
    if hot_receive {
        note_hot_receive_started(db_path);
    }
    let receive_source_tag = crate::db::queue::source_tag_with_sync_window(
        ingress_source_tag,
        encode_sync_window_kind(range.kind),
    );
    let receive_task = spawn_receive_log_task(
        data_recv,
        db_path.to_string(),
        recorded_by.to_string(),
        session_id,
        receive_source_tag,
        activity_timeout,
        rx_capture,
    );

    let store = Store::new(&db);
    let (events_sent, bytes_sent) = send_have_events(&store, &mut data_send, &have_ids).await?;
    drop(data_send);

    let received = match receive_task.await {
        Ok(result) => {
            if hot_receive {
                note_hot_receive_finished(db_path);
            }
            result.map_err(|e| format!("receive log task: {e}"))?
        }
        Err(e) => {
            if hot_receive {
                note_hot_receive_finished(db_path);
            }
            return Err(format!("receive log task join: {e}").into());
        }
    };
    if let Some(path) = received.path.clone() {
        enqueue_receive_log_ingest(db_path, path, hot_receive);
    }
    drain_manual_commands(peer_id, &mut command_rx, &mut pending_round_replies);
    reply_manual_rounds(peer_id, &need_ids, &mut pending_round_replies);

    let _ = mark_outbound_window_completed(db_path, recorded_by, peer_id, range);

    Ok(SyncStats {
        events_sent,
        events_received: received.events_received,
        neg_rounds: 1 + claim_shards.len() as u64,
        bytes_sent,
        bytes_received: received.bytes_received,
        duration_ms: start.elapsed().as_millis(),
    })
}
