//! Sync responder: answer one range session on an established connection.

use std::time::{Duration, Instant};

use tracing::debug;

use crate::db::{open_connection, store::Store};
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::runtime::peering::loops::live_session_peer_ids;
use crate::runtime::sync_engine::session::admission::resolve_sync_admission;
use crate::runtime::SyncStats;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::range_session::{
    load_shared_event_index_slice, open_live_suppression_session, send_have_events,
    spawn_receive_log_task,
};
use crate::sync::session::receive_log::{
    enqueue_receive_log_ingest, enqueue_receive_log_ingest_with_pending_overlay,
    note_hot_receive_finished, note_hot_receive_started,
};
use crate::sync::session::windowing::{
    decode_initial_neg_open, encode_sync_window_kind, is_low_mem_allowed_window,
    is_priority_ingest_window, SyncWindowKind,
};
use crate::sync::session::{INITIAL_CONTROL_PROGRESS_TIMEOUT, NEGENTROPY_FRAME_SIZE_LIMIT};
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};
use crate::tuning::low_mem_mode;
use negentropy::{Id, Negentropy};

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
    let storage = load_shared_event_index_slice(&db, db_path, &ws_id, range)?;
    let mut neg = Negentropy::borrowed(&storage, NEGENTROPY_FRAME_SIZE_LIMIT)?;

    let mut have_ids = Vec::<Id>::new();
    let mut need_ids = Vec::<Id>::new();
    let mut next_query = Some(neg_msg.to_vec());
    loop {
        let query = if let Some(query) = next_query.take() {
            query
        } else {
            let next =
                tokio::time::timeout(INITIAL_CONTROL_PROGRESS_TIMEOUT, control.recv()).await??;
            let Frame::NegMsg { msg } = next else {
                return Err("responder expected follow-up NegMsg".into());
            };
            msg
        };
        if query.is_empty() {
            break;
        }
        let response = neg.reconcile_with_diff(&query, &mut have_ids, &mut need_ids)?;
        control.send(&Frame::NegMsg { msg: response }).await?;
        control.flush().await?;
    }
    have_ids.sort_unstable();
    have_ids.dedup();
    need_ids.sort_unstable();
    need_ids.dedup();
    debug!(
        target: "topo::sync_operation",
        session_id,
        peer = %&peer_id[..peer_id.len().min(16)],
        range = ?range.kind,
        have_count = have_ids.len(),
        need_count = need_ids.len(),
        "responder negentropy reconcile complete"
    );
    drain_manual_commands(&mut command_rx, &mut pending_round_replies);
    reply_manual_rounds(peer_id, &need_ids, &mut pending_round_replies);

    let hot_receive = is_priority_ingest_window(range.kind);
    if hot_receive {
        note_hot_receive_started(db_path);
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
    let receive_task = spawn_receive_log_task(
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
    let store = Store::new(&db);
    let (events_sent, bytes_sent) = send_have_events(
        &db,
        &store,
        &mut data_send,
        &have_ids,
        recorded_by,
        &ws_id,
        range,
        live_suppression.as_mut(),
    )
    .await?;
    drop(data_send);

    let received = match receive_task.await {
        Ok(result) => result.map_err(|e| format!("receive log task: {e}"))?,
        Err(e) => {
            if hot_receive {
                note_hot_receive_finished(db_path);
            }
            return Err(format!("receive log task join: {e}").into());
        }
    };
    if let Some(path) = received.path.clone() {
        if let Some(pending_overlay) = received.pending_overlay.clone() {
            enqueue_receive_log_ingest_with_pending_overlay(
                db_path,
                path,
                hot_receive,
                pending_overlay,
            );
        } else {
            enqueue_receive_log_ingest(db_path, path, hot_receive);
        }
    }
    if hot_receive {
        note_hot_receive_finished(db_path);
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
    reply_manual_rounds(peer_id, &need_ids, &mut pending_round_replies);

    Ok(SyncStats {
        events_sent,
        events_received: received.events_received,
        neg_rounds: 1,
        bytes_sent,
        bytes_received: received.bytes_received,
        duration_ms: start.elapsed().as_millis(),
    })
}
