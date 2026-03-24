//! Sync responder: answer one range session on an established connection.

use std::time::{Duration, Instant};

use negentropy::{Id, Negentropy};
use crate::db::{
    open_connection,
    store::{lookup_workspace_id, Store},
};
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::runtime::SyncStats;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::range_session::{
    load_range_storage, send_have_events, spawn_receive_log_task,
};
use crate::sync::session::receive_log::{
    enqueue_receive_log_ingest, note_hot_receive_finished, note_hot_receive_started,
};
use crate::sync::session::windowing::{decode_initial_neg_open, is_hot_window};
use crate::sync::session::INITIAL_CONTROL_PROGRESS_TIMEOUT;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};

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
    drain_manual_commands(peer_id, &mut command_rx, &mut pending_round_replies);

    let initial = tokio::time::timeout(INITIAL_CONTROL_PROGRESS_TIMEOUT, control.recv()).await??;
    let Frame::NegOpen { msg } = initial else {
        return Err("responder expected NegOpen".into());
    };
    let (range, neg_msg) = decode_initial_neg_open(&msg)?;

    let db = open_connection(db_path)?;
    let ws_id = lookup_workspace_id(&db, recorded_by).ok_or_else(|| {
        format!(
            "no accepted workspace binding for peer_id={}, cannot start sync",
            recorded_by
        )
    })?;
    let storage = load_range_storage(&db, &ws_id, range)?;
    let mut neg = Negentropy::borrowed(&storage, crate::sync::session::negentropy_frame_size())?;

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
    drain_manual_commands(peer_id, &mut command_rx, &mut pending_round_replies);
    reply_manual_rounds(peer_id, &need_ids, &mut pending_round_replies);

    let hot_receive = is_hot_window(range.kind);
    if hot_receive {
        note_hot_receive_started(db_path);
    }
    let receive_task = spawn_receive_log_task(
        data_recv,
        db_path.to_string(),
        recorded_by.to_string(),
        session_id,
        ingress_source_tag.to_string(),
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
        enqueue_receive_log_ingest(db_path, path);
    }
    drain_manual_commands(peer_id, &mut command_rx, &mut pending_round_replies);
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
