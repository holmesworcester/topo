//! Sync initiator: run one range session on an established connection.

use std::time::{Duration, Instant};

use crate::db::{open_connection, store::Store};
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::runtime::peering::loops::live_session_peer_ids;
use crate::runtime::sync_engine::session::admission::resolve_sync_admission;
use crate::runtime::SyncStats;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::range_session::{
    load_shared_event_index_slice, send_have_events, spawn_receive_log_task,
};
use crate::sync::session::receive_log::{
    enqueue_receive_log_ingest, note_hot_receive_finished, note_hot_receive_started,
};
use crate::sync::session::windowing::{
    decode_sync_window_kind, encode_initial_neg_open_task, is_low_mem_allowed_window,
    is_priority_ingest_window, mark_outbound_task_completed,
    restrict_outbound_windows_to_last_week, select_outbound_task, SyncWindowKind,
};
use crate::sync::session::{INITIAL_CONTROL_PROGRESS_TIMEOUT, NEGENTROPY_FRAME_SIZE_LIMIT};
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};
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
    drain_manual_commands(&mut command_rx, &mut pending_round_replies);

    let db = open_connection(db_path)?;
    let ws_id = resolve_sync_admission(&db, recorded_by)?;
    let live_peer_ids = live_session_peer_ids(db_path, recorded_by);
    let task = select_outbound_task(
        db_path,
        recorded_by,
        peer_id,
        &live_peer_ids,
        crate::db::queue::current_timestamp_ms(),
    );
    let storage = load_shared_event_index_slice(&db, &ws_id, task)?;
    let mut neg = Negentropy::borrowed(&storage, NEGENTROPY_FRAME_SIZE_LIMIT)?;
    let initial_msg = encode_initial_neg_open_task(task, neg.initiate()?);

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
                if rejected_kind == task.window.kind
                    && oldest_allowed_kind == SyncWindowKind::LastWeek
                    && !is_low_mem_allowed_window(task.window.kind)
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
                    task.window.kind
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
                // Empty NegMsg is the explicit control-phase terminator for the
                // simplified range session protocol.
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
    drain_manual_commands(&mut command_rx, &mut pending_round_replies);
    reply_manual_rounds(peer_id, &need_ids, &mut pending_round_replies);

    let hot_receive = is_priority_ingest_window(task.window.kind);
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
    let (events_sent, bytes_sent) =
        send_have_events(&store, &mut data_send, &have_ids, task).await?;
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
    drain_manual_commands(&mut command_rx, &mut pending_round_replies);
    reply_manual_rounds(peer_id, &need_ids, &mut pending_round_replies);

    let _ = mark_outbound_task_completed(db_path, recorded_by, peer_id, task);

    Ok(SyncStats {
        events_sent,
        events_received: received.events_received,
        neg_rounds: 1,
        bytes_sent,
        bytes_received: received.bytes_received,
        duration_ms: start.elapsed().as_millis(),
    })
}
