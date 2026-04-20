use std::time::Duration;

use negentropy::Id;
use tokio::sync::OwnedSemaphorePermit;
use tracing::debug;

use crate::crypto::EventId;
use crate::db::store::Store;
use crate::state::pipeline::wait_for_ingest_waiters;
use crate::sync::session::live_suppression::open_live_suppression_session;
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::range_session::send_selected_events;
use crate::sync::session::receive_task::spawn_receive_task;
use crate::sync::session::windowing::SyncWindow;
use crate::transport::{StreamRecv, StreamSend};

pub(crate) type ManualRoundReply =
    std::sync::mpsc::Sender<Result<crate::runtime::sync_control::ManualSyncRoundCapture, String>>;

pub(crate) fn drain_manual_commands(
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

pub(crate) fn reply_manual_rounds(
    peer_id: &str,
    need_ids: &[EventId],
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

pub(crate) fn sort_dedup_ids(ids: &mut Vec<Id>) {
    ids.sort_unstable();
    ids.dedup();
}

pub(crate) fn sort_dedup_event_ids(ids: &mut Vec<EventId>) {
    ids.sort_unstable();
    ids.dedup();
}

pub(crate) struct DataPlaneStats {
    pub(crate) events_sent: u64,
    pub(crate) events_received: u64,
    pub(crate) bytes_sent: u64,
    pub(crate) bytes_received: u64,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_range_data_plane<S, R>(
    store: &Store<'_>,
    mut data_send: S,
    data_recv: R,
    peer_session_ingest_guard: Option<OwnedSemaphorePermit>,
    db_path: &str,
    recorded_by: &str,
    workspace_id: &str,
    peer_id: &str,
    range: SyncWindow,
    session_id: u64,
    ingress_source_tag: &str,
    activity_timeout: Duration,
    rx_capture: Option<SyncRunRxCapture>,
    live_peer_count: usize,
    ordered_event_ids: &[EventId],
    completion_label: &'static str,
) -> Result<DataPlaneStats, Box<dyn std::error::Error + Send + Sync>>
where
    S: StreamSend,
    R: StreamRecv + Send + 'static,
{
    let allow_send = peer_session_ingest_guard.is_some();
    let _peer_session_ingest_guard = peer_session_ingest_guard;
    let settle_between_batches = live_peer_count > 1;
    let (mut live_suppression, receive_live_suppression) = if let Some((session, receive_state)) =
        open_live_suppression_session(
            db_path,
            recorded_by,
            workspace_id,
            peer_id,
            settle_between_batches,
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
        session_id,
        ingress_source_tag.to_string(),
        activity_timeout,
        rx_capture,
        receive_live_suppression,
    );
    let (events_sent, bytes_sent) = if allow_send {
        send_selected_events(
            store,
            &mut data_send,
            ordered_event_ids,
            range,
            live_suppression.as_mut(),
        )
        .await?
    } else {
        (0, 0)
    };
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
        completion = completion_label,
        "sync session complete"
    );
    Ok(DataPlaneStats {
        events_sent,
        events_received: received.events_received,
        bytes_sent,
        bytes_received: received.bytes_received,
    })
}
