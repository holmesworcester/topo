use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::peering_contract::{
    ControlIo, DataRecvIo, DataSendIo, TransportSessionIo, TransportSessionIoError,
};
use crate::crypto::{hash_event, EventId};
use crate::db::queue::current_timestamp_ms;
use crate::db::{open_connection, store::Store};
use crate::protocol::{encode_frame, parse_frame, Frame};
use crate::runtime::sync_engine::runtime::DependencySessionStats;
use crate::runtime::transport::{
    open_outbound_dependency_session, resolve_outbound_session_auth_plan,
    send_outbound_session_auth,
};
use crate::state::{dependency_fetch, pipeline::ingest_now};
use crate::transport::{DaemonConnection, OutboundSessionAuthPlan};

const DEPENDENCY_BATCH_CAP: usize = 16;
const REQUEST_BATCH_CAP: usize = 64;
const RESPONSE_QUEUE_CAP: usize = 256;

type SharedDependencyStats = Arc<Mutex<DependencySessionStats>>;

fn with_stats_mut<F>(stats: &SharedDependencyStats, f: F)
where
    F: FnOnce(&mut DependencySessionStats),
{
    let mut guard = stats
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(&mut guard);
}

fn record_request_ids_tx(stats: &SharedDependencyStats, frame_len: usize, id_count: usize) {
    with_stats_mut(stats, |stats| {
        stats.control_frames_sent = stats.control_frames_sent.saturating_add(1);
        stats.control_bytes_sent = stats.control_bytes_sent.saturating_add(frame_len as u64);
        stats.request_ids_sent = stats.request_ids_sent.saturating_add(id_count as u64);
    });
}

fn record_request_ids_rx(stats: &SharedDependencyStats, frame_len: usize, id_count: usize) {
    with_stats_mut(stats, |stats| {
        stats.control_frames_received = stats.control_frames_received.saturating_add(1);
        stats.control_bytes_received = stats
            .control_bytes_received
            .saturating_add(frame_len as u64);
        stats.request_ids_received = stats.request_ids_received.saturating_add(id_count as u64);
    });
}

fn record_response_event_tx(stats: &SharedDependencyStats, frame_len: usize, payload_len: usize) {
    with_stats_mut(stats, |stats| {
        stats.data_frames_sent = stats.data_frames_sent.saturating_add(1);
        stats.data_bytes_sent = stats.data_bytes_sent.saturating_add(frame_len as u64);
        stats.response_events_sent = stats.response_events_sent.saturating_add(1);
        stats.response_payload_bytes_sent = stats
            .response_payload_bytes_sent
            .saturating_add(payload_len as u64);
    });
}

fn record_response_event_rx(stats: &SharedDependencyStats, frame_len: usize, payload_len: usize) {
    with_stats_mut(stats, |stats| {
        stats.data_frames_received = stats.data_frames_received.saturating_add(1);
        stats.data_bytes_received = stats.data_bytes_received.saturating_add(frame_len as u64);
        stats.response_events_received = stats.response_events_received.saturating_add(1);
        stats.response_payload_bytes_received = stats
            .response_payload_bytes_received
            .saturating_add(payload_len as u64);
    });
}

fn decode_exact_frame(frame: &[u8]) -> Result<Frame, String> {
    let (parsed, consumed) =
        parse_frame(frame).map_err(|e| format!("parse dependency frame: {e}"))?;
    if consumed != frame.len() {
        return Err(format!(
            "parse dependency frame: trailing bytes consumed={consumed} total={}",
            frame.len()
        ));
    }
    Ok(parsed)
}

fn io_error(label: &str, err: TransportSessionIoError) -> String {
    format!("{label}: {err}")
}

fn make_ingest_item(
    blob: Vec<u8>,
    recorded_by: &str,
    source_tag: &str,
) -> crate::contracts::event_pipeline_contract::IngestItem {
    let now_ms = current_timestamp_ms();
    (
        hash_event(&blob),
        blob,
        recorded_by.to_string(),
        source_tag.to_string(),
        now_ms,
        now_ms,
    )
}

async fn run_dependency_control_loop(
    mut control: Box<dyn ControlIo>,
    mut request_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<EventId>>,
    response_tx: mpsc::Sender<Vec<EventId>>,
    cancel: CancellationToken,
    stats: SharedDependencyStats,
) -> Result<(), String> {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            maybe_ids = request_rx.recv() => {
                let Some(mut ids) = maybe_ids else {
                    return Ok(());
                };
                while ids.len() < REQUEST_BATCH_CAP {
                    match request_rx.try_recv() {
                        Ok(extra) => ids.extend(extra),
                        Err(_) => break,
                    }
                }
                ids.sort_unstable();
                ids.dedup();
                for chunk in ids.chunks(REQUEST_BATCH_CAP) {
                    let frame = encode_frame(&Frame::RequestIds { ids: chunk.to_vec() });
                    record_request_ids_tx(&stats, frame.len(), chunk.len());
                    control
                        .send(&frame)
                        .await
                        .map_err(|e| io_error("dependency control send", e))?;
                }
                control
                    .flush()
                    .await
                    .map_err(|e| io_error("dependency control flush", e))?;
            }
            frame = control.recv() => {
                let frame = frame.map_err(|e| io_error("dependency control recv", e))?;
                match decode_exact_frame(&frame)? {
                    Frame::RequestIds { ids } => {
                        record_request_ids_rx(&stats, frame.len(), ids.len());
                        if response_tx.send(ids).await.is_err() {
                            return Ok(());
                        }
                    }
                    Frame::NegOpen { .. }
                    | Frame::NegMsg { .. }
                    | Frame::DiscoveryHints { .. }
                    | Frame::RangePolicyReject { .. }
                    | Frame::IntroOffer { .. }
                    | Frame::OpenSessionAuthPeerShared { .. }
                    | Frame::OpenSessionAuthInvite { .. }
                    | Frame::OpenSessionAuthAck { .. }
                    | Frame::Event { .. } => {}
                }
            }
        }
    }
}

async fn run_dependency_response_sender(
    mut data_send: Box<dyn DataSendIo>,
    db_path: String,
    mut response_rx: mpsc::Receiver<Vec<EventId>>,
    cancel: CancellationToken,
    stats: SharedDependencyStats,
) -> Result<(), String> {
    let db = open_connection(&db_path).map_err(|e| format!("open dependency send db: {e}"))?;
    let store = Store::new(&db);
    loop {
        let ids = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            maybe_ids = response_rx.recv() => maybe_ids,
        };
        let Some(mut ids) = ids else {
            return Ok(());
        };
        while ids.len() < REQUEST_BATCH_CAP {
            match response_rx.try_recv() {
                Ok(extra) => ids.extend(extra),
                Err(_) => break,
            }
        }
        ids.sort_unstable();
        ids.dedup();
        for chunk in ids.chunks(REQUEST_BATCH_CAP) {
            let blobs = store
                .get_shared_batch(chunk)
                .map_err(|e| format!("load dependency response batch: {e}"))?;
            for event_id in chunk {
                let Some(blob) = blobs.get(event_id) else {
                    continue;
                };
                let frame = encode_frame(&Frame::Event { blob: blob.clone() });
                record_response_event_tx(&stats, frame.len(), blob.len());
                data_send
                    .send(&frame)
                    .await
                    .map_err(|e| io_error("dependency data send", e))?;
            }
            data_send
                .flush()
                .await
                .map_err(|e| io_error("dependency data flush", e))?;
        }
    }
}

async fn run_dependency_receiver(
    mut data_recv: Box<dyn DataRecvIo>,
    db_path: String,
    recorded_by: String,
    source_tag: String,
    cancel: CancellationToken,
    stats: SharedDependencyStats,
) -> Result<(), String> {
    let mut recv_buffer = Vec::<u8>::with_capacity(64 * 1024);
    loop {
        let mut batch = Vec::with_capacity(DEPENDENCY_BATCH_CAP);
        while batch.len() < DEPENDENCY_BATCH_CAP {
            match parse_frame(&recv_buffer) {
                Ok((Frame::Event { blob }, consumed)) => {
                    recv_buffer.drain(..consumed);
                    record_response_event_rx(&stats, consumed, blob.len());
                    batch.push(make_ingest_item(blob, &recorded_by, &source_tag));
                }
                Ok((_other, consumed)) => {
                    recv_buffer.drain(..consumed);
                }
                Err(crate::protocol::ParseError::InsufficientData) => {
                    let next = if batch.is_empty() {
                        tokio::select! {
                            _ = cancel.cancelled() => return Ok(()),
                            frame = data_recv.recv() => frame,
                        }
                    } else {
                        let next = tokio::time::timeout(Duration::ZERO, data_recv.recv()).await;
                        let Ok(next) = next else {
                            break;
                        };
                        next
                    };
                    match next {
                        Ok(chunk) => recv_buffer.extend_from_slice(&chunk),
                        Err(TransportSessionIoError::ConnectionLost) => break,
                        Err(err) => return Err(io_error("dependency data recv", err)),
                    }
                }
                Err(err) => return Err(format!("parse dependency frame: {err}")),
            }
        }
        if !batch.is_empty() {
            ingest_now(&db_path, batch)?;
            continue;
        }
        return Ok(());
    }
}

pub async fn run_dependency_session_with_stats(
    io: Box<dyn TransportSessionIo>,
    db_path: String,
    recorded_by: String,
    peer_id: String,
    remote_addr: std::net::SocketAddr,
    cancel: CancellationToken,
) -> Result<DependencySessionStats, String> {
    let started = Instant::now();
    let stats = Arc::new(Mutex::new(DependencySessionStats::default()));
    let source_tag = format!("quic_recv:{}@{}", peer_id, remote_addr);
    let (request_rx, _guard) = dependency_fetch::register(&db_path, &recorded_by, &peer_id);
    let parts = io.split();
    let (response_tx, response_rx) = mpsc::channel::<Vec<EventId>>(RESPONSE_QUEUE_CAP);
    let sender_cancel = cancel.child_token();
    let receiver_cancel = cancel.child_token();
    let sender_task = tokio::task::spawn_local(run_dependency_response_sender(
        parts.data_send,
        db_path.clone(),
        response_rx,
        sender_cancel,
        stats.clone(),
    ));
    let receiver_task = tokio::task::spawn_local(run_dependency_receiver(
        parts.data_recv,
        db_path.clone(),
        recorded_by.clone(),
        source_tag,
        receiver_cancel,
        stats.clone(),
    ));

    let control_result = run_dependency_control_loop(
        parts.control,
        request_rx,
        response_tx,
        cancel.clone(),
        stats.clone(),
    )
    .await;
    cancel.cancel();

    let sender_result = sender_task
        .await
        .map_err(|e| format!("dependency sender join: {e}"))?;
    let receiver_result = receiver_task
        .await
        .map_err(|e| format!("dependency receiver join: {e}"))?;

    control_result?;
    sender_result?;
    receiver_result?;
    let mut final_stats = stats
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    final_stats.duration_ms = started.elapsed().as_millis();
    Ok(final_stats)
}

pub async fn run_dependency_session(
    io: Box<dyn TransportSessionIo>,
    db_path: String,
    recorded_by: String,
    peer_id: String,
    remote_addr: std::net::SocketAddr,
    cancel: CancellationToken,
) -> Result<(), String> {
    let _ =
        run_dependency_session_with_stats(io, db_path, recorded_by, peer_id, remote_addr, cancel)
            .await?;
    Ok(())
}

pub fn spawn_outbound_dependency_session(
    daemon_connection: DaemonConnection,
    db_path: String,
    recorded_by: String,
    remote_session_peer_id: String,
    auth_plan: OutboundSessionAuthPlan,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_local(async move {
        let (session_id, mut io) = match open_outbound_dependency_session(&daemon_connection).await
        {
            Ok(opened) => opened,
            Err(err) => {
                warn!(
                    "dependency session open failed for daemon {}: {}",
                    daemon_connection.remote_daemon_peer_id(),
                    err
                );
                return;
            }
        };
        let effective_auth_plan = open_connection(&db_path)
            .ok()
            .and_then(|conn| {
                resolve_outbound_session_auth_plan(
                    &conn,
                    &recorded_by,
                    &remote_session_peer_id,
                    daemon_connection.remote_daemon_peer_id(),
                    &auth_plan,
                )
                .ok()
            })
            .unwrap_or_else(|| auth_plan.clone());
        let auth_result = match send_outbound_session_auth(
            io.as_mut(),
            &db_path,
            &recorded_by,
            daemon_connection.remote_daemon_peer_id(),
            Some(daemon_connection.remote_daemon_peer_id()),
            &effective_auth_plan,
        )
        .await
        {
            Ok(auth_result) => auth_result,
            Err(err) => {
                warn!(
                    "dependency session auth failed for daemon {} tenant={}: {}",
                    daemon_connection.remote_daemon_peer_id(),
                    recorded_by,
                    err
                );
                return;
            }
        };
        info!(
            "Starting dependency session {} peer={} daemon={} remote={}",
            session_id,
            &auth_result.session_peer_id[..16.min(auth_result.session_peer_id.len())],
            daemon_connection.remote_daemon_peer_id(),
            daemon_connection.remote_addr()
        );
        if let Err(err) = run_dependency_session(
            io,
            db_path,
            recorded_by,
            auth_result.session_peer_id.clone(),
            daemon_connection.remote_addr(),
            shutdown,
        )
        .await
        {
            warn!(
                "dependency session {} ended with error peer={}: {}",
                session_id,
                &auth_result.session_peer_id[..16.min(auth_result.session_peer_id.len())],
                err
            );
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_id_stats_track_control_bytes_and_counts() {
        let stats = Arc::new(Mutex::new(DependencySessionStats::default()));
        let ids = vec![[0x11; 32], [0x22; 32], [0x33; 32]];
        let frame = encode_frame(&Frame::RequestIds { ids: ids.clone() });

        record_request_ids_tx(&stats, frame.len(), ids.len());
        record_request_ids_rx(&stats, frame.len(), ids.len());

        let stats = stats.lock().unwrap().clone();
        assert_eq!(stats.control_frames_sent, 1);
        assert_eq!(stats.control_frames_received, 1);
        assert_eq!(stats.request_ids_sent, ids.len() as u64);
        assert_eq!(stats.request_ids_received, ids.len() as u64);
        assert_eq!(stats.control_bytes_sent, frame.len() as u64);
        assert_eq!(stats.control_bytes_received, frame.len() as u64);
        assert_eq!(stats.total_bytes_sent(), frame.len() as u64);
        assert_eq!(stats.total_bytes_received(), frame.len() as u64);
    }

    #[test]
    fn response_event_stats_track_wire_and_payload_bytes() {
        let stats = Arc::new(Mutex::new(DependencySessionStats::default()));
        let blob = vec![0xAB; 48];
        let frame = encode_frame(&Frame::Event { blob: blob.clone() });

        record_response_event_tx(&stats, frame.len(), blob.len());
        record_response_event_rx(&stats, frame.len(), blob.len());

        let stats = stats.lock().unwrap().clone();
        assert_eq!(stats.data_frames_sent, 1);
        assert_eq!(stats.data_frames_received, 1);
        assert_eq!(stats.response_events_sent, 1);
        assert_eq!(stats.response_events_received, 1);
        assert_eq!(stats.data_bytes_sent, frame.len() as u64);
        assert_eq!(stats.data_bytes_received, frame.len() as u64);
        assert_eq!(stats.response_payload_bytes_sent, blob.len() as u64);
        assert_eq!(stats.response_payload_bytes_received, blob.len() as u64);
        assert_eq!(stats.total_bytes_sent(), frame.len() as u64);
        assert_eq!(stats.total_bytes_received(), frame.len() as u64);
    }
}
