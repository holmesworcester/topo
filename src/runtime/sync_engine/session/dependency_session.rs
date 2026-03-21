use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::peering_contract::{
    ControlIo, DataRecvIo, DataSendIo, TransportSessionIo, TransportSessionIoError,
};
use crate::crypto::{hash_event, EventId};
use crate::db::{open_connection, store::Store};
use crate::protocol::{encode_frame, parse_frame, Frame};
use crate::runtime::transport::open_outbound_dependency_session;
use crate::state::{dependency_fetch, pipeline::ingest_now};
use crate::transport::TransportConnection;

const DEPENDENCY_BATCH_CAP: usize = 16;
const REQUEST_BATCH_CAP: usize = 64;
const RESPONSE_QUEUE_CAP: usize = 256;

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn decode_exact_frame(frame: &[u8]) -> Result<Frame, String> {
    let (parsed, consumed) = parse_frame(frame).map_err(|e| format!("parse dependency frame: {e}"))?;
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
    (
        hash_event(&blob),
        blob,
        recorded_by.to_string(),
        source_tag.to_string(),
        current_timestamp_ms(),
    )
}

async fn run_dependency_control_loop(
    mut control: Box<dyn ControlIo>,
    mut request_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<EventId>>,
    response_tx: mpsc::Sender<Vec<EventId>>,
    cancel: CancellationToken,
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
                    control
                        .send(&encode_frame(&Frame::RequestIds { ids: chunk.to_vec() }))
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
                        if response_tx.send(ids).await.is_err() {
                            return Ok(());
                        }
                    }
                    Frame::NegOpen { .. }
                    | Frame::NegMsg { .. }
                    | Frame::DiscoveryHints { .. }
                    | Frame::IntroOffer { .. }
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
                data_send
                    .send(&encode_frame(&Frame::Event { blob: blob.clone() }))
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
) -> Result<(), String> {
    loop {
        let frame = tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            frame = data_recv.recv() => frame,
        };
        let frame = match frame {
            Ok(frame) => frame,
            Err(TransportSessionIoError::ConnectionLost) => return Ok(()),
            Err(err) => return Err(io_error("dependency data recv", err)),
        };
        let mut batch = Vec::with_capacity(DEPENDENCY_BATCH_CAP);
        if let Frame::Event { blob } = decode_exact_frame(&frame)? {
            batch.push(make_ingest_item(blob, &recorded_by, &source_tag));
        }
        while batch.len() < DEPENDENCY_BATCH_CAP {
            let next = tokio::time::timeout(Duration::ZERO, data_recv.recv()).await;
            let Ok(next) = next else {
                break;
            };
            let frame = match next {
                Ok(frame) => frame,
                Err(TransportSessionIoError::ConnectionLost) => break,
                Err(err) => return Err(io_error("dependency data recv", err)),
            };
            if let Frame::Event { blob } = decode_exact_frame(&frame)? {
                batch.push(make_ingest_item(blob, &recorded_by, &source_tag));
            }
        }
        if !batch.is_empty() {
            ingest_now(&db_path, batch)?;
        }
    }
}

pub async fn run_dependency_session(
    io: Box<dyn TransportSessionIo>,
    db_path: String,
    recorded_by: String,
    peer_id: String,
    remote_addr: std::net::SocketAddr,
    cancel: CancellationToken,
) -> Result<(), String> {
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
    ));
    let receiver_task = tokio::task::spawn_local(run_dependency_receiver(
        parts.data_recv,
        db_path.clone(),
        recorded_by.clone(),
        source_tag,
        receiver_cancel,
    ));

    let control_result =
        run_dependency_control_loop(parts.control, request_rx, response_tx, cancel.clone()).await;
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
    Ok(())
}

pub fn spawn_outbound_dependency_session(
    connection: TransportConnection,
    db_path: String,
    recorded_by: String,
    peer_id: String,
    remote_addr: std::net::SocketAddr,
    shutdown: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_local(async move {
        let (session_id, io) = match open_outbound_dependency_session(&connection).await {
            Ok(opened) => opened,
            Err(err) => {
                warn!("dependency session open failed for peer {}: {}", peer_id, err);
                return;
            }
        };
        info!(
            "Starting dependency session {} peer={} remote={}",
            session_id,
            &peer_id[..16.min(peer_id.len())],
            remote_addr
        );
        if let Err(err) = run_dependency_session(
            io,
            db_path,
            recorded_by,
            peer_id.clone(),
            remote_addr,
            shutdown,
        )
        .await
        {
            warn!(
                "dependency session {} ended with error peer={}: {}",
                session_id,
                &peer_id[..16.min(peer_id.len())],
                err
            );
        }
    })
}
