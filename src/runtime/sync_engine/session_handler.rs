//! Sync session handler: bridges the SessionHandler contract to the
//! sync initiator/responder functions in sync::session.
//!
//! Phase 6: removed `into_any` downcast; uses `TransportSessionIo::split()` and
//! adapter wrappers so sync never depends on QUIC concrete types.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::contracts::peering_contract::{
    ControlIo, DataRecvIo, DataSendIo, SessionDirection, SessionHandler, SessionMeta,
    TransportSessionIo, TransportSessionIoError,
};
use crate::protocol::Frame;
use crate::protocol::{encode_frame, parse_frame};
use crate::sync::session::coordinator::PeerCoord;
use crate::sync::session::logging::{LogDir, LogLane, SessionRunLogger, SyncRunCapture};
use crate::sync::session::{run_sync_initiator, run_sync_responder};
use crate::sync::session::{ConnectionRequestState, ConnectionResponseState};
use crate::transport::connection::ConnectionError;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};

// ---------------------------------------------------------------------------
// Adapters: wrap contract IO traits into StreamConn/StreamSend/StreamRecv
// so session functions can consume them without knowing about QUIC.
// ---------------------------------------------------------------------------

struct ControlAdapter {
    inner: Box<dyn ControlIo>,
    capture: Option<SyncRunCapture>,
}

#[async_trait]
impl StreamConn for ControlAdapter {
    async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
        let frame = encode_frame(msg);
        if let Some(c) = &self.capture {
            c.record_frame(LogLane::Control, LogDir::Tx, msg, frame.len());
        }
        self.inner.send(&frame).await.map_err(|e| map_io_error(e))
    }

    async fn flush(&mut self) -> Result<(), ConnectionError> {
        self.inner.flush().await.map_err(|e| map_io_error(e))
    }

    async fn recv(&mut self) -> Result<Frame, ConnectionError> {
        let frame = self.inner.recv().await.map_err(|e| map_io_error(e))?;
        let (msg, _) = parse_frame(&frame).map_err(|e| ConnectionError::Parse(e))?;
        if let Some(c) = &self.capture {
            c.record_frame(LogLane::Control, LogDir::Rx, &msg, frame.len());
        }
        Ok(msg)
    }
}

struct DataSendAdapter {
    inner: Box<dyn DataSendIo>,
    capture: Option<SyncRunCapture>,
}

#[async_trait]
impl StreamSend for DataSendAdapter {
    async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
        let frame = encode_frame(msg);
        if let Some(c) = &self.capture {
            c.record_frame(LogLane::Data, LogDir::Tx, msg, frame.len());
        }
        self.inner.send(&frame).await.map_err(|e| map_io_error(e))
    }

    async fn flush(&mut self) -> Result<(), ConnectionError> {
        self.inner.flush().await.map_err(|e| map_io_error(e))
    }
}

struct DataRecvAdapter {
    inner: Box<dyn DataRecvIo>,
    capture: Option<SyncRunCapture>,
}

#[async_trait]
impl StreamRecv for DataRecvAdapter {
    async fn recv(&mut self) -> Result<Frame, ConnectionError> {
        let frame = self.inner.recv().await.map_err(|e| map_io_error(e))?;
        let (msg, _) = parse_frame(&frame).map_err(|e| ConnectionError::Parse(e))?;
        if let Some(c) = &self.capture {
            c.record_frame(LogLane::Data, LogDir::Rx, &msg, frame.len());
        }
        Ok(msg)
    }
}

fn map_io_error(err: TransportSessionIoError) -> ConnectionError {
    match err {
        TransportSessionIoError::ConnectionLost => ConnectionError::Closed,
        other => ConnectionError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            other.to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Session handler
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SyncSessionHandler {
    db_path: String,
    timeout_secs: u64,
    direction: SessionDirection,
    coordination: Arc<PeerCoord>,
    request_state: Arc<ConnectionRequestState>,
    response_state: Arc<ConnectionResponseState>,
    shared_ingest: mpsc::Sender<IngestItem>,
}

impl SyncSessionHandler {
    pub fn outbound(
        db_path: String,
        timeout_secs: u64,
        coordination: Arc<PeerCoord>,
        shared_ingest: mpsc::Sender<IngestItem>,
    ) -> Self {
        Self {
            db_path,
            timeout_secs,
            direction: SessionDirection::Outbound,
            coordination,
            request_state: Arc::new(ConnectionRequestState::default()),
            response_state: Arc::new(ConnectionResponseState::default()),
            shared_ingest,
        }
    }

    pub fn responder(
        db_path: String,
        timeout_secs: u64,
        coordination: Arc<PeerCoord>,
        shared_ingest: mpsc::Sender<IngestItem>,
    ) -> Self {
        Self {
            db_path,
            timeout_secs,
            direction: SessionDirection::Inbound,
            coordination,
            request_state: Arc::new(ConnectionRequestState::default()),
            response_state: Arc::new(ConnectionResponseState::default()),
            shared_ingest,
        }
    }
}

impl Drop for SyncSessionHandler {
    fn drop(&mut self) {
        self.request_state.clear();
        self.response_state.clear();
        self.coordination.clear_request_state();
    }
}

const STARTUP_MARKER_TIMEOUT_SECS: u64 = 10;

async fn send_outbound_startup_markers<C, S, R>(
    conn: &mut DualConnection<C, S, R>,
    session_id: u64,
    timeout_secs: u64,
) -> Result<(), String>
where
    C: StreamConn,
    S: StreamSend,
    R: StreamRecv,
{
    let marker_timeout_secs = timeout_secs.min(STARTUP_MARKER_TIMEOUT_SECS).max(1);
    let marker_timeout = Duration::from_secs(marker_timeout_secs);
    tokio::time::timeout(marker_timeout, async {
        conn.control
            .send(&Frame::HaveList { ids: vec![] })
            .await
            .map_err(|e| format!("failed to send control marker: {e}"))?;
        conn.data_send
            .send(&Frame::HaveList { ids: vec![] })
            .await
            .map_err(|e| format!("failed to send data marker: {e}"))?;
        conn.flush_control()
            .await
            .map_err(|e| format!("failed to flush control marker: {e}"))?;
        conn.flush_data()
            .await
            .map_err(|e| format!("failed to flush data marker: {e}"))?;
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| {
        format!(
            "session {} startup markers timed out after {}s",
            session_id, marker_timeout_secs
        )
    })?
}

#[async_trait(?Send)]
impl SessionHandler for SyncSessionHandler {
    async fn on_session(
        &self,
        meta: SessionMeta,
        io: Box<dyn TransportSessionIo>,
        cancel: CancellationToken,
    ) -> Result<(), String> {
        if cancel.is_cancelled() {
            return Err(format!(
                "session {} cancelled before start",
                meta.session_id
            ));
        }

        // Split the abstract TransportSessionIo into independent control/data handles,
        // then wrap them as StreamConn/StreamSend/StreamRecv adapters so the
        // existing session functions work without QUIC-specific types.
        let role_name = match self.direction {
            SessionDirection::Outbound => "initiator",
            SessionDirection::Inbound => "responder",
        };
        let run_logger = SessionRunLogger::maybe_new(&self.db_path, &meta, role_name);
        let capture = run_logger.as_ref().and_then(|l| l.capture());

        let parts = io.split();
        let mut conn: DualConnection<ControlAdapter, DataSendAdapter, DataRecvAdapter> =
            DualConnection {
                control: ControlAdapter {
                    inner: parts.control,
                    capture: capture.clone(),
                },
                data_send: DataSendAdapter {
                    inner: parts.data_send,
                    capture: capture.clone(),
                },
                data_recv: DataRecvAdapter {
                    inner: parts.data_recv,
                    capture,
                },
            };

        let peer_id = hex::encode(meta.peer.0);
        let tenant_id = meta.tenant.0.clone();
        let ingress_source_tag = format!("quic_recv:{}@{}", peer_id, meta.remote_addr);
        let session_owner = format!("{}:{}", role_name, meta.session_id);

        // For outbound sessions, send stream materialization markers before
        // starting the sync protocol. These empty HaveList messages force
        // lazy QUIC streams to open on the receiver side.
        if meta.direction == SessionDirection::Outbound {
            info!(
                "Session {} outbound startup markers begin peer={} remote={}",
                meta.session_id,
                &peer_id[..16.min(peer_id.len())],
                meta.remote_addr
            );
            send_outbound_startup_markers(&mut conn, meta.session_id, self.timeout_secs).await?;
            info!(
                "Session {} outbound startup markers complete peer={} remote={}",
                meta.session_id,
                &peer_id[..16.min(peer_id.len())],
                meta.remote_addr
            );
        }

        let mut stats: Option<crate::runtime::SyncStats> = None;
        let result = match (self.direction, meta.direction) {
            (SessionDirection::Outbound, SessionDirection::Outbound) => {
                info!(
                    "Session {} entering initiator sync peer={} remote={}",
                    meta.session_id,
                    &peer_id[..16.min(peer_id.len())],
                    meta.remote_addr
                );
                let run = run_sync_initiator(
                    conn,
                    meta.session_id,
                    &self.db_path,
                    self.timeout_secs,
                    &session_owner,
                    &peer_id,
                    &tenant_id,
                    &ingress_source_tag,
                    self.coordination.as_ref(),
                    self.request_state.as_ref(),
                    self.response_state.as_ref(),
                    self.shared_ingest.clone(),
                    run_logger.as_ref().and_then(|l| l.capture()),
                    run_logger.as_ref().and_then(|l| l.rx_capture()),
                );
                tokio::pin!(run);
                let run_result: Result<crate::runtime::SyncStats, String> = tokio::select! {
                    _ = cancel.cancelled() => Err(format!("session {} cancelled", meta.session_id)),
                    result = &mut run => {
                        result.map_err(|e| format!("initiator sync failed: {e}"))
                    },
                };
                match run_result {
                    Ok(s) => {
                        stats = Some(s);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            (SessionDirection::Inbound, SessionDirection::Inbound) => {
                info!(
                    "Session {} entering responder sync peer={} remote={}",
                    meta.session_id,
                    &peer_id[..16.min(peer_id.len())],
                    meta.remote_addr
                );
                let run = run_sync_responder(
                    conn,
                    meta.session_id,
                    &self.db_path,
                    self.timeout_secs,
                    &session_owner,
                    &peer_id,
                    &tenant_id,
                    &ingress_source_tag,
                    self.coordination.as_ref(),
                    self.request_state.as_ref(),
                    self.response_state.as_ref(),
                    self.shared_ingest.clone(),
                    run_logger.as_ref().and_then(|l| l.capture()),
                    run_logger.as_ref().and_then(|l| l.rx_capture()),
                );
                tokio::pin!(run);
                let run_result: Result<crate::runtime::SyncStats, String> = tokio::select! {
                    _ = cancel.cancelled() => Err(format!("session {} cancelled", meta.session_id)),
                    result = &mut run => result
                        .map_err(|e| format!("responder sync failed: {e}")),
                };
                match run_result {
                    Ok(s) => {
                        stats = Some(s);
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            (SessionDirection::Outbound, SessionDirection::Inbound) => {
                Err("initiator handler cannot run inbound sessions".to_string())
            }
            (SessionDirection::Inbound, SessionDirection::Outbound) => {
                Err("responder handler cannot run outbound sessions".to_string())
            }
        };

        let error_msg = result.as_ref().err().cloned();
        if let Some(logger) = run_logger {
            let outcome = if error_msg.is_some() { "error" } else { "ok" };
            let _ = logger.finalize(stats.as_ref(), outcome, error_msg);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::peering_contract::{PeerFingerprint, TenantId, TransportSessionIoParts};
    use crate::sync::session::coordinator::CoordinationManager;
    use std::future::pending;

    struct StaticControl;

    #[async_trait]
    impl ControlIo for StaticControl {
        async fn recv(&mut self) -> Result<Vec<u8>, TransportSessionIoError> {
            pending::<Result<Vec<u8>, TransportSessionIoError>>().await
        }

        async fn send(&mut self, _frame: &[u8]) -> Result<(), TransportSessionIoError> {
            Ok(())
        }

        async fn flush(&mut self) -> Result<(), TransportSessionIoError> {
            Ok(())
        }
    }

    struct StalledDataSend;

    #[async_trait]
    impl DataSendIo for StalledDataSend {
        async fn send(&mut self, _frame: &[u8]) -> Result<(), TransportSessionIoError> {
            Ok(())
        }

        async fn flush(&mut self) -> Result<(), TransportSessionIoError> {
            pending::<Result<(), TransportSessionIoError>>().await
        }
    }

    struct IdleDataRecv;

    #[async_trait]
    impl DataRecvIo for IdleDataRecv {
        async fn recv(&mut self) -> Result<Vec<u8>, TransportSessionIoError> {
            pending::<Result<Vec<u8>, TransportSessionIoError>>().await
        }
    }

    struct StalledStartupIo;

    #[async_trait]
    impl TransportSessionIo for StalledStartupIo {
        fn session_id(&self) -> u64 {
            42
        }

        fn max_frame_size(&self) -> usize {
            1024
        }

        fn split(self: Box<Self>) -> TransportSessionIoParts {
            TransportSessionIoParts {
                control: Box::new(StaticControl),
                data_send: Box::new(StalledDataSend),
                data_recv: Box::new(IdleDataRecv),
            }
        }
    }

    #[tokio::test]
    async fn outbound_startup_markers_timeout_when_data_flush_stalls() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("startup-marker-timeout.db");
        let (shared_ingest_tx, _shared_ingest_rx) = mpsc::channel::<IngestItem>(1);
        let coordination = CoordinationManager::new().register_peer();
        let handler = SyncSessionHandler::outbound(
            db_path.to_str().unwrap().to_string(),
            1,
            coordination,
            shared_ingest_tx,
        );
        let meta = SessionMeta {
            session_id: 42,
            tenant: TenantId("tenant-a".to_string()),
            peer: PeerFingerprint([0x11; 32]),
            remote_addr: "127.0.0.1:4000".parse().unwrap(),
            direction: SessionDirection::Outbound,
        };

        let started = std::time::Instant::now();
        let err = handler
            .on_session(meta, Box::new(StalledStartupIo), CancellationToken::new())
            .await
            .expect_err("startup markers should time out instead of hanging");
        assert!(
            err.contains("startup markers timed out"),
            "unexpected error: {err}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "startup marker timeout should fail quickly, not hang"
        );
    }
}
