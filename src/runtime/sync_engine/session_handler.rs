//! Sync connection handler: bridges the SessionHandler contract to the
//! sync initiator/responder functions in sync::session.
//!
//! Phase 6: removed `into_any` downcast; uses `TransportSessionIo::split()` and
//! adapter wrappers so sync never depends on QUIC concrete types.

use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::contracts::peering_contract::{
    ControlIo, DataRecvIo, DataSendIo, SessionDirection, SessionHandler, SessionMeta,
    TransportSessionIo, TransportSessionIoError,
};
use crate::protocol::Frame;
use crate::protocol::{encode_frame, parse_frame};
use crate::sync::session::logging::{LogDir, LogLane, SessionRunLogger, SyncRunCapture};
use crate::sync::session::{run_sync_initiator, run_sync_responder};
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
    fn swap_recv_limit(&mut self, _new_limit: usize) -> usize {
        usize::MAX
    }

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

    async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), ConnectionError> {
        if let Some(c) = &self.capture {
            c.record_marker(
                "data",
                "tx",
                "raw_chunk",
                Some(json!({ "len": bytes.len() }).to_string()),
            );
        }
        self.inner.send(bytes).await.map_err(|e| map_io_error(e))
    }

    async fn flush(&mut self) -> Result<(), ConnectionError> {
        self.inner.flush().await.map_err(|e| map_io_error(e))
    }
}

struct DataRecvAdapter {
    inner: Box<dyn DataRecvIo>,
    capture: Option<SyncRunCapture>,
    recv_buffer: Vec<u8>,
}

#[async_trait]
impl StreamRecv for DataRecvAdapter {
    async fn recv(&mut self) -> Result<Frame, ConnectionError> {
        loop {
            if !self.recv_buffer.is_empty() {
                match parse_frame(&self.recv_buffer) {
                    Ok((msg, consumed)) => {
                        self.recv_buffer.drain(..consumed);
                        if let Some(c) = &self.capture {
                            c.record_frame(LogLane::Data, LogDir::Rx, &msg, consumed);
                        }
                        return Ok(msg);
                    }
                    Err(crate::protocol::ParseError::InsufficientData) => {}
                    Err(e) => return Err(ConnectionError::Parse(e)),
                }
            }

            let chunk = self.inner.recv().await.map_err(|e| map_io_error(e))?;
            self.recv_buffer.extend_from_slice(&chunk);
        }
    }

    async fn recv_chunk(&mut self) -> Result<Vec<u8>, ConnectionError> {
        let chunk = self.inner.recv().await.map_err(|e| map_io_error(e))?;
        if let Some(c) = &self.capture {
            c.record_marker(
                "data",
                "rx",
                "raw_chunk",
                Some(json!({ "len": chunk.len() }).to_string()),
            );
        }
        Ok(chunk)
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
// Connection handler
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct SyncConnectionHandler {
    db_path: String,
    timeout_secs: u64,
    direction: SessionDirection,
    sync_control: Option<Arc<crate::runtime::sync_control::SyncControlRegistry>>,
}

impl SyncConnectionHandler {
    pub fn outbound(db_path: String, timeout_secs: u64) -> Self {
        Self {
            db_path,
            timeout_secs,
            direction: SessionDirection::Outbound,
            sync_control: None,
        }
    }

    pub fn responder(db_path: String, timeout_secs: u64) -> Self {
        Self {
            db_path,
            timeout_secs,
            direction: SessionDirection::Inbound,
            sync_control: None,
        }
    }

    /// Set the sync control registry for manual sync operations.
    pub fn with_sync_control(
        mut self,
        sync_control: Option<Arc<crate::runtime::sync_control::SyncControlRegistry>>,
    ) -> Self {
        self.sync_control = sync_control;
        self
    }

    pub async fn on_session_with_stats(
        &self,
        meta: SessionMeta,
        io: Box<dyn TransportSessionIo>,
        cancel: CancellationToken,
    ) -> Result<crate::runtime::SyncStats, String> {
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
        let conn: DualConnection<ControlAdapter, DataSendAdapter, DataRecvAdapter> =
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
                    recv_buffer: Vec::new(),
                },
            };

        let peer_id = hex::encode(meta.peer.0);
        let tenant_id = meta.tenant.0.clone();
        let ingress_source_tag = format!("quic_recv:{}@{}", peer_id, meta.remote_addr);

        // Register with sync control registry if available.
        let sc_role = match self.direction {
            SessionDirection::Outbound => crate::runtime::sync_control::SessionRole::Initiator,
            SessionDirection::Inbound => crate::runtime::sync_control::SessionRole::Responder,
        };
        let registered = self
            .sync_control
            .as_ref()
            .map(|sc| sc.register_session(&tenant_id, &peer_id, sc_role));
        let (mut manual_cmd_rx, _sc_guard) = match registered {
            Some(rs) => {
                let (crx, guard) = rs.into_parts();
                (Some(crx), Some(guard))
            }
            None => (None, None),
        };

        // No hard total-session timeout. Liveness is enforced at each phase:
        //   - Negentropy control: INITIAL_CONTROL_PROGRESS_TIMEOUT (bounded per message)
        //   - Data receive: activity_timeout (idle between chunks)
        // A session that is still transferring data should never be killed.
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
                    &peer_id,
                    &tenant_id,
                    &ingress_source_tag,
                    run_logger.as_ref().and_then(|l| l.rx_capture()),
                    manual_cmd_rx.take(),
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
                    &peer_id,
                    &tenant_id,
                    &ingress_source_tag,
                    run_logger.as_ref().and_then(|l| l.rx_capture()),
                    manual_cmd_rx.take(),
                );
                tokio::pin!(run);
                let run_result: Result<crate::runtime::SyncStats, String> = tokio::select! {
                    _ = cancel.cancelled() => Err(format!("session {} cancelled", meta.session_id)),
                    result = &mut run => {
                        result.map_err(|e| format!("responder sync failed: {e}"))
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

        match result {
            Ok(()) => stats.ok_or_else(|| "session completed without sync stats".to_string()),
            Err(err) => Err(err),
        }
    }
}

#[async_trait(?Send)]
impl SessionHandler for SyncConnectionHandler {
    async fn on_session(
        &self,
        meta: SessionMeta,
        io: Box<dyn TransportSessionIo>,
        cancel: CancellationToken,
    ) -> Result<(), String> {
        self.on_session_with_stats(meta, io, cancel)
            .await
            .map(|_| ())
    }
}
