//! Sync session handler: bridges the SessionHandler contract to the
//! sync initiator/responder functions in sync::session.
//!
//! Phase 6: removed `into_any` downcast; uses `TransportSessionIo::split()` and
//! adapter wrappers so sync never depends on QUIC concrete types.

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::contracts::peering_contract::{
    ControlIo, DataRecvIo, DataSendIo, SessionDirection, SessionHandler, SessionMeta,
    TransportSessionIo, TransportSessionIoError,
};
use crate::protocol::Frame;
use crate::protocol::{encode_frame, parse_frame};
use crate::sync::session::{run_sync_initiator, run_sync_responder};
use crate::sync::CoordinationManager;
use crate::transport::connection::ConnectionError;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};

// ---------------------------------------------------------------------------
// Adapters: wrap contract IO traits into StreamConn/StreamSend/StreamRecv
// so session functions can consume them without knowing about QUIC.
// ---------------------------------------------------------------------------

struct ControlAdapter {
    inner: Box<dyn ControlIo>,
}

#[async_trait]
impl StreamConn for ControlAdapter {
    async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
        let frame = encode_frame(msg);
        self.inner.send(&frame).await.map_err(|e| map_io_error(e))
    }

    async fn flush(&mut self) -> Result<(), ConnectionError> {
        self.inner.flush().await.map_err(|e| map_io_error(e))
    }

    async fn recv(&mut self) -> Result<Frame, ConnectionError> {
        let frame = self.inner.recv().await.map_err(|e| map_io_error(e))?;
        let (msg, _) = parse_frame(&frame).map_err(|e| ConnectionError::Parse(e))?;
        Ok(msg)
    }
}

struct DataSendAdapter {
    inner: Box<dyn DataSendIo>,
}

#[async_trait]
impl StreamSend for DataSendAdapter {
    async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
        let frame = encode_frame(msg);
        self.inner.send(&frame).await.map_err(|e| map_io_error(e))
    }

    async fn flush(&mut self) -> Result<(), ConnectionError> {
        self.inner.flush().await.map_err(|e| map_io_error(e))
    }
}

struct DataRecvAdapter {
    inner: Box<dyn DataRecvIo>,
}

#[async_trait]
impl StreamRecv for DataRecvAdapter {
    async fn recv(&mut self) -> Result<Frame, ConnectionError> {
        let frame = self.inner.recv().await.map_err(|e| map_io_error(e))?;
        let (msg, _) = parse_frame(&frame).map_err(|e| ConnectionError::Parse(e))?;
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
pub enum SessionRole {
    Initiator {
        coordination_manager: Arc<CoordinationManager>,
    },
    Responder,
}

#[derive(Clone)]
pub struct SyncSessionHandler {
    db_path: String,
    timeout_secs: u64,
    role: SessionRole,
    shared_ingest: mpsc::Sender<IngestItem>,
}

impl SyncSessionHandler {
    pub fn outbound(
        db_path: String,
        timeout_secs: u64,
        coordination_manager: Arc<CoordinationManager>,
        shared_ingest: mpsc::Sender<IngestItem>,
    ) -> Self {
        Self {
            db_path,
            timeout_secs,
            role: SessionRole::Initiator {
                coordination_manager,
            },
            shared_ingest,
        }
    }

    pub fn responder(
        db_path: String,
        timeout_secs: u64,
        shared_ingest: mpsc::Sender<IngestItem>,
    ) -> Self {
        Self {
            db_path,
            timeout_secs,
            role: SessionRole::Responder,
            shared_ingest,
        }
    }
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
        let parts = io.split();
        let mut conn: DualConnection<ControlAdapter, DataSendAdapter, DataRecvAdapter> =
            DualConnection {
                control: ControlAdapter {
                    inner: parts.control,
                },
                data_send: DataSendAdapter {
                    inner: parts.data_send,
                },
                data_recv: DataRecvAdapter {
                    inner: parts.data_recv,
                },
            };

        let peer_id = hex::encode(meta.peer.0);
        let tenant_id = meta.tenant.0.clone();

        // For outbound sessions, send stream materialization markers before
        // starting the sync protocol. These empty HaveList messages force
        // lazy QUIC streams to open on the receiver side.
        if meta.direction == SessionDirection::Outbound {
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
        }

        match (&self.role, meta.direction) {
            (
                SessionRole::Initiator {
                    coordination_manager,
                },
                SessionDirection::Outbound,
            ) => {
                // Register per-session coordination handles so a stale/disconnected
                // assignment channel from a prior session cannot poison future sessions.
                let coordination = coordination_manager.register_peer();
                let run = run_sync_initiator(
                    conn,
                    &self.db_path,
                    self.timeout_secs,
                    &peer_id,
                    &tenant_id,
                    coordination.as_ref(),
                    self.shared_ingest.clone(),
                );
                tokio::pin!(run);
                tokio::select! {
                    _ = cancel.cancelled() => Err(format!("session {} cancelled", meta.session_id)),
                    result = &mut run => result
                        .map(|_| ())
                        .map_err(|e| format!("initiator sync failed: {e}")),
                }
            }
            (SessionRole::Responder, SessionDirection::Inbound) => {
                let run = run_sync_responder(
                    conn,
                    &self.db_path,
                    self.timeout_secs,
                    &peer_id,
                    &tenant_id,
                    self.shared_ingest.clone(),
                );
                tokio::pin!(run);
                tokio::select! {
                    _ = cancel.cancelled() => Err(format!("session {} cancelled", meta.session_id)),
                    result = &mut run => result
                        .map(|_| ())
                        .map_err(|e| format!("responder sync failed: {e}")),
                }
            }
            (SessionRole::Initiator { .. }, SessionDirection::Inbound) => {
                Err("initiator handler cannot run inbound sessions".to_string())
            }
            (SessionRole::Responder, SessionDirection::Outbound) => {
                Err("responder handler cannot run outbound sessions".to_string())
            }
        }
    }
}
