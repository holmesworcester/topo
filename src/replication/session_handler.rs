//! Replication session handler: bridges the SessionHandler contract to the
//! sync initiator/responder functions in replication::session.
//!
//! Moved from sync/session_handler.rs (Phase 5 of Option B refactor).

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::contracts::network_contract::{
    SessionDirection, SessionHandler, SessionIo, SessionMeta,
};
use crate::event_runtime::IngestItem;
use crate::replication::session::{run_sync_initiator_dual, run_sync_responder_dual, PeerCoord};
use crate::sync::SyncMessage;
use crate::transport::connection::{Connection, RecvConnection, SendConnection};
use crate::transport::SyncSessionIo;

type QuinnSessionIo = SyncSessionIo<Connection, SendConnection, RecvConnection>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

#[derive(Clone)]
pub struct ReplicationSessionHandler {
    db_path: String,
    timeout_secs: u64,
    role: SessionRole,
    shared_ingest: Option<mpsc::Sender<IngestItem>>,
    coordination: Option<Arc<PeerCoord>>,
}

impl ReplicationSessionHandler {
    pub fn initiator(db_path: String, timeout_secs: u64) -> Self {
        Self {
            db_path,
            timeout_secs,
            role: SessionRole::Initiator,
            shared_ingest: None,
            coordination: None,
        }
    }

    pub fn initiator_with_coordination(
        db_path: String,
        timeout_secs: u64,
        coordination: Arc<PeerCoord>,
        shared_ingest: Option<mpsc::Sender<IngestItem>>,
    ) -> Self {
        Self {
            db_path,
            timeout_secs,
            role: SessionRole::Initiator,
            shared_ingest,
            coordination: Some(coordination),
        }
    }

    pub fn responder(db_path: String, timeout_secs: u64) -> Self {
        Self {
            db_path,
            timeout_secs,
            role: SessionRole::Responder,
            shared_ingest: None,
            coordination: None,
        }
    }

    pub fn responder_with_shared_ingest(
        db_path: String,
        timeout_secs: u64,
        shared_ingest: mpsc::Sender<IngestItem>,
    ) -> Self {
        Self {
            db_path,
            timeout_secs,
            role: SessionRole::Responder,
            shared_ingest: Some(shared_ingest),
            coordination: None,
        }
    }

    fn downcast_quinn_session_io(io: Box<dyn SessionIo>) -> Result<QuinnSessionIo, String> {
        let any_io = io.into_any();
        any_io
            .downcast::<QuinnSessionIo>()
            .map(|boxed| *boxed)
            .map_err(|_| {
                "replication session handler only supports SyncSessionIo over QUIC dual streams"
                    .to_string()
            })
    }
}

#[async_trait(?Send)]
impl SessionHandler for ReplicationSessionHandler {
    async fn on_session(
        &self,
        meta: SessionMeta,
        io: Box<dyn SessionIo>,
        cancel: CancellationToken,
    ) -> Result<(), String> {
        if cancel.is_cancelled() {
            return Err(format!(
                "session {} cancelled before start",
                meta.session_id
            ));
        }

        let io = Self::downcast_quinn_session_io(io)?;
        let mut conn = io.into_inner();
        let peer_id = hex::encode(meta.peer.0);
        let tenant_id = meta.tenant.0.clone();

        // For outbound sessions, send stream materialization markers before
        // starting the sync protocol. These empty HaveList messages force
        // lazy QUIC streams to open on the receiver side.
        if meta.direction == SessionDirection::Outbound {
            conn.control
                .send(&SyncMessage::HaveList { ids: vec![] })
                .await
                .map_err(|e| format!("failed to send control marker: {e}"))?;
            conn.data_send
                .send(&SyncMessage::HaveList { ids: vec![] })
                .await
                .map_err(|e| format!("failed to send data marker: {e}"))?;
            conn.flush_control()
                .await
                .map_err(|e| format!("failed to flush control marker: {e}"))?;
            conn.flush_data()
                .await
                .map_err(|e| format!("failed to flush data marker: {e}"))?;
        }

        match (self.role, meta.direction) {
            (SessionRole::Initiator, SessionDirection::Outbound) => {
                let run = run_sync_initiator_dual(
                    conn,
                    &self.db_path,
                    self.timeout_secs,
                    &peer_id,
                    &tenant_id,
                    self.coordination.as_deref(),
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
                let run = run_sync_responder_dual(
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
            (SessionRole::Initiator, SessionDirection::Inbound) => {
                Err("initiator handler cannot run inbound sessions".to_string())
            }
            (SessionRole::Responder, SessionDirection::Outbound) => {
                Err("responder handler cannot run outbound sessions".to_string())
            }
        }
    }
}
