use async_trait::async_trait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::contracts::network_contract::{
    SessionDirection, SessionHandler, SessionIo, SessionMeta,
};
use crate::sync::engine::{
    run_sync_initiator_dual, run_sync_responder_dual, IngestItem, PeerCoord,
};
use crate::transport::connection::{Connection, RecvConnection, SendConnection};
use crate::transport::SyncSessionIo;

type QuinnSessionIo = SyncSessionIo<Connection, SendConnection, RecvConnection>;

static NEXT_SESSION_ID: AtomicU64 = AtomicU64::new(1);

pub fn next_session_id() -> u64 {
    NEXT_SESSION_ID.fetch_add(1, Ordering::Relaxed)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacySessionRole {
    Initiator,
    Responder,
}

#[derive(Clone)]
pub struct LegacySyncSessionHandler {
    db_path: String,
    timeout_secs: u64,
    role: LegacySessionRole,
    shared_ingest: Option<mpsc::Sender<IngestItem>>,
    coordination: Option<Arc<PeerCoord>>,
}

impl LegacySyncSessionHandler {
    pub fn initiator(db_path: String, timeout_secs: u64) -> Self {
        Self {
            db_path,
            timeout_secs,
            role: LegacySessionRole::Initiator,
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
            role: LegacySessionRole::Initiator,
            shared_ingest,
            coordination: Some(coordination),
        }
    }

    pub fn responder(db_path: String, timeout_secs: u64) -> Self {
        Self {
            db_path,
            timeout_secs,
            role: LegacySessionRole::Responder,
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
            role: LegacySessionRole::Responder,
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
                "legacy session handler only supports SyncSessionIo over QUIC dual streams"
                    .to_string()
            })
    }
}

#[async_trait(?Send)]
impl SessionHandler for LegacySyncSessionHandler {
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
        let conn = io.into_inner();
        let peer_id = hex::encode(meta.peer.0);
        let tenant_id = meta.tenant.0.clone();

        match (self.role, meta.direction) {
            (LegacySessionRole::Initiator, SessionDirection::Outbound) => {
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
            (LegacySessionRole::Responder, SessionDirection::Inbound) => {
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
            (LegacySessionRole::Initiator, SessionDirection::Inbound) => {
                Err("initiator handler cannot run inbound sessions".to_string())
            }
            (LegacySessionRole::Responder, SessionDirection::Outbound) => {
                Err("responder handler cannot run outbound sessions".to_string())
            }
        }
    }
}
