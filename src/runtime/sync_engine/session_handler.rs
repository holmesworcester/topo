//! Sync connection handler: bridges the SessionHandler contract to the
//! sync initiator/responder functions in sync::session.
//!
//! Phase 6: removed `into_any` downcast; uses `TransportSessionIo::split()` and
//! adapter wrappers so sync never depends on QUIC concrete types.

use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::peering_contract::{
    ControlIo, DataRecvIo, DataSendIo, SessionDirection, SessionHandler, SessionMeta,
    TransportSessionIo, TransportSessionIoError,
};
use crate::event_modules::operational::client_lifecycle::client_id_for_db_path;
use crate::event_modules::operational::sync_round_completed::{
    record_terminal_sync_round_for_active_session, SyncRoundOutcome,
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

fn terminal_round_recorded_by(
    direction: SessionDirection,
    db_path: &str,
    tenant_id: &str,
) -> String {
    match direction {
        SessionDirection::Outbound => tenant_id.to_string(),
        SessionDirection::Inbound => client_id_for_db_path(db_path),
    }
}

fn record_interrupted_sync_round(
    db_path: &str,
    direction: SessionDirection,
    tenant_id: &str,
    session_id: u64,
    outcome: SyncRoundOutcome,
    detail: &str,
    duration_ms: i64,
) -> Result<(), String> {
    let recorded_by = terminal_round_recorded_by(direction, db_path, tenant_id);
    record_terminal_sync_round_for_active_session(
        db_path,
        &recorded_by,
        session_id as i64,
        outcome,
        Some(detail),
        duration_ms,
    )
    .map(|_| ())
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
}

#[async_trait(?Send)]
impl SessionHandler for SyncConnectionHandler {
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
        let session_start = std::time::Instant::now();

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
                let (crx, _prx, guard) = rs.into_parts();
                (Some(crx), Some(guard))
            }
            None => (None, None),
        };

        let mut stats: Option<crate::runtime::SyncStats> = None;
        let session_timeout = std::time::Duration::from_secs(self.timeout_secs.saturating_add(10));
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
                    _ = cancel.cancelled() => {
                        let detail = format!("session {} cancelled", meta.session_id);
                        if let Err(err) = record_interrupted_sync_round(
                            &self.db_path,
                            self.direction,
                            &tenant_id,
                            meta.session_id,
                            SyncRoundOutcome::Cancelled,
                            &detail,
                            session_start.elapsed().as_millis() as i64,
                        ) {
                            warn!("failed to author interrupted initiator round: {}", err);
                        }
                        Err(detail)
                    }
                    result = tokio::time::timeout(session_timeout, &mut run) => {
                        match result {
                            Ok(result) => result.map_err(|e| format!("initiator sync failed: {e}")),
                            Err(_) => {
                                let detail = format!(
                                    "initiator sync timed out after {}s",
                                    session_timeout.as_secs()
                                );
                                if let Err(err) = record_interrupted_sync_round(
                                    &self.db_path,
                                    self.direction,
                                    &tenant_id,
                                    meta.session_id,
                                    SyncRoundOutcome::Error,
                                    &detail,
                                    session_start.elapsed().as_millis() as i64,
                                ) {
                                    warn!("failed to author initiator timeout round: {}", err);
                                }
                                Err(detail)
                            }
                        }
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
                    _ = cancel.cancelled() => {
                        let detail = format!("session {} cancelled", meta.session_id);
                        if let Err(err) = record_interrupted_sync_round(
                            &self.db_path,
                            self.direction,
                            &tenant_id,
                            meta.session_id,
                            SyncRoundOutcome::Cancelled,
                            &detail,
                            session_start.elapsed().as_millis() as i64,
                        ) {
                            warn!("failed to author interrupted responder round: {}", err);
                        }
                        Err(detail)
                    }
                    result = tokio::time::timeout(session_timeout, &mut run) => {
                        match result {
                            Ok(result) => result
                                .map_err(|e| format!("responder sync failed: {e}")),
                            Err(_) => {
                                let detail = format!(
                                    "responder sync timed out after {}s",
                                    session_timeout.as_secs()
                                );
                                if let Err(err) = record_interrupted_sync_round(
                                    &self.db_path,
                                    self.direction,
                                    &tenant_id,
                                    meta.session_id,
                                    SyncRoundOutcome::Error,
                                    &detail,
                                    session_start.elapsed().as_millis() as i64,
                                ) {
                                    warn!("failed to author responder timeout round: {}", err);
                                }
                                Err(detail)
                            }
                        }
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
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_connection, schema::create_tables};
    use crate::event_modules::operational::connection_plan_transitioned::create_connection_plan_transitioned;
    use crate::event_modules::operational::connection_planned::{
        create_connection_planned, discovery_connection_id, ConnectionPlanSourceKind,
        ConnectionPlanStatus,
    };
    use crate::event_modules::operational::outbound_connection_authenticated::create_outbound_connection_authenticated;
    use crate::event_modules::operational::sync_round_started::{
        create_sync_round_started, SyncRoundRole,
    };

    fn setup_started_outbound_round() -> (tempfile::TempDir, String, String, u64) {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("test.db");
        let db_path = db_path.to_string_lossy().to_string();
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO invites_accepted
             (recorded_by, event_id, tenant_event_id, invite_event_id, workspace_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                "tenant-a",
                "ia-tenant-a",
                "tenant-tenant-a",
                "invite-tenant-a",
                "ws-tenant-a",
                0_i64
            ],
        )
        .unwrap();

        let peer_id = hex::encode([0xABu8; 32]);
        let remote_addr: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let planned = create_connection_planned(
            &conn,
            "tenant-a",
            &peer_id,
            remote_addr,
            ConnectionPlanSourceKind::Discovery,
            None,
        )
        .unwrap()
        .unwrap();
        let connection_id = discovery_connection_id("tenant-a", &peer_id);
        let active = create_connection_plan_transitioned(
            &conn,
            "tenant-a",
            planned,
            &connection_id,
            ConnectionPlanStatus::Active,
            Some("test_setup"),
            0,
        )
        .unwrap();
        let basis = create_outbound_connection_authenticated(
            &conn,
            "tenant-a",
            active,
            &connection_id,
            &peer_id,
            remote_addr,
            false,
        )
        .unwrap();
        let session_id = 77_u64;
        create_sync_round_started(
            &conn,
            "tenant-a",
            basis,
            &connection_id,
            "tenant-a",
            &peer_id,
            session_id,
            SyncRoundRole::Initiator,
            "last_day",
            Some(100),
            Some(200),
            Some(0),
            Some(1234),
        )
        .unwrap();
        (tmpdir, db_path, "tenant-a".to_string(), session_id)
    }

    #[test]
    fn interrupted_round_completion_writes_terminal_error_row() {
        let (_tmpdir, db_path, tenant_id, session_id) = setup_started_outbound_round();

        record_interrupted_sync_round(
            &db_path,
            SessionDirection::Outbound,
            &tenant_id,
            session_id,
            SyncRoundOutcome::Error,
            "session timed out",
            250,
        )
        .unwrap();

        let conn = open_connection(&db_path).unwrap();
        let outcome: String = conn
            .query_row(
                "SELECT outcome
                 FROM sync_round_history
                 WHERE recorded_by = ?1 AND session_id = ?2 AND lifecycle_kind = 'completed'
                 ORDER BY created_at DESC, event_id DESC
                 LIMIT 1",
                rusqlite::params![tenant_id, session_id as i64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(outcome, "error");
    }

    #[test]
    fn interrupted_round_completion_is_noop_without_started_round() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("test.db");
        let db_path = db_path.to_string_lossy().to_string();
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        record_interrupted_sync_round(
            &db_path,
            SessionDirection::Outbound,
            "tenant-a",
            99,
            SyncRoundOutcome::Cancelled,
            "session cancelled",
            10,
        )
        .unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM sync_round_history", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 0);
    }
}
