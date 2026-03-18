use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::watch;

use crate::db::open_connection;
use crate::db::{schema::create_tables, sync_control as sync_control_db};
use crate::protocol::Frame;
use crate::shared::sync_control::{SyncPolicyMode, TenantSyncPolicy};
use crate::sync::session::logging::{capture_frame_for_manual_action, LogDir, LogLane};

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[derive(Debug, Clone, Serialize)]
pub struct ManualFrameEvent {
    pub seq: u64,
    pub ts_ms: i64,
    pub lane: String,
    pub direction: String,
    pub frame_type: String,
    pub msg_len: usize,
    pub detail_json: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManualSyncRoundCapture {
    pub tenant_id: String,
    pub peer_id: String,
    pub role: String,
    pub session_id: u64,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub events: Vec<ManualFrameEvent>,
    pub newly_observed_ids: Vec<String>,
    pub already_known_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ManualSyncRequestResult {
    pub tenant_id: String,
    pub peer_id: String,
    pub role: String,
    pub requested_ids: Vec<String>,
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Session command channel: CLI → live session loop
// ---------------------------------------------------------------------------

/// Commands that the CLI can send into a live sync session loop via the
/// registry's command channel.
pub enum SessionCommand {
    /// Force an immediate negentropy reconciliation round (initiator only).
    /// The std::sync reply channel carries the result back to the blocking
    /// RPC thread.
    ForceRound {
        reply: std::sync::mpsc::Sender<Result<ManualSyncRoundCapture, String>>,
    },
    /// Force immediate request issuance from wanted state.
    ForceRequest {
        reply: std::sync::mpsc::Sender<Result<ManualSyncRequestResult, String>>,
    },
}

// ---------------------------------------------------------------------------
// ActionCaptureHub — frame-level capture for manual actions
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct ActionCaptureHub {
    inner: Arc<Mutex<Option<ActiveCapture>>>,
}

#[derive(Debug)]
struct ActiveCapture {
    started_at_ms: i64,
    next_seq: u64,
    events: Vec<ManualFrameEvent>,
}

impl ActionCaptureHub {
    pub fn begin_capture(&self) {
        let mut guard = self.inner.lock().expect("action capture mutex poisoned");
        *guard = Some(ActiveCapture {
            started_at_ms: now_ms(),
            next_seq: 1,
            events: Vec::new(),
        });
    }

    pub fn finish_capture(&self) -> Option<(i64, i64, Vec<ManualFrameEvent>)> {
        let mut guard = self.inner.lock().expect("action capture mutex poisoned");
        let capture = guard.take()?;
        Some((capture.started_at_ms, now_ms(), capture.events))
    }

    pub fn record_frame(&self, lane: LogLane, dir: LogDir, frame: &Frame, msg_len: usize) {
        let mut guard = self.inner.lock().expect("action capture mutex poisoned");
        let Some(capture) = guard.as_mut() else {
            return;
        };
        let (frame_type, detail_json) = capture_frame_for_manual_action(frame, true);
        capture.events.push(ManualFrameEvent {
            seq: capture.next_seq,
            ts_ms: now_ms(),
            lane: lane.as_str().to_string(),
            direction: dir.as_str().to_string(),
            frame_type,
            msg_len,
            detail_json,
        });
        capture.next_seq = capture.next_seq.saturating_add(1);
    }
}

// ---------------------------------------------------------------------------
// Registry internals
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct RegisteredSessionEntry {
    registration_id: u64,
    role: String,
    peer_id: String,
    tenant_id: String,
    command_tx: tokio::sync::mpsc::Sender<SessionCommand>,
}

#[derive(Default)]
struct RegistryState {
    policy_cache: HashMap<String, TenantSyncPolicy>,
    policy_watch: HashMap<String, watch::Sender<TenantSyncPolicy>>,
    sessions: HashMap<(String, String), RegisteredSessionEntry>,
}

pub struct SyncControlRegistry {
    db_path: String,
    state: Mutex<RegistryState>,
    next_registration_id: AtomicU64,
}

/// Timeout for blocking on a session command reply from the RPC thread.
const COMMAND_REPLY_TIMEOUT: Duration = Duration::from_secs(30);

impl SyncControlRegistry {
    pub fn new(db_path: String) -> Self {
        Self {
            db_path,
            state: Mutex::new(RegistryState::default()),
            next_registration_id: AtomicU64::new(1),
        }
    }

    pub fn load_policy(&self, tenant_id: &str) -> Result<TenantSyncPolicy, String> {
        {
            let state = self.state.lock().expect("sync control registry poisoned");
            if let Some(policy) = state.policy_cache.get(tenant_id).copied() {
                return Ok(policy);
            }
        }

        let conn = open_connection(&self.db_path).map_err(|e| e.to_string())?;
        create_tables(&conn).map_err(|e| e.to_string())?;
        sync_control_db::ensure_schema(&conn).map_err(|e| e.to_string())?;
        let policy = sync_control_db::load_policy(&conn, tenant_id).map_err(|e| e.to_string())?;

        let mut state = self.state.lock().expect("sync control registry poisoned");
        state.policy_cache.insert(tenant_id.to_string(), policy);
        state
            .policy_watch
            .entry(tenant_id.to_string())
            .or_insert_with(|| {
                let (tx, _rx) = watch::channel(policy);
                tx
            });
        Ok(policy)
    }

    pub fn save_policy(
        &self,
        tenant_id: &str,
        policy: TenantSyncPolicy,
    ) -> Result<TenantSyncPolicy, String> {
        let conn = open_connection(&self.db_path).map_err(|e| e.to_string())?;
        create_tables(&conn).map_err(|e| e.to_string())?;
        sync_control_db::ensure_schema(&conn).map_err(|e| e.to_string())?;
        let saved =
            sync_control_db::save_policy(&conn, tenant_id, policy).map_err(|e| e.to_string())?;

        let mut state = self.state.lock().expect("sync control registry poisoned");
        state.policy_cache.insert(tenant_id.to_string(), saved);
        match state.policy_watch.get(tenant_id) {
            Some(tx) => {
                let _ = tx.send(saved);
            }
            None => {
                let (tx, _rx) = watch::channel(saved);
                state.policy_watch.insert(tenant_id.to_string(), tx);
            }
        }
        Ok(saved)
    }

    pub fn update_policy(
        &self,
        tenant_id: &str,
        requests: Option<SyncPolicyMode>,
        responses: Option<SyncPolicyMode>,
        forward_on_have: Option<SyncPolicyMode>,
    ) -> Result<TenantSyncPolicy, String> {
        let conn = open_connection(&self.db_path).map_err(|e| e.to_string())?;
        create_tables(&conn).map_err(|e| e.to_string())?;
        sync_control_db::ensure_schema(&conn).map_err(|e| e.to_string())?;
        let saved = sync_control_db::update_policy(
            &conn,
            tenant_id,
            requests,
            responses,
            forward_on_have,
        )
        .map_err(|e| e.to_string())?;
        let mut state = self.state.lock().expect("sync control registry poisoned");
        state.policy_cache.insert(tenant_id.to_string(), saved);
        match state.policy_watch.get(tenant_id) {
            Some(tx) => {
                let _ = tx.send(saved);
            }
            None => {
                let (tx, _rx) = watch::channel(saved);
                state.policy_watch.insert(tenant_id.to_string(), tx);
            }
        }
        Ok(saved)
    }

    pub fn register_session(
        self: &Arc<Self>,
        tenant_id: String,
        peer_id: String,
        role: String,
    ) -> Result<RegisteredSession, String> {
        let policy = self.load_policy(&tenant_id)?;
        let registration_id = self.next_registration_id.fetch_add(1, Ordering::Relaxed);
        let (command_tx, command_rx) = tokio::sync::mpsc::channel(4);
        let policy_rx = {
            let mut state = self.state.lock().expect("sync control registry poisoned");
            let tx = state
                .policy_watch
                .entry(tenant_id.clone())
                .or_insert_with(|| {
                    let (tx, _rx) = watch::channel(policy);
                    tx
                })
                .clone();
            state.sessions.insert(
                (tenant_id.clone(), peer_id.clone()),
                RegisteredSessionEntry {
                    registration_id,
                    role: role.clone(),
                    peer_id: peer_id.clone(),
                    tenant_id: tenant_id.clone(),
                    command_tx,
                },
            );
            tx.subscribe()
        };
        Ok(RegisteredSession {
            command_rx,
            policy_rx,
            _guard: SessionRegistrationGuard {
                registry: Arc::downgrade(self),
                registration_id,
                tenant_id,
                peer_id,
            },
        })
    }

    // -----------------------------------------------------------------------
    // CLI trigger methods — send commands into live session loops
    // -----------------------------------------------------------------------

    /// Force a manual negentropy round on a specific initiator session.
    /// Blocks the calling thread until the round completes or times out.
    pub fn trigger_round_for_peer(
        &self,
        tenant_id: &str,
        peer_prefix: &str,
    ) -> Result<ManualSyncRoundCapture, String> {
        let entry = self.select_session(tenant_id, peer_prefix, true)?;
        let (tx, rx) = std::sync::mpsc::channel();
        entry
            .command_tx
            .try_send(SessionCommand::ForceRound { reply: tx })
            .map_err(|_| "session is busy processing a prior command".to_string())?;
        rx.recv_timeout(COMMAND_REPLY_TIMEOUT)
            .map_err(|_| "timeout waiting for round to complete".to_string())?
    }

    pub fn trigger_round_for_all(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ManualSyncRoundCapture>, String> {
        let sessions = self.select_all_sessions(tenant_id, true)?;
        let mut out = Vec::with_capacity(sessions.len());
        for entry in sessions {
            let (tx, rx) = std::sync::mpsc::channel();
            if entry
                .command_tx
                .try_send(SessionCommand::ForceRound { reply: tx })
                .is_err()
            {
                continue; // session busy, skip
            }
            match rx.recv_timeout(COMMAND_REPLY_TIMEOUT) {
                Ok(Ok(capture)) => out.push(capture),
                Ok(Err(e)) => return Err(e),
                Err(_) => continue, // timeout, skip
            }
        }
        if out.is_empty() {
            return Err(format!("no initiator sessions completed a round for tenant {}", tenant_id));
        }
        Ok(out)
    }

    /// Force immediate request issuance on a specific session.
    pub fn trigger_request_for_peer(
        &self,
        tenant_id: &str,
        peer_prefix: &str,
    ) -> Result<ManualSyncRequestResult, String> {
        let entry = self.select_session(tenant_id, peer_prefix, false)?;

        let policy = self.load_policy(&entry.tenant_id)?;
        if policy.requests == SyncPolicyMode::Disabled {
            return Ok(ManualSyncRequestResult {
                tenant_id: entry.tenant_id.clone(),
                peer_id: entry.peer_id.clone(),
                role: entry.role.clone(),
                requested_ids: Vec::new(),
                reason: Some("requests are disabled for this tenant".to_string()),
            });
        }

        let (tx, rx) = std::sync::mpsc::channel();
        entry
            .command_tx
            .try_send(SessionCommand::ForceRequest { reply: tx })
            .map_err(|_| "session is busy processing a prior command".to_string())?;
        rx.recv_timeout(COMMAND_REPLY_TIMEOUT)
            .map_err(|_| "timeout waiting for request to complete".to_string())?
    }

    pub fn trigger_request_for_all(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ManualSyncRequestResult>, String> {
        let sessions = self.select_all_sessions(tenant_id, false)?;
        let policy = self.load_policy(tenant_id)?;

        let mut out = Vec::with_capacity(sessions.len());
        for entry in sessions {
            if policy.requests == SyncPolicyMode::Disabled {
                out.push(ManualSyncRequestResult {
                    tenant_id: entry.tenant_id.clone(),
                    peer_id: entry.peer_id.clone(),
                    role: entry.role.clone(),
                    requested_ids: Vec::new(),
                    reason: Some("requests are disabled for this tenant".to_string()),
                });
                continue;
            }
            let (tx, rx) = std::sync::mpsc::channel();
            if entry
                .command_tx
                .try_send(SessionCommand::ForceRequest { reply: tx })
                .is_err()
            {
                continue; // session busy
            }
            match rx.recv_timeout(COMMAND_REPLY_TIMEOUT) {
                Ok(Ok(result)) => out.push(result),
                Ok(Err(e)) => return Err(e),
                Err(_) => continue, // timeout
            }
        }
        if out.is_empty() {
            return Err(format!("no sessions completed a request for tenant {}", tenant_id));
        }
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Session selection helpers
    // -----------------------------------------------------------------------

    fn select_session(
        &self,
        tenant_id: &str,
        peer_prefix: &str,
        initiator_only: bool,
    ) -> Result<RegisteredSessionEntry, String> {
        let sessions = self.select_matching_sessions(tenant_id, Some(peer_prefix), initiator_only)?;
        if sessions.is_empty() {
            return Err(format!(
                "no live {}session matches peer '{}'",
                if initiator_only { "initiator " } else { "" },
                peer_prefix
            ));
        }
        if sessions.len() > 1 {
            return Err(format!(
                "peer selector '{}' is ambiguous across {} live session(s)",
                peer_prefix,
                sessions.len()
            ));
        }
        Ok(sessions.into_iter().next().expect("non-empty session selection"))
    }

    fn select_all_sessions(
        &self,
        tenant_id: &str,
        initiator_only: bool,
    ) -> Result<Vec<RegisteredSessionEntry>, String> {
        let sessions = self.select_matching_sessions(tenant_id, None, initiator_only)?;
        if sessions.is_empty() {
            return Err(format!(
                "no live {}sessions for tenant {}",
                if initiator_only { "initiator " } else { "" },
                tenant_id
            ));
        }
        Ok(sessions)
    }

    fn select_matching_sessions(
        &self,
        tenant_id: &str,
        peer_prefix: Option<&str>,
        initiator_only: bool,
    ) -> Result<Vec<RegisteredSessionEntry>, String> {
        let state = self.state.lock().expect("sync control registry poisoned");
        let mut matches = Vec::new();
        for ((session_tenant, session_peer), entry) in &state.sessions {
            if session_tenant != tenant_id {
                continue;
            }
            if initiator_only && entry.role != "initiator" {
                continue;
            }
            if let Some(prefix) = peer_prefix {
                if !session_peer.starts_with(prefix) {
                    continue;
                }
            }
            matches.push(entry.clone());
        }
        Ok(matches)
    }

    fn deregister_session(&self, tenant_id: &str, peer_id: &str, registration_id: u64) {
        let mut state = self.state.lock().expect("sync control registry poisoned");
        if let Some(entry) = state
            .sessions
            .get(&(tenant_id.to_string(), peer_id.to_string()))
            .cloned()
        {
            if entry.registration_id == registration_id {
                state
                    .sessions
                    .remove(&(tenant_id.to_string(), peer_id.to_string()));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RegisteredSession — returned to session handler, holds channels + RAII guard
// ---------------------------------------------------------------------------

pub struct RegisteredSession {
    pub command_rx: tokio::sync::mpsc::Receiver<SessionCommand>,
    pub policy_rx: watch::Receiver<TenantSyncPolicy>,
    _guard: SessionRegistrationGuard,
}

/// Opaque handle that keeps a session registered in the `SyncControlRegistry`.
/// The session is deregistered when this handle is dropped.
pub struct SessionGuard {
    _inner: SessionRegistrationGuard,
}

impl RegisteredSession {
    /// Decompose into channels + an opaque guard. The guard must be held alive
    /// for the duration of the session to keep it registered.
    pub fn into_parts(
        self,
    ) -> (
        tokio::sync::mpsc::Receiver<SessionCommand>,
        watch::Receiver<TenantSyncPolicy>,
        SessionGuard,
    ) {
        (
            self.command_rx,
            self.policy_rx,
            SessionGuard {
                _inner: self._guard,
            },
        )
    }
}

struct SessionRegistrationGuard {
    registry: Weak<SyncControlRegistry>,
    registration_id: u64,
    tenant_id: String,
    peer_id: String,
}

impl Drop for SessionRegistrationGuard {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.deregister_session(&self.tenant_id, &self.peer_id, self.registration_id);
        }
    }
}
