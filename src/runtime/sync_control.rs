//! Sync control runtime: registry, session commands, and capture types.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::shared::sync_control::{SyncPolicyMode, TenantSyncPolicy};

// ---------------------------------------------------------------------------
// Capture types (returned to CLI callers)
// ---------------------------------------------------------------------------

/// A single frame event observed during a manual sync operation.
#[derive(Debug, Clone, Serialize)]
pub struct ManualFrameEvent {
    pub direction: String,
    pub frame_type: String,
    pub size_bytes: usize,
}

/// Result of a manually-triggered negentropy round.
#[derive(Debug, Clone, Serialize)]
pub struct ManualSyncRoundCapture {
    pub peer_id: String,
    pub observed_ids: Vec<String>,
}

/// Result of a manually-triggered request refill.
#[derive(Debug, Clone, Serialize)]
pub struct ManualSyncRequestResult {
    pub peer_id: String,
    pub requested_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

// ---------------------------------------------------------------------------
// Session commands (sent from registry to session loops)
// ---------------------------------------------------------------------------

pub enum SessionCommand {
    ForceRound {
        reply: std::sync::mpsc::Sender<Result<ManualSyncRoundCapture, String>>,
    },
    ForceRequest {
        reply: std::sync::mpsc::Sender<Result<ManualSyncRequestResult, String>>,
    },
}

// ---------------------------------------------------------------------------
// Session entry (one per active session)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionRole {
    Initiator,
    Responder,
}

#[derive(Clone, Debug)]
struct SessionEntry {
    tenant_id: String,
    peer_id: String,
    role: SessionRole,
    command_tx: tokio::sync::mpsc::Sender<SessionCommand>,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

pub struct SyncControlRegistry {
    db_path: String,
    sessions: Mutex<HashMap<u64, SessionEntry>>,
    next_id: Mutex<u64>,
    policy_watchers: Mutex<HashMap<String, Vec<tokio::sync::watch::Sender<TenantSyncPolicy>>>>,
}

impl SyncControlRegistry {
    pub fn new(db_path: String) -> Self {
        SyncControlRegistry {
            db_path,
            sessions: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
            policy_watchers: Mutex::new(HashMap::new()),
        }
    }

    // -- Policy delegation --

    pub fn load_policy(&self, tenant_id: &str) -> Result<TenantSyncPolicy, String> {
        let conn = crate::db::open_connection(&self.db_path).map_err(|e| e.to_string())?;
        crate::db::sync_control::ensure_schema(&conn).map_err(|e| e.to_string())?;
        crate::db::sync_control::load_policy(&conn, tenant_id).map_err(|e| e.to_string())
    }

    pub fn save_policy(
        &self,
        tenant_id: &str,
        policy: &TenantSyncPolicy,
    ) -> Result<TenantSyncPolicy, String> {
        let conn = crate::db::open_connection(&self.db_path).map_err(|e| e.to_string())?;
        crate::db::sync_control::ensure_schema(&conn).map_err(|e| e.to_string())?;
        let saved = crate::db::sync_control::save_policy(&conn, tenant_id, policy)
            .map_err(|e| e.to_string())?;
        self.notify_policy_watchers(tenant_id, &saved);
        Ok(saved)
    }

    pub fn update_policy(
        &self,
        tenant_id: &str,
        requests: Option<SyncPolicyMode>,
        responses: Option<SyncPolicyMode>,
        forward_on_have: Option<SyncPolicyMode>,
    ) -> Result<TenantSyncPolicy, String> {
        let conn = crate::db::open_connection(&self.db_path).map_err(|e| e.to_string())?;
        crate::db::sync_control::ensure_schema(&conn).map_err(|e| e.to_string())?;
        let updated = crate::db::sync_control::update_policy(
            &conn,
            tenant_id,
            requests,
            responses,
            forward_on_have,
        )
        .map_err(|e| e.to_string())?;
        self.notify_policy_watchers(tenant_id, &updated);
        Ok(updated)
    }

    fn notify_policy_watchers(&self, tenant_id: &str, policy: &TenantSyncPolicy) {
        let watchers = self.policy_watchers.lock().unwrap();
        if let Some(senders) = watchers.get(tenant_id) {
            for tx in senders {
                let _ = tx.send(*policy);
            }
        }
    }

    // -- Session registration --

    pub fn register_session(
        self: &Arc<Self>,
        tenant_id: &str,
        peer_id: &str,
        role: SessionRole,
    ) -> RegisteredSession {
        let (command_tx, command_rx) = tokio::sync::mpsc::channel::<SessionCommand>(4);
        let initial_policy = self.load_policy(tenant_id).unwrap_or_default();
        let (policy_tx, policy_rx) = tokio::sync::watch::channel(initial_policy);

        let session_id = {
            let mut next = self.next_id.lock().unwrap();
            let id = *next;
            *next += 1;
            id
        };

        let entry = SessionEntry {
            tenant_id: tenant_id.to_string(),
            peer_id: peer_id.to_string(),
            role,
            command_tx,
        };

        {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.insert(session_id, entry);
        }
        {
            let mut watchers = self.policy_watchers.lock().unwrap();
            watchers
                .entry(tenant_id.to_string())
                .or_default()
                .push(policy_tx);
        }

        let guard = SessionRegistrationGuard {
            registry: Arc::clone(self),
            session_id,
            tenant_id: tenant_id.to_string(),
        };

        RegisteredSession {
            command_rx,
            policy_rx,
            _guard: SessionGuard(guard),
        }
    }

    // -- Trigger helpers --

    pub fn trigger_round_for_peer(
        &self,
        tenant_id: &str,
        peer_prefix: &str,
    ) -> Result<ManualSyncRoundCapture, String> {
        let sessions = self.find_sessions(tenant_id, Some(peer_prefix), true);
        if sessions.is_empty() {
            return Err(format!(
                "no live initiator session matches peer prefix '{}'",
                peer_prefix
            ));
        }
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        for entry in &sessions {
            let _ = entry.command_tx.try_send(SessionCommand::ForceRound {
                reply: reply_tx.clone(),
            });
        }
        drop(reply_tx);
        match reply_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(result) => result,
            Err(_) => Err("timeout waiting for round reply (30s)".to_string()),
        }
    }

    pub fn trigger_round_for_all(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ManualSyncRoundCapture>, String> {
        let sessions = self.find_sessions(tenant_id, None, true);
        if sessions.is_empty() {
            return Err("no live initiator sessions".to_string());
        }
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        for entry in &sessions {
            let _ = entry.command_tx.try_send(SessionCommand::ForceRound {
                reply: reply_tx.clone(),
            });
        }
        drop(reply_tx);
        let mut results = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match reply_rx.recv_timeout(remaining) {
                Ok(Ok(capture)) => results.push(capture),
                Ok(Err(_)) => {}
                Err(_) => break,
            }
        }
        Ok(results)
    }

    pub fn trigger_request_for_peer(
        &self,
        tenant_id: &str,
        peer_prefix: &str,
    ) -> Result<ManualSyncRequestResult, String> {
        // Check policy first
        let policy = self.load_policy(tenant_id).unwrap_or_default();
        if policy.requests == SyncPolicyMode::Disabled {
            return Ok(ManualSyncRequestResult {
                peer_id: peer_prefix.to_string(),
                requested_ids: vec![],
                reason: Some("requests lane is disabled by policy".to_string()),
            });
        }

        let sessions = self.find_sessions(tenant_id, Some(peer_prefix), false);
        if sessions.is_empty() {
            return Err(format!(
                "no live session matches peer prefix '{}'",
                peer_prefix
            ));
        }
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        for entry in &sessions {
            let _ = entry.command_tx.try_send(SessionCommand::ForceRequest {
                reply: reply_tx.clone(),
            });
        }
        drop(reply_tx);
        match reply_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(result) => result,
            Err(_) => Err("timeout waiting for request reply (30s)".to_string()),
        }
    }

    pub fn trigger_request_for_all(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<ManualSyncRequestResult>, String> {
        let policy = self.load_policy(tenant_id).unwrap_or_default();
        let sessions = self.find_sessions(tenant_id, None, false);
        if policy.requests == SyncPolicyMode::Disabled {
            if sessions.is_empty() {
                return Ok(vec![ManualSyncRequestResult {
                    peer_id: "(no peers)".to_string(),
                    requested_ids: vec![],
                    reason: Some("requests are disabled for this tenant".to_string()),
                }]);
            }
            return Ok(sessions
                .iter()
                .map(|s| ManualSyncRequestResult {
                    peer_id: s.peer_id.clone(),
                    requested_ids: vec![],
                    reason: Some("requests are disabled for this tenant".to_string()),
                })
                .collect());
        }
        if sessions.is_empty() {
            return Err("no live sessions".to_string());
        }
        let (reply_tx, reply_rx) = std::sync::mpsc::channel();
        for entry in &sessions {
            let _ = entry.command_tx.try_send(SessionCommand::ForceRequest {
                reply: reply_tx.clone(),
            });
        }
        drop(reply_tx);
        let mut results = Vec::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                break;
            }
            match reply_rx.recv_timeout(remaining) {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(_)) => {}
                Err(_) => break,
            }
        }
        Ok(results)
    }

    // -- Internal helpers --

    fn find_sessions(
        &self,
        tenant_id: &str,
        peer_prefix: Option<&str>,
        initiator_only: bool,
    ) -> Vec<SessionEntry> {
        let sessions = self.sessions.lock().unwrap();
        sessions
            .values()
            .filter(|e| e.tenant_id == tenant_id)
            .filter(|e| {
                if initiator_only {
                    e.role == SessionRole::Initiator
                } else {
                    true
                }
            })
            .filter(|e| {
                if let Some(prefix) = peer_prefix {
                    e.peer_id.starts_with(prefix)
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }

    fn remove_session(&self, session_id: u64, tenant_id: &str) {
        {
            let mut sessions = self.sessions.lock().unwrap();
            sessions.remove(&session_id);
        }
        // Clean up policy watchers that have been dropped
        let mut watchers = self.policy_watchers.lock().unwrap();
        if let Some(senders) = watchers.get_mut(tenant_id) {
            senders.retain(|tx| !tx.is_closed());
            if senders.is_empty() {
                watchers.remove(tenant_id);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Registered session handle (returned to session loops)
// ---------------------------------------------------------------------------

pub struct RegisteredSession {
    pub command_rx: tokio::sync::mpsc::Receiver<SessionCommand>,
    pub policy_rx: tokio::sync::watch::Receiver<TenantSyncPolicy>,
    pub _guard: SessionGuard,
}

impl RegisteredSession {
    pub fn into_parts(
        self,
    ) -> (
        tokio::sync::mpsc::Receiver<SessionCommand>,
        tokio::sync::watch::Receiver<TenantSyncPolicy>,
        SessionGuard,
    ) {
        (self.command_rx, self.policy_rx, self._guard)
    }
}

/// Opaque guard that deregisters the session on drop.
#[allow(dead_code)]
pub struct SessionGuard(SessionRegistrationGuard);

struct SessionRegistrationGuard {
    registry: Arc<SyncControlRegistry>,
    session_id: u64,
    tenant_id: String,
}

impl Drop for SessionRegistrationGuard {
    fn drop(&mut self) {
        self.registry
            .remove_session(self.session_id, &self.tenant_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db_path() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db").to_string_lossy().to_string();
        // Ensure schema
        let conn = crate::db::open_connection(&path).unwrap();
        crate::db::sync_control::ensure_schema(&conn).unwrap();
        drop(conn);
        (dir, path)
    }

    #[test]
    fn registry_policy_roundtrip() {
        let (_dir, path) = temp_db_path();
        let registry = SyncControlRegistry::new(path);

        // Default
        let p = registry.load_policy("t1").unwrap();
        assert_eq!(p, TenantSyncPolicy::default());

        // Update
        let p2 = registry
            .update_policy("t1", Some(SyncPolicyMode::Manual), None, None)
            .unwrap();
        assert_eq!(p2.requests, SyncPolicyMode::Manual);
        assert_eq!(p2.responses, SyncPolicyMode::Auto);
    }

    #[tokio::test]
    async fn register_session_and_receive_command() {
        let (_dir, path) = temp_db_path();
        let registry = Arc::new(SyncControlRegistry::new(path));

        let mut session =
            registry.register_session("tenant1", "abcd1234peer", SessionRole::Initiator);

        // Spawn a thread to simulate session loop receiving the command
        let handle = std::thread::spawn(move || {
            // Use blocking recv on mpsc (tokio channel inside sync thread)
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                match session.command_rx.recv().await {
                    Some(SessionCommand::ForceRequest { reply }) => {
                        let _ = reply.send(Ok(ManualSyncRequestResult {
                            peer_id: "abcd1234peer".to_string(),
                            requested_ids: vec!["event1".to_string()],
                            reason: None,
                        }));
                    }
                    _ => panic!("expected ForceRequest"),
                }
            });
            session // return session to keep guard alive
        });

        // Small delay to let thread start
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Trigger from registry
        let result = registry
            .trigger_request_for_peer("tenant1", "abcd")
            .unwrap();
        assert_eq!(result.peer_id, "abcd1234peer");
        assert_eq!(result.requested_ids.len(), 1);

        let _session = handle.join().unwrap();
    }

    #[tokio::test]
    async fn registry_session_deregisters_on_drop() {
        let (_dir, path) = temp_db_path();
        let registry = Arc::new(SyncControlRegistry::new(path));

        {
            let _session =
                registry.register_session("tenant1", "abcd1234peer", SessionRole::Initiator);
            // While session is alive, trigger with wrong prefix should fail with "no live"
            let result = registry.trigger_round_for_peer("tenant1", "zzzz");
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("no live initiator session"));
        }
        // After drop, trigger should also fail with "no live"
        let result = registry.trigger_round_for_peer("tenant1", "abcd");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no live initiator session"));
    }
}
