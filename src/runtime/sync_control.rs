//! Sync control runtime: registry, session commands, and capture types.

use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

/// Result of a manually-triggered negentropy round.
#[derive(Debug, Clone, Serialize)]
pub struct ManualSyncRoundCapture {
    pub peer_id: String,
    pub observed_ids: Vec<String>,
}

// ---------------------------------------------------------------------------
// Session commands (sent from registry to session loops)
// ---------------------------------------------------------------------------

pub enum SessionCommand {
    ForceRound {
        reply: std::sync::mpsc::Sender<Result<ManualSyncRoundCapture, String>>,
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
    sessions: Mutex<HashMap<u64, SessionEntry>>,
    next_id: Mutex<u64>,
}

struct FrontierAdvanceSlot {
    version: Arc<AtomicU64>,
    notify: Arc<Notify>,
}

#[derive(Clone)]
pub struct FrontierAdvanceSubscription {
    version: Arc<AtomicU64>,
    notify: Arc<Notify>,
    observed_version: u64,
}

impl FrontierAdvanceSubscription {
    pub fn take_changed(&mut self) -> bool {
        let current = self.version.load(Ordering::Acquire);
        if current == self.observed_version {
            return false;
        }
        self.observed_version = current;
        true
    }

    pub fn notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.notify.notified()
    }
}

fn frontier_key(db_path: &str, tenant_id: &str) -> String {
    format!("{db_path}|{tenant_id}")
}

fn frontier_advance_slots() -> &'static Mutex<HashMap<String, FrontierAdvanceSlot>> {
    static SLOTS: std::sync::OnceLock<Mutex<HashMap<String, FrontierAdvanceSlot>>> =
        std::sync::OnceLock::new();
    SLOTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn frontier_advance_slot(db_path: &str, tenant_id: &str) -> (Arc<AtomicU64>, Arc<Notify>) {
    let key = frontier_key(db_path, tenant_id);
    let mut slots = frontier_advance_slots()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let slot = slots.entry(key).or_insert_with(|| FrontierAdvanceSlot {
        version: Arc::new(AtomicU64::new(0)),
        notify: Arc::new(Notify::new()),
    });
    (slot.version.clone(), slot.notify.clone())
}

pub fn frontier_advance_subscription(
    db_path: &str,
    tenant_id: &str,
) -> FrontierAdvanceSubscription {
    let (version, notify) = frontier_advance_slot(db_path, tenant_id);
    FrontierAdvanceSubscription {
        observed_version: version.load(Ordering::Acquire),
        version,
        notify,
    }
}

pub fn note_frontier_advanced(db_path: &str, tenant_id: &str) {
    let (version, notify) = frontier_advance_slot(db_path, tenant_id);
    version.fetch_add(1, Ordering::AcqRel);
    notify.notify_waiters();
}

impl SyncControlRegistry {
    pub fn new() -> Self {
        SyncControlRegistry {
            sessions: Mutex::new(HashMap::new()),
            next_id: Mutex::new(1),
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

        let guard = SessionRegistrationGuard {
            registry: Arc::clone(self),
            session_id,
            tenant_id: tenant_id.to_string(),
        };

        RegisteredSession {
            command_rx,
            _guard: SessionGuard(guard),
        }
    }

    // -- Trigger helpers --

    pub fn trigger_round_for_peer(
        &self,
        tenant_id: &str,
        peer_prefix: &str,
    ) -> Result<ManualSyncRoundCapture, String> {
        let sessions = self.find_sessions(tenant_id, Some(peer_prefix), false);
        if sessions.is_empty() {
            return Err(format!(
                "no live session matches peer prefix '{}'",
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
        let sessions = self.find_sessions(tenant_id, None, false);
        if sessions.is_empty() {
            return Err("no live sessions".to_string());
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
        if results.is_empty() {
            Err("timeout waiting for round reply (30s)".to_string())
        } else {
            Ok(results)
        }
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
        let _ = tenant_id;
        let mut sessions = self.sessions.lock().unwrap();
        sessions.remove(&session_id);
    }
}

// ---------------------------------------------------------------------------
// Registered session handle (returned to session loops)
// ---------------------------------------------------------------------------

pub struct RegisteredSession {
    pub command_rx: tokio::sync::mpsc::Receiver<SessionCommand>,
    pub _guard: SessionGuard,
}

impl RegisteredSession {
    pub fn into_parts(self) -> (tokio::sync::mpsc::Receiver<SessionCommand>, SessionGuard) {
        (self.command_rx, self._guard)
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

    #[tokio::test]
    async fn registry_session_deregisters_on_drop() {
        let registry = Arc::new(SyncControlRegistry::new());

        {
            let _session =
                registry.register_session("tenant1", "abcd1234peer", SessionRole::Initiator);
            // While session is alive, trigger with wrong prefix should fail with "no live"
            let result = registry.trigger_round_for_peer("tenant1", "zzzz");
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("no live session"));
        }
        // After drop, trigger should also fail with "no live"
        let result = registry.trigger_round_for_peer("tenant1", "abcd");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no live session"));
    }

    #[test]
    fn frontier_advance_subscription_detects_new_work() {
        let mut subscription = frontier_advance_subscription("db-a", "tenant-a");
        assert!(!subscription.take_changed());

        note_frontier_advanced("db-a", "tenant-a");
        assert!(subscription.take_changed());
        assert!(!subscription.take_changed());
    }
}
