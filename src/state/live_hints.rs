use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

use rusqlite::Connection;
use tokio::sync::broadcast;

use crate::crypto::EventId;

const LIVE_HINT_CHANNEL_CAPACITY: usize = 4096;

// ---------------------------------------------------------------------------
// Runtime toggle
// ---------------------------------------------------------------------------

static FORWARD_ON_HAVE: AtomicBool = AtomicBool::new(false);

/// Returns true when forward-on-have hint delivery is active.
pub fn forward_on_have_enabled() -> bool {
    FORWARD_ON_HAVE.load(Ordering::Relaxed)
}

/// Toggle forward-on-have at runtime (called from RPC dispatch).
pub fn set_forward_on_have(enabled: bool) {
    FORWARD_ON_HAVE.store(enabled, Ordering::Relaxed);
}

/// One-time initialization from `TOPO_FORWARD_ON_HAVE` env var.
pub fn init_forward_on_have_from_env() {
    let enabled = std::env::var("TOPO_FORWARD_ON_HAVE")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false);
    set_forward_on_have(enabled);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveHint {
    pub event_id: EventId,
    pub source_peer_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveHintEvent {
    pub tenant_id: String,
    pub event_id: EventId,
    pub source_peer_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LiveHintKey {
    db_path: String,
    tenant_id: String,
}

fn registry() -> &'static Mutex<HashMap<LiveHintKey, broadcast::Sender<LiveHint>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<LiveHintKey, broadcast::Sender<LiveHint>>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn sender_for(db_path: &str, tenant_id: &str) -> broadcast::Sender<LiveHint> {
    let key = LiveHintKey {
        db_path: db_path.to_string(),
        tenant_id: tenant_id.to_string(),
    };
    let mut registry = registry()
        .lock()
        .expect("live hint registry mutex poisoned");
    registry
        .entry(key)
        .or_insert_with(|| {
            let (tx, _rx) = broadcast::channel(LIVE_HINT_CHANNEL_CAPACITY);
            tx
        })
        .clone()
}

pub fn subscribe(db_path: &str, tenant_id: &str) -> broadcast::Receiver<LiveHint> {
    sender_for(db_path, tenant_id).subscribe()
}

pub fn publish_many(db_path: &str, events: &[LiveHintEvent]) {
    if !forward_on_have_enabled() || events.is_empty() {
        return;
    }
    for event in events {
        let _ = sender_for(db_path, &event.tenant_id).send(LiveHint {
            event_id: event.event_id,
            source_peer_id: event.source_peer_id.clone(),
        });
    }
}

pub fn publish_from_connection(conn: &Connection, events: &[LiveHintEvent]) {
    if !forward_on_have_enabled() || events.is_empty() {
        return;
    }
    let Some(db_path) = database_path_key(conn).ok().flatten() else {
        return;
    };
    publish_many(&db_path, events);
}

pub fn database_path_key(conn: &Connection) -> rusqlite::Result<Option<String>> {
    let mut stmt = conn.prepare("PRAGMA database_list")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name != "main" {
            continue;
        }
        let path: String = row.get(2)?;
        if path.is_empty() {
            return Ok(None);
        }
        return Ok(Some(path));
    }
    Ok(None)
}

pub fn source_peer_id_from_source_tag(source_tag: &str) -> Option<String> {
    let tail = source_tag.strip_prefix("quic_recv:")?;
    let (peer_id, _) = tail.split_once('@')?;
    if peer_id.is_empty() {
        return None;
    }
    Some(peer_id.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn source_peer_id_is_parsed_from_quic_source_tags() {
        assert_eq!(
            source_peer_id_from_source_tag("quic_recv:peer-a@127.0.0.1"),
            Some("peer-a".to_string())
        );
        assert_eq!(source_peer_id_from_source_tag("local_create"), None);
        assert_eq!(
            source_peer_id_from_source_tag("same_workspace_fanout:peer-a"),
            None
        );
    }

    #[test]
    fn toggle_forward_on_have_at_runtime() {
        let _guard = test_lock().lock().expect("test lock poisoned");
        set_forward_on_have(false);
        assert!(!forward_on_have_enabled());
        set_forward_on_have(true);
        assert!(forward_on_have_enabled());
        set_forward_on_have(false);
        assert!(!forward_on_have_enabled());
    }

    #[test]
    fn publish_many_reaches_subscribers_for_matching_db_and_tenant() {
        let _guard = test_lock().lock().expect("test lock poisoned");
        let prior = forward_on_have_enabled();
        set_forward_on_have(true);
        let mut rx = subscribe("/tmp/live-hints-test.db", "tenant-a");
        let event_id = [7u8; 32];
        publish_many(
            "/tmp/live-hints-test.db",
            &[LiveHintEvent {
                tenant_id: "tenant-a".to_string(),
                event_id,
                source_peer_id: Some("peer-z".to_string()),
            }],
        );

        let hint = rx.try_recv().expect("live hint should be delivered");
        assert_eq!(
            hint,
            LiveHint {
                event_id,
                source_peer_id: Some("peer-z".to_string()),
            }
        );
        set_forward_on_have(prior);
    }
}
