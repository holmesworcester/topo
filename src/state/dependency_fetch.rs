use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tokio::sync::mpsc;

use crate::crypto::EventId;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DependencyKey {
    db_path: String,
    tenant_id: String,
    peer_id: String,
}

pub struct DependencyFetchGuard {
    key: DependencyKey,
}

fn registry() -> &'static Mutex<HashMap<DependencyKey, mpsc::UnboundedSender<Vec<EventId>>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<DependencyKey, mpsc::UnboundedSender<Vec<EventId>>>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn register(
    db_path: &str,
    tenant_id: &str,
    peer_id: &str,
) -> (mpsc::UnboundedReceiver<Vec<EventId>>, DependencyFetchGuard) {
    let key = DependencyKey {
        db_path: db_path.to_string(),
        tenant_id: tenant_id.to_string(),
        peer_id: peer_id.to_string(),
    };
    let (tx, rx) = mpsc::unbounded_channel();
    registry()
        .lock()
        .expect("dependency fetch registry poisoned")
        .insert(key.clone(), tx);
    (rx, DependencyFetchGuard { key })
}

pub fn publish(db_path: &str, tenant_id: &str, peer_id: &str, event_ids: &[EventId]) {
    if event_ids.is_empty() {
        return;
    }
    let key = DependencyKey {
        db_path: db_path.to_string(),
        tenant_id: tenant_id.to_string(),
        peer_id: peer_id.to_string(),
    };
    let sender = registry()
        .lock()
        .expect("dependency fetch registry poisoned")
        .get(&key)
        .cloned();
    if let Some(sender) = sender {
        let _ = sender.send(event_ids.to_vec());
    }
}

pub fn publish_from_connection(
    conn: &rusqlite::Connection,
    tenant_id: &str,
    peer_id: &str,
    event_ids: &[EventId],
) {
    let Some(db_path) = crate::state::live_hints::database_path_key(conn)
        .ok()
        .flatten()
    else {
        return;
    };
    publish(&db_path, tenant_id, peer_id, event_ids);
}

impl Drop for DependencyFetchGuard {
    fn drop(&mut self) {
        let mut registry = registry()
            .lock()
            .expect("dependency fetch registry poisoned");
        registry.remove(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publishes_to_matching_registered_peer() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("match.db").to_string_lossy().to_string();
        let (mut rx, _guard) = register(&db_path, "tenant-a", "peer-a");
        let event_id = [7u8; 32];
        publish(&db_path, "tenant-a", "peer-a", &[event_id]);
        assert_eq!(rx.recv().await, Some(vec![event_id]));
    }

    #[tokio::test]
    async fn ignores_non_matching_registered_peer() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("ignore.db").to_string_lossy().to_string();
        let (mut rx, _guard) = register(&db_path, "tenant-a", "peer-a");
        publish(&db_path, "tenant-a", "peer-b", &[[9u8; 32]]);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), rx.recv())
                .await
                .is_err()
        );
    }
}
