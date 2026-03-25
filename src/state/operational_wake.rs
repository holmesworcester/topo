use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tokio::sync::broadcast;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationalWake {
    ConnectionPlan { connection_id: String },
    ClientRuntime { client_id: String },
}

pub struct OperationalWakeGuard {
    db_path: String,
}

fn registry() -> &'static Mutex<HashMap<String, broadcast::Sender<OperationalWake>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, broadcast::Sender<OperationalWake>>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn sender_for(db_path: &str) -> broadcast::Sender<OperationalWake> {
    let mut registry = registry()
        .lock()
        .expect("operational wake registry mutex poisoned");
    registry
        .entry(db_path.to_string())
        .or_insert_with(|| {
            let (tx, _rx) = broadcast::channel(1024);
            tx
        })
        .clone()
}

pub fn register(db_path: &str) -> (broadcast::Receiver<OperationalWake>, OperationalWakeGuard) {
    (
        sender_for(db_path).subscribe(),
        OperationalWakeGuard {
            db_path: db_path.to_string(),
        },
    )
}

pub fn publish(db_path: &str, wake: OperationalWake) {
    let _ = sender_for(db_path).send(wake);
}

pub fn publish_from_connection(conn: &rusqlite::Connection, wake: OperationalWake) {
    let Some(db_path) = crate::state::live_hints::database_path_key(conn)
        .ok()
        .flatten()
    else {
        return;
    };
    publish(&db_path, wake);
}

impl Drop for OperationalWakeGuard {
    fn drop(&mut self) {
        let mut registry = registry()
            .lock()
            .expect("operational wake registry mutex poisoned");
        if let Some(sender) = registry.get(&self.db_path) {
            if sender.receiver_count() == 0 {
                registry.remove(&self.db_path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn publishes_to_matching_db_path() {
        let db_path = "/tmp/topo-operational-wake-match.db";
        let (mut rx, _guard) = register(db_path);

        publish(
            db_path,
            OperationalWake::ConnectionPlan {
                connection_id: "tenant-a@peer:abc".to_string(),
            },
        );

        let wake = rx.recv().await.expect("wake should be delivered");
        assert_eq!(
            wake,
            OperationalWake::ConnectionPlan {
                connection_id: "tenant-a@peer:abc".to_string()
            }
        );
    }

    #[tokio::test]
    async fn ignores_other_db_paths() {
        let (mut rx, _guard) = register("/tmp/topo-operational-wake-a.db");

        publish(
            "/tmp/topo-operational-wake-b.db",
            OperationalWake::ConnectionPlan {
                connection_id: "tenant-a@peer:abc".to_string(),
            },
        );

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), rx.recv())
                .await
                .is_err()
        );
    }
}
