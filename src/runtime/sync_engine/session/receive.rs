use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

fn peer_session_ingest_gate_map() -> &'static Mutex<HashMap<String, Arc<Semaphore>>> {
    static GATES: OnceLock<Mutex<HashMap<String, Arc<Semaphore>>>> = OnceLock::new();
    GATES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn peer_session_ingest_gate(db_path: &str, peer_id: &str) -> Arc<Semaphore> {
    let mut gates = peer_session_ingest_gate_map()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    gates
        .entry(format!("{db_path}|{peer_id}"))
        .or_insert_with(|| Arc::new(Semaphore::new(1)))
        .clone()
}

pub async fn acquire_peer_session_ingest_guard(
    db_path: &str,
    peer_id: &str,
) -> Result<OwnedSemaphorePermit, String> {
    peer_session_ingest_gate(db_path, peer_id)
        .acquire_owned()
        .await
        .map_err(|_| format!("peer session ingest gate closed for {peer_id}"))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn peer_session_ingest_guard_serializes_same_peer() {
        let first = acquire_peer_session_ingest_guard("/tmp/peer-gate-a", "peer-a")
            .await
            .unwrap();

        let other_peer = tokio::time::timeout(
            Duration::from_millis(100),
            acquire_peer_session_ingest_guard("/tmp/peer-gate-a", "peer-b"),
        )
        .await
        .expect("different peer should not block")
        .unwrap();
        drop(other_peer);

        let waiting = tokio::spawn(async {
            acquire_peer_session_ingest_guard("/tmp/peer-gate-a", "peer-a").await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !waiting.is_finished(),
            "same peer should stay blocked until the previous session releases its ingest guard"
        );

        drop(first);

        let second = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("same peer should unblock after release")
            .expect("join waiting peer ingest guard task")
            .expect("acquire same peer ingest guard");
        drop(second);
    }
}
