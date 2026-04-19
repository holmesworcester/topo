use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::db::queue::current_timestamp_ms;
use crate::tuning::{
    direct_ingest_large_blob_pending_charge_bytes, direct_ingest_large_blob_threshold_bytes,
    direct_ingest_pending_bytes_cap,
};

use super::{ingest_now_result, ImmediateIngestResult};

#[derive(Default)]
struct DirectIngestInner {
    pending: VecDeque<DirectIngestJob>,
    worker_running: bool,
}

struct DirectIngestState {
    inner: Mutex<DirectIngestInner>,
    byte_budget: Arc<Semaphore>,
}

struct DirectIngestJob {
    batch: Vec<IngestItem>,
    _byte_budget_permit: OwnedSemaphorePermit,
    completion: oneshot::Sender<Result<ImmediateIngestResult, String>>,
}

pub type IngestWaiter = oneshot::Receiver<Result<usize, String>>;
pub type DirectIngestWaiter = oneshot::Receiver<Result<ImmediateIngestResult, String>>;

fn direct_ingest_state_map() -> &'static Mutex<HashMap<String, Arc<DirectIngestState>>> {
    static STATES: OnceLock<Mutex<HashMap<String, Arc<DirectIngestState>>>> = OnceLock::new();
    STATES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn direct_ingest_state(db_path: &str) -> Arc<DirectIngestState> {
    let mut states = direct_ingest_state_map()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    states
        .entry(db_path.to_string())
        .or_insert_with(|| {
            Arc::new(DirectIngestState {
                inner: Mutex::new(DirectIngestInner::default()),
                byte_budget: Arc::new(Semaphore::new(direct_ingest_pending_bytes_cap())),
            })
        })
        .clone()
}

fn spawn_direct_ingest_worker(db_path: &str, state: &Arc<DirectIngestState>) -> Result<(), String> {
    let db_path = db_path.to_string();
    let state = state.clone();
    std::thread::Builder::new()
        .name(format!("direct-ingest-{}", current_timestamp_ms()))
        .spawn(move || direct_ingest_worker(db_path, state))
        .map(|_| ())
        .map_err(|e| format!("spawn direct ingest worker: {e}"))
}

pub async fn enqueue_direct_ingest_waiter(
    db_path: &str,
    batch: Vec<IngestItem>,
) -> Result<DirectIngestWaiter, String> {
    if batch.is_empty() {
        let (completion_tx, completion_rx) = oneshot::channel();
        let _ = completion_tx.send(Ok(ImmediateIngestResult {
            persisted_event_ids: Vec::new(),
        }));
        return Ok(completion_rx);
    }

    let pending_bytes = batch
        .iter()
        .map(|(_, blob, _, _, _, _)| blob.len())
        .sum::<usize>()
        .max(1);
    let contains_large_blob = batch
        .iter()
        .any(|(_, blob, _, _, _, _)| blob.len() >= direct_ingest_large_blob_threshold_bytes());
    let pending_bytes = if contains_large_blob {
        pending_bytes.max(direct_ingest_large_blob_pending_charge_bytes())
    } else {
        pending_bytes
    };
    let state = direct_ingest_state(db_path);
    let permits = u32::try_from(pending_bytes)
        .map_err(|_| format!("direct ingest batch too large: {} bytes", pending_bytes))?;
    let permit = state
        .byte_budget
        .clone()
        .acquire_many_owned(permits)
        .await
        .map_err(|_| format!("direct ingest budget closed for {db_path}"))?;
    let (completion_tx, completion_rx) = oneshot::channel();
    let mut spawn_worker = false;
    {
        let mut inner = state
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.pending.push_back(DirectIngestJob {
            batch,
            _byte_budget_permit: permit,
            completion: completion_tx,
        });
        if !inner.worker_running {
            inner.worker_running = true;
            spawn_worker = true;
        }
    }
    if spawn_worker {
        spawn_direct_ingest_worker(db_path, &state)?;
    }
    Ok(completion_rx)
}

fn direct_ingest_worker(db_path: String, state: Arc<DirectIngestState>) {
    loop {
        let Some(mut job) = ({
            let mut inner = state
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match inner.pending.pop_front() {
                Some(job) => Some(job),
                None => {
                    inner.worker_running = false;
                    None
                }
            }
        }) else {
            return;
        };
        let first_stored_at_ms = current_timestamp_ms();
        for item in &mut job.batch {
            item.5 = first_stored_at_ms;
        }
        let result = ingest_now_result(&db_path, job.batch);
        let _ = job.completion.send(result);
    }
}

pub async fn wait_for_ingest_waiters(waiters: Vec<IngestWaiter>) -> Result<usize, String> {
    let mut ingested = 0usize;
    for waiter in waiters {
        let result = tokio::task::spawn_blocking(move || waiter.blocking_recv())
            .await
            .map_err(|e| format!("join direct ingest waiter: {e}"))?
            .map_err(|e| format!("direct ingest waiter dropped: {e}"))?;
        ingested = ingested.saturating_add(result?);
    }
    Ok(ingested)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{event_id_to_base64, hash_event};
    use crate::db::{open_connection, schema::create_tables, timeline::EventTimeline};
    use crate::event_modules::{self as events, KeySecretEvent, ParsedEvent};

    #[tokio::test(flavor = "current_thread")]
    async fn enqueue_direct_ingest_waiter_persists_events_and_timestamps() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let blob = events::encode_event(&ParsedEvent::KeySecret(KeySecretEvent {
            created_at_ms: 4242,
            key_bytes: [0xA5; 32],
        }))
        .unwrap();
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let received_at_ms = 1234;

        let waiter = enqueue_direct_ingest_waiter(
            db_path.to_str().unwrap(),
            vec![(
                event_id,
                blob,
                "tenant-a".to_string(),
                "quic_recv:peer-x".to_string(),
                received_at_ms,
                0,
            )],
        )
        .await
        .unwrap();

        let result = waiter.await.unwrap().unwrap();
        assert_eq!(result.persisted_event_ids, vec![event_id]);

        let timeline = EventTimeline::new(&conn);
        let row = timeline.load(&event_id_b64).unwrap().unwrap();
        assert_eq!(row.first_received_at, Some(received_at_ms));
        assert!(row.first_stored_at.is_some());
        assert!(row.first_stored_at.unwrap() >= received_at_ms);
    }
}
