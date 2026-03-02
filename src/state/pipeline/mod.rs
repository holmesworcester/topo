mod drain;
mod effects;
mod phases;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{error, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::db::open_connection;
use crate::db::store::{
    lookup_workspace_id, SQL_INSERT_EVENT, SQL_INSERT_NEG_ITEM, SQL_INSERT_RECORDED_EVENT,
};
use crate::event_modules::registry;
use crate::tuning::{drain_batch_size, write_batch_cap};

use self::effects::{
    run_post_commit_effects, PostCommitEffectsExecutor, SqlitePostCommitEffectsExecutor,
};
use self::phases::{run_persist_phase, PersistPhaseOutput};

pub use self::drain::drain_project_queue;

fn prewarm_workspace_cache(
    db: &rusqlite::Connection,
    batch: &[IngestItem],
    workspace_cache: &mut HashMap<String, String>,
) {
    for (_, _, recorded_by, _) in batch {
        if workspace_cache.contains_key(recorded_by) {
            continue;
        }
        if let Some(workspace_id) = lookup_workspace_id(db, recorded_by) {
            workspace_cache.insert(recorded_by.clone(), workspace_id);
        }
    }
}

fn commit_and_run_post_commit_effects<E: PostCommitEffectsExecutor>(
    db: &rusqlite::Connection,
    persist_output: &PersistPhaseOutput,
    effects_executor: &E,
    batch_size: usize,
) -> rusqlite::Result<()> {
    db.execute("COMMIT", [])?;
    run_post_commit_effects(effects_executor, persist_output, batch_size);
    Ok(())
}

/// Batch writer task - drains channel and writes to SQLite in batches.
/// Phase 1 persists ingest rows in a transaction, then post-commit effects
/// run directly from persisted output through the executor boundary.
///
/// Each item carries its own `recorded_by`, enabling a single writer to serve
/// multiple tenants sharing one DB.
pub fn batch_writer(
    db_path: String,
    mut rx: mpsc::Receiver<IngestItem>,
    events_received: Arc<AtomicU64>,
) {
    let db = match open_connection(&db_path) {
        Ok(db) => db,
        Err(e) => {
            error!("Writer failed to open db: {}", e);
            return;
        }
    };

    let mut neg_items_stmt = match db.prepare(SQL_INSERT_NEG_ITEM) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare neg_items statement: {}", e);
            return;
        }
    };

    let mut recorded_stmt = match db.prepare(SQL_INSERT_RECORDED_EVENT) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare recorded_events statement: {}", e);
            return;
        }
    };

    let mut events_stmt = match db.prepare(SQL_INSERT_EVENT) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare events statement: {}", e);
            return;
        }
    };

    let mut enqueue_stmt = match db.prepare(
        "INSERT OR IGNORE INTO project_queue (peer_id, event_id, available_at)
         SELECT ?1, ?2, ?3
         WHERE NOT EXISTS (SELECT 1 FROM valid_events WHERE peer_id=?1 AND event_id=?2)
         AND NOT EXISTS (SELECT 1 FROM rejected_events WHERE peer_id=?1 AND event_id=?2)
         AND NOT EXISTS (SELECT 1 FROM blocked_event_deps WHERE peer_id=?1 AND event_id=?2)",
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare enqueue statement: {}", e);
            return;
        }
    };

    let reg = registry();
    let mut workspace_cache: HashMap<String, String> = HashMap::new();
    let effects_executor = SqlitePostCommitEffectsExecutor::new(&db);

    loop {
        let first = match rx.blocking_recv() {
            Some(item) => item,
            None => break,
        };

        let cap = write_batch_cap();
        let mut batch = vec![first];
        while let Ok(item) = rx.try_recv() {
            batch.push(item);
            if batch.len() >= cap {
                break;
            }
        }

        prewarm_workspace_cache(&db, &batch, &mut workspace_cache);

        // BEGIN with retry+backoff — do not drain batch on failure
        let mut begin_ok = false;
        for attempt in 0..3 {
            match db.execute("BEGIN IMMEDIATE", []) {
                Ok(_) => {
                    begin_ok = true;
                    break;
                }
                Err(e) => {
                    warn!("BEGIN failed (attempt {}): {}", attempt + 1, e);
                    // Ensure no leftover transaction state
                    let _ = db.execute("ROLLBACK", []);
                    std::thread::sleep(Duration::from_millis(50 * (1 << attempt)));
                }
            }
        }
        if !begin_ok {
            error!(
                "BEGIN failed after retries, preserving {} items for next batch",
                batch.len()
            );
            // Items remain in wanted — they will be re-requested on next sync
            continue;
        }

        let persist_output = run_persist_phase(
            &db,
            &batch,
            reg,
            &mut workspace_cache,
            &mut neg_items_stmt,
            &mut recorded_stmt,
            &mut events_stmt,
            &mut enqueue_stmt,
        );

        match commit_and_run_post_commit_effects(
            &db,
            &persist_output,
            &effects_executor,
            drain_batch_size(),
        ) {
            Ok(()) => {}
            Err(e) => {
                warn!("COMMIT failed, rolling back: {}", e);
                let _ = db.execute("ROLLBACK", []);
                // Items remain in wanted — they will be re-requested on next sync
                continue;
            }
        }

        events_received.fetch_add(
            persist_output.persisted_event_ids.len() as u64,
            Ordering::Relaxed,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashSet;

    use super::effects::PostCommitEffectsExecutor;
    use super::phases::PersistPhaseOutput;
    use super::*;

    #[derive(Default)]
    struct RecordingExecutor {
        invocations: RefCell<Vec<(PersistPhaseOutput, usize)>>,
    }

    impl PostCommitEffectsExecutor for RecordingExecutor {
        fn run_post_commit_effects(&self, persist_output: &PersistPhaseOutput, batch_size: usize) {
            self.invocations
                .borrow_mut()
                .push((persist_output.clone(), batch_size));
        }
    }

    fn sample_persist_output() -> PersistPhaseOutput {
        PersistPhaseOutput {
            persisted_event_ids: vec![[1u8; 32], [2u8; 32]],
            tenants_seen: HashSet::from(["tenant-b".to_string(), "tenant-a".to_string()]),
        }
    }

    #[test]
    fn event_pipeline_commit_failure_does_not_call_effects() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        let executor = RecordingExecutor::default();
        let persist_output = sample_persist_output();

        let result = commit_and_run_post_commit_effects(&db, &persist_output, &executor, 8);
        assert!(
            result.is_err(),
            "commit should fail without active transaction"
        );
        assert!(
            executor.invocations.borrow().is_empty(),
            "effects should not run if commit fails"
        );
    }

    #[test]
    fn event_pipeline_commit_success_calls_effects_once_with_planned_commands() {
        let db = rusqlite::Connection::open_in_memory().unwrap();
        db.execute("BEGIN IMMEDIATE", []).unwrap();

        let executor = RecordingExecutor::default();
        let persist_output = sample_persist_output();

        commit_and_run_post_commit_effects(&db, &persist_output, &executor, 16).unwrap();

        let invocations = executor.invocations.borrow();
        assert_eq!(invocations.len(), 1, "effects should run once after commit");
        let (recorded_output, recorded_batch_size) = &invocations[0];
        assert_eq!(
            recorded_output, &persist_output,
            "effects should receive persist output directly"
        );
        assert_eq!(*recorded_batch_size, 16, "effects should receive batch size");
    }
}
