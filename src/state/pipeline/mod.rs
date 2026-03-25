mod drain;
mod effects;
mod phases;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::db::open_connection;
use crate::db::store::{
    lookup_workspace_id, SQL_INSERT_EVENT, SQL_INSERT_RECORDED_EVENT,
    SQL_INSERT_SHARED_EVENT_INDEX_ENTRY,
};
use crate::event_modules::{self as events, registry};
use crate::state::live_hints;
use crate::tuning::{bulk_write_batch_cap, drain_batch_size, low_mem_mode, write_batch_cap};

use self::effects::{
    run_post_commit_effects, PostCommitEffectsExecutor, SqlitePostCommitEffectsExecutor,
};
use self::phases::{run_persist_phase, PersistPhaseOutput};

pub use self::drain::drain_project_queue;

fn ingest_is_bulk(item: &IngestItem) -> bool {
    events::outer_semantic_type_code(&item.1) == Some(events::EVENT_TYPE_FILE_SLICE)
}

fn sort_ingest_batch(batch: &mut [IngestItem]) {
    let mut foreground = Vec::with_capacity(batch.len());
    let mut bulk = Vec::new();
    for item in batch.iter().cloned() {
        if ingest_is_bulk(&item) {
            bulk.push(item);
        } else {
            foreground.push(item);
        }
    }
    foreground.extend(bulk);
    batch.clone_from_slice(&foreground);
}

fn ingest_batch_cap(first: &IngestItem) -> usize {
    if ingest_is_bulk(first) {
        bulk_write_batch_cap()
    } else {
        write_batch_cap()
    }
}

fn prewarm_workspace_cache(
    db: &rusqlite::Connection,
    batch: &[IngestItem],
    workspace_cache: &mut HashMap<String, String>,
) {
    for (_, _, recorded_by, _, _, _) in batch {
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
    live_hints::publish_from_connection(db, &persist_output.live_hints);
    run_post_commit_tail(persist_output, effects_executor, batch_size, || {
        enforce_low_mem_wal_cap(db)
    });
    Ok(())
}

fn run_post_commit_tail<E, F>(
    persist_output: &PersistPhaseOutput,
    effects_executor: &E,
    batch_size: usize,
    wal_cap_check: F,
) where
    E: PostCommitEffectsExecutor,
    F: FnOnce() -> rusqlite::Result<()>,
{
    if let Err(e) = wal_cap_check() {
        tracing::warn!("post-commit WAL cap check failed: {}", e);
    }
    run_post_commit_effects(effects_executor, persist_output, batch_size);
}

fn low_mem_wal_cap_bytes() -> i64 {
    const DEFAULT_CAP_MIB: i64 = 12;
    let cap_mib = std::env::var("LOW_MEM_WAL_CAP_MIB")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_CAP_MIB);
    cap_mib * 1024 * 1024
}

fn wal_checkpoint_stats(
    db: &rusqlite::Connection,
    mode: &str,
) -> rusqlite::Result<(i64, i64, i64)> {
    db.query_row(&format!("PRAGMA wal_checkpoint({mode})"), [], |row| {
        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
    })
}

fn enforce_low_mem_wal_cap(db: &rusqlite::Connection) -> rusqlite::Result<()> {
    if !low_mem_mode() {
        return Ok(());
    }

    let page_size: i64 = db.query_row("PRAGMA page_size", [], |row| row.get(0))?;
    let cap_bytes = low_mem_wal_cap_bytes();
    let (_, log_frames, _) = wal_checkpoint_stats(db, "PASSIVE")?;
    let wal_bytes = log_frames.saturating_mul(page_size);
    if wal_bytes <= cap_bytes {
        return Ok(());
    }

    tracing::warn!(
        wal_bytes,
        cap_bytes,
        log_frames,
        "low-mem WAL above cap; forcing TRUNCATE checkpoint"
    );
    let _ = wal_checkpoint_stats(db, "TRUNCATE")?;

    let (_, post_frames, _) = wal_checkpoint_stats(db, "PASSIVE")?;
    let post_bytes = post_frames.saturating_mul(page_size);
    if post_bytes > cap_bytes {
        tracing::warn!(
            wal_bytes = post_bytes,
            cap_bytes,
            log_frames = post_frames,
            "low-mem WAL still above cap after TRUNCATE (likely active reader)"
        );
    }

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

    let mut shared_event_index_stmt = match db.prepare(SQL_INSERT_SHARED_EVENT_INDEX_ENTRY) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare shared_event_index statement: {}", e);
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
        "INSERT OR IGNORE INTO project_queue
         (peer_id, event_id, available_at, priority_lane, priority_ts)
         SELECT ?1, ?2, ?3, ?4, ?5
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
    let mut cumulative_events: u64 = 0;
    let mut profile_epoch = Instant::now();

    // Disable WAL autocheckpoint on the writer — we checkpoint manually
    // after each batch to avoid checkpoint stalls mid-transaction.
    let deferred_wal = !low_mem_mode();
    if deferred_wal {
        let _ = db.execute_batch("PRAGMA wal_autocheckpoint = 0");
    }

    loop {
        let first = match rx.blocking_recv() {
            Some(item) => item,
            None => break,
        };

        let mut batch = vec![first];
        let cap = ingest_batch_cap(&batch[0]);
        while let Ok(item) = rx.try_recv() {
            batch.push(item);
            if batch.len() >= cap {
                break;
            }
        }
        sort_ingest_batch(&mut batch);

        let batch_len = batch.len();

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
            continue;
        }

        let t_persist = Instant::now();
        let persist_output = run_persist_phase(
            &db,
            &batch,
            reg,
            &mut workspace_cache,
            &mut shared_event_index_stmt,
            &mut recorded_stmt,
            &mut events_stmt,
            &mut enqueue_stmt,
        );
        let persist_ms = t_persist.elapsed().as_millis();

        let t_commit = Instant::now();
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
                continue;
            }
        }
        let commit_and_effects_ms = t_commit.elapsed().as_millis();

        let persisted_count = persist_output.persisted_event_ids.len() as u64;
        cumulative_events += persisted_count;
        events_received.fetch_add(persisted_count, Ordering::Relaxed);

        // Non-blocking PASSIVE checkpoint on a cadence — merges WAL pages
        // into the main DB without blocking readers. Every 10k events keeps
        // the WAL bounded without checkpointing on every batch.
        if deferred_wal && cumulative_events % 10_000 < persisted_count {
            let _ = db.execute_batch("PRAGMA wal_checkpoint(PASSIVE)");
        }

        // Profile logging: emit every 10k events to avoid log noise
        if cumulative_events / 10_000 != (cumulative_events - persisted_count) / 10_000 {
            let epoch_ms = profile_epoch.elapsed().as_millis();
            info!(
                "WRITER_PROFILE: cumulative={} batch={} persist={}ms commit+effects={}ms epoch_10k={}ms",
                cumulative_events, batch_len, persist_ms, commit_and_effects_ms, epoch_ms,
            );
            profile_epoch = Instant::now();
        }
    }
}

pub fn ingest_now(db_path: &str, mut batch: Vec<IngestItem>) -> Result<usize, String> {
    if batch.is_empty() {
        return Ok(0);
    }

    let db = open_connection(db_path).map_err(|e| format!("open ingest db: {e}"))?;
    let mut shared_event_index_stmt = db
        .prepare(SQL_INSERT_SHARED_EVENT_INDEX_ENTRY)
        .map_err(|e| format!("prepare shared_event_index statement: {e}"))?;
    let mut recorded_stmt = db
        .prepare(SQL_INSERT_RECORDED_EVENT)
        .map_err(|e| format!("prepare recorded_events statement: {e}"))?;
    let mut events_stmt = db
        .prepare(SQL_INSERT_EVENT)
        .map_err(|e| format!("prepare events statement: {e}"))?;
    let mut enqueue_stmt = db
        .prepare(
            "INSERT OR IGNORE INTO project_queue
             (peer_id, event_id, available_at, priority_lane, priority_ts)
             SELECT ?1, ?2, ?3, ?4, ?5
             WHERE NOT EXISTS (SELECT 1 FROM valid_events WHERE peer_id=?1 AND event_id=?2)
             AND NOT EXISTS (SELECT 1 FROM rejected_events WHERE peer_id=?1 AND event_id=?2)
             AND NOT EXISTS (SELECT 1 FROM blocked_event_deps WHERE peer_id=?1 AND event_id=?2)",
        )
        .map_err(|e| format!("prepare enqueue statement: {e}"))?;

    sort_ingest_batch(&mut batch);
    let reg = registry();
    let mut workspace_cache = HashMap::new();
    prewarm_workspace_cache(&db, &batch, &mut workspace_cache);

    let mut begin_ok = false;
    for attempt in 0..3 {
        match db.execute("BEGIN IMMEDIATE", []) {
            Ok(_) => {
                begin_ok = true;
                break;
            }
            Err(e) => {
                let _ = db.execute("ROLLBACK", []);
                if attempt == 2 {
                    return Err(format!("begin immediate failed after retries: {e}"));
                }
                std::thread::sleep(Duration::from_millis(50 * (1 << attempt)));
            }
        }
    }
    if !begin_ok {
        return Err("begin immediate failed".to_string());
    }

    let persist_output = run_persist_phase(
        &db,
        &batch,
        reg,
        &mut workspace_cache,
        &mut shared_event_index_stmt,
        &mut recorded_stmt,
        &mut events_stmt,
        &mut enqueue_stmt,
    );
    let effects_executor = SqlitePostCommitEffectsExecutor::new(&db);
    commit_and_run_post_commit_effects(&db, &persist_output, &effects_executor, drain_batch_size())
        .map_err(|e| {
            let _ = db.execute("ROLLBACK", []);
            format!("commit immediate ingest batch: {e}")
        })?;
    Ok(persist_output.persisted_event_ids.len())
}

pub fn ingest_one(db_path: &str, item: IngestItem) -> Result<(), String> {
    ingest_now(db_path, vec![item]).map(|_| ())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::HashSet;

    use super::effects::PostCommitEffectsExecutor;
    use super::phases::PersistPhaseOutput;
    use super::*;
    use crate::event_modules::{EVENT_TYPE_FILE_SLICE, EVENT_TYPE_MESSAGE};

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
            live_hints: Vec::new(),
            shared_event_fanouts: Vec::new(),
        }
    }

    fn make_ingest_item(type_code: u8, created_at: u64, marker: u8) -> IngestItem {
        let mut blob = vec![type_code];
        blob.extend_from_slice(&created_at.to_le_bytes());
        (
            [marker; 32],
            blob,
            "tenant-a".to_string(),
            "sync".to_string(),
            0,
            0,
        )
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
        assert_eq!(
            *recorded_batch_size, 16,
            "effects should receive batch size"
        );
    }

    #[test]
    fn event_pipeline_wal_cap_failure_does_not_skip_effects() {
        let executor = RecordingExecutor::default();
        let persist_output = sample_persist_output();

        run_post_commit_tail(&persist_output, &executor, 8, || {
            Err(rusqlite::Error::InvalidQuery)
        });

        let invocations = executor.invocations.borrow();
        assert_eq!(
            invocations.len(),
            1,
            "effects should still run after advisory WAL-cap failure"
        );
        let (recorded_output, recorded_batch_size) = &invocations[0];
        assert_eq!(recorded_output, &persist_output);
        assert_eq!(*recorded_batch_size, 8);
    }

    #[test]
    fn ingest_sort_prefers_foreground_while_preserving_arrival_order() {
        let mut batch = vec![
            make_ingest_item(EVENT_TYPE_FILE_SLICE, 10, 1),
            make_ingest_item(EVENT_TYPE_MESSAGE, 20, 2),
            make_ingest_item(EVENT_TYPE_MESSAGE, 30, 3),
        ];

        sort_ingest_batch(&mut batch);

        assert_eq!(batch[0].0, [2u8; 32]);
        assert_eq!(batch[1].0, [3u8; 32]);
        assert_eq!(batch[2].0, [1u8; 32]);
    }

    #[test]
    fn ingest_batch_cap_micro_batches_bulk_first_items() {
        let bulk = make_ingest_item(EVENT_TYPE_FILE_SLICE, 10, 1);
        let message = make_ingest_item(EVENT_TYPE_MESSAGE, 10, 2);

        assert_eq!(ingest_batch_cap(&bulk), bulk_write_batch_cap());
        assert_eq!(ingest_batch_cap(&message), write_batch_cap());
    }
}
