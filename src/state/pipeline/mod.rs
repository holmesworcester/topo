mod drain;
mod effects;
mod phases;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::hash_event;
use crate::db::open_connection;
use crate::db::receipt_spool::ReceiptSpool;
use crate::db::store::{
    lookup_workspace_id, SQL_INSERT_EVENT, SQL_INSERT_NEG_ITEM, SQL_INSERT_RECORDED_EVENT,
};
use crate::event_modules::{self as events, registry};
use crate::state::live_hints;
use crate::tuning::{
    bulk_write_batch_cap, drain_batch_size, low_mem_mode, receipt_spool_import_enabled,
    receipt_spool_import_idle_ms, write_batch_cap,
};

use self::effects::{
    run_post_commit_effects, PostCommitEffectsExecutor, SqlitePostCommitEffectsExecutor,
};
use self::phases::{run_persist_phase, PersistPhaseOutput};

pub use self::drain::drain_project_queue;

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

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
    for (_, _, recorded_by, _, _) in batch {
        if workspace_cache.contains_key(recorded_by) {
            continue;
        }
        if let Some(workspace_id) = lookup_workspace_id(db, recorded_by) {
            workspace_cache.insert(recorded_by.clone(), workspace_id);
        }
    }
}

fn begin_immediate_with_retry(db: &rusqlite::Connection) -> bool {
    for attempt in 0..3 {
        match db.execute("BEGIN IMMEDIATE", []) {
            Ok(_) => return true,
            Err(e) => {
                warn!("BEGIN failed (attempt {}): {}", attempt + 1, e);
                let _ = db.execute("ROLLBACK", []);
                std::thread::sleep(Duration::from_millis(50 * (1 << attempt)));
            }
        }
    }
    false
}

fn materialize_receipt_spool_batch<E: PostCommitEffectsExecutor>(
    db: &rusqlite::Connection,
    receipt_spool: &ReceiptSpool,
    reg: &'static registry::EventRegistry,
    workspace_cache: &mut HashMap<String, String>,
    neg_items_stmt: &mut rusqlite::Statement<'_>,
    recorded_stmt: &mut rusqlite::Statement<'_>,
    events_stmt: &mut rusqlite::Statement<'_>,
    enqueue_stmt: &mut rusqlite::Statement<'_>,
    effects_executor: &E,
) -> rusqlite::Result<usize> {
    let pending = receipt_spool
        .load_pending_batch(write_batch_cap())
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    if pending.is_empty() {
        return Ok(0);
    }

    let mut batch: Vec<IngestItem> = pending.iter().map(|row| row.item.clone()).collect();
    let spool_ids: Vec<i64> = pending.iter().map(|row| row.spool_id).collect();
    for (event_id, blob, _, _, _) in &mut batch {
        if *event_id == [0u8; 32] {
            *event_id = hash_event(blob);
        }
    }
    prewarm_workspace_cache(db, &batch, workspace_cache);

    if !begin_immediate_with_retry(db) {
        return Ok(0);
    }

    let persist_output = run_persist_phase(
        db,
        &batch,
        reg,
        workspace_cache,
        neg_items_stmt,
        recorded_stmt,
        events_stmt,
        enqueue_stmt,
    );
    receipt_spool
        .mark_materialized(&spool_ids, current_timestamp_ms())
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    commit_and_run_post_commit_effects(db, &persist_output, effects_executor, drain_batch_size())?;
    receipt_spool
        .prune_consumed_file()
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    Ok(persist_output.persisted_event_ids.len())
}

fn run_receipt_importer(
    db_path: String,
    writer_done: Arc<AtomicBool>,
    last_append_at_ms: Arc<AtomicI64>,
) {
    let db = match open_connection(&db_path) {
        Ok(db) => db,
        Err(e) => {
            error!("Receipt importer failed to open db: {}", e);
            return;
        }
    };

    let mut neg_items_stmt = match db.prepare(SQL_INSERT_NEG_ITEM) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!(
                "Receipt importer failed to prepare neg_items statement: {}",
                e
            );
            return;
        }
    };
    let mut recorded_stmt = match db.prepare(SQL_INSERT_RECORDED_EVENT) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!(
                "Receipt importer failed to prepare recorded_events statement: {}",
                e
            );
            return;
        }
    };
    let mut events_stmt = match db.prepare(SQL_INSERT_EVENT) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Receipt importer failed to prepare events statement: {}", e);
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
            error!(
                "Receipt importer failed to prepare enqueue statement: {}",
                e
            );
            return;
        }
    };

    let reg = registry();
    let receipt_spool = ReceiptSpool::new_for_db_path(&db_path);
    let mut workspace_cache: HashMap<String, String> = HashMap::new();
    let effects_executor = SqlitePostCommitEffectsExecutor::new(&db);
    let import_idle_ms = receipt_spool_import_idle_ms() as i64;

    if !low_mem_mode() {
        let _ = db.execute_batch("PRAGMA wal_autocheckpoint = 0");
    }

    loop {
        if !writer_done.load(Ordering::Relaxed) && import_idle_ms > 0 {
            let last_append_ms = last_append_at_ms.load(Ordering::Relaxed);
            let idle_ms = current_timestamp_ms().saturating_sub(last_append_ms);
            if idle_ms < import_idle_ms {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
        }

        match materialize_receipt_spool_batch(
            &db,
            &receipt_spool,
            reg,
            &mut workspace_cache,
            &mut neg_items_stmt,
            &mut recorded_stmt,
            &mut events_stmt,
            &mut enqueue_stmt,
            &effects_executor,
        ) {
            Ok(imported) if imported > 0 => continue,
            Ok(_) => {
                if writer_done.load(Ordering::Relaxed) {
                    match receipt_spool.load_pending_batch(1) {
                        Ok(rows) if rows.is_empty() => break,
                        Ok(_) => {}
                        Err(e) => warn!("receipt importer pending scan failed: {}", e),
                    }
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => {
                warn!("receipt spool materialization failed: {}", e);
                let _ = db.execute("ROLLBACK", []);
                std::thread::sleep(Duration::from_millis(5));
            }
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
    let mut prefetched_first: Option<IngestItem> = None;
    let receipt_spool = ReceiptSpool::new_for_db_path(&db_path);
    let mut cumulative_events: u64 = 0;
    let mut profile_epoch = Instant::now();
    let writer_done = Arc::new(AtomicBool::new(false));
    let last_append_at_ms = Arc::new(AtomicI64::new(0));
    let importer_handle = if receipt_spool_import_enabled() {
        let importer_db_path = db_path.clone();
        let importer_done = Arc::clone(&writer_done);
        let importer_last_append_at_ms = Arc::clone(&last_append_at_ms);
        Some(std::thread::spawn(move || {
            run_receipt_importer(importer_db_path, importer_done, importer_last_append_at_ms);
        }))
    } else {
        None
    };

    loop {
        let first = match prefetched_first.take() {
            Some(item) => item,
            None => match rx.blocking_recv() {
                Some(item) => item,
                None => break,
            },
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
        let hot_backlog = if batch.len() >= cap {
            match rx.try_recv() {
                Ok(item) => {
                    prefetched_first = Some(item);
                    true
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => false,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => false,
            }
        } else {
            false
        };

        let batch_len = batch.len();
        let t_spool = Instant::now();
        let durable_at_ms = current_timestamp_ms();
        let spooled_count = match receipt_spool.append_batch(&batch, durable_at_ms) {
            Ok(count) => count as u64,
            Err(e) => {
                warn!("receipt spool append failed: {}", e);
                continue;
            }
        };
        let spool_ms = t_spool.elapsed().as_millis();
        last_append_at_ms.store(durable_at_ms, Ordering::Relaxed);
        cumulative_events += spooled_count;
        events_received.fetch_add(spooled_count, Ordering::Relaxed);

        if cumulative_events / 10_000 != (cumulative_events.saturating_sub(spooled_count)) / 10_000
        {
            let epoch_ms = profile_epoch.elapsed().as_millis();
            info!(
                "WRITER_PROFILE: cumulative={} batch={} spool={}ms hot_backlog={} epoch_10k={}ms",
                cumulative_events, batch_len, spool_ms, hot_backlog, epoch_ms,
            );
            profile_epoch = Instant::now();
        }
    }

    writer_done.store(true, Ordering::Relaxed);
    if let Some(importer_handle) = importer_handle {
        if let Err(err) = importer_handle.join() {
            error!("Receipt importer thread panicked: {:?}", err);
        }
    }
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
