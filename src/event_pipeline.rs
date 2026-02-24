use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tracing::{error, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::db::open_connection;
use crate::db::project_queue::ProjectQueue;
use crate::db::store::{
    lookup_workspace_id, SQL_INSERT_EVENT, SQL_INSERT_NEG_ITEM, SQL_INSERT_RECORDED_EVENT,
};
use crate::db::wanted::WantedEvents;
use crate::event_modules::{self as events, registry, ShareScope};
use crate::projection::apply::project_one;

use crate::tuning::{drain_batch_size, write_batch_cap};

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[derive(Default)]
struct PersistPhaseOutput {
    persisted_event_ids: Vec<EventId>,
    tenants_seen: HashSet<String>,
}

enum PostCommitCommand {
    RemoveWanted {
        event_id: EventId,
    },
    DrainProjectQueue {
        tenant_id: String,
        batch_size: usize,
    },
    LogProjectQueueHealth {
        tenant_id: String,
    },
    RunPostDrainHooks {
        tenant_id: String,
    },
}

fn short_id(value: &str) -> &str {
    &value[..16.min(value.len())]
}

fn build_post_commit_commands(
    output: &PersistPhaseOutput,
    batch_size: usize,
) -> Vec<PostCommitCommand> {
    let mut commands =
        Vec::with_capacity(output.persisted_event_ids.len() + (output.tenants_seen.len() * 3));

    for event_id in &output.persisted_event_ids {
        commands.push(PostCommitCommand::RemoveWanted {
            event_id: *event_id,
        });
    }

    // Deterministic order makes the command phase easier to reason about.
    let mut tenants: Vec<String> = output.tenants_seen.iter().cloned().collect();
    tenants.sort();
    for tenant_id in tenants {
        commands.push(PostCommitCommand::DrainProjectQueue {
            tenant_id: tenant_id.clone(),
            batch_size,
        });
        commands.push(PostCommitCommand::LogProjectQueueHealth {
            tenant_id: tenant_id.clone(),
        });
        commands.push(PostCommitCommand::RunPostDrainHooks { tenant_id });
    }

    commands
}

fn execute_post_commit_commands(
    db: &rusqlite::Connection,
    wanted: &WantedEvents<'_>,
    pq: &ProjectQueue<'_>,
    commands: &[PostCommitCommand],
) {
    for command in commands {
        match command {
            PostCommitCommand::RemoveWanted { event_id } => {
                let _ = wanted.remove(event_id);
            }
            PostCommitCommand::DrainProjectQueue {
                tenant_id,
                batch_size,
            } => {
                if let Err(e) = pq.drain_with_limit(tenant_id, *batch_size, |conn, event_id_b64| {
                    if let Some(eid) = event_id_from_base64(event_id_b64) {
                        project_one(conn, tenant_id, &eid)
                            .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
                    }
                    Ok(())
                }) {
                    warn!("project_queue drain error for {}: {}", tenant_id, e);
                }
            }
            PostCommitCommand::LogProjectQueueHealth { tenant_id } => {
                if let Ok(h) = pq.health(tenant_id) {
                    if h.pending > 0 || h.max_attempts > 0 {
                        tracing::debug!(tenant=%tenant_id, pending=%h.pending, max_attempts=%h.max_attempts, oldest_age_ms=%h.oldest_age_ms, "project_queue health");
                    }
                }
            }
            PostCommitCommand::RunPostDrainHooks { tenant_id } => {
                match crate::event_modules::post_drain_hooks(db, tenant_id) {
                    Ok(count) if count > 0 => {
                        tracing::info!(
                            "post-drain hooks: tenant {} resolved {} item(s)",
                            short_id(tenant_id),
                            count
                        );
                    }
                    Ok(_) => {}
                    Err(e) => warn!("post-drain hooks failed for {}: {}", short_id(tenant_id), e),
                }
            }
        }
    }
}

/// Drain pending project_queue items for a tenant, projecting each event.
///
/// This encapsulates the `project_one` + `drain_with_limit` pattern so that
/// callers outside `event_pipeline` do not need to import `projection::apply`
/// directly.  Used by both `batch_writer` (internal) and `sync::engine` startup
/// recovery paths.
pub fn drain_project_queue(db_path: &str, tenant_id: &str, batch_size: usize) -> usize {
    let db = match crate::db::open_connection(db_path) {
        Ok(db) => db,
        Err(e) => {
            warn!("drain_project_queue: failed to open db: {}", e);
            return 0;
        }
    };
    let pq = crate::db::project_queue::ProjectQueue::new(&db);
    let tid = tenant_id.to_string();
    pq.drain_with_limit(&tid, batch_size, |conn, event_id_b64| {
        if let Some(eid) = event_id_from_base64(event_id_b64) {
            project_one(conn, &tid, &eid)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        }
        Ok(())
    })
    .unwrap_or(0)
}

/// Batch writer task - drains channel and writes to SQLite in batches.
/// Writes event blob/neg_items/recorded_events, enqueues into project_queue,
/// then drains the queue via `project_one` for crash-recoverable projection.
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

    let wanted = WantedEvents::new(&db);

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

    let reg = registry();
    let pq = ProjectQueue::new(&db);
    // Cache workspace_id per recorded_by to avoid repeated lookups
    let mut workspace_cache: HashMap<String, String> = HashMap::new();

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

        // Pre-warm workspace_id cache for all recorded_by values in this batch
        // BEFORE the transaction — avoids SHARED→EXCLUSIVE lock upgrade inside BEGIN.
        for (_, _, rb) in &batch {
            if !workspace_cache.contains_key(rb) {
                let ws = lookup_workspace_id(&db, rb);
                if !ws.is_empty() {
                    workspace_cache.insert(rb.clone(), ws);
                }
            }
        }

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

        // Phase 1 (transactional): persist ingress rows and enqueue projection work.
        let mut persist_output = PersistPhaseOutput {
            persisted_event_ids: Vec::with_capacity(batch.len()),
            tenants_seen: HashSet::new(),
        };
        for (event_id, blob, recorded_by) in &batch {
            let event_id_b64 = event_id_to_base64(event_id);

            if let Some(created_at_ms) = events::extract_created_at_ms(blob) {
                if let Some(type_code) = events::extract_event_type(blob) {
                    if let Some(meta) = reg.lookup(type_code) {
                        // Only insert into neg_items for shared events (defense-in-depth)
                        if meta.share_scope == ShareScope::Shared {
                            // Look up workspace_id; cache only non-empty values
                            // (empty means trust anchor not yet projected).
                            let ws_id = if let Some(cached) = workspace_cache.get(recorded_by) {
                                cached.clone()
                            } else {
                                let ws = lookup_workspace_id(&db, recorded_by);
                                if !ws.is_empty() {
                                    workspace_cache.insert(recorded_by.clone(), ws.clone());
                                }
                                ws
                            };
                            if let Err(e) = neg_items_stmt.execute(rusqlite::params![
                                &ws_id,
                                created_at_ms as i64,
                                event_id.as_slice()
                            ]) {
                                // Non-fatal: neg_items is a reconciliation cache;
                                // event will be re-added on next sync session.
                                warn!("neg_items insert error for {}: {}", event_id_b64, e);
                            }
                        }

                        if let Err(e) = events_stmt.execute(rusqlite::params![
                            &event_id_b64,
                            meta.type_name,
                            blob.as_slice(),
                            meta.share_scope.as_str(),
                            created_at_ms as i64,
                            current_timestamp_ms()
                        ]) {
                            warn!("events insert error for {}: {}", event_id_b64, e);
                            continue;
                        }

                        let recorded_at = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_millis() as i64;
                        if let Err(e) = recorded_stmt.execute(rusqlite::params![
                            recorded_by,
                            &event_id_b64,
                            recorded_at,
                            "quic_recv"
                        ]) {
                            warn!("recorded_events insert error for {}: {}", event_id_b64, e);
                            continue;
                        }

                        // Enqueue for durable projection (atomicity boundary 1)
                        if let Err(e) = enqueue_stmt.execute(rusqlite::params![
                            recorded_by,
                            &event_id_b64,
                            current_timestamp_ms()
                        ]) {
                            warn!("project_queue enqueue error for {}: {}", event_id_b64, e);
                        }

                        persist_output.tenants_seen.insert(recorded_by.clone());
                        persist_output.persisted_event_ids.push(*event_id);
                    }
                }
            }
        }
        match db.execute("COMMIT", []) {
            Ok(_) => {
                // Phase 2 (post-commit): execute explicit side-effect commands.
                let commands = build_post_commit_commands(&persist_output, drain_batch_size());
                execute_post_commit_commands(&db, &wanted, &pq, &commands);
            }
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
