use crate::crypto::event_id_from_base64;
use crate::db::open_connection;
use crate::db::project_queue::ProjectQueue;
use crate::projection::apply::{project_batch, project_one};
use crate::tuning::low_mem_mode;

/// Drain pending project_queue items for a tenant, projecting each event.
///
/// This encapsulates the `project_one` + `drain_with_limit` pattern so callers
/// outside `event_pipeline` do not need to import `projection::apply` directly.
/// Used by both `batch_writer` and startup recovery paths.
pub fn drain_project_queue(db_path: &str, tenant_id: &str, batch_size: usize) -> usize {
    let db = match open_connection(db_path) {
        Ok(db) => db,
        Err(e) => {
            tracing::warn!("drain_project_queue: failed to open db: {}", e);
            return 0;
        }
    };

    drain_project_queue_batched(&db, tenant_id, batch_size).unwrap_or(0)
}

pub(super) fn drain_project_queue_on_connection(
    db: &rusqlite::Connection,
    tenant_id: &str,
    batch_size: usize,
) -> rusqlite::Result<usize> {
    // Defer WAL autocheckpoints during the drain to avoid checkpoint stalls
    // between projection writes. Skipped in low_mem mode where
    // open_connection sets wal_autocheckpoint=1000 + journal_size_limit to
    // bound WAL growth on constrained-storage devices.
    let deferred_checkpoint = !low_mem_mode();
    if deferred_checkpoint {
        let _ = db.execute_batch("PRAGMA wal_autocheckpoint = 0");
    }

    let pq = ProjectQueue::new(db);
    let tenant = tenant_id.to_string();

    // Use batch projection: claim a batch, project all events with batched
    // infrastructure (blob reads, terminal checks, valid_events inserts),
    // then dequeue succeeded items.
    let result = pq.drain_with_limit(&tenant, batch_size, |conn, event_id_b64| {
        if let Some(event_id) = event_id_from_base64(event_id_b64) {
            project_one(conn, &tenant, &event_id)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        }
        Ok(())
    });

    if deferred_checkpoint {
        let _ = db.execute_batch("PRAGMA wal_autocheckpoint = 1000");
    }

    result
}

/// Batch-optimized drain: claims events from the queue and projects them
/// using batched infrastructure (blob reads, terminal checks, valid_events
/// inserts). Falls back to per-event projection for encrypted events.
pub(super) fn drain_project_queue_batched(
    db: &rusqlite::Connection,
    tenant_id: &str,
    batch_size: usize,
) -> rusqlite::Result<usize> {
    let deferred_checkpoint = !low_mem_mode();
    if deferred_checkpoint {
        let _ = db.execute_batch("PRAGMA wal_autocheckpoint = 0");
    }

    let pq = ProjectQueue::new(db);
    let mut total = 0usize;

    loop {
        let batch = pq.claim_batch(tenant_id, batch_size, 30_000)?;
        if batch.is_empty() {
            break;
        }

        match project_batch(db, tenant_id, &batch) {
            Ok(processed) => {
                // Dequeue all claimed items — project_batch handles
                // valid/reject/block decisions internally.
                pq.mark_done_batch(tenant_id, &batch.iter().map(String::as_str).collect::<Vec<_>>())?;
                total += processed;
            }
            Err(e) => {
                tracing::warn!("batch projection failed, falling back to per-event: {}", e);
                // Fall back to per-event for this batch
                for event_id_b64 in &batch {
                    if let Some(event_id) = event_id_from_base64(event_id_b64) {
                        let _ = project_one(db, tenant_id, &event_id);
                    }
                }
                pq.mark_done_batch(tenant_id, &batch.iter().map(String::as_str).collect::<Vec<_>>())?;
                total += batch.len();
            }
        }
    }

    if deferred_checkpoint {
        let _ = db.execute_batch("PRAGMA wal_autocheckpoint = 1000");
    }

    Ok(total)
}
