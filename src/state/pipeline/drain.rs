use crate::crypto::event_id_from_base64;
use crate::db::open_connection;
use crate::db::project_queue::ProjectQueue;
use crate::projection::apply::project_one;

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

    drain_project_queue_on_connection(&db, tenant_id, batch_size).unwrap_or(0)
}

pub(super) fn drain_project_queue_on_connection(
    db: &rusqlite::Connection,
    tenant_id: &str,
    batch_size: usize,
) -> rusqlite::Result<usize> {
    // Defer WAL autocheckpoints during the drain. Projection writes are
    // autocommit (one implicit transaction per SQL statement), so the default
    // wal_autocheckpoint=1000 triggers frequent checkpoints that stall the
    // writer. Deferring keeps all drain writes in the WAL and lets a single
    // checkpoint run after the drain completes (when autocheckpoint is restored
    // and the next COMMIT triggers it).
    let _ = db.execute_batch("PRAGMA wal_autocheckpoint = 0");

    let pq = ProjectQueue::new(db);
    let tenant = tenant_id.to_string();

    let result = pq.drain_with_limit(&tenant, batch_size, |conn, event_id_b64| {
        if let Some(event_id) = event_id_from_base64(event_id_b64) {
            project_one(conn, &tenant, &event_id)
                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
        }
        Ok(())
    });

    // Restore WAL autocheckpoint to default.
    let _ = db.execute_batch("PRAGMA wal_autocheckpoint = 1000");

    result
}
