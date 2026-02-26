pub mod egress_queue;
pub mod health;
pub mod intro;
pub mod project_queue;
pub mod queue;
pub mod removal_watch;
pub mod schema;
pub mod store;
pub mod transport_creds;
pub mod transport_trust;
pub mod wanted;

use rusqlite::{Connection, Result as SqliteResult};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Open database connection with WAL mode and performance pragmas
pub fn open_connection<P: AsRef<Path>>(path: P) -> SqliteResult<Connection> {
    let conn = Connection::open(path)?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

/// Open in-memory database (for testing)
#[cfg(test)]
pub fn open_in_memory() -> SqliteResult<Connection> {
    let conn = Connection::open_in_memory()?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

fn apply_pragmas(conn: &Connection) -> SqliteResult<()> {
    if low_mem_mode() {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -1024;
            PRAGMA temp_store = FILE;
            PRAGMA mmap_size = 0;
            PRAGMA wal_autocheckpoint = 1000;
            PRAGMA journal_size_limit = 1048576;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = OFF;
            ",
        )?;
    } else {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -64000;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = OFF;
            ",
        )?;
    }
    Ok(())
}

use crate::tuning::low_mem_mode;

pub fn ensure_infra_schema(conn: &Connection) -> SqliteResult<()> {
    wanted::ensure_schema(conn)?;
    store::ensure_schema(conn)?;
    project_queue::ensure_schema(conn)?;
    egress_queue::ensure_schema(conn)?;
    health::ensure_schema(conn)?;
    intro::ensure_schema(conn)?;
    transport_trust::ensure_schema(conn)?;
    transport_creds::ensure_schema(conn)?;
    Ok(())
}

fn identity_rebind_recorded_by_tables() -> Vec<&'static str> {
    let mut tables = crate::event_modules::identity_rebind_recorded_by_tables();
    tables.extend(health::identity_rebind_recorded_by_tables());
    tables.extend(intro::identity_rebind_recorded_by_tables());
    tables.extend(transport_trust::identity_rebind_recorded_by_tables());
    tables
}

fn identity_rebind_peer_id_tables() -> Vec<&'static str> {
    let mut tables = crate::event_modules::identity_rebind_peer_id_tables();
    tables.extend(project_queue::identity_rebind_peer_id_tables());
    tables.extend(store::identity_rebind_peer_id_tables());
    tables
}

/// Finalize identity by rebinding all `recorded_by` / `peer_id` references from
/// `old` to `new` across projection, trust, and pipeline tables in one transaction.
/// This is used when a joiner transitions from invite-derived transport identity
/// to PeerShared-derived identity so transport and event scopes converge.
pub fn finalize_identity(conn: &Connection, old: &str, new: &str) -> Result<(), rusqlite::Error> {
    if old == new {
        return Ok(());
    }

    // Use RAII transaction: auto-rolls-back on drop if not committed,
    // preventing partial state on constraint errors.
    let tx = conn.unchecked_transaction()?;

    for table in identity_rebind_recorded_by_tables() {
        update_identity_column_lossy(&tx, table, "recorded_by", old, new)?;
    }

    for table in identity_rebind_peer_id_tables() {
        update_identity_column_lossy(&tx, table, "peer_id", old, new)?;
    }

    reconcile_projection_state_after_identity_finalization(&tx, new)?;

    tx.commit()?;
    Ok(())
}

fn update_identity_column_lossy(
    tx: &rusqlite::Transaction<'_>,
    table: &str,
    column: &str,
    old: &str,
    new: &str,
) -> Result<(), rusqlite::Error> {
    // First pass: move rows where no uniqueness conflict exists.
    tx.execute(
        &format!(
            "UPDATE OR IGNORE {} SET {} = ?1 WHERE {} = ?2",
            table, column, column
        ),
        rusqlite::params![new, old],
    )?;
    // Second pass: drop stale old-identity rows that conflicted with existing
    // new-identity rows. This keeps finalization idempotent under concurrent sync.
    tx.execute(
        &format!("DELETE FROM {} WHERE {} = ?1", table, column),
        rusqlite::params![old],
    )?;
    Ok(())
}

fn reconcile_projection_state_after_identity_finalization(
    tx: &rusqlite::Transaction<'_>,
    peer_id: &str,
) -> Result<(), rusqlite::Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // After identity finalization, blockers may already be valid under the new
    // peer_id. Remove those edges so blocked headers can converge.
    tx.execute(
        "DELETE FROM blocked_event_deps
         WHERE peer_id = ?1
           AND blocker_event_id IN (
               SELECT event_id FROM valid_events WHERE peer_id = ?1
           )",
        rusqlite::params![peer_id],
    )?;

    tx.execute(
        "UPDATE blocked_events
         SET deps_remaining = (
             SELECT COUNT(*)
             FROM blocked_event_deps d
             WHERE d.peer_id = blocked_events.peer_id
               AND d.event_id = blocked_events.event_id
         )
         WHERE peer_id = ?1",
        rusqlite::params![peer_id],
    )?;

    let mut ready_events = Vec::new();
    {
        let mut stmt = tx.prepare(
            "SELECT event_id
             FROM blocked_events
             WHERE peer_id = ?1
               AND event_id NOT IN (
                   SELECT event_id FROM blocked_event_deps WHERE peer_id = ?1
               )",
        )?;
        let rows = stmt.query_map(rusqlite::params![peer_id], |row| row.get::<_, String>(0))?;
        for row in rows {
            ready_events.push(row?);
        }
    }

    // Re-queue newly unblocked events immediately and release stale leases.
    for event_id in ready_events {
        tx.execute(
            "DELETE FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![peer_id, &event_id],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO project_queue (peer_id, event_id, available_at, attempts, lease_until)
             VALUES (?1, ?2, ?3, 0, NULL)",
            rusqlite::params![peer_id, &event_id, now],
        )?;
        tx.execute(
            "UPDATE project_queue
             SET attempts = 0,
                 lease_until = NULL,
                 available_at = CASE WHEN available_at > ?3 THEN ?3 ELSE available_at END
             WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![peer_id, &event_id, now],
        )?;
    }

    // Any blocked row that remained leased during identity finalization should
    // become claimable.
    tx.execute(
        "UPDATE project_queue
         SET lease_until = NULL
         WHERE peer_id = ?1
           AND event_id IN (SELECT event_id FROM blocked_events WHERE peer_id = ?1)",
        rusqlite::params![peer_id],
    )?;

    // Drop orphan dep edges where the blocked header no longer exists.
    tx.execute(
        "DELETE FROM blocked_event_deps
         WHERE peer_id = ?1
           AND event_id NOT IN (SELECT event_id FROM blocked_events WHERE peer_id = ?1)",
        rusqlite::params![peer_id],
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory() {
        let conn = open_in_memory().unwrap();
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        // In-memory databases may report "memory" instead of "wal"
        assert!(journal_mode == "wal" || journal_mode == "memory");
    }

    #[test]
    fn test_finalize_identity() {
        let conn = open_in_memory().unwrap();
        schema::create_tables(&conn).unwrap();

        let old = "aabbccdd";
        let new = "11223344";

        // Seed representative tables with old recorded_by / peer_id
        conn.execute(
            "INSERT INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, 'evt1', 1000, 'local')",
            rusqlite::params![old],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO messages (message_id, workspace_id, author_id, content, created_at, recorded_by)
             VALUES ('msg1', 'ws1', 'author1', 'hello', 1000, ?1)",
            rusqlite::params![old],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO trust_anchors (peer_id, workspace_id)
             VALUES (?1, 'ws1')",
            rusqlite::params![old],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO bootstrap_context (recorded_by, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint, observed_at)
             VALUES (?1, 'inv1', 'ws1', '127.0.0.1:9000', X'0000000000000000000000000000000000000000000000000000000000000000', 1000)",
            rusqlite::params![old],
        )
        .unwrap();

        // Finalize identity
        finalize_identity(&conn, old, new).unwrap();

        // Verify recorded_events.peer_id updated
        let peer_id: String = conn
            .query_row(
                "SELECT peer_id FROM recorded_events WHERE event_id = 'evt1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(peer_id, new);

        // Verify messages.recorded_by updated
        let rb: String = conn
            .query_row(
                "SELECT recorded_by FROM messages WHERE message_id = 'msg1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rb, new);

        // Verify trust_anchors.peer_id updated
        let ta_pid: String = conn
            .query_row(
                "SELECT peer_id FROM trust_anchors WHERE workspace_id = 'ws1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ta_pid, new);

        // Verify bootstrap_context.recorded_by updated
        let bc_rb: String = conn
            .query_row(
                "SELECT recorded_by FROM bootstrap_context WHERE invite_event_id = 'inv1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(bc_rb, new);
    }

    #[test]
    fn test_finalize_identity_collision_dedupes() {
        let conn = open_in_memory().unwrap();
        schema::create_tables(&conn).unwrap();

        let old = "old_id";
        let new = "new_id";

        // Seed trust_anchors with both old and new peer_id for the same workspace.
        // Migration will try to SET peer_id = new WHERE peer_id = old, which
        // collides with the existing (new, ws_conflict) row.
        conn.execute(
            "INSERT INTO trust_anchors (peer_id, workspace_id)
             VALUES (?1, 'ws_conflict')",
            rusqlite::params![new],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO trust_anchors (peer_id, workspace_id)
             VALUES (?1, 'ws_conflict')",
            rusqlite::params![old],
        )
        .unwrap();

        // Also seed a messages row so we can verify rollback
        conn.execute(
            "INSERT INTO messages (message_id, workspace_id, author_id, content, created_at, recorded_by)
             VALUES ('msg_rollback', 'ws1', 'a1', 'hi', 1000, ?1)",
            rusqlite::params![old],
        )
        .unwrap();

        // Also seed a colliding transport binding row.
        conn.execute(
            "INSERT INTO peer_transport_bindings (recorded_by, peer_id, spki_fingerprint, bound_at)
             VALUES (?1, 'peer_a', X'0101010101010101010101010101010101010101010101010101010101010101', 1000)",
            rusqlite::params![new],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peer_transport_bindings (recorded_by, peer_id, spki_fingerprint, bound_at)
             VALUES (?1, 'peer_a', X'0202020202020202020202020202020202020202020202020202020202020202', 1001)",
            rusqlite::params![old],
        )
        .unwrap();

        // Migration should succeed, preserving new-id rows and dropping stale old-id duplicates.
        finalize_identity(&conn, old, new).unwrap();

        // Messages migrate to new identity.
        let rb: String = conn
            .query_row(
                "SELECT recorded_by FROM messages WHERE message_id = 'msg_rollback'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rb, new);

        // Old trust anchor row should be removed; only one new row remains.
        let ta_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM trust_anchors WHERE peer_id = ?1",
                rusqlite::params![new],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(ta_count, 1);

        let old_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM trust_anchors WHERE peer_id = ?1",
                rusqlite::params![old],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_rows, 0);

        let binding_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM peer_transport_bindings WHERE recorded_by = ?1 AND peer_id = 'peer_a'",
                rusqlite::params![new],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(binding_count, 1);
    }

    #[test]
    fn test_finalize_identity_reconciles_blocked_deps_and_leases() {
        let conn = open_in_memory().unwrap();
        schema::create_tables(&conn).unwrap();

        let old = "oldpeer";
        let new = "newpeer";
        let blocker = "blocker-valid";
        let blocked = "blocked-ready";

        conn.execute(
            "INSERT INTO blocked_event_deps (peer_id, event_id, blocker_event_id)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![old, blocked, blocker],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO blocked_events (peer_id, event_id, deps_remaining)
             VALUES (?1, ?2, 1)",
            rusqlite::params![old, blocked],
        )
        .unwrap();

        // Simulate a leased row from an in-flight drainer.
        conn.execute(
            "INSERT INTO project_queue (peer_id, event_id, available_at, attempts, lease_until)
             VALUES (?1, ?2, 9999999999, 0, 9999999999)",
            rusqlite::params![old, blocked],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO valid_events (peer_id, event_id) VALUES (?1, ?2)",
            rusqlite::params![old, blocker],
        )
        .unwrap();

        finalize_identity(&conn, old, new).unwrap();

        let dep_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![new, blocked],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(dep_rows, 0, "resolved dep edge should be removed");

        let header_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![new, blocked],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(header_rows, 0, "ready blocked header should be removed");

        let (attempts, lease_until): (i64, Option<i64>) = conn
            .query_row(
                "SELECT attempts, lease_until FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![new, blocked],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(attempts, 0);
        assert!(
            lease_until.is_none(),
            "migrated queue row should be released for immediate processing"
        );
    }
}
