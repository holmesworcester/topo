pub mod egress_queue;
pub mod health;
pub mod intro;
pub mod migrations;
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

/// Migrate all `recorded_by` / `peer_id` references from `old` to `new` across
/// all projection and trust tables in a single transaction. This is used after
/// a joiner transitions from an invite-derived transport identity to a
/// PeerShared-derived one, ensuring transport-layer and event-layer identities
/// match.
pub fn migrate_recorded_by(conn: &Connection, old: &str, new: &str) -> Result<(), rusqlite::Error> {
    if old == new {
        return Ok(());
    }

    // Use RAII transaction: auto-rolls-back on drop if not committed,
    // preventing partial state on constraint errors.
    let tx = conn.unchecked_transaction()?;

    // Projection tables (recorded_by column)
    for table in &[
        "workspaces",
        "invite_accepted",
        "user_invites",
        "device_invites",
        "users",
        "peers_shared",
        "admins",
        "removed_entities",
        "secret_shared",
        "transport_keys",
        "peer_transport_bindings",
        "messages",
        "reactions",
        "signed_memos",
        "secret_keys",
        "deleted_messages",
        "deletion_intents",
        "message_attachments",
        "file_slices",
        "intro_attempts",
        "peer_endpoint_observations",
        "local_signer_material",
    ] {
        update_identity_column_lossy(&tx, table, "recorded_by", old, new)?;
    }

    // Trust tables (recorded_by column)
    update_identity_column_lossy(
        &tx,
        "invite_bootstrap_trust",
        "recorded_by",
        old,
        new,
    )?;
    update_identity_column_lossy(
        &tx,
        "pending_invite_bootstrap_trust",
        "recorded_by",
        old,
        new,
    )?;
    update_identity_column_lossy(&tx, "bootstrap_context", "recorded_by", old, new)?;

    // Pipeline tables (peer_id column)
    for table in &[
        "valid_events",
        "rejected_events",
        "blocked_event_deps",
        "blocked_events",
        "project_queue",
        "trust_anchors",
        "recorded_events",
    ] {
        update_identity_column_lossy(&tx, table, "peer_id", old, new)?;
    }

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
    // new-identity rows. This keeps migration idempotent under concurrent sync.
    tx.execute(
        &format!("DELETE FROM {} WHERE {} = ?1", table, column),
        rusqlite::params![old],
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
    fn test_migrate_recorded_by() {
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

        // Run migration
        migrate_recorded_by(&conn, old, new).unwrap();

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
    fn test_migrate_recorded_by_collision_dedupes() {
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
        migrate_recorded_by(&conn, old, new).unwrap();

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
}
