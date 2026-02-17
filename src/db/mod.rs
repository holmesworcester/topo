pub mod migrations;
pub mod schema;
pub mod store;
pub mod wanted;
pub mod queue;
pub mod project_queue;
pub mod egress_queue;
pub mod health;
pub mod transport_trust;
pub mod intro;
pub mod transport_creds;

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

fn low_mem_mode() -> bool {
    read_bool_env("LOW_MEM_IOS") || read_bool_env("LOW_MEM")
}

fn read_bool_env(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => v != "0" && v.to_lowercase() != "false",
        Err(_) => false,
    }
}

/// Migrate all `recorded_by` / `peer_id` references from `old` to `new` across
/// all projection and trust tables in a single transaction. This is used after
/// a joiner transitions from an invite-derived transport identity to a
/// PeerShared-derived one, ensuring transport-layer and event-layer identities
/// match.
pub fn migrate_recorded_by(
    conn: &Connection,
    old: &str,
    new: &str,
) -> Result<(), rusqlite::Error> {
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
        "message_attachments",
        "file_slices",
        "intro_attempts",
        "peer_endpoint_observations",
    ] {
        tx.execute(
            &format!("UPDATE {} SET recorded_by = ?1 WHERE recorded_by = ?2", table),
            rusqlite::params![new, old],
        )?;
    }

    // Trust tables (recorded_by column)
    tx.execute(
        "UPDATE invite_bootstrap_trust SET recorded_by = ?1 WHERE recorded_by = ?2",
        rusqlite::params![new, old],
    )?;
    tx.execute(
        "UPDATE pending_invite_bootstrap_trust SET recorded_by = ?1 WHERE recorded_by = ?2",
        rusqlite::params![new, old],
    )?;

    // Pipeline tables (peer_id column)
    for table in &[
        "valid_events",
        "rejected_events",
        "blocked_event_deps",
        "blocked_events",
        "project_queue",
        "ingress_queue",
        "trust_anchors",
        "recorded_events",
    ] {
        tx.execute(
            &format!("UPDATE {} SET peer_id = ?1 WHERE peer_id = ?2", table),
            rusqlite::params![new, old],
        )?;
    }

    // Service tables (recorded_by, may not exist)
    let _ = tx.execute(
        "UPDATE local_peer_signers SET recorded_by = ?1 WHERE recorded_by = ?2",
        rusqlite::params![new, old],
    );
    let _ = tx.execute(
        "UPDATE local_workspace_keys SET recorded_by = ?1 WHERE recorded_by = ?2",
        rusqlite::params![new, old],
    );

    tx.commit()?;
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
    }

    #[test]
    fn test_migrate_recorded_by_collision() {
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

        // Migration should fail due to UNIQUE constraint on trust_anchors
        let result = migrate_recorded_by(&conn, old, new);
        assert!(result.is_err(), "migration should fail on PK collision");

        // Verify rollback: messages.recorded_by should still be old
        let rb: String = conn
            .query_row(
                "SELECT recorded_by FROM messages WHERE message_id = 'msg_rollback'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(rb, old, "transaction should have rolled back");
    }
}
