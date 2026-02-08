use rusqlite::{Connection, Result as SqliteResult};
use std::time::{SystemTime, UNIX_EPOCH};

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

static MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "add_events_and_reactions",
        sql: "
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                blob BLOB NOT NULL,
                share_scope TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                inserted_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS valid_events (
                peer_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                PRIMARY KEY (peer_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS rejected_events (
                peer_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                rejected_at INTEGER NOT NULL,
                PRIMARY KEY (peer_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS peer_endpoint_observations (
                recorded_by TEXT NOT NULL,
                via_peer_id TEXT NOT NULL,
                origin_ip TEXT NOT NULL,
                origin_port INTEGER NOT NULL,
                observed_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (recorded_by, via_peer_id, origin_ip, origin_port, observed_at)
            );

            CREATE TABLE IF NOT EXISTS reactions (
                event_id TEXT NOT NULL,
                target_event_id TEXT NOT NULL,
                author_id TEXT NOT NULL,
                emoji TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                recorded_by TEXT NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_reactions_target ON reactions(recorded_by, target_event_id);
        ",
    },
    Migration {
        version: 2,
        name: "add_blocked_event_deps",
        sql: "
            CREATE TABLE IF NOT EXISTS blocked_event_deps (
                peer_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                blocker_event_id TEXT NOT NULL,
                PRIMARY KEY (peer_id, event_id, blocker_event_id)
            );
            CREATE INDEX IF NOT EXISTS idx_blocked_by_dep
                ON blocked_event_deps(peer_id, blocker_event_id);
        ",
    },
    Migration {
        version: 3,
        name: "add_peer_keys_and_signed_memos",
        sql: "
            CREATE TABLE IF NOT EXISTS peer_keys (
                event_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                recorded_by TEXT NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );

            CREATE TABLE IF NOT EXISTS signed_memos (
                event_id TEXT NOT NULL,
                signed_by TEXT NOT NULL,
                signer_type INTEGER NOT NULL,
                content TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                recorded_by TEXT NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );
        ",
    },
    Migration {
        version: 4,
        name: "add_secret_keys",
        sql: "
            CREATE TABLE IF NOT EXISTS secret_keys (
                event_id TEXT NOT NULL,
                key_bytes BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                recorded_by TEXT NOT NULL,
                PRIMARY KEY (recorded_by, event_id)
            );
        ",
    },
    Migration {
        version: 5,
        name: "add_queue_tables",
        sql: "
            CREATE TABLE IF NOT EXISTS project_queue (
                peer_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                available_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                lease_until INTEGER,
                PRIMARY KEY (peer_id, event_id)
            );

            CREATE TABLE IF NOT EXISTS egress_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                connection_id TEXT NOT NULL,
                frame_type TEXT NOT NULL DEFAULT 'event',
                event_id BLOB,
                payload BLOB,
                enqueued_at INTEGER NOT NULL,
                available_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                lease_until INTEGER,
                sent_at INTEGER,
                dedupe_key TEXT
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_pending_event
                ON egress_queue(connection_id, event_id)
                WHERE frame_type = 'event' AND sent_at IS NULL;
            CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_dedupe
                ON egress_queue(dedupe_key)
                WHERE dedupe_key IS NOT NULL AND sent_at IS NULL;

            CREATE TABLE IF NOT EXISTS ingress_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_id TEXT NOT NULL,
                from_addr TEXT,
                received_at INTEGER NOT NULL,
                frame BLOB NOT NULL,
                processed INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_ingress_unprocessed
                ON ingress_queue(processed, received_at);
        ",
    },
    Migration {
        version: 6,
        name: "add_deleted_messages",
        sql: "
            CREATE TABLE IF NOT EXISTS deleted_messages (
                recorded_by TEXT NOT NULL,
                message_id TEXT NOT NULL,
                deletion_event_id TEXT NOT NULL,
                author_id TEXT NOT NULL,
                deleted_at INTEGER NOT NULL,
                PRIMARY KEY (recorded_by, message_id)
            );
        ",
    },
    Migration {
        version: 7,
        name: "add_peer_endpoint_indexes",
        sql: "
            CREATE INDEX IF NOT EXISTS idx_peer_endpoint_expires
                ON peer_endpoint_observations(recorded_by, via_peer_id, expires_at);
            CREATE INDEX IF NOT EXISTS idx_peer_endpoint_lookup
                ON peer_endpoint_observations(recorded_by, via_peer_id, origin_ip, origin_port);
        ",
    },
];

fn ensure_schema_migrations(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at INTEGER NOT NULL
        );",
    )
}

pub fn run_migrations(conn: &Connection) -> SqliteResult<()> {
    ensure_schema_migrations(conn)?;

    for migration in MIGRATIONS {
        let already_applied: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM schema_migrations WHERE version = ?1",
            [migration.version],
            |row| row.get(0),
        )?;

        if !already_applied {
            conn.execute_batch(migration.sql)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;
            conn.execute(
                "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![migration.version, migration.name, now],
            )?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;

    #[test]
    fn test_migration_runner() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(tables.contains(&"events".to_string()));
        assert!(tables.contains(&"valid_events".to_string()));
        assert!(tables.contains(&"rejected_events".to_string()));
        assert!(tables.contains(&"peer_endpoint_observations".to_string()));
        assert!(tables.contains(&"reactions".to_string()));
        assert!(tables.contains(&"schema_migrations".to_string()));
    }

    #[test]
    fn test_migration_2_blocked_event_deps() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Table exists
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(tables.contains(&"blocked_event_deps".to_string()));

        // Can insert and query
        conn.execute(
            "INSERT INTO blocked_event_deps (peer_id, event_id, blocker_event_id) VALUES ('p1', 'e1', 'b1')",
            [],
        ).unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = 'p1'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);

        // Idempotent — running migrations again doesn't fail
        run_migrations(&conn).unwrap();
        let count2: i64 = conn.query_row(
            "SELECT COUNT(*) FROM blocked_event_deps", [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count2, 1);

        // Migration version recorded
        let versions: Vec<i64> = conn
            .prepare("SELECT version FROM schema_migrations ORDER BY version")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(versions.contains(&2));
    }

    #[test]
    fn test_migration_idempotent() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        // Run again — should not fail
        run_migrations(&conn).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 7);
    }
}
