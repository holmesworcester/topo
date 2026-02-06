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
    fn test_migration_idempotent() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        // Run again — should not fail
        run_migrations(&conn).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_migrations", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
