use rusqlite::{Connection, ErrorCode, OptionalExtension, Result as SqliteResult};

use super::migrations::run_migrations;

/// Prototype schema epoch for the workspace-era database layout.
///
/// This prototype intentionally does not support backward migration from older
/// schema layouts. Existing DBs from prior epochs must be recreated.
const PROTOTYPE_SCHEMA_EPOCH: i64 = 1;

fn table_exists(conn: &Connection, table_name: &str) -> SqliteResult<bool> {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
        rusqlite::params![table_name],
        |row| row.get(0),
    )
}

fn incompatible_epoch_error(detail: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error {
            code: ErrorCode::Unknown,
            extended_code: 1,
        },
        Some(format!(
            "incompatible prototype DB schema epoch: {}. This prototype has no backward migration; recreate the database file.",
            detail
        )),
    )
}

/// Enforce an explicit schema epoch marker so incompatible prototype DBs fail
/// with a clear error instead of surfacing later as SQL/table mismatches.
///
/// Policy:
/// - Fresh DB (no schema_migrations, no schema_epoch): initialize schema_epoch.
/// - Current epoch DB: proceed.
/// - Legacy migrated DB (has schema_migrations but no schema_epoch): reject.
/// - Wrong/invalid epoch: reject.
fn enforce_schema_epoch(conn: &Connection) -> SqliteResult<()> {
    let has_epoch = table_exists(conn, "schema_epoch")?;
    if has_epoch {
        let epoch_opt: Option<i64> = conn
            .query_row("SELECT epoch FROM schema_epoch LIMIT 1", [], |row| row.get(0))
            .optional()?;
        let epoch = match epoch_opt {
            Some(v) => v,
            None => {
                return Err(incompatible_epoch_error(
                    "schema_epoch table exists but has no rows",
                ))
            }
        };
        if epoch != PROTOTYPE_SCHEMA_EPOCH {
            return Err(incompatible_epoch_error(&format!(
                "expected epoch {}, found {}",
                PROTOTYPE_SCHEMA_EPOCH, epoch
            )));
        }
        return Ok(());
    }

    // Legacy DBs already migrated by older prototype versions have schema_migrations
    // but no schema_epoch marker. Reject these explicitly.
    let has_migrations = table_exists(conn, "schema_migrations")?;
    if has_migrations {
        return Err(incompatible_epoch_error(
            "legacy schema_migrations detected without schema_epoch marker",
        ));
    }

    // Fresh DB: initialize epoch marker.
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_epoch (
            epoch INTEGER NOT NULL
        );",
    )?;
    conn.execute(
        "INSERT INTO schema_epoch (epoch) VALUES (?1)",
        rusqlite::params![PROTOTYPE_SCHEMA_EPOCH],
    )?;
    Ok(())
}

/// Create all tables for the sync system.
pub fn create_tables(conn: &Connection) -> SqliteResult<()> {
    enforce_schema_epoch(conn)?;

    // Run column-rename migrations before DDL so that existing DBs with
    // `network_event_id` get renamed to `workspace_id` before the
    // CREATE INDEX references the new column name.
    run_migrations(conn)?;

    conn.execute_batch(
        "
        -- Events we want but don't have yet (from refs we've seen)
        CREATE TABLE IF NOT EXISTS wanted_events (
            id BLOB PRIMARY KEY,        -- 32-byte Event ID
            first_seen_at INTEGER NOT NULL
        );

        -- Message projection table
        CREATE TABLE IF NOT EXISTS messages (
            message_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            author_id TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            recorded_by TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (recorded_by, message_id)
        );
        CREATE INDEX IF NOT EXISTS idx_messages_workspace ON messages(workspace_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_messages_recorded ON messages(recorded_by, created_at DESC);

        -- Per-tenant receive/create journal
        CREATE TABLE IF NOT EXISTS recorded_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            recorded_at INTEGER NOT NULL,
            source TEXT NOT NULL,
            UNIQUE(peer_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_recorded_peer_order ON recorded_events(peer_id, id);

        -- Negentropy items: sorted by (ts, id) for range-based reconciliation
        CREATE TABLE IF NOT EXISTS neg_items (
            ts INTEGER NOT NULL,        -- created_at_ms timestamp
            id BLOB NOT NULL,           -- 32-byte event ID (raw, not base64)
            PRIMARY KEY (ts, id)
        ) WITHOUT ROWID;

        -- Negentropy block index: sparse index every B items for O(1) index lookup
        CREATE TABLE IF NOT EXISTS neg_blocks (
            block_idx INTEGER PRIMARY KEY,  -- block number (item_index / B)
            ts INTEGER NOT NULL,            -- timestamp of first item in block
            id BLOB NOT NULL,               -- id of first item in block
            count INTEGER NOT NULL          -- cumulative count up to this block
        );

        -- Negentropy metadata: tracks rebuild state
        CREATE TABLE IF NOT EXISTS neg_meta (
            key TEXT PRIMARY KEY,
            value INTEGER NOT NULL
        );
        ",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;

    #[test]
    fn test_create_tables() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Verify tables exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        assert!(tables.contains(&"wanted_events".to_string()));
        assert!(tables.contains(&"messages".to_string()));
        assert!(tables.contains(&"neg_items".to_string()));
        assert!(tables.contains(&"neg_blocks".to_string()));
        assert!(tables.contains(&"neg_meta".to_string()));
        assert!(tables.contains(&"recorded_events".to_string()));
        assert!(tables.contains(&"schema_epoch".to_string()));

        let epoch: i64 = conn
            .query_row("SELECT epoch FROM schema_epoch LIMIT 1", [], |row| row.get(0))
            .unwrap();
        assert_eq!(epoch, PROTOTYPE_SCHEMA_EPOCH);
    }

    #[test]
    fn test_create_tables_idempotent() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        create_tables(&conn).unwrap(); // Should not fail

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_epoch", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_reject_legacy_db_without_epoch_marker() {
        let conn = open_in_memory().unwrap();

        // Simulate an older prototype DB that already has migration state but no
        // schema_epoch marker.
        conn.execute_batch(
            "
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at INTEGER NOT NULL
            );
            INSERT INTO schema_migrations (version, name, applied_at)
            VALUES (8, 'add_identity_tables', 0);
            ",
        )
        .unwrap();

        let err = create_tables(&conn).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("incompatible prototype DB schema epoch"),
            "unexpected error: {}",
            msg
        );
    }

}
