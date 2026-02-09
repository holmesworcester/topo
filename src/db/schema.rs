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

/// Check if the messages table has the old Phase 0 schema (no recorded_by column).
fn needs_messages_migration(conn: &Connection) -> SqliteResult<bool> {
    // If messages table doesn't exist yet, no migration needed (fresh DB).
    let table_exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='messages'",
        [],
        |row| row.get(0),
    )?;
    if !table_exists {
        return Ok(false);
    }

    // Check if recorded_by column exists
    let has_recorded_by: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM pragma_table_info('messages') WHERE name='recorded_by'",
        [],
        |row| row.get(0),
    )?;

    Ok(!has_recorded_by)
}

/// Migrate Phase 0 messages table to Phase 0.5 schema.
/// Adds recorded_by column with empty string default, rebuilds PK to (recorded_by, message_id).
/// Wrapped in an explicit transaction for atomicity.
fn migrate_messages_v1_to_v2(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        BEGIN IMMEDIATE;

        -- Create the new messages table with (recorded_by, message_id) PK
        CREATE TABLE messages_v2 (
            message_id TEXT NOT NULL,
            network_event_id TEXT NOT NULL,
            author_id TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            recorded_by TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (recorded_by, message_id)
        );

        -- Backfill from old table with empty recorded_by sentinel
        INSERT INTO messages_v2 (message_id, network_event_id, author_id, content, created_at, recorded_by)
            SELECT message_id, channel_id, author_id, content, created_at, ''
            FROM messages;

        -- Drop old table and indexes
        DROP TABLE messages;

        -- Rename new table
        ALTER TABLE messages_v2 RENAME TO messages;

        -- Recreate indexes on the new table
        CREATE INDEX IF NOT EXISTS idx_messages_network ON messages(network_event_id, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_messages_recorded ON messages(recorded_by, created_at DESC);

        COMMIT;
        ",
    )?;
    Ok(())
}

/// Backfill legacy rows (recorded_by = '') to the given identity.
/// Returns the number of rows updated.
pub fn backfill_legacy_messages(conn: &Connection, recorded_by: &str) -> SqliteResult<usize> {
    conn.execute(
        "UPDATE messages SET recorded_by = ?1 WHERE recorded_by = ''",
        rusqlite::params![recorded_by],
    )
}

/// Count legacy rows that have not been backfilled (recorded_by = '').
pub fn count_legacy_messages(conn: &Connection) -> SqliteResult<i64> {
    conn.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ''",
        [],
        |row| row.get(0),
    )
}

/// Create all tables for the sync system, migrating from Phase 0 if needed.
pub fn create_tables(conn: &Connection) -> SqliteResult<()> {
    enforce_schema_epoch(conn)?;

    // Check and run migration before CREATE TABLE IF NOT EXISTS
    if needs_messages_migration(conn)? {
        migrate_messages_v1_to_v2(conn)?;
    }

    conn.execute_batch(
        "
        -- Content-addressed blob store
        CREATE TABLE IF NOT EXISTS store (
            id TEXT PRIMARY KEY,        -- Base64 Blake2b-256
            blob BLOB NOT NULL,
            stored_at INTEGER NOT NULL
        );

        -- Events we have and can share (full blob in store)
        CREATE TABLE IF NOT EXISTS shareable_events (
            id TEXT PRIMARY KEY,        -- Event ID (same as store.id)
            stored_at INTEGER NOT NULL
        );

        -- Events we want but don't have yet (from refs we've seen)
        CREATE TABLE IF NOT EXISTS wanted_events (
            id BLOB PRIMARY KEY,        -- 32-byte Event ID
            first_seen_at INTEGER NOT NULL
        );

        -- Outgoing send queue (events requested by peer)
        CREATE TABLE IF NOT EXISTS outgoing_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            peer_id TEXT NOT NULL,
            event_id BLOB NOT NULL,
            enqueued_at INTEGER NOT NULL,
            sent_at INTEGER,
            UNIQUE(peer_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_outgoing_peer ON outgoing_queue(peer_id, enqueued_at);

        -- Incoming queue for projection
        CREATE TABLE IF NOT EXISTS incoming_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            blob BLOB NOT NULL,
            received_at INTEGER NOT NULL,
            processed INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_incoming_unprocessed ON incoming_queue(processed, received_at);

        -- Message projection table
        CREATE TABLE IF NOT EXISTS messages (
            message_id TEXT NOT NULL,
            network_event_id TEXT NOT NULL,
            author_id TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            recorded_by TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (recorded_by, message_id)
        );
        CREATE INDEX IF NOT EXISTS idx_messages_network ON messages(network_event_id, created_at DESC);
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
    run_migrations(conn)?;
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

        assert!(tables.contains(&"store".to_string()));
        assert!(tables.contains(&"shareable_events".to_string()));
        assert!(tables.contains(&"wanted_events".to_string()));
        assert!(tables.contains(&"incoming_queue".to_string()));
        assert!(tables.contains(&"messages".to_string()));
        assert!(tables.contains(&"outgoing_queue".to_string()));
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

    #[test]
    fn test_migrate_phase0_messages_to_phase05() {
        let conn = open_in_memory().unwrap();

        // Create Phase 0 schema: messages with message_id PK, no recorded_by
        conn.execute_batch(
            "
            CREATE TABLE messages (
                message_id TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                author_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX idx_messages_channel ON messages(channel_id, created_at DESC);
            ",
        ).unwrap();

        // Insert some Phase 0 data
        conn.execute(
            "INSERT INTO messages (message_id, channel_id, author_id, content, created_at)
             VALUES ('msg1', 'ch1', 'auth1', 'Hello', 1000)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO messages (message_id, channel_id, author_id, content, created_at)
             VALUES ('msg2', 'ch1', 'auth2', 'World', 2000)",
            [],
        ).unwrap();

        // Run create_tables — should detect old schema and migrate
        create_tables(&conn).unwrap();

        // Verify new schema has recorded_by column
        let has_recorded_by: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('messages') WHERE name='recorded_by'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert!(has_recorded_by);

        // Verify data was preserved with empty recorded_by sentinel
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ''",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 2);

        // Verify content is intact
        let content: String = conn.query_row(
            "SELECT content FROM messages WHERE message_id = 'msg1'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(content, "Hello");

        // Verify PK is now (recorded_by, message_id) by inserting same message_id with different recorded_by
        conn.execute(
            "INSERT INTO messages (message_id, network_event_id, author_id, content, created_at, recorded_by)
             VALUES ('msg1', 'ch1', 'auth1', 'Hello', 1000, 'peer_abc')",
            [],
        ).unwrap();
        let total: i64 = conn.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0)).unwrap();
        assert_eq!(total, 3);

        // Verify idempotent — calling create_tables again should not fail
        create_tables(&conn).unwrap();
    }

    #[test]
    fn test_no_migration_on_fresh_db() {
        let conn = open_in_memory().unwrap();
        // Fresh DB — no messages table yet
        assert!(!needs_messages_migration(&conn).unwrap());
        create_tables(&conn).unwrap();
        // After create_tables, messages exists with recorded_by — no migration needed
        assert!(!needs_messages_migration(&conn).unwrap());
    }

    #[test]
    fn test_backfill_legacy_messages() {
        let conn = open_in_memory().unwrap();

        // Create Phase 0 schema and insert data
        conn.execute_batch(
            "
            CREATE TABLE messages (
                message_id TEXT PRIMARY KEY,
                channel_id TEXT NOT NULL,
                author_id TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            ",
        ).unwrap();
        conn.execute(
            "INSERT INTO messages VALUES ('msg1', 'ch1', 'auth1', 'Hello', 1000)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO messages VALUES ('msg2', 'ch1', 'auth2', 'World', 2000)",
            [],
        ).unwrap();

        // Migrate
        create_tables(&conn).unwrap();

        // Legacy rows exist
        assert_eq!(count_legacy_messages(&conn).unwrap(), 2);

        // Backfill to a concrete identity
        let updated = backfill_legacy_messages(&conn, "peer_abc123").unwrap();
        assert_eq!(updated, 2);

        // No more legacy rows
        assert_eq!(count_legacy_messages(&conn).unwrap(), 0);

        // Messages are now visible under the backfilled identity
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = 'peer_abc123'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 2);

        // Backfill again is a no-op
        let updated = backfill_legacy_messages(&conn, "peer_abc123").unwrap();
        assert_eq!(updated, 0);
    }
}
