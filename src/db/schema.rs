use rusqlite::{Connection, Result as SqliteResult};

/// Create all tables for the sync system
pub fn create_tables(conn: &Connection) -> SqliteResult<()> {
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
            id TEXT PRIMARY KEY,        -- Event ID we need
            first_seen_at INTEGER NOT NULL
        );

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
            message_id TEXT PRIMARY KEY,
            channel_id TEXT NOT NULL,
            author_id TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, created_at DESC);

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

        assert!(tables.contains(&"store".to_string()));
        assert!(tables.contains(&"shareable_events".to_string()));
        assert!(tables.contains(&"wanted_events".to_string()));
        assert!(tables.contains(&"incoming_queue".to_string()));
        assert!(tables.contains(&"messages".to_string()));
        assert!(tables.contains(&"neg_items".to_string()));
        assert!(tables.contains(&"neg_blocks".to_string()));
        assert!(tables.contains(&"neg_meta".to_string()));
    }

    #[test]
    fn test_create_tables_idempotent() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        create_tables(&conn).unwrap(); // Should not fail
    }
}
