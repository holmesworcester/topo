use rusqlite::{params, Connection, Result as SqliteResult};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::EventId;

/// Wanted events - events we need to fetch from peers
pub struct WantedEvents<'a> {
    conn: &'a Connection,
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS wanted_events (
            id BLOB PRIMARY KEY,
            first_seen_at INTEGER NOT NULL
        );
        ",
    )?;
    Ok(())
}

impl<'a> WantedEvents<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Insert a wanted event if not already present. Returns true if inserted.
    pub fn insert(&self, id: &EventId) -> SqliteResult<bool> {
        let now = current_timestamp_ms();
        let rows = self.conn.execute(
            "INSERT OR IGNORE INTO wanted_events (id, first_seen_at) VALUES (?1, ?2)",
            params![&id[..], now],
        )?;
        Ok(rows > 0)
    }

    /// Remove a wanted event
    pub fn remove(&self, id: &EventId) -> SqliteResult<()> {
        self.conn
            .execute("DELETE FROM wanted_events WHERE id = ?1", params![&id[..]])?;
        Ok(())
    }

    /// Count total wanted events
    pub fn count(&self) -> SqliteResult<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM wanted_events", [], |row| row.get(0))
    }

    /// Clear wanted events
    pub fn clear(&self) -> SqliteResult<()> {
        self.conn.execute("DELETE FROM wanted_events", [])?;
        Ok(())
    }
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
