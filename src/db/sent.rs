use rusqlite::{Connection, Result as SqliteResult, params};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::EventId;

/// Sent events - dedupe of events already sent in this sync session
pub struct SentEvents<'a> {
    conn: &'a Connection,
}

impl<'a> SentEvents<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Mark an event as sent if not already present. Returns true if inserted.
    pub fn insert(&self, id: &EventId) -> SqliteResult<bool> {
        let now = current_timestamp_ms();
        let rows = self.conn.execute(
            "INSERT OR IGNORE INTO sent_events (id, sent_at) VALUES (?1, ?2)",
            params![&id[..], now],
        )?;
        Ok(rows > 0)
    }

    /// Clear sent events
    pub fn clear(&self) -> SqliteResult<()> {
        self.conn.execute("DELETE FROM sent_events", [])?;
        Ok(())
    }
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
