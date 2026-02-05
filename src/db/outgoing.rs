use rusqlite::{Connection, Result as SqliteResult, params};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::EventId;

/// Outgoing send queue - events requested by peer
pub struct OutgoingQueue<'a> {
    conn: &'a Connection,
}

impl<'a> OutgoingQueue<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Clear outgoing queue
    pub fn clear(&self) -> SqliteResult<()> {
        self.conn.execute("DELETE FROM outgoing_queue", [])?;
        Ok(())
    }

    /// Enqueue a batch of events. Returns number inserted.
    pub fn enqueue_batch(&self, ids: &[EventId]) -> SqliteResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }

        let now = current_timestamp_ms();
        self.conn.execute("BEGIN", [])?;
        let mut stmt = self.conn.prepare(
            "INSERT OR IGNORE INTO outgoing_queue (id, queued_at) VALUES (?1, ?2)",
        )?;
        let mut inserted = 0usize;
        for id in ids {
            let rows = stmt.execute(params![&id[..], now])?;
            inserted += rows as usize;
        }
        self.conn.execute("COMMIT", [])?;
        Ok(inserted)
    }

    /// Dequeue up to `limit` events (does not delete).
    pub fn dequeue_batch(&self, limit: usize) -> SqliteResult<Vec<EventId>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut stmt = self.conn.prepare(
            "SELECT id FROM outgoing_queue ORDER BY queued_at LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| row.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let blob = row?;
            if blob.len() == 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(&blob);
                out.push(id);
            }
        }
        Ok(out)
    }

    /// Remove a batch of events
    pub fn remove_batch(&self, ids: &[EventId]) -> SqliteResult<()> {
        if ids.is_empty() {
            return Ok(());
        }

        self.conn.execute("BEGIN", [])?;
        let mut stmt = self.conn.prepare("DELETE FROM outgoing_queue WHERE id = ?1")?;
        for id in ids {
            stmt.execute(params![&id[..]])?;
        }
        self.conn.execute("COMMIT", [])?;
        Ok(())
    }

    /// Count total queued events
    pub fn count(&self) -> SqliteResult<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM outgoing_queue", [], |row| row.get(0))
    }
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
