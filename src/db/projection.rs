use rusqlite::{params, Connection, Result as SqliteResult};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::EventId;

/// Projection queue - events awaiting projection
pub struct ProjectionQueue<'a> {
    conn: &'a Connection,
}

impl<'a> ProjectionQueue<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    pub fn clear(&self) -> SqliteResult<()> {
        self.conn.execute("DELETE FROM projection_queue", [])?;
        Ok(())
    }

    pub fn enqueue_batch(&self, ids: &[EventId]) -> SqliteResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }

        let now = current_timestamp_ms();
        self.conn.execute("BEGIN", [])?;
        let mut stmt = self.conn.prepare(
            "INSERT OR IGNORE INTO projection_queue (id, queued_at) VALUES (?1, ?2)",
        )?;
        let mut inserted = 0usize;
        for id in ids {
            let rows = stmt.execute(params![&id[..], now])?;
            inserted += rows as usize;
        }
        self.conn.execute("COMMIT", [])?;
        Ok(inserted)
    }

    pub fn dequeue_batch(&self, limit: usize) -> SqliteResult<Vec<EventId>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut stmt = self.conn.prepare(
            "SELECT id FROM projection_queue ORDER BY queued_at LIMIT ?1",
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

    pub fn remove_batch(&self, ids: &[EventId]) -> SqliteResult<()> {
        if ids.is_empty() {
            return Ok(());
        }

        self.conn.execute("BEGIN", [])?;
        let mut stmt = self.conn.prepare("DELETE FROM projection_queue WHERE id = ?1")?;
        for id in ids {
            stmt.execute(params![&id[..]])?;
        }
        self.conn.execute("COMMIT", [])?;
        Ok(())
    }

    pub fn count(&self) -> SqliteResult<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM projection_queue", [], |row| row.get(0))
    }
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
