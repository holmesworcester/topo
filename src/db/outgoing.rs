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

    /// Clear outgoing queue for a peer
    pub fn clear_peer(&self, peer_id: &str) -> SqliteResult<()> {
        self.conn.execute(
            "DELETE FROM outgoing_queue WHERE peer_id = ?1",
            params![peer_id],
        )?;
        Ok(())
    }

    /// Enqueue a batch of events for a peer. Returns number inserted.
    pub fn enqueue_batch(&self, peer_id: &str, ids: &[EventId]) -> SqliteResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }

        let now = current_timestamp_ms();
        self.conn.execute("BEGIN", [])?;
        let mut stmt = self.conn.prepare(
            "INSERT OR IGNORE INTO outgoing_queue (peer_id, event_id, enqueued_at, sent_at) VALUES (?1, ?2, ?3, NULL)",
        )?;
        let mut inserted = 0usize;
        for id in ids {
            let rows = stmt.execute(params![peer_id, &id[..], now])?;
            inserted += rows as usize;
        }
        self.conn.execute("COMMIT", [])?;
        Ok(inserted)
    }

    /// Dequeue up to `limit` events (does not delete). Returns rowid + event_id.
    pub fn dequeue_batch(&self, peer_id: &str, limit: usize) -> SqliteResult<Vec<(i64, EventId)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let mut stmt = self.conn.prepare(
            "SELECT id, event_id FROM outgoing_queue WHERE peer_id = ?1 AND sent_at IS NULL ORDER BY enqueued_at LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![peer_id, limit as i64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (rowid, blob) = row?;
            if blob.len() == 32 {
                let mut id = [0u8; 32];
                id.copy_from_slice(&blob);
                out.push((rowid, id));
            }
        }
        Ok(out)
    }

    /// Mark a batch of events as sent by rowid
    pub fn mark_sent_batch(&self, rowids: &[i64]) -> SqliteResult<()> {
        if rowids.is_empty() {
            return Ok(());
        }

        let placeholders = std::iter::repeat("?")
            .take(rowids.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("UPDATE outgoing_queue SET sent_at = ?1 WHERE id IN ({})", placeholders);

        self.conn.execute("BEGIN", [])?;
        let mut params: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(rowids.len() + 1);
        let now = current_timestamp_ms();
        params.push(&now);
        for v in rowids {
            params.push(v as &dyn rusqlite::ToSql);
        }
        self.conn.execute(&sql, params.as_slice())?;
        self.conn.execute("COMMIT", [])?;
        Ok(())
    }

    /// Count pending (unsent) events for a peer
    pub fn count_pending(&self, peer_id: &str) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM outgoing_queue WHERE peer_id = ?1 AND sent_at IS NULL",
            params![peer_id],
            |row| row.get(0),
        )
    }
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
