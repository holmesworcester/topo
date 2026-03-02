use rusqlite::{params, Connection, Result as SqliteResult};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::EventId;

/// Deferred need-id queue for low-memory pull backpressure.
///
/// Stores event IDs that were discovered by reconciliation but not yet
/// requested from the peer due to low-memory watermarks.
pub struct NeedQueue<'a> {
    conn: &'a Connection,
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS deferred_need_events (
            peer_id TEXT NOT NULL,
            id BLOB NOT NULL,
            first_seen_at INTEGER NOT NULL,
            PRIMARY KEY (peer_id, id)
        );
        CREATE INDEX IF NOT EXISTS idx_deferred_need_events_peer_seen
        ON deferred_need_events(peer_id, first_seen_at);
        ",
    )?;
    Ok(())
}

impl<'a> NeedQueue<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    pub fn insert_many(&self, peer_id: &str, ids: &[EventId]) -> SqliteResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let now = current_timestamp_ms();
        let mut stmt = self.conn.prepare(
            "INSERT OR IGNORE INTO deferred_need_events (peer_id, id, first_seen_at)
             VALUES (?1, ?2, ?3)",
        )?;
        let mut inserted = 0usize;
        for id in ids {
            let rows = stmt.execute(params![peer_id, &id[..], now])?;
            if rows > 0 {
                inserted += 1;
            }
        }
        Ok(inserted)
    }

    pub fn peek_batch(&self, peer_id: &str, limit: usize) -> SqliteResult<Vec<EventId>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = self.conn.prepare(
            "SELECT id
             FROM deferred_need_events
             WHERE peer_id = ?1
             ORDER BY first_seen_at, rowid
             LIMIT ?2",
        )?;
        let mut rows = stmt.query(params![peer_id, limit_i64])?;
        let mut out = Vec::new();
        while let Some(row) = rows.next()? {
            let blob: Vec<u8> = row.get(0)?;
            if blob.len() != 32 {
                continue;
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&blob);
            out.push(id);
        }
        Ok(out)
    }

    pub fn remove_many(&self, peer_id: &str, ids: &[EventId]) -> SqliteResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let mut stmt = self
            .conn
            .prepare("DELETE FROM deferred_need_events WHERE peer_id = ?1 AND id = ?2")?;
        let mut removed = 0usize;
        for id in ids {
            let rows = stmt.execute(params![peer_id, &id[..]])?;
            if rows > 0 {
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub fn count(&self, peer_id: &str) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM deferred_need_events WHERE peer_id = ?1",
            params![peer_id],
            |row| row.get(0),
        )
    }

    pub fn clear(&self, peer_id: &str) -> SqliteResult<()> {
        self.conn.execute(
            "DELETE FROM deferred_need_events WHERE peer_id = ?1",
            params![peer_id],
        )?;
        Ok(())
    }
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
