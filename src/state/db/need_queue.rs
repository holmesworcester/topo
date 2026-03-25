use rusqlite::{params, Connection, Result as SqliteResult};

use super::queue::{current_timestamp_ms, with_immediate_tx, with_sqlite_busy_retry};
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
        with_immediate_tx(self.conn, || {
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
        })
    }

    pub fn peek_batch(&self, peer_id: &str, limit: usize) -> SqliteResult<Vec<EventId>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        with_sqlite_busy_retry(|| {
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
        })
    }

    pub fn remove_many(&self, peer_id: &str, ids: &[EventId]) -> SqliteResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        with_immediate_tx(self.conn, || {
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
        })
    }

    pub fn count(&self, peer_id: &str) -> SqliteResult<i64> {
        with_sqlite_busy_retry(|| {
            self.conn.query_row(
                "SELECT COUNT(*) FROM deferred_need_events WHERE peer_id = ?1",
                params![peer_id],
                |row| row.get(0),
            )
        })
    }

    pub fn clear(&self, peer_id: &str) -> SqliteResult<()> {
        with_sqlite_busy_retry(|| {
            self.conn.execute(
                "DELETE FROM deferred_need_events WHERE peer_id = ?1",
                params![peer_id],
            )?;
            Ok(())
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_connection, schema::create_tables};
    use std::time::Duration;

    fn make_event_id(byte: u8) -> EventId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    #[test]
    fn test_insert_many_retries_transient_busy_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("need.db");

        let setup = open_connection(&path).unwrap();
        setup.busy_timeout(Duration::from_millis(20)).unwrap();
        create_tables(&setup).unwrap();
        drop(setup);

        let lock_conn = open_connection(&path).unwrap();
        lock_conn.busy_timeout(Duration::from_millis(20)).unwrap();
        lock_conn.execute("BEGIN IMMEDIATE", []).unwrap();

        let path_for_thread = path.clone();
        let worker = std::thread::spawn(move || {
            let conn = open_connection(&path_for_thread).unwrap();
            conn.busy_timeout(Duration::from_millis(20)).unwrap();
            let need_queue = NeedQueue::new(&conn);
            need_queue
                .insert_many("peer-a", &[make_event_id(1), make_event_id(2)])
                .unwrap()
        });

        std::thread::sleep(Duration::from_millis(80));
        lock_conn.execute("COMMIT", []).unwrap();

        assert_eq!(worker.join().unwrap(), 2);

        let verify = open_connection(&path).unwrap();
        let need_queue = NeedQueue::new(&verify);
        assert_eq!(need_queue.count("peer-a").unwrap(), 2);
    }
}
