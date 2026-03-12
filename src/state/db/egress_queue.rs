use rusqlite::{params, Connection, Result as SqliteResult};

use super::queue::{current_timestamp_ms, with_immediate_tx, with_sqlite_busy_retry};
use crate::crypto::EventId;

pub struct EgressQueue<'a> {
    conn: &'a Connection,
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS egress_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connection_id TEXT NOT NULL,
            frame_type TEXT NOT NULL DEFAULT 'event',
            event_id BLOB,
            payload BLOB,
            enqueued_at INTEGER NOT NULL,
            available_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            lease_until INTEGER,
            sent_at INTEGER,
            dedupe_key TEXT
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_pending_event
            ON egress_queue(connection_id, event_id)
            WHERE frame_type = 'event' AND sent_at IS NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_dedupe
            ON egress_queue(dedupe_key)
            WHERE dedupe_key IS NOT NULL AND sent_at IS NULL;
        CREATE INDEX IF NOT EXISTS idx_egress_claim
            ON egress_queue(connection_id, id)
            WHERE sent_at IS NULL;
        ",
    )?;
    Ok(())
}

impl<'a> EgressQueue<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Enqueue a batch of events for a connection. Deduped by partial unique index
    /// on (connection_id, event_id) WHERE frame_type='event' AND sent_at IS NULL.
    /// Returns number inserted.
    pub fn enqueue_events(
        &self,
        connection_id: &str,
        event_ids: &[EventId],
    ) -> SqliteResult<usize> {
        if event_ids.is_empty() {
            return Ok(0);
        }
        let now = current_timestamp_ms();
        with_immediate_tx(self.conn, || {
            let mut stmt = self.conn.prepare(
                "INSERT OR IGNORE INTO egress_queue
                 (connection_id, frame_type, event_id, enqueued_at, available_at)
                 VALUES (?1, 'event', ?2, ?3, ?3)",
            )?;
            let mut inserted = 0usize;
            for id in event_ids {
                inserted += stmt.execute(params![connection_id, &id[..], now])?;
            }
            Ok(inserted)
        })
    }

    /// Claim a batch of unsent items for sending.
    /// Returns (rowid, event_id) pairs.
    ///
    /// Single-consumer-per-connection makes leases unnecessary — the connection
    /// is cleared at session start and end, so no other consumer races.
    pub fn claim_batch(
        &self,
        connection_id: &str,
        limit: usize,
    ) -> SqliteResult<Vec<(i64, EventId)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        with_sqlite_busy_retry(|| {
            let mut stmt = self.conn.prepare(
                "SELECT id, event_id FROM egress_queue
                 WHERE connection_id = ?1
                 AND sent_at IS NULL
                 ORDER BY id DESC
                 LIMIT ?2",
            )?;
            let rows: Vec<(i64, Vec<u8>)> = stmt
                .query_map(params![connection_id, limit as i64], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;

            let mut result = Vec::with_capacity(rows.len());
            for (rowid, blob) in rows {
                if blob.len() == 32 {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&blob);
                    result.push((rowid, id));
                }
            }
            Ok(result)
        })
    }

    /// Mark items as sent by deleting them from the queue.
    ///
    /// Previously this updated `sent_at` and kept rows for TTL-based cleanup.
    /// Deleting immediately keeps the table small during bulk transfers,
    /// preventing progressive scan degradation. Session-end `clear_connection`
    /// handles any stragglers.
    pub fn mark_sent(&self, rowids: &[i64]) -> SqliteResult<()> {
        if rowids.is_empty() {
            return Ok(());
        }
        with_immediate_tx(self.conn, || {
            let mut stmt = self
                .conn
                .prepare("DELETE FROM egress_queue WHERE id = ?1")?;
            for rowid in rowids {
                stmt.execute(params![rowid])?;
            }
            Ok(())
        })
    }

    /// Count pending (unsent) items for a connection.
    pub fn count_pending(&self, connection_id: &str) -> SqliteResult<i64> {
        with_sqlite_busy_retry(|| {
            self.conn.query_row(
                "SELECT COUNT(*) FROM egress_queue
                 WHERE connection_id = ?1 AND sent_at IS NULL",
                params![connection_id],
                |row| row.get(0),
            )
        })
    }

    /// Delete sent items older than the given threshold.
    pub fn cleanup_sent(&self, older_than_ms: i64) -> SqliteResult<usize> {
        let cutoff = current_timestamp_ms() - older_than_ms;
        with_sqlite_busy_retry(|| {
            self.conn.execute(
                "DELETE FROM egress_queue WHERE sent_at IS NOT NULL AND sent_at < ?1",
                params![cutoff],
            )
        })
    }

    /// Delete all items for a connection.
    pub fn clear_connection(&self, connection_id: &str) -> SqliteResult<()> {
        with_sqlite_busy_retry(|| {
            self.conn.execute(
                "DELETE FROM egress_queue WHERE connection_id = ?1",
                params![connection_id],
            )?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_connection, open_in_memory, schema::create_tables};
    use std::time::Duration;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    fn setup_file_db() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("egress.db");
        let conn = open_connection(&path).unwrap();
        conn.busy_timeout(Duration::from_millis(20)).unwrap();
        create_tables(&conn).unwrap();
        drop(conn);
        (dir, path)
    }

    fn make_event_id(byte: u8) -> EventId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    #[test]
    fn test_enqueue_events() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let ids = vec![make_event_id(1), make_event_id(2), make_event_id(3)];
        let inserted = eq.enqueue_events("conn1", &ids).unwrap();
        assert_eq!(inserted, 3);

        let count = eq.count_pending("conn1").unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn test_enqueue_dedupes() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let id = make_event_id(1);
        eq.enqueue_events("conn1", &[id]).unwrap();
        let inserted = eq.enqueue_events("conn1", &[id]).unwrap();
        assert_eq!(
            inserted, 0,
            "duplicate event_id for same connection should be ignored"
        );

        let count = eq.count_pending("conn1").unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_claim_and_sent() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let ids = vec![make_event_id(1), make_event_id(2)];
        eq.enqueue_events("conn1", &ids).unwrap();

        let claimed = eq.claim_batch("conn1", 10).unwrap();
        assert_eq!(claimed.len(), 2);

        let rowids: Vec<i64> = claimed.iter().map(|(r, _)| *r).collect();
        eq.mark_sent(&rowids).unwrap();

        let pending = eq.count_pending("conn1").unwrap();
        assert_eq!(pending, 0);
    }

    #[test]
    fn test_claim_skips_sent() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let ids = vec![make_event_id(1)];
        eq.enqueue_events("conn1", &ids).unwrap();

        let claimed = eq.claim_batch("conn1", 10).unwrap();
        let rowids: Vec<i64> = claimed.iter().map(|(r, _)| *r).collect();
        eq.mark_sent(&rowids).unwrap();

        // Try claiming again — should get nothing
        let claimed2 = eq.claim_batch("conn1", 10).unwrap();
        assert_eq!(claimed2.len(), 0, "sent items should not be re-claimed");
    }

    #[test]
    fn test_mark_sent_deletes() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let ids = vec![make_event_id(1), make_event_id(2)];
        eq.enqueue_events("conn1", &ids).unwrap();

        let claimed = eq.claim_batch("conn1", 10).unwrap();
        let rowids: Vec<i64> = claimed.iter().map(|(r, _)| *r).collect();
        eq.mark_sent(&rowids).unwrap();

        // mark_sent now deletes rows — total count should be 0
        let total: i64 = conn
            .query_row("SELECT COUNT(*) FROM egress_queue", [], |row| row.get(0))
            .unwrap();
        assert_eq!(total, 0);
    }

    #[test]
    fn test_clear_connection() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let ids = vec![make_event_id(1), make_event_id(2)];
        eq.enqueue_events("conn1", &ids).unwrap();
        eq.enqueue_events("conn2", &[make_event_id(3)]).unwrap();

        eq.clear_connection("conn1").unwrap();

        let count1 = eq.count_pending("conn1").unwrap();
        let count2 = eq.count_pending("conn2").unwrap();
        assert_eq!(count1, 0);
        assert_eq!(count2, 1, "conn2's items should be unaffected");
    }

    #[test]
    fn test_enqueue_events_retries_transient_busy_lock() {
        let (_dir, path) = setup_file_db();

        let lock_conn = open_connection(&path).unwrap();
        lock_conn.busy_timeout(Duration::from_millis(20)).unwrap();
        lock_conn.execute("BEGIN IMMEDIATE", []).unwrap();

        let path_for_thread = path.clone();
        let worker = std::thread::spawn(move || {
            let conn = open_connection(&path_for_thread).unwrap();
            conn.busy_timeout(Duration::from_millis(20)).unwrap();
            let eq = EgressQueue::new(&conn);
            eq.enqueue_events("conn1", &[make_event_id(1)]).unwrap()
        });

        std::thread::sleep(Duration::from_millis(80));
        lock_conn.execute("COMMIT", []).unwrap();

        let inserted = worker.join().unwrap();
        assert_eq!(inserted, 1);

        let verify = open_connection(&path).unwrap();
        let eq = EgressQueue::new(&verify);
        assert_eq!(eq.count_pending("conn1").unwrap(), 1);
    }

    #[test]
    fn test_mark_sent_retries_transient_busy_lock() {
        let (_dir, path) = setup_file_db();

        let conn = open_connection(&path).unwrap();
        conn.busy_timeout(Duration::from_millis(20)).unwrap();
        let eq = EgressQueue::new(&conn);
        eq.enqueue_events("conn1", &[make_event_id(1)]).unwrap();
        let claimed = eq.claim_batch("conn1", 1).unwrap();
        let rowids: Vec<i64> = claimed.iter().map(|(rowid, _)| *rowid).collect();
        drop(conn);

        let lock_conn = open_connection(&path).unwrap();
        lock_conn.busy_timeout(Duration::from_millis(20)).unwrap();
        lock_conn.execute("BEGIN IMMEDIATE", []).unwrap();

        let path_for_thread = path.clone();
        let worker = std::thread::spawn(move || {
            let conn = open_connection(&path_for_thread).unwrap();
            conn.busy_timeout(Duration::from_millis(20)).unwrap();
            let eq = EgressQueue::new(&conn);
            eq.mark_sent(&rowids).unwrap();
        });

        std::thread::sleep(Duration::from_millis(80));
        lock_conn.execute("COMMIT", []).unwrap();
        worker.join().unwrap();

        let verify = open_connection(&path).unwrap();
        let eq = EgressQueue::new(&verify);
        assert_eq!(eq.count_pending("conn1").unwrap(), 0);
    }

    #[test]
    fn test_claim_batch_returns_newest_first() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        // Enqueue 100 "old" events
        let old_ids: Vec<EventId> = (0u8..100).map(make_event_id).collect();
        eq.enqueue_events("conn1", &old_ids).unwrap();

        // Enqueue 1 "new" event with a distinct byte
        let new_id = make_event_id(200);
        eq.enqueue_events("conn1", &[new_id]).unwrap();

        // Claim a small batch — newest should come first
        let claimed = eq.claim_batch("conn1", 5).unwrap();
        assert_eq!(claimed.len(), 5);

        // The very first claimed event should be the newest (byte 200)
        assert_eq!(
            claimed[0].1, new_id,
            "newest event should be returned first by claim_batch"
        );

        // The remaining 4 should be the next-most-recent old events (99, 98, 97, 96)
        assert_eq!(claimed[1].1, make_event_id(99));
        assert_eq!(claimed[2].1, make_event_id(98));
        assert_eq!(claimed[3].1, make_event_id(97));
        assert_eq!(claimed[4].1, make_event_id(96));
    }

    #[test]
    fn test_claim_batch_newest_first_survives_mark_sent() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        // Enqueue old backlog
        let old_ids: Vec<EventId> = (0u8..50).map(make_event_id).collect();
        eq.enqueue_events("conn1", &old_ids).unwrap();

        // Enqueue new priority event
        let priority_id = make_event_id(255);
        eq.enqueue_events("conn1", &[priority_id]).unwrap();

        // First claim: should get priority + 4 newest old
        let batch1 = eq.claim_batch("conn1", 5).unwrap();
        assert_eq!(batch1[0].1, priority_id);

        // Mark first batch as sent
        let rowids: Vec<i64> = batch1.iter().map(|(r, _)| *r).collect();
        eq.mark_sent(&rowids).unwrap();

        // Second claim: should get next batch of old events in descending order
        let batch2 = eq.claim_batch("conn1", 5).unwrap();
        assert_eq!(batch2.len(), 5);
        // After removing priority(255), 49, 48, 47, 46 from the first batch,
        // the next batch should be 45, 44, 43, 42, 41
        assert_eq!(batch2[0].1, make_event_id(45));
        assert_eq!(batch2[1].1, make_event_id(44));

        // Mark second batch as sent
        let rowids2: Vec<i64> = batch2.iter().map(|(r, _)| *r).collect();
        eq.mark_sent(&rowids2).unwrap();

        // Total remaining should be 51 - 5 - 5 = 41
        assert_eq!(eq.count_pending("conn1").unwrap(), 41);
    }
}
