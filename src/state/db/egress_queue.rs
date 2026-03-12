use rusqlite::{params, Connection, Result as SqliteResult};

use super::queue::{current_timestamp_ms, with_immediate_tx, with_sqlite_busy_retry};
use crate::crypto::{event_id_to_base64, EventId};

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
            dedupe_key TEXT,
            event_ts INTEGER
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
        CREATE INDEX IF NOT EXISTS idx_egress_ts_claim
            ON egress_queue(connection_id, event_ts DESC, id DESC)
            WHERE sent_at IS NULL;
        ",
    )?;
    // Add event_ts column to existing DBs that lack it (idempotent).
    let has_event_ts: bool = conn
        .prepare("SELECT event_ts FROM egress_queue LIMIT 0")
        .is_ok();
    if !has_event_ts {
        conn.execute_batch("ALTER TABLE egress_queue ADD COLUMN event_ts INTEGER")?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_egress_ts_claim
             ON egress_queue(connection_id, event_ts DESC, id DESC)
             WHERE sent_at IS NULL",
        )?;
    }
    Ok(())
}

impl<'a> EgressQueue<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Enqueue a batch of events for a connection. Deduped by partial unique index
    /// on (connection_id, event_id) WHERE frame_type='event' AND sent_at IS NULL.
    ///
    /// Looks up the event's `created_at` timestamp from the events table so that
    /// `claim_batch` can prioritize newer events over older ones. Events not found
    /// in the events table get `event_ts = NULL` and sort last.
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
            let mut ts_stmt = self.conn.prepare(
                "SELECT created_at FROM events WHERE event_id = ?1",
            )?;
            let mut insert_stmt = self.conn.prepare(
                "INSERT OR IGNORE INTO egress_queue
                 (connection_id, frame_type, event_id, enqueued_at, available_at, event_ts)
                 VALUES (?1, 'event', ?2, ?3, ?3, ?4)",
            )?;
            let mut inserted = 0usize;
            for id in event_ids {
                let id_b64 = event_id_to_base64(id);
                let event_ts: Option<i64> = ts_stmt
                    .query_row(params![id_b64], |row| row.get(0))
                    .ok();
                inserted += insert_stmt.execute(params![connection_id, &id[..], now, event_ts])?;
            }
            Ok(inserted)
        })
    }

    /// Claim a batch of unsent items for sending.
    /// Returns (rowid, event_id) pairs ordered newest-event-first.
    ///
    /// Events are sorted by their original creation timestamp (`event_ts`) in
    /// descending order so that recently-created events (e.g. new messages) are
    /// sent before older backlog (e.g. bulk file slices). Events with unknown
    /// timestamps sort last. Ties are broken by rowid descending.
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
                 ORDER BY event_ts IS NULL, event_ts DESC, id DESC
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

    /// Helper: insert a synthetic event row directly into the events table so
    /// that `enqueue_events` can look up its `created_at` timestamp.
    fn insert_synthetic_event(conn: &Connection, event_id: &EventId, created_at_ms: i64) {
        use crate::crypto::event_id_to_base64;
        let id_b64 = event_id_to_base64(event_id);
        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, 'message', X'00', 'shared', ?2, ?2)",
            params![id_b64, created_at_ms],
        )
        .unwrap();
    }

    #[test]
    fn test_claim_batch_returns_newest_first() {
        let conn = setup();

        // Create three events with distinct timestamps:
        // old (ts=1000), medium (ts=2000), new (ts=3000)
        let old_id = make_event_id(1);
        let mid_id = make_event_id(2);
        let new_id = make_event_id(3);

        insert_synthetic_event(&conn, &old_id, 1000);
        insert_synthetic_event(&conn, &mid_id, 2000);
        insert_synthetic_event(&conn, &new_id, 3000);

        // Enqueue in old-to-new order (simulating bulk discovery)
        let eq = EgressQueue::new(&conn);
        eq.enqueue_events("conn1", &[old_id, mid_id, new_id])
            .unwrap();

        // claim_batch should return newest first
        let claimed = eq.claim_batch("conn1", 10).unwrap();
        assert_eq!(claimed.len(), 3);
        assert_eq!(claimed[0].1, new_id, "newest event should be first");
        assert_eq!(claimed[1].1, mid_id, "middle event should be second");
        assert_eq!(claimed[2].1, old_id, "oldest event should be last");
    }

    #[test]
    fn test_claim_batch_newest_first_regardless_of_enqueue_order() {
        let conn = setup();

        // New message created now, old backlog created yesterday
        let new_msg = make_event_id(10);
        let old_backlog_1 = make_event_id(20);
        let old_backlog_2 = make_event_id(30);

        let yesterday = 1_700_000_000_000i64;
        let now = 1_700_100_000_000i64;

        insert_synthetic_event(&conn, &old_backlog_1, yesterday);
        insert_synthetic_event(&conn, &old_backlog_2, yesterday + 1);
        insert_synthetic_event(&conn, &new_msg, now);

        let eq = EgressQueue::new(&conn);

        // Enqueue old backlog first (as would happen in reconciliation),
        // then the new message
        eq.enqueue_events("peer1", &[old_backlog_1, old_backlog_2])
            .unwrap();
        eq.enqueue_events("peer1", &[new_msg]).unwrap();

        // New message should come first despite being enqueued last
        let claimed = eq.claim_batch("peer1", 10).unwrap();
        assert_eq!(claimed.len(), 3);
        assert_eq!(
            claimed[0].1, new_msg,
            "new message should be sent before old backlog"
        );
    }

    #[test]
    fn test_claim_batch_null_ts_sorts_last() {
        let conn = setup();

        // Event with known timestamp
        let known_id = make_event_id(1);
        insert_synthetic_event(&conn, &known_id, 5000);

        // Event without a row in events table (unknown timestamp)
        let unknown_id = make_event_id(2);

        let eq = EgressQueue::new(&conn);
        eq.enqueue_events("conn1", &[unknown_id, known_id])
            .unwrap();

        let claimed = eq.claim_batch("conn1", 10).unwrap();
        assert_eq!(claimed.len(), 2);
        assert_eq!(
            claimed[0].1, known_id,
            "event with known timestamp should come first"
        );
        assert_eq!(
            claimed[1].1, unknown_id,
            "event with NULL timestamp should sort last"
        );
    }

    #[test]
    fn test_enqueue_stores_event_ts_from_events_table() {
        let conn = setup();

        let id = make_event_id(42);
        let expected_ts = 1_700_050_000_000i64;
        insert_synthetic_event(&conn, &id, expected_ts);

        let eq = EgressQueue::new(&conn);
        eq.enqueue_events("conn1", &[id]).unwrap();

        // Verify the stored event_ts matches
        let stored_ts: Option<i64> = conn
            .query_row(
                "SELECT event_ts FROM egress_queue WHERE connection_id = 'conn1' LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_ts, Some(expected_ts));
    }

    #[test]
    fn test_claim_batch_interleaved_timestamps() {
        let conn = setup();

        // Simulate a realistic scenario: 5 old file slices and 1 new message
        let mut old_slices = Vec::new();
        for i in 0..5u8 {
            let id = make_event_id(i + 1);
            insert_synthetic_event(&conn, &id, 1_000_000 + i as i64);
            old_slices.push(id);
        }
        let new_message = make_event_id(99);
        insert_synthetic_event(&conn, &new_message, 9_000_000);

        let eq = EgressQueue::new(&conn);

        // Enqueue slices first, then message (as would happen in reconciliation)
        eq.enqueue_events("peer1", &old_slices).unwrap();
        eq.enqueue_events("peer1", &[new_message]).unwrap();

        // Claim just 2 — new message should be in this first batch
        let claimed = eq.claim_batch("peer1", 2).unwrap();
        assert_eq!(claimed.len(), 2);
        assert_eq!(
            claimed[0].1, new_message,
            "new message should be claimed first, ahead of 5 old file slices"
        );
    }
}
