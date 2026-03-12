use rusqlite::{params, Connection, Result as SqliteResult};

use super::queue::{current_timestamp_ms, with_immediate_tx, with_sqlite_busy_retry};
use crate::crypto::{event_id_to_base64, EventId};

/// Priority for high-importance events (messages, reactions, identity, keys).
pub const PRIORITY_HIGH: i64 = 0;
/// Priority for bulk/background events (file, file_slice, bench_dep).
pub const PRIORITY_LOW: i64 = 1;

/// Classify an event type code into an egress priority.
///
/// LOW priority: file (24), file_slice (25), bench_dep (26).
/// Everything else is HIGH (messages, reactions, identity, keys, unknown).
pub fn priority_for_type_code(type_code: u8) -> i64 {
    match type_code {
        24 | 25 | 26 => PRIORITY_LOW,
        _ => PRIORITY_HIGH,
    }
}

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
            priority INTEGER NOT NULL DEFAULT 0
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_pending_event
            ON egress_queue(connection_id, event_id)
            WHERE frame_type = 'event' AND sent_at IS NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_dedupe
            ON egress_queue(dedupe_key)
            WHERE dedupe_key IS NOT NULL AND sent_at IS NULL;
        CREATE INDEX IF NOT EXISTS idx_egress_priority_claim
            ON egress_queue(connection_id, priority, id)
            WHERE sent_at IS NULL;
        ",
    )?;
    Ok(())
}

impl<'a> EgressQueue<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Enqueue a batch of events for a connection at default (HIGH) priority.
    /// Deduped by partial unique index on (connection_id, event_id) WHERE
    /// frame_type='event' AND sent_at IS NULL.
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
                 (connection_id, frame_type, event_id, enqueued_at, available_at, priority)
                 VALUES (?1, 'event', ?2, ?3, ?3, ?4)",
            )?;
            let mut inserted = 0usize;
            for id in event_ids {
                inserted += stmt.execute(params![connection_id, &id[..], now, PRIORITY_HIGH])?;
            }
            Ok(inserted)
        })
    }

    /// Enqueue a batch of events with priority derived from the store.
    ///
    /// For each event_id, reads the first byte of the blob from the events
    /// table to determine the type code, then classifies priority. If the
    /// blob is not found, defaults to HIGH priority (safe fallback: don't
    /// delay unknown events).
    pub fn enqueue_events_with_priority(
        &self,
        connection_id: &str,
        event_ids: &[EventId],
    ) -> SqliteResult<usize> {
        if event_ids.is_empty() {
            return Ok(0);
        }
        let now = current_timestamp_ms();
        with_immediate_tx(self.conn, || {
            // Prepare a statement to read just the first byte of the blob.
            // substr(blob,1,1) returns the first byte efficiently without
            // reading the entire blob into memory.
            let mut type_stmt = self.conn.prepare(
                "SELECT substr(blob, 1, 1) FROM events
                 WHERE event_id = ?1 AND share_scope = 'shared'",
            )?;
            let mut insert_stmt = self.conn.prepare(
                "INSERT OR IGNORE INTO egress_queue
                 (connection_id, frame_type, event_id, enqueued_at, available_at, priority)
                 VALUES (?1, 'event', ?2, ?3, ?3, ?4)",
            )?;
            let mut inserted = 0usize;
            for id in event_ids {
                let id_b64 = event_id_to_base64(id);
                let priority = match type_stmt.query_row(params![id_b64], |row| {
                    row.get::<_, Vec<u8>>(0)
                }) {
                    Ok(first_byte) if !first_byte.is_empty() => {
                        priority_for_type_code(first_byte[0])
                    }
                    _ => PRIORITY_HIGH, // fallback: don't delay unknown events
                };
                inserted +=
                    insert_stmt.execute(params![connection_id, &id[..], now, priority])?;
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
                 ORDER BY priority, id
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
    fn test_priority_for_type_code() {
        // Messages, reactions, identity events -> HIGH
        assert_eq!(priority_for_type_code(1), PRIORITY_HIGH); // message
        assert_eq!(priority_for_type_code(2), PRIORITY_HIGH); // reaction
        assert_eq!(priority_for_type_code(7), PRIORITY_HIGH); // message_deletion
        assert_eq!(priority_for_type_code(8), PRIORITY_HIGH); // workspace
        assert_eq!(priority_for_type_code(14), PRIORITY_HIGH); // user
        assert_eq!(priority_for_type_code(22), PRIORITY_HIGH); // key_shared

        // Bulk/background events -> LOW
        assert_eq!(priority_for_type_code(24), PRIORITY_LOW); // file
        assert_eq!(priority_for_type_code(25), PRIORITY_LOW); // file_slice
        assert_eq!(priority_for_type_code(26), PRIORITY_LOW); // bench_dep

        // Unknown -> HIGH (safe fallback)
        assert_eq!(priority_for_type_code(99), PRIORITY_HIGH);
        assert_eq!(priority_for_type_code(0), PRIORITY_HIGH);
    }

    #[test]
    fn test_claim_batch_respects_priority_ordering() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        // Enqueue three LOW-priority events first (they get lower rowids)
        let now = super::current_timestamp_ms();
        conn.execute(
            "INSERT INTO egress_queue (connection_id, frame_type, event_id, enqueued_at, available_at, priority)
             VALUES ('peer1', 'event', ?1, ?2, ?2, ?3)",
            params![&make_event_id(10)[..], now, PRIORITY_LOW],
        ).unwrap();
        conn.execute(
            "INSERT INTO egress_queue (connection_id, frame_type, event_id, enqueued_at, available_at, priority)
             VALUES ('peer1', 'event', ?1, ?2, ?2, ?3)",
            params![&make_event_id(11)[..], now, PRIORITY_LOW],
        ).unwrap();
        conn.execute(
            "INSERT INTO egress_queue (connection_id, frame_type, event_id, enqueued_at, available_at, priority)
             VALUES ('peer1', 'event', ?1, ?2, ?2, ?3)",
            params![&make_event_id(12)[..], now, PRIORITY_LOW],
        ).unwrap();

        // Now enqueue one HIGH-priority event (higher rowid, but should come first)
        conn.execute(
            "INSERT INTO egress_queue (connection_id, frame_type, event_id, enqueued_at, available_at, priority)
             VALUES ('peer1', 'event', ?1, ?2, ?2, ?3)",
            params![&make_event_id(1)[..], now, PRIORITY_HIGH],
        ).unwrap();

        // Claim all 4 — HIGH should come first despite having the highest rowid
        let claimed = eq.claim_batch("peer1", 10).unwrap();
        assert_eq!(claimed.len(), 4);

        // First event should be the HIGH-priority one (event_id byte 1)
        assert_eq!(
            claimed[0].1[0], 1,
            "HIGH-priority message should be claimed before LOW-priority file slices"
        );
        // Remaining three should be the LOW-priority events in id order
        assert_eq!(claimed[1].1[0], 10);
        assert_eq!(claimed[2].1[0], 11);
        assert_eq!(claimed[3].1[0], 12);
    }

    #[test]
    fn test_claim_batch_priority_with_limit() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let now = super::current_timestamp_ms();
        // Enqueue 3 LOW first, then 2 HIGH
        for byte in [10u8, 11, 12] {
            conn.execute(
                "INSERT INTO egress_queue (connection_id, frame_type, event_id, enqueued_at, available_at, priority)
                 VALUES ('peer1', 'event', ?1, ?2, ?2, ?3)",
                params![&make_event_id(byte)[..], now, PRIORITY_LOW],
            ).unwrap();
        }
        for byte in [1u8, 2] {
            conn.execute(
                "INSERT INTO egress_queue (connection_id, frame_type, event_id, enqueued_at, available_at, priority)
                 VALUES ('peer1', 'event', ?1, ?2, ?2, ?3)",
                params![&make_event_id(byte)[..], now, PRIORITY_HIGH],
            ).unwrap();
        }

        // Claim only 2 — should get both HIGH-priority events
        let claimed = eq.claim_batch("peer1", 2).unwrap();
        assert_eq!(claimed.len(), 2);
        assert_eq!(claimed[0].1[0], 1, "first claimed should be HIGH message");
        assert_eq!(claimed[1].1[0], 2, "second claimed should be HIGH reaction");
    }

    #[test]
    fn test_enqueue_events_with_priority_classifies_from_store() {
        use crate::crypto::hash_event;
        use crate::db::store::insert_event;
        use crate::event_modules::ShareScope;

        let conn = setup();
        let eq = EgressQueue::new(&conn);

        // Create a message blob (type=1) and a file_slice blob (type=25)
        let msg_blob = vec![1u8, 0, 0, 0, 0, 0, 0, 0, 0]; // type=1, minimal
        let fs_blob = vec![25u8, 0, 0, 0, 0, 0, 0, 0, 0]; // type=25, minimal

        let msg_id = hash_event(&msg_blob);
        let fs_id = hash_event(&fs_blob);
        let now = 1_700_000_000_000i64;

        insert_event(&conn, &msg_id, "message", &msg_blob, ShareScope::Shared, now, now).unwrap();
        insert_event(&conn, &fs_id, "file_slice", &fs_blob, ShareScope::Shared, now, now).unwrap();

        // Enqueue file_slice first, then message
        let inserted = eq
            .enqueue_events_with_priority("peer1", &[fs_id, msg_id])
            .unwrap();
        assert_eq!(inserted, 2);

        // Claim — message should come first due to HIGH priority
        let claimed = eq.claim_batch("peer1", 10).unwrap();
        assert_eq!(claimed.len(), 2);
        assert_eq!(
            claimed[0].1, msg_id,
            "message (HIGH priority) should be claimed before file_slice (LOW)"
        );
        assert_eq!(
            claimed[1].1, fs_id,
            "file_slice (LOW priority) should come second"
        );
    }

    #[test]
    fn test_enqueue_events_with_priority_unknown_defaults_high() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        // Event ID that does not exist in the events table
        let unknown_id = make_event_id(99);

        let inserted = eq
            .enqueue_events_with_priority("peer1", &[unknown_id])
            .unwrap();
        assert_eq!(inserted, 1);

        // Verify it was classified as HIGH priority
        let priority: i64 = conn
            .query_row(
                "SELECT priority FROM egress_queue WHERE connection_id = 'peer1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            priority, PRIORITY_HIGH,
            "unknown events should default to HIGH priority"
        );
    }
}
