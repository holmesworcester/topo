use rusqlite::{Connection, Result as SqliteResult, params};

use crate::crypto::EventId;
use super::queue::current_timestamp_ms;

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
    pub fn enqueue_events(&self, connection_id: &str, event_ids: &[EventId]) -> SqliteResult<usize> {
        if event_ids.is_empty() {
            return Ok(0);
        }
        let now = current_timestamp_ms();
        self.conn.execute("BEGIN", [])?;
        let mut stmt = self.conn.prepare(
            "INSERT OR IGNORE INTO egress_queue
             (connection_id, frame_type, event_id, enqueued_at, available_at)
             VALUES (?1, 'event', ?2, ?3, ?3)",
        )?;
        let mut inserted = 0usize;
        for id in event_ids {
            inserted += stmt.execute(params![connection_id, &id[..], now])?;
        }
        self.conn.execute("COMMIT", [])?;
        Ok(inserted)
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

        let mut stmt = self.conn.prepare(
            "SELECT id, event_id FROM egress_queue
             WHERE connection_id = ?1
             AND sent_at IS NULL
             ORDER BY id
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
    }

    /// Mark items as sent by rowid.
    pub fn mark_sent(&self, rowids: &[i64]) -> SqliteResult<()> {
        if rowids.is_empty() {
            return Ok(());
        }
        let now = current_timestamp_ms();
        self.conn.execute("BEGIN", [])?;
        let mut stmt = self.conn.prepare(
            "UPDATE egress_queue SET sent_at = ?1, lease_until = NULL WHERE id = ?2",
        )?;
        for rowid in rowids {
            stmt.execute(params![now, rowid])?;
        }
        self.conn.execute("COMMIT", [])?;
        Ok(())
    }

    /// Count pending (unsent) items for a connection.
    pub fn count_pending(&self, connection_id: &str) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM egress_queue
             WHERE connection_id = ?1 AND sent_at IS NULL",
            params![connection_id],
            |row| row.get(0),
        )
    }

    /// Delete sent items older than the given threshold.
    pub fn cleanup_sent(&self, older_than_ms: i64) -> SqliteResult<usize> {
        let cutoff = current_timestamp_ms() - older_than_ms;
        self.conn.execute(
            "DELETE FROM egress_queue WHERE sent_at IS NOT NULL AND sent_at < ?1",
            params![cutoff],
        )
    }

    /// Delete all items for a connection.
    pub fn clear_connection(&self, connection_id: &str) -> SqliteResult<()> {
        self.conn.execute(
            "DELETE FROM egress_queue WHERE connection_id = ?1",
            params![connection_id],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
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
        assert_eq!(inserted, 0, "duplicate event_id for same connection should be ignored");

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
    fn test_cleanup_sent() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let ids = vec![make_event_id(1), make_event_id(2)];
        eq.enqueue_events("conn1", &ids).unwrap();

        let claimed = eq.claim_batch("conn1", 10).unwrap();
        let rowids: Vec<i64> = claimed.iter().map(|(r, _)| *r).collect();
        eq.mark_sent(&rowids).unwrap();

        // Backdate sent_at to make items "old"
        conn.execute(
            "UPDATE egress_queue SET sent_at = sent_at - 600000",
            [],
        ).unwrap();

        // Cleanup items older than 300 seconds
        let cleaned = eq.cleanup_sent(300_000).unwrap();
        assert_eq!(cleaned, 2);

        // Total row count should be 0
        let total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM egress_queue",
            [], |row| row.get(0),
        ).unwrap();
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
}
