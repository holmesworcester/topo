use rusqlite::{Connection, Result as SqliteResult, params};

use super::queue::{current_timestamp_ms, backoff_ms, recover_expired_leases};

pub struct ProjectQueue<'a> {
    conn: &'a Connection,
}

impl<'a> ProjectQueue<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Enqueue an event for projection. Uses the enqueue guard: don't enqueue if
    /// already valid, rejected, or blocked.
    /// Returns true if inserted.
    pub fn enqueue(&self, peer_id: &str, event_id_b64: &str) -> SqliteResult<bool> {
        let now = current_timestamp_ms();
        let rows = self.conn.execute(
            "INSERT OR IGNORE INTO project_queue (peer_id, event_id, available_at)
             SELECT ?1, ?2, ?3
             WHERE NOT EXISTS (SELECT 1 FROM valid_events WHERE peer_id=?1 AND event_id=?2)
             AND NOT EXISTS (SELECT 1 FROM rejected_events WHERE peer_id=?1 AND event_id=?2)
             AND NOT EXISTS (SELECT 1 FROM blocked_event_deps WHERE peer_id=?1 AND event_id=?2)",
            params![peer_id, event_id_b64, now],
        )?;
        Ok(rows > 0)
    }

    /// Batch enqueue with guard. Returns number inserted.
    pub fn enqueue_batch(&self, peer_id: &str, event_ids: &[&str]) -> SqliteResult<usize> {
        if event_ids.is_empty() {
            return Ok(0);
        }
        let now = current_timestamp_ms();
        self.conn.execute("BEGIN", [])?;
        let mut stmt = self.conn.prepare(
            "INSERT OR IGNORE INTO project_queue (peer_id, event_id, available_at)
             SELECT ?1, ?2, ?3
             WHERE NOT EXISTS (SELECT 1 FROM valid_events WHERE peer_id=?1 AND event_id=?2)
             AND NOT EXISTS (SELECT 1 FROM rejected_events WHERE peer_id=?1 AND event_id=?2)
             AND NOT EXISTS (SELECT 1 FROM blocked_event_deps WHERE peer_id=?1 AND event_id=?2)",
        )?;
        let mut inserted = 0usize;
        for eid in event_ids {
            inserted += stmt.execute(params![peer_id, eid, now])?;
        }
        self.conn.execute("COMMIT", [])?;
        Ok(inserted)
    }

    /// Claim a batch of available items for processing.
    /// Returns event_id_b64 strings. Sets lease_until = now + lease_ms.
    pub fn claim_batch(
        &self,
        peer_id: &str,
        limit: usize,
        lease_ms: i64,
    ) -> SqliteResult<Vec<String>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let now = current_timestamp_ms();
        let lease_until = now + lease_ms;

        // Select available items
        let mut select_stmt = self.conn.prepare(
            "SELECT event_id FROM project_queue
             WHERE peer_id = ?1
             AND available_at <= ?2
             AND (lease_until IS NULL OR lease_until <= ?2)
             ORDER BY available_at
             LIMIT ?3",
        )?;
        let event_ids: Vec<String> = select_stmt
            .query_map(params![peer_id, now, limit as i64], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;

        if event_ids.is_empty() {
            return Ok(event_ids);
        }

        // Batch-set lease in a single transaction
        self.conn.execute("BEGIN", [])?;
        let mut update_stmt = self.conn.prepare(
            "UPDATE project_queue SET lease_until = ?1
             WHERE peer_id = ?2 AND event_id = ?3",
        )?;
        for eid in &event_ids {
            update_stmt.execute(params![lease_until, peer_id, eid])?;
        }
        self.conn.execute("COMMIT", [])?;

        Ok(event_ids)
    }

    /// Remove a completed item from the queue.
    pub fn mark_done(&self, peer_id: &str, event_id_b64: &str) -> SqliteResult<()> {
        self.conn.execute(
            "DELETE FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
            params![peer_id, event_id_b64],
        )?;
        Ok(())
    }

    /// Remove a batch of completed items from the queue.
    pub fn mark_done_batch(&self, peer_id: &str, event_ids: &[&str]) -> SqliteResult<()> {
        if event_ids.is_empty() {
            return Ok(());
        }
        self.conn.execute("BEGIN", [])?;
        let mut stmt = self.conn.prepare(
            "DELETE FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
        )?;
        for eid in event_ids {
            stmt.execute(params![peer_id, eid])?;
        }
        self.conn.execute("COMMIT", [])?;
        Ok(())
    }

    /// Mark an item for retry with exponential backoff.
    pub fn mark_retry(&self, peer_id: &str, event_id_b64: &str) -> SqliteResult<()> {
        let now = current_timestamp_ms();
        // Get current attempts
        let attempts: i64 = self.conn.query_row(
            "SELECT attempts FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
            params![peer_id, event_id_b64],
            |row| row.get(0),
        )?;
        let new_attempts = attempts + 1;
        let delay = backoff_ms(new_attempts);
        self.conn.execute(
            "UPDATE project_queue SET attempts = ?1, available_at = ?2, lease_until = NULL
             WHERE peer_id = ?3 AND event_id = ?4",
            params![new_attempts, now + delay, peer_id, event_id_b64],
        )?;
        Ok(())
    }

    /// Count pending items (available or with expired lease).
    pub fn count_pending(&self, peer_id: &str) -> SqliteResult<i64> {
        let now = current_timestamp_ms();
        self.conn.query_row(
            "SELECT COUNT(*) FROM project_queue
             WHERE peer_id = ?1
             AND (lease_until IS NULL OR lease_until <= ?2)",
            params![peer_id, now],
            |row| row.get(0),
        )
    }

    /// Recover expired leases, making them claimable again.
    pub fn recover_expired(&self) -> SqliteResult<usize> {
        let now = current_timestamp_ms();
        recover_expired_leases(self.conn, "project_queue", now)
    }

    /// Claim-process-done loop. Processes all pending items for a peer.
    /// For each item: project_fn runs (which may insert into valid_events, blocked_event_deps,
    /// projection tables, and cascade-unblock dependents), then the item is dequeued.
    /// Returns number of items processed.
    pub fn drain<F>(&self, peer_id: &str, mut project_fn: F) -> SqliteResult<usize>
    where
        F: FnMut(&Connection, &str),
    {
        let mut total = 0;
        loop {
            let batch = self.claim_batch(peer_id, 100, 30_000)?;
            if batch.is_empty() {
                break;
            }
            // Process all items first
            for event_id_b64 in &batch {
                project_fn(self.conn, event_id_b64);
            }
            // Then batch-delete from queue in a single transaction
            self.conn.execute("BEGIN", [])?;
            let mut del_stmt = self.conn.prepare(
                "DELETE FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
            )?;
            for event_id_b64 in &batch {
                del_stmt.execute(params![peer_id, event_id_b64])?;
            }
            self.conn.execute("COMMIT", [])?;
            total += batch.len();
        }
        Ok(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};
    use super::super::queue::current_timestamp_ms;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn test_enqueue_basic() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);
        let inserted = pq.enqueue("peer1", "event_abc").unwrap();
        assert!(inserted);

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_enqueue_guard_valid() {
        let conn = setup();
        // Insert into valid_events
        conn.execute(
            "INSERT INTO valid_events (peer_id, event_id) VALUES ('peer1', 'event_abc')",
            [],
        ).unwrap();

        let pq = ProjectQueue::new(&conn);
        let inserted = pq.enqueue("peer1", "event_abc").unwrap();
        assert!(!inserted, "should not enqueue if already valid");
    }

    #[test]
    fn test_enqueue_guard_rejected() {
        let conn = setup();
        conn.execute(
            "INSERT INTO rejected_events (peer_id, event_id, reason, rejected_at) VALUES ('peer1', 'event_abc', 'bad', 0)",
            [],
        ).unwrap();

        let pq = ProjectQueue::new(&conn);
        let inserted = pq.enqueue("peer1", "event_abc").unwrap();
        assert!(!inserted, "should not enqueue if already rejected");
    }

    #[test]
    fn test_enqueue_guard_blocked() {
        let conn = setup();
        conn.execute(
            "INSERT INTO blocked_event_deps (peer_id, event_id, blocker_event_id) VALUES ('peer1', 'event_abc', 'blocker1')",
            [],
        ).unwrap();

        let pq = ProjectQueue::new(&conn);
        let inserted = pq.enqueue("peer1", "event_abc").unwrap();
        assert!(!inserted, "should not enqueue if already blocked");
    }

    #[test]
    fn test_claim_and_done() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);
        pq.enqueue("peer1", "event_abc").unwrap();

        let claimed = pq.claim_batch("peer1", 10, 30_000).unwrap();
        assert_eq!(claimed.len(), 1);
        assert_eq!(claimed[0], "event_abc");

        pq.mark_done("peer1", "event_abc").unwrap();

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_claim_respects_lease() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);
        pq.enqueue("peer1", "event_abc").unwrap();

        // Claim with long lease
        let claimed = pq.claim_batch("peer1", 10, 60_000).unwrap();
        assert_eq!(claimed.len(), 1);

        // Try to claim again — should get nothing (lease still active)
        let claimed2 = pq.claim_batch("peer1", 10, 60_000).unwrap();
        assert_eq!(claimed2.len(), 0, "leased items should not be re-claimable");
    }

    #[test]
    fn test_retry_with_backoff() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);
        pq.enqueue("peer1", "event_abc").unwrap();

        // Claim and then retry
        pq.claim_batch("peer1", 10, 30_000).unwrap();
        pq.mark_retry("peer1", "event_abc").unwrap();

        // Check attempts incremented
        let attempts: i64 = conn.query_row(
            "SELECT attempts FROM project_queue WHERE peer_id = 'peer1' AND event_id = 'event_abc'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(attempts, 1);

        // available_at should be in the future
        let available_at: i64 = conn.query_row(
            "SELECT available_at FROM project_queue WHERE peer_id = 'peer1' AND event_id = 'event_abc'",
            [], |row| row.get(0),
        ).unwrap();
        let now = current_timestamp_ms();
        assert!(available_at > now, "available_at should be in the future after retry");

        // lease_until should be cleared
        let lease: Option<i64> = conn.query_row(
            "SELECT lease_until FROM project_queue WHERE peer_id = 'peer1' AND event_id = 'event_abc'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(lease.is_none(), "lease should be cleared after retry");
    }

    #[test]
    fn test_recover_expired_leases() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);
        pq.enqueue("peer1", "event_abc").unwrap();

        // Set lease to the past manually
        conn.execute(
            "UPDATE project_queue SET lease_until = 1 WHERE peer_id = 'peer1' AND event_id = 'event_abc'",
            [],
        ).unwrap();

        // Item should not be claimable due to lease
        // (Actually with expired lease it should be claimable, but let's recover first)
        let recovered = pq.recover_expired().unwrap();
        assert_eq!(recovered, 1);

        // Now lease_until should be NULL
        let lease: Option<i64> = conn.query_row(
            "SELECT lease_until FROM project_queue WHERE peer_id = 'peer1' AND event_id = 'event_abc'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(lease.is_none());

        // Should now be claimable
        let claimed = pq.claim_batch("peer1", 10, 30_000).unwrap();
        assert_eq!(claimed.len(), 1);
    }

    #[test]
    fn test_drain_processes_all() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);

        // Enqueue multiple items
        pq.enqueue("peer1", "event_a").unwrap();
        pq.enqueue("peer1", "event_b").unwrap();
        pq.enqueue("peer1", "event_c").unwrap();

        let mut processed = Vec::new();
        let count = pq.drain("peer1", |_conn, eid| {
            processed.push(eid.to_string());
        }).unwrap();

        assert_eq!(count, 3);
        assert_eq!(processed.len(), 3);
        assert!(processed.contains(&"event_a".to_string()));
        assert!(processed.contains(&"event_b".to_string()));
        assert!(processed.contains(&"event_c".to_string()));

        // Queue should be empty
        let remaining: i64 = conn.query_row(
            "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(remaining, 0);
    }

    #[test]
    fn test_enqueue_batch() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);

        // Put one in valid_events as guard test
        conn.execute(
            "INSERT INTO valid_events (peer_id, event_id) VALUES ('peer1', 'event_b')",
            [],
        ).unwrap();

        let ids = vec!["event_a", "event_b", "event_c"];
        let inserted = pq.enqueue_batch("peer1", &ids).unwrap();
        assert_eq!(inserted, 2, "event_b should be skipped (valid_events guard)");

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 2);
    }
}
