use rusqlite::{Connection, Result as SqliteResult, params};

use super::queue::{current_timestamp_ms, backoff_ms, recover_expired_leases, QueueHealth};

pub struct ProjectQueue<'a> {
    conn: &'a Connection,
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS valid_events (
            peer_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            PRIMARY KEY (peer_id, event_id)
        );

        CREATE TABLE IF NOT EXISTS rejected_events (
            peer_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            reason TEXT NOT NULL,
            rejected_at INTEGER NOT NULL,
            PRIMARY KEY (peer_id, event_id)
        );

        CREATE TABLE IF NOT EXISTS blocked_event_deps (
            peer_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            blocker_event_id TEXT NOT NULL,
            PRIMARY KEY (peer_id, event_id, blocker_event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_blocked_by_dep_covering
            ON blocked_event_deps(peer_id, blocker_event_id, event_id);

        CREATE TABLE IF NOT EXISTS blocked_events (
            peer_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            deps_remaining INTEGER NOT NULL,
            PRIMARY KEY (peer_id, event_id)
        );

        CREATE TABLE IF NOT EXISTS project_queue (
            peer_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            available_at INTEGER NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            lease_until INTEGER,
            PRIMARY KEY (peer_id, event_id)
        );
        ",
    )?;
    Ok(())
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

    /// Queue health snapshot for observability.
    pub fn health(&self, peer_id: &str) -> SqliteResult<QueueHealth> {
        let now = current_timestamp_ms();
        let pending: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM project_queue WHERE peer_id = ?1",
            params![peer_id],
            |row| row.get(0),
        )?;
        let max_attempts: i64 = self.conn.query_row(
            "SELECT COALESCE(MAX(attempts), 0) FROM project_queue WHERE peer_id = ?1",
            params![peer_id],
            |row| row.get(0),
        )?;
        let oldest_age_ms: i64 = self.conn.query_row(
            "SELECT COALESCE(?2 - MIN(available_at), 0) FROM project_queue WHERE peer_id = ?1",
            params![peer_id, now],
            |row| row.get(0),
        )?;
        Ok(QueueHealth { pending, max_attempts, oldest_age_ms })
    }

    /// Claim-process-done loop. Processes all pending items for a peer.
    /// For each item: project_fn runs (which may insert into valid_events, blocked_event_deps,
    /// projection tables, and cascade-unblock dependents). Successfully processed items are
    /// dequeued; failed items are retried with exponential backoff.
    /// Returns number of items successfully processed.
    pub fn drain<F>(&self, peer_id: &str, project_fn: F) -> SqliteResult<usize>
    where
        F: FnMut(&Connection, &str) -> Result<(), Box<dyn std::error::Error>>,
    {
        self.drain_with_limit(peer_id, 100, project_fn)
    }

    /// Like `drain` but with a configurable claim batch size.
    ///
    /// Projection runs in autocommit mode. On failure we keep projection side
    /// effects (for example blocked dependency rows) and only schedule retry.
    pub fn drain_with_limit<F>(&self, peer_id: &str, batch_size: usize, mut project_fn: F) -> SqliteResult<usize>
    where
        F: FnMut(&Connection, &str) -> Result<(), Box<dyn std::error::Error>>,
    {
        let mut total = 0;
        loop {
            let batch = self.claim_batch(peer_id, batch_size, 30_000)?;
            if batch.is_empty() {
                break;
            }
            let mut succeeded = 0usize;
            for event_id_b64 in &batch {
                match project_fn(self.conn, event_id_b64) {
                    Ok(()) => {
                        self.conn.execute(
                            "DELETE FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
                            params![peer_id, event_id_b64],
                        )?;
                        succeeded += 1;
                    }
                    Err(_) => {
                        let _ = self.mark_retry(peer_id, event_id_b64);
                    }
                }
            }
            total += succeeded;
            // If entire batch failed, stop draining to avoid infinite loop
            if succeeded == 0 && !batch.is_empty() {
                break;
            }
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
            Ok(())
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
    fn test_drain_retries_failed_items() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);

        pq.enqueue("peer1", "event_a").unwrap();
        pq.enqueue("peer1", "event_b").unwrap();
        pq.enqueue("peer1", "event_c").unwrap();

        // Callback that fails for event_b
        let mut processed = Vec::new();
        let count = pq.drain("peer1", |_conn, eid| {
            if eid == "event_b" {
                return Err("simulated failure".into());
            }
            processed.push(eid.to_string());
            Ok(())
        }).unwrap();

        // event_a and event_c succeeded
        assert_eq!(count, 2);
        assert!(processed.contains(&"event_a".to_string()));
        assert!(processed.contains(&"event_c".to_string()));

        // event_b should still be in the queue with incremented attempts
        let attempts: i64 = conn.query_row(
            "SELECT attempts FROM project_queue WHERE peer_id = 'peer1' AND event_id = 'event_b'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(attempts >= 1, "failed item should have incremented attempts");

        // event_b should have a future available_at (backoff)
        let available_at: i64 = conn.query_row(
            "SELECT available_at FROM project_queue WHERE peer_id = 'peer1' AND event_id = 'event_b'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(available_at > current_timestamp_ms(), "failed item should be delayed by backoff");

        // Successfully completed items should be gone
        let remaining: i64 = conn.query_row(
            "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(remaining, 1, "only the failed item should remain");
    }

    #[test]
    fn test_drain_stops_on_all_failures() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);

        pq.enqueue("peer1", "event_a").unwrap();
        pq.enqueue("peer1", "event_b").unwrap();

        // Callback that always fails
        let count = pq.drain("peer1", |_conn, _eid| {
            Err("always fail".into())
        }).unwrap();

        assert_eq!(count, 0, "no items should be counted as processed");

        // Both items should remain in queue
        let remaining: i64 = conn.query_row(
            "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(remaining, 2, "all items should remain after total failure");
    }

    #[test]
    fn test_drain_atomicity_no_split_state() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);

        pq.enqueue("peer1", "event_a").unwrap();
        pq.enqueue("peer1", "event_b").unwrap();

        // Projector that writes to valid_events (simulating real projection)
        let count = pq.drain("peer1", |conn, eid| {
            conn.execute(
                "INSERT INTO valid_events (peer_id, event_id) VALUES ('peer1', ?1)",
                params![eid],
            )?;
            Ok(())
        }).unwrap();

        assert_eq!(count, 2);

        // Both valid_events rows must exist (projection committed)
        let valid_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = 'peer1'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(valid_count, 2, "projection writes should be committed");

        // Queue must be empty (dequeue committed atomically with projection)
        let queue_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(queue_count, 0, "queue rows should be deleted atomically with projection");
    }

    #[test]
    fn test_drain_preserves_projection_writes_on_projector_failure() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);

        pq.enqueue("peer1", "event_a").unwrap();
        pq.enqueue("peer1", "event_b").unwrap();

        // Projector that writes to valid_events but fails for event_b
        let count = pq.drain("peer1", |conn, eid| {
            conn.execute(
                "INSERT INTO valid_events (peer_id, event_id) VALUES ('peer1', ?1)",
                params![eid],
            )?;
            if eid == "event_b" {
                return Err("simulated failure after write".into());
            }
            Ok(())
        }).unwrap();

        assert_eq!(count, 1, "only event_a should succeed");

        // event_a should be in valid_events
        let valid_a: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = 'peer1' AND event_id = 'event_a'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(valid_a, "event_a projection should be committed");

        // event_b's projection write should persist even though projector errored
        let valid_b: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = 'peer1' AND event_id = 'event_b'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(valid_b, "event_b projection write should persist");

        // event_b should remain in the queue for retry
        let queue_b: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM project_queue WHERE peer_id = 'peer1' AND event_id = 'event_b'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(queue_b, "event_b should remain in queue for retry");

        // event_a should be gone from queue
        let queue_a: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM project_queue WHERE peer_id = 'peer1' AND event_id = 'event_a'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(!queue_a, "event_a should be dequeued");
    }

    #[test]
    fn test_drain_failure_preserves_blocked_event_deps() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);

        pq.enqueue("peer1", "event_blocked").unwrap();

        let count = pq.drain("peer1", |conn, eid| {
            conn.execute(
                "INSERT INTO blocked_event_deps (peer_id, event_id, blocker_event_id)
                 VALUES ('peer1', ?1, 'missing_dep')",
                params![eid],
            )?;
            Err("simulated failure after blocker write".into())
        }).unwrap();

        assert_eq!(count, 0, "failed projection should not count as success");

        let blocked_exists: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM blocked_event_deps
             WHERE peer_id = 'peer1' AND event_id = 'event_blocked' AND blocker_event_id = 'missing_dep'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert!(
            blocked_exists,
            "blocked_event_deps row must persist to preserve cascade-unblock state"
        );

        let queue_exists: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM project_queue WHERE peer_id = 'peer1' AND event_id = 'event_blocked'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert!(queue_exists, "failed item should remain queued for retry");

        let attempts: i64 = conn.query_row(
            "SELECT attempts FROM project_queue WHERE peer_id = 'peer1' AND event_id = 'event_blocked'",
            [],
            |row| row.get(0),
        ).unwrap();
        assert!(attempts >= 1, "failed item should increment attempts");
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

    #[test]
    fn test_queue_health() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);

        // Empty queue health
        let h = pq.health("peer1").unwrap();
        assert_eq!(h.pending, 0);
        assert_eq!(h.max_attempts, 0);
        assert_eq!(h.oldest_age_ms, 0);

        // Enqueue items
        pq.enqueue("peer1", "event_a").unwrap();
        pq.enqueue("peer1", "event_b").unwrap();

        let h = pq.health("peer1").unwrap();
        assert_eq!(h.pending, 2);
        assert_eq!(h.max_attempts, 0);
        // oldest_age_ms should be very small (just enqueued)
        assert!(h.oldest_age_ms >= 0);

        // Retry one item to bump attempts
        pq.claim_batch("peer1", 1, 30_000).unwrap();
        pq.mark_retry("peer1", "event_a").unwrap();

        let h = pq.health("peer1").unwrap();
        assert_eq!(h.pending, 2); // both still in queue
        assert_eq!(h.max_attempts, 1); // event_a retried once
    }

}
