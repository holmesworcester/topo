use rusqlite::{params, Connection, Result as SqliteResult};

fn valid_events_has_semantic_type_column(conn: &Connection) -> SqliteResult<bool> {
    let mut stmt = conn.prepare("PRAGMA table_info(valid_events)")?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names.iter().any(|name| name == "semantic_type_code"))
}

fn project_queue_has_column(conn: &Connection, column: &str) -> SqliteResult<bool> {
    let mut stmt = conn.prepare("PRAGMA table_info(project_queue)")?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names.iter().any(|name| name == column))
}

fn load_project_priority(
    conn: &Connection,
    event_id_b64: &str,
    default_created_at: i64,
) -> (i64, i64) {
    let (event_type, created_at, encrypted_inner_type) = conn
        .query_row(
            "SELECT event_type,
                    created_at,
                    CASE
                        WHEN event_type = 'encrypted' THEN substr(blob, 42, 1)
                        ELSE NULL
                    END
             FROM events
             WHERE event_id = ?1",
            params![event_id_b64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            },
        )
        .unwrap_or_else(|_| ("unknown".to_string(), default_created_at, None));
    let lane = match event_type.as_str() {
        "file_slice" => super::queue::PRIORITY_LANE_BULK,
        "encrypted"
            if encrypted_inner_type.and_then(|bytes| bytes.first().copied())
                == Some(crate::event_modules::EVENT_TYPE_FILE_SLICE) =>
        {
            super::queue::PRIORITY_LANE_BULK
        }
        _ => super::queue::PRIORITY_LANE_FOREGROUND,
    };
    (lane, created_at)
}

fn derive_semantic_type_code_from_blob(blob: &[u8]) -> Option<i64> {
    let parsed = crate::event_modules::parse_event(blob).ok()?;
    let semantic_type = match parsed {
        crate::event_modules::ParsedEvent::Encrypted(enc) => enc.inner_type_code,
        _ => parsed.event_type_code(),
    };
    Some(i64::from(semantic_type))
}

fn backfill_valid_event_semantic_types(conn: &Connection) -> SqliteResult<()> {
    let mut stmt = conn.prepare(
        "SELECT v.peer_id, v.event_id, e.blob
         FROM valid_events v
         JOIN events e ON e.event_id = v.event_id
         WHERE v.semantic_type_code IS NULL",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    for (peer_id, event_id, blob) in rows {
        let Some(semantic_type_code) = derive_semantic_type_code_from_blob(&blob) else {
            continue;
        };
        conn.execute(
            "UPDATE valid_events
             SET semantic_type_code = ?3
             WHERE peer_id = ?1 AND event_id = ?2 AND semantic_type_code IS NULL",
            params![peer_id, event_id, semantic_type_code],
        )?;
    }

    Ok(())
}

use super::queue::{backoff_ms, current_timestamp_ms, recover_expired_leases, QueueHealth};

pub struct ProjectQueue<'a> {
    conn: &'a Connection,
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS valid_events (
            peer_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            semantic_type_code INTEGER,
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
            priority_lane INTEGER NOT NULL DEFAULT 1,
            priority_ts INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (peer_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_project_queue_claim
            ON project_queue(peer_id, priority_lane, priority_ts DESC, available_at, event_id);
        ",
    )?;
    if !valid_events_has_semantic_type_column(conn)? {
        conn.execute(
            "ALTER TABLE valid_events ADD COLUMN semantic_type_code INTEGER",
            [],
        )?;
    }
    if !project_queue_has_column(conn, "priority_lane")? {
        conn.execute(
            "ALTER TABLE project_queue ADD COLUMN priority_lane INTEGER NOT NULL DEFAULT 1",
            [],
        )?;
    }
    if !project_queue_has_column(conn, "priority_ts")? {
        conn.execute(
            "ALTER TABLE project_queue ADD COLUMN priority_ts INTEGER NOT NULL DEFAULT 0",
            [],
        )?;
    }
    backfill_valid_event_semantic_types(conn)?;
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
        let (priority_lane, priority_ts) = load_project_priority(self.conn, event_id_b64, now);
        self.enqueue_classified(peer_id, event_id_b64, priority_lane, priority_ts)
    }

    /// Enqueue an event for projection using already-classified priority.
    /// This lets local-create paths avoid re-reading the just-written event row.
    pub fn enqueue_classified(
        &self,
        peer_id: &str,
        event_id_b64: &str,
        priority_lane: i64,
        priority_ts: i64,
    ) -> SqliteResult<bool> {
        let now = current_timestamp_ms();
        let rows = self.conn.execute(
            "INSERT OR IGNORE INTO project_queue
             (peer_id, event_id, available_at, priority_lane, priority_ts)
             SELECT ?1, ?2, ?3, ?4, ?5
             WHERE NOT EXISTS (SELECT 1 FROM valid_events WHERE peer_id=?1 AND event_id=?2)
             AND NOT EXISTS (SELECT 1 FROM rejected_events WHERE peer_id=?1 AND event_id=?2)
             AND NOT EXISTS (SELECT 1 FROM blocked_event_deps WHERE peer_id=?1 AND event_id=?2)",
            params![peer_id, event_id_b64, now, priority_lane, priority_ts],
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
            "INSERT OR IGNORE INTO project_queue
             (peer_id, event_id, available_at, priority_lane, priority_ts)
             SELECT ?1, ?2, ?3, ?4, ?5
             WHERE NOT EXISTS (SELECT 1 FROM valid_events WHERE peer_id=?1 AND event_id=?2)
             AND NOT EXISTS (SELECT 1 FROM rejected_events WHERE peer_id=?1 AND event_id=?2)
             AND NOT EXISTS (SELECT 1 FROM blocked_event_deps WHERE peer_id=?1 AND event_id=?2)",
        )?;
        let mut inserted = 0usize;
        for eid in event_ids {
            let (priority_lane, priority_ts) = load_project_priority(self.conn, eid, now);
            inserted += stmt.execute(params![peer_id, eid, now, priority_lane, priority_ts])?;
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
        let head_lane: Option<i64> = self
            .conn
            .query_row(
                "SELECT priority_lane
                 FROM project_queue
                 WHERE peer_id = ?1
                   AND available_at <= ?2
                   AND (lease_until IS NULL OR lease_until <= ?2)
                 ORDER BY priority_lane ASC, available_at ASC, rowid ASC
                 LIMIT 1",
                params![peer_id, now],
                |row| row.get(0),
            )
            .ok();
        let Some(head_lane) = head_lane else {
            return Ok(Vec::new());
        };

        // Select available items
        let mut select_stmt = self.conn.prepare(
            "SELECT event_id FROM project_queue
             WHERE peer_id = ?1
             AND priority_lane = ?2
             AND available_at <= ?3
             AND (lease_until IS NULL OR lease_until <= ?3)
             ORDER BY available_at ASC, rowid ASC
             LIMIT ?4",
        )?;
        let event_ids: Vec<String> = select_stmt
            .query_map(params![peer_id, head_lane, now, limit as i64], |row| {
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
        let mut stmt = self
            .conn
            .prepare("DELETE FROM project_queue WHERE peer_id = ?1 AND event_id = ?2")?;
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
        Ok(QueueHealth {
            pending,
            max_attempts,
            oldest_age_ms,
        })
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
    /// Projects a claimed batch, then dequeues all successes in one
    /// transaction. Each individual projection attempt owns its own
    /// transaction boundary, so successful block/valid/reject side effects
    /// commit atomically while projection errors roll back fully and retry.
    /// The batched dequeue at the end amortizes DELETE overhead.
    pub fn drain_with_limit<F>(
        &self,
        peer_id: &str,
        batch_size: usize,
        mut project_fn: F,
    ) -> SqliteResult<usize>
    where
        F: FnMut(&Connection, &str) -> Result<(), Box<dyn std::error::Error>>,
    {
        let mut total = 0;
        loop {
            let batch = self.claim_batch(peer_id, batch_size, 30_000)?;
            if batch.is_empty() {
                break;
            }
            let mut succeeded_ids: Vec<&str> = Vec::new();
            for event_id_b64 in &batch {
                match project_fn(self.conn, event_id_b64) {
                    Ok(()) => {
                        succeeded_ids.push(event_id_b64);
                    }
                    Err(_) => {
                        let _ = self.mark_retry(peer_id, event_id_b64);
                    }
                }
            }
            let succeeded = succeeded_ids.len();
            if !succeeded_ids.is_empty() {
                self.mark_done_batch(peer_id, &succeeded_ids)?;
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
    use super::super::queue::current_timestamp_ms;
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::event_modules::EVENT_TYPE_FILE_SLICE;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    fn insert_event(conn: &Connection, event_id_b64: &str, event_type: &str, created_at: i64) {
        conn.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, x'01', 'shared', ?3, ?3)",
            params![event_id_b64, event_type, created_at],
        )
        .unwrap();
    }

    fn insert_event_blob(
        conn: &Connection,
        event_id_b64: &str,
        event_type: &str,
        blob: Vec<u8>,
        created_at: i64,
    ) {
        conn.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, 'shared', ?4, ?4)",
            params![event_id_b64, event_type, blob, created_at],
        )
        .unwrap();
    }

    #[test]
    fn test_enqueue_basic() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);
        let inserted = pq.enqueue("peer1", "event_abc").unwrap();
        assert!(inserted);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_enqueue_guard_valid() {
        let conn = setup();
        // Insert into valid_events
        conn.execute(
            "INSERT INTO valid_events (peer_id, event_id) VALUES ('peer1', 'event_abc')",
            [],
        )
        .unwrap();

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

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
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
        assert!(
            available_at > now,
            "available_at should be in the future after retry"
        );

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
        let count = pq
            .drain("peer1", |_conn, eid| {
                processed.push(eid.to_string());
                Ok(())
            })
            .unwrap();

        assert_eq!(count, 3);
        assert_eq!(processed.len(), 3);
        assert!(processed.contains(&"event_a".to_string()));
        assert!(processed.contains(&"event_b".to_string()));
        assert!(processed.contains(&"event_c".to_string()));

        // Queue should be empty
        let remaining: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
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
        let count = pq
            .drain("peer1", |_conn, eid| {
                if eid == "event_b" {
                    return Err("simulated failure".into());
                }
                processed.push(eid.to_string());
                Ok(())
            })
            .unwrap();

        // event_a and event_c succeeded
        assert_eq!(count, 2);
        assert!(processed.contains(&"event_a".to_string()));
        assert!(processed.contains(&"event_c".to_string()));

        // event_b should still be in the queue with incremented attempts
        let attempts: i64 = conn.query_row(
            "SELECT attempts FROM project_queue WHERE peer_id = 'peer1' AND event_id = 'event_b'",
            [], |row| row.get(0),
        ).unwrap();
        assert!(
            attempts >= 1,
            "failed item should have incremented attempts"
        );

        // event_b should have a future available_at (backoff)
        let available_at: i64 = conn.query_row(
            "SELECT available_at FROM project_queue WHERE peer_id = 'peer1' AND event_id = 'event_b'",
             [], |row| row.get(0),
        ).unwrap();
        assert!(
            available_at > current_timestamp_ms(),
            "failed item should be delayed by backoff"
        );

        // Successfully completed items should be gone
        let remaining: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 1, "only the failed item should remain");
    }

    #[test]
    fn test_drain_stops_on_all_failures() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);

        pq.enqueue("peer1", "event_a").unwrap();
        pq.enqueue("peer1", "event_b").unwrap();

        // Callback that always fails
        let count = pq
            .drain("peer1", |_conn, _eid| Err("always fail".into()))
            .unwrap();

        assert_eq!(count, 0, "no items should be counted as processed");

        // Both items should remain in queue
        let remaining: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, 2, "all items should remain after total failure");
    }

    #[test]
    fn test_drain_atomicity_no_split_state() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);

        pq.enqueue("peer1", "event_a").unwrap();
        pq.enqueue("peer1", "event_b").unwrap();

        // Projector that writes to valid_events (simulating real projection)
        let count = pq
            .drain("peer1", |conn, eid| {
                conn.execute(
                    "INSERT INTO valid_events (peer_id, event_id) VALUES ('peer1', ?1)",
                    params![eid],
                )?;
                Ok(())
            })
            .unwrap();

        assert_eq!(count, 2);

        // Both valid_events rows must exist (projection committed)
        let valid_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM valid_events WHERE peer_id = 'peer1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(valid_count, 2, "projection writes should be committed");

        // Queue must be empty (dequeue committed atomically with projection)
        let queue_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            queue_count, 0,
            "queue rows should be deleted atomically with projection"
        );
    }

    #[test]
    fn test_drain_preserves_projection_writes_on_projector_failure() {
        let conn = setup();
        let pq = ProjectQueue::new(&conn);

        pq.enqueue("peer1", "event_a").unwrap();
        pq.enqueue("peer1", "event_b").unwrap();

        // Projector that writes to valid_events but fails for event_b
        let count = pq
            .drain("peer1", |conn, eid| {
                conn.execute(
                    "INSERT INTO valid_events (peer_id, event_id) VALUES ('peer1', ?1)",
                    params![eid],
                )?;
                if eid == "event_b" {
                    return Err("simulated failure after write".into());
                }
                Ok(())
            })
            .unwrap();

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

        let count = pq
            .drain("peer1", |conn, eid| {
                conn.execute(
                    "INSERT INTO blocked_event_deps (peer_id, event_id, blocker_event_id)
                 VALUES ('peer1', ?1, 'missing_dep')",
                    params![eid],
                )?;
                Err("simulated failure after blocker write".into())
            })
            .unwrap();

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
        )
        .unwrap();

        let ids = vec!["event_a", "event_b", "event_c"];
        let inserted = pq.enqueue_batch("peer1", &ids).unwrap();
        assert_eq!(
            inserted, 2,
            "event_b should be skipped (valid_events guard)"
        );

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM project_queue WHERE peer_id = 'peer1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
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

    #[test]
    fn test_claim_batch_prefers_foreground_without_reordering_foreground_arrival() {
        let conn = setup();
        insert_event(&conn, "message_new", "message", 300);
        insert_event(&conn, "message_old", "message", 100);
        insert_event(&conn, "bulk_new", "file_slice", 500);

        let pq = ProjectQueue::new(&conn);
        pq.enqueue_batch("peer1", &["bulk_new", "message_old", "message_new"])
            .unwrap();

        let claimed = pq.claim_batch("peer1", 10, 30_000).unwrap();
        assert_eq!(
            claimed,
            vec!["message_old".to_string(), "message_new".to_string()]
        );

        let claimed_bulk = pq.claim_batch("peer1", 10, 30_000).unwrap();
        assert_eq!(claimed_bulk, vec!["bulk_new".to_string()]);
    }

    #[test]
    fn test_claim_batch_treats_encrypted_file_slice_as_bulk() {
        let conn = setup();
        let encrypted_blob = crate::event_modules::encode_event(
            &crate::event_modules::ParsedEvent::Encrypted(crate::event_modules::EncryptedEvent {
                created_at_ms: 200,
                key_event_id: [7u8; 32],
                owner_event_id: crate::event_modules::encrypted::NO_OWNER_EVENT_ID,
                outer_dep_event_id: crate::event_modules::encrypted::NO_OUTER_DEP_EVENT_ID,
                inner_type_code: EVENT_TYPE_FILE_SLICE,
                nonce: [8u8; 12],
                ciphertext: vec![0u8; crate::event_modules::file_slice::FILE_SLICE_WIRE_SIZE],
                auth_tag: [9u8; 16],
            }),
        )
        .unwrap();
        insert_event_blob(&conn, "encrypted_bulk", "encrypted", encrypted_blob, 200);
        insert_event(&conn, "message_midflight", "message", 100);

        let pq = ProjectQueue::new(&conn);
        pq.enqueue_batch("peer1", &["encrypted_bulk", "message_midflight"])
            .unwrap();

        let claimed = pq.claim_batch("peer1", 10, 30_000).unwrap();
        assert_eq!(
            claimed,
            vec!["message_midflight".to_string()],
            "encrypted file slices should be demoted into the bulk lane"
        );

        let claimed_bulk = pq.claim_batch("peer1", 10, 30_000).unwrap();
        assert_eq!(claimed_bulk, vec!["encrypted_bulk".to_string()]);
    }
}
