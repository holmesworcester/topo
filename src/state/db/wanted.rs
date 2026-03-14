use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use super::queue::{
    current_timestamp_ms, with_immediate_tx, with_sqlite_busy_retry, PRIORITY_LANE_FOREGROUND,
};
use crate::crypto::{event_id_to_base64, EventId};

/// Wanted events - events the sink still needs to fetch.
///
/// `wanted_events` records demand exactly once per event ID.
/// `wanted_sources` records which peers appear to have that event.
/// A request lease on `wanted_events` prevents multiple peers from being asked
/// for the same event concurrently unless the lease expires or is released.
pub struct WantedEvents<'a> {
    conn: &'a Connection,
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS wanted_events (
            id BLOB PRIMARY KEY,
            first_seen_at INTEGER NOT NULL,
            lease_peer_id TEXT,
            lease_owner TEXT,
            lease_expires_at INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_wanted_events_lease
        ON wanted_events(lease_peer_id, lease_owner, lease_expires_at);

        CREATE TABLE IF NOT EXISTS wanted_sources (
            event_id BLOB NOT NULL,
            peer_id TEXT NOT NULL,
            first_seen_at INTEGER NOT NULL,
            last_seen_at INTEGER NOT NULL,
            priority_lane INTEGER NOT NULL,
            priority_ts INTEGER NOT NULL,
            PRIMARY KEY (event_id, peer_id)
        );
        CREATE INDEX IF NOT EXISTS idx_wanted_sources_peer_priority
        ON wanted_sources(peer_id, priority_lane, priority_ts DESC, first_seen_at, event_id);
        ",
    )?;
    Ok(())
}

impl<'a> WantedEvents<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Insert pure demand for an event without recording any candidate source.
    ///
    /// This is still useful for paths that know the sink needs an event before
    /// they know which peer can satisfy it.
    pub fn insert(&self, id: &EventId) -> SqliteResult<bool> {
        let now = current_timestamp_ms();
        let id_b64 = event_id_to_base64(id);
        with_immediate_tx(self.conn, || {
            if local_event_exists(self.conn, &id_b64)? {
                delete_wanted_row(self.conn, id)?;
                return Ok(false);
            }

            let rows = self.conn.execute(
                "INSERT OR IGNORE INTO wanted_events (id, first_seen_at) VALUES (?1, ?2)",
                params![&id[..], now],
            )?;
            Ok(rows > 0)
        })
    }

    /// Observe that `peer_id` appears to have each event in `ids`.
    ///
    /// This records event demand once and candidate source membership per peer.
    pub fn observe_many_for_peer(&self, peer_id: &str, ids: &[EventId]) -> SqliteResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let now = current_timestamp_ms();
        with_immediate_tx(self.conn, || {
            let mut local_exists = self
                .conn
                .prepare("SELECT 1 FROM events WHERE event_id = ?1 LIMIT 1")?;
            let mut insert_wanted = self.conn.prepare(
                "INSERT OR IGNORE INTO wanted_events (id, first_seen_at)
                 VALUES (?1, ?2)",
            )?;
            let mut upsert_source = self.conn.prepare(
                "INSERT INTO wanted_sources (
                     event_id, peer_id, first_seen_at, last_seen_at, priority_lane, priority_ts
                 ) VALUES (?1, ?2, ?3, ?3, ?4, ?5)
                 ON CONFLICT(event_id, peer_id) DO UPDATE SET
                     last_seen_at = excluded.last_seen_at,
                     priority_lane = excluded.priority_lane,
                     priority_ts = MAX(wanted_sources.priority_ts, excluded.priority_ts)",
            )?;

            let mut observed = 0usize;
            for id in ids {
                let id_b64 = event_id_to_base64(id);
                let already_local = local_exists
                    .query_row(params![&id_b64], |_| Ok(()))
                    .optional()?
                    .is_some();
                if already_local {
                    delete_wanted_row(self.conn, id)?;
                    continue;
                }
                let _ = insert_wanted.execute(params![&id[..], now])?;
                upsert_source.execute(params![
                    &id[..],
                    peer_id,
                    now,
                    PRIORITY_LANE_FOREGROUND,
                    now,
                ])?;
                observed += 1;
            }
            Ok(observed)
        })
    }

    /// Claim up to `limit` wanted events for `peer_id`.
    ///
    /// Only unleased or expired rows are claimable. The returned IDs are now
    /// leased to `(peer_id, lease_owner)` until `lease_ms` elapses or the lease
    /// is released explicitly.
    pub fn claim_for_peer(
        &self,
        peer_id: &str,
        lease_owner: &str,
        limit: usize,
        lease_ms: i64,
    ) -> SqliteResult<Vec<EventId>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let now = current_timestamp_ms();
        let lease_until = now.saturating_add(lease_ms.max(1));
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);

        with_immediate_tx(self.conn, || {
            let mut stmt = self.conn.prepare(
                "SELECT we.id
                 FROM wanted_events we
                 INNER JOIN wanted_sources ws
                    ON ws.event_id = we.id
                 WHERE ws.peer_id = ?1
                   AND (we.lease_expires_at IS NULL OR we.lease_expires_at <= ?2)
                 ORDER BY
                    ws.priority_lane ASC,
                    ws.priority_ts DESC,
                    ws.first_seen_at ASC,
                    we.first_seen_at ASC,
                    ws.rowid ASC
                 LIMIT ?3",
            )?;

            let mut rows = stmt.query(params![peer_id, now, limit_i64])?;
            let mut selected = Vec::new();
            while let Some(row) = rows.next()? {
                let blob: Vec<u8> = row.get(0)?;
                if blob.len() != 32 {
                    continue;
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&blob);
                selected.push(id);
            }

            let mut claimed = Vec::with_capacity(selected.len());
            let mut update = self.conn.prepare(
                "UPDATE wanted_events
                 SET lease_peer_id = ?1,
                     lease_owner = ?2,
                     lease_expires_at = ?3
                 WHERE id = ?4
                   AND (lease_expires_at IS NULL OR lease_expires_at <= ?5)",
            )?;
            for id in selected {
                let rows = update.execute(params![peer_id, lease_owner, lease_until, &id[..], now])?;
                if rows > 0 {
                    claimed.push(id);
                }
            }
            Ok(claimed)
        })
    }

    /// Count in-flight wanted requests currently leased to `(peer_id, lease_owner)`.
    pub fn count_outstanding_for_peer(&self, peer_id: &str, lease_owner: &str) -> SqliteResult<i64> {
        let now = current_timestamp_ms();
        with_sqlite_busy_retry(|| {
            self.conn.query_row(
                "SELECT COUNT(*)
                 FROM wanted_events
                 WHERE lease_peer_id = ?1
                   AND lease_owner = ?2
                   AND lease_expires_at IS NOT NULL
                   AND lease_expires_at > ?3",
                params![peer_id, lease_owner, now],
                |row| row.get(0),
            )
        })
    }

    /// Count all work this peer can still make progress on:
    /// rows already leased to `(peer_id, lease_owner)` plus rows that are
    /// currently unleased/expired and list this peer as a candidate source.
    pub fn count_backlog_for_peer(&self, peer_id: &str, lease_owner: &str) -> SqliteResult<i64> {
        let now = current_timestamp_ms();
        with_sqlite_busy_retry(|| {
            self.conn.query_row(
                "SELECT COUNT(DISTINCT we.id)
                 FROM wanted_events we
                 INNER JOIN wanted_sources ws
                    ON ws.event_id = we.id
                 WHERE ws.peer_id = ?1
                   AND (
                        (we.lease_peer_id = ?1 AND we.lease_owner = ?2
                         AND we.lease_expires_at IS NOT NULL AND we.lease_expires_at > ?3)
                        OR we.lease_expires_at IS NULL
                        OR we.lease_expires_at <= ?3
                   )",
                params![peer_id, lease_owner, now],
                |row| row.get(0),
            )
        })
    }

    /// Release all leases held by `(peer_id, lease_owner)`.
    pub fn release_peer_leases(&self, peer_id: &str, lease_owner: &str) -> SqliteResult<usize> {
        with_sqlite_busy_retry(|| {
            self.conn.execute(
                "UPDATE wanted_events
                 SET lease_peer_id = NULL,
                     lease_owner = NULL,
                     lease_expires_at = NULL
                 WHERE lease_peer_id = ?1
                   AND lease_owner = ?2",
                params![peer_id, lease_owner],
            )
        })
    }

    /// Remove a wanted event and all candidate-source rows.
    pub fn remove(&self, id: &EventId) -> SqliteResult<()> {
        with_immediate_tx(self.conn, || {
            self.conn
                .execute("DELETE FROM wanted_sources WHERE event_id = ?1", params![&id[..]])?;
            self.conn
                .execute("DELETE FROM wanted_events WHERE id = ?1", params![&id[..]])?;
            Ok(())
        })?;
        Ok(())
    }

    /// Count total wanted events.
    pub fn count(&self) -> SqliteResult<i64> {
        with_sqlite_busy_retry(|| {
            self.conn
                .query_row("SELECT COUNT(*) FROM wanted_events", [], |row| row.get(0))
        })
    }

    /// Clear all wanted demand and candidate-source state.
    pub fn clear(&self) -> SqliteResult<()> {
        with_immediate_tx(self.conn, || {
            self.conn.execute("DELETE FROM wanted_sources", [])?;
            self.conn.execute("DELETE FROM wanted_events", [])?;
            Ok(())
        })?;
        Ok(())
    }
}

fn local_event_exists(conn: &Connection, event_id_b64: &str) -> SqliteResult<bool> {
    conn.query_row(
        "SELECT 1 FROM events WHERE event_id = ?1 LIMIT 1",
        params![event_id_b64],
        |_| Ok(()),
    )
    .optional()
    .map(|row| row.is_some())
}

fn delete_wanted_row(conn: &Connection, id: &EventId) -> SqliteResult<()> {
    conn.execute("DELETE FROM wanted_sources WHERE event_id = ?1", params![&id[..]])?;
    conn.execute("DELETE FROM wanted_events WHERE id = ?1", params![&id[..]])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_connection, schema::create_tables};
    use crate::crypto::event_id_to_base64;
    use std::time::Duration;

    fn make_event_id(byte: u8) -> EventId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    fn insert_local_event(conn: &Connection, id: &EventId) {
        conn.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, 'encrypted', x'00', 'shared', 1, 1)",
            params![event_id_to_base64(id)],
        )
        .unwrap();
    }

    #[test]
    fn test_insert_retries_transient_busy_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wanted.db");

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
            let wanted = WantedEvents::new(&conn);
            wanted
                .observe_many_for_peer("peer-a", &[make_event_id(7)])
                .unwrap()
        });

        std::thread::sleep(Duration::from_millis(80));
        lock_conn.execute("COMMIT", []).unwrap();

        assert_eq!(worker.join().unwrap(), 1);

        let verify = open_connection(&path).unwrap();
        let wanted = WantedEvents::new(&verify);
        assert_eq!(wanted.count().unwrap(), 1);
    }

    #[test]
    fn test_multi_source_claims_do_not_duplicate_live_leases() {
        let conn = crate::db::open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let wanted = WantedEvents::new(&conn);
        let ids = [make_event_id(1), make_event_id(2)];

        wanted.observe_many_for_peer("peer-a", &ids).unwrap();
        wanted.observe_many_for_peer("peer-b", &ids).unwrap();

        let claimed_a = wanted.claim_for_peer("peer-a", "owner-a", 1, 30_000).unwrap();
        assert_eq!(claimed_a.len(), 1);

        let claimed_b = wanted.claim_for_peer("peer-b", "owner-b", 2, 30_000).unwrap();
        assert_eq!(
            claimed_b.len(),
            1,
            "peer-b should only get the still-unleased event"
        );
        assert_ne!(claimed_a[0], claimed_b[0], "live leases must not overlap");
    }

    #[test]
    fn test_release_allows_another_peer_to_claim() {
        let conn = crate::db::open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let wanted = WantedEvents::new(&conn);
        let id = make_event_id(9);

        wanted.observe_many_for_peer("peer-a", &[id]).unwrap();
        wanted.observe_many_for_peer("peer-b", &[id]).unwrap();

        let claimed_a = wanted.claim_for_peer("peer-a", "owner-a", 1, 30_000).unwrap();
        assert_eq!(claimed_a, vec![id]);
        assert_eq!(wanted.release_peer_leases("peer-a", "owner-a").unwrap(), 1);

        let claimed_b = wanted.claim_for_peer("peer-b", "owner-b", 1, 30_000).unwrap();
        assert_eq!(claimed_b, vec![id]);
    }

    #[test]
    fn test_remove_clears_candidate_sources() {
        let conn = crate::db::open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let wanted = WantedEvents::new(&conn);
        let id = make_event_id(5);

        wanted.observe_many_for_peer("peer-a", &[id]).unwrap();
        wanted.observe_many_for_peer("peer-b", &[id]).unwrap();
        wanted.remove(&id).unwrap();

        let wanted_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM wanted_events WHERE id = ?1",
                params![&id[..]],
                |row| row.get(0),
            )
            .unwrap();
        let source_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM wanted_sources WHERE event_id = ?1",
                params![&id[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(wanted_count, 0);
        assert_eq!(source_count, 0);
    }

    #[test]
    fn test_local_event_cannot_be_reobserved_as_wanted() {
        let conn = crate::db::open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let wanted = WantedEvents::new(&conn);
        let id = make_event_id(11);

        wanted.observe_many_for_peer("peer-a", &[id]).unwrap();
        assert_eq!(wanted.count().unwrap(), 1);

        insert_local_event(&conn, &id);
        wanted.remove(&id).unwrap();

        assert_eq!(wanted.observe_many_for_peer("peer-a", &[id]).unwrap(), 0);

        let wanted_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM wanted_events WHERE id = ?1",
                params![&id[..]],
                |row| row.get(0),
            )
            .unwrap();
        let source_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM wanted_sources WHERE event_id = ?1",
                params![&id[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(wanted_count, 0);
        assert_eq!(source_count, 0);
    }
}
