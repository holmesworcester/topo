use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use super::queue::{
    current_timestamp_ms, with_immediate_tx, with_sqlite_busy_retry, PRIORITY_LANE_FOREGROUND,
};
use super::timeline::EventTimeline;
use crate::crypto::{event_id_to_base64, EventId};
use crate::protocol::DiscoveryHint;

/// Wanted events - events the sink still needs to fetch.
///
/// `wanted_events` records demand exactly once per event ID.
/// `wanted_sources` records which peers appear to have that event.
/// `wanted_events` also carries source-discovered type/size metadata so the
/// request planner can budget byte credits without loading blobs.
pub struct WantedEvents<'a> {
    conn: &'a Connection,
}

/// Conservative floor for events whose size is not yet known (e.g. negentropy
/// diff IDs before the responder's DiscoveryHints arrive). Ensures credit
/// accounting is never zero for a real event.
pub const UNKNOWN_EVENT_CREDIT_FLOOR_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WantedCandidate {
    pub event_id: EventId,
    pub semantic_type_code: u8,
    pub encoded_size_bytes: u32,
    pub priority_lane: i64,
    pub priority_ts: i64,
    pub first_seen_at: i64,
}

impl WantedCandidate {
    /// Effective byte cost for credit accounting. Returns the real size when
    /// known, or a conservative floor when metadata has not yet arrived.
    pub fn credit_cost(&self) -> usize {
        if self.encoded_size_bytes == 0 {
            UNKNOWN_EVENT_CREDIT_FLOOR_BYTES
        } else {
            self.encoded_size_bytes as usize
        }
    }
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS wanted_events (
            id BLOB PRIMARY KEY,
            first_seen_at INTEGER NOT NULL,
            semantic_type_code INTEGER,
            encoded_size_bytes INTEGER
        );

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

    /// Insert pure demand for missing events for a specific local tenant.
    ///
    /// This is used by projection blocking paths where the sink knows it still
    /// needs a dependency, but does not yet know which peer can satisfy it.
    /// Demand is tenant-scoped via `recorded_events`, so shared-DB sibling
    /// blobs do not incorrectly suppress fetches for the current tenant.
    pub fn insert_many_for_local(
        &self,
        local_peer_id: &str,
        ids: &[EventId],
    ) -> SqliteResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }

        let now = current_timestamp_ms();
        let mut already_recorded = self.conn.prepare(
            "SELECT 1 FROM recorded_events
             WHERE peer_id = ?1 AND event_id = ?2
             LIMIT 1",
        )?;
        let mut insert_wanted = self
            .conn
            .prepare("INSERT OR IGNORE INTO wanted_events (id, first_seen_at) VALUES (?1, ?2)")?;

        let mut inserted = 0usize;
        for id in ids {
            let id_b64 = event_id_to_base64(id);
            let already_local = already_recorded
                .query_row(params![local_peer_id, &id_b64], |_| Ok(()))
                .optional()?
                .is_some();
            if already_local {
                delete_wanted_row(self.conn, id)?;
                continue;
            }
            let rows = insert_wanted.execute(params![&id[..], now])?;
            if rows > 0 {
                inserted += 1;
            }
        }

        Ok(inserted)
    }

    /// Observe that `peer_id` appears to have each event in `ids`.
    ///
    /// This records event demand once and candidate source membership per peer.
    pub fn observe_many_for_peer(
        &self,
        local_peer_id: &str,
        peer_id: &str,
        hints: &[DiscoveryHint],
        discovery_round_started_at: i64,
        timeline: &EventTimeline<'_>,
    ) -> SqliteResult<usize> {
        if hints.is_empty() {
            return Ok(0);
        }
        let now = current_timestamp_ms();
        with_immediate_tx(self.conn, || {
            let mut already_recorded = self.conn.prepare(
                "SELECT 1 FROM recorded_events
                 WHERE peer_id = ?1 AND event_id = ?2
                 LIMIT 1",
            )?;
            let mut upsert_wanted = self.conn.prepare(
                "INSERT INTO wanted_events (id, first_seen_at, semantic_type_code, encoded_size_bytes)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(id) DO UPDATE SET
                     semantic_type_code = COALESCE(NULLIF(excluded.semantic_type_code, 0), NULLIF(wanted_events.semantic_type_code, 0), excluded.semantic_type_code),
                     encoded_size_bytes = COALESCE(NULLIF(excluded.encoded_size_bytes, 0), NULLIF(wanted_events.encoded_size_bytes, 0), excluded.encoded_size_bytes)",
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
            let mut discovered_ids = Vec::with_capacity(hints.len());
            for hint in hints {
                let id_b64 = event_id_to_base64(&hint.event_id);
                let already_local = already_recorded
                    .query_row(params![local_peer_id, &id_b64], |_| Ok(()))
                    .optional()?
                    .is_some();
                if already_local {
                    delete_wanted_row(self.conn, &hint.event_id)?;
                    continue;
                }
                let _ = upsert_wanted.execute(params![
                    &hint.event_id[..],
                    now,
                    i64::from(hint.semantic_type_code),
                    i64::from(hint.encoded_size_bytes),
                ])?;
                upsert_source.execute(params![
                    &hint.event_id[..],
                    peer_id,
                    now,
                    PRIORITY_LANE_FOREGROUND,
                    now,
                ])?;
                observed += 1;
                discovered_ids.push(hint.event_id);
            }
            if !discovered_ids.is_empty() {
                let _ = timeline.mark_discovered_many_with_round_start(
                    &discovered_ids,
                    discovery_round_started_at,
                    now,
                );
            }
            Ok(observed)
        })
    }

    /// Load candidate request rows for `peer_id`, ordered by current priority.
    pub fn list_candidates_for_peer(
        &self,
        peer_id: &str,
        limit: usize,
    ) -> SqliteResult<Vec<WantedCandidate>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        with_sqlite_busy_retry(|| {
            let mut stmt = self.conn.prepare(
                "SELECT we.id, we.semantic_type_code, we.encoded_size_bytes,
                        ws.priority_lane, ws.priority_ts, we.first_seen_at
                 FROM wanted_events we
                 INNER JOIN wanted_sources ws
                    ON ws.event_id = we.id
                 WHERE ws.peer_id = ?1
                   AND we.semantic_type_code IS NOT NULL
                   AND we.encoded_size_bytes IS NOT NULL
                 ORDER BY
                    ws.priority_lane ASC,
                    ws.priority_ts DESC,
                    ws.first_seen_at ASC,
                    we.first_seen_at ASC,
                    ws.rowid ASC
                 LIMIT ?2",
            )?;
            let rows = stmt.query_map(params![peer_id, limit_i64], |row| {
                let blob: Vec<u8> = row.get(0)?;
                let semantic_type_code_i64: i64 = row.get(1)?;
                let encoded_size_bytes_i64: i64 = row.get(2)?;
                let mut event_id = [0u8; 32];
                if blob.len() != 32 {
                    return Err(rusqlite::Error::InvalidColumnType(
                        0,
                        "id".to_string(),
                        rusqlite::types::Type::Blob,
                    ));
                }
                event_id.copy_from_slice(&blob);
                Ok(WantedCandidate {
                    event_id,
                    semantic_type_code: u8::try_from(semantic_type_code_i64).map_err(|_| {
                        rusqlite::Error::IntegralValueOutOfRange(1, semantic_type_code_i64)
                    })?,
                    encoded_size_bytes: u32::try_from(encoded_size_bytes_i64).map_err(|_| {
                        rusqlite::Error::IntegralValueOutOfRange(2, encoded_size_bytes_i64)
                    })?,
                    priority_lane: row.get(3)?,
                    priority_ts: row.get(4)?,
                    first_seen_at: row.get(5)?,
                })
            })?;
            rows.collect::<Result<Vec<_>, _>>()
        })
    }

    /// Count all work this peer can still make progress on:
    /// distinct wanted rows that currently list this peer as a candidate
    /// source. Request in-flight suppression is now memory-only.
    pub fn count_backlog_for_peer(&self, peer_id: &str) -> SqliteResult<i64> {
        with_sqlite_busy_retry(|| {
            self.conn.query_row(
                "SELECT COUNT(DISTINCT we.id)
                 FROM wanted_events we
                 INNER JOIN wanted_sources ws
                    ON ws.event_id = we.id
                 WHERE ws.peer_id = ?1",
                params![peer_id],
                |row| row.get(0),
            )
        })
    }

    /// Remove a wanted event and all candidate-source rows.
    pub fn remove(&self, id: &EventId) -> SqliteResult<()> {
        with_immediate_tx(self.conn, || {
            self.conn.execute(
                "DELETE FROM wanted_sources WHERE event_id = ?1",
                params![&id[..]],
            )?;
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
    conn.execute(
        "DELETE FROM wanted_sources WHERE event_id = ?1",
        params![&id[..]],
    )?;
    conn.execute("DELETE FROM wanted_events WHERE id = ?1", params![&id[..]])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::event_id_to_base64;
    use crate::db::{open_connection, schema::create_tables, timeline::EventTimeline};
    use std::time::Duration;

    fn make_event_id(byte: u8) -> EventId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    fn discovery_hint(byte: u8, type_code: u8, encoded_size_bytes: u32) -> DiscoveryHint {
        DiscoveryHint {
            event_id: make_event_id(byte),
            semantic_type_code: type_code,
            encoded_size_bytes,
        }
    }

    fn insert_local_event(conn: &Connection, id: &EventId) {
        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, 'encrypted', x'00', 'shared', 1, 1)",
            params![event_id_to_base64(id)],
        )
        .unwrap();
    }

    fn mark_recorded_for_peer(conn: &Connection, peer_id: &str, id: &EventId) {
        insert_local_event(conn, id);
        conn.execute(
            "INSERT INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, 1, 'test')",
            params![peer_id, event_id_to_base64(id)],
        )
        .unwrap();
    }

    #[test]
    fn test_insert_many_for_local_uses_tenant_recorded_state_not_global_blob_presence() {
        let conn = crate::db::open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let wanted = WantedEvents::new(&conn);
        let id = make_event_id(42);

        insert_local_event(&conn, &id);
        assert_eq!(
            wanted.insert_many_for_local("tenant-a", &[id]).unwrap(),
            1,
            "raw blob presence must not suppress tenant-local demand"
        );

        mark_recorded_for_peer(&conn, "tenant-a", &id);
        assert_eq!(
            wanted.insert_many_for_local("tenant-a", &[id]).unwrap(),
            0,
            "tenant-recorded events must not remain wanted"
        );

        let wanted_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM wanted_events WHERE id = ?1",
                params![&id[..]],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(wanted_count, 0);
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
            let timeline = EventTimeline::new(&conn);
            wanted
                .observe_many_for_peer(
                    "local",
                    "peer-a",
                    &[discovery_hint(7, crate::event_modules::EVENT_TYPE_MESSAGE, 144)],
                    1,
                    &timeline,
                )
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
    fn test_multi_source_candidates_keep_metadata_and_backlog() {
        let conn = crate::db::open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let wanted = WantedEvents::new(&conn);
        let timeline = EventTimeline::new(&conn);
        let hints = [
            discovery_hint(1, crate::event_modules::EVENT_TYPE_MESSAGE, 144),
            discovery_hint(2, crate::event_modules::EVENT_TYPE_REACTION, 96),
        ];

        wanted
            .observe_many_for_peer("local", "peer-a", &hints, 1, &timeline)
            .unwrap();
        wanted
            .observe_many_for_peer("local", "peer-b", &hints, 1, &timeline)
            .unwrap();

        let peer_a_candidates = wanted.list_candidates_for_peer("peer-a", 8).unwrap();
        assert_eq!(peer_a_candidates.len(), 2);
        assert_eq!(peer_a_candidates[0].semantic_type_code, crate::event_modules::EVENT_TYPE_MESSAGE);
        assert_eq!(peer_a_candidates[0].encoded_size_bytes, 144);
        assert_eq!(wanted.count_backlog_for_peer("peer-b").unwrap(), 2);
    }

    #[test]
    fn test_remove_clears_candidate_sources() {
        let conn = crate::db::open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let wanted = WantedEvents::new(&conn);
        let timeline = EventTimeline::new(&conn);
        let id = make_event_id(5);

        wanted
            .observe_many_for_peer(
                "local",
                "peer-a",
                &[DiscoveryHint {
                    event_id: id,
                    semantic_type_code: crate::event_modules::EVENT_TYPE_MESSAGE,
                    encoded_size_bytes: 144,
                }],
                1,
                &timeline,
            )
            .unwrap();
        wanted
            .observe_many_for_peer(
                "local",
                "peer-b",
                &[DiscoveryHint {
                    event_id: id,
                    semantic_type_code: crate::event_modules::EVENT_TYPE_MESSAGE,
                    encoded_size_bytes: 144,
                }],
                1,
                &timeline,
            )
            .unwrap();
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
        let timeline = EventTimeline::new(&conn);
        let id = make_event_id(11);

        wanted
            .observe_many_for_peer(
                "local",
                "peer-a",
                &[DiscoveryHint {
                    event_id: id,
                    semantic_type_code: crate::event_modules::EVENT_TYPE_MESSAGE,
                    encoded_size_bytes: 144,
                }],
                1,
                &timeline,
            )
            .unwrap();
        assert_eq!(wanted.count().unwrap(), 1);

        insert_local_event(&conn, &id);
        mark_recorded_for_peer(&conn, "local", &id);
        wanted.remove(&id).unwrap();

        assert_eq!(
            wanted
                .observe_many_for_peer(
                    "local",
                    "peer-a",
                    &[DiscoveryHint {
                        event_id: id,
                        semantic_type_code: crate::event_modules::EVENT_TYPE_MESSAGE,
                        encoded_size_bytes: 144,
                    }],
                    1,
                    &timeline,
                )
                .unwrap(),
            0
        );

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
