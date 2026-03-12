use rusqlite::{params, Connection, Result as SqliteResult};

use super::queue::{
    current_timestamp_ms, with_immediate_tx, with_sqlite_busy_retry, PRIORITY_LANE_BULK,
    PRIORITY_LANE_FOREGROUND,
};
use crate::crypto::{event_id_to_base64, EventId};
use crate::tuning::bulk_egress_claim_count;

fn column_exists(conn: &Connection, table: &str, column: &str) -> SqliteResult<bool> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(names.iter().any(|name| name == column))
}

fn load_event_priority(
    conn: &Connection,
    event_id: &EventId,
    default_created_at: i64,
) -> (i64, i64) {
    let id_b64 = event_id_to_base64(event_id);
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
            params![id_b64],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                ))
            },
        )
        .unwrap_or_else(|_| ("unknown".to_string(), default_created_at, None));
    let semantic_type_code = match event_type.as_str() {
        "file_slice" => Some(crate::event_modules::EVENT_TYPE_FILE_SLICE),
        "encrypted" => encrypted_inner_type.and_then(|bytes| bytes.first().copied()),
        _ => None,
    };
    let lane = if semantic_type_code == Some(crate::event_modules::EVENT_TYPE_FILE_SLICE) {
        PRIORITY_LANE_BULK
    } else {
        PRIORITY_LANE_FOREGROUND
    };
    (lane, created_at)
}

pub fn list_remote_peer_ids(conn: &Connection, recorded_by: &str) -> SqliteResult<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT lower(hex(ps.transport_fingerprint))
         FROM peers_shared ps
         WHERE ps.recorded_by = ?1
           AND length(ps.transport_fingerprint) = 32
           AND NOT EXISTS (
             SELECT 1 FROM local_transport_creds c
             WHERE c.peer_id = lower(hex(ps.transport_fingerprint))
           )
           AND NOT EXISTS (
             SELECT 1 FROM removed_entities r
             WHERE r.recorded_by = ps.recorded_by
               AND r.target_event_id = ps.event_id
           )
           AND NOT EXISTS (
             SELECT 1 FROM removed_entities r
             WHERE r.recorded_by = ps.recorded_by
               AND ps.user_event_id IS NOT NULL
               AND r.target_event_id = ps.user_event_id
               AND r.removal_type = 'user'
           )
         ORDER BY 1",
    )?;
    let peer_ids = stmt
        .query_map(params![recorded_by], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(peer_ids)
}

pub fn enqueue_local_shared_event_to_remote_peers(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
) -> SqliteResult<usize> {
    let now = current_timestamp_ms();
    let (priority_lane, priority_ts) = load_event_priority(conn, event_id, now);
    enqueue_local_shared_event_to_remote_peers_with_priority(
        conn,
        recorded_by,
        event_id,
        priority_lane,
        priority_ts,
    )
}

pub fn enqueue_local_shared_event_to_remote_peers_with_priority(
    conn: &Connection,
    recorded_by: &str,
    event_id: &EventId,
    priority_lane: i64,
    priority_ts: i64,
) -> SqliteResult<usize> {
    let peer_ids = list_remote_peer_ids(conn, recorded_by)?;
    if peer_ids.is_empty() {
        return Ok(0);
    }

    let now = current_timestamp_ms();
    let mut stmt = conn.prepare(
        "INSERT OR IGNORE INTO egress_queue
         (connection_id, frame_type, event_id, enqueued_at, available_at, priority_lane, priority_ts)
         VALUES (?1, 'event', ?2, ?3, ?3, ?4, ?5)",
    )?;
    let mut inserted = 0usize;
    for peer_id in peer_ids {
        inserted += stmt.execute(params![
            peer_id,
            &event_id[..],
            now,
            priority_lane,
            priority_ts
        ])?;
    }
    Ok(inserted)
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
            lease_owner TEXT,
            sent_at INTEGER,
            dedupe_key TEXT,
            priority_lane INTEGER NOT NULL DEFAULT 1,
            priority_ts INTEGER NOT NULL DEFAULT 0
        );
        CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_pending_event
            ON egress_queue(connection_id, event_id)
            WHERE frame_type = 'event' AND sent_at IS NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_egress_dedupe
            ON egress_queue(dedupe_key)
            WHERE dedupe_key IS NOT NULL AND sent_at IS NULL;
        CREATE INDEX IF NOT EXISTS idx_egress_claim
            ON egress_queue(connection_id, priority_lane, priority_ts DESC, id)
            WHERE sent_at IS NULL;
        ",
    )?;
    if !column_exists(conn, "egress_queue", "lease_owner")? {
        conn.execute("ALTER TABLE egress_queue ADD COLUMN lease_owner TEXT", [])?;
    }
    if !column_exists(conn, "egress_queue", "priority_lane")? {
        conn.execute(
            "ALTER TABLE egress_queue ADD COLUMN priority_lane INTEGER NOT NULL DEFAULT 1",
            [],
        )?;
    }
    if !column_exists(conn, "egress_queue", "priority_ts")? {
        conn.execute(
            "ALTER TABLE egress_queue ADD COLUMN priority_ts INTEGER NOT NULL DEFAULT 0",
            [],
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
                 (connection_id, frame_type, event_id, enqueued_at, available_at, priority_lane, priority_ts)
                 VALUES (?1, 'event', ?2, ?3, ?3, ?4, ?5)",
            )?;
            let mut inserted = 0usize;
            for id in event_ids {
                let (priority_lane, priority_ts) = load_event_priority(self.conn, id, now);
                inserted += stmt.execute(params![
                    connection_id,
                    &id[..],
                    now,
                    priority_lane,
                    priority_ts
                ])?;
            }
            Ok(inserted)
        })
    }

    /// Claim a batch of unsent items for sending.
    /// Returns (rowid, event_id) pairs.
    pub fn claim_batch(
        &self,
        connection_id: &str,
        lease_owner: &str,
        limit: usize,
        lease_ms: i64,
    ) -> SqliteResult<Vec<(i64, EventId)>> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let now = current_timestamp_ms();
        let lease_until = now + lease_ms;
        with_immediate_tx(self.conn, || {
            let head_lane: Option<i64> = self
                .conn
                .query_row(
                    "SELECT priority_lane
                     FROM egress_queue
                     WHERE connection_id = ?1
                       AND available_at <= ?2
                       AND sent_at IS NULL
                       AND (lease_until IS NULL OR lease_until <= ?2)
                     ORDER BY priority_lane ASC, priority_ts DESC, id ASC
                     LIMIT 1",
                    params![connection_id, now],
                    |row| row.get(0),
                )
                .ok();
            let Some(head_lane) = head_lane else {
                return Ok(Vec::new());
            };
            let claim_limit = if head_lane == PRIORITY_LANE_BULK {
                limit.min(bulk_egress_claim_count())
            } else {
                limit
            };
            let mut select_stmt = self.conn.prepare(
                "SELECT id, event_id FROM egress_queue
                 WHERE connection_id = ?1
                 AND priority_lane = ?2
                 AND available_at <= ?3
                 AND sent_at IS NULL
                 AND (lease_until IS NULL OR lease_until <= ?3)
                 ORDER BY priority_ts DESC, id ASC
                 LIMIT ?4",
            )?;
            let rows: Vec<(i64, Vec<u8>)> = select_stmt
                .query_map(
                    params![connection_id, head_lane, now, claim_limit as i64],
                    |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)),
                )?
                .collect::<Result<Vec<_>, _>>()?;

            if rows.is_empty() {
                return Ok(Vec::new());
            }

            let mut lease_stmt = self.conn.prepare(
                "UPDATE egress_queue
                 SET lease_owner = ?1, lease_until = ?2
                 WHERE id = ?3
                   AND sent_at IS NULL
                   AND available_at <= ?4
                   AND (lease_until IS NULL OR lease_until <= ?4)",
            )?;
            let mut result = Vec::with_capacity(rows.len());
            for (rowid, blob) in rows {
                let claimed = lease_stmt.execute(params![lease_owner, lease_until, rowid, now])?;
                if claimed == 0 {
                    continue;
                }
                if blob.len() == 32 {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&blob);
                    result.push((rowid, id));
                }
            }

            Ok(result)
        })
    }

    /// Mark items as sent by deleting them from the queue, scoped to the
    /// claiming session lease owner.
    pub fn mark_sent(&self, lease_owner: &str, rowids: &[i64]) -> SqliteResult<()> {
        if rowids.is_empty() {
            return Ok(());
        }
        with_immediate_tx(self.conn, || {
            let mut stmt = self.conn.prepare(
                "DELETE FROM egress_queue
                 WHERE id = ?1 AND lease_owner = ?2",
            )?;
            for rowid in rowids {
                stmt.execute(params![rowid, lease_owner])?;
            }
            Ok(())
        })
    }

    /// Count pending (unsent) items for a connection.
    pub fn count_pending(&self, connection_id: &str) -> SqliteResult<i64> {
        let now = current_timestamp_ms();
        with_sqlite_busy_retry(|| {
            self.conn.query_row(
                "SELECT COUNT(*) FROM egress_queue
                 WHERE connection_id = ?1
                   AND available_at <= ?2
                   AND sent_at IS NULL
                   AND (lease_until IS NULL OR lease_until <= ?2)",
                params![connection_id, now],
                |row| row.get(0),
            )
        })
    }

    /// Release all outstanding leases owned by a session for a connection.
    pub fn release_leases(&self, connection_id: &str, lease_owner: &str) -> SqliteResult<usize> {
        with_sqlite_busy_retry(|| {
            self.conn.execute(
                "UPDATE egress_queue
                 SET lease_owner = NULL, lease_until = NULL
                 WHERE connection_id = ?1
                   AND lease_owner = ?2
                   AND sent_at IS NULL",
                params![connection_id, lease_owner],
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
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::event_modules::EVENT_TYPE_FILE_SLICE;

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

    fn make_peer_fingerprint(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    fn peer_id_hex(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
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
        conn.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, 'message', x'01', 'shared', 10, 10)",
            params![event_id_to_base64(&ids[0])],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, 'message', x'02', 'shared', 20, 20)",
            params![event_id_to_base64(&ids[1])],
        )
        .unwrap();
        eq.enqueue_events("conn1", &ids).unwrap();

        let claimed = eq.claim_batch("conn1", "sess-1", 10, 30_000).unwrap();
        assert_eq!(claimed.len(), 2);

        let rowids: Vec<i64> = claimed.iter().map(|(r, _)| *r).collect();
        eq.mark_sent("sess-1", &rowids).unwrap();

        let pending = eq.count_pending("conn1").unwrap();
        assert_eq!(pending, 0);
    }

    #[test]
    fn test_claim_skips_sent() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let ids = vec![make_event_id(1)];
        conn.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, 'message', x'01', 'shared', 10, 10)",
            params![event_id_to_base64(&ids[0])],
        )
        .unwrap();
        eq.enqueue_events("conn1", &ids).unwrap();

        let claimed = eq.claim_batch("conn1", "sess-1", 10, 30_000).unwrap();
        let rowids: Vec<i64> = claimed.iter().map(|(r, _)| *r).collect();
        eq.mark_sent("sess-1", &rowids).unwrap();

        // Try claiming again — should get nothing
        let claimed2 = eq.claim_batch("conn1", "sess-1", 10, 30_000).unwrap();
        assert_eq!(claimed2.len(), 0, "sent items should not be re-claimed");
    }

    #[test]
    fn test_mark_sent_deletes() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let ids = vec![make_event_id(1), make_event_id(2)];
        for (idx, id) in ids.iter().enumerate() {
            conn.execute(
                "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
                 VALUES (?1, 'message', ?2, 'shared', ?3, ?3)",
                params![event_id_to_base64(id), vec![idx as u8], idx as i64],
            )
            .unwrap();
        }
        eq.enqueue_events("conn1", &ids).unwrap();

        let claimed = eq.claim_batch("conn1", "sess-1", 10, 30_000).unwrap();
        let rowids: Vec<i64> = claimed.iter().map(|(r, _)| *r).collect();
        eq.mark_sent("sess-1", &rowids).unwrap();

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
        for (idx, id) in ids.iter().enumerate() {
            conn.execute(
                "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
                 VALUES (?1, 'message', ?2, 'shared', ?3, ?3)",
                params![event_id_to_base64(id), vec![idx as u8], idx as i64],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, 'message', x'03', 'shared', 3, 3)",
            params![event_id_to_base64(&make_event_id(3))],
        )
        .unwrap();
        eq.enqueue_events("conn1", &ids).unwrap();
        eq.enqueue_events("conn2", &[make_event_id(3)]).unwrap();

        eq.clear_connection("conn1").unwrap();

        let count1 = eq.count_pending("conn1").unwrap();
        let count2 = eq.count_pending("conn2").unwrap();
        assert_eq!(count1, 0);
        assert_eq!(count2, 1, "conn2's items should be unaffected");
    }

    #[test]
    fn test_claim_batch_respects_priority_and_newness() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let message_new = make_event_id(1);
        let message_old = make_event_id(2);
        let bulk_new = make_event_id(3);
        for (id, event_type, created_at) in [
            (message_new, "message", 300i64),
            (message_old, "message", 100i64),
            (bulk_new, "file_slice", 500i64),
        ] {
            conn.execute(
                "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
                 VALUES (?1, ?2, x'01', 'shared', ?3, ?3)",
                params![event_id_to_base64(&id), event_type, created_at],
            )
            .unwrap();
        }

        eq.enqueue_events("conn1", &[bulk_new, message_old, message_new])
            .unwrap();
        let claimed = eq.claim_batch("conn1", "sess-1", 10, 30_000).unwrap();
        let claimed_ids: Vec<EventId> = claimed.into_iter().map(|(_, id)| id).collect();

        assert_eq!(
            claimed_ids,
            vec![message_new, message_old],
            "foreground rows should be claimed before bulk, and newer rows before older ones"
        );

        let claimed_bulk = eq.claim_batch("conn1", "sess-1b", 10, 30_000).unwrap();
        let claimed_bulk_ids: Vec<EventId> = claimed_bulk.into_iter().map(|(_, id)| id).collect();
        assert_eq!(claimed_bulk_ids, vec![bulk_new]);
    }

    #[test]
    fn test_claim_batch_caps_bulk_quantum() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let bulk_a = make_event_id(0x11);
        let bulk_b = make_event_id(0x12);
        let bulk_c = make_event_id(0x13);
        for (id, created_at) in [(bulk_a, 10i64), (bulk_b, 20i64), (bulk_c, 30i64)] {
            conn.execute(
                "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
                 VALUES (?1, 'file_slice', x'01', 'shared', ?2, ?2)",
                params![event_id_to_base64(&id), created_at],
            )
            .unwrap();
        }

        eq.enqueue_events("conn1", &[bulk_a, bulk_b, bulk_c])
            .unwrap();
        let claimed = eq.claim_batch("conn1", "sess-1", 10, 30_000).unwrap();

        assert_eq!(
            claimed.len(),
            bulk_egress_claim_count(),
            "bulk head-of-line batches should be claimed in small quanta"
        );
    }

    #[test]
    fn test_encrypted_file_slice_claims_as_bulk() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let encrypted_file_slice = make_event_id(0x21);
        let message = make_event_id(0x22);
        let encrypted_blob = crate::event_modules::encode_event(
            &crate::event_modules::ParsedEvent::Encrypted(crate::event_modules::EncryptedEvent {
                created_at_ms: 200,
                key_event_id: [7u8; 32],
                inner_type_code: EVENT_TYPE_FILE_SLICE,
                nonce: [8u8; 12],
                ciphertext: vec![0u8; crate::event_modules::file_slice::FILE_SLICE_WIRE_SIZE],
                auth_tag: [9u8; 16],
            }),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, 'encrypted', ?2, 'shared', 200, 200)",
            params![event_id_to_base64(&encrypted_file_slice), encrypted_blob],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, 'message', x'01', 'shared', 100, 100)",
            params![event_id_to_base64(&message)],
        )
        .unwrap();

        eq.enqueue_events("conn1", &[encrypted_file_slice, message])
            .unwrap();
        let claimed = eq.claim_batch("conn1", "sess-1", 10, 30_000).unwrap();
        let claimed_ids: Vec<EventId> = claimed.into_iter().map(|(_, id)| id).collect();

        assert_eq!(
            claimed_ids,
            vec![message],
            "encrypted file slices should be scheduled by their inner semantic type"
        );

        let claimed_bulk = eq.claim_batch("conn1", "sess-2", 10, 30_000).unwrap();
        let claimed_bulk_ids: Vec<EventId> = claimed_bulk.into_iter().map(|(_, id)| id).collect();
        assert_eq!(claimed_bulk_ids, vec![encrypted_file_slice]);
    }

    #[test]
    fn test_concurrent_claims_do_not_duplicate_rows() {
        let conn = setup();
        let eq = EgressQueue::new(&conn);

        let ids = vec![make_event_id(1), make_event_id(2), make_event_id(3)];
        for (idx, id) in ids.iter().enumerate() {
            conn.execute(
                "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
                 VALUES (?1, 'message', x'01', 'shared', ?2, ?2)",
                params![event_id_to_base64(id), idx as i64],
            )
            .unwrap();
        }
        eq.enqueue_events("conn1", &ids).unwrap();

        let first = eq.claim_batch("conn1", "sess-a", 2, 30_000).unwrap();
        let second = eq.claim_batch("conn1", "sess-b", 2, 30_000).unwrap();

        let first_rowids: std::collections::HashSet<i64> =
            first.iter().map(|(rowid, _)| *rowid).collect();
        let second_rowids: std::collections::HashSet<i64> =
            second.iter().map(|(rowid, _)| *rowid).collect();

        assert!(
            first_rowids.is_disjoint(&second_rowids),
            "different lease owners must not claim the same queue rows"
        );
    }

    #[test]
    fn test_enqueue_local_shared_event_targets_only_active_remote_peers() {
        let conn = setup();
        let event_id = make_event_id(9);
        conn.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, 'message', x'09', 'shared', 90, 90)",
            params![event_id_to_base64(&event_id)],
        )
        .unwrap();

        let remote_live = make_peer_fingerprint(0x11);
        let remote_removed = make_peer_fingerprint(0x22);
        let local_peer = make_peer_fingerprint(0x33);

        conn.execute(
            "INSERT INTO peers_shared
             (recorded_by, event_id, public_key, transport_fingerprint, device_name)
             VALUES (?1, ?2, ?3, ?4, 'remote-live')",
            params!["alice", "peer-live", vec![1u8; 32], remote_live],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peers_shared
             (recorded_by, event_id, public_key, transport_fingerprint, device_name)
             VALUES (?1, ?2, ?3, ?4, 'remote-removed')",
            params!["alice", "peer-removed", vec![2u8; 32], remote_removed],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peers_shared
             (recorded_by, event_id, public_key, transport_fingerprint, device_name)
             VALUES (?1, ?2, ?3, ?4, 'local')",
            params!["alice", "peer-local", vec![3u8; 32], local_peer],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO local_transport_creds (peer_id, cert_der, key_der, created_at, source)
             VALUES (?1, x'01', x'02', 1, 'random')",
            params![peer_id_hex(0x33)],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO removed_entities (recorded_by, event_id, target_event_id, removal_type)
             VALUES (?1, ?2, ?3, 'peer')",
            params!["alice", "peer-removed-tombstone", "peer-removed"],
        )
        .unwrap();

        let inserted =
            enqueue_local_shared_event_to_remote_peers(&conn, "alice", &event_id).unwrap();
        assert_eq!(
            inserted, 1,
            "only live remote peers should receive direct egress rows"
        );

        let mut stmt = conn
            .prepare("SELECT connection_id FROM egress_queue ORDER BY connection_id")
            .unwrap();
        let queued_peer_ids = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(queued_peer_ids, vec![peer_id_hex(0x11)]);
    }
}
