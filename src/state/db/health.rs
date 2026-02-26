use rusqlite::{Connection, Result as SqliteResult, params};

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS peer_endpoint_observations (
            recorded_by TEXT NOT NULL,
            via_peer_id TEXT NOT NULL,
            origin_ip TEXT NOT NULL,
            origin_port INTEGER NOT NULL,
            observed_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, via_peer_id, origin_ip, origin_port, observed_at)
        );
        CREATE INDEX IF NOT EXISTS idx_peer_endpoint_expires
            ON peer_endpoint_observations(recorded_by, via_peer_id, expires_at);
        CREATE INDEX IF NOT EXISTS idx_peer_endpoint_lookup
            ON peer_endpoint_observations(recorded_by, via_peer_id, origin_ip, origin_port);
        ",
    )?;
    Ok(())
}

pub fn identity_rebind_recorded_by_tables() -> &'static [&'static str] {
    &["peer_endpoint_observations"]
}

/// Count blocked events for a peer (entries in blocked_event_deps).
pub fn blocked_event_count(conn: &Connection, peer_id: &str) -> SqliteResult<i64> {
    conn.query_row(
        "SELECT COUNT(DISTINCT event_id) FROM blocked_event_deps WHERE peer_id = ?1",
        params![peer_id],
        |row| row.get(0),
    )
}

/// Purge expired endpoint observations. Returns number deleted.
pub fn purge_expired_endpoints(conn: &Connection, now_ms: i64) -> SqliteResult<usize> {
    conn.execute(
        "DELETE FROM peer_endpoint_observations WHERE expires_at <= ?1",
        params![now_ms],
    )
}

/// Record a peer endpoint observation with INSERT OR IGNORE.
pub fn record_endpoint_observation(
    conn: &Connection,
    recorded_by: &str,
    via_peer_id: &str,
    origin_ip: &str,
    origin_port: u16,
    observed_at_ms: i64,
    ttl_ms: i64,
) -> SqliteResult<()> {
    conn.execute(
        "INSERT OR IGNORE INTO peer_endpoint_observations
         (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![recorded_by, via_peer_id, origin_ip, origin_port as i64, observed_at_ms, observed_at_ms + ttl_ms],
    )?;
    Ok(())
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

    #[test]
    fn test_blocked_event_count() {
        let conn = setup();

        // No blocked events initially
        assert_eq!(blocked_event_count(&conn, "peer1").unwrap(), 0);

        // Insert some blocked deps
        conn.execute(
            "INSERT INTO blocked_event_deps (peer_id, event_id, blocker_event_id) VALUES ('peer1', 'e1', 'b1')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO blocked_event_deps (peer_id, event_id, blocker_event_id) VALUES ('peer1', 'e1', 'b2')",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO blocked_event_deps (peer_id, event_id, blocker_event_id) VALUES ('peer1', 'e2', 'b3')",
            [],
        ).unwrap();

        // e1 has 2 blocker rows but counts as 1 distinct event
        assert_eq!(blocked_event_count(&conn, "peer1").unwrap(), 2);

        // Different peer should be 0
        assert_eq!(blocked_event_count(&conn, "peer2").unwrap(), 0);
    }

    #[test]
    fn test_purge_expired_endpoints() {
        let conn = setup();

        // Insert observations with past expires_at
        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES ('me', 'peer1', '1.2.3.4', 5000, 1000, 2000)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES ('me', 'peer2', '5.6.7.8', 6000, 1000, 3000)",
            [],
        ).unwrap();

        // Purge with cutoff at 2500 — first should be deleted, second kept
        let purged = purge_expired_endpoints(&conn, 2500).unwrap();
        assert_eq!(purged, 1);

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM peer_endpoint_observations",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_purge_keeps_valid() {
        let conn = setup();

        // Insert observations with future expires_at
        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES ('me', 'peer1', '1.2.3.4', 5000, 1000, 999999999)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES ('me', 'peer2', '5.6.7.8', 6000, 2000, 999999999)",
            [],
        ).unwrap();

        // Purge with current-ish cutoff — nothing should be deleted
        let purged = purge_expired_endpoints(&conn, 100000).unwrap();
        assert_eq!(purged, 0);

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM peer_endpoint_observations",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_purge_exactly_expired() {
        let conn = setup();

        // Insert observation that expires exactly at 2000
        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES ('me', 'peer1', '1.2.3.4', 5000, 1000, 2000)",
            [],
        ).unwrap();

        // Purge at exactly 2000 — should delete (expires_at <= now)
        let purged = purge_expired_endpoints(&conn, 2000).unwrap();
        assert_eq!(purged, 1);
    }

    #[test]
    fn test_record_endpoint_observation() {
        let conn = setup();

        record_endpoint_observation(&conn, "me", "peer1", "10.0.0.1", 4433, 5000, 86400000).unwrap();

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM peer_endpoint_observations WHERE via_peer_id = 'peer1'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(count, 1);

        let expires_at: i64 = conn.query_row(
            "SELECT expires_at FROM peer_endpoint_observations WHERE via_peer_id = 'peer1'",
            [], |row| row.get(0),
        ).unwrap();
        assert_eq!(expires_at, 5000 + 86400000);
    }
}
