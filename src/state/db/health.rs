use rusqlite::{params, Connection, Result as SqliteResult};

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
        params![
            recorded_by,
            via_peer_id,
            origin_ip,
            origin_port as i64,
            observed_at_ms,
            observed_at_ms + ttl_ms
        ],
    )?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointTarget {
    pub via_peer_id: String,
    pub origin_ip: String,
    pub origin_port: u16,
}

/// Return the latest non-expired observed endpoint for each remote peer.
pub fn list_live_endpoint_targets(
    conn: &Connection,
    recorded_by: &str,
    now_ms: i64,
) -> SqliteResult<Vec<EndpointTarget>> {
    let mut stmt = conn.prepare(
        "SELECT via_peer_id, origin_ip, origin_port
         FROM peer_endpoint_observations
         WHERE recorded_by = ?1
           AND expires_at > ?2
         ORDER BY via_peer_id ASC, observed_at DESC, rowid DESC",
    )?;
    let mut rows = stmt.query(params![recorded_by, now_ms])?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    while let Some(row) = rows.next()? {
        let via_peer_id: String = row.get(0)?;
        if !seen.insert(via_peer_id.clone()) {
            continue;
        }
        let origin_port: i64 = row.get(2)?;
        if !(0..=u16::MAX as i64).contains(&origin_port) {
            continue;
        }
        out.push(EndpointTarget {
            via_peer_id,
            origin_ip: row.get(1)?,
            origin_port: origin_port as u16,
        });
    }
    Ok(out)
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
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES ('me', 'peer2', '5.6.7.8', 6000, 1000, 3000)",
            [],
        )
        .unwrap();

        // Purge with cutoff at 2500 — first should be deleted, second kept
        let purged = purge_expired_endpoints(&conn, 2500).unwrap();
        assert_eq!(purged, 1);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM peer_endpoint_observations",
                [],
                |row| row.get(0),
            )
            .unwrap();
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
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES ('me', 'peer2', '5.6.7.8', 6000, 2000, 999999999)",
            [],
        )
        .unwrap();

        // Purge with current-ish cutoff — nothing should be deleted
        let purged = purge_expired_endpoints(&conn, 100000).unwrap();
        assert_eq!(purged, 0);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM peer_endpoint_observations",
                [],
                |row| row.get(0),
            )
            .unwrap();
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
        )
        .unwrap();

        // Purge at exactly 2000 — should delete (expires_at <= now)
        let purged = purge_expired_endpoints(&conn, 2000).unwrap();
        assert_eq!(purged, 1);
    }

    #[test]
    fn test_record_endpoint_observation() {
        let conn = setup();

        record_endpoint_observation(&conn, "me", "peer1", "10.0.0.1", 4433, 5000, 86400000)
            .unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM peer_endpoint_observations WHERE via_peer_id = 'peer1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);

        let expires_at: i64 = conn
            .query_row(
                "SELECT expires_at FROM peer_endpoint_observations WHERE via_peer_id = 'peer1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(expires_at, 5000 + 86400000);
    }

    #[test]
    fn test_list_live_endpoint_targets_picks_latest_per_peer() {
        let conn = setup();

        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES ('me', 'peer1', '10.0.0.1', 4433, 1000, 999999999)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES ('me', 'peer1', '10.0.0.2', 4434, 2000, 999999999)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES ('me', 'peer2', '10.0.0.3', 4435, 1500, 999999999)",
            [],
        )
        .unwrap();

        let targets = list_live_endpoint_targets(&conn, "me", 5000).unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(
            targets[0],
            EndpointTarget {
                via_peer_id: "peer1".to_string(),
                origin_ip: "10.0.0.2".to_string(),
                origin_port: 4434,
            }
        );
        assert_eq!(
            targets[1],
            EndpointTarget {
                via_peer_id: "peer2".to_string(),
                origin_ip: "10.0.0.3".to_string(),
                origin_port: 4435,
            }
        );
    }

    #[test]
    fn test_list_live_endpoint_targets_filters_expired_rows() {
        let conn = setup();

        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES ('me', 'peer1', '10.0.0.1', 4433, 1000, 1500)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO peer_endpoint_observations
             (recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)
             VALUES ('me', 'peer2', '10.0.0.2', 4434, 1000, 999999999)",
            [],
        )
        .unwrap();

        let targets = list_live_endpoint_targets(&conn, "me", 2000).unwrap();
        assert_eq!(
            targets,
            vec![EndpointTarget {
                via_peer_id: "peer2".to_string(),
                origin_ip: "10.0.0.2".to_string(),
                origin_port: 4434,
            }]
        );
    }
}
