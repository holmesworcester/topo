use rusqlite::{params, Connection, Result as SqliteResult};

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS intro_attempts (
            recorded_by TEXT NOT NULL,
            intro_id BLOB NOT NULL,
            introduced_by_peer_id TEXT NOT NULL,
            other_peer_id TEXT NOT NULL,
            origin_ip TEXT NOT NULL,
            origin_port INTEGER NOT NULL,
            observed_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            status TEXT NOT NULL,
            error TEXT,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, intro_id)
        );
        CREATE INDEX IF NOT EXISTS idx_intro_attempts_peer
            ON intro_attempts(recorded_by, other_peer_id, created_at DESC);
        ",
    )?;
    Ok(())
}

/// Insert a new intro attempt record (status = 'received').
pub fn insert_intro_attempt(
    conn: &Connection,
    recorded_by: &str,
    intro_id: &[u8; 16],
    introduced_by_peer_id: &str,
    other_peer_id: &str,
    origin_ip: &str,
    origin_port: u16,
    observed_at_ms: i64,
    expires_at_ms: i64,
    now_ms: i64,
) -> SqliteResult<bool> {
    let rows = conn.execute(
        "INSERT OR IGNORE INTO intro_attempts
         (recorded_by, intro_id, introduced_by_peer_id, other_peer_id,
          origin_ip, origin_port, observed_at, expires_at,
          status, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'received', ?9, ?9)",
        params![
            recorded_by,
            &intro_id[..],
            introduced_by_peer_id,
            other_peer_id,
            origin_ip,
            origin_port as i64,
            observed_at_ms,
            expires_at_ms,
            now_ms,
        ],
    )?;
    Ok(rows > 0)
}

/// Update the status of an intro attempt. Returns true if a row was updated.
pub fn update_intro_status(
    conn: &Connection,
    recorded_by: &str,
    intro_id: &[u8; 16],
    status: &str,
    error: Option<&str>,
    now_ms: i64,
) -> SqliteResult<bool> {
    let rows = conn.execute(
        "UPDATE intro_attempts SET status = ?1, error = ?2, updated_at = ?3
         WHERE recorded_by = ?4 AND intro_id = ?5",
        params![status, error, now_ms, recorded_by, &intro_id[..]],
    )?;
    Ok(rows > 0)
}

/// Check if an intro_id has already been processed (dedupe).
pub fn intro_already_seen(
    conn: &Connection,
    recorded_by: &str,
    intro_id: &[u8; 16],
) -> SqliteResult<bool> {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM intro_attempts WHERE recorded_by = ?1 AND intro_id = ?2",
        params![recorded_by, &intro_id[..]],
        |row| row.get(0),
    )
}

/// Query intro attempts for a given peer, ordered by most recent first.
pub fn list_intro_attempts(
    conn: &Connection,
    recorded_by: &str,
    filter_peer: Option<&str>,
) -> SqliteResult<Vec<IntroAttemptRow>> {
    let mut rows = Vec::new();
    if let Some(peer) = filter_peer {
        let mut stmt = conn.prepare(
            "SELECT intro_id, introduced_by_peer_id, other_peer_id,
                    origin_ip, origin_port, observed_at, expires_at,
                    status, error, created_at, updated_at
             FROM intro_attempts
             WHERE recorded_by = ?1 AND other_peer_id = ?2
             ORDER BY created_at DESC",
        )?;
        let iter = stmt.query_map(params![recorded_by, peer], row_to_intro_attempt)?;
        for r in iter {
            rows.push(r?);
        }
    } else {
        let mut stmt = conn.prepare(
            "SELECT intro_id, introduced_by_peer_id, other_peer_id,
                    origin_ip, origin_port, observed_at, expires_at,
                    status, error, created_at, updated_at
             FROM intro_attempts
             WHERE recorded_by = ?1
             ORDER BY created_at DESC",
        )?;
        let iter = stmt.query_map(params![recorded_by], row_to_intro_attempt)?;
        for r in iter {
            rows.push(r?);
        }
    }
    Ok(rows)
}

/// Query the freshest non-expired endpoint observation for a peer.
pub fn freshest_endpoint(
    conn: &Connection,
    recorded_by: &str,
    via_peer_id: &str,
    now_ms: i64,
) -> SqliteResult<Option<(String, u16, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT origin_ip, origin_port, observed_at
         FROM peer_endpoint_observations
         WHERE recorded_by = ?1 AND via_peer_id = ?2 AND expires_at > ?3
         ORDER BY observed_at DESC LIMIT 1",
    )?;
    let mut rows = stmt.query_map(params![recorded_by, via_peer_id, now_ms], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)? as u16,
            row.get::<_, i64>(2)?,
        ))
    })?;
    match rows.next() {
        Some(Ok(r)) => Ok(Some(r)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

#[derive(Debug, Clone)]
pub struct IntroAttemptRow {
    pub intro_id: Vec<u8>,
    pub introduced_by_peer_id: String,
    pub other_peer_id: String,
    pub origin_ip: String,
    pub origin_port: u16,
    pub observed_at: i64,
    pub expires_at: i64,
    pub status: String,
    pub error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

fn row_to_intro_attempt(row: &rusqlite::Row) -> SqliteResult<IntroAttemptRow> {
    Ok(IntroAttemptRow {
        intro_id: row.get(0)?,
        introduced_by_peer_id: row.get(1)?,
        other_peer_id: row.get(2)?,
        origin_ip: row.get(3)?,
        origin_port: row.get::<_, i64>(4)? as u16,
        observed_at: row.get(5)?,
        expires_at: row.get(6)?,
        status: row.get(7)?,
        error: row.get(8)?,
        created_at: row.get(9)?,
        updated_at: row.get(10)?,
    })
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
    fn test_insert_and_dedupe() {
        let conn = setup();
        let id = [0xAAu8; 16];

        assert!(!intro_already_seen(&conn, "me", &id).unwrap());

        let inserted = insert_intro_attempt(
            &conn,
            "me",
            &id,
            "introducer1",
            "peerB",
            "1.2.3.4",
            5000,
            1000,
            31000,
            2000,
        )
        .unwrap();
        assert!(inserted);

        assert!(intro_already_seen(&conn, "me", &id).unwrap());

        // Duplicate insert is ignored
        let inserted2 = insert_intro_attempt(
            &conn,
            "me",
            &id,
            "introducer1",
            "peerB",
            "1.2.3.4",
            5000,
            1000,
            31000,
            3000,
        )
        .unwrap();
        assert!(!inserted2);
    }

    #[test]
    fn test_update_status() {
        let conn = setup();
        let id = [0xBBu8; 16];

        insert_intro_attempt(
            &conn, "me", &id, "intro1", "peerC", "10.0.0.1", 4433, 1000, 31000, 2000,
        )
        .unwrap();

        let updated = update_intro_status(&conn, "me", &id, "dialing", None, 3000).unwrap();
        assert!(updated);

        let rows = list_intro_attempts(&conn, "me", None).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "dialing");
        assert_eq!(rows[0].updated_at, 3000);

        // Update to failed with error
        update_intro_status(&conn, "me", &id, "failed", Some("timeout"), 4000).unwrap();
        let rows = list_intro_attempts(&conn, "me", None).unwrap();
        assert_eq!(rows[0].status, "failed");
        assert_eq!(rows[0].error.as_deref(), Some("timeout"));
    }

    #[test]
    fn test_list_with_filter() {
        let conn = setup();

        insert_intro_attempt(
            &conn, "me", &[1u8; 16], "intro1", "peerA", "1.1.1.1", 100, 1000, 31000, 2000,
        )
        .unwrap();
        insert_intro_attempt(
            &conn, "me", &[2u8; 16], "intro1", "peerB", "2.2.2.2", 200, 1000, 31000, 3000,
        )
        .unwrap();

        let all = list_intro_attempts(&conn, "me", None).unwrap();
        assert_eq!(all.len(), 2);

        let filtered = list_intro_attempts(&conn, "me", Some("peerA")).unwrap();
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].other_peer_id, "peerA");
    }

    #[test]
    fn test_freshest_endpoint() {
        let conn = setup();
        use crate::db::health::record_endpoint_observation;

        // No observations
        assert!(freshest_endpoint(&conn, "me", "peer1", 5000)
            .unwrap()
            .is_none());

        // Add two observations at different times
        record_endpoint_observation(&conn, "me", "peer1", "10.0.0.1", 4433, 1000, 86400000)
            .unwrap();
        record_endpoint_observation(&conn, "me", "peer1", "10.0.0.2", 5000, 2000, 86400000)
            .unwrap();

        // Should get the newer one
        let (ip, port, _observed) = freshest_endpoint(&conn, "me", "peer1", 3000)
            .unwrap()
            .unwrap();
        assert_eq!(ip, "10.0.0.2");
        assert_eq!(port, 5000);

        // If both expired, returns None
        assert!(freshest_endpoint(&conn, "me", "peer1", 86400000 + 3000)
            .unwrap()
            .is_none());
    }
}
