use rusqlite::{params, Connection, Result as SqliteResult};

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS local_client_ops (
            recorded_by TEXT NOT NULL,
            client_op_id TEXT NOT NULL,
            event_id BLOB NOT NULL,
            op_kind TEXT NOT NULL,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, client_op_id)
        );
        CREATE INDEX IF NOT EXISTS idx_local_client_ops_event
            ON local_client_ops(recorded_by, event_id);
        ",
    )?;
    Ok(())
}

/// Insert a client_op_id → event_id mapping.
pub fn insert(
    conn: &Connection,
    recorded_by: &str,
    client_op_id: &str,
    event_id: &[u8; 32],
    op_kind: &str,
    created_at_ms: i64,
) -> SqliteResult<()> {
    conn.execute(
        "INSERT OR IGNORE INTO local_client_ops (recorded_by, client_op_id, event_id, op_kind, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![recorded_by, client_op_id, &event_id[..], op_kind, created_at_ms],
    )?;
    Ok(())
}

/// Look up a client_op_id for a given event_id (used to annotate view responses).
pub fn lookup_by_event_id(
    conn: &Connection,
    recorded_by: &str,
    event_id: &[u8],
) -> SqliteResult<Option<String>> {
    let mut stmt = conn.prepare(
        "SELECT client_op_id FROM local_client_ops WHERE recorded_by = ?1 AND event_id = ?2",
    )?;
    let mut rows = stmt.query(params![recorded_by, event_id])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

/// Bulk lookup: returns a map of base64(event_id) → client_op_id for all mapped events
/// belonging to this peer. Used to annotate view responses efficiently.
pub fn all_mappings(
    conn: &Connection,
    recorded_by: &str,
) -> SqliteResult<std::collections::HashMap<String, String>> {
    let mut stmt = conn.prepare(
        "SELECT event_id, client_op_id FROM local_client_ops WHERE recorded_by = ?1",
    )?;
    let mut map = std::collections::HashMap::new();
    let mut rows = stmt.query(params![recorded_by])?;
    while let Some(row) = rows.next()? {
        let eid_bytes: Vec<u8> = row.get(0)?;
        let client_op_id: String = row.get(1)?;
        use base64::Engine;
        let eid_b64 = base64::engine::general_purpose::STANDARD.encode(&eid_bytes);
        map.insert(eid_b64, client_op_id);
    }
    Ok(map)
}

/// Prune entries older than the given age in milliseconds.
pub fn prune(conn: &Connection, recorded_by: &str, max_age_ms: i64) -> SqliteResult<usize> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let cutoff = now - max_age_ms;
    conn.execute(
        "DELETE FROM local_client_ops WHERE recorded_by = ?1 AND created_at_ms < ?2",
        params![recorded_by, cutoff],
    )
}
