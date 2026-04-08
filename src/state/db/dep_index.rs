use rusqlite::{params, Connection, Result as SqliteResult};

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS shared_event_deps (
            workspace_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            dep_event_id TEXT NOT NULL,
            PRIMARY KEY (workspace_id, event_id, dep_event_id)
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS idx_shared_event_deps_lookup
            ON shared_event_deps(workspace_id, event_id, dep_event_id);
        ",
    )?;
    Ok(())
}

pub fn replace_shared_event_deps(
    conn: &Connection,
    workspace_id: &str,
    event_id: &EventId,
    dep_ids: &[EventId],
) -> SqliteResult<()> {
    let event_id_b64 = event_id_to_base64(event_id);
    conn.execute(
        "DELETE FROM shared_event_deps
         WHERE workspace_id = ?1
           AND event_id = ?2",
        params![workspace_id, event_id_b64],
    )?;
    if dep_ids.is_empty() {
        return Ok(());
    }

    let mut stmt = conn.prepare(
        "INSERT OR IGNORE INTO shared_event_deps (workspace_id, event_id, dep_event_id)
         VALUES (?1, ?2, ?3)",
    )?;
    for dep_id in dep_ids {
        stmt.execute(params![
            workspace_id,
            event_id_b64,
            event_id_to_base64(dep_id)
        ])?;
    }
    Ok(())
}

pub fn list_shared_event_deps(
    conn: &Connection,
    workspace_id: &str,
    event_id: &EventId,
) -> SqliteResult<Vec<EventId>> {
    list_shared_event_deps_limited(conn, workspace_id, event_id, usize::MAX)
}

pub fn list_shared_event_deps_limited(
    conn: &Connection,
    workspace_id: &str,
    event_id: &EventId,
    limit: usize,
) -> SqliteResult<Vec<EventId>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let event_id_b64 = event_id_to_base64(event_id);
    let mut stmt = conn.prepare(
        "SELECT dep_event_id
         FROM shared_event_deps
         WHERE workspace_id = ?1
           AND event_id = ?2
         ORDER BY dep_event_id
         LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![workspace_id, event_id_b64, limit as i64], |row| {
        row.get::<_, String>(0)
    })?;
    let mut dep_ids = Vec::new();
    for row in rows {
        let dep_event_id_b64 = row?;
        if let Some(dep_event_id) = event_id_from_base64(&dep_event_id_b64) {
            dep_ids.push(dep_event_id);
        }
    }
    Ok(dep_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn replace_and_list_shared_event_deps_round_trip() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let workspace_id = "ws";
        let event_id = [0x11; 32];
        let dep_a = [0x22; 32];
        let dep_b = [0x33; 32];

        replace_shared_event_deps(&conn, workspace_id, &event_id, &[dep_b, dep_a]).unwrap();
        assert_eq!(
            list_shared_event_deps(&conn, workspace_id, &event_id).unwrap(),
            vec![dep_a, dep_b]
        );

        replace_shared_event_deps(&conn, workspace_id, &event_id, &[dep_b]).unwrap();
        assert_eq!(
            list_shared_event_deps(&conn, workspace_id, &event_id).unwrap(),
            vec![dep_b]
        );
    }
}
