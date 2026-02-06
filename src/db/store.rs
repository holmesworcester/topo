use rusqlite::{Connection, Result as SqliteResult, params};

use crate::crypto::{event_id_to_base64, EventId};

/// Content-addressed blob storage backed by the `events` table.
pub struct Store<'a> {
    conn: &'a Connection,
}

impl<'a> Store<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Get a blob by its event ID (reads from `events` table).
    pub fn get(&self, id: &EventId) -> SqliteResult<Option<Vec<u8>>> {
        let id_str = event_id_to_base64(id);

        let result = self.conn.query_row(
            "SELECT blob FROM events WHERE event_id = ?1",
            params![id_str],
            |row| row.get(0),
        );

        match result {
            Ok(blob) => Ok(Some(blob)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Check if we have a blob
    #[cfg(test)]
    pub fn exists(&self, id: &EventId) -> SqliteResult<bool> {
        let id_str = event_id_to_base64(id);

        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE event_id = ?1",
            params![id_str],
            |row| row.get(0),
        )?;

        Ok(count > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_event;
    use crate::db::{open_in_memory, schema::create_tables};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now_ms() -> i64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64
    }

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn test_get_via_events_table() {
        let conn = setup();
        let store = Store::new(&conn);

        let blob = b"hello world";
        let id = hash_event(blob);
        let id_str = event_id_to_base64(&id);
        let now = now_ms();

        // Insert directly into events table
        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id_str, "message", &blob[..], "shared", now, now],
        ).unwrap();

        let retrieved = store.get(&id).unwrap().unwrap();
        assert_eq!(retrieved, blob);
    }

    #[test]
    fn test_get_nonexistent() {
        let conn = setup();
        let store = Store::new(&conn);

        let id = [0u8; 32];
        assert!(store.get(&id).unwrap().is_none());
    }

    #[test]
    fn test_exists() {
        let conn = setup();
        let store = Store::new(&conn);

        let blob = b"test";
        let id = hash_event(blob);
        let id_str = event_id_to_base64(&id);
        let now = now_ms();

        assert!(!store.exists(&id).unwrap());

        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id_str, "message", &blob[..], "shared", now, now],
        ).unwrap();

        assert!(store.exists(&id).unwrap());
    }
}
