use rusqlite::{Connection, Result as SqliteResult, params};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{event_id_to_base64, EventId};

/// Content-addressed blob storage
pub struct Store<'a> {
    conn: &'a Connection,
}

impl<'a> Store<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Store a blob by its event ID
    pub fn put(&self, id: &EventId, blob: &[u8]) -> SqliteResult<()> {
        let id_str = event_id_to_base64(id);
        let now = current_timestamp_ms();

        self.conn.execute(
            "INSERT OR IGNORE INTO store (id, blob, stored_at) VALUES (?1, ?2, ?3)",
            params![id_str, blob, now],
        )?;
        Ok(())
    }

    /// Store multiple blobs at once
    #[cfg(test)]
    pub fn put_batch(&self, items: &[(EventId, Vec<u8>)]) -> SqliteResult<()> {
        let now = current_timestamp_ms();
        let mut stmt = self.conn.prepare(
            "INSERT OR IGNORE INTO store (id, blob, stored_at) VALUES (?1, ?2, ?3)"
        )?;

        for (id, blob) in items {
            let id_str = event_id_to_base64(id);
            stmt.execute(params![id_str, blob, now])?;
        }
        Ok(())
    }

    /// Get a blob by its event ID
    pub fn get(&self, id: &EventId) -> SqliteResult<Option<Vec<u8>>> {
        let id_str = event_id_to_base64(id);

        let result = self.conn.query_row(
            "SELECT blob FROM store WHERE id = ?1",
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
            "SELECT COUNT(*) FROM store WHERE id = ?1",
            params![id_str],
            |row| row.get(0),
        )?;

        Ok(count > 0)
    }
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash_event;
    use crate::db::{open_in_memory, schema::create_tables};

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn test_put_and_get() {
        let conn = setup();
        let store = Store::new(&conn);

        let blob = b"hello world";
        let id = hash_event(blob);

        store.put(&id, blob).unwrap();
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

        assert!(!store.exists(&id).unwrap());
        store.put(&id, blob).unwrap();
        assert!(store.exists(&id).unwrap());
    }

    #[test]
    fn test_put_batch() {
        let conn = setup();
        let store = Store::new(&conn);

        let items: Vec<_> = (0..5)
            .map(|i| {
                let blob = format!("blob{}", i).into_bytes();
                let id = hash_event(&blob);
                (id, blob)
            })
            .collect();

        store.put_batch(&items).unwrap();

        for (id, expected_blob) in &items {
            let retrieved = store.get(id).unwrap().unwrap();
            assert_eq!(&retrieved, expected_blob);
        }
    }

    #[test]
    fn test_put_idempotent() {
        let conn = setup();
        let store = Store::new(&conn);

        let blob = b"test";
        let id = hash_event(blob);

        store.put(&id, blob).unwrap();
        store.put(&id, blob).unwrap(); // Should not fail
    }
}
