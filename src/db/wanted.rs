use rusqlite::{Connection, Result as SqliteResult, params};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};

/// Wanted events - events we need but don't have yet
pub struct Wanted<'a> {
    conn: &'a Connection,
}

impl<'a> Wanted<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Insert a wanted event if we don't already have it in shareable
    pub fn insert_if_not_shareable(&self, id: &EventId) -> SqliteResult<bool> {
        let id_str = event_id_to_base64(id);
        let now = current_timestamp_ms();

        // Check if we already have it
        let exists: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM shareable_events WHERE id = ?1",
            params![id_str],
            |row| row.get(0),
        )?;

        if exists > 0 {
            return Ok(false);
        }

        // Insert into wanted
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO wanted_events (id, first_seen_at) VALUES (?1, ?2)",
            params![id_str, now],
        )?;

        Ok(inserted > 0)
    }

    /// Insert multiple wanted events (checking shareable for each)
    pub fn insert_batch_if_not_shareable(&self, ids: &[EventId]) -> SqliteResult<usize> {
        let mut count = 0;
        for id in ids {
            if self.insert_if_not_shareable(id)? {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Get a random sample of wanted event IDs
    pub fn sample_random(&self, limit: usize) -> SqliteResult<Vec<EventId>> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM wanted_events ORDER BY RANDOM() LIMIT ?1"
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let id_str: String = row.get(0)?;
            Ok(id_str)
        })?;

        let mut result = Vec::new();
        for row in rows {
            let id_str = row?;
            if let Some(id) = event_id_from_base64(&id_str) {
                result.push(id);
            }
        }
        Ok(result)
    }

    /// Delete a wanted event (when we receive it)
    pub fn delete(&self, id: &EventId) -> SqliteResult<bool> {
        let id_str = event_id_to_base64(id);
        let deleted = self.conn.execute(
            "DELETE FROM wanted_events WHERE id = ?1",
            params![id_str],
        )?;
        Ok(deleted > 0)
    }

    /// Delete multiple wanted events
    pub fn delete_batch(&self, ids: &[EventId]) -> SqliteResult<usize> {
        let mut stmt = self.conn.prepare(
            "DELETE FROM wanted_events WHERE id = ?1"
        )?;

        let mut count = 0;
        for id in ids {
            let id_str = event_id_to_base64(id);
            count += stmt.execute(params![id_str])?;
        }
        Ok(count)
    }

    /// Check if an event is wanted
    pub fn exists(&self, id: &EventId) -> SqliteResult<bool> {
        let id_str = event_id_to_base64(id);
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM wanted_events WHERE id = ?1",
            params![id_str],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Count wanted events
    pub fn count(&self) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM wanted_events",
            [],
            |row| row.get(0),
        )
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
    use crate::db::{open_in_memory, schema::create_tables, shareable::Shareable};

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn test_insert_if_not_shareable() {
        let conn = setup();
        let wanted = Wanted::new(&conn);
        let shareable = Shareable::new(&conn);

        let id = hash_event(b"event1");

        // Should insert since not shareable
        assert!(wanted.insert_if_not_shareable(&id).unwrap());
        assert!(wanted.exists(&id).unwrap());

        // Should not insert again
        assert!(!wanted.insert_if_not_shareable(&id).unwrap());

        // If shareable, should not insert
        let id2 = hash_event(b"event2");
        shareable.insert(&id2, None).unwrap();
        assert!(!wanted.insert_if_not_shareable(&id2).unwrap());
    }

    #[test]
    fn test_sample_random() {
        let conn = setup();
        let wanted = Wanted::new(&conn);

        for i in 0..10 {
            let id = hash_event(format!("event{}", i).as_bytes());
            wanted.insert_if_not_shareable(&id).unwrap();
        }

        let sample = wanted.sample_random(5).unwrap();
        assert_eq!(sample.len(), 5);
    }

    #[test]
    fn test_delete() {
        let conn = setup();
        let wanted = Wanted::new(&conn);

        let id = hash_event(b"event1");
        wanted.insert_if_not_shareable(&id).unwrap();
        assert!(wanted.exists(&id).unwrap());

        wanted.delete(&id).unwrap();
        assert!(!wanted.exists(&id).unwrap());
    }

    #[test]
    fn test_delete_batch() {
        let conn = setup();
        let wanted = Wanted::new(&conn);

        let ids: Vec<_> = (0..5)
            .map(|i| hash_event(format!("event{}", i).as_bytes()))
            .collect();

        for id in &ids {
            wanted.insert_if_not_shareable(id).unwrap();
        }
        assert_eq!(wanted.count().unwrap(), 5);

        wanted.delete_batch(&ids[..3]).unwrap();
        assert_eq!(wanted.count().unwrap(), 2);
    }
}
