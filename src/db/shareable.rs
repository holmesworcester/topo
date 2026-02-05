use rusqlite::{Connection, Result as SqliteResult, params};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{event_id_to_base64, EventId};

/// Shareable events - events we have and can offer to peers
pub struct Shareable<'a> {
    conn: &'a Connection,
}

impl<'a> Shareable<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Insert a shareable event
    pub fn insert(&self, id: &EventId) -> SqliteResult<()> {
        let id_str = event_id_to_base64(id);
        let now = current_timestamp_ms();

        self.conn.execute(
            "INSERT OR IGNORE INTO shareable_events (id, stored_at) VALUES (?1, ?2)",
            params![id_str, now],
        )?;
        Ok(())
    }

    /// Count total shareable events
    #[cfg(test)]
    pub fn count(&self) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM shareable_events",
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
    use crate::db::{open_in_memory, schema::create_tables};

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn test_insert_and_count() {
        let conn = setup();
        let shareable = Shareable::new(&conn);

        assert_eq!(shareable.count().unwrap(), 0);

        let id = hash_event(b"event1");
        shareable.insert(&id).unwrap();
        assert_eq!(shareable.count().unwrap(), 1);

        // Idempotent
        shareable.insert(&id).unwrap();
        assert_eq!(shareable.count().unwrap(), 1);
    }

    #[test]
    fn test_insert_multiple() {
        let conn = setup();
        let shareable = Shareable::new(&conn);

        for i in 0..5 {
            let id = hash_event(format!("event{}", i).as_bytes());
            shareable.insert(&id).unwrap();
        }
        assert_eq!(shareable.count().unwrap(), 5);
    }
}
