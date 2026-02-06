use rusqlite::Connection;

/// Shareable events - queries events with share_scope = 'shared'
pub struct Shareable<'a> {
    conn: &'a Connection,
}

impl<'a> Shareable<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Count total shareable events
    pub fn count(&self) -> rusqlite::Result<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM events WHERE share_scope = 'shared'",
            [],
            |row| row.get(0),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{hash_event, event_id_to_base64};
    use crate::db::{open_in_memory, schema::create_tables};
    use rusqlite::Connection;
    use super::Shareable;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    #[test]
    fn test_insert_and_count() {
        let conn = setup();
        let shareable = Shareable::new(&conn);

        assert_eq!(shareable.count().unwrap(), 0);

        let id = hash_event(b"event1");
        let id_str = event_id_to_base64(&id);
        let now = now_ms();
        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![id_str, "message", b"event1".as_slice(), "shared", now, now],
        ).unwrap();
        assert_eq!(shareable.count().unwrap(), 1);

        // Idempotent
        conn.execute(
            "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![id_str, "message", b"event1".as_slice(), "shared", now, now],
        ).unwrap();
        assert_eq!(shareable.count().unwrap(), 1);
    }

    #[test]
    fn test_insert_multiple() {
        let conn = setup();
        let shareable = Shareable::new(&conn);

        let now = now_ms();
        for i in 0..5 {
            let id = hash_event(format!("event{}", i).as_bytes());
            let id_str = event_id_to_base64(&id);
            let blob = format!("event{}", i);
            conn.execute(
                "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id_str, "message", blob.as_bytes(), "shared", now, now],
            ).unwrap();
        }
        assert_eq!(shareable.count().unwrap(), 5);
    }
}
