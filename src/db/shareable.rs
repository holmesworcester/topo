use rusqlite::{Connection, Result as SqliteResult, params};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};

/// Shareable events - events we have and can offer to peers
pub struct Shareable<'a> {
    conn: &'a Connection,
}

impl<'a> Shareable<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Insert a shareable event
    pub fn insert(&self, id: &EventId, prev_id: Option<&EventId>) -> SqliteResult<()> {
        let id_str = event_id_to_base64(id);
        let prev_id_str = prev_id.map(event_id_to_base64);
        let now = current_timestamp_ms();

        self.conn.execute(
            "INSERT OR IGNORE INTO shareable_events (id, prev_id, is_tip, stored_at) VALUES (?1, ?2, 1, ?3)",
            params![id_str, prev_id_str, now],
        )?;
        Ok(())
    }

    /// Insert multiple shareable events at once
    pub fn insert_batch(&self, items: &[(EventId, Option<EventId>)]) -> SqliteResult<()> {
        let now = current_timestamp_ms();
        let mut stmt = self.conn.prepare(
            "INSERT OR IGNORE INTO shareable_events (id, prev_id, is_tip, stored_at) VALUES (?1, ?2, 1, ?3)"
        )?;

        for (id, prev_id) in items {
            let id_str = event_id_to_base64(id);
            let prev_id_str = prev_id.map(|p| event_id_to_base64(&p));
            stmt.execute(params![id_str, prev_id_str, now])?;
        }
        Ok(())
    }

    /// Mark an event as no longer a tip (something depends on it)
    pub fn mark_not_tip(&self, id: &EventId) -> SqliteResult<()> {
        let id_str = event_id_to_base64(id);
        self.conn.execute(
            "UPDATE shareable_events SET is_tip = 0 WHERE id = ?1",
            params![id_str],
        )?;
        Ok(())
    }

    /// Mark multiple events as not tips
    pub fn mark_not_tips_batch(&self, ids: &[EventId]) -> SqliteResult<()> {
        let mut stmt = self.conn.prepare(
            "UPDATE shareable_events SET is_tip = 0 WHERE id = ?1"
        )?;

        for id in ids {
            let id_str = event_id_to_base64(id);
            stmt.execute(params![id_str])?;
        }
        Ok(())
    }

    /// Check if we have an event
    pub fn exists(&self, id: &EventId) -> SqliteResult<bool> {
        let id_str = event_id_to_base64(id);
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM shareable_events WHERE id = ?1",
            params![id_str],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Get chain tips (events with is_tip = 1)
    pub fn get_tips(&self, limit: usize) -> SqliteResult<Vec<EventId>> {
        let mut stmt = self.conn.prepare(
            "SELECT id FROM shareable_events WHERE is_tip = 1 LIMIT ?1"
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

    /// Count total shareable events
    pub fn count(&self) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM shareable_events",
            [],
            |row| row.get(0),
        )
    }

    /// Count tips
    pub fn count_tips(&self) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM shareable_events WHERE is_tip = 1",
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
    fn test_insert_and_exists() {
        let conn = setup();
        let shareable = Shareable::new(&conn);

        let id = hash_event(b"event1");
        assert!(!shareable.exists(&id).unwrap());

        shareable.insert(&id, None).unwrap();
        assert!(shareable.exists(&id).unwrap());
    }

    #[test]
    fn test_tips() {
        let conn = setup();
        let shareable = Shareable::new(&conn);

        let id1 = hash_event(b"event1");
        let id2 = hash_event(b"event2");
        let id3 = hash_event(b"event3");

        // id3 -> id2 -> id1 (chain)
        shareable.insert(&id1, None).unwrap();
        shareable.insert(&id2, Some(&id1)).unwrap();
        shareable.mark_not_tip(&id1).unwrap();
        shareable.insert(&id3, Some(&id2)).unwrap();
        shareable.mark_not_tip(&id2).unwrap();

        let tips = shareable.get_tips(10).unwrap();
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0], id3);
    }

    #[test]
    fn test_insert_batch() {
        let conn = setup();
        let shareable = Shareable::new(&conn);

        let items: Vec<_> = (0..5)
            .map(|i| {
                let id = hash_event(format!("event{}", i).as_bytes());
                (id, None)
            })
            .collect();

        shareable.insert_batch(&items).unwrap();
        assert_eq!(shareable.count().unwrap(), 5);
        assert_eq!(shareable.count_tips().unwrap(), 5);
    }
}
