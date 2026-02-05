use rusqlite::{Connection, Result as SqliteResult, params};
use crate::crypto::EventId;

/// Helper for wanted_events table - events we need from peer
pub struct Wanted<'a> {
    conn: &'a Connection,
}

impl<'a> Wanted<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Clear all wanted events (call at start of sync)
    pub fn clear(&self) -> SqliteResult<()> {
        self.conn.execute("DELETE FROM wanted_events", [])?;
        Ok(())
    }

    /// Insert a batch of event IDs we need
    pub fn insert_batch(&self, ids: &[EventId]) -> SqliteResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let mut stmt = self.conn.prepare_cached(
            "INSERT OR IGNORE INTO wanted_events (id, first_seen_at) VALUES (?, ?)"
        )?;

        for id in ids {
            // Convert to base64 for TEXT column
            let id_b64 = base64::encode(id);
            stmt.execute(params![id_b64, now])?;
        }
        Ok(())
    }

    /// Remove an event from wanted (after receiving it)
    pub fn remove(&self, id: &EventId) -> SqliteResult<()> {
        let id_b64 = base64::encode(id);
        self.conn.execute(
            "DELETE FROM wanted_events WHERE id = ?",
            [id_b64],
        )?;
        Ok(())
    }

    /// Count wanted events
    pub fn count(&self) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM wanted_events",
            [],
            |row| row.get(0),
        )
    }

    /// Check if there are any wanted events
    pub fn is_empty(&self) -> SqliteResult<bool> {
        Ok(self.count()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn test_wanted_crud() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let wanted = Wanted::new(&conn);

        // Initially empty
        assert!(wanted.is_empty().unwrap());

        // Insert some IDs
        let ids: Vec<EventId> = (0..10).map(|i| {
            let mut id = [0u8; 32];
            id[0] = i;
            id
        }).collect();

        wanted.insert_batch(&ids).unwrap();
        assert_eq!(wanted.count().unwrap(), 10);

        // Remove one
        wanted.remove(&ids[0]).unwrap();
        assert_eq!(wanted.count().unwrap(), 9);

        // Clear all
        wanted.clear().unwrap();
        assert!(wanted.is_empty().unwrap());
    }
}
