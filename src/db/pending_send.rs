use rusqlite::{Connection, Result as SqliteResult, params};
use crate::crypto::EventId;

/// Helper for pending_send table - events we need to send to peer
pub struct PendingSend<'a> {
    conn: &'a Connection,
}

impl<'a> PendingSend<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Clear all pending sends (call at start of sync)
    pub fn clear(&self) -> SqliteResult<()> {
        self.conn.execute("DELETE FROM pending_send", [])?;
        Ok(())
    }

    /// Insert a batch of event IDs to send
    pub fn insert_batch(&self, ids: &[EventId]) -> SqliteResult<()> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;

        let mut stmt = self.conn.prepare_cached(
            "INSERT OR IGNORE INTO pending_send (id, added_at) VALUES (?, ?)"
        )?;

        for id in ids {
            stmt.execute(params![id.as_slice(), now])?;
        }
        Ok(())
    }

    /// Get a batch of event IDs to send (oldest first)
    pub fn get_batch(&self, limit: usize) -> SqliteResult<Vec<EventId>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT id FROM pending_send ORDER BY added_at LIMIT ?"
        )?;

        let rows = stmt.query_map([limit as i64], |row| {
            let blob: Vec<u8> = row.get(0)?;
            let mut id = [0u8; 32];
            if blob.len() == 32 {
                id.copy_from_slice(&blob);
            }
            Ok(id)
        })?;

        rows.collect()
    }

    /// Delete a batch of event IDs after sending
    pub fn delete_batch(&self, ids: &[EventId]) -> SqliteResult<()> {
        let mut stmt = self.conn.prepare_cached(
            "DELETE FROM pending_send WHERE id = ?"
        )?;

        for id in ids {
            stmt.execute([id.as_slice()])?;
        }
        Ok(())
    }

    /// Count pending sends
    pub fn count(&self) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM pending_send",
            [],
            |row| row.get(0),
        )
    }

    /// Check if there are any pending sends
    pub fn is_empty(&self) -> SqliteResult<bool> {
        Ok(self.count()? == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn test_pending_send_crud() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let pending = PendingSend::new(&conn);

        // Initially empty
        assert!(pending.is_empty().unwrap());
        assert_eq!(pending.count().unwrap(), 0);

        // Insert some IDs
        let ids: Vec<EventId> = (0..10).map(|i| {
            let mut id = [0u8; 32];
            id[0] = i;
            id
        }).collect();

        pending.insert_batch(&ids).unwrap();
        assert_eq!(pending.count().unwrap(), 10);

        // Get batch
        let batch = pending.get_batch(5).unwrap();
        assert_eq!(batch.len(), 5);

        // Delete batch
        pending.delete_batch(&batch).unwrap();
        assert_eq!(pending.count().unwrap(), 5);

        // Clear all
        pending.clear().unwrap();
        assert!(pending.is_empty().unwrap());
    }
}
