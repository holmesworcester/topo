use rusqlite::{Connection, Result as SqliteResult, params};
use std::time::{SystemTime, UNIX_EPOCH};

/// Incoming queue - blobs waiting to be processed
pub struct IncomingQueue<'a> {
    conn: &'a Connection,
}

#[derive(Debug, Clone)]
pub struct IncomingItem {
    pub id: i64,
    pub blob: Vec<u8>,
    pub received_at: i64,
}

impl<'a> IncomingQueue<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Add a blob to the incoming queue
    pub fn push(&self, blob: &[u8]) -> SqliteResult<i64> {
        let now = current_timestamp_ms();
        self.conn.execute(
            "INSERT INTO incoming_queue (blob, received_at, processed) VALUES (?1, ?2, 0)",
            params![blob, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// Drain up to `limit` unprocessed items (DELETE...RETURNING equivalent)
    pub fn drain(&self, limit: usize) -> SqliteResult<Vec<IncomingItem>> {
        // Select items first
        let mut stmt = self.conn.prepare(
            "SELECT id, blob, received_at FROM incoming_queue
             WHERE processed = 0
             ORDER BY received_at
             LIMIT ?1"
        )?;

        let items: Vec<IncomingItem> = stmt
            .query_map(params![limit as i64], |row| {
                Ok(IncomingItem {
                    id: row.get(0)?,
                    blob: row.get(1)?,
                    received_at: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        if items.is_empty() {
            return Ok(items);
        }

        // Delete the items we selected
        let ids: Vec<i64> = items.iter().map(|i| i.id).collect();
        let placeholders: Vec<String> = ids.iter().map(|_| "?".to_string()).collect();
        let sql = format!(
            "DELETE FROM incoming_queue WHERE id IN ({})",
            placeholders.join(",")
        );

        let mut delete_stmt = self.conn.prepare(&sql)?;
        let params: Vec<&dyn rusqlite::ToSql> = ids.iter().map(|id| id as &dyn rusqlite::ToSql).collect();
        delete_stmt.execute(params.as_slice())?;

        Ok(items)
    }

    /// Count unprocessed items
    pub fn count_pending(&self) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM incoming_queue WHERE processed = 0",
            [],
            |row| row.get(0),
        )
    }

    /// Count all items
    pub fn count(&self) -> SqliteResult<i64> {
        self.conn.query_row(
            "SELECT COUNT(*) FROM incoming_queue",
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
    use crate::db::{open_in_memory, schema::create_tables};

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn test_push_and_drain() {
        let conn = setup();
        let queue = IncomingQueue::new(&conn);

        queue.push(b"blob1").unwrap();
        queue.push(b"blob2").unwrap();
        queue.push(b"blob3").unwrap();

        assert_eq!(queue.count_pending().unwrap(), 3);

        let items = queue.drain(2).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].blob, b"blob1");
        assert_eq!(items[1].blob, b"blob2");

        assert_eq!(queue.count_pending().unwrap(), 1);

        let items = queue.drain(10).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].blob, b"blob3");

        assert_eq!(queue.count_pending().unwrap(), 0);
    }

    #[test]
    fn test_drain_empty() {
        let conn = setup();
        let queue = IncomingQueue::new(&conn);

        let items = queue.drain(10).unwrap();
        assert!(items.is_empty());
    }
}
