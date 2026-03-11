use rusqlite::{params, Connection, Result as SqliteResult};
use std::time::{SystemTime, UNIX_EPOCH};

use super::queue::with_sqlite_busy_retry;
use crate::crypto::EventId;

/// Wanted events - events we need to fetch from peers
pub struct WantedEvents<'a> {
    conn: &'a Connection,
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS wanted_events (
            id BLOB PRIMARY KEY,
            first_seen_at INTEGER NOT NULL
        );
        ",
    )?;
    Ok(())
}

impl<'a> WantedEvents<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    /// Insert a wanted event if not already present. Returns true if inserted.
    pub fn insert(&self, id: &EventId) -> SqliteResult<bool> {
        let now = current_timestamp_ms();
        let rows = with_sqlite_busy_retry(|| {
            self.conn.execute(
                "INSERT OR IGNORE INTO wanted_events (id, first_seen_at) VALUES (?1, ?2)",
                params![&id[..], now],
            )
        })?;
        Ok(rows > 0)
    }

    /// Remove a wanted event
    pub fn remove(&self, id: &EventId) -> SqliteResult<()> {
        with_sqlite_busy_retry(|| {
            self.conn
                .execute("DELETE FROM wanted_events WHERE id = ?1", params![&id[..]])?;
            Ok(())
        })?;
        Ok(())
    }

    /// Count total wanted events
    pub fn count(&self) -> SqliteResult<i64> {
        with_sqlite_busy_retry(|| {
            self.conn
                .query_row("SELECT COUNT(*) FROM wanted_events", [], |row| row.get(0))
        })
    }

    /// Clear wanted events
    pub fn clear(&self) -> SqliteResult<()> {
        with_sqlite_busy_retry(|| {
            self.conn.execute("DELETE FROM wanted_events", [])?;
            Ok(())
        })?;
        Ok(())
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
    use crate::db::{open_connection, schema::create_tables};
    use std::time::Duration;

    fn make_event_id(byte: u8) -> EventId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    #[test]
    fn test_insert_retries_transient_busy_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wanted.db");

        let setup = open_connection(&path).unwrap();
        setup.busy_timeout(Duration::from_millis(20)).unwrap();
        create_tables(&setup).unwrap();
        drop(setup);

        let lock_conn = open_connection(&path).unwrap();
        lock_conn.busy_timeout(Duration::from_millis(20)).unwrap();
        lock_conn.execute("BEGIN IMMEDIATE", []).unwrap();

        let path_for_thread = path.clone();
        let worker = std::thread::spawn(move || {
            let conn = open_connection(&path_for_thread).unwrap();
            conn.busy_timeout(Duration::from_millis(20)).unwrap();
            let wanted = WantedEvents::new(&conn);
            wanted.insert(&make_event_id(7)).unwrap()
        });

        std::thread::sleep(Duration::from_millis(80));
        lock_conn.execute("COMMIT", []).unwrap();

        assert!(worker.join().unwrap());

        let verify = open_connection(&path).unwrap();
        let wanted = WantedEvents::new(&verify);
        assert_eq!(wanted.count().unwrap(), 1);
    }
}
