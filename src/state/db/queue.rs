//! Shared queue primitives for DB-backed runtime queues.
//!
//! This module centralizes logic reused by queue implementations:
//! - `src/state/db/project_queue.rs` (projection retry/lease workflow)
//!
//! Keeping these helpers here ensures retry timing and queue-health reporting
//! stay consistent when multiple queues evolve.

use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const BACKOFF_BASE_MS: i64 = 1000;
pub const BACKOFF_MAX_ATTEMPTS: u32 = 10;
pub const SQLITE_BUSY_RETRY_BASE_MS: u64 = 10;
pub const SQLITE_BUSY_RETRY_ATTEMPTS: usize = 8;
pub const PRIORITY_LANE_BLOCKER: i64 = 0;
pub const PRIORITY_LANE_TIER_HOUR: i64 = 1;
pub const PRIORITY_LANE_TIER_DAY: i64 = 2;
pub const PRIORITY_LANE_TIER_WEEK: i64 = 3;
pub const PRIORITY_LANE_TIER_MONTH: i64 = 4;
pub const PRIORITY_LANE_FOREGROUND: i64 = 5;
pub const PRIORITY_LANE_BULK: i64 = 6;

/// Queue health snapshot for observability.
#[derive(Debug, Clone)]
pub struct QueueHealth {
    pub pending: i64,
    pub max_attempts: i64,
    pub oldest_age_ms: i64,
}

pub fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

pub fn current_timestamp_ms_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

pub fn classify_priority_from_blob(blob: &[u8], created_at: i64) -> (i64, i64) {
    let lane = if crate::event_modules::outer_semantic_type_code(blob)
        == Some(crate::event_modules::EVENT_TYPE_FILE_SLICE)
    {
        PRIORITY_LANE_BULK
    } else {
        PRIORITY_LANE_FOREGROUND
    };
    (lane, created_at)
}
pub fn is_sqlite_busy(err: &rusqlite::Error) -> bool {
    match err {
        rusqlite::Error::SqliteFailure(_, Some(msg)) => {
            msg.contains("database is locked") || msg.contains("SQLITE_BUSY")
        }
        rusqlite::Error::SqliteFailure(_, None) => false,
        _ => {
            let msg = err.to_string();
            msg.contains("database is locked") || msg.contains("SQLITE_BUSY")
        }
    }
}

pub fn with_sqlite_busy_retry<T, F>(mut op: F) -> rusqlite::Result<T>
where
    F: FnMut() -> rusqlite::Result<T>,
{
    for attempt in 0..SQLITE_BUSY_RETRY_ATTEMPTS {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) if is_sqlite_busy(&err) && attempt + 1 < SQLITE_BUSY_RETRY_ATTEMPTS => {
                thread::sleep(Duration::from_millis(SQLITE_BUSY_RETRY_BASE_MS << attempt));
            }
            Err(err) => return Err(err),
        }
    }

    unreachable!("loop returns on success or final error");
}

pub fn with_immediate_tx<T, F>(conn: &rusqlite::Connection, mut op: F) -> rusqlite::Result<T>
where
    F: FnMut() -> rusqlite::Result<T>,
{
    if !conn.is_autocommit() {
        return op();
    }
    with_sqlite_busy_retry(|| {
        conn.execute("BEGIN IMMEDIATE", [])?;
        match op() {
            Ok(value) => {
                conn.execute("COMMIT", [])?;
                Ok(value)
            }
            Err(err) => {
                let _ = conn.execute("ROLLBACK", []);
                Err(err)
            }
        }
    })
}

pub fn with_immediate_tx_result<T, E, F>(conn: &rusqlite::Connection, mut op: F) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    E: From<rusqlite::Error>,
{
    if !conn.is_autocommit() {
        return op();
    }

    with_sqlite_busy_retry(|| conn.execute("BEGIN IMMEDIATE", []).map(|_| ())).map_err(E::from)?;
    match op() {
        Ok(value) => {
            conn.execute("COMMIT", []).map_err(E::from)?;
            Ok(value)
        }
        Err(err) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(err)
        }
    }
}

/// Calculate backoff delay: base_ms * 2^min(attempts, max_attempts)
pub fn backoff_ms(attempts: i64) -> i64 {
    let capped = (attempts as u32).min(BACKOFF_MAX_ATTEMPTS);
    BACKOFF_BASE_MS.saturating_mul(1i64 << capped)
}

/// Recover expired leases on a given table by clearing lease_until.
///
/// Currently used by `ProjectQueue::recover_expired` to re-expose rows
/// that were claimed but never acknowledged (for example after a crash).
/// Returns the number of rows recovered.
pub fn recover_expired_leases(
    conn: &rusqlite::Connection,
    table: &str,
    now_ms: i64,
) -> rusqlite::Result<usize> {
    let sql = format!(
        "UPDATE {} SET lease_until = NULL WHERE lease_until IS NOT NULL AND lease_until < ?1",
        table
    );
    conn.execute(&sql, rusqlite::params![now_ms])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_calculation() {
        assert_eq!(backoff_ms(0), 1000);
        assert_eq!(backoff_ms(1), 2000);
        assert_eq!(backoff_ms(2), 4000);
        assert_eq!(backoff_ms(3), 8000);
        assert_eq!(backoff_ms(10), 1024000); // ~17 min
    }

    #[test]
    fn test_backoff_cap() {
        // Beyond max attempts, same delay (capped)
        let at_max = backoff_ms(10);
        assert_eq!(backoff_ms(11), at_max);
        assert_eq!(backoff_ms(20), at_max);
        assert_eq!(backoff_ms(100), at_max);
    }

    #[test]
    fn test_current_timestamp_ms() {
        let ts = current_timestamp_ms();
        assert!(ts > 0);
        // Should be a reasonable epoch millis (after 2020)
        assert!(ts > 1_577_836_800_000);
    }

    #[test]
    fn test_with_immediate_tx_reuses_outer_transaction() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE demo (value INTEGER NOT NULL)", [])
            .unwrap();

        conn.execute("BEGIN", []).unwrap();
        with_immediate_tx(&conn, || {
            conn.execute("INSERT INTO demo(value) VALUES (1)", [])?;
            Ok(())
        })
        .unwrap();
        conn.execute("COMMIT", []).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM demo", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_with_immediate_tx_result_rolls_back_on_custom_error() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute("CREATE TABLE demo (value INTEGER NOT NULL)", [])
            .unwrap();

        #[derive(Debug)]
        struct DemoError;

        impl From<rusqlite::Error> for DemoError {
            fn from(_: rusqlite::Error) -> Self {
                Self
            }
        }

        let result = with_immediate_tx_result(&conn, || -> Result<(), DemoError> {
            conn.execute("INSERT INTO demo(value) VALUES (1)", [])?;
            Err(DemoError)
        });
        assert!(result.is_err());

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM demo", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
}
