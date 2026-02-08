use std::time::{SystemTime, UNIX_EPOCH};

pub const BACKOFF_BASE_MS: i64 = 1000;
pub const BACKOFF_MAX_ATTEMPTS: u32 = 10;

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

/// Calculate backoff delay: base_ms * 2^min(attempts, max_attempts)
pub fn backoff_ms(attempts: i64) -> i64 {
    let capped = (attempts as u32).min(BACKOFF_MAX_ATTEMPTS);
    BACKOFF_BASE_MS.saturating_mul(1i64 << capped)
}

/// Recover expired leases on a given table by clearing lease_until.
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
}
