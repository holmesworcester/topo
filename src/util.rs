use std::time::{SystemTime, UNIX_EPOCH};

/// Get current timestamp in milliseconds since Unix epoch
pub fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
