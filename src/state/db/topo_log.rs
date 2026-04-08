//! Persistent topo log verbosity setting (single-row config table).

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use super::sql_types::get_text;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopoLogLevel {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl TopoLogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            TopoLogLevel::Error => "error",
            TopoLogLevel::Warn => "warn",
            TopoLogLevel::Info => "info",
            TopoLogLevel::Debug => "debug",
            TopoLogLevel::Trace => "trace",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "error" => Some(TopoLogLevel::Error),
            "warn" => Some(TopoLogLevel::Warn),
            "info" => Some(TopoLogLevel::Info),
            "debug" => Some(TopoLogLevel::Debug),
            "trace" => Some(TopoLogLevel::Trace),
            _ => None,
        }
    }
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS topo_log_config (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             level TEXT NOT NULL DEFAULT 'warn',
             updated_at_ms INTEGER NOT NULL DEFAULT 0
         )",
    )?;
    Ok(())
}

pub fn load_level(conn: &Connection) -> SqliteResult<TopoLogLevel> {
    let level_str: Option<String> = conn
        .query_row(
            "SELECT level FROM topo_log_config WHERE id = 1",
            [],
            |row| get_text(row, 0),
        )
        .optional()?;
    Ok(level_str
        .and_then(|s| TopoLogLevel::from_str(&s))
        .unwrap_or(TopoLogLevel::Warn))
}

pub fn save_level(conn: &Connection, level: TopoLogLevel) -> SqliteResult<()> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    conn.execute(
        "INSERT INTO topo_log_config (id, level, updated_at_ms) VALUES (1, ?1, ?2)
         ON CONFLICT(id) DO UPDATE SET level = ?1, updated_at_ms = ?2",
        params![level.as_str(), now_ms],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn test_default_level_is_warn() {
        let conn = setup();
        assert_eq!(load_level(&conn).unwrap(), TopoLogLevel::Warn);
    }

    #[test]
    fn test_round_trip_debug() {
        let conn = setup();
        save_level(&conn, TopoLogLevel::Debug).unwrap();
        assert_eq!(load_level(&conn).unwrap(), TopoLogLevel::Debug);
    }

    #[test]
    fn test_round_trip_trace() {
        let conn = setup();
        save_level(&conn, TopoLogLevel::Trace).unwrap();
        assert_eq!(load_level(&conn).unwrap(), TopoLogLevel::Trace);
    }

    #[test]
    fn test_ensure_schema_idempotent() {
        let conn = setup();
        ensure_schema(&conn).unwrap();
        ensure_schema(&conn).unwrap();
        assert_eq!(load_level(&conn).unwrap(), TopoLogLevel::Warn);
    }
}
