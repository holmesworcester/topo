//! Persistent event display mode setting (single-row config table).

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventDisplayMode {
    Tree,
    List,
    Off,
}

impl EventDisplayMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventDisplayMode::Tree => "tree",
            EventDisplayMode::List => "list",
            EventDisplayMode::Off => "off",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "tree" => Some(EventDisplayMode::Tree),
            "list" => Some(EventDisplayMode::List),
            "off" => Some(EventDisplayMode::Off),
            _ => None,
        }
    }
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS event_display_config (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             mode TEXT NOT NULL DEFAULT 'tree',
             updated_at_ms INTEGER NOT NULL DEFAULT 0
         )",
    )?;
    Ok(())
}

pub fn load_mode(conn: &Connection) -> SqliteResult<EventDisplayMode> {
    let mode_str: Option<String> = conn
        .query_row(
            "SELECT mode FROM event_display_config WHERE id = 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    Ok(mode_str
        .and_then(|s| EventDisplayMode::from_str(&s))
        .unwrap_or(EventDisplayMode::Tree))
}

pub fn save_mode(conn: &Connection, mode: EventDisplayMode) -> SqliteResult<()> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    conn.execute(
        "INSERT INTO event_display_config (id, mode, updated_at_ms) VALUES (1, ?1, ?2)
         ON CONFLICT(id) DO UPDATE SET mode = ?1, updated_at_ms = ?2",
        params![mode.as_str(), now_ms],
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
    fn test_default_mode_is_tree() {
        let conn = setup();
        assert_eq!(load_mode(&conn).unwrap(), EventDisplayMode::Tree);
    }

    #[test]
    fn test_round_trip_tree() {
        let conn = setup();
        save_mode(&conn, EventDisplayMode::Tree).unwrap();
        assert_eq!(load_mode(&conn).unwrap(), EventDisplayMode::Tree);
    }

    #[test]
    fn test_round_trip_list() {
        let conn = setup();
        save_mode(&conn, EventDisplayMode::List).unwrap();
        assert_eq!(load_mode(&conn).unwrap(), EventDisplayMode::List);
    }

    #[test]
    fn test_round_trip_off() {
        let conn = setup();
        save_mode(&conn, EventDisplayMode::Off).unwrap();
        assert_eq!(load_mode(&conn).unwrap(), EventDisplayMode::Off);
    }

    #[test]
    fn test_ensure_schema_idempotent() {
        let conn = setup();
        ensure_schema(&conn).unwrap();
        ensure_schema(&conn).unwrap();
        assert_eq!(load_mode(&conn).unwrap(), EventDisplayMode::Tree);
    }
}
