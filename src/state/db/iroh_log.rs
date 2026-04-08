//! Persistent iroh/noq log visibility setting (single-row config table).

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use super::sql_types::get_text;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrohLogMode {
    Show,
    Suppress,
}

impl IrohLogMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            IrohLogMode::Show => "show",
            IrohLogMode::Suppress => "suppress",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "show" => Some(IrohLogMode::Show),
            "suppress" => Some(IrohLogMode::Suppress),
            _ => None,
        }
    }
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS iroh_log_config (
             id INTEGER PRIMARY KEY CHECK (id = 1),
             mode TEXT NOT NULL DEFAULT 'suppress',
             updated_at_ms INTEGER NOT NULL DEFAULT 0
         )",
    )?;
    Ok(())
}

pub fn load_mode(conn: &Connection) -> SqliteResult<IrohLogMode> {
    let mode_str: Option<String> = conn
        .query_row("SELECT mode FROM iroh_log_config WHERE id = 1", [], |row| {
            get_text(row, 0)
        })
        .optional()?;
    Ok(mode_str
        .and_then(|s| IrohLogMode::from_str(&s))
        .unwrap_or(IrohLogMode::Suppress))
}

pub fn save_mode(conn: &Connection, mode: IrohLogMode) -> SqliteResult<()> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    conn.execute(
        "INSERT INTO iroh_log_config (id, mode, updated_at_ms) VALUES (1, ?1, ?2)
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
    fn test_default_mode_is_suppress() {
        let conn = setup();
        assert_eq!(load_mode(&conn).unwrap(), IrohLogMode::Suppress);
    }

    #[test]
    fn test_round_trip_show() {
        let conn = setup();
        save_mode(&conn, IrohLogMode::Show).unwrap();
        assert_eq!(load_mode(&conn).unwrap(), IrohLogMode::Show);
    }

    #[test]
    fn test_round_trip_suppress() {
        let conn = setup();
        save_mode(&conn, IrohLogMode::Suppress).unwrap();
        assert_eq!(load_mode(&conn).unwrap(), IrohLogMode::Suppress);
    }

    #[test]
    fn test_ensure_schema_idempotent() {
        let conn = setup();
        ensure_schema(&conn).unwrap();
        ensure_schema(&conn).unwrap();
        assert_eq!(load_mode(&conn).unwrap(), IrohLogMode::Suppress);
    }
}
