pub mod daemon_identity;
pub mod dep_index;
pub mod event_display;
pub mod health;
pub mod hot_week_deps;
pub mod iroh_log;
pub mod local_client_ops;
pub mod need_queue;
pub mod observability;
pub mod project_queue;
pub mod queue;
pub mod schema;
pub mod sql_types;
pub mod store;
pub mod sync_log;
pub mod timeline;
pub mod topo_log;
pub mod transport_creds;
pub mod transport_trust;

use rusqlite::{Connection, Result as SqliteResult};
use std::time::Duration;
use std::path::Path;

/// Open database connection with WAL mode and performance pragmas
pub fn open_connection<P: AsRef<Path>>(path: P) -> SqliteResult<Connection> {
    let conn = Connection::open(path)?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

/// Wrap a SQLite open error into a user-friendly message.
pub fn friendly_db_error<P: AsRef<Path>>(path: P, e: rusqlite::Error) -> String {
    let p = path.as_ref();
    match e {
        rusqlite::Error::SqliteFailure(ref err, _)
            if err.code == rusqlite::ffi::ErrorCode::CannotOpen =>
        {
            if let Some(parent) = p.parent() {
                if !parent.exists() {
                    return format!(
                        "cannot open database: directory does not exist: {}",
                        parent.display()
                    );
                }
            }
            format!("cannot open database: {}", p.display())
        }
        rusqlite::Error::SqliteFailure(ref err, ref msg) => {
            let detail = msg.as_deref().unwrap_or("unknown error");
            match err.code {
                rusqlite::ffi::ErrorCode::NotADatabase => {
                    format!(
                        "cannot open database: file is not a database: {}",
                        p.display()
                    )
                }
                rusqlite::ffi::ErrorCode::ReadOnly => {
                    format!("cannot open database: read-only: {}", p.display())
                }
                _ => format!("cannot open database: {} ({})", detail, p.display()),
            }
        }
        other => format!("cannot open database: {} ({})", other, p.display()),
    }
}

/// Open in-memory database (for testing)
#[cfg(test)]
pub fn open_in_memory() -> SqliteResult<Connection> {
    let conn = Connection::open_in_memory()?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

fn apply_pragmas(conn: &Connection) -> SqliteResult<()> {
    let busy_timeout = Duration::from_millis(
        std::env::var("TOPO_DB_BUSY_TIMEOUT_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(30_000),
    );
    conn.busy_timeout(busy_timeout)?;

    let journal_mode: String = conn.query_row("PRAGMA journal_mode", [], |row| row.get(0))?;
    if journal_mode != "wal" && journal_mode != "memory" {
        conn.execute_batch("PRAGMA journal_mode = WAL;")?;
    }

    if low_mem_mode() {
        conn.execute_batch(
            "
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -256;
            PRAGMA cache_spill = ON;
            PRAGMA temp_store = FILE;
            PRAGMA mmap_size = 0;
            PRAGMA wal_autocheckpoint = 64;
            PRAGMA journal_size_limit = 262144;
            PRAGMA soft_heap_limit = 2097152;
            PRAGMA foreign_keys = OFF;
            ",
        )?;
    } else {
        conn.execute_batch(
            "
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -64000;
            PRAGMA foreign_keys = OFF;
            PRAGMA temp_store = MEMORY;
            ",
        )?;
    }
    Ok(())
}

use crate::tuning::low_mem_mode;

pub fn ensure_infra_schema(conn: &Connection) -> SqliteResult<()> {
    store::ensure_schema(conn)?;
    daemon_identity::ensure_schema(conn)?;
    dep_index::ensure_schema(conn)?;
    event_display::ensure_schema(conn)?;
    iroh_log::ensure_schema(conn)?;
    project_queue::ensure_schema(conn)?;
    health::ensure_schema(conn)?;
    hot_week_deps::ensure_schema(conn)?;
    sync_log::ensure_schema(conn)?;
    timeline::ensure_schema(conn)?;
    topo_log::ensure_schema(conn)?;
    transport_trust::ensure_schema(conn)?;
    transport_creds::ensure_schema(conn)?;
    need_queue::ensure_schema(conn)?;
    local_client_ops::ensure_schema(conn)?;
    observability::ensure_schema(conn)?;
    crate::state::shared_workspace_fanout::ensure_schema(conn)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sql_types::get_text;
    use super::*;

    #[test]
    fn test_open_in_memory() {
        let conn = open_in_memory().unwrap();
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| get_text(row, 0))
            .unwrap();
        // In-memory databases may report "memory" instead of "wal"
        assert!(journal_mode == "wal" || journal_mode == "memory");
    }

    #[test]
    fn open_connection_succeeds_while_another_connection_holds_immediate_tx() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("busy.sqlite3");

        let writer = open_connection(&db_path).unwrap();
        writer.execute("BEGIN IMMEDIATE", []).unwrap();

        let reader = open_connection(&db_path).unwrap();
        let journal_mode: String = reader
            .query_row("PRAGMA journal_mode", [], |row| get_text(row, 0))
            .unwrap();
        assert_eq!(journal_mode, "wal");
    }
}
