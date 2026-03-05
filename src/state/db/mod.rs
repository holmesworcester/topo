pub mod egress_queue;
pub mod health;
pub mod intro;
pub mod local_client_ops;
pub mod need_queue;
pub mod project_queue;
pub mod queue;
pub mod removal_watch;
pub mod schema;
pub mod store;
pub mod transport_creds;
pub mod transport_trust;
pub mod wanted;

use rusqlite::{Connection, Result as SqliteResult};
use std::path::Path;

/// Open database connection with WAL mode and performance pragmas
pub fn open_connection<P: AsRef<Path>>(path: P) -> SqliteResult<Connection> {
    let conn = Connection::open(path)?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

/// Open in-memory database (for testing)
#[cfg(test)]
pub fn open_in_memory() -> SqliteResult<Connection> {
    let conn = Connection::open_in_memory()?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

fn apply_pragmas(conn: &Connection) -> SqliteResult<()> {
    if low_mem_mode() {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -256;
            PRAGMA cache_spill = ON;
            PRAGMA temp_store = FILE;
            PRAGMA mmap_size = 0;
            PRAGMA wal_autocheckpoint = 64;
            PRAGMA journal_size_limit = 262144;
            PRAGMA soft_heap_limit = 2097152;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = OFF;
            ",
        )?;
    } else {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -64000;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = OFF;
            ",
        )?;
    }
    Ok(())
}

use crate::tuning::low_mem_mode;

pub fn ensure_infra_schema(conn: &Connection) -> SqliteResult<()> {
    wanted::ensure_schema(conn)?;
    store::ensure_schema(conn)?;
    project_queue::ensure_schema(conn)?;
    egress_queue::ensure_schema(conn)?;
    health::ensure_schema(conn)?;
    intro::ensure_schema(conn)?;
    transport_trust::ensure_schema(conn)?;
    transport_creds::ensure_schema(conn)?;
    need_queue::ensure_schema(conn)?;
    local_client_ops::ensure_schema(conn)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory() {
        let conn = open_in_memory().unwrap();
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        // In-memory databases may report "memory" instead of "wal"
        assert!(journal_mode == "wal" || journal_mode == "memory");
    }
}
