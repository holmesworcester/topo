pub mod schema;
pub mod shareable;
pub mod store;
pub mod pending_send;
pub mod wanted;

pub use pending_send::PendingSend;
pub use wanted::Wanted;

use rusqlite::{Connection, Result as SqliteResult};
use std::path::Path;

/// Open database connection with WAL mode and performance pragmas
pub fn open_connection<P: AsRef<Path>>(path: P) -> SqliteResult<Connection> {
    let conn = Connection::open(path)?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

/// Open in-memory database (for testing)
pub fn open_in_memory() -> SqliteResult<Connection> {
    let conn = Connection::open_in_memory()?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

fn apply_pragmas(conn: &Connection) -> SqliteResult<()> {
    // Configurable cache: DB_CACHE_KIB env var, or LOW_MEM mode (1MB), default 4MB
    let cache_kib = std::env::var("DB_CACHE_KIB")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or_else(|| {
            let low_mem = std::env::var("LOW_MEM").map(|v| v != "0").unwrap_or(false);
            if low_mem { 1024 } else { 4096 }
        });

    conn.execute_batch(&format!(
        "
        PRAGMA journal_mode = WAL;
        PRAGMA synchronous = NORMAL;
        PRAGMA cache_size = -{cache_kib};
        PRAGMA busy_timeout = 5000;
        PRAGMA foreign_keys = OFF;
        "
    ))?;
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
