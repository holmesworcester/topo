use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{ffi, Connection};

/// Emit low-memory instrumentation to tracing and (optionally) an append-only file.
pub fn emit(line: &str, file_path: Option<&str>) {
    tracing::info!("{}", line);

    let Some(path) = file_path else {
        return;
    };

    let ts_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);

    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{} {}", ts_ms, line);
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SqliteDbMemStats {
    pub cache_used_bytes: i64,
    pub schema_used_bytes: i64,
    pub stmt_used_bytes: i64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SqliteGlobalMemStats {
    pub memory_used_bytes: i64,
    pub memory_high_bytes: i64,
    pub pagecache_overflow_bytes: i64,
    pub pagecache_overflow_high_bytes: i64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AllocatorMemStats {
    pub arena_bytes: i64,
    pub used_bytes: i64,
    pub free_bytes: i64,
    pub mmap_bytes: i64,
}

fn read_db_status(db: *mut ffi::sqlite3, op: i32) -> Option<(i64, i64)> {
    let mut current = 0;
    let mut highwater = 0;
    // SAFETY: sqlite3_db_status requires a valid sqlite3* handle; callers
    // provide handles from rusqlite::Connection::handle().
    let rc = unsafe { ffi::sqlite3_db_status(db, op, &mut current, &mut highwater, 0) };
    if rc == ffi::SQLITE_OK {
        Some((current as i64, highwater as i64))
    } else {
        None
    }
}

fn read_global_status(op: i32) -> Option<(i64, i64)> {
    let mut current = 0;
    let mut highwater = 0;
    // SAFETY: sqlite3_status is process-global and safe to call with writable
    // pointers to local stack integers.
    let rc = unsafe { ffi::sqlite3_status(op, &mut current, &mut highwater, 0) };
    if rc == ffi::SQLITE_OK {
        Some((current as i64, highwater as i64))
    } else {
        None
    }
}

pub fn sqlite_db_memory(conn: &Connection) -> Option<SqliteDbMemStats> {
    // SAFETY: handle() returns the raw sqlite3* for this live connection.
    let db = unsafe { conn.handle() };
    if db.is_null() {
        return None;
    }
    let (cache_used_bytes, _) = read_db_status(db, ffi::SQLITE_DBSTATUS_CACHE_USED)?;
    let (schema_used_bytes, _) = read_db_status(db, ffi::SQLITE_DBSTATUS_SCHEMA_USED)?;
    let (stmt_used_bytes, _) = read_db_status(db, ffi::SQLITE_DBSTATUS_STMT_USED)?;
    Some(SqliteDbMemStats {
        cache_used_bytes,
        schema_used_bytes,
        stmt_used_bytes,
    })
}

pub fn sqlite_global_memory() -> Option<SqliteGlobalMemStats> {
    let (memory_used_bytes, memory_high_bytes) =
        read_global_status(ffi::SQLITE_STATUS_MEMORY_USED)?;
    let (pagecache_overflow_bytes, pagecache_overflow_high_bytes) =
        read_global_status(ffi::SQLITE_STATUS_PAGECACHE_OVERFLOW)?;
    Some(SqliteGlobalMemStats {
        memory_used_bytes,
        memory_high_bytes,
        pagecache_overflow_bytes,
        pagecache_overflow_high_bytes,
    })
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn allocator_memory() -> Option<AllocatorMemStats> {
    // SAFETY: mallinfo2 is a read-only process allocator statistics query.
    let stats = unsafe { libc::mallinfo2() };
    Some(AllocatorMemStats {
        arena_bytes: i64::try_from(stats.arena).ok()?,
        used_bytes: i64::try_from(stats.uordblks).ok()?,
        free_bytes: i64::try_from(stats.fordblks).ok()?,
        mmap_bytes: i64::try_from(stats.hblkhd).ok()?,
    })
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn allocator_memory() -> Option<AllocatorMemStats> {
    None
}
