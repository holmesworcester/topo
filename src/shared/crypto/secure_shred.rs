//! In-place secure-zero helpers for FS-sensitive key material.
//!
//! Phase B of the delete-triggered strong-FS track: when the purge
//! cascade removes a K_bundle row from `key_secrets`, we want the
//! plaintext bytes on disk to be overwritten (not merely unlinked) so
//! that page-reuse / SQLite-internal residue inside the same DB file
//! does not leak the purged key material to a later attacker who
//! images the file.
//!
//! See `docs/DESIGN.md` §9.6.2 and `docs/PLAN.md` §22.2.
//!
//! Boundary: this module is defense-in-depth at the SQLite layer only.
//! Filesystem-level residues on SSDs (wear-leveling, bad-block remap,
//! TRIM timing) are outside the scope of this module and are called
//! out as a known residual attack surface in §9.6.6.

use rusqlite::{params, Connection};

/// Volatile zero-overwrite of a byte slice.
///
/// Uses `std::ptr::write_volatile` in a loop so the compiler cannot
/// elide the overwrite even when the slice is about to go out of
/// scope. Includes a `std::sync::atomic::compiler_fence` for the
/// same reason. Good against compile-time DCE; not a defense against
/// cold-boot DRAM recovery or other RAM-level physical attacks.
pub fn secure_zero(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// Overwrite the BLOB stored at a specific row with zeros before the
/// row is DELETEd.
///
/// Runs two statements: first an `UPDATE` that sets the target column
/// to a zero-filled blob of the same length, then a `DELETE` of the
/// row. Both execute in whatever transaction the caller has open; the
/// caller must wrap in BEGIN/COMMIT if atomicity across the two is
/// required (it usually is — the purge path already runs inside a
/// tenant-scoped transaction).
///
/// `where_col` / `where_val` are passed through directly; callers are
/// responsible for using parameterized binds against attacker-
/// controlled inputs (standard SQL-injection hygiene).
pub fn secure_shred_blob(
    conn: &Connection,
    table: &str,
    blob_col: &str,
    where_col: &str,
    where_val: &str,
) -> rusqlite::Result<()> {
    let len: Option<i64> = conn
        .query_row(
            &format!(
                "SELECT length({blob_col}) FROM {table} WHERE {where_col} = ?1 LIMIT 1"
            ),
            params![where_val],
            |row| row.get(0),
        )
        .ok();
    if let Some(len) = len {
        let zeros = vec![0u8; len as usize];
        conn.execute(
            &format!("UPDATE {table} SET {blob_col} = ?1 WHERE {where_col} = ?2"),
            params![zeros, where_val],
        )?;
    }
    conn.execute(
        &format!("DELETE FROM {table} WHERE {where_col} = ?1"),
        params![where_val],
    )?;
    Ok(())
}

/// Two-key variant for tables with a compound primary key like
/// `key_secrets (recorded_by, event_id)`. Same two-step overwrite +
/// delete, parameterized by both key columns.
pub fn secure_shred_blob_pk2(
    conn: &Connection,
    table: &str,
    blob_col: &str,
    pk_col_1: &str,
    pk_val_1: &str,
    pk_col_2: &str,
    pk_val_2: &str,
) -> rusqlite::Result<()> {
    let len: Option<i64> = conn
        .query_row(
            &format!(
                "SELECT length({blob_col}) FROM {table} \
                 WHERE {pk_col_1} = ?1 AND {pk_col_2} = ?2 LIMIT 1"
            ),
            params![pk_val_1, pk_val_2],
            |row| row.get(0),
        )
        .ok();
    if let Some(len) = len {
        let zeros = vec![0u8; len as usize];
        conn.execute(
            &format!(
                "UPDATE {table} SET {blob_col} = ?1 \
                 WHERE {pk_col_1} = ?2 AND {pk_col_2} = ?3"
            ),
            params![zeros, pk_val_1, pk_val_2],
        )?;
    }
    conn.execute(
        &format!(
            "DELETE FROM {table} WHERE {pk_col_1} = ?1 AND {pk_col_2} = ?2"
        ),
        params![pk_val_1, pk_val_2],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secure_zero_overwrites_all_bytes() {
        let mut buf = vec![0xFFu8; 256];
        secure_zero(&mut buf);
        assert!(buf.iter().all(|&b| b == 0));
    }

    #[test]
    fn secure_shred_blob_zeros_then_deletes() {
        let conn = Connection::open_in_memory().expect("open :memory:");
        conn.execute(
            "CREATE TABLE k (id TEXT PRIMARY KEY, bytes BLOB NOT NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO k (id, bytes) VALUES (?1, ?2)",
            params!["secret-id", vec![0xAAu8; 32]],
        )
        .unwrap();

        secure_shred_blob(&conn, "k", "bytes", "id", "secret-id").unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM k WHERE id = ?1", params!["secret-id"], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0, "row must be deleted after shred");
    }

    #[test]
    fn secure_shred_blob_tolerates_missing_row() {
        let conn = Connection::open_in_memory().expect("open :memory:");
        conn.execute(
            "CREATE TABLE k (id TEXT PRIMARY KEY, bytes BLOB NOT NULL)",
            [],
        )
        .unwrap();
        secure_shred_blob(&conn, "k", "bytes", "id", "missing").unwrap();
    }

    #[test]
    fn secure_shred_blob_pk2_works_for_compound_keys() {
        let conn = Connection::open_in_memory().expect("open :memory:");
        conn.execute(
            "CREATE TABLE k (
                a TEXT NOT NULL,
                b TEXT NOT NULL,
                bytes BLOB NOT NULL,
                PRIMARY KEY (a, b)
            )",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO k (a, b, bytes) VALUES (?1, ?2, ?3)",
            params!["tenant", "evid", vec![0x77u8; 48]],
        )
        .unwrap();

        secure_shred_blob_pk2(&conn, "k", "bytes", "a", "tenant", "b", "evid").unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM k WHERE a = ?1 AND b = ?2",
                params!["tenant", "evid"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }
}
