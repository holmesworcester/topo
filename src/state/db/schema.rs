use rusqlite::{Connection, ErrorCode, OptionalExtension, Result as SqliteResult};

/// Prototype schema epoch for the workspace-era database layout.
///
/// This prototype intentionally does not support backward migration from older
/// schema layouts. Existing DBs from prior epochs must be recreated.
const PROTOTYPE_SCHEMA_EPOCH: i64 = 2;

fn table_exists(conn: &Connection, table_name: &str) -> SqliteResult<bool> {
    conn.query_row(
        "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
        rusqlite::params![table_name],
        |row| row.get(0),
    )
}

fn incompatible_epoch_error(detail: &str) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error {
            code: ErrorCode::Unknown,
            extended_code: 1,
        },
        Some(format!(
            "incompatible prototype DB schema epoch: {}. This prototype has no backward migration; recreate the database file.",
            detail
        )),
    )
}

/// Enforce an explicit schema epoch marker so incompatible prototype DBs fail
/// with a clear error instead of surfacing later as SQL/table mismatches.
///
/// Policy:
/// - Fresh DB (no schema_migrations, no schema_epoch): initialize schema_epoch.
/// - Current epoch DB: proceed.
/// - Legacy migrated DB (has schema_migrations but no schema_epoch): reject.
/// - Wrong/invalid epoch: reject.
pub fn ensure_schema_epoch(conn: &Connection) -> SqliteResult<()> {
    let has_epoch = table_exists(conn, "schema_epoch")?;
    if has_epoch {
        let epoch_opt: Option<i64> = conn
            .query_row("SELECT epoch FROM schema_epoch LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional()?;
        let epoch = match epoch_opt {
            Some(v) => v,
            None => {
                return Err(incompatible_epoch_error(
                    "schema_epoch table exists but has no rows",
                ))
            }
        };
        if epoch != PROTOTYPE_SCHEMA_EPOCH {
            return Err(incompatible_epoch_error(&format!(
                "expected epoch {}, found {}",
                PROTOTYPE_SCHEMA_EPOCH, epoch
            )));
        }
        return Ok(());
    }

    let has_migrations = table_exists(conn, "schema_migrations")?;
    if has_migrations {
        return Err(incompatible_epoch_error(
            "legacy schema_migrations detected without schema_epoch marker",
        ));
    }

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_epoch (
            epoch INTEGER NOT NULL
        );",
    )?;
    conn.execute(
        "INSERT INTO schema_epoch (epoch) VALUES (?1)",
        rusqlite::params![PROTOTYPE_SCHEMA_EPOCH],
    )?;
    Ok(())
}

/// Ensure all schema owned by infra and event modules in a deterministic order.
pub fn ensure_all_schema(conn: &Connection) -> SqliteResult<()> {
    ensure_schema_epoch(conn)?;
    super::ensure_infra_schema(conn)?;
    crate::event_modules::ensure_schema(conn)?;
    Ok(())
}

/// Backward-compatible entrypoint used throughout the codebase.
pub fn create_tables(conn: &Connection) -> SqliteResult<()> {
    ensure_all_schema(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_create_tables() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();

        // Infra-owned tables
        assert!(tables.contains(&"events".to_string()));
        assert!(tables.contains(&"project_queue".to_string()));
        assert!(tables.contains(&"egress_queue".to_string()));
        assert!(tables.contains(&"bootstrap_context".to_string()));

        // Event-owned tables
        assert!(tables.contains(&"workspaces".to_string()));
        assert!(tables.contains(&"messages".to_string()));
        assert!(tables.contains(&"reactions".to_string()));
        assert!(tables.contains(&"deletion_intents".to_string()));

        // Epoch-only startup guard
        assert!(tables.contains(&"schema_epoch".to_string()));
        assert!(!tables.contains(&"schema_migrations".to_string()));

        let epoch: i64 = conn
            .query_row("SELECT epoch FROM schema_epoch LIMIT 1", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(epoch, PROTOTYPE_SCHEMA_EPOCH);
    }

    #[test]
    fn test_create_tables_idempotent() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        create_tables(&conn).unwrap();

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_epoch", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_reject_legacy_db_without_epoch_marker() {
        let conn = open_in_memory().unwrap();

        conn.execute_batch(
            "
            CREATE TABLE schema_migrations (
                version INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                applied_at INTEGER NOT NULL
            );
            INSERT INTO schema_migrations (version, name, applied_at)
            VALUES (8, 'add_identity_tables', 0);
            ",
        )
        .unwrap();

        let err = create_tables(&conn).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("incompatible prototype DB schema epoch"),
            "unexpected error: {}",
            msg
        );
    }

    #[test]
    fn test_state_db_has_no_transport_runtime_imports() {
        let db_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/state/db");
        for entry in fs::read_dir(db_dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let content = fs::read_to_string(&path).unwrap();
            let has_transport_import = content.lines().any(|line| {
                let trimmed = line.trim_start();
                trimmed.starts_with("use crate::transport::")
                    || trimmed.starts_with("use crate::runtime::transport::")
            });
            assert!(
                !has_transport_import,
                "state/db module {} must not import crate::transport",
                path.display()
            );
        }
    }
}
