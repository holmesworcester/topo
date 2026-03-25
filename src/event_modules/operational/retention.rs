//! Retention and TTL policy for local operational events.
//!
//! Local operational events accumulate over time. This module provides safe
//! pruning that preserves the latest-state query invariant: after retention,
//! all current-state queries against projected tables still produce the
//! expected answers.
//!
//! The pruning strategy keeps the latest event per entity (connection,
//! sync round, client run) and prunes older history rows that are fully
//! superseded.

use rusqlite::{params, Connection, Result as SqliteResult};

use crate::db::queue::{current_timestamp_ms, with_sqlite_busy_retry};

/// Default retention window: 7 days in milliseconds.
pub const DEFAULT_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Prune operational history rows older than `retention_ms` that have been
/// superseded by newer rows. Returns the total number of pruned rows.
pub fn prune_operational_history(
    conn: &Connection,
    retention_ms: i64,
) -> SqliteResult<usize> {
    let cutoff = current_timestamp_ms() - retention_ms;
    let mut total = 0usize;

    // Prune outbound_connection_history: keep latest per (tenant_id, connection_id)
    total += prune_table_keeping_latest(
        conn,
        "outbound_connection_history",
        "tenant_id",
        "connection_id",
        "created_at",
        cutoff,
    )?;

    // Prune connection_plan_history: keep latest per (tenant_id, connection_id)
    total += prune_table_keeping_latest(
        conn,
        "connection_plan_history",
        "tenant_id",
        "connection_id",
        "created_at",
        cutoff,
    )?;

    // Prune client_runtime_history: keep latest per (client_id, run_id)
    total += prune_table_keeping_latest(
        conn,
        "client_runtime_history",
        "client_id",
        "run_id",
        "created_at",
        cutoff,
    )?;

    Ok(total)
}

fn prune_table_keeping_latest(
    conn: &Connection,
    table: &str,
    group_col1: &str,
    group_col2: &str,
    time_col: &str,
    cutoff: i64,
) -> SqliteResult<usize> {
    // SQL: delete rows older than cutoff that are NOT the latest row in their group.
    // "Latest" = row with MAX(time_col, event_id) per group.
    let sql = format!(
        "DELETE FROM {table}
         WHERE {time_col} < ?1
           AND rowid NOT IN (
               SELECT rowid FROM {table} t2
               WHERE t2.{group_col1} = {table}.{group_col1}
                 AND t2.{group_col2} = {table}.{group_col2}
               ORDER BY t2.{time_col} DESC, t2.rowid DESC
               LIMIT 1
           )"
    );
    with_sqlite_busy_retry(|| {
        let count = conn.execute(&sql, params![cutoff])?;
        Ok(count)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn prune_with_no_data_returns_zero() {
        let conn = setup();
        let pruned = prune_operational_history(&conn, DEFAULT_RETENTION_MS).unwrap();
        assert_eq!(pruned, 0);
    }

    #[test]
    fn prune_keeps_latest_per_group() {
        let conn = setup();

        // Insert two rows for the same (tenant, connection_id) group
        conn.execute(
            "INSERT INTO outbound_connection_history
                 (tenant_id, event_id, connection_id, lifecycle_kind, remote_peer_id,
                  remote_addr, basis_event_id, used_bootstrap_fallback, created_at)
             VALUES ('t-a', 'e-old', 'conn-1', 'failed', 'peer-x',
                     '127.0.0.1:7443', 'basis-1', 0, 100)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO outbound_connection_history
                 (tenant_id, event_id, connection_id, lifecycle_kind, remote_peer_id,
                  remote_addr, basis_event_id, used_bootstrap_fallback, created_at)
             VALUES ('t-a', 'e-new', 'conn-1', 'authenticated', 'peer-x',
                     '127.0.0.1:7443', 'basis-2', 0, 200)",
            [],
        )
        .unwrap();

        // Prune with cutoff = now (both rows are "old" from the cutoff's perspective)
        let pruned = prune_operational_history(&conn, 0).unwrap();
        assert_eq!(pruned, 1, "should prune only the older row");

        // Verify the newer row is still there
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbound_connection_history WHERE tenant_id = 't-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}
