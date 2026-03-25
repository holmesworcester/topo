//! Retention and TTL policy for local operational events.
//!
//! Pruning preserves causal correctness: a row is only prunable if it is
//! causally superseded (another row references it as basis_event_id) AND
//! older than the retention window. The causal leaf — the row with no
//! successor — is never pruned regardless of age.

use rusqlite::{params, Connection, Result as SqliteResult};

use crate::db::queue::{current_timestamp_ms, with_sqlite_busy_retry};

/// Default retention window: 7 days in milliseconds.
pub const DEFAULT_RETENTION_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// Prune operational history rows older than `retention_ms` that are causally
/// superseded. A row is causally superseded if another row in the same table
/// references it as `basis_event_id`. Returns total pruned rows.
pub fn prune_operational_history(
    conn: &Connection,
    retention_ms: i64,
) -> SqliteResult<usize> {
    let cutoff = current_timestamp_ms() - retention_ms;
    let mut total = 0usize;

    // connection_plan_history: causal chain via basis_event_id within (tenant_id, connection_id)
    total += prune_causal_superseded(
        conn,
        "connection_plan_history",
        "tenant_id",
        "connection_id",
        "event_id",
        "basis_event_id",
        "created_at",
        cutoff,
    )?;

    // client_runtime_history: causal chain via basis_event_id within (client_id, run_id)
    total += prune_causal_superseded(
        conn,
        "client_runtime_history",
        "client_id",
        "run_id",
        "event_id",
        "basis_event_id",
        "created_at",
        cutoff,
    )?;

    // outbound_connection_history: no basis chain within the table itself
    // (basis_event_id points to connection_plan_history), so use latest-per-group
    total += prune_keeping_latest(
        conn,
        "outbound_connection_history",
        "tenant_id",
        "connection_id",
        "created_at",
        cutoff,
    )?;

    // ingress_provenance: pure append-only, prune by age
    total += prune_by_age(conn, "ingress_provenance", "ingested_at", cutoff)?;

    Ok(total)
}

/// Prune rows that are causally superseded: another row in the same table
/// has `basis_col = this_row.id_col`. Only prune if older than cutoff.
fn prune_causal_superseded(
    conn: &Connection,
    table: &str,
    group_col1: &str,
    group_col2: &str,
    id_col: &str,
    basis_col: &str,
    time_col: &str,
    cutoff: i64,
) -> SqliteResult<usize> {
    let sql = format!(
        "DELETE FROM {table}
         WHERE {time_col} < ?1
           AND EXISTS (
               SELECT 1 FROM {table} successor
               WHERE successor.{group_col1} = {table}.{group_col1}
                 AND successor.{group_col2} = {table}.{group_col2}
                 AND successor.{basis_col} = {table}.{id_col}
           )"
    );
    with_sqlite_busy_retry(|| conn.execute(&sql, params![cutoff]))
}

/// Prune rows keeping the latest per group (for tables without internal
/// causal chains).
fn prune_keeping_latest(
    conn: &Connection,
    table: &str,
    group_col1: &str,
    group_col2: &str,
    time_col: &str,
    cutoff: i64,
) -> SqliteResult<usize> {
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
    with_sqlite_busy_retry(|| conn.execute(&sql, params![cutoff]))
}

/// Prune rows purely by age (for append-only tables with no grouping).
fn prune_by_age(
    conn: &Connection,
    table: &str,
    time_col: &str,
    cutoff: i64,
) -> SqliteResult<usize> {
    let sql = format!("DELETE FROM {table} WHERE {time_col} < ?1");
    with_sqlite_busy_retry(|| conn.execute(&sql, params![cutoff]))
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
    fn prune_keeps_causal_leaf_in_connection_plan() {
        let conn = setup();
        // A -> B (B.basis_event_id = A.event_id). A is superseded, B is the leaf.
        conn.execute(
            "INSERT INTO connection_plan_history
                 (tenant_id, event_id, connection_id, remote_peer_id, remote_addr,
                  source_kind, plan_status, basis_event_id, created_at)
             VALUES ('t-a', 'ev-A', 'conn-1', 'peer-x', '127.0.0.1:7443',
                     'discovery', 'planned', NULL, 100)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO connection_plan_history
                 (tenant_id, event_id, connection_id, remote_peer_id, remote_addr,
                  source_kind, plan_status, basis_event_id, created_at)
             VALUES ('t-a', 'ev-B', 'conn-1', 'peer-x', '127.0.0.1:7443',
                     'discovery', 'active', 'ev-A', 200)",
            [],
        )
        .unwrap();

        let pruned = prune_operational_history(&conn, 0).unwrap();
        assert_eq!(pruned, 1, "only the causally superseded row should be pruned");

        // Verify ev-B (the leaf) remains
        let remaining: String = conn
            .query_row(
                "SELECT event_id FROM connection_plan_history WHERE tenant_id = 't-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, "ev-B");
    }

    #[test]
    fn prune_never_removes_causal_leaf_even_when_old() {
        let conn = setup();
        // Single row with no successor — it's a causal leaf
        conn.execute(
            "INSERT INTO connection_plan_history
                 (tenant_id, event_id, connection_id, remote_peer_id, remote_addr,
                  source_kind, plan_status, basis_event_id, created_at)
             VALUES ('t-a', 'ev-only', 'conn-1', 'peer-x', '127.0.0.1:7443',
                     'discovery', 'planned', NULL, 1)",
            [],
        )
        .unwrap();

        let pruned = prune_operational_history(&conn, 0).unwrap();
        assert_eq!(pruned, 0, "causal leaf must never be pruned");
    }

    #[test]
    fn prune_keeps_latest_outbound_history_per_group() {
        let conn = setup();
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

        let pruned = prune_operational_history(&conn, 0).unwrap();
        assert_eq!(pruned, 1);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbound_connection_history WHERE tenant_id = 't-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn prune_client_runtime_keeps_causal_leaf() {
        let conn = setup();
        // started -> activated -> stopped (chain of 3, only leaf survives)
        conn.execute(
            "INSERT INTO client_runtime_history
                 (client_id, event_id, run_id, db_path, configured_bind_addr,
                  runtime_status, tenant_count, started_at_ms, basis_event_id, created_at)
             VALUES ('c-1', 'ev-start', 'run-1', '/tmp/db', '127.0.0.1:7000',
                     'starting', 1, 100, NULL, 100)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO client_runtime_history
                 (client_id, event_id, run_id, db_path, configured_bind_addr,
                  runtime_status, tenant_count, started_at_ms, basis_event_id, created_at)
             VALUES ('c-1', 'ev-active', 'run-1', '/tmp/db', '127.0.0.1:7000',
                     'active', 1, 100, 'ev-start', 200)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO client_runtime_history
                 (client_id, event_id, run_id, db_path, configured_bind_addr,
                  runtime_status, tenant_count, started_at_ms, basis_event_id, created_at)
             VALUES ('c-1', 'ev-stopped', 'run-1', '/tmp/db', '127.0.0.1:7000',
                     'stopped', 1, 100, 'ev-active', 300)",
            [],
        )
        .unwrap();

        let pruned = prune_operational_history(&conn, 0).unwrap();
        assert_eq!(pruned, 2, "two superseded rows should be pruned");

        let remaining: String = conn
            .query_row(
                "SELECT event_id FROM client_runtime_history WHERE client_id = 'c-1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(remaining, "ev-stopped");
    }

    #[test]
    fn prune_respects_retention_window() {
        let conn = setup();
        // A -> B, but A is within the retention window
        let now = current_timestamp_ms();
        conn.execute(
            "INSERT INTO connection_plan_history
                 (tenant_id, event_id, connection_id, remote_peer_id, remote_addr,
                  source_kind, plan_status, basis_event_id, created_at)
             VALUES ('t-a', 'ev-A', 'conn-1', 'peer-x', '127.0.0.1:7443',
                     'discovery', 'planned', NULL, ?1)",
            params![now - 1000],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO connection_plan_history
                 (tenant_id, event_id, connection_id, remote_peer_id, remote_addr,
                  source_kind, plan_status, basis_event_id, created_at)
             VALUES ('t-a', 'ev-B', 'conn-1', 'peer-x', '127.0.0.1:7443',
                     'discovery', 'active', 'ev-A', ?1)",
            params![now],
        )
        .unwrap();

        // With 7-day retention, both rows are within window
        let pruned = prune_operational_history(&conn, DEFAULT_RETENTION_MS).unwrap();
        assert_eq!(pruned, 0, "nothing should be pruned within retention window");
    }
}
