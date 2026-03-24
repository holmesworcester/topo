//! Legacy invite bootstrap race characterization tests.
//!
//! These remain as ignored diagnostics. They are not part of the normal
//! acceptance set for the range-owned sync path.

use std::time::Duration;

mod cli_harness;

use cli_harness::{
    accept_invite_with_identity_on_running_daemon, create_workspace, ensure_active_peer,
    hold_network_test_lock_for_binary, start_daemon, temp_db, topo_cmd,
};
use rusqlite::{Connection, Result as SqliteResult};

#[tokio::test(flavor = "multi_thread")]
#[ignore = "legacy bootstrap-race repro; enable only when diagnosing bootstrap endpoint churn"]
async fn invite_endpoint_race_prevents_bootstrap_sync() {
    hold_network_test_lock_for_binary();

    let (_inviter_dir, inviter_db) = temp_db();
    create_workspace(&inviter_db);
    let _inviter = start_daemon(&inviter_db);
    ensure_active_peer(&inviter_db, Duration::from_secs(10));

    let invite = topo_cmd(&inviter_db, &["invite"]);
    assert!(invite.status.success(), "create invite failed");
    let invite_link = String::from_utf8_lossy(&invite.stdout).trim().to_string();

    let (_invitee_dir, invitee_db) = temp_db();
    let _invitee = start_daemon(&invitee_db);

    assert!(topo_cmd(&inviter_db, &["sync-log", "enable", "--all-runs"])
        .status
        .success());
    assert!(topo_cmd(&invitee_db, &["sync-log", "enable", "--all-runs"])
        .status
        .success());

    accept_invite_with_identity_on_running_daemon(
        &invitee_db,
        &invite_link,
        "bob",
        "laptop",
        Duration::from_secs(30),
    );
    tokio::time::sleep(Duration::from_secs(5)).await;

    let inviter_sync_runs = query_sync_runs(
        &inviter_db,
        "SELECT run_id, peer_id, rounds, events_sent, outcome
         FROM sync_runs
         WHERE direction = 'inbound'
         ORDER BY started_at_ms ASC",
    )
    .expect("query inviter sync runs");

    let invitee_sync_runs = query_sync_runs(
        &invitee_db,
        "SELECT run_id, peer_id, rounds, events_sent, outcome
         FROM sync_runs
         WHERE direction = 'outbound'
         ORDER BY started_at_ms ASC
         LIMIT 100",
    )
    .expect("query invitee sync runs");

    let inviter_observations = query_count(
        &inviter_db,
        "SELECT COUNT(*) FROM peer_endpoint_observations
         WHERE origin_ip LIKE '127.0.0.%' OR origin_ip LIKE '100.%'",
    )
    .expect("query inviter observations");

    println!("\n=== BUG REPRODUCTION RESULTS ===");
    println!("Inviter sync_runs (inbound): {}", inviter_sync_runs.len());
    println!("Invitee sync_runs (outbound): {}", invitee_sync_runs.len());
    println!("Inviter endpoint_observations: {}", inviter_observations);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "legacy bootstrap-race verification; enable only when diagnosing bootstrap endpoint churn"]
async fn invite_endpoint_race_fixed_allows_bootstrap_sync() {
    hold_network_test_lock_for_binary();

    let (_inviter_dir, inviter_db) = temp_db();
    create_workspace(&inviter_db);
    let _inviter = start_daemon(&inviter_db);
    ensure_active_peer(&inviter_db, Duration::from_secs(10));

    let invite = topo_cmd(&inviter_db, &["invite"]);
    assert!(invite.status.success(), "create invite failed");
    let invite_link = String::from_utf8_lossy(&invite.stdout).trim().to_string();

    let (_invitee_dir, invitee_db) = temp_db();
    let _invitee = start_daemon(&invitee_db);

    assert!(topo_cmd(&inviter_db, &["sync-log", "enable", "--all-runs"])
        .status
        .success());
    assert!(topo_cmd(&invitee_db, &["sync-log", "enable", "--all-runs"])
        .status
        .success());

    accept_invite_with_identity_on_running_daemon(
        &invitee_db,
        &invite_link,
        "bob",
        "laptop",
        Duration::from_secs(30),
    );
    tokio::time::sleep(Duration::from_secs(3)).await;

    let inviter_sync_runs = query_sync_runs(
        &inviter_db,
        "SELECT run_id, peer_id, rounds, events_sent, outcome
         FROM sync_runs
         WHERE direction = 'inbound' AND rounds > 0
         ORDER BY started_at_ms ASC",
    )
    .expect("query inviter sync runs");

    let invitee_sync_runs = query_sync_runs(
        &invitee_db,
        "SELECT run_id, peer_id, rounds, events_sent, outcome
         FROM sync_runs
         WHERE direction = 'outbound' AND rounds > 0
         ORDER BY started_at_ms ASC",
    )
    .expect("query invitee sync runs");

    println!("\n=== FIX VERIFICATION RESULTS ===");
    println!("Inviter successful sync_runs: {}", inviter_sync_runs.len());
    println!("Invitee successful sync_runs: {}", invitee_sync_runs.len());
}

fn query_sync_runs(db_path: &str, sql: &str) -> SqliteResult<Vec<(i64, String, i64, i64, String)>> {
    let conn = Connection::open(db_path)?;
    let mut stmt = conn.prepare(sql)?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get(0)?,
            row.get(1)?,
            row.get(2)?,
            row.get(3)?,
            row.get(4)?,
        ))
    })?;
    rows.collect()
}

fn query_count(db_path: &str, sql: &str) -> SqliteResult<i64> {
    let conn = Connection::open(db_path)?;
    conn.query_row(sql, [], |row| row.get(0))
}
