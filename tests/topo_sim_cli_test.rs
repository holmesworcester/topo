mod cli_harness;

use cli_harness::*;
use std::process::Command;
use std::time::Duration;

fn topo_sim_bin() -> String {
    let _ = bin();
    env!("CARGO_BIN_EXE_topo-sim").to_string()
}

fn run_topo_sim(dbs: &[String], mode: &str, topology: &str, rounds: u32) -> serde_json::Value {
    run_topo_sim_with_options(dbs, mode, topology, rounds, false)
}

fn run_topo_sim_with_options(
    dbs: &[String],
    mode: &str,
    topology: &str,
    rounds: u32,
    repair_run: bool,
) -> serde_json::Value {
    let mut cmd = Command::new(topo_sim_bin());
    cmd.arg("--mode")
        .arg(mode)
        .arg("--topology")
        .arg(topology)
        .arg("--rounds")
        .arg(rounds.to_string());
    if repair_run {
        cmd.arg("--repair-run");
    }
    for db in dbs {
        cmd.arg("--db").arg(db);
    }
    let out = cmd.output().expect("run topo-sim");
    assert!(
        out.status.success(),
        "topo-sim failed:\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("parse topo-sim json")
}

fn create_invited_peer_dbs(tmpdir: &tempfile::TempDir, count: usize) -> Vec<String> {
    assert!(count >= 2, "need at least two peers");
    let alice_db = tmpdir
        .path()
        .join("peer0.db")
        .to_string_lossy()
        .into_owned();
    create_workspace(&alice_db);

    let mut alice = start_daemon(&alice_db);
    wait_for_daemon_ready(&alice_db, Duration::from_secs(10));
    let alice_addr = daemon_listen_addr(&alice_db);

    let mut dbs = vec![alice_db.clone()];
    for idx in 1..count {
        let db = tmpdir
            .path()
            .join(format!("peer{idx}.db"))
            .to_string_lossy()
            .into_owned();
        let invite = create_invite(&alice_db, &alice_addr);
        accept_invite_with_identity(&db, &invite, &format!("user{idx}"), &format!("device{idx}"));
        dbs.push(db);
    }

    stop_daemon(&alice_db, &mut alice);
    wait_for_daemon_stopped(&alice_db, Duration::from_secs(10));
    dbs
}

fn send_message_with_running_daemon(db: &str, content: &str) {
    let mut daemon = start_daemon(db);
    wait_for_daemon_ready(db, Duration::from_secs(10));
    send_message(db, content);
    stop_daemon(db, &mut daemon);
    wait_for_daemon_stopped(db, Duration::from_secs(10));
}

fn assert_message_count_with_running_daemon(db: &str, expected: usize) {
    let mut daemon = start_daemon(db);
    wait_for_daemon_ready(db, Duration::from_secs(10));
    assert_now(db, &format!("message_count == {expected}"));
    stop_daemon(db, &mut daemon);
    wait_for_daemon_stopped(db, Duration::from_secs(10));
}

#[test]
fn topo_sim_planner_mode_runs_and_reports_rounds() {
    let tmpdir = tempfile::tempdir().unwrap();
    let dbs = create_invited_peer_dbs(&tmpdir, 2);

    let report = run_topo_sim(&dbs, "planner", "graph", 2);
    assert_eq!(report["rounds"].as_array().unwrap().len(), 2);
    assert_eq!(report["rounds"][0]["mode"], "RealConnectTargets");
    assert_eq!(report["rounds"][1]["mode"], "RealConnectTargets");
}

#[test]
fn topo_sim_rejects_missing_db_and_bad_topology() {
    let no_db = Command::new(topo_sim_bin())
        .output()
        .expect("run topo-sim without db");
    assert!(!no_db.status.success());
    assert!(
        String::from_utf8_lossy(&no_db.stderr).contains("provide at least one --db PATH")
            || String::from_utf8_lossy(&no_db.stdout).contains("provide at least one --db PATH")
    );

    let tmpdir = tempfile::tempdir().unwrap();
    let dbs = create_invited_peer_dbs(&tmpdir, 2);
    let bad_topology = Command::new(topo_sim_bin())
        .args([
            "--mode",
            "nearest-neighbor-no-auth",
            "--topology",
            "bogus",
            "--db",
            &dbs[0],
        ])
        .output()
        .expect("run topo-sim with bad topology");
    assert!(!bad_topology.status.success());
    assert!(
        String::from_utf8_lossy(&bad_topology.stderr).contains("unsupported --topology")
            || String::from_utf8_lossy(&bad_topology.stdout).contains("unsupported --topology")
    );
}

#[test]
fn topo_sim_fake_star_propagates_one_message_to_all_peers_in_one_round() {
    let tmpdir = tempfile::tempdir().unwrap();
    let dbs = create_invited_peer_dbs(&tmpdir, 4);

    let content = "star-propagation";
    send_message_with_running_daemon(&dbs[0], content);
    assert_message_count_with_running_daemon(&dbs[0], 1);
    for db in dbs.iter().skip(1) {
        assert_message_count_with_running_daemon(db, 0);
    }

    let report = run_topo_sim(&dbs, "nearest-neighbor-no-auth", "star", 1);
    assert_eq!(report["rounds"][0]["mode"], "NearestNeighborNoAuth");
    assert_eq!(report["rounds"][0]["fake_topology"], "Star");
    assert!(
        report["rounds"][0]["sessions_executed"].as_u64().unwrap() >= 1,
        "star topology should execute at least one simulated pair sync"
    );

    for db in &dbs {
        assert_message_count_with_running_daemon(db, 1);
    }
}

#[test]
fn topo_sim_fake_graph_propagates_one_message_to_all_peers_within_bounded_rounds() {
    let tmpdir = tempfile::tempdir().unwrap();
    let dbs = create_invited_peer_dbs(&tmpdir, 12);

    let content = "graph-propagation";
    send_message_with_running_daemon(&dbs[0], content);
    assert_message_count_with_running_daemon(&dbs[0], 1);
    for db in dbs.iter().skip(1) {
        assert_message_count_with_running_daemon(db, 0);
    }

    let report = run_topo_sim(&dbs, "nearest-neighbor-no-auth", "graph", 4);
    let rounds = report["rounds"].as_array().expect("round list");
    assert_eq!(rounds.len(), 4);
    assert_eq!(rounds[0]["fake_topology"], "Graph");
    assert!(
        rounds
            .iter()
            .any(|round| round["sessions_executed"].as_u64().unwrap_or(0) > 0),
        "graph topology should execute simulated pair sync sessions"
    );

    for db in &dbs {
        assert_message_count_with_running_daemon(db, 1);
    }
}

#[test]
fn topo_sim_repair_run_is_sim_only_and_reports_stats() {
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("single.db")
        .to_string_lossy()
        .into_owned();
    create_workspace(&db);

    let report = run_topo_sim_with_options(&[db], "nearest-neighbor-no-auth", "graph", 0, true);
    assert!(report.get("repair_stats").is_some());
    assert_eq!(
        report["repair_stats"]["request_stats"]["emitted_requests"]
            .as_u64()
            .unwrap_or_default(),
        0
    );
    assert_eq!(
        report["repair_stats"]["response_stats"]["emitted_responses"]
            .as_u64()
            .unwrap_or_default(),
        0
    );
}
