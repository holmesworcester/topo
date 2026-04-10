//! Daemon-based multi-source tiered-window catch-up benchmarks.
//!
//! Two realistic loopback scenarios:
//! - cold join: a fresh peer joins a community that is already in sync
//! - rejoin: an existing peer goes offline, the rest advance, then it rejoins
//!
//! We intentionally avoid extra bootstrap/trust scaffolding here. The point of
//! these tests is to measure what the real daemon/runtime does today.

mod cli_harness;
mod daemon_perf_harness;

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cli_harness::{
    accept_invite_with_identity_on_running_daemon, active_tenant_peer_id, assert_eventually,
    connections_json, create_workspace_with_details, daemon_listen_addr,
    daemon_transport_fingerprint, ensure_active_peer, generate_messages,
    hold_network_test_lock_for_binary, send_message, start_daemon_with_options, stop_daemon,
    sync_log_json, topo_assert_eventually, topo_cmd, topo_create_invite_retry,
    wait_for_active_tenant_ready, wait_for_daemon_stopped, DaemonOptions, HarnessDaemon,
};
use daemon_perf_harness::write_summary;

const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const WEEK_MS: i64 = 7 * DAY_MS;
const TWELVE_WEEK_MS: i64 = 12 * WEEK_MS;
const THREE_YEARS_MS: i64 = 3 * 365 * DAY_MS;

#[derive(Clone, Copy)]
struct RangeTiming {
    count: i64,
    first_stored_at_ms: Option<i64>,
    projected_at_ms: Option<i64>,
}

#[allow(dead_code)]
#[derive(Debug)]
struct BenchOutcome {
    useful_unique_events: i64,
    downloader_event_frames: i64,
    delivery_efficiency: f64,
    source_recorded_events: Vec<i64>,
    active_sources: usize,
}

#[allow(dead_code)]
#[derive(Debug)]
struct ReplicatedRejoinOutcome {
    projected_delta_messages: i64,
    active_sources: usize,
    source_event_frames: Vec<i64>,
    downloader_event_frames: i64,
    delivery_efficiency: f64,
    catchup_wall_secs: f64,
    messages_per_second: f64,
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as i64
}

fn env_i64(name: &str, default: i64) -> i64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(default)
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn inherited_tier_env() -> Vec<(String, String)> {
    [
        "TOPO_GENERATE_MESSAGE_SPREAD_MS",
        "TOPO_EVENT_TIMELINE",
        "TOPO_EVENT_TIMELINE_GROUPS",
        "TOPO_ENABLE_LIVE_SUPPRESSION",
        "TOPO_LIVE_SUPPRESSION_EVENT_ID_CAP",
        "TOPO_LIVE_SUPPRESSION_SEND_BATCH_SIZE",
        "TOPO_LIVE_SUPPRESSION_BATCH_SETTLE_MS",
    ]
    .into_iter()
    .filter_map(|key| {
        std::env::var(key)
            .ok()
            .map(|value| (key.to_string(), value))
    })
    .collect()
}

fn enable_sync_logging(db: &str) {
    let out = topo_cmd(db, &["sync-log", "enable", "--all-runs"]);
    assert!(
        out.status.success(),
        "sync-log enable failed for {}: {}",
        db,
        String::from_utf8_lossy(&out.stderr)
    );
    let conn = topo::db::open_connection(db).expect("open db for sync-log retention");
    topo::db::sync_log::update_config(
        &conn,
        topo::db::sync_log::SyncLogConfigPatch {
            max_runs: Some(50_000),
            ..Default::default()
        },
    )
    .expect("raise sync-log retention for perf attribution");
}

fn bench_tmpdir(label: &str) -> tempfile::TempDir {
    let root = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/holmes/p7tmp"));
    std::fs::create_dir_all(&root).expect("create benchmark tmp root");
    let mut builder = tempfile::Builder::new();
    builder.prefix(label);
    if std::env::var_os("TOPO_KEEP_BENCH_TMPDIR").is_some() {
        builder.disable_cleanup(true);
    }
    let tmpdir = builder.tempdir_in(root).expect("create benchmark tempdir");
    if std::env::var_os("TOPO_KEEP_BENCH_TMPDIR").is_some() {
        eprintln!("keeping benchmark tempdir: {}", tmpdir.path().display());
    }
    tmpdir
}

fn wait_for_predicate_with_sync_kicks(dbs: &[String], predicate: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut last_failure = String::new();
    loop {
        let mut failures = Vec::new();
        for db in dbs {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "predicate timed out after {:?}: predicate={} last_failure={}",
                timeout,
                predicate,
                last_failure
            );
            let slice_ms = remaining.min(Duration::from_secs(1)).as_millis().max(1) as u64;
            let out = topo_assert_eventually(db, predicate, slice_ms);
            if !out.status.success() {
                failures.push(format!(
                    "{} => {}",
                    db,
                    String::from_utf8_lossy(&out.stdout).trim()
                ));
            }
        }
        if failures.is_empty() {
            return;
        }
        last_failure = failures.join(" | ");
        for db in dbs {
            trigger_sync_round_all(db);
        }
    }
}

fn wait_for_predicate_without_sync_kicks(dbs: &[String], predicate: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut last_failure = String::new();
    loop {
        let mut failures = Vec::new();
        for db in dbs {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "predicate timed out after {:?}: predicate={} last_failure={}",
                timeout,
                predicate,
                last_failure
            );
            let slice_ms = remaining.min(Duration::from_secs(1)).as_millis().max(1) as u64;
            let out = topo_assert_eventually(db, predicate, slice_ms);
            if !out.status.success() {
                failures.push(format!(
                    "{} => {}",
                    db,
                    String::from_utf8_lossy(&out.stdout).trim()
                ));
            }
        }
        if failures.is_empty() {
            return;
        }
        last_failure = failures.join(" | ");
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_message_count_all_via_cli(dbs: &[String], expected: i64, timeout: Duration) {
    wait_for_predicate_with_sync_kicks(dbs, &format!("message_count >= {}", expected), timeout);
}

fn wait_for_message_count_via_cli_without_sync_kicks(
    db: &str,
    expected: i64,
    timeout: Duration,
) -> i64 {
    wait_for_predicate_without_sync_kicks(
        &[db.to_string()],
        &format!("message_count >= {}", expected),
        timeout,
    );
    current_timestamp_ms()
}

fn wait_for_message_count_all_via_cli_without_sync_kicks(
    dbs: &[String],
    expected: i64,
    timeout: Duration,
) {
    wait_for_predicate_without_sync_kicks(dbs, &format!("message_count >= {}", expected), timeout);
}

fn event_visible_on_all_via_cli(dbs: &[String], event_id_hex: &str, timeout: Duration) -> bool {
    let predicate = format!("has_event:{} >= 1", event_id_hex);
    dbs.iter().all(|db| {
        let out = topo_assert_eventually(db, &predicate, timeout.as_millis().max(1) as u64);
        out.status.success()
    })
}

fn peers_output(db: &str) -> String {
    let out = topo_cmd(db, &["peers"]);
    assert!(
        out.status.success(),
        "peers failed for {}: {}",
        db,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn wait_for_peers_output_to_include_labels(
    db: &str,
    expected_labels: &[String],
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        let peers = peers_output(db);
        if expected_labels.iter().all(|label| peers.contains(label)) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "peers output for {} did not include {:?} within {:?}:\n{}",
            db,
            expected_labels,
            timeout,
            peers
        );
        trigger_sync_round_all(db);
        thread::sleep(Duration::from_millis(100));
    }
}

fn sync_log_show_output(db: &str, extra_args: &[&str]) -> String {
    let mut args = vec!["sync-log", "show", "--all", "--limit", "100000"];
    args.extend_from_slice(extra_args);
    let out = topo_cmd(db, &args);
    assert!(
        out.status.success(),
        "sync-log show failed for {}: stdout={} stderr={}",
        db,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

fn parse_sync_events_rx_total(stdout: &str) -> i64 {
    stdout
        .lines()
        .filter(|line| line.starts_with("RUN "))
        .filter_map(|line| {
            line.split_whitespace().find_map(|field| {
                field
                    .strip_prefix("sync_events_rx=")
                    .and_then(|value| value.parse::<i64>().ok())
            })
        })
        .sum()
}

fn sync_events_received_for_peer_via_cli(db: &str, peer_id: &str) -> i64 {
    parse_sync_events_rx_total(&sync_log_show_output(db, &["--peer", peer_id]))
}

fn nonnegative_count_delta(after: i64, before: i64) -> i64 {
    after.checked_sub(before).unwrap_or(0).max(0)
}

fn source_sync_event_frame_deltas_via_cli(db: &str, sources: &[Node], before: &[i64]) -> Vec<i64> {
    sources
        .iter()
        .zip(before.iter())
        .map(|(source, before_count)| {
            let after = sync_events_received_for_peer_via_cli(db, &source.tenant_peer_id);
            nonnegative_count_delta(after, *before_count)
        })
        .collect()
}

fn wait_for_source_sync_event_frame_deltas_via_cli(
    db: &str,
    sources: &[Node],
    before: &[i64],
    minimum_total: i64,
    timeout: Duration,
    stable_for: Duration,
) -> Vec<i64> {
    let start = Instant::now();
    let mut last = source_sync_event_frame_deltas_via_cli(db, sources, before);
    let mut stable_since = None;
    loop {
        let current = source_sync_event_frame_deltas_via_cli(db, sources, before);
        let current_total: i64 = current.iter().sum();
        if current == last && current_total >= minimum_total {
            let since = stable_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= stable_for {
                return current;
            }
        } else {
            last = current;
            stable_since = None;
        }
        assert!(
            start.elapsed() < timeout,
            "source sync-log receive deltas did not stabilize within {:?}: minimum_total={} current_total={} deltas={:?}",
            timeout,
            minimum_total,
            current_total,
            last,
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn total_message_count_sql(db: &str) -> i64 {
    let conn = topo::db::open_connection(db).expect("open db for total_message_count");
    let peer_id = active_tenant_peer_id(db).expect("active tenant peer id");
    conn.query_row(
        "SELECT COUNT(*)
         FROM messages
         WHERE recorded_by = ?1",
        rusqlite::params![peer_id],
        |row| row.get(0),
    )
    .expect("query total_message_count")
}

fn message_ids_since_sql(db: &str, cutoff_ms: Option<i64>) -> BTreeSet<String> {
    let conn = topo::db::open_connection(db).expect("open db for message_ids_since");
    let mut stmt = conn
        .prepare(
            "SELECT message_id
             FROM messages
             WHERE (?1 IS NULL OR created_at >= ?1)",
        )
        .expect("prepare message_ids_since");
    stmt.query_map(rusqlite::params![cutoff_ms], |row| {
        topo::db::sql_types::get_text(row, 0)
    })
    .expect("query message_ids_since")
    .collect::<Result<BTreeSet<_>, _>>()
    .expect("collect message_ids_since")
}

fn union_message_count_since_sql(dbs: &[String], cutoff_ms: Option<i64>) -> i64 {
    let mut message_ids = BTreeSet::new();
    for db in dbs {
        message_ids.extend(message_ids_since_sql(db, cutoff_ms));
    }
    message_ids.len() as i64
}

fn message_count_since_sql(db: &str, cutoff_ms: i64) -> i64 {
    let conn = topo::db::open_connection(db).expect("open db for message_count_since");
    let peer_id = active_tenant_peer_id(db).expect("active tenant peer id");
    conn.query_row(
        "SELECT COUNT(*)
         FROM messages
         WHERE recorded_by = ?1
           AND created_at >= ?2",
        rusqlite::params![peer_id, cutoff_ms],
        |row| row.get(0),
    )
    .expect("query message_count_since")
}

fn range_timing_sql(db: &str, min_created_at_ms: Option<i64>) -> RangeTiming {
    let conn = topo::db::open_connection(db).expect("open db for range_timing");
    let peer_id = active_tenant_peer_id(db).expect("active tenant peer id");
    conn.query_row(
        "SELECT COUNT(*), MAX(t.first_stored_at), MAX(t.projected_at)
         FROM messages m
         LEFT JOIN event_timeline t ON t.event_id = m.message_id
         WHERE m.recorded_by = ?1
           AND (?2 IS NULL OR m.created_at >= ?2)",
        rusqlite::params![peer_id, min_created_at_ms],
        |row| {
            Ok(RangeTiming {
                count: row.get(0)?,
                first_stored_at_ms: row.get(1)?,
                projected_at_ms: row.get(2)?,
            })
        },
    )
    .expect("query range_timing")
}

fn elapsed_secs(metric_start_ms: i64, ts_ms: Option<i64>) -> f64 {
    ts_ms
        .unwrap_or(metric_start_ms)
        .saturating_sub(metric_start_ms) as f64
        / 1000.0
}

fn wait_for_message_count(db: &str, expected: i64, timeout: Duration) -> i64 {
    let start = Instant::now();
    let mut last_count = -1;
    let mut stable_since = None;
    loop {
        let count = total_message_count_sql(db);
        if count >= expected {
            return current_timestamp_ms();
        }
        if count == last_count {
            let since = stable_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_secs(2) {
                trigger_sync_round_all(db);
                stable_since = None;
            }
        } else {
            last_count = count;
            stable_since = None;
        }
        assert!(
            start.elapsed() < timeout,
            "message_count timed out after {:?} for db={}: expected_at_least={} actual={}",
            timeout,
            db,
            expected,
            count
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_message_count_since(db: &str, cutoff_ms: i64, expected: i64, timeout: Duration) -> i64 {
    let start = Instant::now();
    let mut last_count = -1;
    let mut stable_since = None;
    loop {
        let count = message_count_since_sql(db, cutoff_ms);
        if count >= expected {
            return current_timestamp_ms();
        }
        if count == last_count {
            let since = stable_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_secs(2) {
                trigger_sync_round_all(db);
                stable_since = None;
            }
        } else {
            last_count = count;
            stable_since = None;
        }
        assert!(
            start.elapsed() < timeout,
            "message_count_since timed out after {:?} for db={}: cutoff_ms={} expected_at_least={} actual={}",
            timeout,
            db,
            cutoff_ms,
            expected,
            count
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_message_count_all(dbs: &[String], expected: i64, timeout: Duration) {
    let start = Instant::now();
    let mut last_counts = Vec::<i64>::new();
    let mut stable_since = None;
    loop {
        let counts: Vec<i64> = dbs.iter().map(|db| total_message_count_sql(db)).collect();
        if counts.iter().all(|count| *count >= expected) {
            return;
        }
        if counts == last_counts {
            let since = stable_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= Duration::from_secs(2) {
                for db in dbs {
                    trigger_sync_round_all(db);
                }
                stable_since = None;
            }
        } else {
            last_counts = counts.clone();
            stable_since = None;
        }
        assert!(
            start.elapsed() < timeout,
            "message_count_all timed out after {:?}: expected_at_least={} counts={:?}",
            timeout,
            expected,
            counts
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn sync_log_receive_counts_by_peer(value: &serde_json::Value) -> HashMap<String, i64> {
    let mut counts = HashMap::new();
    for run in value["runs"].as_array().into_iter().flatten() {
        let Some(peer_id) = run["peer_id"].as_str() else {
            continue;
        };
        let events_received = run["events_received"]
            .as_i64()
            .or_else(|| run["events_received"].as_u64().map(|v| v as i64))
            .unwrap_or(0);
        if events_received > 0 {
            *counts.entry(peer_id.to_string()).or_insert(0) += events_received;
        }
    }
    counts
}

fn received_events_by_peer_via_cli(db: &str) -> HashMap<String, i64> {
    sync_log_receive_counts_by_peer(&sync_log_json(db, 100_000))
}

fn ingest_observability_json_or_empty(db: &str) -> Option<serde_json::Value> {
    let out = topo_cmd(db, &["observability", "ingest", "--json"]);
    if out.status.success() {
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Some(
            serde_json::from_str(stdout.trim()).expect("failed to parse observability ingest JSON"),
        );
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    if stderr.contains("no active tenant") {
        None
    } else {
        panic!("topo observability ingest --json failed: {}", stderr);
    }
}

fn diff_count_map(
    after: &HashMap<String, i64>,
    before: &HashMap<String, i64>,
) -> HashMap<String, i64> {
    let mut delta = HashMap::new();
    for (key, after_count) in after {
        let before_count = before.get(key).copied().unwrap_or(0);
        let diff = after_count.saturating_sub(before_count);
        if diff > 0 {
            delta.insert(key.clone(), diff);
        }
    }
    delta
}

fn observed_events_by_source_peer_via_cli(db: &str) -> HashMap<String, i64> {
    let Some(value) = ingest_observability_json_or_empty(db) else {
        return HashMap::new();
    };
    let mut counts = HashMap::new();
    for source in value["sources"].as_array().into_iter().flatten() {
        let key = source["source_peer_id"]
            .as_str()
            .or_else(|| source["source"].as_str())
            .unwrap_or("unknown")
            .to_string();
        let count = source["event_count"].as_i64().unwrap_or(0);
        if count > 0 {
            *counts.entry(key).or_insert(0) += count;
        }
    }
    counts
}

fn count_source_tag_events(source_counts: &HashMap<String, i64>, sources: &[Node]) -> Vec<i64> {
    sources
        .iter()
        .map(|source| {
            source_counts
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect()
}

fn changed_sync_run_count_from_value(value: &serde_json::Value) -> i64 {
    value["runs"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|run| {
            let rounds = run["rounds"]
                .as_i64()
                .or_else(|| run["rounds"].as_u64().map(|v| v as i64))
                .unwrap_or(0);
            let events_sent = run["events_sent"]
                .as_i64()
                .or_else(|| run["events_sent"].as_u64().map(|v| v as i64))
                .unwrap_or(0);
            let events_received = run["events_received"]
                .as_i64()
                .or_else(|| run["events_received"].as_u64().map(|v| v as i64))
                .unwrap_or(0);
            rounds > 0 || events_sent > 0 || events_received > 0
        })
        .count() as i64
}

fn changed_sync_run_count_via_cli(db: &str) -> i64 {
    changed_sync_run_count_from_value(&sync_log_json(db, 100_000))
}

fn endpoint_observation_count(db: &str, remote_peer_id: &str) -> i64 {
    let now_ms = current_timestamp_ms();
    let conn = topo::db::open_connection(db).expect("open db for endpoint observation count");
    conn.query_row(
        "SELECT COUNT(*)
         FROM peer_endpoint_observations
         WHERE via_peer_id = ?1
           AND expires_at > ?2",
        rusqlite::params![remote_peer_id, now_ms],
        |row| row.get(0),
    )
    .unwrap_or(0)
}

fn unique_sync_received_event_count_via_cli(db: &str) -> i64 {
    ingest_observability_json_or_empty(db)
        .and_then(|value| value["quic_received_unique_event_count"].as_i64())
        .unwrap_or(0)
}

fn wait_for_downloader_receives_stable(db: &str, timeout: Duration, stable_for: Duration) {
    let start = Instant::now();
    let mut last: i64 = received_events_by_peer_via_cli(db).values().sum();
    let mut stable_since = None;
    loop {
        let current: i64 = received_events_by_peer_via_cli(db).values().sum();
        if current == last {
            let since = stable_since.get_or_insert_with(Instant::now);
            if since.elapsed() >= stable_for {
                return;
            }
        } else {
            last = current;
            stable_since = None;
        }
        assert!(
            start.elapsed() < timeout,
            "downloader receive totals did not stabilize within {:?}: total={}",
            timeout,
            current
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn trigger_sync_round_all(db: &str) {
    let out = topo_cmd(db, &["sync", "round", "all"]);
    if !out.status.success() {
        eprintln!(
            "  note: sync round all failed for {}: {}",
            db,
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

fn wait_for_endpoint_target_count_at_least(db: &str, minimum: usize, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let connections = connections_json(db);
        if connections.len() >= minimum {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "expected at least {} endpoint targets in {} within {:?}, got {:?}",
            minimum,
            db,
            timeout,
            connections
        );
        trigger_sync_round_all(db);
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_full_mesh_peer_visibility(nodes: &[NodeView], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let mut missing = Vec::new();
        for observer in nodes {
            for remote in nodes {
                if observer.db == remote.db {
                    continue;
                }
                let peers = peers_output(&observer.db);
                if !peers.contains(&remote.label) {
                    missing.push(format!("{}->{}", observer.label, remote.label));
                }
            }
        }
        if missing.is_empty() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "full-mesh endpoint observations did not converge within {:?}: missing={:?}",
            timeout,
            missing
        );
        for node in nodes {
            trigger_sync_round_all(&node.db);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn assert_full_mesh_connectivity_basics(nodes: &[NodeView], timeout: Duration) {
    let expected_peer_count = nodes.len();
    let expected_endpoint_count = nodes.len().saturating_sub(1);
    let timeout_ms = timeout.as_millis().max(1) as u64;
    for node in nodes {
        assert_eventually(
            &node.db,
            &format!("peer_count == {}", expected_peer_count),
            timeout_ms,
        );
        assert_eventually(
            &node.db,
            &format!("endpoint_observation_count >= {}", expected_endpoint_count),
            timeout_ms,
        );
    }
    wait_for_full_mesh_peer_visibility(nodes, timeout);
    for node in nodes {
        let expected_labels: Vec<String> = nodes
            .iter()
            .filter(|remote| remote.db != node.db)
            .map(|remote| remote.label.clone())
            .collect();
        wait_for_peers_output_to_include_labels(&node.db, &expected_labels, timeout);
        wait_for_endpoint_target_count_at_least(&node.db, expected_endpoint_count, timeout);
    }
}

fn assert_full_mesh_live_message_delivery(nodes: &[NodeView], timeout: Duration) -> i64 {
    let dbs: Vec<String> = nodes.iter().map(|node| node.db.clone()).collect();
    let deadline = Instant::now() + timeout;
    let mut remaining: BTreeSet<usize> = (0..nodes.len()).collect();
    let mut delivered = 0;
    let mut attempts = 0;
    while !remaining.is_empty() {
        assert!(
            Instant::now() < deadline,
            "full-mesh live probe delivery did not converge within {:?}: remaining_origins={:?}",
            timeout,
            remaining
                .iter()
                .map(|idx| nodes[*idx].label.clone())
                .collect::<Vec<_>>()
        );
        let origin_indexes: Vec<usize> = remaining.iter().copied().collect();
        for origin_index in origin_indexes {
            let remaining_time = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining_time.is_zero(),
                "full-mesh live probe delivery timed out for origin={} after {:?}",
                nodes[origin_index].label,
                timeout
            );
            let node = &nodes[origin_index];
            attempts += 1;
            let event_id = send_message(
                &node.db,
                &format!("live-full-mesh-probe-{}-{}", node.label, attempts),
            );
            let probe_timeout = remaining_time.min(Duration::from_secs(2));
            if event_visible_on_all_via_cli(&dbs, &event_id, probe_timeout) {
                remaining.remove(&origin_index);
                delivered += 1;
                eprintln!(
                    "full-mesh live probe from {} visible on {} nodes after {} attempts",
                    node.label,
                    nodes.len(),
                    attempts
                );
            }
        }
        if !remaining.is_empty() {
            thread::sleep(Duration::from_millis(250));
        }
    }
    delivered
}

struct Node {
    label: String,
    db: String,
    _daemon: HarnessDaemon,
    tenant_peer_id: String,
    transport_peer_id: String,
}

#[derive(Clone)]
struct NodeView {
    label: String,
    db: String,
}

impl From<&Node> for NodeView {
    fn from(value: &Node) -> Self {
        Self {
            label: value.label.clone(),
            db: value.db.clone(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ConnectivityMode {
    BootstrapOnly,
    DiscoveryLoopback,
}

impl ConnectivityMode {
    fn suffix(self) -> &'static str {
        match self {
            Self::BootstrapOnly => "bootstrap_only",
            Self::DiscoveryLoopback => "discovery_loopback",
        }
    }

    fn title(self) -> &'static str {
        match self {
            Self::BootstrapOnly => "bootstrap-only",
            Self::DiscoveryLoopback => "loopback discovery",
        }
    }
}

fn start_peer(
    db: &str,
    extra_env: Vec<(String, String)>,
    connectivity: ConnectivityMode,
) -> HarnessDaemon {
    let mut extra_env = extra_env;
    if matches!(connectivity, ConnectivityMode::DiscoveryLoopback) {
        extra_env.push(("TOPO_TEST_DISCOVERY_LOOPBACK".to_string(), "1".to_string()));
    }
    start_daemon_with_options(
        db,
        &DaemonOptions {
            disable_discovery: matches!(connectivity, ConnectivityMode::BootstrapOnly),
            extra_env,
            ..Default::default()
        },
    )
}

fn create_online_community(
    tmpdir: &tempfile::TempDir,
    peer_labels: &[String],
    connectivity: ConnectivityMode,
) -> (Vec<Node>, String) {
    assert!(!peer_labels.is_empty(), "peer_labels must not be empty");
    let inherited_env = inherited_tier_env();
    let hub_db = tmpdir.path().join("hub.db").to_str().unwrap().to_string();
    create_workspace_with_details(&hub_db, "workspace", "hub", "desktop");
    enable_sync_logging(&hub_db);
    let hub_daemon = start_peer(&hub_db, inherited_env.clone(), connectivity);
    ensure_active_peer(&hub_db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&hub_db, Duration::from_secs(120));

    let invite_link = topo_create_invite_retry(&hub_db, &daemon_listen_addr(&hub_db));

    let mut nodes = Vec::with_capacity(peer_labels.len());
    nodes.push(Node {
        label: "hub".to_string(),
        db: hub_db.clone(),
        _daemon: hub_daemon,
        tenant_peer_id: active_tenant_peer_id(&hub_db).expect("hub active tenant peer id"),
        transport_peer_id: daemon_transport_fingerprint(&hub_db),
    });

    for label in peer_labels.iter().skip(1) {
        let db = tmpdir
            .path()
            .join(format!("{label}.db"))
            .to_str()
            .unwrap()
            .to_string();
        enable_sync_logging(&db);
        let daemon = start_peer(&db, inherited_env.clone(), connectivity);
        accept_invite_with_identity_on_running_daemon(
            &db,
            &invite_link,
            label,
            &format!("{label}-device"),
            Duration::from_secs(60),
        );
        ensure_active_peer(&db, Duration::from_secs(10));
        wait_for_active_tenant_ready(&db, Duration::from_secs(120));
        nodes.push(Node {
            label: label.clone(),
            db: db.clone(),
            _daemon: daemon,
            tenant_peer_id: active_tenant_peer_id(&db).expect("joined active tenant peer id"),
            transport_peer_id: daemon_transport_fingerprint(&db),
        });
    }

    (nodes, invite_link)
}

fn emit_warmup_messages(nodes: &[Node]) -> i64 {
    let trace_warmup_events = std::env::var_os("TOPO_TRACE_WARMUP_EVENTS").is_some();
    for node in nodes {
        let label = format!("warmup-{}", node.label);
        let event_id = send_message(&node.db, &label);
        if trace_warmup_events {
            eprintln!(
                "warmup event: origin={} label={} event_id={}",
                node.label, label, event_id
            );
        }
    }
    nodes.len() as i64
}

fn generate_messages_distributed(nodes: &[&Node], total_messages: i64) {
    assert!(total_messages >= 0, "total_messages must be non-negative");
    if nodes.is_empty() || total_messages == 0 {
        return;
    }
    let per_node = total_messages / nodes.len() as i64;
    let remainder = total_messages % nodes.len() as i64;
    for (idx, node) in nodes.iter().enumerate() {
        let count = per_node + i64::from((idx as i64) < remainder);
        if count > 0 {
            generate_messages(&node.db, count as usize);
        }
    }
}

fn generate_messages_replicated(nodes: &[Node], total_messages: i64) {
    assert!(!nodes.is_empty(), "nodes must not be empty");
    assert!(total_messages >= 0, "total_messages must be non-negative");
    if total_messages == 0 {
        return;
    }
    generate_messages(&nodes[0].db, total_messages as usize);
}

fn write_summary_with_sources(
    summary_key: &str,
    title: &str,
    ranges: &[(&str, RangeTiming)],
    metric_start_ms: i64,
    total_wall_secs: f64,
    useful_unique_events: i64,
    downloader_event_frames: i64,
    delivery_efficiency: f64,
    active_sources: usize,
    unattributed_event_frames: i64,
    sources: &[Node],
    source_event_frames: &[i64],
    source_sync_run_deltas: &[i64],
    endpoint_obs_counts: &[i64],
) {
    let mut summary = format!(
        "=== {title} ===\n  Wall time:      {:.2}s\n  Useful unique events: {}\n  Downloader event frames: {}\n  Delivery efficiency: {:.1}%\n  Active source peers: {}\n",
        total_wall_secs,
        useful_unique_events,
        downloader_event_frames,
        delivery_efficiency * 100.0,
        active_sources,
    );
    for (label, timing) in ranges {
        summary.push_str(&format!(
            "  {:<12} {} msgs durable in {:.2}s projected in {:.2}s\n",
            label,
            timing.count,
            elapsed_secs(metric_start_ms, timing.first_stored_at_ms),
            elapsed_secs(metric_start_ms, timing.projected_at_ms),
        ));
    }
    summary.push_str("\n  Per-source downloader receives:\n");
    for (((source, sent), run_delta), obs_count) in sources
        .iter()
        .zip(source_event_frames.iter())
        .zip(source_sync_run_deltas.iter())
        .zip(endpoint_obs_counts.iter())
    {
        summary.push_str(&format!(
            "    {}: recv_frames={} changed_runs={} endpoint_obs={}\n",
            source.label, sent, run_delta, obs_count
        ));
    }
    if unattributed_event_frames > 0 {
        summary.push_str(&format!(
            "    [unattributed]: recv_frames={}\n",
            unattributed_event_frames
        ));
    }
    eprintln!("\n{summary}");
    write_summary(summary_key, &summary);
}

fn run_cold_join_bench(source_count: usize, connectivity: ConnectivityMode) -> BenchOutcome {
    assert!(source_count >= 2, "source_count must be >= 2");
    hold_network_test_lock_for_binary();
    std::env::set_var(
        "TOPO_GENERATE_MESSAGE_SPREAD_MS",
        THREE_YEARS_MS.to_string(),
    );
    std::env::set_var("TOPO_EVENT_TIMELINE", "1");
    std::env::set_var("TOPO_EVENT_TIMELINE_GROUPS", "persist,projection");

    let total_messages = env_i64("TOPO_MULTI_SOURCE_TOTAL_MESSAGES", 10_000);
    let tmpdir = bench_tmpdir("mscj-");
    let mut peer_labels = vec!["hub".to_string()];
    for idx in 1..source_count {
        peer_labels.push(format!("source-{idx:02}"));
    }
    let (sources, invite_link) = create_online_community(&tmpdir, &peer_labels, connectivity);
    let source_dbs: Vec<String> = sources.iter().map(|source| source.db.clone()).collect();

    let source_refs: Vec<&Node> = sources.iter().collect();
    generate_messages_distributed(&source_refs, total_messages);
    let source_expected_total = union_message_count_since_sql(&source_dbs, None);
    wait_for_message_count_all(
        &source_dbs,
        source_expected_total,
        Duration::from_secs(1200),
    );

    let measurement_now_ms = current_timestamp_ms();
    let day_cutoff = measurement_now_ms - DAY_MS;
    let week_cutoff = measurement_now_ms - WEEK_MS;
    let expected_total = union_message_count_since_sql(&source_dbs, None);
    let expected_day = union_message_count_since_sql(&source_dbs, Some(day_cutoff));
    let expected_week = union_message_count_since_sql(&source_dbs, Some(week_cutoff));
    let expected_twelve_weeks =
        union_message_count_since_sql(&source_dbs, Some(measurement_now_ms - TWELVE_WEEK_MS));
    let sink_db = tmpdir.path().join("sink.db").to_str().unwrap().to_string();
    enable_sync_logging(&sink_db);
    let inherited_env = inherited_tier_env();
    let mut sink_daemon = start_peer(&sink_db, inherited_env, connectivity);
    let sink_received_frames_before = received_events_by_peer_via_cli(&sink_db);
    let sink_recorded_sources_before = observed_events_by_source_peer_via_cli(&sink_db);
    let useful_unique_events_before = unique_sync_received_event_count_via_cli(&sink_db);
    let source_sync_runs_before: Vec<i64> = source_dbs
        .iter()
        .map(|db| changed_sync_run_count_via_cli(db))
        .collect();

    let metric_start_ms = current_timestamp_ms();
    let bench_start = Instant::now();
    accept_invite_with_identity_on_running_daemon(
        &sink_db,
        &invite_link,
        "sink",
        "laptop",
        Duration::from_secs(120),
    );

    let _day_projected_ms = if expected_day > 0 {
        wait_for_message_count_since(
            &sink_db,
            day_cutoff,
            expected_day,
            Duration::from_secs(1800),
        )
    } else {
        metric_start_ms
    };
    let _week_projected_ms = if expected_week > 0 {
        wait_for_message_count_since(
            &sink_db,
            week_cutoff,
            expected_week,
            Duration::from_secs(1800),
        )
    } else {
        metric_start_ms
    };
    let _twelve_week_projected_ms = if expected_twelve_weeks > 0 {
        wait_for_message_count_since(
            &sink_db,
            measurement_now_ms - TWELVE_WEEK_MS,
            expected_twelve_weeks,
            Duration::from_secs(1800),
        )
    } else {
        metric_start_ms
    };
    let full_projected_ms =
        wait_for_message_count(&sink_db, expected_total, Duration::from_secs(3600));
    let _ = full_projected_ms;

    let day_timing = range_timing_sql(&sink_db, Some(day_cutoff));
    let week_timing = range_timing_sql(&sink_db, Some(week_cutoff));
    let twelve_week_timing = range_timing_sql(&sink_db, Some(measurement_now_ms - TWELVE_WEEK_MS));
    let all_timing = range_timing_sql(&sink_db, None);

    wait_for_downloader_receives_stable(
        &sink_db,
        Duration::from_secs(60),
        Duration::from_millis(500),
    );
    let sink_received_frames_after = received_events_by_peer_via_cli(&sink_db);
    let sink_received_frame_deltas =
        diff_count_map(&sink_received_frames_after, &sink_received_frames_before);
    let source_event_frames: Vec<i64> = sources
        .iter()
        .map(|source| {
            sink_received_frame_deltas
                .get(&source.tenant_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let sink_recorded_sources_after = observed_events_by_source_peer_via_cli(&sink_db);
    let sink_recorded_source_deltas =
        diff_count_map(&sink_recorded_sources_after, &sink_recorded_sources_before);
    let source_recorded_events = count_source_tag_events(&sink_recorded_source_deltas, &sources);
    let source_sync_runs_after: Vec<i64> = source_dbs
        .iter()
        .map(|db| changed_sync_run_count_via_cli(db))
        .collect();
    let source_sync_run_deltas: Vec<i64> = source_sync_runs_after
        .iter()
        .zip(source_sync_runs_before.iter())
        .map(|(after, before)| after.saturating_sub(*before))
        .collect();
    let endpoint_obs_counts: Vec<i64> = sources
        .iter()
        .map(|source| endpoint_observation_count(&sink_db, &source.transport_peer_id))
        .collect();
    let downloader_event_frames: i64 = sink_received_frame_deltas.values().sum();
    let attributed_event_frames: i64 = source_event_frames.iter().sum();
    let unattributed_event_frames = downloader_event_frames.saturating_sub(attributed_event_frames);
    let useful_unique_events = unique_sync_received_event_count_via_cli(&sink_db)
        .saturating_sub(useful_unique_events_before);
    let delivery_efficiency = if downloader_event_frames > 0 {
        useful_unique_events as f64 / downloader_event_frames as f64
    } else {
        0.0
    };
    let active_sources = sink_received_frame_deltas
        .values()
        .filter(|count| **count > 0)
        .count();

    write_summary_with_sources(
        &format!(
            "daemon_multi_source_tiered_window_perf_test.cold_join_{}x_{}_{}",
            source_count,
            total_messages,
            connectivity.suffix()
        ),
        &format!(
            "Cold join multi-source tiered window catchup: {} sources, {} messages, {}",
            source_count,
            total_messages,
            connectivity.title()
        ),
        &[
            ("Last day", day_timing),
            ("Last week", week_timing),
            ("Last 12 weeks", twelve_week_timing),
            ("All", all_timing),
        ],
        metric_start_ms,
        bench_start.elapsed().as_secs_f64(),
        useful_unique_events,
        downloader_event_frames,
        delivery_efficiency,
        active_sources,
        unattributed_event_frames,
        &sources,
        &source_event_frames,
        &source_sync_run_deltas,
        &endpoint_obs_counts,
    );

    stop_daemon(&sink_db, &mut sink_daemon);
    wait_for_daemon_stopped(&sink_db, Duration::from_secs(10));

    BenchOutcome {
        useful_unique_events,
        downloader_event_frames,
        delivery_efficiency,
        source_recorded_events,
        active_sources,
    }
}

fn run_rejoin_bench(source_count: usize, connectivity: ConnectivityMode) -> BenchOutcome {
    assert!(source_count >= 2, "source_count must be >= 2");
    hold_network_test_lock_for_binary();
    std::env::set_var(
        "TOPO_GENERATE_MESSAGE_SPREAD_MS",
        THREE_YEARS_MS.to_string(),
    );
    std::env::set_var("TOPO_EVENT_TIMELINE", "1");
    std::env::set_var("TOPO_EVENT_TIMELINE_GROUPS", "persist,projection");

    let total_messages = env_i64("TOPO_MULTI_SOURCE_TOTAL_MESSAGES", 10_000);
    let baseline_messages = env_i64("TOPO_MULTI_SOURCE_BASELINE_MESSAGES", total_messages / 2);
    assert!(
        baseline_messages >= 0 && baseline_messages <= total_messages,
        "TOPO_MULTI_SOURCE_BASELINE_MESSAGES must satisfy 0 <= baseline <= total"
    );

    let tmpdir = bench_tmpdir("msrj-");
    let mut peer_labels = vec!["hub".to_string()];
    for idx in 1..source_count {
        peer_labels.push(format!("source-{idx:02}"));
    }
    peer_labels.push("rejoiner".to_string());

    let (mut nodes, _invite_link) = create_online_community(&tmpdir, &peer_labels, connectivity);
    let rejoiner = nodes.pop().expect("rejoiner node missing");
    assert_eq!(rejoiner.label, "rejoiner");
    let sources = nodes;
    let source_dbs: Vec<String> = sources.iter().map(|source| source.db.clone()).collect();
    let all_dbs: Vec<String> = sources
        .iter()
        .map(|source| source.db.clone())
        .chain(std::iter::once(rejoiner.db.clone()))
        .collect();

    let warmup_messages = emit_warmup_messages(&sources) + 1;
    let _ = send_message(&rejoiner.db, "warmup-rejoiner");
    wait_for_message_count_all_via_cli(&all_dbs, warmup_messages, Duration::from_secs(120));

    let all_nodes: Vec<&Node> = sources.iter().chain(std::iter::once(&rejoiner)).collect();
    if baseline_messages > 0 {
        generate_messages_distributed(&all_nodes, baseline_messages);
    }
    let baseline_expected_total = union_message_count_since_sql(&all_dbs, None);
    wait_for_message_count_all(&all_dbs, baseline_expected_total, Duration::from_secs(1200));

    let pre_rejoin_endpoint_obs: Vec<i64> = sources
        .iter()
        .map(|source| endpoint_observation_count(&rejoiner.db, &source.transport_peer_id))
        .collect();

    let mut rejoiner_daemon = rejoiner._daemon;
    stop_daemon(&rejoiner.db, &mut rejoiner_daemon);
    wait_for_daemon_stopped(&rejoiner.db, Duration::from_secs(10));

    let delta_messages = total_messages - baseline_messages;
    if delta_messages > 0 {
        let source_refs: Vec<&Node> = sources.iter().collect();
        generate_messages_distributed(&source_refs, delta_messages);
    }
    let source_expected_total = union_message_count_since_sql(&source_dbs, None);
    wait_for_message_count_all(
        &source_dbs,
        source_expected_total,
        Duration::from_secs(1200),
    );

    let measurement_now_ms = current_timestamp_ms();
    let day_cutoff = measurement_now_ms - DAY_MS;
    let week_cutoff = measurement_now_ms - WEEK_MS;
    let expected_total = union_message_count_since_sql(&source_dbs, None);
    let expected_day = union_message_count_since_sql(&source_dbs, Some(day_cutoff));
    let expected_week = union_message_count_since_sql(&source_dbs, Some(week_cutoff));
    let expected_twelve_weeks =
        union_message_count_since_sql(&source_dbs, Some(measurement_now_ms - TWELVE_WEEK_MS));
    let useful_unique_events_before = unique_sync_received_event_count_via_cli(&rejoiner.db);
    let rejoiner_received_frames_before = received_events_by_peer_via_cli(&rejoiner.db);
    let rejoiner_recorded_sources_before = observed_events_by_source_peer_via_cli(&rejoiner.db);
    let source_sync_runs_before: Vec<i64> = source_dbs
        .iter()
        .map(|db| changed_sync_run_count_via_cli(db))
        .collect();

    let metric_start_ms = current_timestamp_ms();
    let bench_start = Instant::now();
    let inherited_env = inherited_tier_env();
    let _rejoiner_daemon = start_peer(&rejoiner.db, inherited_env, connectivity);
    ensure_active_peer(&rejoiner.db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&rejoiner.db, Duration::from_secs(120));

    let _day_projected_ms = if expected_day > 0 {
        wait_for_message_count_since(
            &rejoiner.db,
            day_cutoff,
            expected_day,
            Duration::from_secs(1800),
        )
    } else {
        metric_start_ms
    };
    let _week_projected_ms = if expected_week > 0 {
        wait_for_message_count_since(
            &rejoiner.db,
            week_cutoff,
            expected_week,
            Duration::from_secs(1800),
        )
    } else {
        metric_start_ms
    };
    let _twelve_week_projected_ms = if expected_twelve_weeks > 0 {
        wait_for_message_count_since(
            &rejoiner.db,
            measurement_now_ms - TWELVE_WEEK_MS,
            expected_twelve_weeks,
            Duration::from_secs(1800),
        )
    } else {
        metric_start_ms
    };
    let full_projected_ms =
        wait_for_message_count(&rejoiner.db, expected_total, Duration::from_secs(3600));
    let _ = full_projected_ms;

    let day_timing = range_timing_sql(&rejoiner.db, Some(day_cutoff));
    let week_timing = range_timing_sql(&rejoiner.db, Some(week_cutoff));
    let twelve_week_timing =
        range_timing_sql(&rejoiner.db, Some(measurement_now_ms - TWELVE_WEEK_MS));
    let all_timing = range_timing_sql(&rejoiner.db, None);

    wait_for_downloader_receives_stable(
        &rejoiner.db,
        Duration::from_secs(60),
        Duration::from_millis(500),
    );
    let rejoiner_received_frames_after = received_events_by_peer_via_cli(&rejoiner.db);
    let rejoiner_received_frame_deltas = diff_count_map(
        &rejoiner_received_frames_after,
        &rejoiner_received_frames_before,
    );
    let source_event_frames: Vec<i64> = sources
        .iter()
        .map(|source| {
            rejoiner_received_frame_deltas
                .get(&source.tenant_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let rejoiner_recorded_sources_after = observed_events_by_source_peer_via_cli(&rejoiner.db);
    let rejoiner_recorded_source_deltas = diff_count_map(
        &rejoiner_recorded_sources_after,
        &rejoiner_recorded_sources_before,
    );
    let source_recorded_events =
        count_source_tag_events(&rejoiner_recorded_source_deltas, &sources);
    let source_sync_runs_after: Vec<i64> = source_dbs
        .iter()
        .map(|db| changed_sync_run_count_via_cli(db))
        .collect();
    let source_sync_run_deltas: Vec<i64> = source_sync_runs_after
        .iter()
        .zip(source_sync_runs_before.iter())
        .map(|(after, before)| after.saturating_sub(*before))
        .collect();
    let endpoint_obs_after: Vec<i64> = sources
        .iter()
        .map(|source| endpoint_observation_count(&rejoiner.db, &source.transport_peer_id))
        .collect();
    let endpoint_obs_counts: Vec<i64> = endpoint_obs_after
        .iter()
        .zip(pre_rejoin_endpoint_obs.iter())
        .map(|(after, before)| after.saturating_sub(*before).max(*after))
        .collect();
    let downloader_event_frames: i64 = rejoiner_received_frame_deltas.values().sum();
    let attributed_event_frames: i64 = source_event_frames.iter().sum();
    let unattributed_event_frames = downloader_event_frames.saturating_sub(attributed_event_frames);
    let useful_unique_events_after = unique_sync_received_event_count_via_cli(&rejoiner.db);
    let useful_unique_events =
        useful_unique_events_after.saturating_sub(useful_unique_events_before);
    let delivery_efficiency = if downloader_event_frames > 0 {
        useful_unique_events as f64 / downloader_event_frames as f64
    } else {
        0.0
    };
    let active_sources = rejoiner_received_frame_deltas
        .values()
        .filter(|count| **count > 0)
        .count();

    write_summary_with_sources(
        &format!(
            "daemon_multi_source_tiered_window_perf_test.rejoin_{}x_{}_{}",
            source_count,
            total_messages,
            connectivity.suffix()
        ),
        &format!(
            "Rejoin multi-source tiered window catchup: {} sources, baseline {}, total {}, {}",
            source_count,
            baseline_messages,
            total_messages,
            connectivity.title()
        ),
        &[
            ("Last day", day_timing),
            ("Last week", week_timing),
            ("Last 12 weeks", twelve_week_timing),
            ("All", all_timing),
        ],
        metric_start_ms,
        bench_start.elapsed().as_secs_f64(),
        useful_unique_events,
        downloader_event_frames,
        delivery_efficiency,
        active_sources,
        unattributed_event_frames,
        &sources,
        &source_event_frames,
        &source_sync_run_deltas,
        &endpoint_obs_counts,
    );

    BenchOutcome {
        useful_unique_events,
        downloader_event_frames,
        delivery_efficiency,
        source_recorded_events,
        active_sources,
    }
}

fn run_replicated_rejoin_bench(
    source_count: usize,
    connectivity: ConnectivityMode,
) -> ReplicatedRejoinOutcome {
    assert!(source_count >= 1, "source_count must be >= 1");
    hold_network_test_lock_for_binary();
    std::env::set_var("TOPO_GENERATE_MESSAGE_SPREAD_MS", HOUR_MS.to_string());
    std::env::set_var("TOPO_EVENT_TIMELINE", "1");
    std::env::set_var("TOPO_EVENT_TIMELINE_GROUPS", "persist,projection");
    std::env::set_var("TOPO_ENABLE_LIVE_SUPPRESSION", "1");

    let total_messages = env_i64("TOPO_MULTI_SOURCE_COMPARE_TOTAL_MESSAGES", 1_000);
    let tmpdir = bench_tmpdir("msrr-");
    let mut peer_labels = vec!["hub".to_string()];
    for idx in 1..source_count {
        peer_labels.push(format!("source-{idx:02}"));
    }
    peer_labels.push("rejoiner".to_string());

    let (mut nodes, _invite_link) = create_online_community(&tmpdir, &peer_labels, connectivity);
    let rejoiner = nodes.pop().expect("rejoiner node missing");
    assert_eq!(rejoiner.label, "rejoiner");
    let sources = nodes;
    let all_node_views: Vec<NodeView> = sources
        .iter()
        .map(NodeView::from)
        .chain(std::iter::once(NodeView::from(&rejoiner)))
        .collect();
    let source_dbs: Vec<String> = sources.iter().map(|source| source.db.clone()).collect();
    let all_dbs: Vec<String> = sources
        .iter()
        .map(|source| source.db.clone())
        .chain(std::iter::once(rejoiner.db.clone()))
        .collect();

    assert_full_mesh_connectivity_basics(&all_node_views, Duration::from_secs(120));
    let live_probe_messages =
        assert_full_mesh_live_message_delivery(&all_node_views, Duration::from_secs(120));

    let warmup_messages = live_probe_messages + emit_warmup_messages(&sources) + 1;
    let rejoiner_warmup_id = send_message(&rejoiner.db, "warmup-rejoiner");
    if std::env::var_os("TOPO_TRACE_WARMUP_EVENTS").is_some() {
        eprintln!(
            "warmup event: origin={} label=warmup-rejoiner event_id={}",
            rejoiner.label, rejoiner_warmup_id
        );
    }
    wait_for_message_count_all_via_cli_without_sync_kicks(
        &all_dbs,
        warmup_messages,
        Duration::from_secs(120),
    );

    let mut rejoiner_daemon = rejoiner._daemon;
    stop_daemon(&rejoiner.db, &mut rejoiner_daemon);
    wait_for_daemon_stopped(&rejoiner.db, Duration::from_secs(10));

    generate_messages_replicated(&sources, total_messages);
    let expected_source_total = total_messages + warmup_messages;
    wait_for_message_count_all_via_cli_without_sync_kicks(
        &source_dbs,
        expected_source_total,
        Duration::from_secs(1200),
    );

    let rejoiner_received_frames_before: Vec<i64> = sources
        .iter()
        .map(|source| sync_events_received_for_peer_via_cli(&rejoiner.db, &source.tenant_peer_id))
        .collect();
    let inherited_env = inherited_tier_env();
    let catchup_start = Instant::now();
    rejoiner_daemon = start_peer(&rejoiner.db, inherited_env, connectivity);
    ensure_active_peer(&rejoiner.db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&rejoiner.db, Duration::from_secs(120));
    assert_full_mesh_connectivity_basics(&all_node_views, Duration::from_secs(120));
    let _ = wait_for_message_count_via_cli_without_sync_kicks(
        &rejoiner.db,
        expected_source_total,
        Duration::from_secs(1800),
    );
    let catchup_wall_secs = catchup_start.elapsed().as_secs_f64();
    let source_event_frames = wait_for_source_sync_event_frame_deltas_via_cli(
        &rejoiner.db,
        &sources,
        &rejoiner_received_frames_before,
        total_messages,
        Duration::from_secs(60),
        Duration::from_millis(500),
    );
    let active_sources = source_event_frames
        .iter()
        .filter(|count| **count > 0)
        .count();
    let downloader_event_frames: i64 = source_event_frames.iter().sum();
    let delivery_efficiency = if downloader_event_frames > 0 {
        total_messages as f64 / downloader_event_frames as f64
    } else {
        0.0
    };
    let messages_per_second = total_messages as f64 / catchup_wall_secs.max(f64::EPSILON);

    eprintln!(
        "\nreplicated rejoin {}: projected_delta_messages={} catchup_wall={:.2}s messages_per_second={:.1} active_sources={} downloader_event_frames={} delivery_efficiency={:.1}% sync_log_rx_by_source={:?}",
        connectivity.title(),
        total_messages,
        catchup_wall_secs,
        messages_per_second,
        active_sources,
        downloader_event_frames,
        delivery_efficiency * 100.0,
        source_event_frames,
    );
    stop_daemon(&rejoiner.db, &mut rejoiner_daemon);
    wait_for_daemon_stopped(&rejoiner.db, Duration::from_secs(10));

    ReplicatedRejoinOutcome {
        projected_delta_messages: total_messages,
        active_sources,
        source_event_frames,
        downloader_event_frames,
        delivery_efficiency,
        catchup_wall_secs,
        messages_per_second,
    }
}

#[test]
#[ignore]
fn perf_multi_source_cold_join_4x_10k() {
    let _ = run_cold_join_bench(4, ConnectivityMode::BootstrapOnly);
}

#[test]
#[ignore]
fn perf_multi_source_cold_join_8x_10k() {
    let _ = run_cold_join_bench(8, ConnectivityMode::BootstrapOnly);
}

#[test]
#[ignore]
fn perf_multi_source_rejoin_4x_10k() {
    let _ = run_rejoin_bench(4, ConnectivityMode::BootstrapOnly);
}

#[test]
#[ignore]
fn perf_multi_source_rejoin_8x_10k() {
    let _ = run_rejoin_bench(8, ConnectivityMode::BootstrapOnly);
}

#[test]
#[ignore]
fn perf_multi_source_cold_join_4x_10k_discovery() {
    let _ = run_cold_join_bench(4, ConnectivityMode::DiscoveryLoopback);
}

#[test]
#[ignore]
fn perf_multi_source_cold_join_8x_10k_discovery() {
    let _ = run_cold_join_bench(8, ConnectivityMode::DiscoveryLoopback);
}

#[test]
#[ignore]
fn perf_multi_source_rejoin_4x_10k_discovery() {
    let _ = run_rejoin_bench(4, ConnectivityMode::DiscoveryLoopback);
}

#[test]
#[ignore]
fn perf_multi_source_rejoin_8x_10k_discovery() {
    let _ = run_rejoin_bench(8, ConnectivityMode::DiscoveryLoopback);
}

#[test]
fn replicated_rejoin_2x_1k_live_suppression_basic_rejoin_connectivity_holds() {
    std::env::set_var("TOPO_MULTI_SOURCE_COMPARE_TOTAL_MESSAGES", "1000");
    let outcome = run_replicated_rejoin_bench(2, ConnectivityMode::DiscoveryLoopback);
    assert!(
        outcome.projected_delta_messages > 0,
        "expected replicated rejoin setup to catch up at least one source"
    );
}

#[test]
#[ignore = "long-running multi-source rejoin proof"]
fn replicated_rejoin_2x_1k_live_suppression_uses_multiple_sources_after_preconvergence() {
    std::env::set_var("TOPO_MULTI_SOURCE_COMPARE_TOTAL_MESSAGES", "1000");
    let outcome = run_replicated_rejoin_bench(2, ConnectivityMode::DiscoveryLoopback);
    assert!(
        outcome.active_sources >= 2,
        "expected both known replicated sources to contribute after rejoin, got active_sources={} sync_log_rx={:?}",
        outcome.active_sources,
        outcome.source_event_frames,
    );
    assert!(
        outcome.projected_delta_messages > 0,
        "expected the rejoiner to ingest replicated events"
    );
}

#[test]
#[ignore = "long-running multi-source rejoin proof"]
fn replicated_rejoin_2x_10k_live_suppression_uses_multiple_sources_after_preconvergence() {
    std::env::set_var("TOPO_MULTI_SOURCE_COMPARE_TOTAL_MESSAGES", "10000");
    let outcome = run_replicated_rejoin_bench(2, ConnectivityMode::DiscoveryLoopback);
    assert!(
        outcome.active_sources >= 2,
        "expected both known replicated sources to contribute after rejoin, got active_sources={} sync_log_rx={:?}",
        outcome.active_sources,
        outcome.source_event_frames,
    );
    assert!(
        outcome.projected_delta_messages > 0,
        "expected the rejoiner to ingest replicated events"
    );
}

#[test]
#[ignore = "env-driven replicated rejoin perf comparison"]
fn replicated_rejoin_live_suppression_compare_from_env() {
    let source_count = env_usize("TOPO_MULTI_SOURCE_COMPARE_SOURCE_COUNT", 2);
    let outcome = run_replicated_rejoin_bench(source_count, ConnectivityMode::DiscoveryLoopback);
    assert!(
        outcome.projected_delta_messages > 0,
        "expected the rejoiner to ingest replicated events"
    );
    assert!(
        outcome.active_sources >= 1,
        "expected at least one source to contribute, got active_sources={} sync_log_rx={:?}",
        outcome.active_sources,
        outcome.source_event_frames,
    );
}

#[test]
#[ignore = "fresh invitees only know the inviter until discovery warms enough to expose the full peer set"]
fn cold_join_4x_1k_uses_multiple_sources_efficiently() {
    std::env::set_var("TOPO_MULTI_SOURCE_TOTAL_MESSAGES", "1000");
    let outcome = run_cold_join_bench(4, ConnectivityMode::DiscoveryLoopback);

    assert!(
        outcome
            .source_recorded_events
            .iter()
            .filter(|count| **count > 0)
            .count()
            >= 2,
        "expected at least 2 peers to contribute recorded events, got {:?}",
        outcome.source_recorded_events
    );
}

#[test]
#[ignore = "graph harness provides the stable multi-source proof; daemon rejoin remains diagnostic while discovery/bootstrap convergence is still noisy"]
fn rejoin_4x_1k_uses_multiple_sources_after_preconvergence() {
    std::env::set_var("TOPO_MULTI_SOURCE_TOTAL_MESSAGES", "1000");
    std::env::set_var("TOPO_MULTI_SOURCE_BASELINE_MESSAGES", "500");
    let outcome = run_rejoin_bench(4, ConnectivityMode::DiscoveryLoopback);

    assert!(
        outcome.active_sources >= 2,
        "expected at least 2 peers to contribute after rejoin, got active_sources={} counts={:?}",
        outcome.active_sources,
        outcome.source_recorded_events
    );
    assert!(
        outcome.useful_unique_events > 0,
        "expected rejoiner to ingest new events during rejoin"
    );
}

#[test]
fn downloader_receive_metric_counts_events_by_remote_peer() {
    use topo::db::schema::create_tables;

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let db_path = tmpdir.path().join("metric.db");
    let db_path_str = db_path.to_str().expect("db path utf-8");
    let conn = topo::db::open_connection(db_path_str).expect("open db");
    create_tables(&conn).expect("create schema");

    conn.execute(
        "INSERT INTO sync_runs
         (run_id, started_at_ms, ended_at_ms, session_id, tenant_id, peer_id, direction, remote_addr, role,
          rounds, events_sent, events_received, bytes_sent, bytes_received, changed, outcome, error)
         VALUES
         (1, 1, 2, 1, 'tenant', 'sink-peer', 'outbound', '127.0.0.1:1', 'initiator', 1, 2, 2, 20, 20, 1, 'ok', NULL),
         (2, 3, 4, 2, 'tenant', 'other-peer', 'outbound', '127.0.0.1:2', 'initiator', 1, 3, 3, 30, 30, 1, 'ok', NULL)",
        [],
    )
    .expect("insert sync_runs");

    let from_json = sync_log_receive_counts_by_peer(&sync_log_json(db_path_str, 100));
    let from_cli = received_events_by_peer_via_cli(db_path_str);

    assert_eq!(from_json.get("sink-peer").copied(), Some(2));
    assert_eq!(from_json.get("other-peer").copied(), Some(3));
    assert_eq!(from_cli.get("sink-peer").copied(), Some(2));
    assert_eq!(from_cli.get("other-peer").copied(), Some(3));
}
