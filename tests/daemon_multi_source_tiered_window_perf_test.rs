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
    accept_invite_with_identity_on_running_daemon, create_workspace_with_details,
    daemon_listen_addr, daemon_transport_fingerprint, ensure_active_peer, generate_messages,
    hold_network_test_lock_for_binary, metrics_json, send_message, start_daemon_with_options,
    stop_daemon, topo_assert_eventually, topo_cmd, topo_create_invite_retry,
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

#[derive(Debug)]
struct ReplicatedJoinOutcome {
    total_messages: i64,
    total_wall_secs: f64,
    durable_msgs_per_sec: f64,
    projected_msgs_per_sec: f64,
    useful_unique_events: i64,
    downloader_event_frames: i64,
    delivery_efficiency: f64,
    active_sources: usize,
    source_labels: Vec<String>,
    source_event_frames: Vec<i64>,
    source_recorded_events: Vec<i64>,
}

#[derive(Debug)]
struct ReplicatedRejoinOutcome {
    useful_unique_events: i64,
    active_sources: usize,
    source_event_frames: Vec<i64>,
    source_recorded_events: Vec<i64>,
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

fn inherited_tier_env() -> Vec<(String, String)> {
    [
        "TOPO_GENERATE_MESSAGE_SPREAD_MS",
        "TOPO_EVENT_TIMELINE",
        "TOPO_EVENT_TIMELINE_GROUPS",
        "TOPO_ENABLE_LIVE_SUPPRESSION",
        "TOPO_LIVE_SUPPRESSION_EVENT_ID_CAP",
        "TOPO_LIVE_SUPPRESSION_SEND_BATCH_SIZE",
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
}

fn bench_tmpdir(label: &str) -> tempfile::TempDir {
    let root = std::env::var_os("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/home/holmes/p7tmp"));
    std::fs::create_dir_all(&root).expect("create benchmark tmp root");
    tempfile::Builder::new()
        .prefix(label)
        .tempdir_in(root)
        .expect("create benchmark tempdir")
}

fn metrics_snapshot(
    db: &str,
    since_ms: Option<i64>,
    message_created_after_ms: Option<i64>,
    include_message_ids: bool,
) -> serde_json::Value {
    metrics_json(db, since_ms, message_created_after_ms, include_message_ids)
}

fn message_ids_since_cli(db: &str, cutoff_ms: Option<i64>) -> BTreeSet<String> {
    metrics_snapshot(db, None, cutoff_ms, true)["message_ids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_str().map(|value| value.to_string()))
        .collect()
}

fn union_message_count_since_cli(dbs: &[String], cutoff_ms: Option<i64>) -> i64 {
    let mut message_ids = BTreeSet::new();
    for db in dbs {
        message_ids.extend(message_ids_since_cli(db, cutoff_ms));
    }
    message_ids.len() as i64
}

fn range_timing_cli(db: &str, min_created_at_ms: Option<i64>) -> RangeTiming {
    let range = &metrics_snapshot(db, None, min_created_at_ms, false)["message_range"];
    RangeTiming {
        count: range["count"].as_i64().unwrap_or_default(),
        first_stored_at_ms: range["first_stored_at_ms"].as_i64(),
        projected_at_ms: range["projected_at_ms"].as_i64(),
    }
}

fn count_map_from_metrics_array(value: &serde_json::Value, field: &str) -> HashMap<String, i64> {
    value[field]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|item| {
            Some((
                item["peer_id"].as_str()?.to_string(),
                item["count"].as_i64().unwrap_or_default(),
            ))
        })
        .collect()
}

fn elapsed_secs(metric_start_ms: i64, ts_ms: Option<i64>) -> f64 {
    ts_ms
        .unwrap_or(metric_start_ms)
        .saturating_sub(metric_start_ms) as f64
        / 1000.0
}

fn messages_per_sec(count: i64, elapsed_secs: f64) -> f64 {
    if count <= 0 {
        0.0
    } else if elapsed_secs <= f64::EPSILON {
        count as f64
    } else {
        count as f64 / elapsed_secs
    }
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

fn wait_for_message_count(db: &str, expected: i64, timeout: Duration) -> i64 {
    wait_for_predicate_with_sync_kicks(
        &[db.to_string()],
        &format!("message_count >= {}", expected),
        timeout,
    );
    current_timestamp_ms()
}

fn wait_for_message_count_since(db: &str, cutoff_ms: i64, expected: i64, timeout: Duration) -> i64 {
    wait_for_predicate_with_sync_kicks(
        &[db.to_string()],
        &format!("message_count_since:{} >= {}", cutoff_ms, expected),
        timeout,
    );
    current_timestamp_ms()
}

fn wait_for_message_count_all(dbs: &[String], expected: i64, timeout: Duration) {
    wait_for_predicate_with_sync_kicks(dbs, &format!("message_count >= {}", expected), timeout);
}

fn received_events_by_peer_since_cli(db: &str, since_ms: i64) -> HashMap<String, i64> {
    let metrics = metrics_snapshot(db, Some(since_ms), None, false);
    count_map_from_metrics_array(&metrics, "received_event_frames_by_peer")
}

fn recorded_events_by_transport_peer_since_cli(db: &str, since_ms: i64) -> HashMap<String, i64> {
    let metrics = metrics_snapshot(db, Some(since_ms), None, false);
    count_map_from_metrics_array(&metrics, "recorded_events_by_transport_peer")
}

fn changed_sync_run_count_since_cli(db: &str, since_ms: i64) -> i64 {
    metrics_snapshot(db, Some(since_ms), None, false)["changed_sync_run_count"]
        .as_i64()
        .unwrap_or_default()
}

fn live_endpoint_observation_count_by_peer_cli(db: &str) -> HashMap<String, i64> {
    let metrics = metrics_snapshot(db, None, None, false);
    count_map_from_metrics_array(&metrics, "live_endpoint_observations_by_peer")
}

fn unique_sync_received_event_count_since_cli(db: &str, since_ms: i64) -> i64 {
    metrics_snapshot(db, Some(since_ms), None, false)["unique_sync_received_event_count"]
        .as_i64()
        .unwrap_or_default()
}

fn wait_for_downloader_receives_stable(
    db: &str,
    since_ms: i64,
    timeout: Duration,
    stable_for: Duration,
) {
    let start = Instant::now();
    let mut last = metrics_snapshot(db, Some(since_ms), None, false)["received_event_frames_total"]
        .as_i64()
        .unwrap_or_default();
    let mut stable_since = None;
    loop {
        let current = metrics_snapshot(db, Some(since_ms), None, false)
            ["received_event_frames_total"]
            .as_i64()
            .unwrap_or_default();
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

struct Node {
    label: String,
    db: String,
    _daemon: HarnessDaemon,
    transport_peer_id: String,
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
            transport_peer_id: daemon_transport_fingerprint(&db),
        });
    }

    (nodes, invite_link)
}

fn emit_warmup_messages(nodes: &[Node]) -> i64 {
    for node in nodes {
        let _ = send_message(&node.db, &format!("warmup-{}", node.label));
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
    source_recorded_events: &[i64],
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
        let durable_secs = elapsed_secs(metric_start_ms, timing.first_stored_at_ms);
        let projected_secs = elapsed_secs(metric_start_ms, timing.projected_at_ms);
        summary.push_str(&format!(
            "  {:<12} {} msgs durable in {:.2}s ({:.1} msg/s) projected in {:.2}s ({:.1} msg/s)\n",
            label,
            timing.count,
            durable_secs,
            messages_per_sec(timing.count, durable_secs),
            projected_secs,
            messages_per_sec(timing.count, projected_secs),
        ));
    }
    summary.push_str("\n  Per-source downloader receives:\n");
    for ((((source, sent), recorded), run_delta), obs_count) in sources
        .iter()
        .zip(source_event_frames.iter())
        .zip(source_recorded_events.iter())
        .zip(source_sync_run_deltas.iter())
        .zip(endpoint_obs_counts.iter())
    {
        summary.push_str(&format!(
            "    {}: recv_frames={} durable_attributed={} changed_runs={} endpoint_obs={}\n",
            source.label, sent, recorded, run_delta, obs_count
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
    let source_expected_total = union_message_count_since_cli(&source_dbs, None);
    wait_for_message_count_all(
        &source_dbs,
        source_expected_total,
        Duration::from_secs(1200),
    );

    let measurement_now_ms = current_timestamp_ms();
    let day_cutoff = measurement_now_ms - DAY_MS;
    let week_cutoff = measurement_now_ms - WEEK_MS;
    let expected_total = union_message_count_since_cli(&source_dbs, None);
    let expected_day = union_message_count_since_cli(&source_dbs, Some(day_cutoff));
    let expected_week = union_message_count_since_cli(&source_dbs, Some(week_cutoff));
    let expected_twelve_weeks =
        union_message_count_since_cli(&source_dbs, Some(measurement_now_ms - TWELVE_WEEK_MS));
    let sink_db = tmpdir.path().join("sink.db").to_str().unwrap().to_string();
    enable_sync_logging(&sink_db);
    let inherited_env = inherited_tier_env();
    let mut sink_daemon = start_peer(&sink_db, inherited_env, connectivity);

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

    let day_timing = range_timing_cli(&sink_db, Some(day_cutoff));
    let week_timing = range_timing_cli(&sink_db, Some(week_cutoff));
    let twelve_week_timing = range_timing_cli(&sink_db, Some(measurement_now_ms - TWELVE_WEEK_MS));
    let all_timing = range_timing_cli(&sink_db, None);

    wait_for_downloader_receives_stable(
        &sink_db,
        metric_start_ms,
        Duration::from_secs(60),
        Duration::from_millis(500),
    );
    let sink_received_frame_deltas = received_events_by_peer_since_cli(&sink_db, metric_start_ms);
    let source_event_frames: Vec<i64> = sources
        .iter()
        .map(|source| {
            sink_received_frame_deltas
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let sink_recorded_source_deltas =
        recorded_events_by_transport_peer_since_cli(&sink_db, metric_start_ms);
    let source_recorded_events: Vec<i64> = sources
        .iter()
        .map(|source| {
            sink_recorded_source_deltas
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let source_sync_run_deltas: Vec<i64> = source_dbs
        .iter()
        .map(|db| changed_sync_run_count_since_cli(db, metric_start_ms))
        .collect();
    let sink_endpoint_obs = live_endpoint_observation_count_by_peer_cli(&sink_db);
    let endpoint_obs_counts: Vec<i64> = sources
        .iter()
        .map(|source| {
            sink_endpoint_obs
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let downloader_event_frames: i64 = sink_received_frame_deltas.values().sum();
    let attributed_event_frames: i64 = source_event_frames.iter().sum();
    let unattributed_event_frames = downloader_event_frames.saturating_sub(attributed_event_frames);
    let useful_unique_events =
        unique_sync_received_event_count_since_cli(&sink_db, metric_start_ms);
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
        &source_recorded_events,
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
    wait_for_message_count_all(&all_dbs, warmup_messages, Duration::from_secs(120));

    let all_nodes: Vec<&Node> = sources.iter().chain(std::iter::once(&rejoiner)).collect();
    if baseline_messages > 0 {
        generate_messages_distributed(&all_nodes, baseline_messages);
    }
    let baseline_expected_total = union_message_count_since_cli(&all_dbs, None);
    wait_for_message_count_all(&all_dbs, baseline_expected_total, Duration::from_secs(1200));

    let mut rejoiner_daemon = rejoiner._daemon;
    stop_daemon(&rejoiner.db, &mut rejoiner_daemon);
    wait_for_daemon_stopped(&rejoiner.db, Duration::from_secs(10));

    let delta_messages = total_messages - baseline_messages;
    if delta_messages > 0 {
        let source_refs: Vec<&Node> = sources.iter().collect();
        generate_messages_distributed(&source_refs, delta_messages);
    }
    let source_expected_total = union_message_count_since_cli(&source_dbs, None);
    wait_for_message_count_all(
        &source_dbs,
        source_expected_total,
        Duration::from_secs(1200),
    );

    let measurement_now_ms = current_timestamp_ms();
    let day_cutoff = measurement_now_ms - DAY_MS;
    let week_cutoff = measurement_now_ms - WEEK_MS;
    let expected_total = union_message_count_since_cli(&source_dbs, None);
    let expected_day = union_message_count_since_cli(&source_dbs, Some(day_cutoff));
    let expected_week = union_message_count_since_cli(&source_dbs, Some(week_cutoff));
    let expected_twelve_weeks =
        union_message_count_since_cli(&source_dbs, Some(measurement_now_ms - TWELVE_WEEK_MS));

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

    let day_timing = range_timing_cli(&rejoiner.db, Some(day_cutoff));
    let week_timing = range_timing_cli(&rejoiner.db, Some(week_cutoff));
    let twelve_week_timing =
        range_timing_cli(&rejoiner.db, Some(measurement_now_ms - TWELVE_WEEK_MS));
    let all_timing = range_timing_cli(&rejoiner.db, None);

    wait_for_downloader_receives_stable(
        &rejoiner.db,
        metric_start_ms,
        Duration::from_secs(60),
        Duration::from_millis(500),
    );
    let rejoiner_received_frame_deltas =
        received_events_by_peer_since_cli(&rejoiner.db, metric_start_ms);
    let source_event_frames: Vec<i64> = sources
        .iter()
        .map(|source| {
            rejoiner_received_frame_deltas
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let rejoiner_recorded_source_deltas =
        recorded_events_by_transport_peer_since_cli(&rejoiner.db, metric_start_ms);
    let source_recorded_events: Vec<i64> = sources
        .iter()
        .map(|source| {
            rejoiner_recorded_source_deltas
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let source_sync_run_deltas: Vec<i64> = source_dbs
        .iter()
        .map(|db| changed_sync_run_count_since_cli(db, metric_start_ms))
        .collect();
    let rejoiner_endpoint_obs = live_endpoint_observation_count_by_peer_cli(&rejoiner.db);
    let endpoint_obs_counts: Vec<i64> = sources
        .iter()
        .map(|source| {
            rejoiner_endpoint_obs
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let downloader_event_frames: i64 = rejoiner_received_frame_deltas.values().sum();
    let attributed_event_frames: i64 = source_event_frames.iter().sum();
    let unattributed_event_frames = downloader_event_frames.saturating_sub(attributed_event_frames);
    let useful_unique_events =
        unique_sync_received_event_count_since_cli(&rejoiner.db, metric_start_ms);
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
        &source_recorded_events,
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

fn run_replicated_cold_join_bench(
    source_count: usize,
    connectivity: ConnectivityMode,
) -> ReplicatedJoinOutcome {
    assert!(source_count >= 1, "source_count must be >= 1");
    hold_network_test_lock_for_binary();
    std::env::set_var("TOPO_GENERATE_MESSAGE_SPREAD_MS", HOUR_MS.to_string());
    std::env::set_var("TOPO_EVENT_TIMELINE", "1");
    std::env::set_var("TOPO_EVENT_TIMELINE_GROUPS", "persist,projection");
    std::env::set_var("TOPO_ENABLE_LIVE_SUPPRESSION", "1");

    let total_messages = env_i64("TOPO_MULTI_SOURCE_COMPARE_TOTAL_MESSAGES", 10_000);
    let tmpdir = bench_tmpdir("mscmp-");
    let mut peer_labels = vec!["hub".to_string()];
    for idx in 1..source_count {
        peer_labels.push(format!("source-{idx:02}"));
    }
    let (sources, invite_link) = create_online_community(&tmpdir, &peer_labels, connectivity);
    let source_dbs: Vec<String> = sources.iter().map(|source| source.db.clone()).collect();

    generate_messages_replicated(&sources, total_messages);
    wait_for_message_count_all(&source_dbs, total_messages, Duration::from_secs(1200));

    let expected_total = union_message_count_since_cli(&source_dbs, None);
    let sink_db = tmpdir.path().join("sink.db").to_str().unwrap().to_string();
    enable_sync_logging(&sink_db);
    let inherited_env = inherited_tier_env();
    let mut sink_daemon = start_peer(&sink_db, inherited_env, connectivity);

    let metric_start_ms = current_timestamp_ms();
    let bench_start = Instant::now();
    accept_invite_with_identity_on_running_daemon(
        &sink_db,
        &invite_link,
        "sink",
        "laptop",
        Duration::from_secs(120),
    );
    let full_projected_ms =
        wait_for_message_count(&sink_db, expected_total, Duration::from_secs(3600));
    let all_timing = range_timing_cli(&sink_db, None);

    wait_for_downloader_receives_stable(
        &sink_db,
        metric_start_ms,
        Duration::from_secs(60),
        Duration::from_millis(500),
    );
    let sink_received_frame_deltas = received_events_by_peer_since_cli(&sink_db, metric_start_ms);
    let source_event_frames: Vec<i64> = sources
        .iter()
        .map(|source| {
            sink_received_frame_deltas
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let sink_recorded_source_deltas =
        recorded_events_by_transport_peer_since_cli(&sink_db, metric_start_ms);
    let source_recorded_events: Vec<i64> = sources
        .iter()
        .map(|source| {
            sink_recorded_source_deltas
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let source_sync_run_deltas: Vec<i64> = source_dbs
        .iter()
        .map(|db| changed_sync_run_count_since_cli(db, metric_start_ms))
        .collect();
    let sink_endpoint_obs = live_endpoint_observation_count_by_peer_cli(&sink_db);
    let endpoint_obs_counts: Vec<i64> = sources
        .iter()
        .map(|source| {
            sink_endpoint_obs
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let downloader_event_frames: i64 = sink_received_frame_deltas.values().sum();
    let attributed_event_frames: i64 = source_event_frames.iter().sum();
    let unattributed_event_frames = downloader_event_frames.saturating_sub(attributed_event_frames);
    let useful_unique_events =
        unique_sync_received_event_count_since_cli(&sink_db, metric_start_ms);
    let delivery_efficiency = if downloader_event_frames > 0 {
        useful_unique_events as f64 / downloader_event_frames as f64
    } else {
        0.0
    };
    let active_sources = sink_received_frame_deltas
        .values()
        .filter(|count| **count > 0)
        .count();
    let projected_at_ms = all_timing.projected_at_ms.or(Some(full_projected_ms));
    let durable_secs = elapsed_secs(metric_start_ms, all_timing.first_stored_at_ms);
    let projected_secs = elapsed_secs(metric_start_ms, projected_at_ms);

    write_summary_with_sources(
        &format!(
            "daemon_multi_source_tiered_window_perf_test.replicated_join_{}x_{}_{}",
            source_count,
            total_messages,
            connectivity.suffix()
        ),
        &format!(
            "Replicated cold join catchup: {} source peers with full dataset, {} messages, {}",
            source_count,
            total_messages,
            connectivity.title()
        ),
        &[(
            "All",
            RangeTiming {
                count: all_timing.count,
                first_stored_at_ms: all_timing.first_stored_at_ms,
                projected_at_ms,
            },
        )],
        metric_start_ms,
        bench_start.elapsed().as_secs_f64(),
        useful_unique_events,
        downloader_event_frames,
        delivery_efficiency,
        active_sources,
        unattributed_event_frames,
        &sources,
        &source_event_frames,
        &source_recorded_events,
        &source_sync_run_deltas,
        &endpoint_obs_counts,
    );

    stop_daemon(&sink_db, &mut sink_daemon);
    wait_for_daemon_stopped(&sink_db, Duration::from_secs(10));

    ReplicatedJoinOutcome {
        total_messages: all_timing.count,
        total_wall_secs: bench_start.elapsed().as_secs_f64(),
        durable_msgs_per_sec: messages_per_sec(all_timing.count, durable_secs),
        projected_msgs_per_sec: messages_per_sec(all_timing.count, projected_secs),
        useful_unique_events,
        downloader_event_frames,
        delivery_efficiency,
        active_sources,
        source_labels: sources.iter().map(|source| source.label.clone()).collect(),
        source_event_frames,
        source_recorded_events,
    }
}

fn append_replicated_join_summary(
    summary: &mut String,
    label: &str,
    outcome: &ReplicatedJoinOutcome,
) {
    summary.push_str(&format!(
        "  {label}: messages={} wall={:.2}s durable={:.1} msg/s projected={:.1} msg/s useful_unique={} recv_frames={} efficiency={:.1}% active_sources={}\n",
        outcome.total_messages,
        outcome.total_wall_secs,
        outcome.durable_msgs_per_sec,
        outcome.projected_msgs_per_sec,
        outcome.useful_unique_events,
        outcome.downloader_event_frames,
        outcome.delivery_efficiency * 100.0,
        outcome.active_sources,
    ));
    for ((source_label, recv_frames), recorded_events) in outcome
        .source_labels
        .iter()
        .zip(outcome.source_event_frames.iter())
        .zip(outcome.source_recorded_events.iter())
    {
        summary.push_str(&format!(
            "    {}: recv_frames={} durable_attributed={}\n",
            source_label, recv_frames, recorded_events
        ));
    }
}

fn write_replicated_compare_summary(
    connectivity: ConnectivityMode,
    single_source: &ReplicatedJoinOutcome,
    four_source: &ReplicatedJoinOutcome,
) {
    let mut summary = format!(
        "=== Replicated join comparison ({}) ===\n",
        connectivity.title()
    );
    append_replicated_join_summary(&mut summary, "10k 1:1", single_source);
    append_replicated_join_summary(&mut summary, "10k 4:1", four_source);
    summary.push_str(&format!(
        "\n  Delta (4:1 - 1:1): durable={:+.1} msg/s projected={:+.1} msg/s active_sources={:+}\n",
        four_source.durable_msgs_per_sec - single_source.durable_msgs_per_sec,
        four_source.projected_msgs_per_sec - single_source.projected_msgs_per_sec,
        four_source.active_sources as isize - single_source.active_sources as isize,
    ));
    eprintln!("\n{summary}");
    write_summary(
        &format!(
            "daemon_multi_source_tiered_window_perf_test.compare_replicated_1x_vs_4x_{}_{}",
            single_source.total_messages,
            connectivity.suffix()
        ),
        &summary,
    );
}

fn run_replicated_rejoin_bench(
    source_count: usize,
    connectivity: ConnectivityMode,
) -> ReplicatedRejoinOutcome {
    assert!(source_count >= 2, "source_count must be >= 2");
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
    let source_dbs: Vec<String> = sources.iter().map(|source| source.db.clone()).collect();
    let all_dbs: Vec<String> = sources
        .iter()
        .map(|source| source.db.clone())
        .chain(std::iter::once(rejoiner.db.clone()))
        .collect();

    let warmup_messages = emit_warmup_messages(&sources) + 1;
    let _ = send_message(&rejoiner.db, "warmup-rejoiner");
    wait_for_message_count_all(&all_dbs, warmup_messages, Duration::from_secs(120));

    let mut rejoiner_daemon = rejoiner._daemon;
    stop_daemon(&rejoiner.db, &mut rejoiner_daemon);
    wait_for_daemon_stopped(&rejoiner.db, Duration::from_secs(10));

    generate_messages_replicated(&sources, total_messages);
    let expected_source_total = total_messages + warmup_messages;
    wait_for_message_count_all(
        &source_dbs,
        expected_source_total,
        Duration::from_secs(1200),
    );

    let metric_start_ms = current_timestamp_ms();
    let inherited_env = inherited_tier_env();
    rejoiner_daemon = start_peer(&rejoiner.db, inherited_env, connectivity);
    ensure_active_peer(&rejoiner.db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&rejoiner.db, Duration::from_secs(120));
    let _ = wait_for_message_count(
        &rejoiner.db,
        expected_source_total,
        Duration::from_secs(1800),
    );
    wait_for_downloader_receives_stable(
        &rejoiner.db,
        metric_start_ms,
        Duration::from_secs(60),
        Duration::from_millis(500),
    );

    let rejoiner_received_frame_deltas =
        received_events_by_peer_since_cli(&rejoiner.db, metric_start_ms);
    let source_event_frames: Vec<i64> = sources
        .iter()
        .map(|source| {
            rejoiner_received_frame_deltas
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let rejoiner_recorded_source_deltas =
        recorded_events_by_transport_peer_since_cli(&rejoiner.db, metric_start_ms);
    let source_recorded_events: Vec<i64> = sources
        .iter()
        .map(|source| {
            rejoiner_recorded_source_deltas
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let downloader_event_frames: i64 = rejoiner_received_frame_deltas.values().sum();
    let useful_unique_events =
        unique_sync_received_event_count_since_cli(&rejoiner.db, metric_start_ms);
    let delivery_efficiency = if downloader_event_frames > 0 {
        useful_unique_events as f64 / downloader_event_frames as f64
    } else {
        0.0
    };
    let active_sources = rejoiner_received_frame_deltas
        .values()
        .filter(|count| **count > 0)
        .count();

    eprintln!(
        "\nreplicated rejoin {}: useful_unique={} recv_frames={} efficiency={:.1}% active_sources={} recv_by_source={:?} durable_by_source={:?}",
        connectivity.title(),
        useful_unique_events,
        downloader_event_frames,
        delivery_efficiency * 100.0,
        active_sources,
        source_event_frames,
        source_recorded_events,
    );
    stop_daemon(&rejoiner.db, &mut rejoiner_daemon);
    wait_for_daemon_stopped(&rejoiner.db, Duration::from_secs(10));

    ReplicatedRejoinOutcome {
        useful_unique_events,
        active_sources,
        source_event_frames,
        source_recorded_events,
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
#[ignore]
fn perf_compare_replicated_10k_1x_vs_4x_discovery() {
    let single_source = run_replicated_cold_join_bench(1, ConnectivityMode::DiscoveryLoopback);
    let four_source = run_replicated_cold_join_bench(4, ConnectivityMode::DiscoveryLoopback);
    write_replicated_compare_summary(
        ConnectivityMode::DiscoveryLoopback,
        &single_source,
        &four_source,
    );
}

#[test]
#[ignore]
fn replicated_cold_join_2x_1k_live_suppression_uses_multiple_sources() {
    std::env::set_var("TOPO_MULTI_SOURCE_COMPARE_TOTAL_MESSAGES", "1000");
    let outcome = run_replicated_cold_join_bench(2, ConnectivityMode::DiscoveryLoopback);
    assert!(
        outcome.active_sources >= 2,
        "expected both replicated sources to contribute, got active_sources={} recv_frames={:?} durable_attributed={:?}",
        outcome.active_sources,
        outcome.source_event_frames,
        outcome.source_recorded_events,
    );
}

#[test]
#[ignore]
fn replicated_rejoin_2x_1k_live_suppression_uses_multiple_sources_after_preconvergence() {
    std::env::set_var("TOPO_MULTI_SOURCE_COMPARE_TOTAL_MESSAGES", "1000");
    let outcome = run_replicated_rejoin_bench(2, ConnectivityMode::DiscoveryLoopback);
    assert!(
        outcome.active_sources >= 2,
        "expected both known replicated sources to contribute after rejoin, got active_sources={} recv_frames={:?} durable_attributed={:?}",
        outcome.active_sources,
        outcome.source_event_frames,
        outcome.source_recorded_events,
    );
    assert!(
        outcome.useful_unique_events > 0,
        "expected the rejoiner to ingest replicated events"
    );
}

#[test]
#[ignore]
fn replicated_rejoin_2x_10k_live_suppression_uses_multiple_sources_after_preconvergence() {
    std::env::set_var("TOPO_MULTI_SOURCE_COMPARE_TOTAL_MESSAGES", "10000");
    let outcome = run_replicated_rejoin_bench(2, ConnectivityMode::DiscoveryLoopback);
    assert!(
        outcome.active_sources >= 2,
        "expected both known replicated sources to contribute after rejoin, got active_sources={} recv_frames={:?} durable_attributed={:?}",
        outcome.active_sources,
        outcome.source_event_frames,
        outcome.source_recorded_events,
    );
    assert!(
        outcome.useful_unique_events > 0,
        "expected the rejoiner to ingest replicated events"
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
    use topo::db::{open_connection, schema::create_tables};

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let db_path = tmpdir.path().join("metric.db");
    let db_path_str = db_path.to_str().expect("db path utf-8");
    let conn = open_connection(db_path_str).expect("open metrics db");
    create_tables(&conn).expect("create tables");

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

    let metrics =
        topo::service::svc_sync_metrics(&conn, "tenant", None, None, false).expect("sync metrics");
    let from_metrics: HashMap<String, i64> = metrics
        .received_event_frames_by_peer
        .into_iter()
        .map(|item| (item.peer_id, item.count))
        .collect();

    assert_eq!(from_metrics.get("sink-peer").copied(), Some(2));
    assert_eq!(from_metrics.get("other-peer").copied(), Some(3));
}

#[test]
fn cli_metrics_reports_receiver_sync_and_timeline_counts() {
    hold_network_test_lock_for_binary();
    std::env::set_var("TOPO_EVENT_TIMELINE", "1");
    std::env::set_var("TOPO_EVENT_TIMELINE_GROUPS", "persist,projection");

    let tmpdir = bench_tmpdir("metrics-cli-");
    let peer_labels = vec!["hub".to_string(), "peer-01".to_string()];
    let (nodes, _invite_link) =
        create_online_community(&tmpdir, &peer_labels, ConnectivityMode::DiscoveryLoopback);
    let hub = &nodes[0];
    let receiver = &nodes[1];

    let metric_start_ms = current_timestamp_ms();
    let _ = send_message(&hub.db, "metrics-probe");
    let _ = wait_for_message_count(&receiver.db, 1, Duration::from_secs(120));
    wait_for_downloader_receives_stable(
        &receiver.db,
        metric_start_ms,
        Duration::from_secs(30),
        Duration::from_millis(500),
    );

    let metrics = metrics_snapshot(
        &receiver.db,
        Some(metric_start_ms),
        Some(metric_start_ms),
        false,
    );
    let received_by_peer = count_map_from_metrics_array(&metrics, "received_event_frames_by_peer");
    let recorded_by_peer =
        count_map_from_metrics_array(&metrics, "recorded_events_by_transport_peer");

    assert!(
        metrics["message_range"]["count"]
            .as_i64()
            .unwrap_or_default()
            >= 1,
        "expected at least one new message in range, got {}",
        metrics["message_range"]["count"]
    );
    assert!(
        metrics["message_range"]["first_stored_at_ms"]
            .as_i64()
            .is_some(),
        "expected durable timeline marker in metrics: {}",
        metrics
    );
    assert!(
        metrics["message_range"]["projected_at_ms"]
            .as_i64()
            .is_some(),
        "expected projected timeline marker in metrics: {}",
        metrics
    );
    assert!(
        metrics["received_event_frames_total"]
            .as_i64()
            .unwrap_or_default()
            > 0,
        "expected receiver to log incoming sync frames: {}",
        metrics
    );
    assert!(
        metrics["unique_sync_received_event_count"]
            .as_i64()
            .unwrap_or_default()
            > 0,
        "expected receiver to attribute at least one incoming event: {}",
        metrics
    );
    assert!(
        received_by_peer
            .get(&hub.transport_peer_id)
            .copied()
            .unwrap_or_default()
            > 0,
        "expected hub peer to contribute receive frames: {:?}",
        received_by_peer
    );
    assert!(
        recorded_by_peer
            .get(&hub.transport_peer_id)
            .copied()
            .unwrap_or_default()
            > 0,
        "expected hub peer to contribute recorded events: {:?}",
        recorded_by_peer
    );
}
