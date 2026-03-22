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
    accept_invite_with_identity_on_running_daemon, active_tenant_peer_id, create_invite_with_spki,
    create_workspace_with_details, daemon_listen_addr, daemon_transport_fingerprint,
    ensure_active_peer, generate_messages, hold_network_test_lock_for_binary, send_message,
    start_daemon_with_options, stop_daemon, topo_cmd, wait_for_active_tenant_ready,
    wait_for_daemon_stopped, DaemonOptions, HarnessDaemon,
};
use daemon_perf_harness::write_summary;

const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const WEEK_MS: i64 = 7 * DAY_MS;
const MONTH_MS: i64 = 30 * DAY_MS;
const YEAR_MS: i64 = 365 * DAY_MS;
const THREE_YEARS_MS: i64 = 3 * 365 * DAY_MS;

#[derive(Clone, Copy)]
struct RangeTiming {
    count: i64,
    persisted_at_ms: Option<i64>,
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
        "TOPO_SYNC_WINDOW_SHAPE",
        "TOPO_GENERATE_MESSAGE_SPREAD_MS",
        "TOPO_FORWARD_ON_HAVE",
        "TOPO_EVENT_TIMELINE",
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
    stmt.query_map(rusqlite::params![cutoff_ms], |row| row.get::<_, String>(0))
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
        "SELECT COUNT(*), MAX(t.persisted_at), MAX(t.projected_at)
         FROM messages m
         LEFT JOIN event_timeline t ON t.event_id = m.message_id
         WHERE m.recorded_by = ?1
           AND (?2 IS NULL OR m.created_at >= ?2)",
        rusqlite::params![peer_id, min_created_at_ms],
        |row| {
            Ok(RangeTiming {
                count: row.get(0)?,
                persisted_at_ms: row.get(1)?,
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
    loop {
        let count = total_message_count_sql(db);
        if count >= expected {
            return current_timestamp_ms();
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
    loop {
        let count = message_count_since_sql(db, cutoff_ms);
        if count >= expected {
            return current_timestamp_ms();
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
    loop {
        let counts: Vec<i64> = dbs.iter().map(|db| total_message_count_sql(db)).collect();
        if counts.iter().all(|count| *count >= expected) {
            return;
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

fn received_event_frames_by_peer_for_conn(conn: &rusqlite::Connection) -> HashMap<String, i64> {
    let mut stmt = conn
        .prepare(
            "SELECT r.peer_id, COUNT(*)
             FROM sync_run_events e
             JOIN sync_runs r ON r.run_id = e.run_id
             WHERE e.lane = 'data'
               AND e.direction = 'rx'
               AND e.frame_type = 'Event'
             GROUP BY r.peer_id",
        )
        .expect("prepare downloader receive query");
    stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })
    .expect("query downloader receive rows")
    .collect::<Result<HashMap<_, _>, _>>()
    .expect("collect downloader receive rows")
}

fn received_event_frames_by_peer_for_db(db: &str) -> HashMap<String, i64> {
    let conn = topo::db::open_connection(db).expect("open db for downloader receive rows");
    received_event_frames_by_peer_for_conn(&conn)
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

fn received_recorded_events_by_source_for_db(db: &str) -> HashMap<String, i64> {
    let conn = topo::db::open_connection(db).expect("open db for recorded source rows");
    let Some(peer_id) = active_tenant_peer_id(db) else {
        return HashMap::new();
    };
    let mut stmt = conn
        .prepare(
            "SELECT source, COUNT(*)
             FROM recorded_events
             WHERE peer_id = ?1
               AND source LIKE 'quic_recv:%'
             GROUP BY source",
        )
        .expect("prepare recorded source query");
    stmt.query_map(rusqlite::params![peer_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })
    .expect("query recorded source rows")
    .collect::<Result<HashMap<_, _>, _>>()
    .expect("collect recorded source rows")
}

fn count_source_tag_events(
    source_counts: &HashMap<String, i64>,
    sources: &[Node],
) -> Vec<i64> {
    sources
        .iter()
        .map(|source| {
            let prefix = format!("quic_recv:{}@", source.transport_peer_id);
            source_counts
                .iter()
                .filter(|(tag, _)| tag.starts_with(&prefix))
                .map(|(_, count)| *count)
                .sum()
        })
        .collect()
}

fn changed_sync_run_count(db: &str) -> i64 {
    let conn = topo::db::open_connection(db).expect("open db for sync run count");
    conn.query_row(
        "SELECT COUNT(*)
         FROM sync_runs
         WHERE rounds > 0 OR events_sent > 0 OR events_received > 0",
        [],
        |row| row.get(0),
    )
    .unwrap_or(0)
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

fn unique_sync_received_event_count_sql(db: &str) -> i64 {
    let conn = topo::db::open_connection(db).expect("open db for sync received event count");
    conn.query_row(
        "SELECT COUNT(DISTINCT event_id)
         FROM sync_run_rx_events",
        [],
        |row| row.get(0),
    )
    .unwrap_or(0)
}

fn wait_for_downloader_receives_stable(db: &str, timeout: Duration, stable_for: Duration) {
    let start = Instant::now();
    let mut last: i64 = received_event_frames_by_peer_for_db(db).values().sum();
    let mut stable_since = None;
    loop {
        let current: i64 = received_event_frames_by_peer_for_db(db).values().sum();
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

    let invite_link = create_invite_with_spki(
        &hub_db,
        &daemon_listen_addr(&hub_db),
        Some(&daemon_transport_fingerprint(&hub_db)),
    );

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
            elapsed_secs(metric_start_ms, timing.persisted_at_ms),
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
    std::env::set_var("TOPO_FORWARD_ON_HAVE", "0");
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
    wait_for_message_count_all(&source_dbs, source_expected_total, Duration::from_secs(1200));

    let measurement_now_ms = current_timestamp_ms();
    let hour_cutoff = measurement_now_ms - HOUR_MS;
    let day_cutoff = measurement_now_ms - DAY_MS;
    let week_cutoff = measurement_now_ms - WEEK_MS;
    let month_cutoff = measurement_now_ms - MONTH_MS;
    let year_cutoff = measurement_now_ms - YEAR_MS;
    let expected_total = union_message_count_since_sql(&source_dbs, None);
    let expected_hour = union_message_count_since_sql(&source_dbs, Some(hour_cutoff));
    let expected_day = union_message_count_since_sql(&source_dbs, Some(day_cutoff));
    let expected_week = union_message_count_since_sql(&source_dbs, Some(week_cutoff));
    let expected_month = union_message_count_since_sql(&source_dbs, Some(month_cutoff));
    let expected_year = union_message_count_since_sql(&source_dbs, Some(year_cutoff));
    let sink_db = tmpdir.path().join("sink.db").to_str().unwrap().to_string();
    enable_sync_logging(&sink_db);
    let inherited_env = inherited_tier_env();
    let mut sink_daemon = start_peer(&sink_db, inherited_env, connectivity);
    let sink_received_frames_before = received_event_frames_by_peer_for_db(&sink_db);
    let sink_recorded_sources_before = received_recorded_events_by_source_for_db(&sink_db);
    let useful_unique_events_before = unique_sync_received_event_count_sql(&sink_db);
    let source_sync_runs_before: Vec<i64> = source_dbs
        .iter()
        .map(|db| changed_sync_run_count(db))
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

    let _hour_projected_ms = if expected_hour > 0 {
        wait_for_message_count_since(
            &sink_db,
            hour_cutoff,
            expected_hour,
            Duration::from_secs(1800),
        )
    } else {
        metric_start_ms
    };
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
    let _month_projected_ms = if expected_month > 0 {
        wait_for_message_count_since(
            &sink_db,
            month_cutoff,
            expected_month,
            Duration::from_secs(1800),
        )
    } else {
        metric_start_ms
    };
    let full_projected_ms =
        wait_for_message_count(&sink_db, expected_total, Duration::from_secs(3600));
    let _ = (expected_year, full_projected_ms);

    let hour_timing = range_timing_sql(&sink_db, Some(hour_cutoff));
    let day_timing = range_timing_sql(&sink_db, Some(day_cutoff));
    let week_timing = range_timing_sql(&sink_db, Some(week_cutoff));
    let month_timing = range_timing_sql(&sink_db, Some(month_cutoff));
    let year_timing = range_timing_sql(&sink_db, Some(year_cutoff));
    let all_timing = range_timing_sql(&sink_db, None);

    wait_for_downloader_receives_stable(
        &sink_db,
        Duration::from_secs(60),
        Duration::from_millis(500),
    );
    let sink_received_frames_after = received_event_frames_by_peer_for_db(&sink_db);
    let sink_received_frame_deltas =
        diff_count_map(&sink_received_frames_after, &sink_received_frames_before);
    let source_event_frames: Vec<i64> = sources
        .iter()
        .map(|source| {
            sink_received_frame_deltas
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let sink_recorded_sources_after = received_recorded_events_by_source_for_db(&sink_db);
    let sink_recorded_source_deltas =
        diff_count_map(&sink_recorded_sources_after, &sink_recorded_sources_before);
    let source_recorded_events =
        count_source_tag_events(&sink_recorded_source_deltas, &sources);
    let source_sync_runs_after: Vec<i64> = source_dbs
        .iter()
        .map(|db| changed_sync_run_count(db))
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
    let useful_unique_events =
        unique_sync_received_event_count_sql(&sink_db).saturating_sub(useful_unique_events_before);
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
            ("Last hour", hour_timing),
            ("Last day", day_timing),
            ("Last week", week_timing),
            ("Last month", month_timing),
            ("Last year", year_timing),
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
    std::env::set_var("TOPO_FORWARD_ON_HAVE", "0");
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
    wait_for_message_count_all(&source_dbs, source_expected_total, Duration::from_secs(1200));

    let measurement_now_ms = current_timestamp_ms();
    let hour_cutoff = measurement_now_ms - HOUR_MS;
    let day_cutoff = measurement_now_ms - DAY_MS;
    let week_cutoff = measurement_now_ms - WEEK_MS;
    let month_cutoff = measurement_now_ms - MONTH_MS;
    let year_cutoff = measurement_now_ms - YEAR_MS;
    let expected_total = union_message_count_since_sql(&source_dbs, None);
    let expected_hour = union_message_count_since_sql(&source_dbs, Some(hour_cutoff));
    let expected_day = union_message_count_since_sql(&source_dbs, Some(day_cutoff));
    let expected_week = union_message_count_since_sql(&source_dbs, Some(week_cutoff));
    let expected_month = union_message_count_since_sql(&source_dbs, Some(month_cutoff));
    let expected_year = union_message_count_since_sql(&source_dbs, Some(year_cutoff));
    let useful_unique_events_before = unique_sync_received_event_count_sql(&rejoiner.db);
    let rejoiner_received_frames_before = received_event_frames_by_peer_for_db(&rejoiner.db);
    let rejoiner_recorded_sources_before = received_recorded_events_by_source_for_db(&rejoiner.db);
    let source_sync_runs_before: Vec<i64> = source_dbs
        .iter()
        .map(|db| changed_sync_run_count(db))
        .collect();

    let metric_start_ms = current_timestamp_ms();
    let bench_start = Instant::now();
    let inherited_env = inherited_tier_env();
    let _rejoiner_daemon = start_peer(&rejoiner.db, inherited_env, connectivity);
    ensure_active_peer(&rejoiner.db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&rejoiner.db, Duration::from_secs(120));

    let _hour_projected_ms = if expected_hour > 0 {
        wait_for_message_count_since(
            &rejoiner.db,
            hour_cutoff,
            expected_hour,
            Duration::from_secs(1800),
        )
    } else {
        metric_start_ms
    };
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
    let _month_projected_ms = if expected_month > 0 {
        wait_for_message_count_since(
            &rejoiner.db,
            month_cutoff,
            expected_month,
            Duration::from_secs(1800),
        )
    } else {
        metric_start_ms
    };
    let full_projected_ms =
        wait_for_message_count(&rejoiner.db, expected_total, Duration::from_secs(3600));
    let _ = (expected_year, full_projected_ms);

    let hour_timing = range_timing_sql(&rejoiner.db, Some(hour_cutoff));
    let day_timing = range_timing_sql(&rejoiner.db, Some(day_cutoff));
    let week_timing = range_timing_sql(&rejoiner.db, Some(week_cutoff));
    let month_timing = range_timing_sql(&rejoiner.db, Some(month_cutoff));
    let year_timing = range_timing_sql(&rejoiner.db, Some(year_cutoff));
    let all_timing = range_timing_sql(&rejoiner.db, None);

    wait_for_downloader_receives_stable(
        &rejoiner.db,
        Duration::from_secs(60),
        Duration::from_millis(500),
    );
    let rejoiner_received_frames_after = received_event_frames_by_peer_for_db(&rejoiner.db);
    let rejoiner_received_frame_deltas = diff_count_map(
        &rejoiner_received_frames_after,
        &rejoiner_received_frames_before,
    );
    let source_event_frames: Vec<i64> = sources
        .iter()
        .map(|source| {
            rejoiner_received_frame_deltas
                .get(&source.transport_peer_id)
                .copied()
                .unwrap_or(0)
        })
        .collect();
    let rejoiner_recorded_sources_after = received_recorded_events_by_source_for_db(&rejoiner.db);
    let rejoiner_recorded_source_deltas = diff_count_map(
        &rejoiner_recorded_sources_after,
        &rejoiner_recorded_sources_before,
    );
    let source_recorded_events =
        count_source_tag_events(&rejoiner_recorded_source_deltas, &sources);
    let source_sync_runs_after: Vec<i64> = source_dbs
        .iter()
        .map(|db| changed_sync_run_count(db))
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
    let useful_unique_events_after = unique_sync_received_event_count_sql(&rejoiner.db);
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
            ("Last hour", hour_timing),
            ("Last day", day_timing),
            ("Last week", week_timing),
            ("Last month", month_timing),
            ("Last year", year_timing),
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
#[ignore = "fresh invitees only know the inviter until discovery warms enough to expose the full peer set"]
fn cold_join_4x_1k_uses_multiple_sources_efficiently() {
    std::env::set_var("TOPO_MULTI_SOURCE_TOTAL_MESSAGES", "1000");
    std::env::set_var("TOPO_SYNC_WINDOW_SHAPE", "disjoint");
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
    std::env::set_var("TOPO_SYNC_WINDOW_SHAPE", "disjoint");
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
fn downloader_receive_metric_counts_frames_by_remote_peer() {
    use topo::db::sync_log::ensure_schema;

    let tmpdir = tempfile::tempdir().expect("tempdir");
    let db_path = tmpdir.path().join("metric.db");
    let db_path_str = db_path.to_str().expect("db path utf-8");
    let conn = topo::db::open_connection(db_path_str).expect("open db");
    ensure_schema(&conn).expect("ensure sync_log schema");

    conn.execute(
        "INSERT INTO sync_runs
         (run_id, started_at_ms, ended_at_ms, session_id, tenant_id, peer_id, direction, remote_addr, role,
          rounds, events_sent, events_received, bytes_sent, bytes_received, changed, outcome, error)
         VALUES
         (1, 1, 2, 1, 'tenant', 'sink-peer', 'outbound', '127.0.0.1:1', 'initiator', 1, 2, 0, 20, 0, 1, 'ok', NULL),
         (2, 3, 4, 2, 'tenant', 'other-peer', 'outbound', '127.0.0.1:2', 'initiator', 1, 3, 0, 30, 0, 1, 'ok', NULL)",
        [],
    )
    .expect("insert sync_runs");
    conn.execute(
        "INSERT INTO sync_run_events
         (run_id, seq, ts_ms, lane, direction, frame_type, msg_len, detail_json)
         VALUES
         (1, 1, 11, 'data', 'rx', 'Event', 10, NULL),
         (1, 2, 12, 'data', 'rx', 'Event', 10, NULL),
         (2, 1, 13, 'data', 'rx', 'Event', 10, NULL),
         (2, 2, 14, 'data', 'rx', 'Event', 10, NULL),
         (2, 3, 15, 'data', 'rx', 'Event', 10, NULL)",
        [],
    )
    .expect("insert sync_run_events");

    let from_conn = received_event_frames_by_peer_for_conn(&conn);
    let from_db = received_event_frames_by_peer_for_db(db_path_str);

    assert_eq!(from_conn.get("sink-peer").copied(), Some(2));
    assert_eq!(from_conn.get("other-peer").copied(), Some(3));
    assert_eq!(from_db.get("sink-peer").copied(), Some(2));
    assert_eq!(from_db.get("other-peer").copied(), Some(3));
}
