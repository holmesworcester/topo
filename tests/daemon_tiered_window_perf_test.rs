//! Tiered window catch-up benchmark:
//! last day -> last week -> last 12 weeks -> old.
//!
//! Run with:
//! `cargo test --release --test daemon_tiered_window_perf_test -- --ignored --nocapture --test-threads=1`

mod cli_harness;
mod perf_network_shaper;

use std::net::{Ipv4Addr, SocketAddr};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cli_harness::{
    accept_invite_with_identity_on_running_daemon, create_invite_with_spki,
    create_workspace_with_seeded_history, daemon_identity_fingerprint, daemon_listen_addr,
    ensure_active_peer, message_count_sql, random_port, start_daemon_with_options, stop_daemon,
    wait_for_daemon_stopped, DaemonOptions,
};
use perf_network_shaper::{NetworkProfile, UdpTrafficShaper, REALISTIC_NETWORK_PROFILES};

const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const WEEK_MS: i64 = 7 * DAY_MS;
const TWELVE_WEEK_MS: i64 = 12 * WEEK_MS;
const THREE_YEARS_MS: i64 = 3 * 365 * DAY_MS;

struct RangeTiming {
    count: i64,
    first_stored_at_ms: Option<i64>,
    projected_at_ms: Option<i64>,
}

struct NewestMessageTiming {
    created_at_ms: Option<i64>,
    first_stored_at_ms: Option<i64>,
    projected_at_ms: Option<i64>,
}

struct AuthoringDepTiming {
    user_created_at_ms: i64,
    peer_shared_created_at_ms: i64,
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

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|value| value != "0" && value.to_lowercase() != "false")
        .unwrap_or(false)
}

fn inherited_tier_env() -> Vec<(String, String)> {
    ["TOPO_GENERATE_MESSAGE_SPREAD_MS", "TOPO_EVENT_TIMELINE"]
        .into_iter()
        .filter_map(|key| {
            std::env::var(key)
                .ok()
                .map(|value| (key.to_string(), value))
        })
        .collect()
}

fn tier_role_env(base: &[(String, String)], lowmem: bool) -> Vec<(String, String)> {
    let mut env = base.to_vec();
    if lowmem {
        env.push(("LOW_MEM_IOS".to_string(), "1".to_string()));
    }
    env
}

fn join_catchup_network_profile_from_env() -> Option<NetworkProfile> {
    let slug = match std::env::var("TOPO_JOIN_CATCHUP_NETWORK_PROFILE") {
        Ok(value) => value,
        Err(_) => return None,
    };
    let slug = slug.trim();
    if slug.is_empty() || slug.eq_ignore_ascii_case("loopback") {
        return None;
    }
    REALISTIC_NETWORK_PROFILES
        .iter()
        .copied()
        .find(|profile| profile.slug == slug)
        .unwrap_or_else(|| {
            panic!(
                "unknown TOPO_JOIN_CATCHUP_NETWORK_PROFILE `{slug}`; supported={}",
                REALISTIC_NETWORK_PROFILES
                    .iter()
                    .map(|profile| profile.slug)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        })
        .into()
}

fn message_count_since_sql(db: &str, cutoff_ms: i64) -> i64 {
    let conn = topo::db::open_connection(db).expect("open db for message_count_since");
    let peer_id = cli_harness::active_tenant_peer_id(db).expect("active tenant peer id");
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
    let peer_id = cli_harness::active_tenant_peer_id(db).expect("active tenant peer id");
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

fn newest_message_timing_sql(db: &str) -> NewestMessageTiming {
    let conn = topo::db::open_connection(db).expect("open db for newest_message_timing");
    let peer_id = cli_harness::active_tenant_peer_id(db).expect("active tenant peer id");
    conn.query_row(
        "SELECT MAX(m.created_at), MAX(t.first_stored_at), MAX(t.projected_at)
         FROM messages m
         LEFT JOIN event_timeline t ON t.event_id = m.message_id
         WHERE m.recorded_by = ?1
           AND m.created_at = (
               SELECT MAX(created_at)
               FROM messages
               WHERE recorded_by = ?1
           )",
        rusqlite::params![peer_id],
        |row| {
            Ok(NewestMessageTiming {
                created_at_ms: row.get(0)?,
                first_stored_at_ms: row.get(1)?,
                projected_at_ms: row.get(2)?,
            })
        },
    )
    .expect("query newest_message_timing")
}

fn authoring_dep_timing_sql(db: &str) -> AuthoringDepTiming {
    let conn = topo::db::open_connection(db).expect("open db for authoring_dep_timing");
    let peer_id = cli_harness::active_tenant_peer_id(db).expect("active tenant peer id");
    conn.query_row(
        "SELECT COALESCE((
                    SELECT MIN(e.created_at)
                    FROM users u
                    JOIN events e ON e.event_id = u.event_id
                    WHERE u.recorded_by = ?1
                ), 0),
                COALESCE((
                    SELECT MIN(e.created_at)
                    FROM peers_shared ps
                    JOIN events e ON e.event_id = ps.event_id
                    WHERE ps.recorded_by = ?1
                ), 0)",
        rusqlite::params![peer_id],
        |row| {
            Ok(AuthoringDepTiming {
                user_created_at_ms: row.get(0)?,
                peer_shared_created_at_ms: row.get(1)?,
            })
        },
    )
    .expect("query authoring_dep_timing")
}

fn elapsed_secs(metric_start_ms: i64, ts_ms: Option<i64>) -> f64 {
    ts_ms
        .unwrap_or(metric_start_ms)
        .saturating_sub(metric_start_ms) as f64
        / 1000.0
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

fn wait_for_message_count(db: &str, expected: i64, timeout: Duration) -> i64 {
    let start = Instant::now();
    loop {
        let count = message_count_sql(db);
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

fn wait_for_message_count_exact(db: &str, expected: i64, timeout: Duration) -> i64 {
    let start = Instant::now();
    loop {
        let count = message_count_sql(db);
        if count == expected {
            return current_timestamp_ms();
        }
        assert!(
            start.elapsed() < timeout,
            "exact message_count timed out after {:?} for db={}: expected={} actual={}",
            timeout,
            db,
            expected,
            count
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_newest_message_visible(db: &str, timeout: Duration) -> (NewestMessageTiming, i64, i64) {
    let start = Instant::now();
    loop {
        let timing = newest_message_timing_sql(db);
        if timing.projected_at_ms.is_some() {
            return (timing, current_timestamp_ms(), message_count_sql(db));
        }
        assert!(
            start.elapsed() < timeout,
            "newest message visibility timed out after {:?} for db={}",
            timeout,
            db
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn write_summary(summary_key: &str, summary: &str) {
    let summary_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/perf-results");
    std::fs::create_dir_all(&summary_dir).expect("create target/perf-results");
    std::fs::write(summary_dir.join(format!("{summary_key}.summary")), summary)
        .expect("write benchmark summary file");
}

fn run_tiered_window_bench(total_messages_override: Option<i64>) {
    std::env::set_var(
        "TOPO_GENERATE_MESSAGE_SPREAD_MS",
        THREE_YEARS_MS.to_string(),
    );
    std::env::set_var("TOPO_EVENT_TIMELINE", "1");
    std::env::set_var("TOPO_EVENT_TIMELINE_GROUPS", "persist,projection");

    let total_messages = total_messages_override
        .unwrap_or_else(|| env_i64("TOPO_TIERED_SYNC_TOTAL_MESSAGES", 50_000));
    let network_profile = join_catchup_network_profile_from_env();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    create_workspace_with_seeded_history(
        &alice_db,
        "workspace",
        "alice",
        "desktop",
        total_messages as usize,
        Some("3y"),
    );
    let inherited_env = inherited_tier_env();
    let mut alice_daemon = start_daemon_with_options(
        &alice_db,
        &DaemonOptions {
            disable_discovery: true,
            extra_env: tier_role_env(&inherited_env, env_bool("TOPO_TIERED_ALICE_LOWMEM")),
            ..Default::default()
        },
    );
    ensure_active_peer(&alice_db, Duration::from_secs(10));
    assert!(
        message_count_sql(&alice_db) >= total_messages,
        "alice should have generated all messages"
    );

    let measurement_now_ms = current_timestamp_ms();
    let authoring_dep_timing = authoring_dep_timing_sql(&alice_db);
    let day_cutoff = measurement_now_ms - DAY_MS;
    assert!(
        authoring_dep_timing.user_created_at_ms < day_cutoff,
        "creator user event should be outside the hot last-day window: user_created_at_ms={} day_cutoff={}",
        authoring_dep_timing.user_created_at_ms,
        day_cutoff
    );
    assert!(
        authoring_dep_timing.peer_shared_created_at_ms < day_cutoff,
        "creator peer_shared event should be outside the hot last-day window: peer_shared_created_at_ms={} day_cutoff={}",
        authoring_dep_timing.peer_shared_created_at_ms,
        day_cutoff
    );
    let week_cutoff = measurement_now_ms - WEEK_MS;
    let twelve_week_cutoff = measurement_now_ms - TWELVE_WEEK_MS;
    let expected_day = message_count_since_sql(&alice_db, day_cutoff);
    let expected_week = message_count_since_sql(&alice_db, week_cutoff);
    let expected_twelve_weeks = message_count_since_sql(&alice_db, twelve_week_cutoff);

    let alice_direct_addr = daemon_listen_addr(&alice_db);
    let (invite_addr, bob_bind_addr, network_guard) = if let Some(profile) = network_profile {
        let alice_real_addr = alice_direct_addr
            .parse::<SocketAddr>()
            .unwrap_or_else(|_| panic!("parse alice daemon listen addr `{alice_direct_addr}`"));
        let bob_bind_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, random_port()));
        let shaper = UdpTrafficShaper::new(alice_real_addr, bob_bind_addr, profile);
        (
            shaper.left_addr().to_string(),
            Some(bob_bind_addr),
            Some(shaper),
        )
    } else {
        (alice_direct_addr.clone(), None, None)
    };
    let invite_link = create_invite_with_spki(
        &alice_db,
        &invite_addr,
        Some(&daemon_identity_fingerprint(&alice_db)),
    );
    let mut bob_daemon = start_daemon_with_options(
        &bob_db,
        &DaemonOptions {
            bind_ip: bob_bind_addr.map(|addr| addr.ip().to_string()),
            bind_port: bob_bind_addr.map(|addr| addr.port()),
            disable_discovery: true,
            extra_env: tier_role_env(&inherited_env, env_bool("TOPO_TIERED_BOB_LOWMEM")),
            ..Default::default()
        },
    );
    let _network_guard = network_guard;

    let metric_start_ms = current_timestamp_ms();
    let bench_start = Instant::now();
    accept_invite_with_identity_on_running_daemon(
        &bob_db,
        &invite_link,
        "bob",
        "laptop",
        Duration::from_secs(30),
    );

    let day_projected_ms = if expected_day > 0 {
        wait_for_message_count_since(&bob_db, day_cutoff, expected_day, Duration::from_secs(1200))
    } else {
        metric_start_ms
    };
    let week_projected_ms = if expected_week > 0 {
        wait_for_message_count_since(
            &bob_db,
            week_cutoff,
            expected_week,
            Duration::from_secs(1200),
        )
    } else {
        metric_start_ms
    };
    let twelve_week_projected_ms = if expected_twelve_weeks > 0 {
        wait_for_message_count_since(
            &bob_db,
            twelve_week_cutoff,
            expected_twelve_weeks,
            Duration::from_secs(1200),
        )
    } else {
        metric_start_ms
    };
    let full_projected_ms =
        wait_for_message_count(&bob_db, total_messages, Duration::from_secs(1200));
    let full_wall_secs = bench_start.elapsed().as_secs_f64();

    let day_timing = range_timing_sql(&bob_db, Some(day_cutoff));
    let week_timing = range_timing_sql(&bob_db, Some(week_cutoff));
    let twelve_week_timing = range_timing_sql(&bob_db, Some(twelve_week_cutoff));
    let all_timing = range_timing_sql(&bob_db, None);
    let newest_timing = newest_message_timing_sql(&bob_db);

    let summary = format!(
        "=== tiered window catchup ===\n  Window ladder: LastDay -> LastWeek -> Last12Weeks -> Old\n  Messages preloaded on inviter: {total_messages}\n  Network profile: {}\n  Generated spread: 3 years\n  Aged auth deps: user={} peer_shared={}\n  Metric start: invite accept on running joiner daemon\n  Last day:      {} msgs durable in {:.2}s projected in {:.2}s\n  Last week:     {} msgs durable in {:.2}s projected in {:.2}s\n  Last 12 weeks: {} msgs durable in {:.2}s projected in {:.2}s\n  All:           {} msgs durable in {:.2}s projected in {:.2}s\n  Newest message: created_at={} durable in {:.2}s visible in {:.2}s\n  Total catchup wall: {:.2}s\n",
        network_profile.map(|profile| profile.slug).unwrap_or("loopback"),
        authoring_dep_timing.user_created_at_ms,
        authoring_dep_timing.peer_shared_created_at_ms,
        day_timing.count,
        elapsed_secs(metric_start_ms, day_timing.first_stored_at_ms),
        elapsed_secs(metric_start_ms, day_timing.projected_at_ms.or(Some(day_projected_ms))),
        week_timing.count,
        elapsed_secs(metric_start_ms, week_timing.first_stored_at_ms),
        elapsed_secs(metric_start_ms, week_timing.projected_at_ms.or(Some(week_projected_ms))),
        twelve_week_timing.count,
        elapsed_secs(metric_start_ms, twelve_week_timing.first_stored_at_ms),
        elapsed_secs(
            metric_start_ms,
            twelve_week_timing
                .projected_at_ms
                .or(Some(twelve_week_projected_ms))
        ),
        all_timing.count,
        elapsed_secs(metric_start_ms, all_timing.first_stored_at_ms),
        elapsed_secs(metric_start_ms, all_timing.projected_at_ms.or(Some(full_projected_ms))),
        newest_timing.created_at_ms.unwrap_or_default(),
        elapsed_secs(metric_start_ms, newest_timing.first_stored_at_ms),
        elapsed_secs(metric_start_ms, newest_timing.projected_at_ms),
        full_wall_secs,
    );
    eprintln!("\n{summary}");
    let summary_key = format!(
        "daemon_tiered_window_perf_test.disjoint_{}_{}",
        total_messages,
        network_profile
            .map(|profile| profile.slug)
            .unwrap_or("loopback"),
    );
    write_summary(&summary_key, &summary);

    stop_daemon(&bob_db, &mut bob_daemon);
    wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));
    stop_daemon(&alice_db, &mut alice_daemon);
    wait_for_daemon_stopped(&alice_db, Duration::from_secs(10));
}

#[test]
#[ignore]
fn perf_tiered_window_50k_parallel() {
    run_tiered_window_bench(None);
}

#[test]
#[ignore]
fn perf_tiered_window_100k_parallel() {
    run_tiered_window_bench(Some(100_000));
}

#[test]
#[ignore]
fn perf_last_day_only_sync_renders_newest_message_with_old_deps() {
    let total_messages = env_i64("TOPO_LAST_DAY_ONLY_TOTAL_MESSAGES", 10_000);
    let newest_visible_budget_secs = env_i64("TOPO_LAST_DAY_ONLY_VISIBLE_MAX_SECS", 10) as f64;
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let daemon_env = vec![
        ("TOPO_EVENT_TIMELINE".to_string(), "1".to_string()),
        (
            "TOPO_EVENT_TIMELINE_GROUPS".to_string(),
            "persist,projection".to_string(),
        ),
    ];

    create_workspace_with_seeded_history(
        &alice_db,
        "workspace",
        "alice",
        "desktop",
        total_messages as usize,
        Some("3y"),
    );
    let mut alice_daemon = start_daemon_with_options(
        &alice_db,
        &DaemonOptions {
            disable_discovery: true,
            last_day_only_sync: true,
            extra_env: daemon_env.clone(),
            ..Default::default()
        },
    );
    ensure_active_peer(&alice_db, Duration::from_secs(10));

    let measurement_now_ms = current_timestamp_ms();
    let authoring_dep_timing = authoring_dep_timing_sql(&alice_db);
    let day_cutoff = measurement_now_ms - DAY_MS;
    let expected_day = message_count_since_sql(&alice_db, day_cutoff);
    assert!(
        authoring_dep_timing.user_created_at_ms < day_cutoff,
        "creator user event should be outside the hot last-day window: user_created_at_ms={} day_cutoff={}",
        authoring_dep_timing.user_created_at_ms,
        day_cutoff
    );
    assert!(
        authoring_dep_timing.peer_shared_created_at_ms < day_cutoff,
        "creator peer_shared event should be outside the hot last-day window: peer_shared_created_at_ms={} day_cutoff={}",
        authoring_dep_timing.peer_shared_created_at_ms,
        day_cutoff
    );
    assert!(
        expected_day > 0 && expected_day < total_messages,
        "expected a non-empty hot range smaller than the full history: expected_day={} total_messages={}",
        expected_day,
        total_messages
    );

    let invite_link = create_invite_with_spki(
        &alice_db,
        &daemon_listen_addr(&alice_db),
        Some(&daemon_identity_fingerprint(&alice_db)),
    );
    let mut bob_daemon = start_daemon_with_options(
        &bob_db,
        &DaemonOptions {
            disable_discovery: true,
            last_day_only_sync: true,
            extra_env: daemon_env,
            ..Default::default()
        },
    );

    let bench_start = Instant::now();
    accept_invite_with_identity_on_running_daemon(
        &bob_db,
        &invite_link,
        "bob",
        "laptop",
        Duration::from_secs(30),
    );

    let (newest_timing, newest_visible_wall_ms, bob_total_at_newest) =
        wait_for_newest_message_visible(&bob_db, Duration::from_secs(120));
    let newest_visible_secs = bench_start.elapsed().as_secs_f64();
    assert!(
        newest_visible_secs <= newest_visible_budget_secs,
        "newest message should become visible quickly in last-day-only mode: visible_secs={:.2} budget_secs={:.2} bob_total_at_newest={}",
        newest_visible_secs,
        newest_visible_budget_secs,
        bob_total_at_newest
    );
    assert!(
        bob_total_at_newest < total_messages,
        "newest message should become visible before full history projection: bob_total_at_newest={} total_messages={}",
        bob_total_at_newest,
        total_messages
    );

    let hot_complete_ms =
        wait_for_message_count_exact(&bob_db, expected_day, Duration::from_secs(120));
    thread::sleep(Duration::from_secs(1));
    let bob_total_after_hot = message_count_sql(&bob_db);
    let bob_day_after_hot = message_count_since_sql(&bob_db, day_cutoff);
    assert_eq!(
        bob_total_after_hot, expected_day,
        "last-day-only mode should not project cold messages"
    );
    assert_eq!(
        bob_day_after_hot, expected_day,
        "all hot-range messages should be projected once dep sync completes"
    );
    assert!(
        newest_timing.projected_at_ms.is_some(),
        "newest message should be visible once wait_for_newest_message_visible returns"
    );

    let summary = format!(
        "=== last-day-only dep sync ===\n  Messages preloaded on inviter: {total_messages}\n  Hot range messages: {expected_day}\n  Aged auth deps: user={} peer_shared={}\n  Newest message: created_at={} visible in {:.2}s\n  Bob projected at newest visibility: {}\n  Bob projected after hot completion: {} in {:.2}s\n",
        authoring_dep_timing.user_created_at_ms,
        authoring_dep_timing.peer_shared_created_at_ms,
        newest_timing.created_at_ms.unwrap_or_default(),
        newest_visible_secs,
        bob_total_at_newest,
        bob_total_after_hot,
        elapsed_secs(
            newest_visible_wall_ms.min(hot_complete_ms),
            Some(hot_complete_ms),
        ),
    );
    eprintln!("\n{summary}");
    write_summary(
        &format!(
            "daemon_tiered_window_perf_test.last_day_only_{}",
            total_messages
        ),
        &summary,
    );

    stop_daemon(&bob_db, &mut bob_daemon);
    wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));
    stop_daemon(&alice_db, &mut alice_daemon);
    wait_for_daemon_stopped(&alice_db, Duration::from_secs(10));
}
