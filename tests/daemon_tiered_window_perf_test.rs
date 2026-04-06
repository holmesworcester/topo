//! Tiered window catch-up benchmark:
//! today -> yesterday -> last week -> last 12 weeks -> full history.
//!
//! Run with:
//! `cargo test --release --test daemon_tiered_window_perf_test -- --ignored --nocapture --test-threads=1`

mod cli_harness;
mod perf_network_shaper;

use std::collections::HashSet;
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

struct NewestSignerChainTiming {
    signer_created_at_ms: i64,
    signer_chain_depth: usize,
    authored_message_count: i64,
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
    [
        "TOPO_GENERATE_MESSAGE_SPREAD_MS",
        "TOPO_EVENT_TIMELINE",
        "TOPO_SYNC_LAST_DAY_ONLY",
    ]
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

fn message_count_in_range_sql(
    db: &str,
    min_created_at_ms: i64,
    max_created_at_ms_exclusive: i64,
) -> i64 {
    let conn = topo::db::open_connection(db).expect("open db for message_count_in_range");
    let peer_id = cli_harness::active_tenant_peer_id(db).expect("active tenant peer id");
    conn.query_row(
        "SELECT COUNT(*)
         FROM messages
         WHERE recorded_by = ?1
           AND created_at >= ?2
           AND created_at < ?3",
        rusqlite::params![peer_id, min_created_at_ms, max_created_at_ms_exclusive],
        |row| row.get(0),
    )
    .expect("query message_count_in_range")
}

fn utc_day_start_ms(ts_ms: i64) -> i64 {
    topo::db::dep_claims::utc_day_start_ms(ts_ms)
}

fn range_timing_sql(
    db: &str,
    min_created_at_ms: Option<i64>,
    max_created_at_ms_exclusive: Option<i64>,
) -> RangeTiming {
    let conn = topo::db::open_connection(db).expect("open db for range_timing");
    let peer_id = cli_harness::active_tenant_peer_id(db).expect("active tenant peer id");
    conn.query_row(
        "SELECT COUNT(*), MAX(t.first_stored_at), MAX(t.projected_at)
         FROM messages m
         LEFT JOIN event_timeline t ON t.event_id = m.message_id
         WHERE m.recorded_by = ?1
           AND (?2 IS NULL OR m.created_at >= ?2)
           AND (?3 IS NULL OR m.created_at < ?3)",
        rusqlite::params![peer_id, min_created_at_ms, max_created_at_ms_exclusive],
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

fn signer_chain_depth(conn: &rusqlite::Connection, event_id_b64: &str) -> usize {
    let mut seen = HashSet::new();
    let mut current = Some(event_id_b64.to_string());
    let mut depth = 0usize;

    while let Some(event_id_b64) = current {
        assert!(
            seen.insert(event_id_b64.clone()),
            "unexpected cycle in signer chain at {}",
            event_id_b64
        );
        depth = depth.saturating_add(1);
        let blob: Vec<u8> = conn
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![&event_id_b64],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| panic!("load signer chain blob for {}", event_id_b64));
        let parsed = topo::event_modules::parse_event(&blob)
            .unwrap_or_else(|err| panic!("parse signer chain event {}: {}", event_id_b64, err));
        current = parsed
            .signer_fields()
            .map(|(event_id, _)| topo::crypto::event_id_to_base64(&event_id));
    }

    depth
}

fn newest_message_signer_chain_timing_sql(db: &str) -> NewestSignerChainTiming {
    let conn = topo::db::open_connection(db).expect("open db for newest_message_signer_chain");
    let peer_id = cli_harness::active_tenant_peer_id(db).expect("active tenant peer id");
    let (signer_event_id_b64, signer_recorded_by, signer_created_at_ms): (String, String, i64) =
        conn.query_row(
            "SELECT ps.event_id, ps.recorded_by, e.created_at
             FROM peers_shared ps
             JOIN events e ON e.event_id = ps.event_id
             WHERE ps.recorded_by <> ?1
             ORDER BY e.created_at DESC, ps.event_id DESC
             LIMIT 1",
            rusqlite::params![&peer_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("load newest seeded signer");
    let authored_message_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![&signer_recorded_by],
            |row| row.get(0),
        )
        .expect("count newest signer messages");

    NewestSignerChainTiming {
        signer_created_at_ms,
        signer_chain_depth: signer_chain_depth(&conn, &signer_event_id_b64),
        authored_message_count,
    }
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

fn write_summary(summary_key: &str, summary: &str) {
    let summary_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/perf-results");
    std::fs::create_dir_all(&summary_dir).expect("create target/perf-results");
    std::fs::write(summary_dir.join(format!("{summary_key}.summary")), summary)
        .expect("write benchmark summary file");
}

fn run_tiered_window_bench(total_messages_override: Option<i64>, hot_only: bool) {
    std::env::set_var(
        "TOPO_GENERATE_MESSAGE_SPREAD_MS",
        THREE_YEARS_MS.to_string(),
    );
    std::env::set_var("TOPO_EVENT_TIMELINE", "1");
    std::env::set_var("TOPO_EVENT_TIMELINE_GROUPS", "persist,projection");
    let prev_sync_last_day_only = std::env::var("TOPO_SYNC_LAST_DAY_ONLY").ok();
    if hot_only {
        std::env::set_var("TOPO_SYNC_LAST_DAY_ONLY", "1");
    } else {
        std::env::remove_var("TOPO_SYNC_LAST_DAY_ONLY");
    }

    let total_messages = total_messages_override
        .unwrap_or_else(|| env_i64("TOPO_TIERED_SYNC_TOTAL_MESSAGES", 50_000));
    let device_chain_length = env_i64("TOPO_TIERED_SYNC_DEVICE_CHAIN_LENGTH", 0).max(0) as usize;
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
        device_chain_length,
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
    let newest_signer_chain = newest_message_signer_chain_timing_sql(&alice_db);
    let today_start_ms = utc_day_start_ms(measurement_now_ms);
    let yesterday_start_ms = today_start_ms - DAY_MS;
    let week_start_ms = today_start_ms - WEEK_MS;
    let twelve_week_start_ms = today_start_ms - TWELVE_WEEK_MS;
    let tomorrow_start_ms = today_start_ms + DAY_MS;
    assert!(
        authoring_dep_timing.user_created_at_ms < yesterday_start_ms,
        "creator user event should be outside the hot today/yesterday window: user_created_at_ms={} yesterday_start_ms={}",
        authoring_dep_timing.user_created_at_ms,
        yesterday_start_ms
    );
    assert!(
        authoring_dep_timing.peer_shared_created_at_ms < yesterday_start_ms,
        "creator peer_shared event should be outside the hot today/yesterday window: peer_shared_created_at_ms={} yesterday_start_ms={}",
        authoring_dep_timing.peer_shared_created_at_ms,
        yesterday_start_ms
    );
    assert!(
        newest_signer_chain.signer_created_at_ms < yesterday_start_ms,
        "newest message signer should be outside the hot today/yesterday window: signer_created_at_ms={} yesterday_start_ms={}",
        newest_signer_chain.signer_created_at_ms,
        yesterday_start_ms
    );
    assert_eq!(
        newest_signer_chain.signer_chain_depth,
        5 + device_chain_length.saturating_mul(2),
        "latest peer_shared signer chain depth should reflect the seeded device chain"
    );
    assert_eq!(
        newest_signer_chain.authored_message_count, total_messages,
        "seeded messages should be authored by the tip of the device chain"
    );
    let _expected_today = message_count_in_range_sql(&alice_db, today_start_ms, tomorrow_start_ms);
    let expected_hot = message_count_since_sql(&alice_db, yesterday_start_ms);
    assert!(
        expected_hot > 0,
        "benchmark requires at least one hot today/yesterday message: total_messages={} end_at_ms={} yesterday_start_ms={}",
        total_messages,
        measurement_now_ms,
        yesterday_start_ms
    );
    let expected_week = message_count_in_range_sql(&alice_db, week_start_ms, yesterday_start_ms);
    let expected_twelve_weeks =
        message_count_in_range_sql(&alice_db, twelve_week_start_ms, week_start_ms);

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

    let hot_projected_ms = if expected_hot > 0 {
        wait_for_message_count_since(
            &bob_db,
            yesterday_start_ms,
            expected_hot,
            Duration::from_secs(1200),
        )
    } else {
        metric_start_ms
    };
    let full_wall_secs;
    let summary;
    let summary_key;

    let today_timing = range_timing_sql(&bob_db, Some(today_start_ms), Some(tomorrow_start_ms));
    let hot_timing = range_timing_sql(&bob_db, Some(yesterday_start_ms), Some(tomorrow_start_ms));
    let newest_timing = newest_message_timing_sql(&bob_db);

    if hot_only {
        full_wall_secs = bench_start.elapsed().as_secs_f64();
        let visible_total = message_count_sql(&bob_db);
        summary = format!(
            "=== hot-only catchup ===
  Window ladder: Today -> Yesterday
  Messages preloaded on inviter: {total_messages}
  Network profile: {}
  Generated spread: 3 years
  Linked devices seeded: {} (dependency depth {}, tip_created_at={}, tip_authored_messages={})
  Aged auth deps: user={} peer_shared={}
  Metric start: invite accept on running joiner daemon
  Today:         {} msgs durable in {:.2}s projected in {:.2}s
  Hot (2 days):  {} msgs durable in {:.2}s projected in {:.2}s
  Visible total: {} msgs
  Newest message: created_at={} durable in {:.2}s visible in {:.2}s
  Hot-range wall: {:.2}s
",
            network_profile
                .map(|profile| profile.slug)
                .unwrap_or("loopback"),
            device_chain_length,
            newest_signer_chain.signer_chain_depth,
            newest_signer_chain.signer_created_at_ms,
            newest_signer_chain.authored_message_count,
            authoring_dep_timing.user_created_at_ms,
            authoring_dep_timing.peer_shared_created_at_ms,
            today_timing.count,
            elapsed_secs(metric_start_ms, today_timing.first_stored_at_ms),
            elapsed_secs(metric_start_ms, today_timing.projected_at_ms),
            hot_timing.count,
            elapsed_secs(metric_start_ms, hot_timing.first_stored_at_ms),
            elapsed_secs(
                metric_start_ms,
                hot_timing.projected_at_ms.or(Some(hot_projected_ms))
            ),
            visible_total,
            newest_timing.created_at_ms.unwrap_or_default(),
            elapsed_secs(metric_start_ms, newest_timing.first_stored_at_ms),
            elapsed_secs(metric_start_ms, newest_timing.projected_at_ms),
            full_wall_secs,
        );
        summary_key = format!(
            "daemon_tiered_window_perf_test.hot_only{}_{}_{}",
            if device_chain_length > 0 {
                format!("_chain{}_", device_chain_length)
            } else {
                "_".to_string()
            },
            total_messages,
            network_profile
                .map(|profile| profile.slug)
                .unwrap_or("loopback"),
        );
    } else {
        let week_projected_ms = if expected_week > 0 {
            wait_for_message_count(
                &bob_db,
                expected_hot + expected_week,
                Duration::from_secs(1200),
            )
        } else {
            metric_start_ms
        };
        let twelve_week_projected_ms = if expected_twelve_weeks > 0 {
            wait_for_message_count(
                &bob_db,
                expected_hot + expected_week + expected_twelve_weeks,
                Duration::from_secs(1200),
            )
        } else {
            metric_start_ms
        };
        let full_projected_ms =
            wait_for_message_count(&bob_db, total_messages, Duration::from_secs(1200));
        full_wall_secs = bench_start.elapsed().as_secs_f64();

        let week_timing = range_timing_sql(&bob_db, Some(week_start_ms), Some(yesterday_start_ms));
        let twelve_week_timing =
            range_timing_sql(&bob_db, Some(twelve_week_start_ms), Some(week_start_ms));
        let all_timing = range_timing_sql(&bob_db, None, None);

        summary = format!(
            "=== tiered window catchup ===
  Window ladder: Today -> Yesterday -> LastWeek -> Last12Weeks -> Full
  Messages preloaded on inviter: {total_messages}
  Network profile: {}
  Generated spread: 3 years
  Linked devices seeded: {} (dependency depth {}, tip_created_at={}, tip_authored_messages={})
  Aged auth deps: user={} peer_shared={}
  Metric start: invite accept on running joiner daemon
  Today:         {} msgs durable in {:.2}s projected in {:.2}s
  Hot (2 days):  {} msgs durable in {:.2}s projected in {:.2}s
  Last week:     {} msgs durable in {:.2}s projected in {:.2}s
  Last 12 weeks: {} msgs durable in {:.2}s projected in {:.2}s
  All:           {} msgs durable in {:.2}s projected in {:.2}s
  Newest message: created_at={} durable in {:.2}s visible in {:.2}s
  Full catchup wall: {:.2}s
",
            network_profile
                .map(|profile| profile.slug)
                .unwrap_or("loopback"),
            device_chain_length,
            newest_signer_chain.signer_chain_depth,
            newest_signer_chain.signer_created_at_ms,
            newest_signer_chain.authored_message_count,
            authoring_dep_timing.user_created_at_ms,
            authoring_dep_timing.peer_shared_created_at_ms,
            today_timing.count,
            elapsed_secs(metric_start_ms, today_timing.first_stored_at_ms),
            elapsed_secs(metric_start_ms, today_timing.projected_at_ms),
            hot_timing.count,
            elapsed_secs(metric_start_ms, hot_timing.first_stored_at_ms),
            elapsed_secs(
                metric_start_ms,
                hot_timing.projected_at_ms.or(Some(hot_projected_ms))
            ),
            week_timing.count,
            elapsed_secs(metric_start_ms, week_timing.first_stored_at_ms),
            elapsed_secs(
                metric_start_ms,
                week_timing.projected_at_ms.or(Some(week_projected_ms))
            ),
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
            elapsed_secs(
                metric_start_ms,
                all_timing.projected_at_ms.or(Some(full_projected_ms))
            ),
            newest_timing.created_at_ms.unwrap_or_default(),
            elapsed_secs(metric_start_ms, newest_timing.first_stored_at_ms),
            elapsed_secs(metric_start_ms, newest_timing.projected_at_ms),
            full_wall_secs,
        );
        summary_key = format!(
            "daemon_tiered_window_perf_test.disjoint{}_{}_{}",
            if device_chain_length > 0 {
                format!("_chain{}_", device_chain_length)
            } else {
                "_".to_string()
            },
            total_messages,
            network_profile
                .map(|profile| profile.slug)
                .unwrap_or("loopback"),
        );
    }
    eprintln!("\n{summary}");
    write_summary(&summary_key, &summary);

    match prev_sync_last_day_only {
        Some(value) => std::env::set_var("TOPO_SYNC_LAST_DAY_ONLY", value),
        None => std::env::remove_var("TOPO_SYNC_LAST_DAY_ONLY"),
    }

    stop_daemon(&bob_db, &mut bob_daemon);
    wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));
    stop_daemon(&alice_db, &mut alice_daemon);
    wait_for_daemon_stopped(&alice_db, Duration::from_secs(10));
}

#[test]
#[ignore]
fn perf_tiered_window_50k_parallel() {
    run_tiered_window_bench(None, false);
}

#[test]
#[ignore]
fn perf_tiered_window_100k_parallel() {
    run_tiered_window_bench(Some(100_000), false);
}

#[test]
#[ignore]
fn perf_hot_only_window_100k_parallel() {
    run_tiered_window_bench(Some(100_000), true);
}

#[test]
fn hot_only_window_syncs_32_linked_devices() {
    let prev = std::env::var("TOPO_TIERED_SYNC_DEVICE_CHAIN_LENGTH").ok();
    std::env::set_var("TOPO_TIERED_SYNC_DEVICE_CHAIN_LENGTH", "32");
    run_tiered_window_bench(Some(256), true);
    match prev {
        Some(value) => std::env::set_var("TOPO_TIERED_SYNC_DEVICE_CHAIN_LENGTH", value),
        None => std::env::remove_var("TOPO_TIERED_SYNC_DEVICE_CHAIN_LENGTH"),
    }
}

#[test]
#[ignore]
fn perf_hot_only_window_chain_64_parallel() {
    let prev = std::env::var("TOPO_TIERED_SYNC_DEVICE_CHAIN_LENGTH").ok();
    std::env::set_var("TOPO_TIERED_SYNC_DEVICE_CHAIN_LENGTH", "64");
    run_tiered_window_bench(Some(256), true);
    match prev {
        Some(value) => std::env::set_var("TOPO_TIERED_SYNC_DEVICE_CHAIN_LENGTH", value),
        None => std::env::remove_var("TOPO_TIERED_SYNC_DEVICE_CHAIN_LENGTH"),
    }
}
