//! Low-memory sync budget tests.
//!
//! These tests run one daemon per peer so VmHWM is measured per daemon, not as
//! one process-shared RSS sample. For realism, the sender stays normal and only
//! the receiver restarts in `LOW_MEM_IOS=1` before the recent delta arrives.

mod cli_harness;

use std::time::{Duration, Instant};

use cli_harness::{
    accept_invite, active_tenant_peer_id, create_invite, create_workspace_with_details,
    daemon_listen_addr, ensure_active_peer, message_count_sql, peak_rss_mib_for_pid,
    start_daemon_with_options, stop_daemon, wait_for_active_tenant_ready, wait_for_daemon_stopped,
    wait_for_live_sync_session, DaemonOptions,
};

const WEEK_MS: i64 = 7 * 24 * 60 * 60 * 1000;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<f64>().ok())
        .unwrap_or(default)
}

fn current_timestamp_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_millis() as i64
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

fn wait_for_message_count(db: &str, expected: i64, timeout: Duration) {
    let start = Instant::now();
    loop {
        let count = message_count_sql(db);
        if count >= expected {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "message_count timed out after {:?} for db={}: expected_at_least={} actual={}",
            timeout,
            db,
            expected,
            count
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_message_count_since(db: &str, cutoff_ms: i64, expected: i64, timeout: Duration) {
    let start = Instant::now();
    loop {
        let count = message_count_since_sql(db, cutoff_ms);
        if count >= expected {
            return;
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
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn generate_messages_with_span(db: &str, count: usize, history_span: &str) {
    ensure_active_peer(db, Duration::from_secs(10));
    let peer_id = cli_harness::active_tenant_peer_id(db).expect("active tenant peer id");
    let chunk_size = std::env::var("TOPO_TEST_GENERATE_CHUNK_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(100_000);
    let mut remaining = count;
    while remaining > 0 {
        let next = remaining.min(chunk_size);
        topo::event_modules::message::commands::generate_for_peer(
            db,
            &peer_id,
            next,
            Some(history_span),
        )
        .expect("generate synthetic messages with span");
        remaining -= next;
    }
}

fn restart_receiver_lowmem(db: &str) -> cli_harness::HarnessDaemon {
    start_daemon_with_options(
        db,
        &DaemonOptions {
            disable_discovery: true,
            extra_env: vec![
                ("LOW_MEM_IOS".to_string(), "1".to_string()),
                (
                    "LOW_MEM_WAL_CAP_MIB".to_string(),
                    std::env::var("LOW_MEM_WAL_CAP_MIB").unwrap_or_else(|_| "12".to_string()),
                ),
            ],
            ..Default::default()
        },
    )
}

fn timeout_for_events(total_events: usize, min_secs: u64) -> Duration {
    let scaled_secs = ((total_events / 1_000).max(1) as u64) * 6;
    Duration::from_secs(scaled_secs.max(min_secs))
}

fn run_lowmem_delta_budget_case(
    label: &str,
    baseline_events: usize,
    delta_events: usize,
    budget_mib: f64,
) {
    let tmpdir = tempfile::tempdir().expect("create tempdir");
    let alice_db = tmpdir.path().join(format!("{label}-alice.db"));
    let bob_db = tmpdir.path().join(format!("{label}-bob.db"));
    let alice_db = alice_db.to_str().expect("alice db path").to_string();
    let bob_db = bob_db.to_str().expect("bob db path").to_string();

    create_workspace_with_details(&alice_db, "lowmem", "alice", "desktop");
    let mut alice_daemon = start_daemon_with_options(
        &alice_db,
        &DaemonOptions {
            disable_discovery: true,
            ..Default::default()
        },
    );
    ensure_active_peer(&alice_db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&alice_db, Duration::from_secs(60));

    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));
    accept_invite(&bob_db, &invite_link);

    let mut bob_daemon = start_daemon_with_options(
        &bob_db,
        &DaemonOptions {
            disable_discovery: true,
            ..Default::default()
        },
    );
    ensure_active_peer(&bob_db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(60));
    wait_for_live_sync_session(&alice_db, Duration::from_secs(60));
    wait_for_live_sync_session(&bob_db, Duration::from_secs(60));

    generate_messages_with_span(&alice_db, baseline_events, "365d");
    let baseline_timeout = timeout_for_events(baseline_events, 300);
    wait_for_message_count(&alice_db, baseline_events as i64, baseline_timeout);
    wait_for_message_count(&bob_db, baseline_events as i64, baseline_timeout);

    stop_daemon(&bob_db, &mut bob_daemon);
    wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));

    bob_daemon = restart_receiver_lowmem(&bob_db);
    let bob_pid = bob_daemon.child().id();
    ensure_active_peer(&bob_db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(60));
    wait_for_live_sync_session(&alice_db, Duration::from_secs(60));
    wait_for_live_sync_session(&bob_db, Duration::from_secs(60));

    let week_cutoff_ms = current_timestamp_ms() - WEEK_MS;
    let alice_recent_before_delta = message_count_since_sql(&alice_db, week_cutoff_ms);
    let bob_recent_before_delta = message_count_since_sql(&bob_db, week_cutoff_ms);

    generate_messages_with_span(&alice_db, delta_events, "6d");

    let expected_total = baseline_events as i64 + delta_events as i64;
    let expected_alice_recent = alice_recent_before_delta + delta_events as i64;
    let expected_recent = bob_recent_before_delta + delta_events as i64;
    let delta_timeout = timeout_for_events(baseline_events + delta_events, 300);
    wait_for_message_count(&alice_db, expected_total, delta_timeout);
    wait_for_message_count(&bob_db, expected_total, delta_timeout);
    wait_for_message_count_since(
        &alice_db,
        week_cutoff_ms,
        expected_alice_recent,
        delta_timeout,
    );
    wait_for_message_count_since(&bob_db, week_cutoff_ms, expected_recent, delta_timeout);

    let bob_peak = peak_rss_mib_for_pid(bob_pid).expect("bob daemon VmHWM unavailable");
    assert!(
        bob_peak <= budget_mib,
        "low_mem receiver RSS budget exceeded: bob_peak={:.2} MiB budget={:.2} MiB baseline={} delta={}",
        bob_peak,
        budget_mib,
        baseline_events,
        delta_events
    );

    eprintln!();
    eprintln!("=== Low-mem delta budget ({label}) ===");
    eprintln!("  Baseline:       {}", baseline_events);
    eprintln!("  Delta (<=1w):   {}", delta_events);
    eprintln!("  Alice recent pre: {}", alice_recent_before_delta);
    eprintln!("  Alice recent end: {}", expected_alice_recent);
    eprintln!("  Bob recent pre: {}", bob_recent_before_delta);
    eprintln!("  Bob recent end: {}", expected_recent);
    eprintln!("  Bob peak RSS:   {:.2} MiB", bob_peak);
    eprintln!("  Budget:         {:.2} MiB", budget_mib);
    eprintln!();

    stop_daemon(&bob_db, &mut bob_daemon);
    stop_daemon(&alice_db, &mut alice_daemon);
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "daemon VmHWM sanity only; use lowmem cgroup for hard gates"]
fn low_mem_ios_budget_smoke_10k() {
    let baseline_events = env_usize("LOW_MEM_IOS_BASELINE_EVENTS", 500_000);
    let delta_events = env_usize("LOW_MEM_IOS_DELTA_EVENTS", 10_000);
    let budget_mib = env_f64("LOW_MEM_IOS_BUDGET_MIB", 24.0);
    run_lowmem_delta_budget_case("smoke", baseline_events, delta_events, budget_mib);
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "long-running daemon VmHWM soak; run explicitly"]
fn low_mem_ios_budget_soak_million() {
    let baseline_events = env_usize("LOW_MEM_IOS_SOAK_BASELINE_EVENTS", 1_000_000);
    let delta_events = env_usize("LOW_MEM_IOS_SOAK_DELTA_EVENTS", 10_000);
    let budget_mib = env_f64("LOW_MEM_IOS_SOAK_BUDGET_MIB", 24.0);
    run_lowmem_delta_budget_case("soak", baseline_events, delta_events, budget_mib);
}

/// Measure how lowmem RSS grows as a function of events-in-sync-range and
/// baseline (already-stored) events.  Alice has N events, Bob starts fresh in
/// lowmem, syncs, and we measure Bob's peak RSS.
///
/// Run: TMPDIR=/mnt/storage/tmp cargo test --release --test low_mem_test \
///        -- lowmem_rss_scaling --nocapture --ignored
fn run_lowmem_fresh_sync(label: &str, events: usize, history_span: &str) -> f64 {
    let tmpdir = tempfile::tempdir().expect("create tempdir");
    let alice_db = tmpdir.path().join(format!("{label}-alice.db"));
    let bob_db = tmpdir.path().join(format!("{label}-bob.db"));
    let alice_db = alice_db.to_str().unwrap().to_string();
    let bob_db = bob_db.to_str().unwrap().to_string();

    create_workspace_with_details(&alice_db, "lowmem", "alice", "desktop");
    let mut alice_daemon = start_daemon_with_options(
        &alice_db,
        &DaemonOptions {
            disable_discovery: true,
            ..Default::default()
        },
    );
    ensure_active_peer(&alice_db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&alice_db, Duration::from_secs(60));

    generate_messages_with_span(&alice_db, events, history_span);
    wait_for_message_count(&alice_db, events as i64, timeout_for_events(events, 120));

    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));
    accept_invite(&bob_db, &invite_link);

    let mut bob_daemon = restart_receiver_lowmem(&bob_db);
    let bob_pid = bob_daemon.child().id();
    ensure_active_peer(&bob_db, Duration::from_secs(10));
    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(60));
    wait_for_live_sync_session(&alice_db, Duration::from_secs(60));
    wait_for_live_sync_session(&bob_db, Duration::from_secs(60));

    // For events within the lowmem sync range (LastDay + LastWeek), Bob should
    // sync them all.  For events outside that range, Bob won't see them.
    let week_cutoff_ms = current_timestamp_ms() - WEEK_MS;
    let alice_recent = message_count_since_sql(&alice_db, week_cutoff_ms);
    let timeout = timeout_for_events(events, 300);
    wait_for_message_count_since(&bob_db, week_cutoff_ms, alice_recent, timeout);

    let bob_peak = peak_rss_mib_for_pid(bob_pid).unwrap_or(0.0);
    let bob_total = message_count_sql(&bob_db);
    let bob_recent = message_count_since_sql(&bob_db, week_cutoff_ms);

    eprintln!(
        "  {label:>20}: events={events:>7} span={history_span:>5} \
         bob_total={bob_total:>7} bob_recent={bob_recent:>7} \
         bob_peak_rss={bob_peak:.1} MiB"
    );

    stop_daemon(&bob_db, &mut bob_daemon);
    stop_daemon(&alice_db, &mut alice_daemon);
    bob_peak
}

/// Hard gate: lowmem receiver syncing 20k recent events must stay under 24 MiB.
/// This runs as part of the default test suite (not ignored).
#[test]
#[cfg(target_os = "linux")]
fn lowmem_20k_fresh_sync_under_budget() {
    let budget_mib = 24.0;
    let bob_peak = run_lowmem_fresh_sync("gate-20k", 20_000, "6d");
    assert!(
        bob_peak <= budget_mib,
        "lowmem 20k fresh sync exceeded {budget_mib} MiB budget: peak={bob_peak:.1} MiB"
    );
}

#[test]
#[cfg(target_os = "linux")]
#[ignore = "scaling measurement; run explicitly"]
fn lowmem_rss_scaling() {
    eprintln!();
    eprintln!("=== Lowmem RSS scaling: events in sync range (6d span) ===");
    for &n in &[1_000, 5_000, 10_000, 20_000, 50_000] {
        run_lowmem_fresh_sync(&format!("range-{n}"), n, "6d");
    }

    eprintln!();
    eprintln!("=== Lowmem RSS scaling: baseline outside range (365d span) ===");
    for &n in &[1_000, 10_000, 50_000, 100_000] {
        run_lowmem_fresh_sync(&format!("baseline-{n}"), n, "365d");
    }
    eprintln!();
}
