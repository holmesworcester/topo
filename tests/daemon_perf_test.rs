//! Daemon-based sync throughput benchmarks.
//!
//! These benchmarks use real daemon processes, warm the topology before timing,
//! and report per-daemon VmHWM instead of process-shared RSS.

mod cli_harness;

use std::thread;
use std::time::{Duration, Instant};

use cli_harness::{
    accept_invite_with_identity, assert_eventually, create_invite_with_spki, create_workspace,
    daemon_listen_addr, daemon_transport_fingerprint, ensure_active_peer, generate_messages,
    message_count_sql, peak_rss_mib_for_pid, send_message, start_daemon, wait_for_daemon_stopped,
};
use topo::testutil::DaemonGuard;

struct SharedWorkspaceBench {
    _tmpdir: tempfile::TempDir,
    alice_db: String,
    bob_db: String,
    alice_daemon: DaemonGuard,
    alice_pid: u32,
    bob_daemon: DaemonGuard,
    bob_pid: u32,
}

impl SharedWorkspaceBench {
    fn new() -> Self {
        let tmpdir = tempfile::tempdir().unwrap();
        let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
        let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

        create_workspace(&alice_db);
        wait_for_daemon_stopped(&alice_db, Duration::from_secs(10));
        let mut alice_daemon = start_daemon(&alice_db);
        let alice_pid = alice_daemon.child().id();

        let invite_link = create_invite_with_spki(
            &alice_db,
            &daemon_listen_addr(&alice_db),
            Some(&daemon_transport_fingerprint(&alice_db)),
        );
        accept_invite_with_identity(&bob_db, &invite_link, "bob", "laptop");
        wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));

        let mut bob_daemon = start_daemon(&bob_db);
        let bob_pid = bob_daemon.child().id();

        ensure_active_peer(&alice_db, Duration::from_secs(10));
        ensure_active_peer(&bob_db, Duration::from_secs(10));

        Self {
            _tmpdir: tmpdir,
            alice_db,
            bob_db,
            alice_daemon,
            alice_pid,
            bob_daemon,
            bob_pid,
        }
    }

    fn warm_one_way(&self) -> i64 {
        let warm_eid = send_message(&self.alice_db, "warmup-alice");
        assert_eventually(
            &self.bob_db,
            &format!("has_event:{} >= 1", warm_eid),
            30_000,
        );
        wait_for_message_count(&self.bob_db, 1, Duration::from_secs(30));
        message_count_sql(&self.bob_db)
    }

    fn warm_bidirectional(&self) -> i64 {
        let alice_eid = send_message(&self.alice_db, "warmup-alice");
        let bob_eid = send_message(&self.bob_db, "warmup-bob");

        assert_eventually(
            &self.alice_db,
            &format!("has_event:{} >= 1", bob_eid),
            30_000,
        );
        assert_eventually(
            &self.bob_db,
            &format!("has_event:{} >= 1", alice_eid),
            30_000,
        );
        wait_for_message_count(&self.alice_db, 2, Duration::from_secs(30));
        wait_for_message_count(&self.bob_db, 2, Duration::from_secs(30));
        message_count_sql(&self.alice_db)
    }

    fn daemon_rss(&self) -> (f64, f64, f64) {
        let alice = peak_rss_mib_for_pid(self.alice_pid).expect("alice VmHWM unavailable");
        let bob = peak_rss_mib_for_pid(self.bob_pid).expect("bob VmHWM unavailable");
        (alice, bob, alice.max(bob))
    }
}

impl Drop for SharedWorkspaceBench {
    fn drop(&mut self) {
        let _ = self.alice_daemon.child().try_wait();
        let _ = self.bob_daemon.child().try_wait();
    }
}

fn wait_for_message_count(db: &str, expected: i64, timeout: Duration) {
    let start = Instant::now();
    loop {
        let count = message_count_sql(db);
        if count == expected {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "message_count timed out after {:?} for db={}: expected={}, actual={}",
            timeout,
            db,
            expected,
            count
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn emit_summary(
    summary_key: &str,
    title: &str,
    wall_secs: f64,
    messages: i64,
    msgs_per_sec: f64,
    alice_rss: f64,
    bob_rss: f64,
    max_rss: f64,
) {
    let summary = format!(
        "=== {title} ===\n  Wall time:    {wall_secs:.2}s\n  Messages:     {messages}\n  Msgs/s:       {msgs_per_sec:.0}\n  Peak RSS:     {max_rss:.1} MiB (max daemon VmHWM)\n  Alice peak RSS: {alice_rss:.1} MiB\n  Bob peak RSS:   {bob_rss:.1} MiB\n"
    );
    eprintln!("\n{summary}");
    let summary_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/perf-results");
    std::fs::create_dir_all(&summary_dir).expect("create target/perf-results");
    std::fs::write(summary_dir.join(format!("{summary_key}.summary")), summary)
        .expect("write benchmark summary file");
}

/// 50k one-way sync: generate on one side after the daemons are already connected.
#[test]
#[ignore]
fn perf_sync_50k() {
    const N: i64 = 50_000;

    let bench = SharedWorkspaceBench::new();
    let baseline = bench.warm_one_way();

    let start = Instant::now();
    generate_messages(&bench.alice_db, N as usize);
    wait_for_message_count(&bench.bob_db, baseline + N, Duration::from_secs(300));
    let wall_secs = start.elapsed().as_secs_f64();

    let (alice_rss, bob_rss, max_rss) = bench.daemon_rss();
    let msgs_per_sec = N as f64 / wall_secs;
    emit_summary(
        "daemon_perf_test.perf_sync_50k",
        "50k one-way sync (daemon, warm)",
        wall_secs,
        N,
        msgs_per_sec,
        alice_rss,
        bob_rss,
        max_rss,
    );
}

/// 10k bidirectional sync: both sides generate after the daemons are already connected.
#[test]
fn perf_sync_10k() {
    const PER_PEER: i64 = 5_000;
    const TOTAL: i64 = PER_PEER * 2;

    let bench = SharedWorkspaceBench::new();
    let baseline = bench.warm_bidirectional();

    let start = Instant::now();
    generate_messages(&bench.alice_db, PER_PEER as usize);
    generate_messages(&bench.bob_db, PER_PEER as usize);
    wait_for_message_count(&bench.alice_db, baseline + TOTAL, Duration::from_secs(120));
    wait_for_message_count(&bench.bob_db, baseline + TOTAL, Duration::from_secs(120));
    let wall_secs = start.elapsed().as_secs_f64();

    let (alice_rss, bob_rss, max_rss) = bench.daemon_rss();
    let msgs_per_sec = TOTAL as f64 / wall_secs;
    emit_summary(
        "daemon_perf_test.perf_sync_10k",
        "10k bidirectional sync (daemon, warm)",
        wall_secs,
        TOTAL,
        msgs_per_sec,
        alice_rss,
        bob_rss,
        max_rss,
    );
}

/// 10k continuous sync: connected daemons receive live writes from both sides.
#[test]
fn perf_continuous_10k() {
    const PER_PEER: i64 = 5_000;
    const TOTAL: i64 = PER_PEER * 2;

    let bench = SharedWorkspaceBench::new();
    let baseline = bench.warm_bidirectional();

    let alice_db = bench.alice_db.clone();
    let bob_db = bench.bob_db.clone();
    let start = Instant::now();
    let alice_writer = thread::spawn(move || generate_messages(&alice_db, PER_PEER as usize));
    let bob_writer = thread::spawn(move || generate_messages(&bob_db, PER_PEER as usize));
    alice_writer.join().expect("alice generate thread panicked");
    bob_writer.join().expect("bob generate thread panicked");
    wait_for_message_count(&bench.alice_db, baseline + TOTAL, Duration::from_secs(300));
    wait_for_message_count(&bench.bob_db, baseline + TOTAL, Duration::from_secs(300));
    let wall_secs = start.elapsed().as_secs_f64();

    let (alice_rss, bob_rss, max_rss) = bench.daemon_rss();
    let msgs_per_sec = TOTAL as f64 / wall_secs;
    emit_summary(
        "daemon_perf_test.perf_continuous_10k",
        "10k continuous sync (daemon, warm)",
        wall_secs,
        TOTAL,
        msgs_per_sec,
        alice_rss,
        bob_rss,
        max_rss,
    );
}

/// 100k one-way sync.
#[test]
#[ignore]
fn perf_sync_100k() {
    const N: i64 = 100_000;

    let bench = SharedWorkspaceBench::new();
    let baseline = bench.warm_one_way();

    let start = Instant::now();
    generate_messages(&bench.alice_db, N as usize);
    wait_for_message_count(&bench.bob_db, baseline + N, Duration::from_secs(600));
    let wall_secs = start.elapsed().as_secs_f64();

    let (alice_rss, bob_rss, max_rss) = bench.daemon_rss();
    let msgs_per_sec = N as f64 / wall_secs;
    emit_summary(
        "daemon_perf_test.perf_sync_100k",
        "100k one-way sync (daemon, warm)",
        wall_secs,
        N,
        msgs_per_sec,
        alice_rss,
        bob_rss,
        max_rss,
    );
}

/// 200k one-way sync.
#[test]
#[ignore]
fn perf_sync_200k() {
    const N: i64 = 200_000;

    let bench = SharedWorkspaceBench::new();
    let baseline = bench.warm_one_way();

    let start = Instant::now();
    generate_messages(&bench.alice_db, N as usize);
    wait_for_message_count(&bench.bob_db, baseline + N, Duration::from_secs(600));
    let wall_secs = start.elapsed().as_secs_f64();

    let (alice_rss, bob_rss, max_rss) = bench.daemon_rss();
    let msgs_per_sec = N as f64 / wall_secs;
    emit_summary(
        "daemon_perf_test.perf_sync_200k",
        "200k one-way sync (daemon, warm)",
        wall_secs,
        N,
        msgs_per_sec,
        alice_rss,
        bob_rss,
        max_rss,
    );
}

/// 500k one-way sync.
#[test]
#[ignore]
fn perf_sync_500k() {
    const N: i64 = 500_000;

    let bench = SharedWorkspaceBench::new();
    let baseline = bench.warm_one_way();

    let start = Instant::now();
    generate_messages(&bench.alice_db, N as usize);
    wait_for_message_count(&bench.bob_db, baseline + N, Duration::from_secs(1_200));
    let wall_secs = start.elapsed().as_secs_f64();

    let (alice_rss, bob_rss, max_rss) = bench.daemon_rss();
    let msgs_per_sec = N as f64 / wall_secs;
    emit_summary(
        "daemon_perf_test.perf_sync_500k",
        "500k one-way sync (daemon, warm)",
        wall_secs,
        N,
        msgs_per_sec,
        alice_rss,
        bob_rss,
        max_rss,
    );
}
