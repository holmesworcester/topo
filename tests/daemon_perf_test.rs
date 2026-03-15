//! Daemon-based sync throughput benchmarks.
//!
//! These benchmarks use real daemon processes, warm the topology before timing,
//! and report per-daemon VmHWM instead of process-shared RSS.

mod cli_harness;

use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use cli_harness::{
    assert_eventually, create_invite_with_spki, daemon_listen_addr, daemon_transport_fingerprint,
    ensure_active_peer, generate_messages, message_count_sql, peak_rss_mib_for_pid, send_message,
    start_daemon_with_options, topo_cmd, DaemonOptions,
};
use topo::testutil::DaemonGuard;

struct SharedWorkspaceBench {
    tmpdir: Option<tempfile::TempDir>,
    tmpdir_path: PathBuf,
    keep_tmpdir: bool,
    alice_db: String,
    bob_db: String,
    alice_daemon: DaemonGuard,
    alice_pid: u32,
    bob_daemon: DaemonGuard,
    bob_pid: u32,
}

impl SharedWorkspaceBench {
    fn new() -> Self {
        let keep_tmpdir = perf_debug_env("PERF_KEEP_TMPDIR");
        let (tmpdir, tmpdir_path) = if keep_tmpdir {
            let path = tempfile::tempdir().unwrap().keep();
            eprintln!(
                "PERF_KEEP_TMPDIR=1: preserving benchmark artifacts under {}",
                path.display()
            );
            (None, path)
        } else {
            let tmpdir = tempfile::tempdir().unwrap();
            let path = tmpdir.path().to_path_buf();
            (Some(tmpdir), path)
        };

        let alice_db = tmpdir_path.join("alice.db").to_str().unwrap().to_string();
        let bob_db = tmpdir_path.join("bob.db").to_str().unwrap().to_string();

        create_workspace_direct(&alice_db, "user", "device");
        let mut alice_daemon = start_perf_daemon(&alice_db, &tmpdir_path, "alice");
        let alice_pid = alice_daemon.child().id();

        let invite_link = create_invite_with_spki(
            &alice_db,
            &daemon_listen_addr(&alice_db),
            Some(&daemon_transport_fingerprint(&alice_db)),
        );
        accept_invite_direct(&bob_db, &invite_link, "bob", "laptop");

        let mut bob_daemon = start_perf_daemon(&bob_db, &tmpdir_path, "bob");
        let bob_pid = bob_daemon.child().id();

        ensure_active_peer(&alice_db, Duration::from_secs(10));
        ensure_active_peer(&bob_db, Duration::from_secs(10));
        maybe_enable_sync_logging(&alice_db);
        maybe_enable_sync_logging(&bob_db);

        Self {
            tmpdir,
            tmpdir_path,
            keep_tmpdir,
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
        if self.keep_tmpdir {
            eprintln!(
                "preserved perf benchmark artifacts at {}",
                self.tmpdir_path.display()
            );
            return;
        }
        if let Some(tmpdir) = self.tmpdir.take() {
            drop(tmpdir);
        }
    }
}

fn perf_debug_env(name: &str) -> bool {
    std::env::var(name)
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false)
}

fn start_perf_daemon(db: &str, tmpdir: &std::path::Path, label: &str) -> DaemonGuard {
    if !perf_debug_env("PERF_DAEMON_LOGS") {
        return start_daemon_with_options(
            db,
            &DaemonOptions {
                disable_discovery: true,
                ..Default::default()
            },
        );
    }
    start_daemon_with_options(
        db,
        &DaemonOptions {
            stdout_file: Some(tmpdir.join(format!("{label}.daemon.stdout.log"))),
            stderr_file: Some(tmpdir.join(format!("{label}.daemon.stderr.log"))),
            disable_discovery: true,
            ..Default::default()
        },
    )
}

fn create_workspace_direct(db: &str, username: &str, device_name: &str) {
    topo::event_modules::workspace::commands::create_workspace_for_db(
        db,
        "workspace",
        username,
        device_name,
    )
    .expect("create_workspace_for_db");
}

fn accept_invite_direct(db: &str, invite_link: &str, username: &str, device_name: &str) {
    topo::event_modules::workspace::commands::accept_invite(db, invite_link, username, device_name)
        .expect("accept_invite");
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
            "message_count timed out after {:?} for db={}: expected={}, actual={}\n{}",
            timeout,
            db,
            expected,
            count,
            format_bench_diagnostics(db)
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_message_count_pair(left_db: &str, right_db: &str, expected: i64, timeout: Duration) {
    let start = Instant::now();
    loop {
        let left = message_count_sql(left_db);
        let right = message_count_sql(right_db);
        if left == expected && right == expected {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "paired message_count timed out after {:?}\nleft db={}: expected={}, actual={}\n{}\nright db={}: expected={}, actual={}\n{}",
            timeout,
            left_db,
            expected,
            left,
            format_bench_diagnostics(left_db),
            right_db,
            expected,
            right,
            format_bench_diagnostics(right_db),
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn maybe_enable_sync_logging(db: &str) {
    if !perf_debug_env("PERF_ENABLE_SYNC_LOG") {
        return;
    }
    let out = topo_cmd(db, &["sync-log", "enable", "--all-runs"]);
    assert!(
        out.status.success(),
        "sync-log enable failed for {}: {}",
        db,
        String::from_utf8_lossy(&out.stderr)
    );
}

fn query_count(conn: &rusqlite::Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get::<_, i64>(0))
        .unwrap_or(-1)
}

fn format_bench_diagnostics(db: &str) -> String {
    let conn = match rusqlite::Connection::open(db) {
        Ok(conn) => conn,
        Err(err) => return format!("diagnostics unavailable: failed to open db: {err}"),
    };

    let recorded_events = query_count(&conn, "SELECT COUNT(*) FROM recorded_events");
    let wanted_events = query_count(&conn, "SELECT COUNT(*) FROM wanted_events");
    let blocked_events = query_count(&conn, "SELECT COUNT(*) FROM blocked_events");
    let project_queue = query_count(&conn, "SELECT COUNT(*) FROM project_queue");
    let sync_runs = query_count(&conn, "SELECT COUNT(*) FROM sync_runs");

    let mut out = String::new();
    out.push_str("bench diagnostics:\n");
    out.push_str(&format!(
        "  recorded_events={recorded_events} wanted_events={wanted_events} blocked_events={blocked_events} project_queue={project_queue} sync_runs={sync_runs}\n"
    ));

    if let Ok(mut stmt) = conn.prepare(
        "SELECT run_id, direction, role, rounds, events_sent, events_received, bytes_sent, bytes_received, outcome, COALESCE(error, '')
         FROM sync_runs
         ORDER BY run_id DESC
         LIMIT 6",
    ) {
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                    row.get::<_, String>(8)?,
                    row.get::<_, String>(9)?,
                ))
            })
            .ok();
        if let Some(rows) = rows {
            out.push_str("  recent_runs:\n");
            for row in rows.flatten() {
                let (run_id, direction, role, rounds, sent, recv, bytes_sent, bytes_recv, outcome, error) = row;
                out.push_str(&format!(
                    "    run_id={run_id} {direction}/{role} rounds={rounds} sent={sent} recv={recv} bytes_sent={bytes_sent} bytes_recv={bytes_recv} outcome={outcome}"
                ));
                if !error.is_empty() {
                    out.push_str(&format!(" error={error}"));
                }
                out.push('\n');
            }
        }
    }

    if let Ok(mut stmt) = conn.prepare(
        "SELECT peer_id, remote_addr, COUNT(*) AS active_runs
         FROM sync_runs
         WHERE outcome = 'in_progress'
         GROUP BY peer_id, remote_addr
         ORDER BY active_runs DESC, peer_id, remote_addr
         LIMIT 6",
    ) {
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })
            .ok();
        if let Some(rows) = rows {
            let active_rows: Vec<_> = rows.flatten().collect();
            if !active_rows.is_empty() {
                out.push_str("  active_runs_by_peer:\n");
                for (peer_id, remote_addr, active_runs) in active_rows {
                    out.push_str(&format!(
                        "    peer={} remote_addr={} active_runs={}\n",
                        &peer_id[..16.min(peer_id.len())],
                        remote_addr,
                        active_runs
                    ));
                }
            }
        }
    }

    if let Ok(mut stmt) = conn.prepare(
        "SELECT run_id, seq, frame_type, detail_json
         FROM sync_run_events
         WHERE frame_type IN ('SendIdle', 'InitialControlTimeout')
         ORDER BY run_id DESC, seq DESC
         LIMIT 8",
    ) {
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                ))
            })
            .ok();
        if let Some(rows) = rows {
            let marker_rows: Vec<_> = rows.flatten().collect();
            if !marker_rows.is_empty() {
                out.push_str("  recent_sync_markers:\n");
                for (run_id, seq, frame_type, detail_json) in marker_rows {
                    out.push_str(&format!(
                        "    run_id={run_id} seq={seq} type={frame_type} detail={}\n",
                        detail_json.unwrap_or_default()
                    ));
                }
            }
        }
    }

    out
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
    wait_for_message_count_pair(
        &bench.alice_db,
        &bench.bob_db,
        baseline + TOTAL,
        Duration::from_secs(120),
    );
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
    wait_for_message_count_pair(
        &bench.alice_db,
        &bench.bob_db,
        baseline + TOTAL,
        Duration::from_secs(300),
    );
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
