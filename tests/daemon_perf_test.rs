//! Daemon-based sync throughput benchmarks.
//!
//! These benchmarks use real daemon processes, warm the topology before timing,
//! and report per-daemon VmHWM instead of process-shared RSS.

mod cli_harness;

use std::path::PathBuf;
use std::thread;
use std::time::{Duration, Instant};

use cli_harness::{
    accept_invite_with_identity_on_running_daemon, accept_invite_with_identity_persisted_only,
    assert_eventually, create_invite, create_invite_with_spki, create_workspace_with_details,
    daemon_listen_addr, daemon_transport_fingerprint, ensure_active_peer, generate_messages,
    get_users_raw, message_count_sql, peak_rss_mib_for_pid, send_message,
    start_daemon_with_options, topo_cmd, wait_for_active_tenant_ready,
    wait_for_tenant_ready_by_username, DaemonOptions, HarnessDaemon,
};

struct SharedWorkspaceBench {
    tmpdir: Option<tempfile::TempDir>,
    tmpdir_path: PathBuf,
    keep_tmpdir: bool,
    alice_db: String,
    bob_db: String,
    alice_daemon: HarnessDaemon,
    alice_pid: u32,
    bob_daemon: HarnessDaemon,
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

fn start_perf_daemon(db: &str, tmpdir: &std::path::Path, label: &str) -> HarnessDaemon {
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
    accept_invite_with_identity_persisted_only(
        db,
        invite_link,
        username,
        device_name,
        Duration::from_secs(30),
    );
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
    let blocked_events = query_count(&conn, "SELECT COUNT(*) FROM blocked_events");
    let project_queue = query_count(&conn, "SELECT COUNT(*) FROM project_queue");
    let sync_runs = query_count(&conn, "SELECT COUNT(*) FROM sync_runs");

    let mut out = String::new();
    out.push_str("bench diagnostics:\n");
    out.push_str(&format!(
        "  recorded_events={recorded_events} blocked_events={blocked_events} project_queue={project_queue} sync_runs={sync_runs}\n"
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
                let (
                    run_id,
                    direction,
                    role,
                    rounds,
                    sent,
                    recv,
                    bytes_sent,
                    bytes_recv,
                    outcome,
                    error,
                ) = row;
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

/// Preloaded sync: 10k messages created on Alice BEFORE timing starts.
/// Measures pure negentropy discovery + transfer + Bob's ingest.
/// Source creation is NOT in the hot path.
#[test]
fn perf_preloaded_10k() {
    const N: i64 = 10_000;

    let bench = SharedWorkspaceBench::new();
    // Warm the connection first so bootstrap identity sync is done
    let baseline = bench.warm_one_way();

    // Generate all messages on Alice (untimed)
    generate_messages(&bench.alice_db, N as usize);
    // Wait for Alice's daemon to persist all generated messages
    wait_for_message_count(&bench.alice_db, baseline + N, Duration::from_secs(60));

    // Now measure: how fast does Bob get the events via negentropy + transfer?
    let bob_before = message_count_sql(&bench.bob_db);
    let remaining = baseline + N - bob_before;
    if remaining <= 0 {
        eprintln!("All events already synced — nothing to measure");
        return;
    }
    let start = Instant::now();
    wait_for_message_count(&bench.bob_db, baseline + N, Duration::from_secs(300));
    let wall_secs = start.elapsed().as_secs_f64();

    let (alice_rss, bob_rss, max_rss) = bench.daemon_rss();
    let msgs_per_sec = remaining as f64 / wall_secs;
    emit_summary(
        "daemon_perf_test.perf_preloaded_10k",
        "10k preloaded sync (negentropy + transfer + ingest only)",
        wall_secs,
        remaining,
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

// ---------------------------------------------------------------------------
// Star topology (hub + N leaves) — realistic daemon-managed join path
// ---------------------------------------------------------------------------

fn perf_usize_env(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(default)
}

struct StarLeafBench {
    db: String,
    _daemon: HarnessDaemon,
    pid: u32,
}

struct StarTopologyBench {
    tmpdir: Option<tempfile::TempDir>,
    tmpdir_path: PathBuf,
    keep_tmpdir: bool,
    hub_db: String,
    _hub_daemon: HarnessDaemon,
    hub_pid: u32,
    leaves: Vec<StarLeafBench>,
}

#[derive(Debug, Clone, Copy)]
struct ProcMetrics {
    current_rss_mib: f64,
    peak_rss_mib: f64,
    threads: usize,
    fds: usize,
    maps: usize,
}

impl StarTopologyBench {
    fn new(leaf_count: usize, lowmem: bool) -> Self {
        assert!(leaf_count > 0, "leaf_count must be > 0");

        let keep_tmpdir = perf_debug_env("PERF_KEEP_TMPDIR");
        let (tmpdir, tmpdir_path) = if keep_tmpdir {
            let path = tempfile::tempdir().unwrap().keep();
            eprintln!(
                "PERF_KEEP_TMPDIR=1: preserving star benchmark artifacts under {}",
                path.display()
            );
            (None, path)
        } else {
            let tmpdir = tempfile::tempdir().unwrap();
            let path = tmpdir.path().to_path_buf();
            (Some(tmpdir), path)
        };

        let hub_db = tmpdir_path.join("hub.db").to_str().unwrap().to_string();
        create_workspace_with_details(&hub_db, "workspace", "hub", "hub-device");
        // Hub always runs without lowmem — it is the server and needs full
        // buffers.  Only leaves run in lowmem mode (matching real-world mobile
        // clients).
        let mut hub_daemon = start_hub_daemon(&hub_db, &tmpdir_path);
        let hub_pid = hub_daemon.child().id();
        ensure_active_peer(&hub_db, Duration::from_secs(10));
        maybe_enable_sync_logging(&hub_db);

        let reused_invite = create_invite(&hub_db, &daemon_listen_addr(&hub_db));

        let mut leaves: Vec<StarLeafBench> = Vec::with_capacity(leaf_count);
        for idx in 0..leaf_count {
            let username = format!("leaf-{idx:03}");

            let db = tmpdir_path
                .join(format!("leaf-{idx:03}.db"))
                .to_str()
                .unwrap()
                .to_string();
            let mut daemon = start_star_daemon(&db, &tmpdir_path, &username, lowmem);
            accept_invite_with_identity_on_running_daemon(
                &db,
                &reused_invite,
                &username,
                &format!("device-{idx:03}"),
                Duration::from_secs(30),
            );
            let pid = daemon.child().id();
            ensure_active_peer(&db, Duration::from_secs(30));
            wait_for_active_tenant_ready(&db, Duration::from_secs(120));
            wait_for_tenant_ready_by_username(&db, &username, Duration::from_secs(120));
            maybe_enable_sync_logging(&db);
            wait_for_username_visible(&hub_db, &username, Duration::from_secs(90));
            wait_for_username_visible(&db, "hub", Duration::from_secs(90));

            // O(1) per-join probes: verify hub<->leaf bidirectional sync and
            // (when applicable) first/last existing leaf can still publish.
            // Full all-node convergence is verified once after the loop.
            let leaf_probe = send_message(&db, &format!("join-leaf-{idx:03}-leaf"));
            let hub_probe = send_message(&hub_db, &format!("join-leaf-{idx:03}-hub"));
            assert_event_visible_on_all(
                &[hub_db.as_str()],
                leaf_probe.trim(),
                Duration::from_secs(120),
            );
            assert_event_visible_on_all(&[db.as_str()], hub_probe.trim(), Duration::from_secs(120));

            if let Some(last) = leaves.last() {
                let last_probe = send_message(&last.db, &format!("join-leaf-{idx:03}-last"));
                assert_event_visible_on_all(
                    &[hub_db.as_str(), db.as_str()],
                    last_probe.trim(),
                    Duration::from_secs(120),
                );
            }
            if leaves.len() >= 2 {
                let first = &leaves[0];
                let first_probe = send_message(&first.db, &format!("join-leaf-{idx:03}-first"));
                assert_event_visible_on_all(
                    &[hub_db.as_str(), db.as_str()],
                    first_probe.trim(),
                    Duration::from_secs(120),
                );
            }

            leaves.push(StarLeafBench {
                db,
                _daemon: daemon,
                pid,
            });
        }

        // Final all-node convergence: one probe from hub, verify every node
        // sees it.
        let all_dbs: Vec<&str> = {
            let mut v = Vec::with_capacity(leaves.len() + 1);
            v.push(hub_db.as_str());
            for l in &leaves {
                v.push(l.db.as_str());
            }
            v
        };
        let final_probe = send_message(&hub_db, "star-setup-final-convergence");
        assert_event_visible_on_all(&all_dbs, final_probe.trim(), Duration::from_secs(120));

        Self {
            tmpdir,
            tmpdir_path,
            keep_tmpdir,
            hub_db,
            _hub_daemon: hub_daemon,
            hub_pid,
            leaves,
        }
    }

    fn all_dbs(&self) -> Vec<&str> {
        let mut out = Vec::with_capacity(self.leaves.len() + 1);
        out.push(self.hub_db.as_str());
        for leaf in &self.leaves {
            out.push(leaf.db.as_str());
        }
        out
    }

    fn warm_hub_to_all(&self) -> i64 {
        let warm_id = send_message(&self.hub_db, "star-warmup-hub");
        let dbs = self.all_dbs();
        assert_event_visible_on_all(&dbs, warm_id.trim(), Duration::from_secs(120));
        message_count_sql(&self.hub_db)
    }

    fn proc_metrics(&self) -> (ProcMetrics, Vec<ProcMetrics>) {
        let hub = read_proc_metrics(self.hub_pid).expect("hub proc metrics unavailable");
        let leaves = self
            .leaves
            .iter()
            .map(|leaf| read_proc_metrics(leaf.pid).expect("leaf proc metrics unavailable"))
            .collect();
        (hub, leaves)
    }
}

impl Drop for StarTopologyBench {
    fn drop(&mut self) {
        if self.keep_tmpdir {
            eprintln!(
                "preserved star benchmark artifacts at {}",
                self.tmpdir_path.display()
            );
            return;
        }
        if let Some(tmpdir) = self.tmpdir.take() {
            drop(tmpdir);
        }
    }
}

/// Start the hub daemon with discovery enabled (matching the passing CLI test
/// pattern where the workspace creator uses `start_discovery_daemon`).
fn start_hub_daemon(db: &str, tmpdir: &std::path::Path) -> HarnessDaemon {
    let extra_env = vec![
        ("TOPO_TEST_DISCOVERY_LOOPBACK".to_string(), "1".to_string()),
        // Override TOPO_DISABLE_DISCOVERY with an empty string so hub mDNS is
        // not suppressed when the test process inherits this variable from the
        // sandbox or test runner.  env_flag() in supervisor.rs only returns
        // true for "1", "true", or "yes"; empty string evaluates to false.
        ("TOPO_DISABLE_DISCOVERY".to_string(), "".to_string()),
    ];

    if !perf_debug_env("PERF_DAEMON_LOGS") {
        return start_daemon_with_options(
            db,
            &DaemonOptions {
                bind_ip: Some("127.0.0.1".to_string()),
                extra_env,
                ..Default::default()
            },
        );
    }

    start_daemon_with_options(
        db,
        &DaemonOptions {
            bind_ip: Some("127.0.0.1".to_string()),
            stdout_file: Some(tmpdir.join("hub.daemon.stdout.log")),
            stderr_file: Some(tmpdir.join("hub.daemon.stderr.log")),
            extra_env,
            ..Default::default()
        },
    )
}

/// Start a leaf daemon with discovery disabled.
fn start_star_daemon(
    db: &str,
    tmpdir: &std::path::Path,
    label: &str,
    lowmem: bool,
) -> HarnessDaemon {
    let mut extra_env = Vec::new();
    if lowmem {
        extra_env.push(("LOW_MEM_IOS".to_string(), "1".to_string()));
    }

    // disable_discovery: true is set in BOTH branches below.
    if !perf_debug_env("PERF_DAEMON_LOGS") {
        return start_daemon_with_options(
            db,
            &DaemonOptions {
                bind_ip: Some("127.0.0.1".to_string()),
                disable_discovery: true,
                extra_env,
                ..Default::default()
            },
        );
    }

    start_daemon_with_options(
        db,
        &DaemonOptions {
            bind_ip: Some("127.0.0.1".to_string()),
            stdout_file: Some(tmpdir.join(format!("{label}.daemon.stdout.log"))),
            stderr_file: Some(tmpdir.join(format!("{label}.daemon.stderr.log"))),
            disable_discovery: true,
            extra_env,
            ..Default::default()
        },
    )
}

/// Assert that `event_id` is visible on every DB within a single shared deadline.
fn assert_event_visible_on_all(dbs: &[&str], event_id: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let predicate = format!("has_event:{} >= 1", event_id.trim());
    for db in dbs {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let remaining_ms = remaining.as_millis().min(u64::MAX as u128) as u64;
        assert_eventually(db, &predicate, remaining_ms);
    }
}

fn wait_for_message_count_all(dbs: &[&str], expected: i64, timeout: Duration) {
    let start = Instant::now();
    loop {
        let counts: Vec<i64> = dbs.iter().map(|db| message_count_sql(db)).collect();
        if counts.iter().all(|&c| c >= expected) {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "message_count across star timed out after {:?}: expected={} actual={:?}\n{}",
            timeout,
            expected,
            counts,
            dbs.iter()
                .map(|db| format!("db={}\n{}", db, format_bench_diagnostics(db)))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_username_visible(db: &str, username: &str, timeout: Duration) {
    let start = Instant::now();
    loop {
        let users = get_users_raw(db);
        if users.contains(username) {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "username {} did not become visible in {:?} for db={}\nusers=\n{}",
            username,
            timeout,
            db,
            users,
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn message_contents_sql(db: &str) -> Vec<String> {
    let conn = rusqlite::Connection::open(db).expect("open db for message_contents_sql");
    let mut stmt = conn
        .prepare("SELECT content FROM messages ORDER BY rowid")
        .expect("prepare message_contents_sql");
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query message_contents_sql");
    rows.filter_map(|r| r.ok()).collect()
}

fn read_proc_metrics(pid: u32) -> Option<ProcMetrics> {
    let current_rss = peak_rss_mib_for_pid(pid)?;
    let peak_rss = current_rss;
    let threads = std::fs::read_dir(format!("/proc/{pid}/task"))
        .ok()
        .map(|d| d.count())
        .unwrap_or(0);
    let fds = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .ok()
        .map(|d| d.count())
        .unwrap_or(0);
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .ok()
        .map(|s| s.lines().count())
        .unwrap_or(0);
    Some(ProcMetrics {
        current_rss_mib: current_rss,
        peak_rss_mib: peak_rss,
        threads,
        fds,
        maps,
    })
}

/// Minimal real-daemon star topology smoke:
/// one hub workspace, two joined leaves, and messages fan out to all nodes.
#[test]
fn star_topology_smoke_two_leaves() {
    let bench = StarTopologyBench::new(2, false);
    let hub_msg = "hub-star-smoke";
    let leaf0_msg = "leaf0-star-smoke";
    let leaf1_msg = "leaf1-star-smoke";

    let dbs = bench.all_dbs();
    let _warm_count = bench.warm_hub_to_all();
    let hub_event = send_message(&bench.hub_db, hub_msg);
    let leaf0_event = send_message(&bench.leaves[0].db, leaf0_msg);
    let leaf1_event = send_message(&bench.leaves[1].db, leaf1_msg);
    assert_event_visible_on_all(&dbs, hub_event.trim(), Duration::from_secs(120));
    assert_event_visible_on_all(&dbs, leaf0_event.trim(), Duration::from_secs(120));
    assert_event_visible_on_all(&dbs, leaf1_event.trim(), Duration::from_secs(120));

    for db in bench.all_dbs() {
        let messages = message_contents_sql(db);
        assert!(
            messages.iter().any(|message| message.contains(hub_msg)),
            "hub message missing from db={}: {:?}",
            db,
            messages
        );
        assert!(
            messages.iter().any(|message| message.contains(leaf0_msg)),
            "leaf0 message missing from db={}: {:?}",
            db,
            messages
        );
        assert!(
            messages.iter().any(|message| message.contains(leaf1_msg)),
            "leaf1 message missing from db={}: {:?}",
            db,
            messages
        );
    }
}

/// Star topology capacity probe: hub + configurable number of leaves.
#[test]
#[ignore]
fn perf_star_topology_capacity() {
    let leaf_count = perf_usize_env("STAR_TOPOLOGY_LEAVES", 10);
    let hub_messages = perf_usize_env("STAR_TOPOLOGY_HUB_MESSAGES", 1);
    let messages_per_leaf = perf_usize_env("STAR_TOPOLOGY_MESSAGES_PER_LEAF", 1);
    let lowmem = perf_debug_env("STAR_TOPOLOGY_LOWMEM");

    let bench = StarTopologyBench::new(leaf_count, lowmem);
    let baseline = bench.warm_hub_to_all();
    let total_nodes = leaf_count + 1;

    let start = Instant::now();
    for i in 0..hub_messages {
        send_message(&bench.hub_db, &format!("star-hub-msg-{i:03}"));
    }
    for (leaf_idx, leaf) in bench.leaves.iter().enumerate() {
        for msg_idx in 0..messages_per_leaf {
            send_message(
                &leaf.db,
                &format!("star-leaf-{leaf_idx:03}-msg-{msg_idx:03}"),
            );
        }
    }
    let total_messages = hub_messages + leaf_count * messages_per_leaf;
    let expected = baseline + total_messages as i64;
    let dbs = bench.all_dbs();
    wait_for_message_count_all(&dbs, expected, Duration::from_secs(300));
    let wall_secs = start.elapsed().as_secs_f64();

    let (hub_metrics, leaf_metrics) = bench.proc_metrics();
    let total_deliveries = total_messages * total_nodes;
    let msgs_per_sec = total_messages as f64 / wall_secs;
    let deliveries_per_sec = total_deliveries as f64 / wall_secs;

    let leaf_rss_current: Vec<f64> = leaf_metrics.iter().map(|m| m.current_rss_mib).collect();
    let leaf_rss_peak: Vec<f64> = leaf_metrics.iter().map(|m| m.peak_rss_mib).collect();
    let leaf_threads: Vec<usize> = leaf_metrics.iter().map(|m| m.threads).collect();
    let leaf_fds: Vec<usize> = leaf_metrics.iter().map(|m| m.fds).collect();
    let leaf_maps: Vec<usize> = leaf_metrics.iter().map(|m| m.maps).collect();

    let avg = |v: &[f64]| v.iter().sum::<f64>() / v.len().max(1) as f64;
    let p95 = |v: &mut Vec<f64>| {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[((v.len() as f64 * 0.95) as usize).min(v.len() - 1)]
    };
    let max_f = |v: &[f64]| v.iter().cloned().fold(0.0_f64, f64::max);
    let avg_u = |v: &[usize]| v.iter().sum::<usize>() as f64 / v.len().max(1) as f64;
    let max_u = |v: &[usize]| v.iter().cloned().max().unwrap_or(0);

    let summary = format!(
        "=== Star topology capacity probe (daemon, warm) ===\n\
         \x20 Leaf daemons:        {leaf_count}\n\
         \x20 Total nodes:         {total_nodes}\n\
         \x20 Lowmem:              {lowmem}\n\
         \x20 Hub messages:        {hub_messages}\n\
         \x20 Messages/leaf:       {messages_per_leaf}\n\
         \x20 Total messages:      {total_messages}\n\
         \x20 Total deliveries:    {total_deliveries}\n\
         \x20 Wall time:           {wall_secs:.2}s\n\
         \x20 Messages/s:          {msgs_per_sec:.0}\n\
         \x20 Deliveries/s:        {deliveries_per_sec:.0}\n\
         \x20 Hub RSS current:     {:.1} MiB\n\
         \x20 Hub RSS peak:        {:.1} MiB\n\
         \x20 Leaf RSS current:    avg {:.1} MiB / p95 {:.1} MiB / max {:.1} MiB\n\
         \x20 Leaf RSS peak:       avg {:.1} MiB / p95 {:.1} MiB / max {:.1} MiB\n\
         \x20 Hub threads:         {}\n\
         \x20 Leaf threads:        avg {:.1} / max {}\n\
         \x20 Hub FDs:             {}\n\
         \x20 Leaf FDs:            avg {:.1} / max {}\n\
         \x20 Hub maps:            {}\n\
         \x20 Leaf maps:           avg {:.1} / max {}\n",
        hub_metrics.current_rss_mib,
        hub_metrics.peak_rss_mib,
        avg(&leaf_rss_current),
        p95(&mut leaf_rss_current.clone()),
        max_f(&leaf_rss_current),
        avg(&leaf_rss_peak),
        p95(&mut leaf_rss_peak.clone()),
        max_f(&leaf_rss_peak),
        hub_metrics.threads,
        avg_u(&leaf_threads),
        max_u(&leaf_threads),
        hub_metrics.fds,
        avg_u(&leaf_fds),
        max_u(&leaf_fds),
        hub_metrics.maps,
        avg_u(&leaf_maps),
        max_u(&leaf_maps),
    );
    eprintln!("\n{summary}");
    let summary_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("target/perf-results");
    std::fs::create_dir_all(&summary_dir).expect("create target/perf-results");
    std::fs::write(
        summary_dir.join("daemon_perf_test.perf_star_topology_capacity.summary"),
        &summary,
    )
    .expect("write star topology summary file");
}
