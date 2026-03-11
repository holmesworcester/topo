//! Test for dual-session double-send bug.
//!
//! When peer A sends events to peer B, both the outbound (A-initiated) and
//! inbound (B-initiated) sync sessions independently discover the same delta
//! and transmit the same event data over the wire. This test measures total
//! bytes_sent across all sync runs to detect when data is sent more than once.
//!
//! Run with: cargo test --release --test double_send_test -- --nocapture --test-threads=1
//!
//! See docs/BUG_DUAL_SESSION_DOUBLE_SEND.md for full details.

mod cli_harness;

use std::thread;
use std::time::{Duration, Instant};

use cli_harness::{
    accept_invite_with_identity, assert_eventually, create_invite_with_spki, create_workspace,
    daemon_listen_addr, daemon_transport_fingerprint, ensure_active_peer, generate_messages,
    message_count_sql, start_daemon, topo_cmd, wait_for_daemon_stopped,
};
use topo::testutil::DaemonGuard;

struct SharedWorkspaceBench {
    _tmpdir: tempfile::TempDir,
    alice_db: String,
    bob_db: String,
    alice_daemon: DaemonGuard,
    bob_daemon: DaemonGuard,
}

impl SharedWorkspaceBench {
    fn new() -> Self {
        let tmpdir = tempfile::tempdir().unwrap();
        let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
        let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

        create_workspace(&alice_db);
        wait_for_daemon_stopped(&alice_db, Duration::from_secs(10));
        let alice_daemon = start_daemon(&alice_db);

        let invite_link = create_invite_with_spki(
            &alice_db,
            &daemon_listen_addr(&alice_db),
            Some(&daemon_transport_fingerprint(&alice_db)),
        );
        accept_invite_with_identity(&bob_db, &invite_link, "bob", "laptop");
        wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));

        let bob_daemon = start_daemon(&bob_db);

        ensure_active_peer(&alice_db, Duration::from_secs(10));
        ensure_active_peer(&bob_db, Duration::from_secs(10));

        Self {
            _tmpdir: tmpdir,
            alice_db,
            bob_db,
            alice_daemon,
            bob_daemon,
        }
    }

    /// Enable sync logging on both peers.
    fn enable_sync_logging(&self) {
        for db in [&self.alice_db, &self.bob_db] {
            let out = topo_cmd(db, &["sync-log", "enable", "--all-runs"]);
            assert!(
                out.status.success(),
                "sync-log enable failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    /// Warm topology: send one message each way and wait for convergence.
    fn warm(&self) -> i64 {
        let warm_eid = cli_harness::send_message(&self.alice_db, "warmup-alice");
        assert_eventually(
            &self.bob_db,
            &format!("has_event:{} >= 1", warm_eid),
            30_000,
        );
        wait_for_message_count(&self.bob_db, 1, Duration::from_secs(30));
        message_count_sql(&self.bob_db)
    }

    /// Query total bytes_sent from sync_runs on a given peer's database.
    /// Only counts runs that started after `after_ms` (epoch ms).
    fn total_bytes_sent_after(&self, db: &str, after_ms: i64) -> u64 {
        let conn = rusqlite::Connection::open(db).expect("failed to open db");
        conn.query_row(
            "SELECT COALESCE(SUM(bytes_sent), 0) FROM sync_runs WHERE started_at_ms > ?1",
            rusqlite::params![after_ms],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0) as u64
    }

    /// Query total events_sent from sync_runs on a given peer's database.
    /// Only counts runs that started after `after_ms`.
    fn total_events_sent_after(&self, db: &str, after_ms: i64) -> u64 {
        let conn = rusqlite::Connection::open(db).expect("failed to open db");
        conn.query_row(
            "SELECT COALESCE(SUM(events_sent), 0) FROM sync_runs WHERE started_at_ms > ?1",
            rusqlite::params![after_ms],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0) as u64
    }

    /// Count sync runs by direction on a given peer's database.
    fn count_runs_by_direction(&self, db: &str, after_ms: i64) -> (i64, i64) {
        let conn = rusqlite::Connection::open(db).expect("failed to open db");
        let outbound: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sync_runs WHERE started_at_ms > ?1 AND direction = 'outbound'",
                rusqlite::params![after_ms],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let inbound: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sync_runs WHERE started_at_ms > ?1 AND direction = 'inbound'",
                rusqlite::params![after_ms],
                |row| row.get(0),
            )
            .unwrap_or(0);
        (outbound, inbound)
    }

    /// Current epoch milliseconds.
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
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
        if count >= expected {
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

/// One-way sync: Alice generates N messages, Bob receives them.
/// Measures total bytes_sent across both peers' sync_runs and checks
/// whether the data was sent approximately once (not twice).
///
/// The "double send" bug causes both the outbound and inbound sync sessions
/// to independently transmit the same events, resulting in ~2x bytes_sent.
#[test]
fn double_send_one_way_sync() {
    const N: i64 = 1_000;

    let bench = SharedWorkspaceBench::new();
    bench.enable_sync_logging();
    let baseline = bench.warm();

    // Record timestamp boundary so we only measure the test sync runs.
    // Give sync log a moment to flush warmup runs.
    thread::sleep(Duration::from_secs(2));
    let boundary_ms = bench.now_ms();

    let start = Instant::now();
    generate_messages(&bench.alice_db, N as usize);
    wait_for_message_count(&bench.bob_db, baseline + N, Duration::from_secs(120));
    let wall_secs = start.elapsed().as_secs_f64();

    // Let sync sessions complete and flush their logs.
    thread::sleep(Duration::from_secs(3));

    // Measure bytes_sent from both peers' sync_runs (only runs after boundary).
    let alice_bytes_sent = bench.total_bytes_sent_after(&bench.alice_db, boundary_ms);
    let bob_bytes_sent = bench.total_bytes_sent_after(&bench.bob_db, boundary_ms);
    let total_bytes_sent = alice_bytes_sent + bob_bytes_sent;

    let alice_events_sent = bench.total_events_sent_after(&bench.alice_db, boundary_ms);
    let bob_events_sent = bench.total_events_sent_after(&bench.bob_db, boundary_ms);
    let total_events_sent = alice_events_sent + bob_events_sent;

    // Count sync sessions by direction on alice's side.
    let (alice_outbound_runs, alice_inbound_runs) =
        bench.count_runs_by_direction(&bench.alice_db, boundary_ms);
    let (bob_outbound_runs, bob_inbound_runs) =
        bench.count_runs_by_direction(&bench.bob_db, boundary_ms);

    // Alice's store count gives us the expected number of shared events.
    let alice_store_count: i64 = {
        let conn =
            rusqlite::Connection::open(&bench.alice_db).expect("failed to open alice db");
        conn.query_row(
            "SELECT COUNT(*) FROM events WHERE share_scope = 'shared'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(0)
    };

    // One-way: Alice has all events, Bob needs to receive N new ones.
    // In a correct implementation, total_events_sent should be ~N (Alice sends
    // to Bob). With the double-send bug, it will be ~2*N (both sessions send).
    //
    // We use 1.5x as the threshold: anything above means significant duplication.
    let duplication_ratio = if N > 0 {
        total_events_sent as f64 / N as f64
    } else {
        0.0
    };

    eprintln!();
    eprintln!("=== Double-send detection: one-way {N} messages ===");
    eprintln!("  Wall time:          {wall_secs:.2}s");
    eprintln!("  Alice store (shared): {alice_store_count}");
    eprintln!("  Alice bytes_sent:   {alice_bytes_sent}");
    eprintln!("  Bob bytes_sent:     {bob_bytes_sent}");
    eprintln!("  Total bytes_sent:   {total_bytes_sent}");
    eprintln!("  Alice events_sent:  {alice_events_sent}");
    eprintln!("  Bob events_sent:    {bob_events_sent}");
    eprintln!("  Total events_sent:  {total_events_sent}");
    eprintln!("  Expected events:    ~{N}");
    eprintln!("  Duplication ratio:  {duplication_ratio:.2}x");
    eprintln!("  Alice runs:         {alice_outbound_runs} outbound, {alice_inbound_runs} inbound");
    eprintln!("  Bob runs:           {bob_outbound_runs} outbound, {bob_inbound_runs} inbound");
    eprintln!();

    // KNOWN BUG: Concurrent sync sessions send the same events multiple times.
    // See docs/BUG_DUAL_SESSION_DOUBLE_SEND.md.
    //
    // This assertion documents the bug: we expect duplication > 1.5x.
    // When the bug is fixed, flip this to assert!(duplication_ratio < 1.5).
    assert!(
        duplication_ratio > 1.5,
        "Double-send bug appears to be fixed! Duplication ratio {duplication_ratio:.2}x <= 1.5x. \
         Flip this assertion to assert < 1.5 and remove the known-bug marker."
    );

    eprintln!(
        "  CONFIRMED: double-send bug reproduced (ratio {duplication_ratio:.2}x > 1.5x)"
    );
    eprintln!();
}
