//! Runtime regression for duplicate event sends under concurrent peer sessions.
//!
//! This test measures aggregate `events_sent` across both peers' sync runs
//! while Alice generates a one-way burst for Bob. A correct implementation
//! should stay close to 1x sends, not ~2x or worse.

mod cli_harness;

use std::thread;
use std::time::{Duration, Instant};

use cli_harness::{
    accept_invite_with_identity, assert_eventually, create_invite_with_spki, create_workspace,
    daemon_listen_addr, daemon_transport_fingerprint, ensure_active_peer, generate_messages,
    message_count_sql, start_daemon, topo_cmd, wait_for_daemon_stopped, HarnessDaemon,
};

struct SharedWorkspaceBench {
    _tmpdir: tempfile::TempDir,
    alice_db: String,
    bob_db: String,
    alice_daemon: HarnessDaemon,
    bob_daemon: HarnessDaemon,
}

impl SharedWorkspaceBench {
    fn enable_sync_logging_for_db(db: &str) {
        let out = topo_cmd(db, &["sync-log", "enable", "--all-runs"]);
        assert!(
            out.status.success(),
            "sync-log enable failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn new() -> Self {
        let tmpdir = tempfile::tempdir().unwrap();
        let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
        let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

        create_workspace(&alice_db);
        wait_for_daemon_stopped(&alice_db, Duration::from_secs(10));
        Self::enable_sync_logging_for_db(&alice_db);
        let alice_daemon = start_daemon(&alice_db);

        let invite_link = create_invite_with_spki(
            &alice_db,
            &daemon_listen_addr(&alice_db),
            Some(&daemon_transport_fingerprint(&alice_db)),
        );
        accept_invite_with_identity(&bob_db, &invite_link, "bob", "laptop");
        wait_for_daemon_stopped(&bob_db, Duration::from_secs(10));
        Self::enable_sync_logging_for_db(&bob_db);

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

    fn total_events_sent(&self, db: &str) -> u64 {
        let conn = rusqlite::Connection::open(db).expect("failed to open db");
        conn.query_row(
            "SELECT COUNT(*)
             FROM sync_run_events
             WHERE lane = 'data'
               AND direction = 'tx'
               AND frame_type = 'Event'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0) as u64
    }

    fn events_sent_totals(&self) -> (u64, u64) {
        (
            self.total_events_sent(&self.alice_db),
            self.total_events_sent(&self.bob_db),
        )
    }

    fn count_changed_runs_by_direction(&self, db: &str) -> (i64, i64) {
        let conn = rusqlite::Connection::open(db).expect("failed to open db");
        let outbound: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sync_runs
                 WHERE direction = 'outbound'
                   AND (rounds > 0 OR events_sent > 0 OR events_received > 0)",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        let inbound: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sync_runs
                 WHERE direction = 'inbound'
                   AND (rounds > 0 OR events_sent > 0 OR events_received > 0)",
                [],
                |row| row.get(0),
            )
            .unwrap_or(0);
        (outbound, inbound)
    }

    fn wait_for_events_sent_stable(
        &self,
        timeout: Duration,
        stable_for: Duration,
        interval: Duration,
    ) -> (u64, u64) {
        let start = Instant::now();
        let mut last = self.events_sent_totals();
        let mut stable_since = None;

        loop {
            let current = self.events_sent_totals();
            if current == last {
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
                "events_sent totals did not stabilize within {:?}; last={:?}",
                timeout,
                current
            );
            thread::sleep(interval);
        }
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

#[test]
fn duplicate_sends_stay_below_regression_threshold() {
    const N: i64 = 200;

    let bench = SharedWorkspaceBench::new();
    let baseline = bench.warm();

    let _ = bench.wait_for_events_sent_stable(
        Duration::from_secs(10),
        Duration::from_millis(500),
        Duration::from_millis(100),
    );
    let (alice_events_sent_before, bob_events_sent_before) = bench.events_sent_totals();
    let (alice_outbound_before, alice_inbound_before) =
        bench.count_changed_runs_by_direction(&bench.alice_db);
    let (bob_outbound_before, bob_inbound_before) =
        bench.count_changed_runs_by_direction(&bench.bob_db);

    let start = Instant::now();
    generate_messages(&bench.alice_db, N as usize);
    wait_for_message_count(&bench.bob_db, baseline + N, Duration::from_secs(90));
    let wall_secs = start.elapsed().as_secs_f64();

    let (alice_events_sent_after, bob_events_sent_after) = bench.wait_for_events_sent_stable(
        Duration::from_secs(20),
        Duration::from_millis(500),
        Duration::from_millis(100),
    );
    let alice_events_sent = alice_events_sent_after.saturating_sub(alice_events_sent_before);
    let bob_events_sent = bob_events_sent_after.saturating_sub(bob_events_sent_before);
    let total_events_sent = alice_events_sent + bob_events_sent;

    let (alice_outbound_total, alice_inbound_total) =
        bench.count_changed_runs_by_direction(&bench.alice_db);
    let (bob_outbound_total, bob_inbound_total) =
        bench.count_changed_runs_by_direction(&bench.bob_db);
    let alice_outbound_runs = alice_outbound_total - alice_outbound_before;
    let alice_inbound_runs = alice_inbound_total - alice_inbound_before;
    let bob_outbound_runs = bob_outbound_total - bob_outbound_before;
    let bob_inbound_runs = bob_inbound_total - bob_inbound_before;
    let active_outbound_carriers =
        usize::from(alice_events_sent > 0) + usize::from(bob_events_sent > 0);

    let duplication_ratio = total_events_sent as f64 / N as f64;

    eprintln!();
    eprintln!("=== Double-send regression: one-way {N} messages ===");
    eprintln!("  Wall time:          {wall_secs:.2}s");
    eprintln!("  Alice events_sent:  {alice_events_sent}");
    eprintln!("  Bob events_sent:    {bob_events_sent}");
    eprintln!("  Total events_sent:  {total_events_sent}");
    eprintln!("  Duplication ratio:  {duplication_ratio:.2}x");
    eprintln!("  Alice runs:         {alice_outbound_runs} outbound, {alice_inbound_runs} inbound");
    eprintln!("  Bob runs:           {bob_outbound_runs} outbound, {bob_inbound_runs} inbound");
    eprintln!();

    assert!(
        duplication_ratio < 1.50,
        "duplicate sends regressed: ratio {duplication_ratio:.2}x for {N} messages"
    );
    assert_eq!(
        active_outbound_carriers, 1,
        "exactly one side should carry the measured burst outbound"
    );
    assert!(
        alice_inbound_runs + bob_inbound_runs <= 1,
        "the measured burst should not require more than one inbound sync run"
    );
}
