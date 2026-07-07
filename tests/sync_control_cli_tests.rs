//! CLI integration tests for manual sync round controls.
//!
//! Tests the `topo sync` command surface end-to-end via real daemon processes:
//!   SC1 — sync round all / peer (two-peer, live QUIC session required)

mod cli_harness;

use cli_harness::*;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

fn sync_control_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    hold_network_test_lock_for_binary();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

// ---------------------------------------------------------------------------
// SC1: sync round subcommand syntax works
// ---------------------------------------------------------------------------

#[test]
fn test_sync_round_all_subcommand_syntax() {
    let _guard = sync_control_test_lock();
    let (_dir, db) = temp_db();

    create_workspace(&db);
    let _daemon = start_daemon(&db);
    ensure_active_peer(&db, Duration::from_secs(10));

    // "sync round all" should be a valid subcommand (not "error: unexpected argument")
    let out = topo_cmd(&db, &["sync", "round", "all"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "'sync round all' should be a valid subcommand, not an unexpected argument:\n{}",
        stderr
    );
}

// ---------------------------------------------------------------------------
// Two-peer helpers
// ---------------------------------------------------------------------------

fn wait_for_sync_round_all(db: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let out = topo_cmd(db, &["sync", "round", "all"]);
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).to_string();
        }
        if Instant::now() >= deadline {
            panic!(
                "sync round all never succeeded within {:?}\nstdout: {}\nstderr: {}",
                timeout,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

// ---------------------------------------------------------------------------
// SC1: Two-peer round succeeds with a live peer
// ---------------------------------------------------------------------------

#[test]
fn test_sync_round_with_live_peer() {
    let _guard = sync_control_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    create_workspace(&alice_db);
    let _alice_daemon = start_daemon(&alice_db);
    let invite = create_invite_with_public_addr(&alice_db, &daemon_listen_addr(&alice_db));

    accept_invite(&bob_db, &invite);
    let _bob_daemon = start_daemon(&bob_db);

    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(60));
    wait_for_live_sync_session(&alice_db, Duration::from_secs(60));
    wait_for_live_sync_session(&bob_db, Duration::from_secs(60));

    // SC2: sync round all
    let round_stdout = wait_for_sync_round_all(&bob_db, Duration::from_secs(30));
    assert!(
        round_stdout.contains("SYNC ROUND"),
        "expected 'SYNC ROUND' in output:\n{}",
        round_stdout
    );
    assert!(
        round_stdout.contains("Newly observed:"),
        "expected 'Newly observed:' section:\n{}",
        round_stdout
    );
}
