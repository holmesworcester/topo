//! CLI integration tests for manual sync controls (SC1-SC4).
//!
//! Tests the `topo sync` command surface end-to-end via real daemon processes:
//!   SC1 — policy show/set (single-peer, no live session required)
//!   SC2 — sync round all / peer (two-peer, live QUIC session required)
//!   SC3 — sync request all / peer (two-peer, live QUIC session required)
//!   SC4 — policy affects request behavior: disabled refuses, manual allows

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
// SC1: Policy show — default is both-auto
// ---------------------------------------------------------------------------

#[test]
fn test_sync_policy_show_default() {
    let _guard = sync_control_test_lock();
    let (_dir, db) = temp_db();

    create_workspace(&db);
    let _daemon = start_daemon(&db);
    ensure_active_peer(&db, Duration::from_secs(10));

    let out = topo_cmd(&db, &["sync", "policy", "show"]);
    assert!(
        out.status.success(),
        "sync policy show failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Must use structured output, not raw JSON
    assert!(
        stdout.contains("SYNC POLICY:"),
        "expected 'SYNC POLICY:' header (not JSON):\n{}",
        stdout
    );
    assert!(
        stdout.contains("requests:"),
        "expected 'requests:' field:\n{}",
        stdout
    );
    assert!(
        stdout.contains("responses:"),
        "expected 'responses:' field:\n{}",
        stdout
    );
    let auto_count = stdout.matches("auto").count();
    assert!(
        auto_count >= 2,
        "both fields should default to 'auto' (found {}):\n{}",
        auto_count,
        stdout
    );
    // Must NOT be raw JSON
    assert!(
        !stdout.contains("{"),
        "policy show should not output raw JSON:\n{}",
        stdout
    );
}

// ---------------------------------------------------------------------------
// SC1: Policy set — change one field, verify output and persistence
// ---------------------------------------------------------------------------

#[test]
fn test_sync_policy_set_requests_manual() {
    let _guard = sync_control_test_lock();
    let (_dir, db) = temp_db();

    create_workspace(&db);
    let _daemon = start_daemon(&db);
    ensure_active_peer(&db, Duration::from_secs(10));

    let set = topo_cmd(&db, &["sync", "policy", "set", "--requests", "manual"]);
    assert!(
        set.status.success(),
        "sync policy set failed: {}",
        String::from_utf8_lossy(&set.stderr)
    );
    let set_stdout = String::from_utf8_lossy(&set.stdout);
    assert!(
        set_stdout.contains("SYNC POLICY (updated):"),
        "expected 'SYNC POLICY (updated):' header:\n{}",
        set_stdout
    );
    assert!(
        set_stdout.contains("manual"),
        "output should contain 'manual':\n{}",
        set_stdout
    );
    assert!(
        set_stdout
            .lines()
            .any(|line| line.trim_start().starts_with("requests:") && line.contains("manual")),
        "requests lane should update to manual:\n{}",
        set_stdout
    );
    assert!(
        set_stdout
            .lines()
            .any(|line| line.trim_start().starts_with("responses:") && line.contains("auto")),
        "unset responses lane should remain auto:\n{}",
        set_stdout
    );

    // Verify persistence with a second show
    let show = topo_cmd(&db, &["sync", "policy", "show"]);
    assert!(show.status.success());
    let show_stdout = String::from_utf8_lossy(&show.stdout);
    assert!(
        show_stdout.contains("manual"),
        "policy should persist as 'manual' after re-show:\n{}",
        show_stdout
    );
}

// ---------------------------------------------------------------------------
// SC1: Policy set — both lanes to disabled, then restore
// ---------------------------------------------------------------------------

#[test]
fn test_sync_policy_set_all_disabled_then_restore() {
    let _guard = sync_control_test_lock();
    let (_dir, db) = temp_db();

    create_workspace(&db);
    let _daemon = start_daemon(&db);
    ensure_active_peer(&db, Duration::from_secs(10));

    let set = topo_cmd(
        &db,
        &[
            "sync",
            "policy",
            "set",
            "--requests",
            "disabled",
            "--responses",
            "disabled",
        ],
    );
    assert!(set.status.success());
    let stdout = String::from_utf8_lossy(&set.stdout);
    let disabled_count = stdout.matches("disabled").count();
    assert!(
        disabled_count >= 2,
        "both fields should show 'disabled' (found {}):\n{}",
        disabled_count,
        stdout
    );

    // Restore
    let restore = topo_cmd(
        &db,
        &[
            "sync",
            "policy",
            "set",
            "--requests",
            "auto",
            "--responses",
            "auto",
        ],
    );
    assert!(restore.status.success());
    let restore_stdout = String::from_utf8_lossy(&restore.stdout);
    let auto_count = restore_stdout.matches("auto").count();
    assert!(
        auto_count >= 2,
        "restored should show 2x 'auto' (found {}):\n{}",
        auto_count,
        restore_stdout
    );
}

// ---------------------------------------------------------------------------
// SC1: Invalid mode gives clear error
// ---------------------------------------------------------------------------

#[test]
fn test_sync_policy_set_invalid_mode() {
    let _guard = sync_control_test_lock();
    let (_dir, db) = temp_db();

    create_workspace(&db);
    let _daemon = start_daemon(&db);
    ensure_active_peer(&db, Duration::from_secs(10));

    let out = topo_cmd(&db, &["sync", "policy", "set", "--requests", "bogus"]);
    // Should fail with a clear error message
    assert!(!out.status.success(), "bogus mode should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid") || stderr.contains("bogus"),
        "error should mention the invalid value:\n{}",
        stderr
    );
}

// ---------------------------------------------------------------------------
// SC1: sync round/request subcommand syntax works
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

    // Same for request
    let out = topo_cmd(&db, &["sync", "request", "all"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("unexpected argument"),
        "'sync request all' should be a valid subcommand, not an unexpected argument:\n{}",
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

fn wait_for_sync_request_all(db: &str, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let out = topo_cmd(db, &["sync", "request", "all"]);
        if out.status.success() {
            return String::from_utf8_lossy(&out.stdout).to_string();
        }
        if Instant::now() >= deadline {
            panic!(
                "sync request all never succeeded within {:?}\nstdout: {}\nstderr: {}",
                timeout,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn wait_for_live_sync_session(db: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let out = topo_cmd(db, &["sync", "request", "all"]);
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !stdout.contains("(no live sessions)") && !stdout.contains("(no peers)") {
                return;
            }
        }
        if Instant::now() >= deadline {
            panic!(
                "live sync session never became available within {:?}\nstdout: {}\nstderr: {}",
                timeout,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

// ---------------------------------------------------------------------------
// SC2 / SC3 / SC4: Two-peer round, request, and disabled-refusal
// ---------------------------------------------------------------------------

#[test]
fn test_sync_round_and_request_with_live_peer() {
    let _guard = sync_control_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    create_workspace(&alice_db);
    let _alice_daemon = start_daemon(&alice_db);
    let invite = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    accept_invite(&bob_db, &invite);
    let _bob_daemon = start_daemon(&bob_db);

    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(60));
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

    // SC3: sync request all
    let req_stdout = wait_for_sync_request_all(&bob_db, Duration::from_secs(30));
    assert!(
        req_stdout.contains("SYNC REQUEST"),
        "expected 'SYNC REQUEST' in output:\n{}",
        req_stdout
    );
    assert!(
        req_stdout.contains("event(s) requested") || req_stdout.contains("no events eligible"),
        "expected event count or eligible message:\n{}",
        req_stdout
    );

    // SC4: disabled policy refuses requests with clear message
    let set = topo_cmd(
        &bob_db,
        &["sync", "policy", "set", "--requests", "disabled"],
    );
    assert!(set.status.success());

    let req_disabled = topo_cmd(&bob_db, &["sync", "request", "all"]);
    assert!(
        req_disabled.status.success(),
        "disabled request should exit 0: stderr={}",
        String::from_utf8_lossy(&req_disabled.stderr)
    );
    let disabled_stdout = String::from_utf8_lossy(&req_disabled.stdout);
    assert!(
        disabled_stdout.contains("disabled"),
        "expected 'disabled' in output:\n{}",
        disabled_stdout
    );
    // Must NOT show "peer=all" — should show actual peer ID or real placeholder
    assert!(
        !disabled_stdout.contains("peer=all"),
        "disabled output should show actual peer ID, not 'peer=all':\n{}",
        disabled_stdout
    );

    // SC4: manual policy allows requests (no "disabled" reason)
    let set_manual = topo_cmd(&bob_db, &["sync", "policy", "set", "--requests", "manual"]);
    assert!(set_manual.status.success());

    let req_manual = topo_cmd(&bob_db, &["sync", "request", "all"]);
    assert!(
        req_manual.status.success(),
        "manual request failed: stderr={}",
        String::from_utf8_lossy(&req_manual.stderr)
    );
    let manual_stdout = String::from_utf8_lossy(&req_manual.stdout);
    assert!(
        !manual_stdout.contains("disabled"),
        "manual should NOT show 'disabled':\n{}",
        manual_stdout
    );
    assert!(
        manual_stdout.contains("SYNC REQUEST"),
        "manual should produce SYNC REQUEST output:\n{}",
        manual_stdout
    );
}
