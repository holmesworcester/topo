//! CLI integration tests for manual sync controls (SC1–SC4).
//!
//! Tests the `topo sync` command surface end-to-end via real daemon processes:
//!   SC1 — policy show / set (single-peer, no live session required)
//!   SC2 — sync round all / peer (two-peer, live QUIC session required)
//!   SC3 — sync request all / peer (two-peer, live QUIC session required)
//!   SC4 — policy affects request behavior: disabled refuses, manual allows
//!
//! Each test uses real daemon binaries and real SQLite state, matching the
//! captures in docs/sync-controls-cli-captures.txt.

mod cli_harness;

use cli_harness::*;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

fn sync_control_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    hold_network_test_lock_for_binary();
    let guard = LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    cleanup_test_daemons();
    guard
}

// ---------------------------------------------------------------------------
// SC1: Policy show — default is all-auto
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
    assert!(
        stdout.contains("SYNC POLICY:"),
        "expected SYNC POLICY: header:\n{}",
        stdout
    );
    assert!(
        stdout.contains("requests:"),
        "expected requests: field:\n{}",
        stdout
    );
    assert!(
        stdout.contains("responses:"),
        "expected responses: field:\n{}",
        stdout
    );
    assert!(
        stdout.contains("forward_on_have:"),
        "expected forward_on_have: field:\n{}",
        stdout
    );
    let auto_count = stdout.matches("auto").count();
    assert!(
        auto_count >= 3,
        "all three fields should default to 'auto' (found {} occurrences):\n{}",
        auto_count,
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

    // Set only requests to manual
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
    // The other two fields should still be auto
    let auto_count = set_stdout.matches("auto").count();
    assert!(
        auto_count >= 2,
        "unset fields should remain 'auto' (found {} occurrences):\n{}",
        auto_count,
        set_stdout
    );

    // Verify persistence with a second show
    let show = topo_cmd(&db, &["sync", "policy", "show"]);
    assert!(show.status.success(), "sync policy show after set failed");
    let show_stdout = String::from_utf8_lossy(&show.stdout);
    assert!(
        show_stdout.contains("manual"),
        "policy should persist as 'manual' after daemon re-show:\n{}",
        show_stdout
    );
    // The other two should still be auto
    assert!(
        show_stdout.contains("auto"),
        "unset fields should still show 'auto':\n{}",
        show_stdout
    );
}

// ---------------------------------------------------------------------------
// SC1: Policy set — all three fields at once, then restore to auto
// ---------------------------------------------------------------------------

#[test]
fn test_sync_policy_set_all_disabled_then_restore() {
    let _guard = sync_control_test_lock();
    let (_dir, db) = temp_db();

    create_workspace(&db);
    let _daemon = start_daemon(&db);
    ensure_active_peer(&db, Duration::from_secs(10));

    // Set all three to disabled
    let set = topo_cmd(&db, &[
        "sync", "policy", "set",
        "--requests", "disabled",
        "--responses", "disabled",
        "--forward-on-have", "disabled",
    ]);
    assert!(
        set.status.success(),
        "set all to disabled failed: {}",
        String::from_utf8_lossy(&set.stderr)
    );
    let set_stdout = String::from_utf8_lossy(&set.stdout);
    assert!(
        set_stdout.contains("SYNC POLICY (updated):"),
        "expected updated header:\n{}",
        set_stdout
    );
    let disabled_count = set_stdout.matches("disabled").count();
    assert!(
        disabled_count >= 3,
        "all three fields should be 'disabled' (found {}):\n{}",
        disabled_count,
        set_stdout
    );

    // Show to verify persistence
    let show = topo_cmd(&db, &["sync", "policy", "show"]);
    assert!(show.status.success());
    let show_stdout = String::from_utf8_lossy(&show.stdout);
    let show_disabled = show_stdout.matches("disabled").count();
    assert!(
        show_disabled >= 3,
        "persisted policy should show 3x 'disabled' (found {}):\n{}",
        show_disabled,
        show_stdout
    );

    // Restore all to auto
    let restore = topo_cmd(&db, &[
        "sync", "policy", "set",
        "--requests", "auto",
        "--responses", "auto",
        "--forward-on-have", "auto",
    ]);
    assert!(
        restore.status.success(),
        "restore to auto failed: {}",
        String::from_utf8_lossy(&restore.stderr)
    );
    let restore_stdout = String::from_utf8_lossy(&restore.stdout);
    let auto_count = restore_stdout.matches("auto").count();
    assert!(
        auto_count >= 3,
        "restored policy should show 3x 'auto' (found {}):\n{}",
        auto_count,
        restore_stdout
    );
}

// ---------------------------------------------------------------------------
// Two-peer helpers
// ---------------------------------------------------------------------------

/// Poll `topo sync round all` until it succeeds (live sessions registered) or
/// times out. Returns the combined stdout on success.
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

/// Poll `topo sync request all` until it succeeds or times out. Returns stdout.
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

// ---------------------------------------------------------------------------
// SC2 / SC3 / SC4: Two-peer round, request, and disabled-refusal
// ---------------------------------------------------------------------------

/// Set up two connected peers (alice creates workspace, invites bob), then:
///   SC2: `topo sync round all` produces SYNC ROUND with role/duration/observed
///   SC3: `topo sync request all` produces SYNC REQUEST with role/event count
///   SC4: Setting requests=disabled makes `topo sync request all` say "disabled";
///        restoring to manual allows requests again.
#[test]
fn test_sync_round_and_request_with_live_peer() {
    let _guard = sync_control_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    // Alice: create workspace, start daemon, generate invite
    create_workspace(&alice_db);
    let _alice_daemon = start_daemon(&alice_db);
    let invite = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob: accept invite (bootstrap sync includes stopping the temp daemon),
    // then start bob's persistent daemon.
    accept_invite(&bob_db, &invite);
    let _bob_daemon = start_daemon(&bob_db);

    // Wait for bob's active tenant to be fully ready before issuing sync commands.
    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(60));

    // --- SC2: sync round all ---
    // Sessions are registered when QUIC connections are established (on_session).
    // Poll until at least one session is live, then check output format.
    let round_stdout = wait_for_sync_round_all(&bob_db, Duration::from_secs(30));

    assert!(
        round_stdout.contains("SYNC ROUND"),
        "expected 'SYNC ROUND' in output:\n{}",
        round_stdout
    );
    assert!(
        round_stdout.contains("role="),
        "expected 'role=' in SYNC ROUND output:\n{}",
        round_stdout
    );
    assert!(
        round_stdout.contains("duration="),
        "expected 'duration=' in SYNC ROUND output:\n{}",
        round_stdout
    );
    assert!(
        round_stdout.contains("Newly observed:"),
        "expected 'Newly observed:' section in SYNC ROUND output:\n{}",
        round_stdout
    );

    // --- SC3: sync request all ---
    let req_stdout = wait_for_sync_request_all(&bob_db, Duration::from_secs(30));

    assert!(
        req_stdout.contains("SYNC REQUEST"),
        "expected 'SYNC REQUEST' in output:\n{}",
        req_stdout
    );
    assert!(
        req_stdout.contains("role="),
        "expected 'role=' in SYNC REQUEST output:\n{}",
        req_stdout
    );
    // Either shows count or "no events eligible for request"
    assert!(
        req_stdout.contains("event(s) requested") || req_stdout.contains("no events eligible"),
        "expected event count or eligible message in SYNC REQUEST output:\n{}",
        req_stdout
    );

    // --- SC4: disabled policy refuses requests ---
    let set_disabled = topo_cmd(&bob_db, &["sync", "policy", "set", "--requests", "disabled"]);
    assert!(
        set_disabled.status.success(),
        "policy set --requests disabled failed: {}",
        String::from_utf8_lossy(&set_disabled.stderr)
    );

    // With requests=disabled, sync request all should succeed at process level
    // but output should contain "disabled" in the per-peer result.
    let req_disabled = topo_cmd(&bob_db, &["sync", "request", "all"]);
    assert!(
        req_disabled.status.success(),
        "sync request all with disabled policy should exit 0: stderr={}",
        String::from_utf8_lossy(&req_disabled.stderr)
    );
    let disabled_stdout = String::from_utf8_lossy(&req_disabled.stdout);
    assert!(
        disabled_stdout.contains("disabled"),
        "expected 'disabled' in request output when requests=disabled:\n{}",
        disabled_stdout
    );

    // --- SC4: manual policy still allows requests (no "disabled" reason) ---
    let set_manual = topo_cmd(&bob_db, &["sync", "policy", "set", "--requests", "manual"]);
    assert!(
        set_manual.status.success(),
        "policy set --requests manual failed: {}",
        String::from_utf8_lossy(&set_manual.stderr)
    );

    let req_manual = topo_cmd(&bob_db, &["sync", "request", "all"]);
    assert!(
        req_manual.status.success(),
        "sync request all with manual policy failed: stderr={}",
        String::from_utf8_lossy(&req_manual.stderr)
    );
    let manual_stdout = String::from_utf8_lossy(&req_manual.stdout);
    assert!(
        !manual_stdout.contains("disabled"),
        "manual policy should NOT produce 'disabled' in request output:\n{}",
        manual_stdout
    );
    assert!(
        manual_stdout.contains("SYNC REQUEST"),
        "manual policy should still produce SYNC REQUEST output:\n{}",
        manual_stdout
    );
}
