//! CLI black-box integration tests.
//!
//! Tests the `topo` binary end-to-end: multi-peer sync flows via invite,
//! CLI command output formatting (event-tree, event-list, reactions, files,
//! completions), and workspace management (ban, workspaces, db registry).
//!
//! **Boundary**: tests that exercise the CLI binary's user-facing behavior —
//! command output, multi-peer sync scenarios, and trust policy enforcement.
//! For RPC protocol mechanics and daemon lifecycle state transitions, see
//! `rpc_test.rs`. For invite-only autodial realism, see
//! `cheat_proof_realism_test.rs`. For real multi-process QUIC sync, see
//! `two_process_test.rs`.

mod cli_harness;

use cli_harness::*;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use topo::testutil::DaemonGuard;

fn cli_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Functional sync test using invite-based shared workspace flow.
/// Alice bootstraps identity, creates invite, starts daemon.
/// Bob accepts invite (bootstrap sync), starts daemon with invite-seeded autodial.
/// Both send messages in the shared workspace.
#[test]
fn test_cli_bidirectional_sync() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 30000;

    // Alice creates workspace (identity chain)
    create_workspace(&alice_db);

    // Alice starts daemon (auto-selects single peer)
    let _alice = start_daemon(&alice_db);

    // Alice sends messages via daemon RPC
    send_message(&alice_db, "Hello from Alice");
    let alice_eid = send_message(&alice_db, "How are you?");

    // Alice creates invite (via daemon RPC)
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob accepts invite (bootstrap sync from Alice)
    accept_invite(&bob_db, &invite_link);

    // Bob starts daemon; invite-seeded autodial reaches Alice.
    let _bob = start_daemon(&bob_db);
    std::thread::sleep(Duration::from_secs(1));

    // Bob sends a message in the shared workspace
    let bob_eid = send_message(&bob_db, "Hey Alice!");
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_eid),
        timeout_ms,
    );
    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", alice_eid),
        timeout_ms,
    );

    // Verify specific message content arrived on both sides
    let alice_msgs = get_messages(&alice_db);
    assert!(
        alice_msgs.len() >= 3,
        "Alice should see at least 3 messages, got {}",
        alice_msgs.len()
    );
    assert!(alice_msgs.contains(&"Hello from Alice".to_string()));
    assert!(alice_msgs.contains(&"How are you?".to_string()));
    assert!(alice_msgs.contains(&"Hey Alice!".to_string()));

    let bob_msgs = get_messages(&bob_db);
    assert!(
        bob_msgs.len() >= 3,
        "Bob should see at least 3 messages, got {}",
        bob_msgs.len()
    );
    assert!(bob_msgs.contains(&"Hello from Alice".to_string()));
    assert!(bob_msgs.contains(&"How are you?".to_string()));
    assert!(bob_msgs.contains(&"Hey Alice!".to_string()));
}

/// Functional sync test using invite-based flow.
/// Verifies sync picks up new messages over time (ongoing sync).
#[test]
fn test_cli_ongoing_sync() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 30000;

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    // Alice sends bootstrap message
    let _bootstrap_eid = send_message(&alice_db, "bootstrap");
    assert_now(&alice_db, "message_count >= 1");

    // Alice creates invite
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob accepts invite and starts daemon
    accept_invite(&bob_db, &invite_link);
    let _bob = start_daemon(&bob_db);
    // Explicit bootstrap readiness gate: avoid racing ongoing-sync assertions
    // before the invite/bootstrap prerequisite sync has converged.
    assert_eventually(&bob_db, "message_count >= 1", timeout_ms);

    // Both send messages over time
    send_message(&alice_db, "Round 1");
    send_message(&bob_db, "Round 2");
    send_message(&alice_db, "Round 3a");
    let bob_last_eid = send_message(&bob_db, "Round 3b");
    std::thread::sleep(Duration::from_secs(1));
    let alice_last_eid = send_message(&alice_db, "Round 4");

    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_last_eid),
        timeout_ms,
    );
    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", alice_last_eid),
        timeout_ms,
    );
}

/// Two separate local daemons should discover and sync on the same machine
/// even when invite-seeded placeholder autodial is disabled.
#[test]
#[cfg(feature = "discovery")]
fn test_cli_local_mdns_discovery_without_placeholder_autodial() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 20000;

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let _alice = start_daemon_with_options(
        &alice_db,
        &DaemonOptions {
            disable_placeholder_autodial: true,
            ..Default::default()
        },
    );

    // Alice creates invite while daemon is running.
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob accepts invite and starts daemon with placeholder autodial disabled.
    // With placeholder autodial disabled, Bob discovers Alice via mDNS only.
    accept_invite(&bob_db, &invite_link);
    let _bob = start_daemon_with_options(
        &bob_db,
        &DaemonOptions {
            disable_placeholder_autodial: true,
            ..Default::default()
        },
    );

    // Validate bidirectional convergence using messages created after both
    // daemons are running (avoids counting accept-invite bootstrap artifacts).
    let alice_live_eid = send_message(&alice_db, "alice-via-mdns-localhost");
    assert_eventually(
        &bob_db,
        &format!("has_event:{} >= 1", alice_live_eid),
        timeout_ms,
    );

    let bob_msg_eid = send_message(&bob_db, "bob-via-mdns-localhost");
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_msg_eid),
        timeout_ms,
    );
}

#[test]
fn test_cli_send_and_messages() {
    let _guard = cli_test_lock();
    // Basic test: create workspace, start daemon, send/messages work
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("test.db").to_str().unwrap().to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let _first_eid = send_message(&db, "First message");
    let second_eid = send_message(&db, "Second message");

    assert_now(&db, "message_count == 2");
    assert_now(&db, &format!("has_event:{} >= 1", second_eid));

    let messages = get_messages(&db);
    assert_eq!(messages.len(), 2);
    assert!(messages.contains(&"First message".to_string()));
    assert!(messages.contains(&"Second message".to_string()));
}

/// TRUST POLICY TEST: untrusted peer is rejected.
/// Alice bootstraps identity (PeerShared self-trust makes has_any_trusted_peer true).
/// Bob has independent identity (not in Alice's workspace). Alice should reject Bob.
#[test]
fn test_cli_unpinned_peer_rejected() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    // Alice sends a message
    send_message(&alice_db, "alice bootstrap");

    // Bob creates independent workspace (not in Alice's workspace)
    create_workspace(&bob_db);
    let _bob = start_daemon(&bob_db);

    // Bob sends a message
    let bob_eid = send_message(&bob_db, "Should not arrive");
    // Give some time for sync to try
    std::thread::sleep(Duration::from_secs(3));

    assert_now(&alice_db, &format!("has_event:{} == 0", bob_eid));
}

/// Daemon start on an empty DB should keep control plane up in IdleNoTenants state.
#[test]
fn test_cli_start_without_trust_starts_idle_runtime() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("no_trust.db")
        .to_str()
        .unwrap()
        .to_string();
    let socket = socket_path_for_db(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .arg("start")
            .arg("--bind")
            .arg(format!("127.0.0.1:{}", random_port()))
            .arg("--db")
            .arg(&db)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("failed to run start"),
    );

    let start = Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(socket.exists(), "daemon socket did not appear");

    let status = Command::new(bin())
        .args(["--db", &db, "status"])
        .output()
        .expect("status command");
    assert!(
        status.status.success(),
        "status should succeed on empty-db daemon: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        stdout.contains("Runtime:   IdleNoTenants"),
        "status should show idle runtime state, got: {}",
        stdout
    );

    let stop = Command::new(bin())
        .args(["--db", &db, "stop"])
        .output()
        .expect("stop command");
    assert!(stop.status.success(), "stop should succeed");
}

/// Bootstrap trust test using production invite / accept-invite CLI flow.
/// No direct SQL trust seeding — trust is materialized through CLI commands.
///
/// Projection-first flow: accept-invite creates identity chain (events may
/// block pending prerequisites). The daemon's ongoing peering loop delivers
/// the required events from Alice via bootstrap autodial, cascading the
/// identity chain to completion.
#[test]
fn test_cli_sync_bootstrap_from_accepted_invite_data() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir
        .path()
        .join("alice_bootstrap.db")
        .to_str()
        .unwrap()
        .to_string();
    let bob_db = tmpdir
        .path()
        .join("bob_bootstrap.db")
        .to_str()
        .unwrap()
        .to_string();
    let timeout_ms = 15000;

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    // Alice sends bootstrap message
    send_message(&alice_db, "bootstrap");

    // Alice creates invite (via daemon RPC)
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Alice should have emitted content key wrapping during invite creation
    assert!(
        count_rows(&alice_db, "key_shared") >= 1,
        "inviter should emit at least one key_shared key-wrap during invite creation"
    );

    // Bob accepts invite: installs deterministic cert, creates identity chain
    // (events may block pending sync of prerequisite events from Alice).
    accept_invite(&bob_db, &invite_link);

    // Bob starts daemon; invite bootstrap trust seeds daemon autodial.
    // Autodial connects to Alice, syncs prerequisite events, identity chain
    // cascades to completion, and messages project.
    let _bob = start_daemon(&bob_db);

    // Wait for Bob's identity chain to complete (message_count >= 1 means
    // Alice's "bootstrap" message has been fully projected on Bob's side,
    // which requires the full identity chain cascade).
    assert_eventually(&bob_db, "message_count >= 1", timeout_ms);

    // After sync, Bob should have Alice's key_shared event (content key ciphertext).
    // Note: deferred content key unwrapping (key_shared → key_secrets) is a
    // follow-up feature for the projection-first flow. The old inline bootstrap
    // sync performed this unwrap immediately, but the daemon-driven cascade
    // doesn't yet trigger it automatically.
    assert!(
        count_rows(&bob_db, "key_shared") >= 1,
        "invitee should have inviter's key_shared event after sync"
    );

    let bob_eid = send_message(&bob_db, "bootstrap trust from invite data");
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_eid),
        timeout_ms,
    );
}

// ---------------------------------------------------------------------------
// CLI command output tests
// ---------------------------------------------------------------------------

#[test]
fn test_cli_completions_bash() {
    let output = Command::new(bin())
        .args(["completions", "bash"])
        .output()
        .expect("failed to run completions");
    assert!(output.status.success(), "completions bash failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "bash completions should produce output");
    assert!(
        stdout.contains("topo"),
        "bash completions should reference 'topo'"
    );
}

#[test]
fn test_cli_completions_zsh() {
    let output = Command::new(bin())
        .args(["completions", "zsh"])
        .output()
        .expect("failed to run completions");
    assert!(output.status.success(), "completions zsh failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.is_empty(), "zsh completions should produce output");
}

#[test]
fn test_cli_ban_user() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("ban.db").to_str().unwrap().to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    // There should be 1 user (the workspace creator)
    let out = Command::new(bin())
        .args(["--db", &db, "users"])
        .output()
        .expect("users command");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("1."), "should have at least 1 user");

    // Ban user #1
    let out = Command::new(bin())
        .args(["--db", &db, "ban", "1"])
        .output()
        .expect("ban command");
    assert!(
        out.status.success(),
        "ban failed: {} {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Banned"), "should confirm ban");
}

#[test]
fn test_cli_workspaces() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("wsalias.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "workspaces"])
        .output()
        .expect("workspaces command");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("WORKSPACES"),
        "workspaces should show WORKSPACES header"
    );
}

#[test]
fn test_cli_db_registry() {
    let tmpdir = tempfile::tempdir().unwrap();
    let reg_dir = tmpdir.path().join("registry");
    std::fs::create_dir_all(&reg_dir).unwrap();

    // Use TOPO_REGISTRY_DIR to isolate
    let out = Command::new(bin())
        .env("TOPO_REGISTRY_DIR", reg_dir.to_str().unwrap())
        .args(["db", "add", "/tmp/test_registry.db", "--name", "mytest"])
        .output()
        .expect("db add");
    assert!(out.status.success(), "db add failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Added"), "should confirm add");

    // List
    let out = Command::new(bin())
        .env("TOPO_REGISTRY_DIR", reg_dir.to_str().unwrap())
        .args(["db", "list"])
        .output()
        .expect("db list");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("mytest"), "should show alias name");

    // Rename
    let out = Command::new(bin())
        .env("TOPO_REGISTRY_DIR", reg_dir.to_str().unwrap())
        .args(["db", "rename", "mytest", "renamed"])
        .output()
        .expect("db rename");
    assert!(out.status.success());

    // Remove
    let out = Command::new(bin())
        .env("TOPO_REGISTRY_DIR", reg_dir.to_str().unwrap())
        .args(["db", "remove", "renamed"])
        .output()
        .expect("db remove");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Removed"), "should confirm remove");

    // List should now be empty
    let out = Command::new(bin())
        .env("TOPO_REGISTRY_DIR", reg_dir.to_str().unwrap())
        .args(["db", "list"])
        .output()
        .expect("db list");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("No databases"), "should show empty message");
}

#[test]
fn test_cli_db_invalid_numeric_selector_errors() {
    let tmpdir = tempfile::tempdir().unwrap();
    let reg_dir = tmpdir.path().join("registry");
    std::fs::create_dir_all(&reg_dir).unwrap();

    // --db 999 with empty registry should error, not silently use "999" as filename.
    let out = Command::new(bin())
        .env("TOPO_REGISTRY_DIR", reg_dir.to_str().unwrap())
        .args(["--db", "999", "status"])
        .output()
        .expect("db 999");
    assert!(
        !out.status.success(),
        "should fail for invalid numeric selector, got success"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid index"),
        "should mention invalid index, got: {}",
        stderr
    );
}

#[test]
fn test_cli_react_by_message_number() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("msgnum.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    // Send two messages.
    send_message(&db, "first msg");
    send_message(&db, "second msg");

    // React to message #1 by number.
    let out = Command::new(bin())
        .args(["--db", &db, "react", "--target", "1", "thumbsup"])
        .output()
        .expect("react by number");
    assert!(
        out.status.success(),
        "react by number failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Reacted"),
        "expected Reacted output, got: {}",
        stdout
    );

    // React to message #2 with # prefix.
    let out = Command::new(bin())
        .args(["--db", &db, "react", "--target", "#2", "heart"])
        .output()
        .expect("react by #N");
    assert!(
        out.status.success(),
        "react by #N failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Delete message #1 by number.
    let out = Command::new(bin())
        .args(["--db", &db, "delete-message", "--target", "1"])
        .output()
        .expect("delete by number");
    assert!(
        out.status.success(),
        "delete by number failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Deleted"),
        "expected Deleted output, got: {}",
        stdout
    );

    // Invalid message number should error.
    let out = Command::new(bin())
        .args(["--db", &db, "react", "--target", "99", "sad"])
        .output()
        .expect("react invalid number");
    assert!(
        !out.status.success(),
        "should fail for invalid message number"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid message number"),
        "expected error message, got: {}",
        stderr
    );
}

#[test]
fn test_cli_messages_include_reactions() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("enrich.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    // Send a message and react to it.
    send_message(&db, "hello world");
    let out = Command::new(bin())
        .args(["--db", &db, "react", "--target", "1", "thumbsup"])
        .output()
        .expect("react");
    assert!(
        out.status.success(),
        "react failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Add a second different reaction to the same message.
    let out = Command::new(bin())
        .args(["--db", &db, "react", "--target", "1", "fire"])
        .output()
        .expect("react fire");
    assert!(
        out.status.success(),
        "react fire failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // `topo messages` output should contain both reactions as real emoji.
    let raw = get_messages_raw(&db);
    assert!(
        raw.contains("\u{1f44d}"),
        "expected thumbsup emoji in messages output, got:\n{}",
        raw
    );
    assert!(
        raw.contains("\u{1f525}"),
        "expected fire emoji in messages output, got:\n{}",
        raw
    );
    // Should NOT contain the text shortcode — only real emoji.
    assert!(
        !raw.contains("thumbsup"),
        "should render emoji glyph, not shortcode name, got:\n{}",
        raw
    );
}

#[test]
fn test_cli_send_file_and_messages_display() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("sendfile.db")
        .to_str()
        .unwrap()
        .to_string();

    // Create a temp file to attach.
    let file_path = tmpdir.path().join("notes.txt");
    std::fs::write(&file_path, "These are my notes.\n").unwrap();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    // send-file with content + attachment
    let out = Command::new(bin())
        .args([
            "--db",
            &db,
            "send-file",
            "Check out my notes",
            "--file",
            file_path.to_str().unwrap(),
        ])
        .output()
        .expect("send-file");
    assert!(
        out.status.success(),
        "send-file failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("notes.txt"),
        "send-file output should show filename, got: {}",
        stdout
    );

    // `topo messages` should show the message and the attachment.
    let raw = get_messages_raw(&db);
    assert!(
        raw.contains("Check out my notes"),
        "messages should contain message content, got:\n{}",
        raw
    );
    assert!(
        raw.contains("notes.txt"),
        "messages should contain filename, got:\n{}",
        raw
    );
    // Local files should be complete (all slices present) → ✔
    assert!(
        raw.contains("\u{2714}"),
        "local attachment should show checkmark (complete), got:\n{}",
        raw
    );
}

#[test]
fn test_cli_files_and_save_file_roundtrip_after_sync() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir
        .path()
        .join("alice_files.db")
        .to_str()
        .unwrap()
        .to_string();
    let bob_db = tmpdir
        .path()
        .join("bob_files.db")
        .to_str()
        .unwrap()
        .to_string();
    let timeout_ms = 30000;

    let source_path = tmpdir.path().join("payload.bin");
    let mut expected = vec![0u8; 300_123];
    for (i, b) in expected.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    std::fs::write(&source_path, &expected).unwrap();

    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));
    accept_invite(&bob_db, &invite_link);
    let _bob = start_daemon(&bob_db);

    let send_out = Command::new(bin())
        .args([
            "--db",
            &alice_db,
            "send-file",
            "binary payload",
            "--file",
            source_path.to_str().unwrap(),
        ])
        .output()
        .expect("send-file");
    assert!(
        send_out.status.success(),
        "send-file failed: {}",
        String::from_utf8_lossy(&send_out.stderr)
    );
    let send_stdout = String::from_utf8_lossy(&send_out.stdout);
    let msg_eid = send_stdout
        .lines()
        .find_map(|line| line.strip_prefix("event_id:").map(|s| s.trim().to_string()))
        .expect("send-file output missing event_id");

    assert_eventually(&bob_db, &format!("has_event:{} >= 1", msg_eid), timeout_ms);

    let files_deadline = Instant::now() + Duration::from_secs(20);
    let _files_stdout = loop {
        let files_out = Command::new(bin())
            .args(["--db", &bob_db, "files"])
            .output()
            .expect("files command");
        assert!(
            files_out.status.success(),
            "files command failed: {}",
            String::from_utf8_lossy(&files_out.stderr)
        );
        let files_stdout = String::from_utf8_lossy(&files_out.stdout).to_string();
        if files_stdout.contains("payload.bin") && files_stdout.contains("1.") {
            break files_stdout;
        }
        if Instant::now() >= files_deadline {
            panic!(
                "timed out waiting for bob files list to include payload.bin:\n{}",
                files_stdout
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    };

    let restored_path = tmpdir.path().join("restored.bin");
    let save_deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let save_out = Command::new(bin())
            .args([
                "--db",
                &bob_db,
                "save-file",
                "--target",
                "1",
                "--out",
                restored_path.to_str().unwrap(),
            ])
            .output()
            .expect("save-file command");
        if save_out.status.success() {
            break;
        }
        let last_stderr = String::from_utf8_lossy(&save_out.stderr).to_string();
        let retryable =
            last_stderr.contains("file incomplete") || last_stderr.contains("invalid file number");
        if !retryable {
            panic!("save-file failed unexpectedly: {}", last_stderr);
        }
        if Instant::now() >= save_deadline {
            panic!(
                "timed out waiting for save-file success; last err={}",
                last_stderr
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    let restored = std::fs::read(&restored_path).unwrap();
    assert_eq!(restored, expected, "saved file bytes should match source");
}

#[test]
fn test_cli_generate_files_messages_display() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("genfiles.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    // generate-files creates synthetic message + attachment
    let out = Command::new(bin())
        .args([
            "--db",
            &db,
            "generate-files",
            "--count",
            "1",
            "--size-mib",
            "1",
        ])
        .output()
        .expect("generate-files");
    assert!(
        out.status.success(),
        "generate-files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // `topo messages` should show the attachment with filename and checkmark.
    let raw = get_messages_raw(&db);
    assert!(
        raw.contains("file-0.bin"),
        "messages should contain synthetic filename, got:\n{}",
        raw
    );
    assert!(
        raw.contains("\u{2714}"),
        "local attachment should show checkmark (complete), got:\n{}",
        raw
    );
}

#[test]
fn test_cli_event_tree_shows_structure() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("event_tree.db")
        .to_str()
        .unwrap()
        .to_string();

    // create-workspace populates the db with identity chain events.
    create_workspace(&db);

    // event-tree is served via daemon RPC.
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "event-tree"])
        .output()
        .expect("event-tree command");
    assert!(
        out.status.success(),
        "event-tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Should contain the root workspace event.
    assert!(
        stdout.contains("workspace"),
        "event-tree should show workspace event, got:\n{}",
        stdout
    );
    // Should contain tree connectors (proves hierarchy is rendered).
    assert!(
        stdout.contains("├──") || stdout.contains("└──"),
        "event-tree should show tree connectors, got:\n{}",
        stdout
    );
    // Should contain the root marker.
    assert!(
        stdout.contains("root"),
        "event-tree should mark root events, got:\n{}",
        stdout
    );
    // Should show event count footer.
    assert!(
        stdout.contains("events."),
        "event-tree should show event count, got:\n{}",
        stdout
    );
    // Parenthesized short IDs.
    assert!(
        stdout.contains("("),
        "event-tree should show parenthesized IDs, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_list_shows_all_events() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("event_list.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "event-list"])
        .output()
        .expect("event-list command");
    assert!(
        out.status.success(),
        "event-list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);

    // Should show the event-list footer.
    assert!(
        stdout.contains("events. Sorted by insertion order."),
        "event-list should show event count footer, got:\n{}",
        stdout
    );
    // Should contain workspace event type.
    assert!(
        stdout.contains("workspace"),
        "event-list should show workspace event, got:\n{}",
        stdout
    );
    // Should show dep references with parenthesized IDs.
    assert!(
        stdout.contains("signed_by:"),
        "event-list should show dep fields, got:\n{}",
        stdout
    );
    // Should show event count footer.
    assert!(
        stdout.contains("events."),
        "event-list should show event count, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_tree_empty_db() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("empty.db").to_str().unwrap().to_string();

    // event-tree is served via daemon RPC (even for an empty db).
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "event-tree"])
        .output()
        .expect("event-tree command");
    assert!(
        out.status.success(),
        "event-tree on empty db failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("no events"),
        "event-tree on empty db should say no events, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_list_empty_db() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("empty_list.db")
        .to_str()
        .unwrap()
        .to_string();

    // event-list is served via daemon RPC (even for an empty db).
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "event-list"])
        .output()
        .expect("event-list command");
    assert!(
        out.status.success(),
        "event-list on empty db failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("no events"),
        "event-list on empty db should say no events, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_tree_cross_refs_shown() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("cross_ref.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let out = Command::new(bin())
        .args(["--db", &db, "event-tree"])
        .output()
        .expect("event-tree command");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);

    // peer_shared has two deps (user_event_id + signed_by);
    // the tree parent is user_event_id, so signed_by should appear as a cross-ref.
    let has_cross_ref = stdout.lines().any(|line| {
        line.contains("peer_shared") && line.contains("[") && line.contains("signed_by:")
    });
    assert!(
        has_cross_ref,
        "event-tree should show cross-ref annotation on peer_shared, got:\n{}",
        stdout
    );
}

#[test]
fn test_cli_event_commands_require_daemon() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("no_daemon.db")
        .to_str()
        .unwrap()
        .to_string();

    let event_list = Command::new(bin())
        .args(["--db", &db, "event-list"])
        .output()
        .expect("event-list command");
    assert!(
        !event_list.status.success(),
        "event-list should fail without daemon"
    );
    let list_stderr = String::from_utf8_lossy(&event_list.stderr);
    assert!(
        list_stderr.contains("daemon is not running"),
        "event-list should report daemon requirement, got:\n{}",
        list_stderr
    );

    let event_tree = Command::new(bin())
        .args(["--db", &db, "event-tree"])
        .output()
        .expect("event-tree command");
    assert!(
        !event_tree.status.success(),
        "event-tree should fail without daemon"
    );
    let tree_stderr = String::from_utf8_lossy(&event_tree.stderr);
    assert!(
        tree_stderr.contains("daemon is not running"),
        "event-tree should report daemon requirement, got:\n{}",
        tree_stderr
    );
}
