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
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use topo::crypto::event_id_from_base64;
use topo::db::open_connection;
use topo::event_modules::workspace::commands::{
    accept_invite as accept_invite_without_sync, create_user_invite_raw,
};
use topo::event_modules::workspace::invite_link::{create_invite_link, parse_bootstrap_address};
use topo::testutil::{DaemonGuard, Peer};

fn cli_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn create_user_invite_link_for_test_peer(creator: &Peer, bootstrap_addr: &str) -> String {
    let creator_db = open_connection(&creator.db_path).expect("open creator db");
    let creator_peer_key = creator
        .peer_shared_signing_key
        .as_ref()
        .expect("creator must have a peer_shared signer");
    let creator_peer_eid = creator
        .peer_shared_event_id
        .expect("creator must have a peer_shared event");
    let creator_admin_eid = creator_db
        .query_row(
            "SELECT event_id
             FROM admins
             WHERE recorded_by = ?1
             ORDER BY event_id ASC
             LIMIT 1",
            rusqlite::params![&creator.identity],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|b64| event_id_from_base64(&b64))
        .expect("creator must have an admin event");

    let invite = create_user_invite_raw(
        &creator_db,
        &creator.identity,
        creator_peer_key,
        &creator_peer_eid,
        &creator_admin_eid,
        &creator.workspace_id,
    )
    .expect("create user invite");
    let bootstrap_addr =
        parse_bootstrap_address(bootstrap_addr).expect("parse bootstrap address for invite link");
    create_invite_link(&invite, &[bootstrap_addr], &creator.spki_fingerprint())
        .expect("create invite link")
}

fn tenant_index_for_peer_id(db_path: &str, peer_id: &str) -> usize {
    let conn = open_connection(db_path).expect("open db");
    let mut stmt = conn
        .prepare(
            "SELECT DISTINCT recorded_by
             FROM invites_accepted
             ORDER BY recorded_by",
        )
        .expect("prepare tenant scope query");
    let peer_ids = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .expect("query tenant scopes")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect tenant scopes");
    peer_ids
        .iter()
        .position(|id| id == peer_id)
        .map(|idx| idx + 1)
        .expect("peer id should appear in tenant scopes")
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
    // daemons are running (avoids counting accept bootstrap artifacts).
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

#[test]
fn test_cli_selected_partial_join_tenant_reports_initial_sync_errors() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    create_workspace(&bob_db);

    let alice = Peer::new_with_identity("alice-partial-source");
    let unreachable_bootstrap = format!("127.0.0.1:{}", random_port());
    let invite_link = create_user_invite_link_for_test_peer(&alice, &unreachable_bootstrap);
    let partial_join = accept_invite_without_sync(&bob_db, &invite_link, "bob-join", "pending")
        .expect("accept invite without bootstrap sync");
    let partial_tenant_index = tenant_index_for_peer_id(&bob_db, &partial_join.peer_id);

    let _daemon = start_daemon(&bob_db);

    let select = topo_cmd(&bob_db, &["use-tenant", &partial_tenant_index.to_string()]);
    assert!(
        select.status.success(),
        "use-tenant failed: stdout={} stderr={}",
        String::from_utf8_lossy(&select.stdout),
        String::from_utf8_lossy(&select.stderr)
    );

    let active = topo_cmd(&bob_db, &["active-tenant"]);
    assert!(active.status.success(), "active-tenant failed");
    assert_eq!(
        String::from_utf8_lossy(&active.stdout).trim(),
        partial_join.peer_id,
        "active tenant should match the selected partial-join peer"
    );

    let identity = topo_cmd(&bob_db, &["identity"]);
    assert!(
        identity.status.success(),
        "identity should still succeed on a partial join tenant: stdout={} stderr={}",
        String::from_utf8_lossy(&identity.stdout),
        String::from_utf8_lossy(&identity.stderr)
    );
    let identity_stdout = String::from_utf8_lossy(&identity.stdout);
    assert!(
        identity_stdout.contains("Transport:"),
        "identity output should include transport fingerprint: {}",
        identity_stdout
    );
    assert!(
        identity_stdout.contains("User:      (none)"),
        "identity should show that user identity is not projected yet: {}",
        identity_stdout
    );

    let send = topo_cmd(&bob_db, &["send", "still-waiting"]);
    assert!(
        !send.status.success(),
        "send should fail for a tenant whose initial sync has not completed"
    );
    let send_stderr = String::from_utf8_lossy(&send.stderr);
    assert!(
        send_stderr.contains("workspace has not completed initial sync yet"),
        "send should explain the partial-join state: {}",
        send_stderr
    );

    let invite = topo_cmd(
        &bob_db,
        &["invite", "--public-addr", &unreachable_bootstrap],
    );
    assert!(
        !invite.status.success(),
        "invite should fail for a tenant whose initial sync has not completed"
    );
    let invite_stderr = String::from_utf8_lossy(&invite.stderr);
    assert!(
        invite_stderr.contains("workspace has not completed initial sync yet"),
        "invite should explain the partial-join state: {}",
        invite_stderr
    );

    let link = topo_cmd(&bob_db, &["link", "--public-addr", &unreachable_bootstrap]);
    assert!(
        !link.status.success(),
        "device-link invite should fail for a tenant whose initial sync has not completed"
    );
    let link_stderr = String::from_utf8_lossy(&link.stderr);
    assert!(
        link_stderr.contains("workspace has not completed initial sync yet"),
        "device-link invite should explain the partial-join state: {}",
        link_stderr
    );
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

/// E2E file sync test: Alice sends a file, Bob receives all slices, saves to disk.
#[test]
fn test_cli_file_upload_sync_and_save() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 30000;

    // Create a test file with known content
    let test_file = tmpdir.path().join("testfile.txt");
    let test_content = "Hello from the file system! This is a test file for e2e sync.\n";
    std::fs::write(&test_file, test_content).unwrap();

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let _alice = start_daemon(&alice_db);

    // Alice sends the file
    let file_eid = send_file(
        &alice_db,
        "Check out this file",
        test_file.to_str().unwrap(),
    );
    assert!(!file_eid.is_empty(), "send-file should return event_id");

    // Alice creates invite
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob accepts invite and starts daemon
    accept_invite(&bob_db, &invite_link);
    let _bob = start_daemon(&bob_db);

    // Wait for Bob to receive Alice's message event
    assert_eventually(&bob_db, &format!("has_event:{} >= 1", file_eid), timeout_ms);

    // Wait for message projection and attachment completion
    assert_eventually(&bob_db, "message_count >= 1", timeout_ms);

    // Poll until Bob shows the attachment with checkmark (all slices projected)
    let start = std::time::Instant::now();
    loop {
        let raw = get_messages_raw(&bob_db);
        if raw.contains("\u{2714}") {
            break;
        }
        if start.elapsed().as_secs() >= 30 {
            panic!(
                "Bob's file attachment never completed (no checkmark in messages output):\n{}",
                raw
            );
        }
        std::thread::sleep(Duration::from_millis(500));
    }

    // Save the file to disk
    let saved_path = tmpdir.path().join("received_file.txt");
    let out = save_file(&bob_db, "1", saved_path.to_str().unwrap());
    assert!(
        out.status.success(),
        "save-file failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("saved") && stdout.contains("bytes"),
        "save-file output should confirm bytes written, got: {}",
        stdout
    );

    // Verify saved content matches original
    let saved_content = std::fs::read_to_string(&saved_path).unwrap();
    assert_eq!(
        saved_content, test_content,
        "saved file content should match original"
    );
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

/// Bootstrap trust test using production invite / accept CLI flow.
/// No direct SQL trust seeding — trust is materialized through CLI commands.
///
/// Projection-first flow: accept creates identity chain (events may
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
        .args(["--db", &db, "react", "thumbsup", "1"])
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
        .args(["--db", &db, "react", "heart", "#2"])
        .output()
        .expect("react by #N");
    assert!(
        out.status.success(),
        "react by #N failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Delete message #1 by number.
    let out = Command::new(bin())
        .args(["--db", &db, "delete-message", "1"])
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
        .args(["--db", &db, "react", "sad", "99"])
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
        .args(["--db", &db, "react", "thumbsup", "1"])
        .output()
        .expect("react");
    assert!(
        out.status.success(),
        "react failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Add a second different reaction to the same message.
    let out = Command::new(bin())
        .args(["--db", &db, "react", "fire", "1"])
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
fn test_cli_sub_commands_accept_name_selector_and_nested_shape() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("subs.db").to_str().unwrap().to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let create_out = Command::new(bin())
        .args([
            "--db",
            &db,
            "sub",
            "create",
            "--name",
            "new-messages",
            "--event-type",
            "message",
        ])
        .output()
        .expect("sub create");
    assert!(
        create_out.status.success(),
        "sub create failed: {}",
        String::from_utf8_lossy(&create_out.stderr)
    );

    let list_out = Command::new(bin())
        .args(["--db", &db, "subs", "list"])
        .output()
        .expect("subs list");
    assert!(
        list_out.status.success(),
        "subs list failed: {}",
        String::from_utf8_lossy(&list_out.stderr)
    );
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    assert!(
        list_stdout.contains("new-messages"),
        "subs list should include subscription name, got: {}",
        list_stdout
    );

    send_message(&db, "hello subscriptions");
    let poll_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let poll_out = Command::new(bin())
            .args(["--db", &db, "sub", "poll", "new-messages"])
            .output()
            .expect("sub poll by name");
        assert!(
            poll_out.status.success(),
            "sub poll by name failed: {}",
            String::from_utf8_lossy(&poll_out.stderr)
        );
        let poll_stdout = String::from_utf8_lossy(&poll_out.stdout).to_string();
        if poll_stdout.contains("hello subscriptions") {
            break;
        }
        if Instant::now() >= poll_deadline {
            panic!(
                "timed out waiting for subscription item by name selector:\n{}",
                poll_stdout
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let state_out = Command::new(bin())
        .args(["--db", &db, "sub", "state"])
        .output()
        .expect("sub state default selector");
    assert!(
        state_out.status.success(),
        "sub state default selector failed: {}",
        String::from_utf8_lossy(&state_out.stderr)
    );
    let state_stdout = String::from_utf8_lossy(&state_out.stdout);
    assert!(
        state_stdout.contains("pending="),
        "sub state should print summary, got: {}",
        state_stdout
    );

    let disable_out = Command::new(bin())
        .args(["--db", &db, "sub", "disable", "--sub", "new-messages"])
        .output()
        .expect("sub disable --sub");
    assert!(
        disable_out.status.success(),
        "sub disable --sub failed: {}",
        String::from_utf8_lossy(&disable_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&disable_out.stderr).contains("deprecated"),
        "sub disable --sub should emit deprecation warning, got: {}",
        String::from_utf8_lossy(&disable_out.stderr)
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
fn test_cli_send_file_accepts_path_from_stdin_when_flag_omitted() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("sendfile_stdin.db")
        .to_str()
        .unwrap()
        .to_string();

    let file_path = tmpdir.path().join("stdin-notes.txt");
    std::fs::write(&file_path, "attachment via stdin path\n").unwrap();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let mut child = Command::new(bin())
        .args(["--db", &db, "send-file", "stdin attachment"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn send-file");
    child
        .stdin
        .as_mut()
        .expect("send-file stdin should be piped")
        .write_all(format!("{}\n", file_path.display()).as_bytes())
        .expect("write file path to send-file stdin");

    let out = child.wait_with_output().expect("wait for send-file");
    assert!(
        out.status.success(),
        "send-file failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("stdin-notes.txt"),
        "send-file output should show filename, got: {}",
        stdout
    );
}

#[test]
fn test_cli_send_file_without_path_uses_placeholder_and_save_file_defaults_target() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("sendfile_placeholder.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let _daemon = start_daemon(&db);

    let send_out = Command::new(bin())
        .args(["--db", &db, "send-file", "missing path"])
        .stdin(Stdio::null())
        .output()
        .expect("send-file");
    assert!(
        send_out.status.success(),
        "send-file should fall back to placeholder when no file path is provided: {}",
        String::from_utf8_lossy(&send_out.stderr)
    );
    let send_stdout = String::from_utf8_lossy(&send_out.stdout);
    assert!(
        send_stdout.contains("topo-placeholder.txt"),
        "send-file should report placeholder filename, got: {}",
        send_stdout
    );

    let positional_out = tmpdir.path().join("placeholder-positional.txt");
    let save_positional = Command::new(bin())
        .args([
            "--db",
            &db,
            "save-file",
            "1",
            "--out",
            positional_out.to_str().unwrap(),
        ])
        .output()
        .expect("save-file positional target");
    assert!(
        save_positional.status.success(),
        "save-file with positional target failed: {}",
        String::from_utf8_lossy(&save_positional.stderr)
    );

    let long_flag_out = tmpdir.path().join("placeholder-long-flag.txt");
    let save_long_flag = Command::new(bin())
        .args([
            "--db",
            &db,
            "save-file",
            "--target",
            "1",
            "--out",
            long_flag_out.to_str().unwrap(),
        ])
        .output()
        .expect("save-file --target");
    assert!(
        save_long_flag.status.success(),
        "save-file --target failed: {}",
        String::from_utf8_lossy(&save_long_flag.stderr)
    );
    assert!(
        String::from_utf8_lossy(&save_long_flag.stderr).contains("deprecated"),
        "save-file --target should emit deprecation warning, got: {}",
        String::from_utf8_lossy(&save_long_flag.stderr)
    );

    let default_out = tmpdir.path().join("placeholder-default.txt");
    let save_default = Command::new(bin())
        .args([
            "--db",
            &db,
            "save-file",
            "--out",
            default_out.to_str().unwrap(),
        ])
        .output()
        .expect("save-file default target");
    assert!(
        save_default.status.success(),
        "save-file default target failed: {}",
        String::from_utf8_lossy(&save_default.stderr)
    );

    let positional_content = std::fs::read_to_string(&positional_out).unwrap();
    let long_flag_content = std::fs::read_to_string(&long_flag_out).unwrap();
    let default_content = std::fs::read_to_string(&default_out).unwrap();
    assert_eq!(positional_content, "placeholder file\n");
    assert_eq!(long_flag_content, "placeholder file\n");
    assert_eq!(default_content, "placeholder file\n");
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

// ---------------------------------------------------------------------------
// Error-message quality tests
// ---------------------------------------------------------------------------

/// When a second daemon tries to bind the same port, it should exit with a
/// clear error about the port being in use, not silently retry forever.
#[test]
fn test_cli_port_already_in_use_error() {
    let _guard = cli_test_lock();
    let (_tmpdir_a, db_a) = temp_db();
    let (_tmpdir_b, db_b) = temp_db();

    // Daemon A binds a specific port.
    let port = random_port();
    create_workspace(&db_a);
    let _daemon_a = start_daemon_on_port(&db_a, port);

    // Daemon B tries the same port — should fail with an informative error.
    create_workspace(&db_b);
    let output = Command::new(bin())
        .arg("--db")
        .arg(&db_b)
        .arg("start")
        .arg("--bind")
        .arg(format!("127.0.0.1:{}", port))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("failed to run second daemon");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "second daemon on same port should exit with error"
    );
    assert!(
        stderr.contains("already in use") || stderr.contains("address already in use"),
        "error should mention port already in use, got:\n{}",
        stderr
    );
}

/// Connecting to an address where nothing is listening should produce a
/// human-readable diagnostic (timeout or connection refused), not raw errors.
#[test]
fn test_cli_connect_to_dead_address_error() {
    let _guard = cli_test_lock();
    let (_tmpdir_a, db_a) = temp_db();
    let (_tmpdir_b, db_b) = temp_db();

    // Alice creates workspace and generates an invite with a dead address.
    create_workspace(&db_a);
    let _daemon_a = start_daemon(&db_a);
    let dead_port = random_port();
    let invite = create_invite(&db_a, &format!("127.0.0.1:{}", dead_port));
    drop(_daemon_a); // Kill Alice's daemon so the address is dead.

    // Bob accepts the invite — daemon will try to connect to the dead address.
    // Redirect daemon output to file so we can inspect logs after shutdown.
    let log_dir = std::path::Path::new(&db_b).parent().unwrap();
    let stdout_path = log_dir.join("daemon_stdout.log");

    let _daemon_b = start_daemon_with_options(
        &db_b,
        &DaemonOptions {
            stdout_file: Some(stdout_path.clone()),
            ..Default::default()
        },
    );

    // Accept invite (this triggers bootstrap connect attempts to the dead address).
    let accept_out = Command::new(bin())
        .args(["--db", &db_b, "accept", &invite])
        .output()
        .expect("accept command");
    assert!(
        accept_out.status.success(),
        "accept should succeed: {}",
        String::from_utf8_lossy(&accept_out.stderr)
    );

    // QUIC (UDP) has no TCP-style "connection refused" — dead addresses time out
    // after ~30s. Wait long enough for at least one timeout.
    std::thread::sleep(Duration::from_secs(35));

    // Stop daemon.
    let _ = Command::new(bin())
        .args(["--db", &db_b, "stop"])
        .output();
    std::thread::sleep(Duration::from_millis(500));
    drop(_daemon_b);

    let output = std::fs::read_to_string(&stdout_path).unwrap_or_default();

    assert!(
        output.contains("timed out")
            || output.contains("connection refused")
            || output.contains("nothing is listening")
            || output.contains("unreachable"),
        "connect-to-dead-address should produce a human-readable diagnostic \
         (timed out / connection refused / unreachable), got:\n{}",
        output
    );
    // Verify it includes our diagnostic text, not just raw error.
    assert!(
        output.contains("the peer may be offline")
            || output.contains("nothing is listening")
            || output.contains("unreachable"),
        "error should include actionable guidance, got:\n{}",
        output
    );
}

/// When peers present untrusted certificates, the error should explain it's a
/// certificate mismatch, not dump raw TLS internals.
#[test]
fn test_cli_untrusted_peer_certificate_error() {
    let _guard = cli_test_lock();
    let (_tmpdir_a, db_a) = temp_db();
    let (_tmpdir_b, db_b) = temp_db();

    // Alice creates workspace and runs daemon.
    create_workspace(&db_a);
    let port_a = random_port();
    let _daemon_a = start_daemon_on_port(&db_a, port_a);

    // Create an invite from Alice with a BOGUS SPKI fingerprint.
    // Bob will connect to Alice's real address but his client-side TLS
    // verifier will reject because Alice's real cert doesn't match the
    // bogus fingerprint in the invite.
    let bogus_spki = "aa".repeat(32); // 64 hex chars = 32 bytes of 0xaa
    let invite =
        create_invite_with_spki(&db_a, &format!("127.0.0.1:{}", port_a), Some(&bogus_spki));

    // Bob's daemon — redirect stdout to file for log inspection.
    create_workspace(&db_b);
    let log_dir_b = std::path::Path::new(&db_b).parent().unwrap();
    let bob_stdout = log_dir_b.join("daemon_stdout.log");

    let _daemon_b = start_daemon_with_options(
        &db_b,
        &DaemonOptions {
            stdout_file: Some(bob_stdout.clone()),
            ..Default::default()
        },
    );

    // Accept the invite — triggers bootstrap connect attempts.
    // Bob will connect to Alice but reject her cert (wrong SPKI).
    let accept_out = Command::new(bin())
        .args(["--db", &db_b, "accept", &invite])
        .output()
        .expect("accept command");
    assert!(
        accept_out.status.success(),
        "accept should succeed: {}",
        String::from_utf8_lossy(&accept_out.stderr)
    );

    // Give time for runtime restart + TLS handshake attempts.
    std::thread::sleep(Duration::from_secs(8));

    // Stop daemons and read logs.
    let _ = Command::new(bin())
        .args(["--db", &db_b, "stop"])
        .output();
    std::thread::sleep(Duration::from_millis(500));
    drop(_daemon_b);

    let bob_log = std::fs::read_to_string(&bob_stdout).unwrap_or_default();

    // Bob should see our improved error about certificate mismatch
    // (his client-side TLS verifier rejects Alice's cert because the
    // SPKI in the invite doesn't match Alice's real cert).
    assert!(
        bob_log.contains("Certificate mismatch")
            || bob_log.contains("not trusted")
            || bob_log.contains("trust_rejected"),
        "untrusted peer error should mention certificate mismatch or \
         trust rejection, got:\n{}",
        bob_log
    );
    // Should include human-readable explanation.
    assert!(
        bob_log.contains("transport identity")
            || bob_log.contains("not trusted by this workspace")
            || bob_log.contains("Certificate mismatch"),
        "error should include human-readable explanation, got:\n{}",
        bob_log
    );
}
