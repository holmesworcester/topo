use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use rusqlite::Connection;

fn bin() -> String {
    env!("CARGO_BIN_EXE_topo").to_string()
}

/// Pick a random port in the ephemeral range to avoid conflicts between
/// parallel test runs and other services.
fn random_port() -> u16 {
    // Bind to :0, read the assigned port, close immediately
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn socket_path_for_db(db: &str) -> PathBuf {
    topo::service::socket_path_for_db(db)
}

fn create_workspace(db: &str) {
    let out = Command::new(bin())
        .args(["create-workspace", "--db", db])
        .output()
        .expect("create-workspace");
    assert!(
        out.status.success(),
        "create-workspace failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn start_daemon_with_options(db: &str, bind_port: u16, disable_placeholder_autodial: bool) -> Child {
    let socket = socket_path_for_db(db);
    let mut cmd = Command::new(bin());
    cmd.arg("--db")
        .arg(db)
        .arg("start")
        .arg("--bind")
        .arg(format!("127.0.0.1:{}", bind_port))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if disable_placeholder_autodial {
        cmd.env("P7_DISABLE_PLACEHOLDER_AUTODIAL", "1");
    }

    let mut child = cmd.spawn().expect("failed to start daemon");

    // Wait for socket to appear, checking that daemon hasn't exited early.
    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        // Check if process already exited (immediate crash / bind failure).
        if let Some(status) = child.try_wait().expect("failed to check daemon status") {
            panic!(
                "daemon exited immediately with {} (db={}, port={})",
                status, db, bind_port
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        socket.exists(),
        "daemon socket did not appear at {} within 5s (db={}, port={})",
        socket.display(),
        db,
        bind_port
    );

    // Verify daemon is accepting RPC (socket exists but server may not be listening yet).
    let rpc_start = std::time::Instant::now();
    loop {
        let out = Command::new(bin())
            .args(["--db", db, "status"])
            .output()
            .expect("failed to probe daemon status");
        if out.status.success() {
            break;
        }
        if rpc_start.elapsed().as_secs() >= 5 {
            panic!(
                "daemon socket exists but RPC not responding after 5s (db={}, port={}): {}",
                db,
                bind_port,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    child
}

fn start_daemon(db: &str, bind_port: u16) -> Child {
    start_daemon_with_options(db, bind_port, false)
}

fn send_message(db: &str, content: &str) -> String {
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("send")
        .arg(content)
        .output()
        .expect("failed to run send");
    assert!(
        output.status.success(),
        "send failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("event_id:"))
        .expect("send output missing event_id: line")
        .to_string()
}

fn assert_now(db: &str, predicate: &str) {
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("assert-now")
        .arg(predicate)
        .output()
        .expect("failed to run assert-now");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "assert-now failed: {} ({})",
        predicate,
        text.trim()
    );
}

fn assert_eventually(db: &str, predicate: &str, timeout_ms: u64) {
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("assert-eventually")
        .arg(predicate)
        .arg("--timeout-ms")
        .arg(timeout_ms.to_string())
        .output()
        .expect("failed to run assert-eventually");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "assert-eventually timed out: {} ({})",
        predicate,
        text.trim()
    );
}

fn get_messages(db: &str) -> Vec<String> {
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("messages")
        .output()
        .expect("failed to run messages");
    let text = String::from_utf8_lossy(&output.stdout);
    // Parse numbered lines like "    1. Hello from Alice"
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            // Match "N. content" pattern
            let dot_pos = trimmed.find(". ")?;
            let prefix = &trimmed[..dot_pos];
            if prefix.chars().all(|c| c.is_ascii_digit()) {
                Some(trimmed[dot_pos + 2..].to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Helper: run create-invite CLI command (daemon-only). Returns the invite link printed to stdout.
fn create_invite(db: &str, bootstrap_addr: &str) -> String {
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("create-invite")
        .arg("--public-addr")
        .arg(bootstrap_addr)
        .output()
        .expect("failed to run create-invite");
    assert!(
        output.status.success(),
        "create-invite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Extract the quiet:// link line (may have "Created invite #N" prefix line)
    stdout
        .lines()
        .find(|line| line.starts_with("quiet://"))
        .unwrap_or_else(|| stdout.trim())
        .to_string()
}

/// Helper: run accept-invite CLI command (direct, pre-daemon).
fn accept_invite(db: &str, invite_link: &str) {
    let output = Command::new(bin())
        .arg("accept-invite")
        .arg("--db")
        .arg(db)
        .arg("--invite")
        .arg(invite_link)
        .output()
        .expect("failed to run accept-invite");
    assert!(
        output.status.success(),
        "accept-invite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn count_rows(db: &str, table: &str) -> i64 {
    let conn = Connection::open(db).expect("failed to open db");
    let sql = format!("SELECT COUNT(*) FROM {}", table);
    conn.query_row(&sql, [], |row| row.get(0))
        .expect("failed to query row count")
}

/// Functional sync test using invite-based shared workspace flow.
/// Alice bootstraps identity, creates invite, starts daemon.
/// Bob accepts invite (bootstrap sync), starts daemon with invite-seeded autodial.
/// Both send messages in the shared workspace.
#[test]
fn test_cli_bidirectional_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 15000;

    let alice_port = random_port();
    let bob_port = random_port();

    // Alice creates workspace (identity chain)
    create_workspace(&alice_db);

    // Alice starts daemon (auto-selects single peer)
    let mut alice = start_daemon(&alice_db, alice_port);

    // Alice sends messages via daemon RPC
    send_message(&alice_db, "Hello from Alice");
    let alice_eid = send_message(&alice_db, "How are you?");

    // Alice creates invite (via daemon RPC)
    let invite_link = create_invite(&alice_db, &format!("127.0.0.1:{}", alice_port));

    // Bob accepts invite (bootstrap sync from Alice)
    accept_invite(&bob_db, &invite_link);

    // Bob starts daemon; invite-seeded autodial reaches Alice.
    let mut bob = start_daemon(&bob_db, bob_port);
    std::thread::sleep(Duration::from_secs(1));

    // Bob sends a message in the shared workspace
    let bob_eid = send_message(&bob_db, "Hey Alice!");
    assert_eventually(&alice_db, &format!("has_event:{} >= 1", bob_eid), timeout_ms);
    assert_eventually(&bob_db, &format!("has_event:{} >= 1", alice_eid), timeout_ms);

    // Verify specific message content arrived on both sides
    let alice_msgs = get_messages(&alice_db);
    assert!(alice_msgs.len() >= 3, "Alice should see at least 3 messages, got {}", alice_msgs.len());
    assert!(alice_msgs.contains(&"Hello from Alice".to_string()));
    assert!(alice_msgs.contains(&"How are you?".to_string()));
    assert!(alice_msgs.contains(&"Hey Alice!".to_string()));

    let bob_msgs = get_messages(&bob_db);
    assert!(bob_msgs.len() >= 3, "Bob should see at least 3 messages, got {}", bob_msgs.len());
    assert!(bob_msgs.contains(&"Hello from Alice".to_string()));
    assert!(bob_msgs.contains(&"How are you?".to_string()));
    assert!(bob_msgs.contains(&"Hey Alice!".to_string()));

    // Cleanup
    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}

/// Functional sync test using invite-based flow.
/// Verifies sync picks up new messages over time (ongoing sync).
#[test]
fn test_cli_ongoing_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 15000;

    let alice_port = random_port();
    let bob_port = random_port();

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let mut alice = start_daemon(&alice_db, alice_port);

    // Alice sends bootstrap message
    send_message(&alice_db, "bootstrap");

    // Alice creates invite
    let invite_link = create_invite(&alice_db, &format!("127.0.0.1:{}", alice_port));

    // Bob accepts invite and starts daemon
    accept_invite(&bob_db, &invite_link);
    let mut bob = start_daemon(&bob_db, bob_port);
    std::thread::sleep(Duration::from_secs(1));

    // Both send messages over time
    send_message(&alice_db, "Round 1");
    send_message(&bob_db, "Round 2");
    send_message(&alice_db, "Round 3a");
    let bob_last_eid = send_message(&bob_db, "Round 3b");
    std::thread::sleep(Duration::from_secs(1));
    let alice_last_eid = send_message(&alice_db, "Round 4");

    assert_eventually(&alice_db, &format!("has_event:{} >= 1", bob_last_eid), timeout_ms);
    assert_eventually(&bob_db, &format!("has_event:{} >= 1", alice_last_eid), timeout_ms);

    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}

/// Two separate local daemons should discover and sync on the same machine
/// even when invite-seeded placeholder autodial is disabled.
#[test]
fn test_cli_local_mdns_discovery_without_placeholder_autodial() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 20000;

    let alice_port = random_port();
    let bob_port = random_port();

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let mut alice = start_daemon_with_options(&alice_db, alice_port, true);

    // Alice sends seed message and creates invite
    let alice_seed_eid = send_message(&alice_db, "alice-seed");
    let invite_link = create_invite(&alice_db, &format!("127.0.0.1:{}", alice_port));

    // Bob accepts invite and starts daemon with placeholder autodial disabled
    accept_invite(&bob_db, &invite_link);
    let mut bob = start_daemon_with_options(&bob_db, bob_port, true);
    std::thread::sleep(Duration::from_secs(2));

    // Validate bidirectional convergence.
    let bob_msg_eid = send_message(&bob_db, "bob-via-mdns-localhost");
    assert_eventually(&alice_db, &format!("has_event:{} >= 1", bob_msg_eid), timeout_ms);
    assert_eventually(&bob_db, &format!("has_event:{} >= 1", alice_seed_eid), timeout_ms);

    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}

#[test]
fn test_cli_send_and_messages() {
    // Basic test: create workspace, start daemon, send/messages work
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("test.db").to_str().unwrap().to_string();
    let port = random_port();

    create_workspace(&db);
    let mut daemon = start_daemon(&db, port);

    let _first_eid = send_message(&db, "First message");
    let second_eid = send_message(&db, "Second message");

    assert_now(&db, "message_count == 2");
    assert_now(&db, &format!("has_event:{} >= 1", second_eid));

    let messages = get_messages(&db);
    assert_eq!(messages.len(), 2);
    assert!(messages.contains(&"First message".to_string()));
    assert!(messages.contains(&"Second message".to_string()));

    let _ = daemon.kill();
    let _ = daemon.wait();
}

/// TRUST POLICY TEST: untrusted peer is rejected.
/// Alice bootstraps identity (PeerShared self-trust makes has_any_trusted_peer true).
/// Bob has independent identity (not in Alice's workspace). Alice should reject Bob.
#[test]
fn test_cli_unpinned_peer_rejected() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    let alice_port = random_port();
    let bob_port = random_port();

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let mut alice = start_daemon(&alice_db, alice_port);

    // Alice sends a message
    send_message(&alice_db, "alice bootstrap");

    // Bob creates independent workspace (not in Alice's workspace)
    create_workspace(&bob_db);
    let mut bob = start_daemon(&bob_db, bob_port);

    // Bob sends a message
    let bob_eid = send_message(&bob_db, "Should not arrive");
    // Give some time for sync to try
    std::thread::sleep(Duration::from_secs(3));

    assert_now(&alice_db, &format!("has_event:{} == 0", bob_eid));

    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}

/// TRUST POLICY TEST: sync with no trusted peers is rejected at startup.
#[test]
fn test_cli_sync_without_trust_fails() {
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir
        .path()
        .join("no_trust.db")
        .to_str()
        .unwrap()
        .to_string();
    let port = random_port();

    // Start sync with no identity chain (no trusted peers) — should fail immediately
    let output = Command::new(bin())
        .arg("sync")
        .arg("--bind")
        .arg(format!("127.0.0.1:{}", port))
        .arg("--db")
        .arg(&db)
        .output()
        .expect("failed to run sync");

    assert!(
        !output.status.success(),
        "sync with no trusted peers should fail, but exited with {:?}",
        output.status.code()
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No local identities"),
        "error should mention missing identities, got: {}",
        stderr
    );
}

/// Bootstrap trust test using production create-invite / accept-invite CLI flow.
/// No direct SQL trust seeding — trust is materialized through CLI commands.
/// accept-invite does bootstrap sync (fetches workspace events from Alice),
/// then creates the full identity chain and records transport trust.
#[test]
fn test_cli_sync_bootstrap_from_accepted_invite_data() {
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

    let alice_port = random_port();
    let bob_port = random_port();

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let mut alice = start_daemon(&alice_db, alice_port);

    // Alice sends bootstrap message
    send_message(&alice_db, "bootstrap");

    // Alice creates invite (via daemon RPC)
    let invite_link = create_invite(
        &alice_db,
        &format!("127.0.0.1:{}", alice_port),
    );

    // Bob accepts invite: installs deterministic cert, bootstrap-syncs from
    // Alice, creates identity chain, records bootstrap trust.
    accept_invite(&bob_db, &invite_link);
    assert!(
        count_rows(&alice_db, "secret_shared") >= 1,
        "inviter should emit at least one secret_shared key-wrap during invite creation"
    );
    assert!(
        count_rows(&bob_db, "secret_keys") >= 1,
        "invitee should materialize local secret_key after unwrap"
    );
    assert!(
        count_rows(&bob_db, "secret_shared") >= 1,
        "invitee should eventually project inviter secret_shared after local key materialization"
    );

    // Bob starts daemon; invite bootstrap trust seeds daemon autodial.
    let mut bob = start_daemon(&bob_db, bob_port);
    std::thread::sleep(Duration::from_secs(1));

    let bob_eid = send_message(&bob_db, "bootstrap trust from invite data");
    assert_eventually(&alice_db, &format!("has_event:{} >= 1", bob_eid), timeout_ms);

    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}

// ---------------------------------------------------------------------------
// New CLI command tests
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
    assert!(stdout.contains("topo"), "bash completions should reference 'topo'");
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
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("ban.db").to_str().unwrap().to_string();
    let port = random_port();

    create_workspace(&db);
    let mut daemon = start_daemon(&db, port);

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

    let _ = daemon.kill();
    let _ = daemon.wait();
}

#[test]
fn test_cli_workspaces_alias() {
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("wsalias.db").to_str().unwrap().to_string();
    let port = random_port();

    create_workspace(&db);
    let mut daemon = start_daemon(&db, port);

    // Test both "networks" and "workspaces" alias
    let out = Command::new(bin())
        .args(["--db", &db, "networks"])
        .output()
        .expect("networks command");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("WORKSPACES"), "networks should show WORKSPACES header");

    let out = Command::new(bin())
        .args(["--db", &db, "workspaces"])
        .output()
        .expect("workspaces command");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("WORKSPACES"), "workspaces alias should work");

    let _ = daemon.kill();
    let _ = daemon.wait();
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
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("msgnum.db").to_str().unwrap().to_string();
    let port = random_port();

    create_workspace(&db);
    let mut daemon = start_daemon(&db, port);

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
    assert!(stdout.contains("Reacted"), "expected Reacted output, got: {}", stdout);

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
    assert!(stdout.contains("Deleted"), "expected Deleted output, got: {}", stdout);

    // Invalid message number should error.
    let out = Command::new(bin())
        .args(["--db", &db, "react", "--target", "99", "sad"])
        .output()
        .expect("react invalid number");
    assert!(!out.status.success(), "should fail for invalid message number");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid message number"), "expected error message, got: {}", stderr);

    let _ = daemon.kill();
    let _ = daemon.wait();
}
