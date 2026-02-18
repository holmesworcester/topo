use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
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

fn start_daemon_with_options(db: &str, disable_placeholder_autodial: bool) -> Child {
    let socket = socket_path_for_db(db);
    let mut cmd = Command::new(bin());
    cmd.arg("--db")
        .arg(db)
        .arg("start")
        .arg("--bind")
        .arg("127.0.0.1:0")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if disable_placeholder_autodial {
        cmd.env("P7_DISABLE_PLACEHOLDER_AUTODIAL", "1");
    }

    let child = cmd.spawn().expect("failed to start daemon");

    // Wait for socket to appear.
    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        socket.exists(),
        "daemon socket did not appear at {}",
        socket.display()
    );
    wait_for_daemon_ready(db, Duration::from_secs(15));

    child
}

fn wait_for_daemon_ready(db: &str, timeout: Duration) {
    let socket = socket_path_for_db(db);
    let start = Instant::now();
    while start.elapsed() < timeout {
        if socket.exists() {
            if let Ok(resp) =
                topo::rpc::client::rpc_call(&socket, topo::rpc::protocol::RpcMethod::Status)
            {
                if resp.ok {
                    return;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("daemon did not become ready for RPC within {:?}", timeout);
}

fn daemon_listen_addr(db: &str) -> String {
    let socket = socket_path_for_db(db);
    let resp = topo::rpc::client::rpc_call(&socket, topo::rpc::protocol::RpcMethod::Status)
        .expect("status RPC for listen addr");
    assert!(resp.ok, "status RPC returned error");
    let data = resp.data.expect("status response missing data");
    data.get("runtime")
        .and_then(|r| r.get("listen_addr"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .expect("status response missing runtime.listen_addr")
}

fn cli_test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn start_daemon(db: &str) -> Child {
    start_daemon_with_options(db, false)
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
        .arg("--bootstrap")
        .arg(bootstrap_addr)
        .output()
        .expect("failed to run create-invite");
    assert!(
        output.status.success(),
        "create-invite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
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
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 15000;

    // Alice creates workspace (identity chain)
    create_workspace(&alice_db);

    // Alice starts daemon (auto-selects single peer)
    let mut alice = start_daemon(&alice_db);

    // Alice sends messages via daemon RPC
    send_message(&alice_db, "Hello from Alice");
    let alice_eid = send_message(&alice_db, "How are you?");

    // Alice creates invite (via daemon RPC)
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob accepts invite (bootstrap sync from Alice)
    accept_invite(&bob_db, &invite_link);

    // Bob starts daemon; invite-seeded autodial reaches Alice.
    let mut bob = start_daemon(&bob_db);
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
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 15000;

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let mut alice = start_daemon(&alice_db);

    // Alice sends bootstrap message
    send_message(&alice_db, "bootstrap");

    // Alice creates invite
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob accepts invite and starts daemon
    accept_invite(&bob_db, &invite_link);
    let mut bob = start_daemon(&bob_db);
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
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 20000;

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let mut alice = start_daemon_with_options(&alice_db, true);

    // Alice sends seed message and creates invite
    let alice_seed_eid = send_message(&alice_db, "alice-seed");
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob accepts invite and starts daemon with placeholder autodial disabled
    accept_invite(&bob_db, &invite_link);
    let mut bob = start_daemon_with_options(&bob_db, true);
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
    let _guard = cli_test_lock();
    // Basic test: create workspace, start daemon, send/messages work
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("test.db").to_str().unwrap().to_string();

    create_workspace(&db);
    let mut daemon = start_daemon(&db);

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
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let mut alice = start_daemon(&alice_db);

    // Alice sends a message
    send_message(&alice_db, "alice bootstrap");

    // Bob creates independent workspace (not in Alice's workspace)
    create_workspace(&bob_db);
    let mut bob = start_daemon(&bob_db);

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
    let _guard = cli_test_lock();
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
    let mut alice = start_daemon(&alice_db);

    // Alice sends bootstrap message
    send_message(&alice_db, "bootstrap");

    // Alice creates invite (via daemon RPC)
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

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
    let mut bob = start_daemon(&bob_db);
    std::thread::sleep(Duration::from_secs(1));

    let bob_eid = send_message(&bob_db, "bootstrap trust from invite data");
    assert_eventually(&alice_db, &format!("has_event:{} >= 1", bob_eid), timeout_ms);

    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
}
