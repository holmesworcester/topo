use rusqlite::Connection;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

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
    // Wait until tenant discovery sees at least one peer before stopping it.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        let peers = Command::new(bin())
            .args(["--db", db, "peers"])
            .output()
            .expect("peers probe");
        if peers.status.success() {
            let stdout = String::from_utf8_lossy(&peers.stdout);
            if stdout
                .lines()
                .any(|line| line.trim_start().starts_with("1."))
            {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // create-workspace auto-starts the daemon; callers decide daemon lifecycle.
    let _ = Command::new(bin()).args(["--db", db, "stop"]).output();
    wait_for_daemon_stopped(db, Duration::from_secs(10));
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

    let mut child = cmd.spawn().expect("failed to start daemon");

    // Wait for socket to appear, checking that daemon hasn't exited early.
    let start = std::time::Instant::now();
    loop {
        // Check if process already exited (immediate crash / bind failure).
        if let Some(status) = child.try_wait().expect("failed to check daemon status") {
            panic!("daemon exited immediately with {} (db={})", status, db);
        }
        if socket.exists() {
            break;
        }
        if start.elapsed().as_secs() >= 5 {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        socket.exists(),
        "daemon socket did not appear at {} within 5s (db={})",
        socket.display(),
        db
    );
    wait_for_daemon_ready(db, Duration::from_secs(15));

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
                "daemon socket exists but RPC not responding after 5s (db={}): {}",
                db,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }

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

fn wait_for_daemon_stopped(db: &str, timeout: Duration) {
    let socket = socket_path_for_db(db);
    let start = Instant::now();
    while start.elapsed() < timeout {
        if !socket.exists() {
            return;
        }

        let rpc_alive =
            topo::rpc::client::rpc_call(&socket, topo::rpc::protocol::RpcMethod::Status)
                .map(|resp| resp.ok)
                .unwrap_or(false);
        if !rpc_alive {
            let _ = std::fs::remove_file(&socket);
            if !socket.exists() {
                return;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "daemon did not stop within {:?} (db={}, socket={})",
        timeout,
        db,
        socket.display()
    );
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

fn first_peer_index(peers_stdout: &str) -> Option<usize> {
    peers_stdout.lines().find_map(|line| {
        let trimmed = line.trim_start();
        let dot_pos = trimmed.find('.')?;
        let idx = &trimmed[..dot_pos];
        if idx.chars().all(|c| c.is_ascii_digit()) {
            idx.parse::<usize>().ok()
        } else {
            None
        }
    })
}

fn ensure_active_peer(db: &str, timeout: Duration) {
    let start = Instant::now();
    let mut last_active = String::new();
    let mut last_peers = String::new();
    let mut last_use_peer_err = String::new();

    while start.elapsed() < timeout {
        let active = Command::new(bin())
            .args(["--db", db, "active-peer"])
            .output()
            .expect("failed to run active-peer");
        if active.status.success() {
            let active_stdout = String::from_utf8_lossy(&active.stdout).trim().to_string();
            if !active_stdout.is_empty() && active_stdout != "(no active peer)" {
                return;
            }
            last_active = active_stdout;
        } else {
            last_active = format!("error: {}", String::from_utf8_lossy(&active.stderr).trim());
        }

        let peers = Command::new(bin())
            .args(["--db", db, "peers"])
            .output()
            .expect("failed to run peers");
        if peers.status.success() {
            let peers_stdout = String::from_utf8_lossy(&peers.stdout).to_string();
            if let Some(index) = first_peer_index(&peers_stdout) {
                let use_peer = Command::new(bin())
                    .arg("--db")
                    .arg(db)
                    .arg("use-peer")
                    .arg(index.to_string())
                    .output()
                    .expect("failed to run use-peer");
                if use_peer.status.success() {
                    return;
                }
                last_use_peer_err = String::from_utf8_lossy(&use_peer.stderr).trim().to_string();
            }
            last_peers = peers_stdout;
        } else {
            last_peers = format!("error: {}", String::from_utf8_lossy(&peers.stderr).trim());
        }

        std::thread::sleep(Duration::from_millis(100));
    }

    panic!(
        "failed to establish active peer within {:?} (db={}): active={}, peers={}, use-peer-error={}",
        timeout,
        db,
        last_active,
        last_peers.replace('\n', " | "),
        last_use_peer_err
    );
}

fn send_message(db: &str, content: &str) -> String {
    ensure_active_peer(db, Duration::from_secs(10));
    let start = Instant::now();
    loop {
        let output = Command::new(bin())
            .arg("--db")
            .arg(db)
            .arg("send")
            .arg(content)
            .output()
            .expect("failed to run send");
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout
                .lines()
                .find_map(|line| line.strip_prefix("event_id:"))
                .expect("send output missing event_id: line")
                .to_string();
        }

        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let retryable = stderr.contains("no identity") || stderr.contains("no active peer");
        if retryable && start.elapsed() < Duration::from_secs(20) {
            if stderr.contains("no active peer") {
                ensure_active_peer(db, Duration::from_secs(5));
            }
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        panic!("send failed: {}", stderr);
    }
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

/// Helper: run accept-invite CLI command through daemon RPC.
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
    // Ensure tenant discovery is persisted before stopping the auto-started daemon.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        let peers = Command::new(bin())
            .args(["--db", db, "peers"])
            .output()
            .expect("peers probe");
        if peers.status.success() {
            let stdout = String::from_utf8_lossy(&peers.stdout);
            if stdout
                .lines()
                .any(|line| line.trim_start().starts_with("1."))
            {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    // accept-invite auto-starts daemon; callers decide daemon lifecycle.
    let _ = Command::new(bin()).args(["--db", db, "stop"]).output();
    wait_for_daemon_stopped(db, Duration::from_secs(10));
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
    let timeout_ms = 30000;

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
    let timeout_ms = 30000;

    // Alice creates workspace and starts daemon
    create_workspace(&alice_db);
    let mut alice = start_daemon(&alice_db);

    // Alice sends bootstrap message
    let _bootstrap_eid = send_message(&alice_db, "bootstrap");
    assert_now(&alice_db, "message_count >= 1");

    // Alice creates invite
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob accepts invite and starts daemon
    accept_invite(&bob_db, &invite_link);
    let mut bob = start_daemon(&bob_db);
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

    let _ = alice.kill();
    let _ = bob.kill();
    let _ = alice.wait();
    let _ = bob.wait();
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
    let mut alice = start_daemon_with_options(&alice_db, true);

    // Alice creates invite while daemon is running.
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Bob accepts invite and starts daemon with placeholder autodial disabled.
    // With placeholder autodial disabled, Bob discovers Alice via mDNS only.
    accept_invite(&bob_db, &invite_link);
    let mut bob = start_daemon_with_options(&bob_db, true);

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

    let mut daemon = Command::new(bin())
        .arg("start")
        .arg("--bind")
        .arg(format!("127.0.0.1:{}", random_port()))
        .arg("--db")
        .arg(&db)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to run start");

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

    let _ = daemon.wait();
}

/// Bootstrap trust test using production create-invite / accept-invite CLI flow.
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
    let mut alice = start_daemon(&alice_db);

    // Alice sends bootstrap message
    send_message(&alice_db, "bootstrap");

    // Alice creates invite (via daemon RPC)
    let invite_link = create_invite(&alice_db, &daemon_listen_addr(&alice_db));

    // Alice should have emitted content key wrapping during invite creation
    assert!(
        count_rows(&alice_db, "secret_shared") >= 1,
        "inviter should emit at least one secret_shared key-wrap during invite creation"
    );

    // Bob accepts invite: installs deterministic cert, creates identity chain
    // (events may block pending sync of prerequisite events from Alice).
    accept_invite(&bob_db, &invite_link);

    // Bob starts daemon; invite bootstrap trust seeds daemon autodial.
    // Autodial connects to Alice, syncs prerequisite events, identity chain
    // cascades to completion, and messages project.
    let mut bob = start_daemon(&bob_db);

    // Wait for Bob's identity chain to complete (message_count >= 1 means
    // Alice's "bootstrap" message has been fully projected on Bob's side,
    // which requires the full identity chain cascade).
    assert_eventually(&bob_db, "message_count >= 1", timeout_ms);

    // After sync, Bob should have Alice's secret_shared event (content key ciphertext).
    // Note: deferred content key unwrapping (secret_shared → secret_keys) is a
    // follow-up feature for the projection-first flow. The old inline bootstrap
    // sync performed this unwrap immediately, but the daemon-driven cascade
    // doesn't yet trigger it automatically.
    assert!(
        count_rows(&bob_db, "secret_shared") >= 1,
        "invitee should have inviter's secret_shared event after sync"
    );

    let bob_eid = send_message(&bob_db, "bootstrap trust from invite data");
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_eid),
        timeout_ms,
    );

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
    let tmpdir = tempfile::tempdir().unwrap();
    let db = tmpdir.path().join("ban.db").to_str().unwrap().to_string();

    create_workspace(&db);
    let mut daemon = start_daemon(&db);

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
    let db = tmpdir
        .path()
        .join("wsalias.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let mut daemon = start_daemon(&db);

    // Test both "networks" and "workspaces" alias
    let out = Command::new(bin())
        .args(["--db", &db, "networks"])
        .output()
        .expect("networks command");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("WORKSPACES"),
        "networks should show WORKSPACES header"
    );

    let out = Command::new(bin())
        .args(["--db", &db, "workspaces"])
        .output()
        .expect("workspaces command");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("WORKSPACES"),
        "workspaces alias should work"
    );

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
    let db = tmpdir
        .path()
        .join("msgnum.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&db);
    let mut daemon = start_daemon(&db);

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

    let _ = daemon.kill();
    let _ = daemon.wait();
}
