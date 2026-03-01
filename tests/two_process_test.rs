//! Two-process integration test: real QUIC sync between separate daemon invocations.
//!
//! This test validates the full invite + bootstrap sync + ongoing sync flow
//! using real separate processes, just like a user would run from the command line.

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn bin() -> String {
    env!("CARGO_BIN_EXE_topo").to_string()
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
    // create-workspace auto-starts daemon; this suite controls daemon start explicitly.
    let _ = Command::new(bin()).args(["--db", db, "stop"]).output();
    wait_for_daemon_stopped(db, Duration::from_secs(10));
}

fn wait_for_daemon_ready(db: &str, timeout: Duration) {
    let socket = socket_path_for_db(db);
    let start = std::time::Instant::now();
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
    let start = std::time::Instant::now();
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

fn daemon_transport_fingerprint(db: &str) -> String {
    let socket = socket_path_for_db(db);
    let resp =
        topo::rpc::client::rpc_call(&socket, topo::rpc::protocol::RpcMethod::TransportIdentity)
            .expect("transport-identity RPC");
    assert!(resp.ok, "transport-identity RPC returned error");
    let data = resp.data.expect("transport-identity response missing data");
    data.get("fingerprint")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .expect("transport-identity response missing fingerprint")
}

fn start_daemon(db: &str) -> Child {
    let socket = socket_path_for_db(db);
    let mut cmd = Command::new(bin());
    cmd.arg("--db")
        .arg(db)
        .arg("start")
        .arg("--bind")
        .arg("127.0.0.1:0")
        .env("RUST_LOG", "topo::event_pipeline=debug,topo::peering::runtime::autodial=debug,topo::projection=debug,topo::sync::session=info,topo=warn")
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = cmd.spawn().expect("failed to start daemon");

    let start = std::time::Instant::now();
    loop {
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
        "daemon socket did not appear at {}",
        socket.display()
    );
    wait_for_daemon_ready(db, Duration::from_secs(15));

    child
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
    let start = std::time::Instant::now();
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
            }
        }

        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "failed to establish active peer within {:?} (db={})",
        timeout, db
    );
}

fn send_message(db: &str, content: &str) -> String {
    ensure_active_peer(db, Duration::from_secs(10));
    let start = std::time::Instant::now();
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
        panic!("send failed for db={}: {}", db, stderr);
    }
}

fn create_invite(db: &str, bootstrap_addr: &str, public_spki: Option<&str>) -> String {
    let mut cmd = Command::new(bin());
    cmd.arg("--db")
        .arg(db)
        .arg("create-invite")
        .arg("--public-addr")
        .arg(bootstrap_addr);
    if let Some(spki) = public_spki {
        cmd.arg("--public-spki").arg(spki);
    }
    let output = cmd.output().expect("failed to run create-invite");
    assert!(
        output.status.success(),
        "create-invite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|line| line.starts_with("quiet://"))
        .expect("create-invite output missing quiet:// link")
        .to_string()
}

fn accept_invite(db: &str, invite_link: &str, username: &str, devicename: &str) {
    let output = Command::new(bin())
        .arg("accept-invite")
        .arg("--db")
        .arg(db)
        .arg("--invite")
        .arg(invite_link)
        .arg("--username")
        .arg(username)
        .arg("--devicename")
        .arg(devicename)
        .output()
        .expect("failed to run accept-invite");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "accept-invite failed:\n  stdout: {}\n  stderr: {}",
        stdout.trim(),
        stderr.trim()
    );
    // accept-invite auto-starts daemon; this suite controls daemon start explicitly.
    let _ = Command::new(bin()).args(["--db", db, "stop"]).output();
    wait_for_daemon_stopped(db, Duration::from_secs(10));
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
    text.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
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

/// Full two-process invite + bootstrap sync + ongoing sync test.
///
/// 1. Alice creates workspace and starts daemon
/// 2. Alice creates an invite
/// 3. Bob accepts the invite (real QUIC bootstrap sync from Alice)
/// 4. Both run daemons, exchange messages, verify convergence
#[test]
fn test_two_process_invite_and_sync() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let timeout_ms = 30000;

    // Step 1: Alice creates workspace and starts daemon.
    create_workspace(&alice_db);
    let mut alice_daemon = start_daemon(&alice_db);

    // Step 2: Alice creates an invite pointing to her sync address (via daemon RPC).
    let invite_link = create_invite(
        &alice_db,
        &daemon_listen_addr(&alice_db),
        Some(&daemon_transport_fingerprint(&alice_db)),
    );
    assert!(
        invite_link.starts_with("quiet://invite/"),
        "Expected quiet://invite/ link, got: {}",
        invite_link
    );

    // Step 3: Bob accepts the invite. This connects to Alice's sync endpoint
    // via real QUIC, fetches prerequisite events, then creates Bob's identity chain.
    accept_invite(&bob_db, &invite_link, "bob", "laptop");

    // Bob's daemon handles bootstrap sync via autodial: the runtime discovers
    // bootstrap trust from projected SQL state and dials Alice's sync address.
    let mut bob_daemon = start_daemon(&bob_db);

    // Step 4: Exchange messages and verify convergence.
    let alice_eid = send_message(&alice_db, "Hello from alice");
    let bob_eid = send_message(&bob_db, "Hello from bob");

    // Wait for sync convergence: each peer should have the other's last message event
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

    // Wait for cross-peer message projection.
    assert_eventually(&alice_db, "message_count >= 2", timeout_ms);
    assert_eventually(&bob_db, "message_count >= 2", timeout_ms);

    // Verify Alice's messages.
    let alice_msgs = get_messages(&alice_db);
    assert!(
        alice_msgs.contains(&"Hello from alice".to_string()),
        "Alice should have her message, got: {:?}",
        alice_msgs
    );
    assert!(
        alice_msgs.contains(&"Hello from bob".to_string()),
        "Alice should see Bob's message (shared workspace), got: {:?}",
        alice_msgs
    );

    // Verify Bob's messages.
    let bob_msgs = get_messages(&bob_db);
    assert!(
        bob_msgs.contains(&"Hello from bob".to_string()),
        "Bob should have his message, got: {:?}",
        bob_msgs
    );
    assert!(
        bob_msgs.contains(&"Hello from alice".to_string()),
        "Bob should see Alice's message (shared workspace), got: {:?}",
        bob_msgs
    );

    // Cleanup
    let _ = alice_daemon.kill();
    let _ = bob_daemon.kill();
    let _ = alice_daemon.wait();
    let _ = bob_daemon.wait();
}
