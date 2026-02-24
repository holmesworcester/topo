//! RPC tests: protocol roundtrip, daemon+CLI integration, command regression.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

fn bin() -> String {
    env!("CARGO_BIN_EXE_topo").to_string()
}

fn temp_db() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db").to_str().unwrap().to_string();
    (dir, db)
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
    // create-workspace auto-starts the daemon; most tests start it explicitly.
    let _ = Command::new(bin()).args(["--db", db, "stop"]).output();
}

fn wait_for_socket(socket: &PathBuf) {
    let start = Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        socket.exists(),
        "daemon socket did not appear at {}",
        socket.display()
    );
}

fn status_via_rpc(socket: &PathBuf) -> serde_json::Value {
    let resp = topo::rpc::client::rpc_call(socket, topo::rpc::protocol::RpcMethod::Status)
        .expect("status RPC");
    assert!(resp.ok, "status RPC should succeed: {:?}", resp.error);
    resp.data.expect("status response missing data")
}

fn wait_for_runtime_state(socket: &PathBuf, expected: &str, timeout: Duration) -> serde_json::Value {
    let start = Instant::now();
    let mut last = serde_json::Value::Null;
    while start.elapsed() < timeout {
        let data = status_via_rpc(socket);
        if data["runtime_state"].as_str() == Some(expected) {
            return data;
        }
        last = data;
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!(
        "runtime state did not reach {} within {:?}, last status={}",
        expected, timeout, last
    );
}

fn stop_daemon(db: &str, daemon: &mut Child) {
    let _ = Command::new(bin()).args(["--db", db, "stop"]).output();
    let start = Instant::now();
    loop {
        match daemon.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if start.elapsed().as_secs() >= 5 {
                    let _ = daemon.kill();
                    let _ = daemon.wait();
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                let _ = daemon.kill();
                let _ = daemon.wait();
                return;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 1. RPC protocol unit tests
// ---------------------------------------------------------------------------

#[test]
fn rpc_request_encode_decode_roundtrip() {
    use topo::rpc::protocol::*;

    let req = RpcRequest {
        version: PROTOCOL_VERSION,
        method: RpcMethod::Status,
    };
    let frame = encode_frame(&req).unwrap();
    let decoded: RpcRequest = decode_frame(&mut &frame[..]).unwrap();
    assert_eq!(decoded.version, PROTOCOL_VERSION);
    match decoded.method {
        RpcMethod::Status => {}
        other => panic!("expected Status, got {:?}", other),
    }
}

#[test]
fn rpc_request_send_roundtrip() {
    use topo::rpc::protocol::*;

    let req = RpcRequest {
        version: PROTOCOL_VERSION,
        method: RpcMethod::Send {
            content: "hello world".into(),
        },
    };
    let frame = encode_frame(&req).unwrap();
    let decoded: RpcRequest = decode_frame(&mut &frame[..]).unwrap();
    match decoded.method {
        RpcMethod::Send { content } => {
            assert_eq!(content, "hello world");
        }
        other => panic!("expected Send, got {:?}", other),
    }
}

#[test]
fn rpc_response_success_roundtrip() {
    use topo::rpc::protocol::*;
    use topo::service::StatusResponse;

    let data = StatusResponse {
        events_count: 42,
        messages_count: 10,
        reactions_count: 3,
        recorded_events_count: 42,
        neg_items_count: 42,
    };
    let resp = RpcResponse::success(data);
    let frame = encode_frame(&resp).unwrap();
    let decoded: RpcResponse = decode_frame(&mut &frame[..]).unwrap();
    assert!(decoded.ok);
    assert!(decoded.error.is_none());
    let d = decoded.data.unwrap();
    assert_eq!(d["events_count"], 42);
    assert_eq!(d["messages_count"], 10);
}

#[test]
fn rpc_response_error_roundtrip() {
    use topo::rpc::protocol::*;

    let resp = RpcResponse::error("something went wrong");
    let frame = encode_frame(&resp).unwrap();
    let decoded: RpcResponse = decode_frame(&mut &frame[..]).unwrap();
    assert!(!decoded.ok);
    assert_eq!(decoded.error.as_deref(), Some("something went wrong"));
    assert!(decoded.data.is_none());
}

#[test]
fn rpc_all_methods_serialize() {
    use topo::rpc::protocol::*;

    let methods = vec![
        RpcMethod::Status,
        RpcMethod::Messages { limit: 50 },
        RpcMethod::Send {
            content: "msg".into(),
        },
        RpcMethod::Generate { count: 10 },
        RpcMethod::AssertNow {
            predicate: "message_count == 0".into(),
        },
        RpcMethod::AssertEventually {
            predicate: "message_count == 5".into(),
            timeout_ms: 10000,
            interval_ms: 200,
        },
        RpcMethod::TransportIdentity,
        RpcMethod::React {
            target: "abc".into(),
            emoji: "thumbs_up".into(),
        },
        RpcMethod::DeleteMessage {
            target: "def".into(),
        },
        RpcMethod::Reactions,
        RpcMethod::Users,
        RpcMethod::Keys { summary: true },
        RpcMethod::Workspaces,
        RpcMethod::IntroAttempts {
            peer: Some("peer1".into()),
        },
        RpcMethod::Shutdown,
        RpcMethod::Peers,
        RpcMethod::UsePeer { index: 1 },
        RpcMethod::ActivePeer,
        RpcMethod::CreateWorkspace {
            workspace_name: "test".into(),
            username: "user".into(),
            device_name: "device".into(),
        },
        RpcMethod::CreateInvite {
            public_addr: "127.0.0.1:4433".into(),
            public_spki: None,
        },
        RpcMethod::CreateDeviceLink {
            public_addr: "127.0.0.1:4433".into(),
            public_spki: None,
        },
        RpcMethod::AcceptLink {
            invite: "quiet://link/test".into(),
            devicename: "device".into(),
        },
        RpcMethod::Ban {
            target: "1".into(),
        },
        RpcMethod::Identity,
        RpcMethod::Channels,
        RpcMethod::NewChannel {
            name: "general".into(),
        },
        RpcMethod::UseChannel {
            selector: "1".into(),
        },
        RpcMethod::AcceptInvite {
            invite: "quiet://invite/test".into(),
            username: "user".into(),
            devicename: "device".into(),
        },
        RpcMethod::Upnp,
    ];

    for method in methods {
        let req = RpcRequest {
            version: PROTOCOL_VERSION,
            method,
        };
        let frame = encode_frame(&req).unwrap();
        let decoded: RpcRequest = decode_frame(&mut &frame[..]).unwrap();
        assert_eq!(decoded.version, PROTOCOL_VERSION);
    }
}

// ---------------------------------------------------------------------------
// 2. Integration: daemon via `topo start` + CLI commands
// ---------------------------------------------------------------------------

#[test]
fn daemon_and_cli_status() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    // Create workspace (identity chain) so daemon can start.
    create_workspace(&db);

    // Start daemon in background.
    let mut daemon = Command::new(bin())
        .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();

    // Wait for socket to appear.
    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(socket.exists(), "daemon socket did not appear");

    // Query status via unified CLI (routes through daemon via RPC).
    let out = Command::new(bin())
        .args(["--db", &db, "status"])
        .output()
        .unwrap();

    // Kill daemon.
    let _ = daemon.kill();
    let _ = daemon.wait();

    assert!(out.status.success(), "status failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("STATUS"),
        "status output should contain STATUS header"
    );
    assert!(
        stdout.contains("Events:"),
        "status output should contain Events count"
    );
}

#[test]
fn daemon_and_cli_send_and_messages() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    // Create workspace so daemon can start.
    create_workspace(&db);

    // Start daemon.
    let mut daemon = Command::new(bin())
        .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();

    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Send a message via unified CLI (routes through daemon via RPC).
    let out = Command::new(bin())
        .args(["--db", &db, "send", "hello from topo"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "send failed: stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Sent: hello from topo"));

    // Query messages.
    let out = Command::new(bin())
        .args(["--db", &db, "messages"])
        .output()
        .unwrap();

    // Kill daemon.
    let _ = daemon.kill();
    let _ = daemon.wait();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hello from topo"),
        "should find message in list, got: {}",
        stdout
    );
}

#[test]
fn daemon_and_cli_assert_now() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    // Create workspace so daemon can start.
    create_workspace(&db);

    // Start daemon.
    let mut daemon = Command::new(bin())
        .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();

    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Assert message_count == 0 (no messages sent yet; should pass).
    let out = Command::new(bin())
        .args(["--db", &db, "assert-now", "message_count == 0"])
        .output()
        .unwrap();

    assert!(out.status.success(), "assert-now should pass");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PASS"));

    // Assert message_count == 99 (should fail with exit 1).
    let out = Command::new(bin())
        .args(["--db", &db, "assert-now", "message_count == 99"])
        .output()
        .unwrap();

    // Kill daemon.
    let _ = daemon.kill();
    let _ = daemon.wait();

    assert_eq!(
        out.status.code(),
        Some(1),
        "assert-now should fail with exit 1"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("FAIL"));
}

// ---------------------------------------------------------------------------
// 3. Service function unit tests
// ---------------------------------------------------------------------------

#[test]
fn service_socket_path_derivation() {
    let path = topo::service::socket_path_for_db("server.db");
    assert!(path.to_str().unwrap().ends_with("server.topo.sock"));

    let path = topo::service::socket_path_for_db("/tmp/mydb.db");
    assert_eq!(path.to_str().unwrap(), "/tmp/mydb.topo.sock");
}

#[test]
fn service_predicate_parsing() {
    use topo::service::parse_predicate;

    let (field, op, val) = parse_predicate("message_count == 10").unwrap();
    assert_eq!(field, "message_count");
    assert_eq!(op.symbol(), "==");
    assert_eq!(val, 10);

    let (field, op, val) = parse_predicate("store_count >= 0").unwrap();
    assert_eq!(field, "store_count");
    assert_eq!(op.symbol(), ">=");
    assert_eq!(val, 0);

    assert!(parse_predicate("bad").is_err());
    assert!(parse_predicate("x ?? 1").is_err());
}

// ---------------------------------------------------------------------------
// 5. Regression tests for topo consolidation
// ---------------------------------------------------------------------------

#[test]
fn daemon_stop_flow_clean_exit_and_socket_removal() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    // Create workspace so daemon can start sync.
    create_workspace(&db);

    // Start daemon in background.
    let mut daemon = Command::new(bin())
        .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();

    // Wait for socket to appear.
    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(socket.exists(), "daemon socket did not appear");

    // Stop daemon via `topo stop`.
    let out = Command::new(bin())
        .args(["--db", &db, "stop"])
        .output()
        .unwrap();
    assert!(out.status.success(), "stop failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("daemon stopped"),
        "expected 'daemon stopped', got: {}",
        stdout
    );

    // Wait for daemon process to exit.
    let exit_start = std::time::Instant::now();
    loop {
        match daemon.try_wait() {
            Ok(Some(status)) => {
                // Daemon exited — success regardless of exit code (may be non-zero
                // because tokio tasks get cancelled on shutdown).
                let _ = status;
                break;
            }
            Ok(None) => {
                if exit_start.elapsed().as_secs() >= 5 {
                    let _ = daemon.kill();
                    let _ = daemon.wait();
                    panic!("daemon did not exit within 5s after stop");
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("error waiting for daemon: {}", e),
        }
    }

    // Socket should be cleaned up.
    assert!(!socket.exists(), "socket file should be removed after stop");
}

#[test]
fn custom_socket_routing() {
    let (dir, db) = temp_db();
    let custom_socket = dir.path().join("custom.sock");

    // Create workspace so daemon can start sync.
    create_workspace(&db);

    // Start daemon on custom socket.
    let mut daemon = Command::new(bin())
        .args([
            "--db",
            &db,
            "--socket",
            custom_socket.to_str().unwrap(),
            "start",
            "--bind",
            "127.0.0.1:0",
        ])
        .spawn()
        .unwrap();

    // Wait for custom socket to appear.
    let start = std::time::Instant::now();
    while !custom_socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(custom_socket.exists(), "custom socket did not appear");

    // Query status via custom socket.
    let out = Command::new(bin())
        .args([
            "--db",
            &db,
            "--socket",
            custom_socket.to_str().unwrap(),
            "status",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "status via custom socket failed: {:?}",
        out
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("STATUS"),
        "status output should contain STATUS header"
    );

    // Default socket should NOT exist (daemon is on custom socket).
    let default_socket = socket_path_for_db(&db);
    assert!(
        !default_socket.exists(),
        "default socket should not exist when custom socket is used"
    );

    // Stop daemon via custom socket.
    let out = Command::new(bin())
        .args([
            "--db",
            &db,
            "--socket",
            custom_socket.to_str().unwrap(),
            "stop",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "stop via custom socket failed: {:?}",
        out
    );

    let _ = daemon.wait();
}

#[test]
fn daemon_status_includes_runtime_net_info() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let mut daemon = Command::new(bin())
        .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();

    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(socket.exists(), "daemon socket did not appear");

    // Give daemon a moment to populate runtime net info.
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Query status via RPC.
    let resp =
        topo::rpc::client::rpc_call(&socket, topo::rpc::protocol::RpcMethod::Status).unwrap();
    assert!(resp.ok, "status RPC should succeed");
    let data = resp.data.unwrap();

    // runtime.listen_addr should be present and contain a port.
    let runtime = &data["runtime"];
    assert!(
        runtime["listen_addr"].is_string(),
        "runtime.listen_addr should be a string, got: {:?}",
        runtime
    );
    let listen_addr = runtime["listen_addr"].as_str().unwrap();
    assert!(
        listen_addr.contains(':'),
        "listen_addr should be host:port, got: {}",
        listen_addr
    );

    // upnp should be absent (not attempted yet — requires explicit `topo upnp`).
    assert!(
        runtime.get("upnp").is_none() || runtime["upnp"].is_null(),
        "upnp should not be present before running topo upnp"
    );

    let _ = daemon.kill();
    let _ = daemon.wait();
}

#[test]
fn daemon_cli_status_shows_listen_line() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let mut daemon = Command::new(bin())
        .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();

    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    std::thread::sleep(std::time::Duration::from_millis(500));

    let out = Command::new(bin())
        .args(["--db", &db, "status"])
        .output()
        .unwrap();

    let _ = daemon.kill();
    let _ = daemon.wait();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Listen:"),
        "status output should contain Listen line, got: {}",
        stdout
    );
}

#[test]
fn daemon_start_on_empty_db_reports_idle_runtime_state() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    let mut daemon = Command::new(bin())
        .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();
    wait_for_socket(&socket);

    let out = Command::new(bin())
        .args(["--db", &db, "status"])
        .output()
        .unwrap();
    assert!(out.status.success(), "status failed on empty DB daemon");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Runtime:   IdleNoTenants"),
        "expected idle runtime state, got: {}",
        stdout
    );

    stop_daemon(&db, &mut daemon);
}

#[test]
fn create_workspace_autostarts_daemon_and_activates_runtime() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);
    assert!(!socket.exists(), "socket should not exist before command");

    let out = Command::new(bin())
        .args(["create-workspace", "--db", &db])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "create-workspace failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("peer_id:"), "missing peer_id output: {}", stdout);
    assert!(
        stdout.contains("workspace_id:"),
        "missing workspace_id output: {}",
        stdout
    );
    wait_for_socket(&socket);

    let data = wait_for_runtime_state(&socket, "Active", Duration::from_secs(10));
    assert!(
        data.get("runtime")
            .and_then(|rt| rt.get("listen_addr"))
            .and_then(|v| v.as_str())
            .is_some(),
        "expected runtime.listen_addr in active state: {}",
        data
    );

    let _ = Command::new(bin()).args(["--db", &db, "stop"]).output();
}

#[test]
fn accept_invite_on_running_idle_daemon_activates_runtime_without_restart() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    let alice_socket = socket_path_for_db(&alice_db);
    let bob_socket = socket_path_for_db(&bob_db);

    // Alice: bootstrap via RPC-only create-workspace (auto-starts daemon).
    let create = Command::new(bin())
        .args(["create-workspace", "--db", &alice_db])
        .output()
        .unwrap();
    assert!(create.status.success(), "alice create-workspace failed");
    wait_for_socket(&alice_socket);
    let alice_status = wait_for_runtime_state(&alice_socket, "Active", Duration::from_secs(10));
    let alice_listen = alice_status["runtime"]["listen_addr"]
        .as_str()
        .expect("alice runtime.listen_addr")
        .to_string();

    let invite_out = Command::new(bin())
        .args(["--db", &alice_db, "create-invite", "--public-addr", &alice_listen])
        .output()
        .unwrap();
    assert!(
        invite_out.status.success(),
        "create-invite failed: stdout={} stderr={}",
        String::from_utf8_lossy(&invite_out.stdout),
        String::from_utf8_lossy(&invite_out.stderr)
    );
    let invite_link = String::from_utf8_lossy(&invite_out.stdout)
        .lines()
        .find(|line| line.starts_with("quiet://"))
        .expect("create-invite output missing invite link")
        .to_string();

    // Bob: explicit daemon start on empty DB should stay idle first.
    let mut bob_daemon = Command::new(bin())
        .args(["--db", &bob_db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();
    let bob_pid_before = bob_daemon.id();
    wait_for_socket(&bob_socket);
    let _ = wait_for_runtime_state(&bob_socket, "IdleNoTenants", Duration::from_secs(10));

    // accept-invite must route through RPC and trigger runtime activation.
    let accept = Command::new(bin())
        .args([
            "accept-invite",
            "--db",
            &bob_db,
            "--invite",
            &invite_link,
            "--username",
            "bob",
            "--devicename",
            "laptop",
        ])
        .output()
        .unwrap();
    assert!(
        accept.status.success(),
        "accept-invite failed: stdout={} stderr={}",
        String::from_utf8_lossy(&accept.stdout),
        String::from_utf8_lossy(&accept.stderr)
    );
    assert!(
        bob_daemon.try_wait().unwrap().is_none(),
        "bob daemon should keep running (no restart required)"
    );
    assert_eq!(bob_daemon.id(), bob_pid_before, "daemon process should be unchanged");
    let _ = wait_for_runtime_state(&bob_socket, "Active", Duration::from_secs(10));

    let _ = Command::new(bin()).args(["--db", &alice_db, "stop"]).output();
    stop_daemon(&bob_db, &mut bob_daemon);
}

#[test]
fn db_scoped_commands_remain_isolated_between_daemons() {
    let tmpdir = tempfile::tempdir().unwrap();
    let db_a = tmpdir.path().join("a.db").to_str().unwrap().to_string();
    let db_b = tmpdir.path().join("b.db").to_str().unwrap().to_string();

    let create_a = Command::new(bin())
        .args(["create-workspace", "--db", &db_a])
        .output()
        .unwrap();
    assert!(create_a.status.success());
    let create_b = Command::new(bin())
        .args(["create-workspace", "--db", &db_b])
        .output()
        .unwrap();
    assert!(create_b.status.success());

    let send_a = Command::new(bin())
        .args(["--db", &db_a, "send", "db-a-message"])
        .output()
        .unwrap();
    assert!(
        send_a.status.success(),
        "send on db A failed: {}",
        String::from_utf8_lossy(&send_a.stderr)
    );

    let status_a = status_via_rpc(&socket_path_for_db(&db_a));
    let status_b = status_via_rpc(&socket_path_for_db(&db_b));
    assert!(
        status_a["messages_count"].as_i64().unwrap_or(0) >= 1,
        "db A should show at least one message: {}",
        status_a
    );
    assert_eq!(
        status_b["messages_count"].as_i64().unwrap_or(-1),
        0,
        "db B should remain unchanged: {}",
        status_b
    );

    let _ = Command::new(bin()).args(["--db", &db_a, "stop"]).output();
    let _ = Command::new(bin()).args(["--db", &db_b, "stop"]).output();
}

#[test]
fn local_signer_secret_events_do_not_pass_shared_egress_gate() {
    let (_dir, db) = temp_db();
    create_workspace(&db);

    let conn = rusqlite::Connection::open(&db).unwrap();
    let local_event_b64: String = conn
        .query_row(
            "SELECT event_id FROM events WHERE event_type = 'local_signer_secret' LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let local_event_id =
        topo::crypto::event_id_from_base64(&local_event_b64).expect("valid local event id");
    let store = topo::db::store::Store::new(&conn);
    assert!(
        store.get_shared(&local_event_id).unwrap().is_none(),
        "local_signer_secret must never be returned by shared egress gate"
    );
}

#[test]
fn shutdown_handler_does_not_call_process_exit() {
    // Source-level guard: verify that the RPC server dispatch does NOT contain
    // process::exit. This is a simple grep-style check to prevent regression.
    let server_source = include_str!("../src/rpc/server.rs");
    assert!(
        !server_source.contains("process::exit"),
        "RPC server must not call process::exit; use coordinated shutdown instead"
    );
}

// ---------------------------------------------------------------------------
// 6. New RPC method tests
// ---------------------------------------------------------------------------

#[test]
fn rpc_identity_command() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    // Create workspace (identity chain) so daemon can start.
    create_workspace(&db);

    // Start daemon in background.
    let mut daemon = Command::new(bin())
        .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();

    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Query identity via CLI
    let out = Command::new(bin())
        .args(["--db", &db, "identity"])
        .output()
        .unwrap();

    let _ = daemon.kill();
    let _ = daemon.wait();

    assert!(out.status.success(), "identity failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("IDENTITY:"), "should contain IDENTITY header");
    assert!(stdout.contains("Transport:"), "should contain Transport line");
    assert!(stdout.contains("User:"), "should contain User line");
    assert!(stdout.contains("Peer:"), "should contain Peer line");
}

#[test]
fn rpc_channel_lifecycle() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let mut daemon = Command::new(bin())
        .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();

    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // List channels — should have "general" by default
    let out = Command::new(bin())
        .args(["--db", &db, "channels"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("general"), "should have default 'general' channel, got: {}", stdout);

    // Create a new channel
    let out = Command::new(bin())
        .args(["--db", &db, "new-channel", "random"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("random"), "should show new channel name");

    // Switch to the new channel
    let out = Command::new(bin())
        .args(["--db", &db, "channel", "2"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("random"), "should show switched channel name");

    // Verify channels list now shows 2
    let out = Command::new(bin())
        .args(["--db", &db, "channels"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("general"), "should still have general");
    assert!(stdout.contains("random"), "should also have random");

    let _ = daemon.kill();
    let _ = daemon.wait();
}

#[test]
fn rpc_invite_ref_resolution() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let mut daemon = Command::new(bin())
        .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
        .spawn()
        .unwrap();

    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    // Create invite — should get ref #1
    let out = Command::new(bin())
        .args(["--db", &db, "create-invite", "--public-addr", "127.0.0.1:4433"])
        .output()
        .unwrap();
    assert!(out.status.success(), "create-invite failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("#1") || stdout.contains("quiet://"),
        "should show invite ref or link, got: {}",
        stdout
    );

    let _ = daemon.kill();
    let _ = daemon.wait();
}
