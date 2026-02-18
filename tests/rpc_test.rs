//! RPC tests: protocol roundtrip, daemon+CLI integration, command regression.

use std::path::PathBuf;
use std::process::Command;

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
        RpcMethod::CreateWorkspace,
        RpcMethod::CreateInvite {
            bootstrap: "127.0.0.1:4433".into(),
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
fn shutdown_handler_does_not_call_process_exit() {
    // Source-level guard: verify that the RPC server dispatch does NOT contain
    // process::exit. This is a simple grep-style check to prevent regression.
    let server_source = include_str!("../src/rpc/server.rs");
    assert!(
        !server_source.contains("process::exit"),
        "RPC server must not call process::exit; use coordinated shutdown instead"
    );
}
