//! RPC protocol and daemon lifecycle tests.
//!
//! Tests RPC encode/decode roundtrips, daemon start/stop lifecycle, runtime
//! state transitions (idle → active), socket routing, service function
//! correctness, and per-command RPC integration (identity, invite, peers).
//!
//! **Boundary**: tests that exercise RPC protocol mechanics, daemon process
//! lifecycle, and individual RPC method correctness. For multi-peer sync
//! scenarios and CLI output formatting, see `cli_test.rs`.

mod cli_harness;

use cli_harness::*;
use std::process::Command;
use std::time::Duration;
use topo::testutil::DaemonGuard;

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
            client_op_id: None,
        },
    };
    let frame = encode_frame(&req).unwrap();
    let decoded: RpcRequest = decode_frame(&mut &frame[..]).unwrap();
    match decoded.method {
        RpcMethod::Send {
            content,
            client_op_id,
        } => {
            assert_eq!(content, "hello world");
            assert!(client_op_id.is_none());
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
            client_op_id: None,
        },
        RpcMethod::Files { limit: 50 },
        RpcMethod::SaveFile {
            target: "1".into(),
            output_path: "/tmp/out.bin".into(),
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
            client_op_id: None,
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
        RpcMethod::Tenants,
        RpcMethod::UseTenant { index: 1 },
        RpcMethod::ActiveTenant,
        RpcMethod::CreateWorkspace {
            workspace_name: "test".into(),
            username: "user".into(),
            device_name: "device".into(),
        },
        RpcMethod::CreateInvite {
            public_addr: Some("127.0.0.1:4433".to_string()),
            public_spki: None,
        },
        RpcMethod::CreateDeviceLink {
            public_addr: Some("127.0.0.1:4433".to_string()),
            public_spki: None,
        },
        RpcMethod::AcceptLink {
            invite: "topo://link/test".into(),
            devicename: "device".into(),
        },
        RpcMethod::Ban { target: "1".into() },
        RpcMethod::Identity,
        RpcMethod::AcceptInvite {
            invite: "topo://invite/test".into(),
            username: "user".into(),
            devicename: "device".into(),
        },
        RpcMethod::Peers,
        RpcMethod::Upnp,
        RpcMethod::SubCreate {
            name: "inbox".into(),
            event_type: "message".into(),
            delivery_mode: "full".into(),
            spec_json: String::new(),
        },
        RpcMethod::SubList,
        RpcMethod::SubDisable {
            subscription_id: "sub_1".into(),
        },
        RpcMethod::SubEnable {
            subscription_id: "sub_1".into(),
        },
        RpcMethod::SubPoll {
            subscription_id: "sub_1".into(),
            after_seq: 0,
            limit: 50,
        },
        RpcMethod::SubAck {
            subscription_id: "sub_1".into(),
            through_seq: 10,
        },
        RpcMethod::SubState {
            subscription_id: "sub_1".into(),
        },
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

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

    wait_for_socket(&socket);

    let out = Command::new(bin())
        .args(["--db", &db, "status"])
        .output()
        .unwrap();

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

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

    let start = std::time::Instant::now();
    while !socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

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

    let out = Command::new(bin())
        .args(["--db", &db, "messages"])
        .output()
        .unwrap();

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("hello from topo"),
        "should find message in list, got: {}",
        stdout
    );
}

#[test]
fn daemon_messages_and_create_workspace_are_idempotent_with_multi_identity_rows() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    // First bootstrap workspace.
    create_workspace(&db);

    let conn = topo::db::open_connection(&db).unwrap();
    let (extra_cert, extra_key) = topo::transport::generate_self_signed_cert().unwrap();
    let extra_fp = topo::transport::extract_spki_fingerprint(extra_cert.as_ref()).unwrap();
    let extra_peer_id = hex::encode(extra_fp);
    topo::db::transport_creds::store_local_creds(
        &conn,
        &extra_peer_id,
        extra_cert.as_ref(),
        extra_key.secret_pkcs8_der(),
    )
    .unwrap();
    let local_creds_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM local_transport_creds", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(
        local_creds_count >= 2,
        "expected multi-identity shape after inserting extra cred, got {}",
        local_creds_count
    );
    drop(conn);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&socket);

    // Regression 1: create-workspace should be idempotent, not fail on
    // "Multiple local identities found".
    let out = Command::new(bin())
        .args(["--db", &db, "create-workspace"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "second create-workspace should succeed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    // Regression 2: messages should use active tenant scope and succeed.
    let out = Command::new(bin())
        .args(["--db", &db, "messages"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "messages should succeed in multi-identity DB: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn daemon_and_cli_assert_now() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

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
    let path = topo::service::socket_path_for_db("topo.db");
    assert!(path.to_str().unwrap().ends_with("topo.topo.sock"));

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

    let (field, op, val) = parse_predicate("recorded_events_count >= 0").unwrap();
    assert_eq!(field, "recorded_events_count");
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

    create_workspace(&db);

    let mut daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

    wait_for_socket(&socket);

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
        match daemon.child().try_wait() {
            Ok(Some(status)) => {
                let _ = status;
                break;
            }
            Ok(None) => {
                if exit_start.elapsed().as_secs() >= 5 {
                    panic!("daemon did not exit within 5s after stop");
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => panic!("error waiting for daemon: {}", e),
        }
    }

    assert!(!socket.exists(), "socket file should be removed after stop");
}

#[test]
fn custom_socket_routing() {
    let (dir, db) = temp_db();
    let custom_socket = dir.path().join("custom.sock");

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
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
            .unwrap(),
    );

    let start = std::time::Instant::now();
    while !custom_socket.exists() && start.elapsed().as_secs() < 5 {
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(custom_socket.exists(), "custom socket did not appear");

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

    let default_socket = socket_path_for_db(&db);
    assert!(
        !default_socket.exists(),
        "default socket should not exist when custom socket is used"
    );

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
}

#[test]
fn daemon_status_includes_runtime_net_info() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

    wait_for_socket(&socket);

    // Give daemon a moment to populate runtime net info.
    std::thread::sleep(std::time::Duration::from_millis(500));

    let data = status_via_rpc(&socket);

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

    assert!(
        runtime.get("upnp").is_none() || runtime["upnp"].is_null(),
        "upnp should not be present before running topo upnp"
    );
}

#[test]
fn daemon_cli_status_shows_listen_line() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

    wait_for_socket(&socket);

    std::thread::sleep(std::time::Duration::from_millis(500));

    let out = Command::new(bin())
        .args(["--db", &db, "status"])
        .output()
        .unwrap();

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

    let mut daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );
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
fn upnp_on_empty_daemon_works_without_workspace() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    // Use a fixed port so bind_addr is resolved early (port 0 is deferred
    // to the runtime since the OS-assigned port isn't known until bind).
    let mut daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:14433"])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&socket);
    let _ = wait_for_runtime_state(&socket, "IdleNoTenants", Duration::from_secs(10));

    // UPnP should succeed (return ok) even without a workspace.
    // On loopback it reports "not_attempted" but does not error.
    let out = Command::new(bin())
        .args(["--db", &db, "upnp"])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "upnp should succeed on empty daemon, got stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains("not attempted") || stdout.contains("success") || stdout.contains("failed"),
        "expected a UPnP status report, got: {}",
        stdout
    );

    stop_daemon(&db, &mut daemon);
}

#[test]
fn create_workspace_on_running_daemon_activates_runtime() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);
    assert!(!socket.exists(), "socket should not exist before command");

    let mut daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&socket);
    let _ = wait_for_runtime_state(&socket, "IdleNoTenants", Duration::from_secs(10));

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
    assert!(
        stdout.contains("peer_id:"),
        "missing peer_id output: {}",
        stdout
    );
    assert!(
        stdout.contains("workspace_id:"),
        "missing workspace_id output: {}",
        stdout
    );

    let data = wait_for_runtime_state(&socket, "Active", Duration::from_secs(10));
    assert!(
        data.get("runtime")
            .and_then(|rt| rt.get("listen_addr"))
            .and_then(|v| v.as_str())
            .is_some(),
        "expected runtime.listen_addr in active state: {}",
        data
    );

    stop_daemon(&db, &mut daemon);
}

#[test]
fn accept_invite_on_running_idle_daemon_activates_runtime_without_restart() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    let alice_socket = socket_path_for_db(&alice_db);
    let bob_socket = socket_path_for_db(&bob_db);

    // Alice: start daemon, then create workspace.
    let mut alice_daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &alice_db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&alice_socket);
    let _ = wait_for_runtime_state(&alice_socket, "IdleNoTenants", Duration::from_secs(10));
    let create = Command::new(bin())
        .args(["create-workspace", "--db", &alice_db])
        .output()
        .unwrap();
    assert!(create.status.success(), "alice create-workspace failed");
    let alice_status = wait_for_runtime_state(&alice_socket, "Active", Duration::from_secs(10));
    let alice_listen = alice_status["runtime"]["listen_addr"]
        .as_str()
        .expect("alice runtime.listen_addr")
        .to_string();

    let invite_out = Command::new(bin())
        .args([
            "--db",
            &alice_db,
            "invite",
            "--public-addr",
            &alice_listen,
        ])
        .output()
        .unwrap();
    assert!(
        invite_out.status.success(),
        "invite failed: stdout={} stderr={}",
        String::from_utf8_lossy(&invite_out.stdout),
        String::from_utf8_lossy(&invite_out.stderr)
    );
    let invite_link = String::from_utf8_lossy(&invite_out.stdout)
        .lines()
        .find(|line| line.starts_with("topo://"))
        .expect("invite output missing invite link")
        .to_string();

    // Bob: explicit daemon start on empty DB should stay idle first.
    let mut bob_daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &bob_db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );
    let bob_pid_before = bob_daemon.child().id();
    wait_for_socket(&bob_socket);
    let _ = wait_for_runtime_state(&bob_socket, "IdleNoTenants", Duration::from_secs(10));

    // accept must route through RPC and trigger runtime activation.
    let accept = Command::new(bin())
        .args([
            "accept",
            "--db",
            &bob_db,
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
        "accept failed: stdout={} stderr={}",
        String::from_utf8_lossy(&accept.stdout),
        String::from_utf8_lossy(&accept.stderr)
    );
    assert!(
        bob_daemon.child().try_wait().unwrap().is_none(),
        "bob daemon should keep running (no restart required)"
    );
    assert_eq!(
        bob_daemon.child().id(),
        bob_pid_before,
        "daemon process should be unchanged"
    );
    let _ = wait_for_runtime_state(&bob_socket, "Active", Duration::from_secs(10));

    stop_daemon(&alice_db, &mut alice_daemon);
    stop_daemon(&bob_db, &mut bob_daemon);
}

#[test]
fn accept_invite_when_already_in_workspace_adds_second_tenant() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    // Alice creates a workspace and publishes an invite from a running daemon.
    create_workspace(&alice_db);
    let mut alice_daemon = start_daemon(&alice_db);
    let alice_listen = daemon_listen_addr(&alice_db);
    let invite_link = create_invite(&alice_db, &alice_listen);

    // Bob already has an existing workspace before accepting Alice's invite.
    create_workspace(&bob_db);
    let mut bob_daemon = start_daemon(&bob_db);

    // Accepting the new invite should succeed even with an existing tenant.
    let accept = Command::new(bin())
        .args([
            "accept",
            "--db",
            &bob_db,
            &invite_link,
            "--username",
            "bob2",
            "--devicename",
            "laptop2",
        ])
        .output()
        .unwrap();
    assert!(
        accept.status.success(),
        "accept failed: stdout={} stderr={}",
        String::from_utf8_lossy(&accept.stdout),
        String::from_utf8_lossy(&accept.stderr)
    );

    // Tenants list should now include both workspaces.
    let tenants_out = Command::new(bin())
        .args(["--db", &bob_db, "tenants"])
        .output()
        .unwrap();
    assert!(
        tenants_out.status.success(),
        "tenants failed: stdout={} stderr={}",
        String::from_utf8_lossy(&tenants_out.stdout),
        String::from_utf8_lossy(&tenants_out.stderr)
    );
    let tenants_stdout = String::from_utf8_lossy(&tenants_out.stdout);
    let tenant_count = tenants_stdout
        .lines()
        .filter(|line| line.trim_start().starts_with(|c: char| c.is_ascii_digit()))
        .count();
    assert!(
        tenant_count >= 2,
        "expected at least 2 tenants after second invite accept, got {}:\n{}",
        tenant_count,
        tenants_stdout
    );

    stop_daemon(&alice_db, &mut alice_daemon);
    stop_daemon(&bob_db, &mut bob_daemon);
}

#[test]
fn accept_invite_on_running_active_daemon_with_existing_workspace_succeeds() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();
    let alice_socket = socket_path_for_db(&alice_db);
    let bob_socket = socket_path_for_db(&bob_db);

    // Alice daemon: create workspace and invite.
    let mut alice_daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &alice_db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&alice_socket);
    let _ = wait_for_runtime_state(&alice_socket, "IdleNoTenants", Duration::from_secs(10));
    let alice_create = Command::new(bin())
        .args(["create-workspace", "--db", &alice_db, "--username", "alice"])
        .output()
        .unwrap();
    assert!(
        alice_create.status.success(),
        "alice create-workspace failed: {}",
        String::from_utf8_lossy(&alice_create.stderr)
    );
    let alice_status = wait_for_runtime_state(&alice_socket, "Active", Duration::from_secs(10));
    let alice_listen = alice_status["runtime"]["listen_addr"]
        .as_str()
        .expect("alice runtime.listen_addr")
        .to_string();
    let invite_link = create_invite(&alice_db, &alice_listen);

    // Bob daemon: create first workspace (becomes Active), then accept second invite.
    let mut bob_daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &bob_db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );
    let bob_pid_before = bob_daemon.child().id();
    wait_for_socket(&bob_socket);
    let _ = wait_for_runtime_state(&bob_socket, "IdleNoTenants", Duration::from_secs(10));
    let bob_create = Command::new(bin())
        .args(["create-workspace", "--db", &bob_db, "--username", "bob"])
        .output()
        .unwrap();
    assert!(
        bob_create.status.success(),
        "bob create-workspace failed: stdout={} stderr={}",
        String::from_utf8_lossy(&bob_create.stdout),
        String::from_utf8_lossy(&bob_create.stderr)
    );
    let _ = wait_for_runtime_state(&bob_socket, "Active", Duration::from_secs(10));

    let accept = Command::new(bin())
        .args([
            "accept",
            "--db",
            &bob_db,
            &invite_link,
            "--username",
            "bob2",
            "--devicename",
            "laptop2",
        ])
        .output()
        .unwrap();
    assert!(
        accept.status.success(),
        "accept failed: stdout={} stderr={}",
        String::from_utf8_lossy(&accept.stdout),
        String::from_utf8_lossy(&accept.stderr)
    );
    assert!(
        bob_daemon.child().try_wait().unwrap().is_none(),
        "bob daemon should stay running"
    );
    assert_eq!(
        bob_daemon.child().id(),
        bob_pid_before,
        "bob daemon process should be unchanged"
    );

    let tenants_out = Command::new(bin())
        .args(["--db", &bob_db, "tenants"])
        .output()
        .unwrap();
    assert!(
        tenants_out.status.success(),
        "tenants failed: stdout={} stderr={}",
        String::from_utf8_lossy(&tenants_out.stdout),
        String::from_utf8_lossy(&tenants_out.stderr)
    );
    let tenants_stdout = String::from_utf8_lossy(&tenants_out.stdout);
    let tenant_count = tenants_stdout
        .lines()
        .filter(|line| line.trim_start().starts_with(|c: char| c.is_ascii_digit()))
        .count();
    assert!(
        tenant_count >= 2,
        "expected at least 2 tenants after accept, got {}:\n{}",
        tenant_count,
        tenants_stdout
    );

    // The accepted tenant must become operational: it needs local transport creds.
    let parsed_invite =
        topo::event_modules::workspace::invite_link::parse_invite_link(&invite_link)
            .expect("parse invite link");
    let invited_ws_b64 = topo::crypto::event_id_to_base64(&parsed_invite.workspace_id);
    let start = std::time::Instant::now();
    let mut found_transport = false;
    while start.elapsed() < Duration::from_secs(20) {
        let conn = topo::db::open_connection(&bob_db).expect("open bob db");
        let maybe_peer: Option<String> = conn
            .query_row(
                "SELECT recorded_by
                 FROM invites_accepted
                 WHERE workspace_id = ?1
                 ORDER BY created_at DESC, event_id DESC
                 LIMIT 1",
                rusqlite::params![&invited_ws_b64],
                |row| row.get(0),
            )
            .ok();
        if let Some(peer_id) = maybe_peer {
            let has_transport: bool = conn
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1
                         FROM local_transport_creds
                         WHERE peer_id = ?1
                         LIMIT 1
                     )",
                    rusqlite::params![&peer_id],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            if has_transport {
                found_transport = true;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(
        found_transport,
        "accepted tenant never obtained local transport credentials"
    );

    stop_daemon(&alice_db, &mut alice_daemon);
    stop_daemon(&bob_db, &mut bob_daemon);
}

#[test]
fn db_scoped_commands_remain_isolated_between_daemons() {
    let tmpdir = tempfile::tempdir().unwrap();
    let db_a = tmpdir.path().join("a.db").to_str().unwrap().to_string();
    let db_b = tmpdir.path().join("b.db").to_str().unwrap().to_string();

    create_workspace(&db_a);
    create_workspace(&db_b);

    let socket_a = socket_path_for_db(&db_a);
    let socket_b = socket_path_for_db(&db_b);
    let mut daemon_a = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db_a, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );
    let mut daemon_b = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db_b, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&socket_a);
    wait_for_socket(&socket_b);

    let send_a = Command::new(bin())
        .args(["--db", &db_a, "send", "db-a-message"])
        .output()
        .unwrap();
    assert!(
        send_a.status.success(),
        "send on db A failed: {}",
        String::from_utf8_lossy(&send_a.stderr)
    );

    let status_a = status_via_rpc(&socket_a);
    let status_b = status_via_rpc(&socket_b);
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

    stop_daemon(&db_a, &mut daemon_a);
    stop_daemon(&db_b, &mut daemon_b);
}

#[test]
fn peer_secret_events_do_not_pass_shared_egress_gate() {
    let (_dir, db) = temp_db();
    create_workspace(&db);

    let conn = rusqlite::Connection::open(&db).unwrap();
    let local_event_b64: String = conn
        .query_row(
            "SELECT event_id FROM events WHERE event_type = 'peer_secret' LIMIT 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let local_event_id =
        topo::crypto::event_id_from_base64(&local_event_b64).expect("valid local event id");
    let store = topo::db::store::Store::new(&conn);
    assert!(
        store.get_shared(&local_event_id).unwrap().is_none(),
        "peer_secret must never be returned by shared egress gate"
    );
}

#[test]
fn shutdown_handler_does_not_call_process_exit() {
    let server_source = include_str!("../src/runtime/control/rpc/server.rs");
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

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

    wait_for_socket(&socket);

    let out = Command::new(bin())
        .args(["--db", &db, "identity"])
        .output()
        .unwrap();

    assert!(out.status.success(), "identity failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("IDENTITY:"),
        "should contain IDENTITY header"
    );
    assert!(
        stdout.contains("Transport:"),
        "should contain Transport line"
    );
    assert!(stdout.contains("User:"), "should contain User line");
    assert!(stdout.contains("Peer:"), "should contain Peer line");
}

#[test]
fn rpc_invite_ref_resolution() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

    wait_for_socket(&socket);

    let out = Command::new(bin())
        .args([
            "--db",
            &db,
            "invite",
            "--public-addr",
            "127.0.0.1:4433",
        ])
        .output()
        .unwrap();
    assert!(out.status.success(), "invite failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("#1") || stdout.contains("topo://"),
        "should show invite ref or link, got: {}",
        stdout
    );
}

// ---------------------------------------------------------------------------
// 7. Peers command tests
// ---------------------------------------------------------------------------

#[test]
fn rpc_peers_returns_local_peer_after_create_workspace() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

    wait_for_socket(&socket);

    let resp = topo::rpc::client::rpc_call(&socket, topo::rpc::protocol::RpcMethod::Peers).unwrap();
    assert!(resp.ok, "peers RPC should succeed: {:?}", resp.error);
    let data = resp.data.expect("peers response missing data");
    let items = data.as_array().expect("peers should return an array");

    assert_eq!(
        items.len(),
        1,
        "should have exactly one peer after create-workspace, got: {:?}",
        items
    );

    let peer = &items[0];
    assert!(
        peer["peer_id"].is_string(),
        "peer should have peer_id string"
    );
    assert!(
        peer["local"].as_bool().unwrap_or(false),
        "the only peer after create-workspace should be local"
    );
    assert!(
        peer["device_name"].is_string(),
        "peer should have device_name"
    );
}

#[test]
fn cli_peers_output_format() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

    wait_for_socket(&socket);

    let out = Command::new(bin())
        .args(["--db", &db, "peers"])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "peers command failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("PEERS"),
        "should contain PEERS header, got: {}",
        stdout
    );
    assert!(
        stdout.contains("[local]"),
        "local peer should show [local] marker, got: {}",
        stdout
    );
    assert!(
        stdout.contains("1."),
        "should show numbered list, got: {}",
        stdout
    );
}

#[test]
fn peers_shows_remote_after_invite_accept() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    let alice_socket = socket_path_for_db(&alice_db);
    let bob_socket = socket_path_for_db(&bob_db);

    // Alice: start daemon, create workspace.
    let mut alice_daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &alice_db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&alice_socket);
    let _ = wait_for_runtime_state(&alice_socket, "IdleNoTenants", Duration::from_secs(10));
    let create = Command::new(bin())
        .args(["create-workspace", "--db", &alice_db, "--username", "alice"])
        .output()
        .unwrap();
    assert!(create.status.success(), "alice create-workspace failed");
    let alice_status = wait_for_runtime_state(&alice_socket, "Active", Duration::from_secs(10));
    let alice_listen = alice_status["runtime"]["listen_addr"]
        .as_str()
        .expect("alice runtime.listen_addr")
        .to_string();

    // Alice creates invite.
    let invite_out = Command::new(bin())
        .args([
            "--db",
            &alice_db,
            "invite",
            "--public-addr",
            &alice_listen,
        ])
        .output()
        .unwrap();
    assert!(invite_out.status.success(), "invite failed");
    let invite_link = String::from_utf8_lossy(&invite_out.stdout)
        .lines()
        .find(|line| line.starts_with("topo://"))
        .expect("missing invite link")
        .to_string();

    // Bob: start daemon, accept invite.
    let mut bob_daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &bob_db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );
    wait_for_socket(&bob_socket);
    let accept = Command::new(bin())
        .args([
            "accept",
            "--db",
            &bob_db,
            &invite_link,
            "--username",
            "bob",
        ])
        .output()
        .unwrap();
    assert!(
        accept.status.success(),
        "accept failed: {}",
        String::from_utf8_lossy(&accept.stderr)
    );
    let _ = wait_for_runtime_state(&bob_socket, "Active", Duration::from_secs(10));

    // Wait for sync to propagate identity events
    let start = std::time::Instant::now();
    loop {
        let resp = topo::rpc::client::rpc_call(&bob_socket, topo::rpc::protocol::RpcMethod::Peers)
            .unwrap();
        if resp.ok {
            if let Some(data) = &resp.data {
                if let Some(items) = data.as_array() {
                    if items.len() >= 2 {
                        let local_count = items
                            .iter()
                            .filter(|p| p["local"].as_bool().unwrap_or(false))
                            .count();
                        let remote_count = items
                            .iter()
                            .filter(|p| !p["local"].as_bool().unwrap_or(false))
                            .count();
                        assert_eq!(local_count, 1, "bob should see exactly one local peer");
                        assert!(
                            remote_count >= 1,
                            "bob should see at least one remote peer (alice)"
                        );

                        let has_endpoint = items.iter().any(|p| {
                            !p["local"].as_bool().unwrap_or(false) && p["endpoint"].is_string()
                        });
                        assert!(
                            has_endpoint,
                            "remote peer should have endpoint from sync, got: {:?}",
                            items
                        );
                        break;
                    }
                }
            }
        }
        if start.elapsed() > Duration::from_secs(30) {
            let resp =
                topo::rpc::client::rpc_call(&bob_socket, topo::rpc::protocol::RpcMethod::Peers)
                    .unwrap();
            panic!(
                "bob did not see 2 peers within 30s, last response: {:?}",
                resp.data
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    stop_daemon(&alice_db, &mut alice_daemon);
    stop_daemon(&bob_db, &mut bob_daemon);
}

// ---------------------------------------------------------------------------
// 8. RPC CLI demo surface tests
// ---------------------------------------------------------------------------

#[test]
fn rpc_methods_lists_all_known_methods() {
    let out = Command::new(bin())
        .args(["rpc", "methods"])
        .output()
        .unwrap();
    assert!(out.status.success(), "rpc methods failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("RPC METHODS"), "should show header");
    assert!(stdout.contains("Status"), "should list Status");
    assert!(stdout.contains("Send"), "should list Send");
    assert!(stdout.contains("Messages"), "should list Messages");
    assert!(stdout.contains("Peers"), "should list Peers");
    assert!(stdout.contains("View"), "should list View");
}

#[test]
fn rpc_methods_json_output() {
    let out = Command::new(bin())
        .args(["rpc", "methods", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "rpc methods --json failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    let arr = parsed.as_array().expect("should be an array");
    assert!(
        arr.len() >= 25,
        "should list at least 25 methods, got {}",
        arr.len()
    );
    for entry in arr {
        assert!(entry["name"].is_string(), "method should have name");
        assert!(entry["purpose"].is_string(), "method should have purpose");
    }
}

#[test]
fn rpc_describe_known_method() {
    let out = Command::new(bin())
        .args(["rpc", "describe", "Send"])
        .output()
        .unwrap();
    assert!(out.status.success(), "rpc describe Send failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Send:"), "should show method name header");
    assert!(stdout.contains("content"), "should show content parameter");
    assert!(stdout.contains("Example:"), "should show example");
}

#[test]
fn rpc_describe_json_output() {
    let out = Command::new(bin())
        .args(["rpc", "describe", "Send", "--json"])
        .output()
        .unwrap();
    assert!(out.status.success(), "rpc describe --json failed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert_eq!(parsed["name"].as_str(), Some("Send"));
    assert!(parsed["params"].is_array(), "should have params array");
}

#[test]
fn rpc_describe_unknown_method_fails() {
    let out = Command::new(bin())
        .args(["rpc", "describe", "NoSuchMethod"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "should fail for unknown method");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown method"),
        "should mention unknown method"
    );
}

#[test]
fn rpc_describe_case_insensitive() {
    let out = Command::new(bin())
        .args(["rpc", "describe", "status"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "rpc describe should be case-insensitive"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Status:"), "should show Status header");
}

#[test]
fn rpc_call_method_json_status() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

    wait_for_socket(&socket);

    let out = Command::new(bin())
        .args([
            "--db",
            &db,
            "rpc",
            "call",
            "--method-json",
            r#"{"type":"Status"}"#,
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "rpc call --method-json Status failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["ok"].as_bool().unwrap_or(false), "should be ok=true");
    assert!(parsed["version"].is_number(), "should have version");
}

#[test]
fn rpc_call_request_json() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

    wait_for_socket(&socket);

    let out = Command::new(bin())
        .args([
            "--db",
            &db,
            "rpc",
            "call",
            "--request-json",
            r#"{"version":1,"method":{"type":"Status"}}"#,
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "rpc call --request-json failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["ok"].as_bool().unwrap_or(false), "should be ok=true");
}

#[test]
fn rpc_call_invalid_json_fails() {
    let (_dir, db) = temp_db();

    let out = Command::new(bin())
        .args(["--db", &db, "rpc", "call", "--method-json", "not json"])
        .output()
        .unwrap();

    assert!(!out.status.success(), "should fail on invalid JSON");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("invalid method JSON"),
        "should mention invalid JSON, got: {}",
        stderr
    );
}

#[test]
fn rpc_call_method_json_missing_type_fails() {
    let out = Command::new(bin())
        .args(["rpc", "call", "--method-json", r#"{"bogus":"field"}"#])
        .output()
        .unwrap();
    assert!(!out.status.success(), "should fail on missing type");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("\"type\" field"),
        "should mention type field, got: {}",
        stderr
    );
}

#[test]
fn rpc_call_request_json_missing_version_fails() {
    let out = Command::new(bin())
        .args(["rpc", "call", "--request-json", r#"{"type":"Status"}"#])
        .output()
        .unwrap();
    assert!(!out.status.success(), "should fail on missing version");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("\"version\" field"),
        "should mention version field, got: {}",
        stderr
    );
    assert!(
        stderr.contains("--method-json"),
        "should hint about --method-json, got: {}",
        stderr
    );
}

#[test]
fn rpc_call_no_input_fails() {
    let out = Command::new(bin()).args(["rpc", "call"]).output().unwrap();
    assert!(!out.status.success(), "should fail with no input");
}

#[test]
fn catalog_drift_test_method_count_matches_protocol() {
    let catalog_names = topo::rpc::catalog::method_names();

    let known_methods = vec![
        "Status",
        "Messages",
        "Send",
        "SendFile",
        "Files",
        "SaveFile",
        "Generate",
        "GenerateFiles",
        "AssertNow",
        "AssertEventually",
        "TransportIdentity",
        "React",
        "DeleteMessage",
        "Reactions",
        "Users",
        "Keys",
        "Workspaces",
        "IntroAttempts",
        "CreateInvite",
        "AcceptInvite",
        "CreateDeviceLink",
        "AcceptLink",
        "Ban",
        "Identity",
        "Shutdown",
        "Tenants",
        "UseTenant",
        "ActiveTenant",
        "CreateWorkspace",
        "Peers",
        "Upnp",
        "View",
        "EventList",
        "Intro",
    ];

    for method in &known_methods {
        assert!(
            catalog_names.contains(method),
            "catalog missing method: {}",
            method
        );
    }
    assert_eq!(
        catalog_names.len(),
        known_methods.len(),
        "catalog has {} methods, protocol has {} — drift detected",
        catalog_names.len(),
        known_methods.len()
    );
}

#[test]
fn rpc_call_file_input() {
    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

    wait_for_socket(&socket);

    let tmpdir = tempfile::tempdir().unwrap();
    let file_path = tmpdir.path().join("req.json");
    std::fs::write(&file_path, r#"{"version":1,"method":{"type":"Status"}}"#).unwrap();

    let out = Command::new(bin())
        .args([
            "--db",
            &db,
            "rpc",
            "call",
            "--file",
            file_path.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "rpc call --file failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["ok"].as_bool().unwrap_or(false), "should be ok=true");
}

#[test]
fn rpc_call_stdin_input() {
    use std::io::Write;
    use std::process::Stdio;

    let (_dir, db) = temp_db();
    let socket = socket_path_for_db(&db);

    create_workspace(&db);

    let _daemon = DaemonGuard::new(
        Command::new(bin())
            .args(["--db", &db, "start", "--bind", "127.0.0.1:0"])
            .spawn()
            .unwrap(),
    );

    wait_for_socket(&socket);

    let mut child = Command::new(bin())
        .args(["--db", &db, "rpc", "call", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"version":1,"method":{"type":"Status"}}"#)
        .unwrap();

    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "rpc call --stdin failed: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["ok"].as_bool().unwrap_or(false), "should be ok=true");
}
