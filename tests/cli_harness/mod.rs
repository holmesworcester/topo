//! Shared test harness for CLI/daemon integration tests.
//!
//! Provides common helper functions for starting daemons, creating workspaces,
//! sending messages, managing invites, and asserting convergence. Used by
//! cli_test, rpc_test, cheat_proof_realism_test, and two_process_test.

#![allow(dead_code)]

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use topo::testutil::DaemonGuard;

// ---------------------------------------------------------------------------
// Core utilities
// ---------------------------------------------------------------------------

pub fn bin() -> String {
    env!("CARGO_BIN_EXE_topo").to_string()
}

/// Pick a random port in the ephemeral range to avoid conflicts.
pub fn random_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

pub fn temp_db() -> (tempfile::TempDir, String) {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("test.db").to_str().unwrap().to_string();
    (dir, db)
}

pub fn socket_path_for_db(db: &str) -> PathBuf {
    topo::service::socket_path_for_db(db)
}

/// Run a topo subcommand and return the output.
pub fn run_topo(args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .output()
        .expect("failed to run topo")
}

/// Run a topo subcommand scoped to a specific db.
pub fn topo_cmd(db: &str, args: &[&str]) -> Output {
    Command::new(bin())
        .arg("--db")
        .arg(db)
        .args(args)
        .output()
        .expect("failed to run topo")
}

// ---------------------------------------------------------------------------
// Daemon lifecycle
// ---------------------------------------------------------------------------

/// Options for starting a daemon.
pub struct DaemonOptions {
    /// Specific port to bind to. None = random (127.0.0.1:0).
    pub bind_port: Option<u16>,
    /// Disable placeholder autodial via environment variable.
    pub disable_placeholder_autodial: bool,
    /// Inherit stdout/stderr for debugging (instead of suppressing).
    pub inherit_stdio: bool,
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self {
            bind_port: None,
            disable_placeholder_autodial: false,
            inherit_stdio: false,
        }
    }
}

/// Start a daemon with default options (random port, suppressed I/O).
pub fn start_daemon(db: &str) -> DaemonGuard {
    start_daemon_with_options(db, &DaemonOptions::default())
}

/// Start a daemon on a specific port with suppressed I/O.
pub fn start_daemon_on_port(db: &str, port: u16) -> DaemonGuard {
    start_daemon_with_options(
        db,
        &DaemonOptions {
            bind_port: Some(port),
            ..Default::default()
        },
    )
}

/// Start a daemon with full control over options.
pub fn start_daemon_with_options(db: &str, opts: &DaemonOptions) -> DaemonGuard {
    let socket = socket_path_for_db(db);
    let bind_addr = match opts.bind_port {
        Some(port) => format!("127.0.0.1:{}", port),
        None => "127.0.0.1:0".to_string(),
    };

    let mut cmd = Command::new(bin());
    cmd.arg("--db")
        .arg(db)
        .arg("start")
        .arg("--bind")
        .arg(&bind_addr);

    if opts.disable_placeholder_autodial {
        cmd.env("P7_DISABLE_PLACEHOLDER_AUTODIAL", "1");
    }

    if opts.inherit_stdio {
        cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    } else {
        cmd.stdout(Stdio::null()).stderr(Stdio::null());
    }

    let mut child = cmd.spawn().expect("failed to start topo daemon");

    // Wait for socket to appear, checking that daemon hasn't exited early.
    let start = Instant::now();
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
        "daemon socket did not appear at {} within 5s (db={})",
        socket.display(),
        db
    );

    wait_for_daemon_ready(db, Duration::from_secs(15));

    // Extra RPC readiness check via CLI status command.
    let rpc_start = Instant::now();
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

    DaemonGuard::new(child)
}

/// Wait for the daemon's RPC socket to appear.
pub fn wait_for_socket(socket: &PathBuf) {
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

/// Wait for the daemon to become RPC-ready.
pub fn wait_for_daemon_ready(db: &str, timeout: Duration) {
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
    panic!(
        "daemon did not become ready for RPC within {:?} (db={})",
        timeout, db
    );
}

/// Wait for the daemon to stop (socket removed and RPC unresponsive).
pub fn wait_for_daemon_stopped(db: &str, timeout: Duration) {
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

/// Send stop command and wait for the daemon process to exit.
pub fn stop_daemon(db: &str, daemon: &mut DaemonGuard) {
    let _ = Command::new(bin()).args(["--db", db, "stop"]).output();
    let start = Instant::now();
    loop {
        match daemon.child().try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if start.elapsed().as_secs() >= 5 {
                    return; // DaemonGuard will kill on drop
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => return, // DaemonGuard will kill on drop
        }
    }
}

// ---------------------------------------------------------------------------
// RPC helpers
// ---------------------------------------------------------------------------

/// Query status via RPC and return the parsed JSON data.
pub fn status_via_rpc(socket: &PathBuf) -> serde_json::Value {
    let resp = topo::rpc::client::rpc_call(socket, topo::rpc::protocol::RpcMethod::Status)
        .expect("status RPC");
    assert!(resp.ok, "status RPC should succeed: {:?}", resp.error);
    resp.data.expect("status response missing data")
}

/// Poll the daemon until runtime_state reaches `expected`, returning status data.
pub fn wait_for_runtime_state(
    socket: &PathBuf,
    expected: &str,
    timeout: Duration,
) -> serde_json::Value {
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

/// Get the daemon's listen address from status RPC.
pub fn daemon_listen_addr(db: &str) -> String {
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

/// Get the daemon's transport SPKI fingerprint.
pub fn daemon_transport_fingerprint(db: &str) -> String {
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

// ---------------------------------------------------------------------------
// Workspace / identity
// ---------------------------------------------------------------------------

/// Create a workspace via CLI, using a temporary daemon.
/// Waits for tenant discovery and stops the daemon cleanly afterward.
pub fn create_workspace(db: &str) {
    let tmp_daemon = start_daemon(db);
    let out = Command::new(bin())
        .args(["create-workspace", "--db", db])
        .output()
        .expect("create-workspace");
    assert!(
        out.status.success(),
        "create-workspace failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Wait until tenant discovery sees at least one peer before stopping.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        let peers = Command::new(bin())
            .args(["--db", db, "tenants"])
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
    // Stop temporary daemon; callers decide daemon lifecycle.
    let _ = Command::new(bin()).args(["--db", db, "stop"]).output();
    drop(tmp_daemon);
    wait_for_daemon_stopped(db, Duration::from_secs(10));
}

/// Create a workspace with custom username via CLI.
pub fn create_workspace_with_username(db: &str, username: &str) {
    let tmp_daemon = start_daemon(db);
    let out = Command::new(bin())
        .args(["create-workspace", "--db", db, "--username", username])
        .output()
        .expect("create-workspace");
    assert!(
        out.status.success(),
        "create-workspace failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        let peers = Command::new(bin())
            .args(["--db", db, "tenants"])
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
    let _ = Command::new(bin()).args(["--db", db, "stop"]).output();
    drop(tmp_daemon);
    wait_for_daemon_stopped(db, Duration::from_secs(10));
}

// ---------------------------------------------------------------------------
// CLI command helpers
// ---------------------------------------------------------------------------

/// Parse the first numbered peer index from `topo tenants` output.
pub fn first_peer_index(peers_stdout: &str) -> Option<usize> {
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

/// Ensure the daemon has an active tenant selected.
pub fn ensure_active_peer(db: &str, timeout: Duration) {
    let start = Instant::now();
    let mut last_active = String::new();
    let mut last_peers = String::new();
    let mut last_use_peer_err = String::new();

    while start.elapsed() < timeout {
        let active = Command::new(bin())
            .args(["--db", db, "active-tenant"])
            .output()
            .expect("failed to run active-tenant");
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
            .args(["--db", db, "tenants"])
            .output()
            .expect("failed to run tenants");
        if peers.status.success() {
            let peers_stdout = String::from_utf8_lossy(&peers.stdout).to_string();
            if let Some(index) = first_peer_index(&peers_stdout) {
                let use_peer = Command::new(bin())
                    .arg("--db")
                    .arg(db)
                    .arg("use-tenant")
                    .arg(index.to_string())
                    .output()
                    .expect("failed to run use-tenant");
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
        "failed to establish active tenant within {:?} (db={}): active={}, tenants={}, use-tenant-error={}",
        timeout,
        db,
        last_active,
        last_peers.replace('\n', " | "),
        last_use_peer_err
    );
}

/// Send a message via daemon RPC, retrying transient errors.
pub fn send_message(db: &str, content: &str) -> String {
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
        let retryable = stderr.contains("no identity") || stderr.contains("no active tenant");
        if retryable && start.elapsed() < Duration::from_secs(20) {
            if stderr.contains("no active tenant") {
                ensure_active_peer(db, Duration::from_secs(5));
            }
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        panic!("send failed for db={}: {}", db, stderr);
    }
}

/// Create an invite via daemon RPC. Returns the `topo://` invite link.
pub fn create_invite(db: &str, bootstrap_addr: &str) -> String {
    create_invite_with_spki(db, bootstrap_addr, None)
}

/// Create an invite with optional SPKI fingerprint.
pub fn create_invite_with_spki(
    db: &str,
    bootstrap_addr: &str,
    public_spki: Option<&str>,
) -> String {
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
        .find(|line| line.starts_with("topo://"))
        .unwrap_or_else(|| stdout.trim())
        .to_string()
}

/// Accept an invite via daemon RPC using a temporary daemon.
/// Waits for tenant discovery and stops the daemon cleanly afterward.
pub fn accept_invite(db: &str, invite_link: &str) {
    accept_invite_with_identity(db, invite_link, "user", "device")
}

/// Accept an invite with custom username and device name.
pub fn accept_invite_with_identity(db: &str, invite_link: &str, username: &str, devicename: &str) {
    let tmp_daemon = start_daemon(db);
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
    // Ensure tenant discovery is persisted before stopping.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        let peers = Command::new(bin())
            .args(["--db", db, "tenants"])
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
    // Stop temporary daemon; callers decide daemon lifecycle.
    let _ = Command::new(bin()).args(["--db", db, "stop"]).output();
    drop(tmp_daemon);
    wait_for_daemon_stopped(db, Duration::from_secs(10));
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

/// Assert a predicate holds right now (via `topo assert-now`).
pub fn assert_now(db: &str, predicate: &str) {
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

/// Assert a predicate eventually holds (via `topo assert-eventually`).
pub fn assert_eventually(db: &str, predicate: &str, timeout_ms: u64) {
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

// ---------------------------------------------------------------------------
// Message query helpers
// ---------------------------------------------------------------------------

/// Get raw `topo messages` output.
pub fn get_messages_raw(db: &str) -> String {
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("messages")
        .output()
        .expect("failed to run messages");
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Get parsed message content lines from `topo messages` output.
pub fn get_messages(db: &str) -> Vec<String> {
    let text = get_messages_raw(db);
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

// ---------------------------------------------------------------------------
// Database helpers
// ---------------------------------------------------------------------------

/// Count rows in a table (direct SQL query).
pub fn count_rows(db: &str, table: &str) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("failed to open db");
    let sql = format!("SELECT COUNT(*) FROM {}", table);
    conn.query_row(&sql, [], |row| row.get(0))
        .expect("failed to query row count")
}

// ---------------------------------------------------------------------------
// Cheat-proof realism helpers
// ---------------------------------------------------------------------------

/// Check if a stderr message is a transient RPC startup error that should be retried.
pub fn is_transient_rpc_startup_error(stderr: &str) -> bool {
    stderr.contains("daemon not running")
        || stderr.contains("Connection reset by peer")
        || stderr.contains("no identity — run `topo create-workspace` first")
        || stderr.contains("no active tenant — run `topo use-tenant <N>`")
}

/// Run a topo RPC command with automatic retry on transient errors.
pub fn topo_rpc_retry(db: &str, args: &[&str], timeout: Duration) -> Output {
    let start = Instant::now();
    let mut attempt = 0u32;
    loop {
        let out = topo_cmd(db, args);
        if out.status.success() {
            return out;
        }
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("no active tenant") {
            let _ = topo_cmd(db, &["use-tenant", "1"]);
        }
        if start.elapsed() >= timeout || !is_transient_rpc_startup_error(&stderr) {
            return out;
        }
        attempt += 1;
        let delay_ms = 25u64 * (1u64 << attempt.min(5));
        std::thread::sleep(Duration::from_millis(delay_ms));
    }
}

/// Send a message via RPC with retry. Returns the event ID.
pub fn topo_send_retry(db: &str, content: &str) -> String {
    let out = topo_rpc_retry(db, &["send", content], Duration::from_secs(4));
    assert!(
        out.status.success(),
        "topo send failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("event_id:"))
        .expect("send output missing event_id: line")
        .to_string()
}

/// Create an invite via RPC with retry. Returns the invite link.
pub fn topo_create_invite_retry(db: &str, bootstrap_addr: &str) -> String {
    let out = topo_rpc_retry(
        db,
        &["create-invite", "--public-addr", bootstrap_addr],
        Duration::from_secs(3),
    );
    assert!(
        out.status.success(),
        "topo create-invite failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find(|line| line.starts_with("topo://"))
        .expect("create-invite output missing topo:// link")
        .to_string()
}

/// Accept an invite via a temporary daemon (lightweight version for cheat-proof tests).
/// Does not wait for tenant discovery — drops the daemon immediately after accept.
pub fn accept_invite_lightweight(db: &str, invite_link: &str) {
    let _tmp_daemon = start_daemon(db);
    let out = run_topo(&[
        "accept-invite",
        "--db",
        db,
        "--invite",
        invite_link,
        "--username",
        "user",
        "--devicename",
        "device",
    ]);
    assert!(
        out.status.success(),
        "accept-invite failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Return `topo assert-eventually` output without asserting success.
pub fn topo_assert_eventually(db: &str, predicate: &str, timeout_ms: u64) -> Output {
    topo_cmd(
        db,
        &[
            "assert-eventually",
            predicate,
            "--timeout-ms",
            &timeout_ms.to_string(),
        ],
    )
}
