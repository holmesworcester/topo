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

pub struct LocalTenantInfo {
    pub peer_id: String,
    pub workspace_id: String,
    pub transport_peer_id: String,
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
    /// Redirect stdout to a file path (takes precedence over inherit_stdio).
    pub stdout_file: Option<std::path::PathBuf>,
    /// Redirect stderr to a file path (takes precedence over inherit_stdio).
    pub stderr_file: Option<std::path::PathBuf>,
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self {
            bind_port: None,
            disable_placeholder_autodial: false,
            inherit_stdio: false,
            stdout_file: None,
            stderr_file: None,
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

    for attempt in 0..3 {
        let mut cmd = Command::new(bin());
        cmd.arg("--db")
            .arg(db)
            .arg("start")
            .arg("--bind")
            .arg(&bind_addr);

        if opts.disable_placeholder_autodial {
            cmd.env("P7_DISABLE_PLACEHOLDER_AUTODIAL", "1");
        }

        if let Some(ref path) = opts.stdout_file {
            let f = std::fs::File::create(path).expect("create stdout log file");
            cmd.stdout(f);
        } else if opts.inherit_stdio {
            cmd.stdout(Stdio::inherit());
        } else {
            cmd.stdout(Stdio::null());
        }

        if let Some(ref path) = opts.stderr_file {
            let f = std::fs::File::create(path).expect("create stderr log file");
            cmd.stderr(f);
        } else if opts.inherit_stdio {
            cmd.stderr(Stdio::inherit());
        } else {
            cmd.stderr(Stdio::null());
        }

        let mut child = cmd.spawn().expect("failed to start topo daemon");

        let start = Instant::now();
        let mut exited_early = None;
        loop {
            if let Some(status) = child.try_wait().expect("failed to check daemon status") {
                exited_early = Some(status);
                break;
            }
            if socket.exists() || start.elapsed().as_secs() >= 5 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        if let Some(status) = exited_early {
            if attempt < 2 {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            panic!("daemon exited immediately with {} (db={})", status, db);
        }

        if !socket.exists() {
            let _ = child.kill();
            let _ = child.wait();
            if attempt < 2 {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            panic!(
                "daemon socket did not appear at {} within 5s (db={})",
                socket.display(),
                db
            );
        }

        wait_for_daemon_ready(db, Duration::from_secs(15));

        let rpc_start = Instant::now();
        loop {
            let out = Command::new(bin())
                .args(["--db", db, "tenant", "active"])
                .output()
                .expect("failed to probe daemon tenant active");
            if out.status.success() {
                return DaemonGuard::new(child);
            }
            if rpc_start.elapsed().as_secs() >= 5 {
                let _ = child.kill();
                let _ = child.wait();
                if attempt < 2 {
                    std::thread::sleep(Duration::from_millis(100));
                    break;
                }
                panic!(
                    "daemon socket exists but RPC not responding after 5s (db={}): {}",
                    db,
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    panic!("daemon failed to start after retries (db={})", db);
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
                topo::rpc::client::rpc_call(&socket, topo::rpc::protocol::RpcMethod::ActiveTenant)
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
            topo::rpc::client::rpc_call(&socket, topo::rpc::protocol::RpcMethod::ActiveTenant)
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

/// Create a workspace via CLI with full control over visible identity fields.
/// Waits for tenant discovery and stops the daemon cleanly afterward.
pub fn create_workspace_with_details(
    db: &str,
    workspace_name: &str,
    username: &str,
    device_name: &str,
) {
    let tmp_daemon = start_daemon(db);
    let out = Command::new(bin())
        .args([
            "create-workspace",
            "--db",
            db,
            "--workspace-name",
            workspace_name,
            "--username",
            username,
            "--device-name",
            device_name,
        ])
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
            .args(["--db", db, "tenant", "list"])
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

/// Create a workspace via CLI, using default names.
/// Waits for tenant discovery and stops the daemon cleanly afterward.
pub fn create_workspace(db: &str) {
    create_workspace_with_details(db, "workspace", "user", "device");
}

/// Create a workspace with custom username via CLI.
pub fn create_workspace_with_username(db: &str, username: &str) {
    create_workspace_with_details(db, "workspace", username, "device");
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
            .args(["--db", db, "tenant", "active"])
            .output()
            .expect("failed to run tenant active");
        if active.status.success() {
            let active_stdout = String::from_utf8_lossy(&active.stdout).trim().to_string();
            if !active_stdout.is_empty() && active_stdout != "(no active tenant)" {
                return;
            }
            last_active = active_stdout;
        } else {
            last_active = format!("error: {}", String::from_utf8_lossy(&active.stderr).trim());
        }

        let peers = Command::new(bin())
            .args(["--db", db, "tenant", "list"])
            .output()
            .expect("failed to run tenant list");
        if peers.status.success() {
            let peers_stdout = String::from_utf8_lossy(&peers.stdout).to_string();
            if let Some(index) = first_peer_index(&peers_stdout) {
                let use_peer = Command::new(bin())
                    .args(["--db", db, "tenant", "use", &index.to_string()])
                    .output()
                    .expect("failed to run tenant use");
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
        "failed to establish active tenant within {:?} (db={}): active={}, tenants={}, tenant-use-error={}",
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
        let retryable = stderr.contains("no identity")
            || stderr.contains("no active tenant")
            || stderr.contains("workspace has not completed initial sync yet")
            || stderr.contains("blocked on");
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
        .arg("invite")
        .arg("--public-addr")
        .arg(bootstrap_addr);
    if let Some(spki) = public_spki {
        cmd.arg("--public-spki").arg(spki);
    }
    let output = cmd.output().expect("failed to run invite");
    assert!(
        output.status.success(),
        "invite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|line| line.starts_with("topo://"))
        .unwrap_or_else(|| stdout.trim())
        .to_string()
}

/// Create a device-link invite via daemon RPC. Returns the `topo://link/` link.
pub fn create_device_link(db: &str, bootstrap_addr: &str) -> String {
    create_device_link_with_spki(db, bootstrap_addr, None)
}

/// Create a device-link invite with optional SPKI fingerprint.
pub fn create_device_link_with_spki(
    db: &str,
    bootstrap_addr: &str,
    public_spki: Option<&str>,
) -> String {
    let mut cmd = Command::new(bin());
    cmd.arg("--db")
        .arg(db)
        .arg("link")
        .arg("--public-addr")
        .arg(bootstrap_addr);
    if let Some(spki) = public_spki {
        cmd.arg("--public-spki").arg(spki);
    }
    let output = cmd.output().expect("failed to run link");
    assert!(
        output.status.success(),
        "link failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .find(|line| line.starts_with("topo://link/"))
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
    let signer_wait_timeout =
        match topo::event_modules::workspace::invite_link::parse_invite_link(invite_link) {
            Ok(invite) if invite.bootstrap_addrs.is_empty() => Duration::from_secs(2),
            _ => Duration::from_secs(60),
        };
    accept_invite_with_identity_and_timeout(
        db,
        invite_link,
        username,
        devicename,
        signer_wait_timeout,
    );
}

pub fn accept_invite_with_identity_and_timeout(
    db: &str,
    invite_link: &str,
    username: &str,
    devicename: &str,
    signer_wait_timeout: Duration,
) {
    let tmp_daemon = start_daemon(db);
    let output = Command::new(bin())
        .arg("accept")
        .arg("--db")
        .arg(db)
        .arg(invite_link)
        .arg("--username")
        .arg(username)
        .arg("--devicename")
        .arg(devicename)
        .output()
        .expect("failed to run accept");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "accept failed:\n  stdout: {}\n  stderr: {}",
        stdout.trim(),
        stderr.trim()
    );
    // Ensure tenant discovery is persisted before stopping.
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        let peers = Command::new(bin())
            .args(["--db", db, "tenant", "list"])
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
    if let Err(debug) = wait_for_local_peer_signer(db, signer_wait_timeout) {
        eprintln!(
            "accept_invite: peer signer not materialized yet; continuing (db={}): {}",
            db, debug
        );
    }
    // Stop temporary daemon; callers decide daemon lifecycle.
    let _ = Command::new(bin()).args(["--db", db, "stop"]).output();
    drop(tmp_daemon);
    wait_for_daemon_stopped(db, Duration::from_secs(10));
}

/// Accept a device-link invite via daemon RPC using a temporary daemon.
pub fn accept_device_link(db: &str, invite_link: &str) {
    accept_device_link_with_name(db, invite_link, "device")
}

/// Accept a device-link invite with a custom device name.
pub fn accept_device_link_with_name(db: &str, invite_link: &str, devicename: &str) {
    let signer_wait_timeout =
        match topo::event_modules::workspace::invite_link::parse_invite_link(invite_link) {
            Ok(invite) if invite.bootstrap_addrs.is_empty() => Duration::from_secs(2),
            _ => Duration::from_secs(60),
        };
    accept_device_link_with_name_and_timeout(db, invite_link, devicename, signer_wait_timeout);
}

pub fn accept_device_link_with_name_and_timeout(
    db: &str,
    invite_link: &str,
    devicename: &str,
    signer_wait_timeout: Duration,
) {
    let tmp_daemon = start_daemon(db);
    let output = Command::new(bin())
        .arg("accept-link")
        .arg("--db")
        .arg(db)
        .arg("--invite")
        .arg(invite_link)
        .arg("--devicename")
        .arg(devicename)
        .output()
        .expect("failed to run accept-link");
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "accept-link failed:\n  stdout: {}\n  stderr: {}",
        stdout.trim(),
        stderr.trim()
    );
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(5) {
        let peers = Command::new(bin())
            .args(["--db", db, "tenant", "list"])
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
    if let Err(debug) = wait_for_local_peer_signer(db, signer_wait_timeout) {
        eprintln!(
            "accept_device_link: peer signer not materialized yet; continuing (db={}): {}",
            db, debug
        );
    }
    let _ = Command::new(bin()).args(["--db", db, "stop"]).output();
    drop(tmp_daemon);
    wait_for_daemon_stopped(db, Duration::from_secs(10));
}

fn wait_for_local_peer_signer(db: &str, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(conn) = topo::db::open_connection(db) {
            let tenant_id: Option<String> = conn
                .query_row(
                    "SELECT recorded_by
                     FROM invites_accepted
                     ORDER BY created_at DESC, event_id DESC
                     LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .ok();
            if let Some(tenant_id) = tenant_id {
                let has_signer: bool = conn
                    .query_row(
                        "SELECT EXISTS(
                             SELECT 1
                             FROM peer_secrets
                             WHERE recorded_by = ?1
                             LIMIT 1
                         )",
                        rusqlite::params![tenant_id],
                        |row| row.get(0),
                    )
                    .unwrap_or(false);
                if has_signer {
                    return Ok(());
                }
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let debug = topo::db::open_connection(db)
        .ok()
        .map(|conn| {
            let invites: i64 = conn
                .query_row("SELECT COUNT(*) FROM invites_accepted", [], |row| row.get(0))
                .unwrap_or(0);
            let signer_rows: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM peer_secrets",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let signer_events: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM events WHERE type_name = 'peer_secret'",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let signer_rejects: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM rejected_events r
                     JOIN events e ON e.event_id = r.event_id
                     WHERE e.type_name = 'peer_secret'",
                    [],
                    |row| row.get(0),
                )
                .unwrap_or(0);
            let last_tenant: Option<String> = conn
                .query_row(
                    "SELECT recorded_by FROM invites_accepted ORDER BY created_at DESC, event_id DESC LIMIT 1",
                    [],
                    |row| row.get(0),
                )
                .ok();
            let (last_tenant_recorded, last_tenant_valid, last_tenant_blocked, last_tenant_queue) =
                last_tenant
                    .as_ref()
                    .map(|tenant_id| {
                        let recorded: i64 = conn
                            .query_row(
                                "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
                                rusqlite::params![tenant_id],
                                |row| row.get(0),
                            )
                            .unwrap_or(0);
                        let valid: i64 = conn
                            .query_row(
                                "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
                                rusqlite::params![tenant_id],
                                |row| row.get(0),
                            )
                            .unwrap_or(0);
                        let blocked: i64 = conn
                            .query_row(
                                "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1",
                                rusqlite::params![tenant_id],
                                |row| row.get(0),
                            )
                            .unwrap_or(0);
                        let queued: i64 = conn
                            .query_row(
                                "SELECT COUNT(*) FROM project_queue WHERE peer_id = ?1",
                                rusqlite::params![tenant_id],
                                |row| row.get(0),
                            )
                            .unwrap_or(0);
                        (recorded, valid, blocked, queued)
                    })
                    .unwrap_or((0, 0, 0, 0));
            let last_blockers = last_tenant
                .as_ref()
                .map(|tenant_id| {
                    let mut stmt = conn
                        .prepare(
                            "SELECT bed.event_id, bed.blocker_event_id
                             FROM blocked_event_deps bed
                             WHERE bed.peer_id = ?1
                             ORDER BY bed.event_id, bed.blocker_event_id
                             LIMIT 6",
                        )
                        .ok()?;
                    let rows = stmt
                        .query_map(rusqlite::params![tenant_id], |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                            ))
                        })
                        .ok()?
                        .collect::<Result<Vec<_>, _>>()
                        .ok()?;
                    Some(rows)
                })
                .flatten()
                .unwrap_or_default();
            format!(
                "invites_accepted={}, peer_secret_rows={}, signer_events={}, signer_rejects={}, last_tenant={}, last_tenant_recorded={}, last_tenant_valid={}, last_tenant_blocked={}, last_tenant_queue={}, last_blockers={:?}",
                invites,
                signer_rows,
                signer_events,
                signer_rejects,
                last_tenant.unwrap_or_else(|| "<none>".to_string()),
                last_tenant_recorded,
                last_tenant_valid,
                last_tenant_blocked,
                last_tenant_queue,
                last_blockers
            )
        })
        .unwrap_or_else(|| "db-open-failed".to_string());
    Err(format!(
        "local peer signer not materialized within {:?} (db={}): {}",
        timeout, db, debug
    ))
}

pub fn wait_for_local_peer_signer_ready(db: &str, timeout: Duration) {
    if let Err(debug) = wait_for_local_peer_signer(db, timeout) {
        panic!("{}", debug);
    }
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

/// Get raw `topo view` output.
pub fn get_view_raw(db: &str) -> String {
    ensure_active_peer(db, Duration::from_secs(10));
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("view")
        .output()
        .expect("failed to run view");
    assert!(
        output.status.success(),
        "view failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Get raw `topo status` output.
pub fn get_status_raw(db: &str) -> String {
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("status")
        .output()
        .expect("failed to run status");
    assert!(
        output.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Get raw `topo users` output.
pub fn get_users_raw(db: &str) -> String {
    ensure_active_peer(db, Duration::from_secs(10));
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("users")
        .output()
        .expect("failed to run users");
    assert!(
        output.status.success(),
        "users failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Get raw `topo tenant list` output.
pub fn get_tenants_raw(db: &str) -> String {
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .args(["tenant", "list"])
        .output()
        .expect("failed to run tenant list");
    assert!(
        output.status.success(),
        "tenant list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Get raw `topo workspaces` output.
pub fn get_workspaces_raw(db: &str) -> String {
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("workspaces")
        .output()
        .expect("failed to run workspaces");
    assert!(
        output.status.success(),
        "workspaces failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Get raw `topo peers` output.
pub fn get_peers_raw(db: &str) -> String {
    ensure_active_peer(db, Duration::from_secs(10));
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("peers")
        .output()
        .expect("failed to run peers");
    assert!(
        output.status.success(),
        "peers failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Select the active tenant by CLI selector (index, #index, or peer id).
pub fn use_tenant(db: &str, selector: &str) {
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .args(["tenant", "use", selector])
        .output()
        .expect("failed to run tenant use");
    assert!(
        output.status.success(),
        "tenant use failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
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

pub fn event_count_sql(db: &str, event_type: &str) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("failed to open db");
    conn.query_row(
        "SELECT COUNT(*) FROM events WHERE event_type = ?1",
        rusqlite::params![event_type],
        |row| row.get(0),
    )
    .expect("failed to query event count")
}

pub fn message_count_sql(db: &str) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("failed to open db");
    conn.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
        .expect("failed to query message count")
}

pub fn stored_message_event_count_sql(db: &str) -> i64 {
    let conn = rusqlite::Connection::open(db).expect("failed to open db");
    conn.query_row(
        "SELECT COUNT(*) FROM valid_events WHERE semantic_type_code = ?1",
        rusqlite::params![i64::from(topo::event_modules::EVENT_TYPE_MESSAGE)],
        |row| row.get(0),
    )
    .expect("failed to query stored message event count")
}

pub fn read_local_tenant_info(db: &str) -> LocalTenantInfo {
    let conn = topo::db::open_connection(db).expect("failed to open db");
    let mut tenants =
        topo::db::transport_creds::discover_local_tenants(&conn).expect("discover_local_tenants");
    assert_eq!(
        tenants.len(),
        1,
        "expected exactly one local tenant for benchmark db={}",
        db
    );
    let tenant = tenants.remove(0);
    LocalTenantInfo {
        peer_id: tenant.peer_id,
        workspace_id: tenant.workspace_id,
        transport_peer_id: tenant.transport_peer_id,
    }
}

pub fn seed_invite_bootstrap_trust(
    db: &str,
    invite_event_id: &str,
    bootstrap_addr: &str,
    bootstrap_spki_hex: &str,
) {
    let tenant = read_local_tenant_info(db);
    let spki_bytes = hex::decode(bootstrap_spki_hex).expect("decode bootstrap SPKI hex");
    assert_eq!(
        spki_bytes.len(),
        32,
        "expected 32-byte bootstrap SPKI fingerprint, got {} bytes",
        spki_bytes.len()
    );
    let mut spki = [0u8; 32];
    spki.copy_from_slice(&spki_bytes);

    let conn = topo::db::open_connection(db).expect("failed to open db");
    topo::db::transport_trust::record_invite_bootstrap_trust(
        &conn,
        &tenant.peer_id,
        &format!("ia-{invite_event_id}"),
        invite_event_id,
        &tenant.workspace_id,
        bootstrap_addr,
        &spki,
    )
    .expect("record_invite_bootstrap_trust");
}

pub fn generate_messages(db: &str, count: usize) {
    ensure_active_peer(db, Duration::from_secs(10));
    let output = topo_cmd(db, &["generate", "--count", &count.to_string()]);
    assert!(
        output.status.success(),
        "generate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub fn peak_rss_mib_for_pid(pid: u32) -> Option<f64> {
    let status_path = format!("/proc/{pid}/status");
    let status = std::fs::read_to_string(status_path).ok()?;
    for line in status.lines() {
        if line.starts_with("VmHWM:") {
            let kb: f64 = line.split_whitespace().nth(1)?.parse().ok()?;
            return Some(kb / 1024.0);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Cheat-proof realism helpers
// ---------------------------------------------------------------------------

/// Check if a stderr message is a transient RPC startup error that should be retried.
pub fn is_transient_rpc_startup_error(stderr: &str) -> bool {
    stderr.contains("daemon not running")
        || stderr.contains("Connection reset by peer")
        || stderr.contains("no identity — run `topo create-workspace` first")
        || stderr.contains("workspace has not completed initial sync yet")
        || stderr.contains("no active tenant — run `topo tenant use <N>`")
        || stderr.contains("blocked on")
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
            let _ = topo_cmd(db, &["tenant", "use", "1"]);
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
    let out = topo_rpc_retry(db, &["send", content], Duration::from_secs(60));
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
        &["invite", "--public-addr", bootstrap_addr],
        Duration::from_secs(3),
    );
    assert!(
        out.status.success(),
        "topo invite failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout
        .lines()
        .find(|line| line.starts_with("topo://"))
        .expect("invite output missing topo:// link")
        .to_string()
}

/// Accept an invite via a temporary daemon.
/// Uses the same readiness gates as `accept_invite_with_identity`.
pub fn accept_invite_lightweight(db: &str, invite_link: &str) {
    accept_invite_with_identity(db, invite_link, "user", "device");
}

/// Send a file via daemon RPC. Returns the event ID.
pub fn send_file(db: &str, content: &str, file_path: &str) -> String {
    ensure_active_peer(db, Duration::from_secs(10));
    let start = Instant::now();
    loop {
        let output = Command::new(bin())
            .arg("--db")
            .arg(db)
            .arg("send-file")
            .arg(content)
            .arg("--file")
            .arg(file_path)
            .output()
            .expect("failed to run send-file");
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            return stdout
                .lines()
                .find_map(|line| line.strip_prefix("event_id:"))
                .expect("send-file output missing event_id: line")
                .to_string();
        }

        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let retryable = stderr.contains("no identity")
            || stderr.contains("no active tenant")
            || stderr.contains("workspace has not completed initial sync yet")
            || stderr.contains("blocked on");
        if retryable && start.elapsed() < Duration::from_secs(20) {
            if stderr.contains("no active tenant") {
                ensure_active_peer(db, Duration::from_secs(5));
            }
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        panic!("send-file failed for db={}: {}", db, stderr);
    }
}

/// Save a received file to disk via daemon RPC.
pub fn save_file(db: &str, file_target: &str, output_path: &str) -> Output {
    Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("save-file")
        .arg(file_target)
        .arg("--out")
        .arg(output_path)
        .output()
        .expect("failed to run save-file")
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
