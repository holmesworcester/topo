//! Shared test harness for CLI/daemon integration tests.
//!
//! Provides common helper functions for starting daemons, creating workspaces,
//! sending messages, managing invites, and asserting convergence. Used by
//! cli_test, rpc_test, cheat_proof_realism_test, and two_process_test.

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use topo::testutil::DaemonGuard;

static DAEMON_INSTANCE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_daemon_instance_id() -> u64 {
    DAEMON_INSTANCE_COUNTER.fetch_add(1, Ordering::Relaxed)
}

// Registry mapping db_path → (stdout_log_path, stderr_log_path) for the running daemon.
// Populated at daemon start, removed at drop/kill, consulted by daemon_debug_context().
static DAEMON_LOG_REGISTRY: OnceLock<Mutex<HashMap<String, (PathBuf, PathBuf)>>> = OnceLock::new();

fn daemon_log_registry() -> &'static Mutex<HashMap<String, (PathBuf, PathBuf)>> {
    DAEMON_LOG_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// RAII guard for a daemon started by the test harness.
///
/// Owns the child process and cleans it up on drop:
///   1. Sends `topo --db {db} stop` (blocks up to 5 s for graceful exit)
///   2. Polls the child for up to 2 s
///   3. SIGKILLs if still alive
///   4. Removes the socket file if still present
pub struct HarnessDaemon {
    child: Option<std::process::Child>,
    db_path: String,
    socket_path: PathBuf,
}

impl HarnessDaemon {
    pub fn new(child: std::process::Child, db: &str) -> Self {
        let socket_path = topo::service::socket_path_for_db(db);
        Self {
            child: Some(child),
            db_path: db.to_string(),
            socket_path,
        }
    }

    /// Access the underlying child process.
    pub fn child(&mut self) -> &mut std::process::Child {
        self.child.as_mut().expect("HarnessDaemon already consumed")
    }

    /// Take ownership of the child process without running the drop cleanup.
    pub fn take_child(&mut self) -> Option<std::process::Child> {
        self.child.take()
    }

    /// Mark the daemon as already stopped so Drop does nothing.
    pub fn clear(&mut self) {
        self.child = None;
    }

    /// Immediately SIGKILL the child and remove the socket file.
    pub fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
        daemon_log_registry().lock().unwrap().remove(&self.db_path);
    }

    /// Graceful stop: send `topo stop`, wait up to 5 s, force-kill if needed.
    /// Panics if the daemon does not stop.
    pub fn stop(&mut self) {
        let db = self.db_path.clone();
        let _ = Command::new(bin()).args(["--db", &db, "stop"]).output();
        let start = Instant::now();
        let mut stopped = false;
        while start.elapsed().as_secs() < 5 {
            if let Some(ref mut child) = self.child {
                match child.try_wait() {
                    Ok(Some(_)) => {
                        stopped = true;
                        break;
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            } else {
                stopped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if !stopped {
            if let Some(mut child) = self.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
        wait_for_daemon_stopped(&db, Duration::from_secs(5));
        self.clear();
        // Don't clear the log registry here — stop() is a mid-test operation
        // and downstream code may still call daemon_debug_context() if a
        // post-stop assertion panics. The registry entry is cleared in Drop.
    }
}

impl Drop for HarnessDaemon {
    fn drop(&mut self) {
        let Some(ref mut child) = self.child else {
            return;
        };
        // Graceful stop: blocks until `topo stop` exits (up to 5s), best-effort.
        let _ = Command::new(bin())
            .args(["--db", &self.db_path, "stop"])
            .output();
        // Poll for up to 2 s.
        let start = Instant::now();
        let mut exited = false;
        while start.elapsed().as_secs() < 2 {
            match child.try_wait() {
                Ok(Some(_)) => {
                    exited = true;
                    break;
                }
                Ok(None) => {}
                Err(_) => break,
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !exited {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;
        if self.socket_path.exists() {
            let _ = std::fs::remove_file(&self.socket_path);
        }
        daemon_log_registry().lock().unwrap().remove(&self.db_path);
    }
}

const DAEMON_START_MAX_ATTEMPTS: usize = 20;
const DAEMON_START_RETRY_BASE_MS: u64 = 200;

// ---------------------------------------------------------------------------
// Core utilities
// ---------------------------------------------------------------------------

pub fn bin() -> String {
    hold_network_test_binary_lock();
    env!("CARGO_BIN_EXE_topo").to_string()
}

fn git_common_dir() -> String {
    static COMMON_DIR: OnceLock<String> = OnceLock::new();
    COMMON_DIR
        .get_or_init(|| {
            let out = Command::new("git")
                .args([
                    "-C",
                    env!("CARGO_MANIFEST_DIR"),
                    "rev-parse",
                    "--git-common-dir",
                ])
                .output()
                .expect("run git rev-parse --git-common-dir");
            if !out.status.success() {
                panic!(
                    "git rev-parse --git-common-dir failed: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
            String::from_utf8_lossy(&out.stdout).trim().to_string()
        })
        .clone()
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

fn hold_network_test_binary_lock() {
    static LOCK_HELD: OnceLock<()> = OnceLock::new();
    LOCK_HELD.get_or_init(|| {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::Hash;
        use std::hash::Hasher;
        git_common_dir().hash(&mut hasher);
        let lock_path =
            std::env::temp_dir().join(format!("topo-network-tests-{:016x}.lock", hasher.finish()));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(&lock_path)
            .unwrap_or_else(|err| {
                panic!(
                    "failed to open cross-process network test lock {}: {}",
                    lock_path.display(),
                    err
                )
            });
        let rc = unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&file), libc::LOCK_EX) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            panic!(
                "failed to acquire cross-process network test lock {}: {}",
                lock_path.display(),
                err
            );
        }

        // Intentionally leak the locked file so the advisory lock is held for
        // the lifetime of this test binary. This prevents other daemon-heavy
        // test binaries from running concurrently under the default cargo test
        // scheduler and creating spurious transport timeouts.
        let _ = Box::leak(Box::new(file));
    });
}

pub fn hold_network_test_lock_for_binary() {
    hold_network_test_binary_lock();
}

fn hold_network_test_thread_lock() {
    static THREAD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    thread_local! {
        static THREAD_GUARD: RefCell<Option<std::sync::MutexGuard<'static, ()>>> = const {
            RefCell::new(None)
        };
    }

    let lock = THREAD_LOCK.get_or_init(|| Mutex::new(()));
    THREAD_GUARD.with(|slot| {
        if slot.borrow().is_none() {
            let guard = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            *slot.borrow_mut() = Some(guard);
        }
    });
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

fn run_cli_with_db_lock_retry(args: &[&str], description: &str, timeout: Duration) -> Output {
    let start = Instant::now();
    loop {
        let output = Command::new(bin())
            .args(args)
            .output()
            .unwrap_or_else(|_| panic!("failed to run {description}"));
        if output.status.success() {
            return output;
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("database is locked") && start.elapsed() < timeout {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        return output;
    }
}

// ---------------------------------------------------------------------------
// Daemon lifecycle
// ---------------------------------------------------------------------------

/// Options for starting a daemon.
pub struct DaemonOptions {
    /// IP address to bind to. None = 127.0.0.1 for deterministic local tests.
    pub bind_ip: Option<String>,
    /// Specific port to bind to. None = random (127.0.0.1:0).
    pub bind_port: Option<u16>,
    /// Allow retrying on an ephemeral port if the requested bind port is busy.
    pub allow_ephemeral_bind_fallback: bool,
    /// Disable placeholder autodial via environment variable.
    pub disable_placeholder_autodial: bool,
    /// Disable mDNS discovery via environment variable.
    pub disable_discovery: bool,
    /// Inherit stdout/stderr for debugging (instead of suppressing).
    pub inherit_stdio: bool,
    /// Redirect stdout to a file path (takes precedence over inherit_stdio).
    pub stdout_file: Option<std::path::PathBuf>,
    /// Redirect stderr to a file path (takes precedence over inherit_stdio).
    pub stderr_file: Option<std::path::PathBuf>,
    /// Extra environment variables for the daemon process only.
    pub extra_env: Vec<(String, String)>,
}

impl Default for DaemonOptions {
    fn default() -> Self {
        Self {
            bind_ip: None,
            bind_port: None,
            allow_ephemeral_bind_fallback: true,
            disable_placeholder_autodial: false,
            disable_discovery: false,
            inherit_stdio: false,
            stdout_file: None,
            stderr_file: None,
            extra_env: Vec::new(),
        }
    }
}

fn default_daemon_log_path(db: &str, stream: &str) -> PathBuf {
    let db_path = PathBuf::from(db);
    let db_name = db_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("test.db");
    let sanitized = db_name.replace('.', "_");
    let pid = std::process::id();
    let instance_id = next_daemon_instance_id();
    std::env::temp_dir().join(format!("topo-{sanitized}-{pid}-{instance_id}.{stream}.log"))
}

fn read_daemon_log(path: &PathBuf) -> String {
    std::fs::read_to_string(path).unwrap_or_default()
}

fn tail_daemon_log(path: &PathBuf, max_lines: usize) -> String {
    let text = read_daemon_log(path);
    let mut lines: Vec<&str> = text.lines().collect();
    if lines.len() > max_lines {
        lines = lines.split_off(lines.len() - max_lines);
    }
    lines.join("\n")
}

fn daemon_debug_context(db: &str) -> String {
    let socket = socket_path_for_db(db);
    let (stdout_path, stderr_path) = daemon_log_registry()
        .lock()
        .unwrap()
        .get(db)
        .cloned()
        .unwrap_or_else(|| {
            // Fallback for callers that run after the daemon has already been dropped
            // (registry entry removed). Use a best-effort path without a counter.
            let db_name = PathBuf::from(db)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("test.db")
                .replace('.', "_");
            let pid = std::process::id();
            (
                std::env::temp_dir().join(format!("topo-{db_name}-{pid}.stdout.log")),
                std::env::temp_dir().join(format!("topo-{db_name}-{pid}.stderr.log")),
            )
        });
    format!(
        "daemon=\n  socket_exists={}\n  socket_path={}\n  stdout_log={}\n{}\n  stderr_log={}\n{}",
        socket.exists(),
        socket.display(),
        stdout_path.display(),
        tail_daemon_log(&stdout_path, 80),
        stderr_path.display(),
        tail_daemon_log(&stderr_path, 80)
    )
}

fn daemon_inherit_stdio_env() -> bool {
    std::env::var("TOPO_TEST_DAEMON_INHERIT_STDIO")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false)
}

fn daemon_debug_log_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("TOPO_TEST_DAEMON_LOG_DIR").map(std::path::PathBuf::from)
}

/// Start a daemon with default options (random port, suppressed I/O).
pub fn start_daemon(db: &str) -> HarnessDaemon {
    start_daemon_with_options(
        db,
        &DaemonOptions {
            disable_discovery: true,
            ..Default::default()
        },
    )
}

/// Start a daemon on a specific port with suppressed I/O.
pub fn start_daemon_on_port(db: &str, port: u16) -> HarnessDaemon {
    start_daemon_with_options(
        db,
        &DaemonOptions {
            bind_port: Some(port),
            disable_discovery: true,
            ..Default::default()
        },
    )
}

/// Start a daemon with mDNS discovery enabled.
pub fn start_discovery_daemon(db: &str) -> HarnessDaemon {
    start_daemon_with_options(
        db,
        &DaemonOptions {
            // Same-host discovery tests still browse/advertise over mDNS, but
            // binding the QUIC socket to loopback avoids environment-specific
            // wildcard-bind failures without changing the sync path under test.
            bind_ip: Some("127.0.0.1".to_string()),
            extra_env: vec![("TOPO_TEST_DISCOVERY_LOOPBACK".to_string(), "1".to_string())],
            ..Default::default()
        },
    )
}

/// Start a discovery-enabled daemon on a specific port.
pub fn start_discovery_daemon_on_port(db: &str, port: u16) -> HarnessDaemon {
    start_daemon_with_options(
        db,
        &DaemonOptions {
            bind_ip: Some("127.0.0.1".to_string()),
            bind_port: Some(port),
            extra_env: vec![("TOPO_TEST_DISCOVERY_LOOPBACK".to_string(), "1".to_string())],
            ..Default::default()
        },
    )
}

/// Start a daemon with full control over options.
pub fn start_daemon_with_options(db: &str, opts: &DaemonOptions) -> HarnessDaemon {
    hold_network_test_binary_lock();
    hold_network_test_thread_lock();
    let socket = socket_path_for_db(db);
    let bind_ip = opts.bind_ip.as_deref().unwrap_or("127.0.0.1");
    let requested_bind_addr = match opts.bind_port {
        Some(port) => format!("{bind_ip}:{port}"),
        None => format!("{bind_ip}:0"),
    };
    let mut retry_with_ephemeral_bind = false;

    for attempt in 0..DAEMON_START_MAX_ATTEMPTS {
        let bind_addr = if retry_with_ephemeral_bind {
            format!("{bind_ip}:0")
        } else {
            requested_bind_addr.clone()
        };
        let inherit_stdio = opts.inherit_stdio || daemon_inherit_stdio_env();
        let debug_log_base = daemon_debug_log_dir().map(|dir| {
            std::fs::create_dir_all(&dir).expect("create daemon debug log dir");
            let db_label = std::path::Path::new(db)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("daemon");
            dir.join(format!(
                "{}-pid{}-attempt{}",
                db_label,
                std::process::id(),
                attempt + 1
            ))
        });
        let stdout_path = opts
            .stdout_file
            .clone()
            .or_else(|| {
                debug_log_base
                    .as_ref()
                    .map(|base| base.with_extension("stdout.log"))
            })
            .unwrap_or_else(|| default_daemon_log_path(db, "stdout"));
        let stderr_path = opts
            .stderr_file
            .clone()
            .or_else(|| {
                debug_log_base
                    .as_ref()
                    .map(|base| base.with_extension("stderr.log"))
            })
            .unwrap_or_else(|| default_daemon_log_path(db, "stderr"));
        let mut cmd = Command::new(bin());
        cmd.arg("--db")
            .arg(db)
            .arg("start")
            .arg("--bind")
            .arg(&bind_addr);
        cmd.env_clear();
        for key in [
            "HOME",
            "TMPDIR",
            "XDG_RUNTIME_DIR",
            "PATH",
            "RUST_LOG",
            "RUST_BACKTRACE",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        ] {
            if let Some(value) = std::env::var_os(key) {
                cmd.env(key, value);
            }
        }

        if opts.disable_placeholder_autodial {
            cmd.env("TOPO_DISABLE_PLACEHOLDER_AUTODIAL", "1");
        }
        if opts.disable_discovery {
            cmd.env("TOPO_DISABLE_DISCOVERY", "1");
        } else {
            cmd.env_remove("TOPO_DISABLE_DISCOVERY");
        }
        for (key, value) in &opts.extra_env {
            cmd.env(key, value);
        }

        if inherit_stdio && opts.stdout_file.is_none() && debug_log_base.is_none() {
            cmd.stdout(Stdio::inherit());
        } else {
            let f = std::fs::File::create(&stdout_path).expect("create default stdout log file");
            cmd.stdout(f);
        }

        if inherit_stdio && opts.stderr_file.is_none() && debug_log_base.is_none() {
            cmd.stderr(Stdio::inherit());
        } else {
            let f = std::fs::File::create(&stderr_path).expect("create default stderr log file");
            cmd.stderr(f);
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
            wait_for_daemon_stopped(db, Duration::from_secs(2));
            if attempt + 1 < DAEMON_START_MAX_ATTEMPTS {
                retry_with_ephemeral_bind |=
                    opts.allow_ephemeral_bind_fallback && opts.bind_port.is_some();
                let backoff_ms =
                    DAEMON_START_RETRY_BASE_MS.saturating_mul((attempt as u64).saturating_add(1));
                std::thread::sleep(Duration::from_millis(backoff_ms));
                continue;
            }
            panic!(
                "daemon exited immediately with {} (db={})\nstdout:\n{}\nstderr:\n{}",
                status,
                db,
                read_daemon_log(&stdout_path),
                read_daemon_log(&stderr_path)
            );
        }

        if !socket.exists() {
            let _ = child.kill();
            let _ = child.wait();
            if socket.exists() {
                wait_for_daemon_stopped(db, Duration::from_secs(2));
            }
            if attempt + 1 < DAEMON_START_MAX_ATTEMPTS {
                retry_with_ephemeral_bind |=
                    opts.allow_ephemeral_bind_fallback && opts.bind_port.is_some();
                let backoff_ms =
                    DAEMON_START_RETRY_BASE_MS.saturating_mul((attempt as u64).saturating_add(1));
                std::thread::sleep(Duration::from_millis(backoff_ms));
                continue;
            }
            panic!(
                "daemon socket did not appear at {} within 5s (db={})\nstdout:\n{}\nstderr:\n{}",
                socket.display(),
                db,
                read_daemon_log(&stdout_path),
                read_daemon_log(&stderr_path)
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
                if let Some(status) = child.try_wait().expect("failed to check daemon status") {
                    wait_for_daemon_stopped(db, Duration::from_secs(2));
                    if attempt < 7 {
                        retry_with_ephemeral_bind |=
                            opts.allow_ephemeral_bind_fallback && opts.bind_port.is_some();
                        std::thread::sleep(Duration::from_millis(100));
                        break;
                    }
                    panic!(
                        "daemon child exited after readiness probe with {} (db={})\nstdout:\n{}\nstderr:\n{}",
                        status,
                        db,
                        read_daemon_log(&stdout_path),
                        read_daemon_log(&stderr_path)
                    );
                }
                daemon_log_registry()
                    .lock()
                    .unwrap()
                    .insert(db.to_string(), (stdout_path.clone(), stderr_path.clone()));
                return HarnessDaemon::new(child, db);
            }
            if rpc_start.elapsed().as_secs() >= 5 {
                let _ = child.kill();
                let _ = child.wait();
                wait_for_daemon_stopped(db, Duration::from_secs(2));
                if attempt < 7 {
                    retry_with_ephemeral_bind |=
                        opts.allow_ephemeral_bind_fallback && opts.bind_port.is_some();
                    std::thread::sleep(Duration::from_millis(100));
                    break;
                }
                panic!(
                    "daemon socket exists but RPC not responding after 5s (db={}): {}\nstdout:\n{}\nstderr:\n{}",
                    db,
                    String::from_utf8_lossy(&out.stderr),
                    read_daemon_log(&stdout_path),
                    read_daemon_log(&stderr_path)
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
        "daemon did not stop within {:?} (db={}, socket={})\n{}",
        timeout,
        db,
        socket.display(),
        daemon_debug_context(db)
    );
}

/// Trait for daemon handles that support a graceful stop operation.
pub trait StopDaemon {
    fn stop_with_db(&mut self, db: &str);
}

impl StopDaemon for HarnessDaemon {
    fn stop_with_db(&mut self, _db: &str) {
        self.stop();
    }
}

impl StopDaemon for DaemonGuard {
    fn stop_with_db(&mut self, db: &str) {
        let _ = Command::new(bin()).args(["--db", db, "stop"]).output();
        let start = Instant::now();
        loop {
            match self.child().try_wait() {
                Ok(Some(_)) => {
                    wait_for_daemon_stopped(db, Duration::from_secs(5));
                    self.clear();
                    return;
                }
                Ok(None) => {
                    if start.elapsed().as_secs() >= 5 {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => break,
            }
        }
        if let Some(mut child) = self.take() {
            let _ = child.kill();
            let _ = child.wait();
            wait_for_daemon_stopped(db, Duration::from_secs(5));
        }
    }
}

/// Send stop command and wait for the daemon process to exit.
pub fn stop_daemon<D: StopDaemon>(db: &str, daemon: &mut D) {
    daemon.stop_with_db(db);
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

fn try_status_via_rpc_for_db(db: &str) -> Result<serde_json::Value, String> {
    let socket = socket_path_for_db(db);
    let resp = topo::rpc::client::rpc_call(&socket, topo::rpc::protocol::RpcMethod::Status)
        .map_err(|err| err.to_string())?;
    if !resp.ok {
        return Err(resp
            .error
            .unwrap_or_else(|| "status RPC returned error".to_string()));
    }
    resp.data
        .ok_or_else(|| "status response missing data".to_string())
}

fn status_tenant_count(data: &serde_json::Value) -> usize {
    data.get("tenants")
        .and_then(|tenants| tenants.as_array())
        .map(|tenants| tenants.len())
        .unwrap_or(0)
}

pub fn wait_for_tenant_count(db: &str, min_count: usize, timeout: Duration) -> serde_json::Value {
    let result = assert_value_eventually(
        timeout,
        Duration::from_millis(100),
        &format!("tenant count >= {min_count}"),
        || try_status_via_rpc_for_db(db),
        |result| match result {
            Ok(data) => status_tenant_count(data) >= min_count,
            Err(_) => false,
        },
    );
    match result {
        Ok(data) => data,
        Err(err) => panic!("status RPC did not become available for {}: {}", db, err),
    }
}

pub fn wait_for_active_tenant_ready(db: &str, timeout: Duration) -> serde_json::Value {
    match wait_for_active_tenant_ready_debug(db, timeout) {
        Ok(()) => try_status_via_rpc_for_db(db)
            .unwrap_or_else(|err| panic!("status RPC unavailable for {} after ready: {}", db, err)),
        Err(err) => panic!(
            "timed out waiting for active tenant ready after {:?}; last value: {}\n{}\n{}",
            timeout,
            err,
            assert_eventually_debug_context(db),
            daemon_debug_context(db)
        ),
    }
}

pub fn wait_for_active_tenant_transport_converged(db: &str, timeout: Duration) {
    match wait_for_active_tenant_transport_converged_debug(db, timeout) {
        Ok(()) => {}
        Err(err) => panic!(
            "timed out waiting for active tenant transport convergence after {:?}; last value: {}\n{}\n{}",
            timeout,
            err,
            assert_eventually_debug_context(db),
            daemon_debug_context(db)
        ),
    }
}

pub fn wait_for_tenant_transport_converged(db: &str, tenant_peer_id: &str, timeout: Duration) {
    match wait_for_tenant_transport_converged_debug(db, tenant_peer_id, timeout) {
        Ok(()) => {}
        Err(err) => panic!(
            "timed out waiting for tenant {} transport convergence after {:?}; last value: {}\n{}\n{}",
            tenant_peer_id,
            timeout,
            err,
            assert_eventually_debug_context(db),
            daemon_debug_context(db)
        ),
    }
}

pub fn wait_for_active_tenant_bootstrap_ready(db: &str, timeout: Duration) {
    match wait_for_active_tenant_bootstrap_ready_debug(db, timeout) {
        Ok(()) => {}
        Err(err) => panic!(
            "timed out waiting for active tenant bootstrap readiness after {:?}; last value: {}\n{}\n{}",
            timeout,
            err,
            assert_eventually_debug_context(db),
            daemon_debug_context(db)
        ),
    }
}

pub fn wait_for_tenant_bootstrap_ready(db: &str, tenant_peer_id: &str, timeout: Duration) {
    match wait_for_tenant_bootstrap_ready_debug(db, tenant_peer_id, timeout) {
        Ok(()) => {}
        Err(err) => panic!(
            "timed out waiting for tenant {} bootstrap readiness after {:?}; last value: {}\n{}\n{}",
            tenant_peer_id,
            timeout,
            err,
            assert_eventually_debug_context(db),
            daemon_debug_context(db)
        ),
    }
}

pub fn wait_for_tenant_ready_by_username(
    db: &str,
    username: &str,
    timeout: Duration,
) -> serde_json::Value {
    let result = assert_value_eventually(
        timeout,
        Duration::from_millis(100),
        &format!("tenant `{username}` ready"),
        || try_status_via_rpc_for_db(db),
        |result| match result {
            Ok(data) => data["tenants"]
                .as_array()
                .map(|tenants| {
                    tenants.iter().any(|tenant| {
                        tenant["username"].as_str() == Some(username)
                            && tenant["ready"].as_bool().unwrap_or(false)
                    })
                })
                .unwrap_or(false),
            Err(_) => false,
        },
    );
    match result {
        Ok(data) => data,
        Err(err) => panic!("status RPC did not become available for {}: {}", db, err),
    }
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
    let listen_addr = data
        .get("runtime")
        .and_then(|r| r.get("listen_addr"))
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .expect("status response missing runtime.listen_addr");
    listen_addr
        .parse::<std::net::SocketAddr>()
        .map(|addr| {
            if addr.ip().is_unspecified() {
                std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, addr.port())).to_string()
            } else {
                addr.to_string()
            }
        })
        .unwrap_or(listen_addr)
}

/// Resolve the active tenant transport fingerprint used for steady-state peer
/// observations, falling back to the daemon bootstrap identity when no tenant
/// is active yet.
pub fn daemon_transport_fingerprint(db: &str) -> String {
    if let Some(peer_id) = active_tenant_peer_id(db) {
        return peer_id;
    }
    daemon_identity_fingerprint(db)
}

/// Get the daemon identity fingerprint used for bootstrap invite SPKI.
pub fn daemon_identity_fingerprint(db: &str) -> String {
    let (peer_id, _cert_der, _key_der) = topo::transport::ensure_daemon_identity_from_db(db)
        .expect("load daemon transport identity");
    peer_id
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
    create_workspace_with_seeded_history(db, workspace_name, username, device_name, 0, None, 0);
}

pub fn create_workspace_with_seeded_history(
    db: &str,
    workspace_name: &str,
    username: &str,
    device_name: &str,
    message_count: usize,
    network_age: Option<&str>,
    device_chain_length: usize,
) {
    let mut tmp_daemon = start_daemon(db);
    let mut args = vec![
        "create-workspace".to_string(),
        "--db".to_string(),
        db.to_string(),
        "--workspace-name".to_string(),
        workspace_name.to_string(),
        "--username".to_string(),
        username.to_string(),
        "--device-name".to_string(),
        device_name.to_string(),
    ];
    if message_count > 0 {
        args.push("--message-count".to_string());
        args.push(message_count.to_string());
    }
    if let Some(network_age) = network_age {
        args.push("--network-age".to_string());
        args.push(network_age.to_string());
    }
    if device_chain_length > 0 {
        args.push("--device-chain-length".to_string());
        args.push(device_chain_length.to_string());
    }
    let out = Command::new(bin())
        .env("TOPO_RPC_READ_TIMEOUT_SECS", "600")
        .env("TOPO_RPC_WRITE_TIMEOUT_SECS", "120")
        .args(&args)
        .output()
        .expect("create-workspace");
    assert!(
        out.status.success(),
        "create-workspace failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Wait until tenant discovery sees at least one peer before proceeding.
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
    stop_daemon(db, &mut tmp_daemon);
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
        "failed to establish active tenant within {:?} (db={}): active={}, tenants={}, tenant-use-error={}\n{}",
        timeout,
        db,
        last_active,
        last_peers.replace('\n', " | "),
        last_use_peer_err,
        daemon_debug_context(db)
    );
}

pub fn active_tenant_peer_id(db: &str) -> Option<String> {
    let active = Command::new(bin())
        .args(["--db", db, "tenant", "active"])
        .output()
        .ok()?;
    if !active.status.success() {
        return None;
    }
    let active_stdout = String::from_utf8_lossy(&active.stdout).trim().to_string();
    if active_stdout.is_empty() || active_stdout == "(no active tenant)" {
        None
    } else {
        Some(active_stdout)
    }
}

/// Wait until `sync request all` sees at least one live session.
pub fn wait_for_live_sync_session(db: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let out = Command::new(bin())
            .args(["--db", db, "sync", "request", "all"])
            .output()
            .expect("failed to run sync request all");
        if out.status.success() {
            let stdout = String::from_utf8_lossy(&out.stdout);
            if !stdout.contains("(no live sessions)") && !stdout.contains("(no peers)") {
                return;
            }
        }
        if Instant::now() >= deadline {
            panic!(
                "live sync session never became available within {:?} (db={})\nstdout: {}\nstderr: {}\n{}",
                timeout,
                db,
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
                daemon_debug_context(db)
            );
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Send a message via daemon RPC, retrying transient errors.
pub fn send_message(db: &str, content: &str) -> String {
    let send_timeout = Duration::from_secs(60);
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
        if retryable && start.elapsed() < send_timeout {
            if stderr.contains("no active tenant") {
                ensure_active_peer(db, Duration::from_secs(5));
            }
            if stderr.contains("workspace has not completed initial sync yet") {
                let remaining = send_timeout.saturating_sub(start.elapsed());
                let wait_for = remaining.min(Duration::from_secs(5));
                let _ = wait_for_active_tenant_ready_debug(db, wait_for);
            }
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        let readiness_debug = if stderr.contains("workspace has not completed initial sync yet") {
            wait_for_active_tenant_ready_debug(db, Duration::from_secs(1))
                .err()
                .map(|debug| format!(" ({debug})"))
                .unwrap_or_default()
        } else {
            String::new()
        };
        panic!("send failed for db={}: {}{}", db, stderr, readiness_debug);
    }
}

pub fn rotate_key(db: &str) -> (String, u64) {
    ensure_active_peer(db, Duration::from_secs(10));
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("rotate-key")
        .output()
        .expect("failed to run rotate-key");
    assert!(
        output.status.success(),
        "rotate-key failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let rotation_event_id = stdout
        .lines()
        .find_map(|line| line.strip_prefix("rotation_event_id:"))
        .expect("rotate-key output missing rotation_event_id")
        .to_string();
    let proactive_shares = stdout
        .lines()
        .find_map(|line| line.strip_prefix("proactive_shares:"))
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0);
    (rotation_event_id, proactive_shares)
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
    accept_invite_with_identity_and_timeout(
        db,
        invite_link,
        username,
        devicename,
        Duration::from_secs(10),
    );
}

pub fn accept_invite_with_identity_persisted_only(
    db: &str,
    invite_link: &str,
    username: &str,
    devicename: &str,
    accept_timeout: Duration,
) {
    accept_invite_with_identity_inner(db, invite_link, username, devicename, accept_timeout, false);
}

pub fn accept_invite_with_identity_and_timeout(
    db: &str,
    invite_link: &str,
    username: &str,
    devicename: &str,
    accept_timeout: Duration,
) {
    accept_invite_with_identity_inner(db, invite_link, username, devicename, accept_timeout, true);
}

fn accept_invite_with_identity_inner(
    db: &str,
    invite_link: &str,
    username: &str,
    devicename: &str,
    accept_timeout: Duration,
    wait_for_transport_convergence: bool,
) {
    let mut tmp_daemon = start_daemon(db);
    accept_invite_with_identity_on_running_daemon(
        db,
        invite_link,
        username,
        devicename,
        accept_timeout,
    );
    if wait_for_transport_convergence {
        let accepted_peer_id = active_tenant_peer_id(db)
            .expect("accepted invite should set the new tenant active on the running daemon");
        wait_for_tenant_transport_converged(db, &accepted_peer_id, accept_timeout);
    }
    // Stop temporary daemon; callers decide daemon lifecycle.
    stop_daemon(db, &mut tmp_daemon);
    wait_for_daemon_stopped(db, Duration::from_secs(10));
}

pub fn accept_invite_with_identity_on_running_daemon(
    db: &str,
    invite_link: &str,
    username: &str,
    devicename: &str,
    accept_timeout: Duration,
) {
    let before_count = try_status_via_rpc_for_db(db)
        .ok()
        .map(|data| status_tenant_count(&data))
        .unwrap_or(0);
    let output = run_cli_with_db_lock_retry(
        &[
            "accept",
            "--db",
            db,
            invite_link,
            "--username",
            username,
            "--devicename",
            devicename,
        ],
        "accept",
        Duration::from_secs(10),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "accept failed:\n  stdout: {}\n  stderr: {}",
        stdout.trim(),
        stderr.trim()
    );
    wait_for_tenant_count(db, before_count.saturating_add(1), accept_timeout);
}

/// Accept a device-link invite via daemon RPC using a temporary daemon.
pub fn accept_device_link(db: &str, invite_link: &str) {
    accept_device_link_with_name(db, invite_link, "device")
}

/// Accept a device-link invite with a custom device name.
pub fn accept_device_link_with_name(db: &str, invite_link: &str, devicename: &str) {
    accept_device_link_with_name_and_timeout(db, invite_link, devicename, Duration::from_secs(10));
}

pub fn accept_device_link_with_name_and_timeout(
    db: &str,
    invite_link: &str,
    devicename: &str,
    accept_timeout: Duration,
) {
    let mut tmp_daemon = start_daemon(db);
    accept_device_link_with_name_on_running_daemon(db, invite_link, devicename, accept_timeout);
    let accepted_peer_id = active_tenant_peer_id(db)
        .expect("accepted device link should set the new tenant active on the running daemon");
    wait_for_tenant_transport_converged(db, &accepted_peer_id, accept_timeout);
    stop_daemon(db, &mut tmp_daemon);
    wait_for_daemon_stopped(db, Duration::from_secs(10));
}

pub fn accept_device_link_with_name_on_running_daemon(
    db: &str,
    invite_link: &str,
    devicename: &str,
    accept_timeout: Duration,
) {
    let before_count = try_status_via_rpc_for_db(db)
        .ok()
        .map(|data| status_tenant_count(&data))
        .unwrap_or(0);
    let output = run_cli_with_db_lock_retry(
        &[
            "accept-link",
            "--db",
            db,
            invite_link,
            "--devicename",
            devicename,
        ],
        "accept-link",
        Duration::from_secs(10),
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "accept-link failed:\n  stdout: {}\n  stderr: {}",
        stdout.trim(),
        stderr.trim()
    );
    wait_for_tenant_count(db, before_count.saturating_add(1), accept_timeout);
}

fn wait_for_active_tenant_ready_debug(db: &str, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    let mut last = String::from("status unavailable");
    while start.elapsed() < timeout {
        match try_status_via_rpc_for_db(db) {
            Ok(data) => {
                if data["tenants"]
                    .as_array()
                    .map(|tenants| {
                        tenants.iter().any(|tenant| {
                            tenant["active"].as_bool().unwrap_or(false)
                                && tenant["ready"].as_bool().unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
                {
                    return Ok(());
                }
                last = data.to_string();
            }
            Err(err) => {
                last = err;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(last)
}

fn wait_for_active_tenant_transport_converged_debug(
    db: &str,
    timeout: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    let mut last = String::from("status unavailable");
    while start.elapsed() < timeout {
        let status = try_status_via_rpc_for_db(db);
        let active_peer_id = status
            .as_ref()
            .ok()
            .and_then(|data| {
                data["tenants"].as_array().and_then(|tenants| {
                    tenants.iter().find_map(|tenant| {
                        tenant["active"]
                            .as_bool()
                            .unwrap_or(false)
                            .then(|| tenant["peer_id"].as_str().map(str::to_string))
                            .flatten()
                    })
                })
            })
            .or_else(|| {
                let conn = topo::db::open_connection(db).ok()?;
                topo::db::transport_creds::discover_local_tenants(&conn)
                    .ok()?
                    .into_iter()
                    .next()
                    .map(|tenant| tenant.peer_id)
            });

        match active_peer_id {
            Some(active_peer_id) => {
                match wait_for_tenant_transport_converged_debug(
                    db,
                    &active_peer_id,
                    Duration::from_millis(1),
                ) {
                    Ok(()) => return Ok(()),
                    Err(err) => {
                        last = err;
                    }
                }
            }
            None => {
                last = status
                    .map(|data| data.to_string())
                    .unwrap_or_else(|err| err);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(last)
}

fn wait_for_tenant_transport_converged_debug(
    db: &str,
    tenant_peer_id: &str,
    timeout: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    let mut last = String::from("transport target unavailable");
    while start.elapsed() < timeout {
        match topo::db::open_connection(db).ok().and_then(|conn| {
            topo::db::transport_creds::resolve_tenant_transport_target(&conn, tenant_peer_id)
                .ok()
                .flatten()
        }) {
            Some(target) if target.transport_peer_id == tenant_peer_id => return Ok(()),
            Some(target) => {
                last = format!(
                    "tenant_peer_id={} transport_peer_id={} source={}",
                    tenant_peer_id, target.transport_peer_id, target.source
                );
            }
            None => {
                last = format!(
                    "tenant_peer_id={} transport target unavailable",
                    tenant_peer_id
                );
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(last)
}

fn wait_for_active_tenant_bootstrap_ready_debug(db: &str, timeout: Duration) -> Result<(), String> {
    let start = Instant::now();
    let mut last = String::from("status unavailable");
    while start.elapsed() < timeout {
        let active_peer_id = active_tenant_peer_id(db).or_else(|| {
            let conn = topo::db::open_connection(db).ok()?;
            topo::db::transport_creds::discover_local_tenants(&conn)
                .ok()?
                .into_iter()
                .next()
                .map(|tenant| tenant.peer_id)
        });

        if let Some(active_peer_id) = active_peer_id {
            match wait_for_tenant_bootstrap_ready_debug(
                db,
                &active_peer_id,
                Duration::from_millis(1),
            ) {
                Ok(()) => return Ok(()),
                Err(err) => last = err,
            }
        } else {
            last = String::from("no active tenant");
        }

        std::thread::sleep(Duration::from_millis(100));
    }
    Err(last)
}

fn wait_for_tenant_bootstrap_ready_debug(
    db: &str,
    tenant_peer_id: &str,
    timeout: Duration,
) -> Result<(), String> {
    let start = Instant::now();
    let mut last = String::from("status unavailable");
    while start.elapsed() < timeout {
        if let Ok(conn) = topo::db::open_connection(db) {
            let transport_target =
                topo::db::transport_creds::resolve_tenant_transport_target(&conn, tenant_peer_id)
                    .ok()
                    .flatten();
            let converged = transport_target
                .as_ref()
                .map(|target| {
                    target.transport_peer_id == tenant_peer_id
                        && target.source == topo::db::transport_creds::CRED_SOURCE_PEER_SHARED
                })
                .unwrap_or(false);
            if converged {
                return Ok(());
            }

            let bootstrap_targets =
                topo::db::transport_trust::list_active_invite_bootstrap_targets(
                    &conn,
                    tenant_peer_id,
                )
                .map(|targets| targets.len())
                .unwrap_or(0);
            if bootstrap_targets > 0 {
                return Ok(());
            }

            last = format!(
                "tenant_peer_id={} bootstrap_targets={} transport_target={:?}",
                tenant_peer_id,
                bootstrap_targets,
                transport_target.map(|target| (target.transport_peer_id, target.source))
            );
        } else {
            last = format!("tenant_peer_id={} db unavailable", tenant_peer_id);
        }

        std::thread::sleep(Duration::from_millis(100));
    }
    Err(last)
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

fn assert_eventually_debug_context(db: &str) -> String {
    fn run(db: &str, args: &[&str]) -> String {
        let output = Command::new(bin())
            .arg("--db")
            .arg(db)
            .args(args)
            .output()
            .ok();
        match output {
            Some(output) if output.status.success() => {
                String::from_utf8_lossy(&output.stdout).trim().to_string()
            }
            Some(output) => format!(
                "ERR: {}",
                String::from_utf8_lossy(&output.stderr).trim().to_string()
            ),
            None => "ERR: command failed to spawn".to_string(),
        }
    }

    fn db_debug(db: &str) -> String {
        let Ok(conn) = topo::db::open_connection(db) else {
            return "db=ERR: open failed".to_string();
        };
        let active_peer_id = run(db, &["tenant", "active"]);
        let active_peer_id = if active_peer_id.is_empty() || active_peer_id == "(no active tenant)"
        {
            conn.query_row(
                "SELECT recorded_by
                 FROM invites_accepted
                 ORDER BY created_at DESC, event_id DESC
                 LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .ok()
        } else {
            Some(active_peer_id)
        };

        let local_transport_creds: i64 = conn
            .query_row("SELECT COUNT(*) FROM local_transport_creds", [], |row| {
                row.get(0)
            })
            .unwrap_or(0);
        let blocked_events: i64 = active_peer_id
            .as_ref()
            .and_then(|peer_id| {
                conn.query_row(
                    "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1",
                    rusqlite::params![peer_id],
                    |row| row.get(0),
                )
                .ok()
            })
            .unwrap_or(0);
        let pending_bootstrap_trust: i64 = active_peer_id
            .as_ref()
            .and_then(|peer_id| {
                conn.query_row(
                    "SELECT COUNT(*) FROM pending_invite_bootstrap_trust WHERE recorded_by = ?1",
                    rusqlite::params![peer_id],
                    |row| row.get(0),
                )
                .ok()
            })
            .unwrap_or(0);
        let bootstrap_context_rows: i64 = active_peer_id
            .as_ref()
            .and_then(|peer_id| {
                conn.query_row(
                    "SELECT COUNT(*) FROM bootstrap_context WHERE recorded_by = ?1",
                    rusqlite::params![peer_id],
                    |row| row.get(0),
                )
                .ok()
            })
            .unwrap_or(0);
        let endpoint_observations: i64 = active_peer_id
            .as_ref()
            .and_then(|peer_id| {
                conn.query_row(
                    "SELECT COUNT(*) FROM peer_endpoint_observations WHERE recorded_by = ?1",
                    rusqlite::params![peer_id],
                    |row| row.get(0),
                )
                .ok()
            })
            .unwrap_or(0);
        let latest_endpoints: Vec<String> = active_peer_id
            .as_ref()
            .and_then(|peer_id| {
                let mut stmt = conn
                    .prepare(
                        "SELECT via_peer_id, origin_ip, origin_port
                         FROM peer_endpoint_observations
                         WHERE recorded_by = ?1
                         ORDER BY observed_at DESC
                         LIMIT 3",
                    )
                    .ok()?;
                let rows = stmt
                    .query_map(rusqlite::params![peer_id], |row| {
                        Ok(format!(
                            "{}@{}:{}",
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                        ))
                    })
                    .ok()?;
                Some(rows.filter_map(Result::ok).collect())
            })
            .unwrap_or_default();
        let blocked_details: Vec<String> = active_peer_id
            .as_ref()
            .and_then(|peer_id| {
                let mut stmt = conn
                    .prepare(
                        "SELECT d.event_id, d.blocker_event_id
                         FROM blocked_event_deps d
                         WHERE d.peer_id = ?1
                         ORDER BY d.rowid
                         LIMIT 8",
                    )
                    .ok()?;
                let rows = stmt
                    .query_map(rusqlite::params![peer_id], |row| {
                        let event_id: String = row.get(0)?;
                        let blocker_id: String = row.get(1)?;
                        Ok((event_id, blocker_id))
                    })
                    .ok()?;
                Some(
                    rows.filter_map(Result::ok)
                        .map(|(event_id, blocker_id)| {
                            let event_type = conn
                                .query_row(
                                    "SELECT event_type FROM events WHERE event_id = ?1",
                                    rusqlite::params![&event_id],
                                    |row| row.get::<_, String>(0),
                                )
                                .unwrap_or_else(|_| "<missing>".to_string());
                            let blocker_type = conn
                                .query_row(
                                    "SELECT event_type FROM events WHERE event_id = ?1",
                                    rusqlite::params![&blocker_id],
                                    |row| row.get::<_, String>(0),
                                )
                                .unwrap_or_else(|_| "<missing>".to_string());
                            let blocker_recorded = conn
                                .query_row(
                                    "SELECT COUNT(*) > 0 FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
                                    rusqlite::params![peer_id, &blocker_id],
                                    |row| row.get::<_, bool>(0),
                                )
                                .unwrap_or(false);
                            let blocker_valid = conn
                                .query_row(
                                    "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                                    rusqlite::params![peer_id, &blocker_id],
                                    |row| row.get::<_, bool>(0),
                                )
                                .unwrap_or(false);
                            let blocker_blocked = conn
                                .query_row(
                                    "SELECT COUNT(*) > 0 FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
                                    rusqlite::params![peer_id, &blocker_id],
                                    |row| row.get::<_, bool>(0),
                                )
                                .unwrap_or(false);
                            format!(
                                "{} ({}) <- {} [type={}, recorded={}, valid={}, blocked={}]",
                                event_id,
                                event_type,
                                blocker_id,
                                blocker_type,
                                blocker_recorded,
                                blocker_valid,
                                blocker_blocked
                            )
                        })
                        .collect(),
                )
            })
            .unwrap_or_default();

        format!(
            "db=\n  active_peer={}\n  local_transport_creds={}\n  blocked_events={}\n  blocked_details={:?}\n  pending_bootstrap_trust={}\n  bootstrap_context_rows={}\n  endpoint_observations={}\n  latest_endpoints={:?}",
            active_peer_id.unwrap_or_else(|| "<none>".to_string()),
            local_transport_creds,
            blocked_events,
            blocked_details,
            pending_bootstrap_trust,
            bootstrap_context_rows,
            endpoint_observations,
            latest_endpoints
        )
    }

    format!(
        "active={}\ntenants=\n{}\nusers=\n{}\nmessages=\n{}\nstatus=\n{}\n{}",
        run(db, &["tenant", "active"]),
        run(db, &["tenant", "list"]),
        run(db, &["users"]),
        run(db, &["messages"]),
        run(db, &["status"]),
        db_debug(db),
    )
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
    let debug = assert_eventually_debug_context(db);
    assert!(
        output.status.success(),
        "assert-eventually timed out: {} ({})\n{}\n{}",
        predicate,
        text.trim(),
        debug,
        daemon_debug_context(db)
    );
}

pub fn assert_value_eventually<T, F, P>(
    timeout: Duration,
    interval: Duration,
    description: &str,
    mut fetch: F,
    predicate: P,
) -> T
where
    T: std::fmt::Debug,
    F: FnMut() -> T,
    P: Fn(&T) -> bool,
{
    let start = Instant::now();
    loop {
        let value = fetch();
        if predicate(&value) {
            return value;
        }
        assert!(
            start.elapsed() < timeout,
            "timed out waiting for {} after {:?}; last value: {:?}",
            description,
            timeout,
            value
        );
        std::thread::sleep(interval);
    }
}

pub fn assert_condition_holds_for<F>(
    duration: Duration,
    interval: Duration,
    description: &str,
    mut predicate: F,
) where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + duration;
    loop {
        assert!(
            predicate(),
            "condition stopped holding before {:?}: {}",
            duration,
            description
        );
        if Instant::now() >= deadline {
            return;
        }
        std::thread::sleep(interval);
    }
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

pub fn get_content_keys_raw(db: &str) -> String {
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("content-keys")
        .output()
        .expect("failed to run content-keys");
    String::from_utf8_lossy(&output.stdout).to_string()
}

pub fn get_content_key_ids(db: &str) -> Vec<String> {
    let text = get_content_keys_raw(db);
    text.lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("key ")
                .map(|value| value.to_string())
        })
        .collect()
}

/// Get raw `topo files` output.
pub fn get_files_raw(db: &str) -> String {
    let output = Command::new(bin())
        .arg("--db")
        .arg(db)
        .arg("files")
        .output()
        .expect("failed to run files");
    assert!(
        output.status.success(),
        "files failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).to_string()
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
        "tenant use failed: stdout={} stderr={}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
        daemon_debug_context(db)
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

pub fn wait_for_endpoint_observation(db_path: &str, remote_peer_id: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_millis() as i64;
        let conn = topo::db::open_connection(db_path).expect("open db");
        let pending_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM pending_invite_bootstrap_trust",
                [],
                |row| row.get(0),
            )
            .expect("count pending_invite_bootstrap_trust");
        let observed_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*)
                 FROM peer_endpoint_observations
                 WHERE via_peer_id = ?1
                   AND expires_at > ?2",
                rusqlite::params![remote_peer_id, now_ms],
                |row| row.get(0),
            )
            .expect("count peer_endpoint_observations");
        let transport_identity_materialized =
            topo::db::transport_creds::discover_local_tenants(&conn)
                .map(|tenants| {
                    tenants.len() == 1 && tenants[0].transport_peer_id == tenants[0].peer_id
                })
                .unwrap_or(false);
        drop(conn);

        if transport_identity_materialized && pending_rows == 0 && observed_rows > 0 {
            return;
        }

        assert!(
            Instant::now() < deadline,
            "bootstrap materialization + endpoint observation did not converge for peer {} in {}ms",
            remote_peer_id,
            timeout.as_millis()
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn wait_for_pending_bootstrap_trust_cleared_and_endpoint_observation(
    db_path: &str,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_millis() as i64;
        let conn = topo::db::open_connection(db_path).expect("open db");
        let active_peer_id: Option<String> =
            topo::db::transport_creds::discover_local_tenants(&conn)
                .ok()
                .and_then(|mut tenants| {
                    if tenants.len() == 1 {
                        Some(tenants.remove(0).peer_id)
                    } else {
                        None
                    }
                });
        let pending_rows: i64 = active_peer_id
            .as_ref()
            .and_then(|peer_id| {
                conn.query_row(
                    "SELECT COUNT(*) FROM pending_invite_bootstrap_trust WHERE recorded_by = ?1",
                    rusqlite::params![peer_id],
                    |row| row.get(0),
                )
                .ok()
            })
            .unwrap_or(i64::MAX);
        let observed_rows: i64 = active_peer_id
            .as_ref()
            .and_then(|peer_id| {
                conn.query_row(
                    "SELECT COUNT(*)
                     FROM peer_endpoint_observations
                     WHERE recorded_by = ?1
                       AND expires_at > ?2",
                    rusqlite::params![peer_id, now_ms],
                    |row| row.get(0),
                )
                .ok()
            })
            .unwrap_or(0);
        drop(conn);

        if pending_rows == 0 && observed_rows > 0 {
            return;
        }

        assert!(
            Instant::now() < deadline,
            "pending bootstrap trust + endpoint observation did not converge in {}ms for {} (active_peer_id={:?}, pending_rows={}, observed_rows={})",
            timeout.as_millis(),
            db_path,
            active_peer_id,
            pending_rows,
            observed_rows
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn generate_messages(db: &str, count: usize) {
    ensure_active_peer(db, Duration::from_secs(10));
    let peer_id = active_tenant_peer_id(db).expect("active tenant peer id");
    let chunk_size = std::env::var("TOPO_TEST_GENERATE_CHUNK_SIZE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(100_000);
    let mut remaining = count;
    while remaining > 0 {
        let next = remaining.min(chunk_size);
        topo::event_modules::message::commands::generate_for_peer(db, &peer_id, next, None)
            .expect("generate synthetic messages");
        remaining -= next;
    }
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
        if stderr.contains("workspace has not completed initial sync yet") {
            let remaining = timeout.saturating_sub(start.elapsed());
            let wait_for = remaining.min(Duration::from_secs(5));
            let _ = wait_for_active_tenant_ready_debug(db, wait_for);
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

/// Accept an invite via a temporary daemon and persist the resulting tenant.
/// Realism tests use this when acceptance happens before the long-lived daemon
/// starts; writability is asserted later through normal runtime behavior.
pub fn accept_invite_lightweight(db: &str, invite_link: &str) {
    let mut tmp_daemon = start_discovery_daemon(db);
    accept_invite_with_identity_on_running_daemon(
        db,
        invite_link,
        "user",
        "device",
        Duration::from_secs(10),
    );
    stop_daemon(db, &mut tmp_daemon);
    wait_for_daemon_stopped(db, Duration::from_secs(10));
}

/// Send a file via daemon RPC. Returns the event ID.
pub fn send_file(db: &str, content: &str, file_path: &str) -> String {
    let send_timeout = Duration::from_secs(60);
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
        if retryable && start.elapsed() < send_timeout {
            if stderr.contains("no active tenant") {
                ensure_active_peer(db, Duration::from_secs(5));
            }
            if stderr.contains("workspace has not completed initial sync yet") {
                ensure_active_peer(db, Duration::from_secs(5));
            }
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        let readiness_debug = if stderr.contains("workspace has not completed initial sync yet") {
            wait_for_active_tenant_ready_debug(db, Duration::from_secs(1))
                .err()
                .map(|debug| format!(" ({debug})"))
                .unwrap_or_default()
        } else {
            String::new()
        };
        panic!(
            "send-file failed for db={}: {}{}",
            db, stderr, readiness_debug
        );
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

pub fn save_file_eventually(db: &str, file_target: &str, output_path: &str, timeout: Duration) {
    let start = Instant::now();
    loop {
        let output = save_file(db, file_target, output_path);
        if output.status.success() {
            return;
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let retryable =
            stderr.contains("file incomplete") || stderr.contains("invalid file number");
        assert!(
            retryable && start.elapsed() < timeout,
            "save-file failed before {:?}: {}",
            timeout,
            stderr.trim()
        );
        std::thread::sleep(Duration::from_millis(200));
    }
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

// ---------------------------------------------------------------------------
// Setup helpers to DRY two-peer / single-peer boilerplate
// ---------------------------------------------------------------------------

/// Two-peer workspace with identity convergence confirmed.
/// Returns (alice_db, bob_db, alice_daemon, bob_daemon).
pub fn setup_two_peers(
    tmpdir: &tempfile::TempDir,
) -> (String, String, HarnessDaemon, HarnessDaemon) {
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    create_workspace(&alice_db);
    let alice = start_daemon(&alice_db);
    wait_for_daemon_ready(&alice_db, std::time::Duration::from_secs(10));
    let alice_addr = daemon_listen_addr(&alice_db);
    let invite = create_invite(&alice_db, &alice_addr);

    accept_invite(&bob_db, &invite);
    let bob = start_daemon(&bob_db);
    wait_for_daemon_ready(&bob_db, std::time::Duration::from_secs(10));

    assert_eventually(&alice_db, "peer_count == 2", 60000);
    assert_eventually(&bob_db, "peer_count == 2", 60000);

    (alice_db, bob_db, alice, bob)
}

/// Single-peer workspace with daemon running.
/// Returns (db_path, daemon).
pub fn setup_single_peer(tmpdir: &tempfile::TempDir, name: &str) -> (String, HarnessDaemon) {
    let db = tmpdir
        .path()
        .join(format!("{}.db", name))
        .to_str()
        .unwrap()
        .to_string();
    create_workspace(&db);
    let daemon = start_daemon(&db);
    wait_for_daemon_ready(&db, std::time::Duration::from_secs(10));
    (db, daemon)
}

// ---------------------------------------------------------------------------
// Subscription CLI helpers
// ---------------------------------------------------------------------------

/// Create a subscription with default options.
pub fn sub_create(db: &str, name: &str, event_type: &str) {
    let out = Command::new(bin())
        .args([
            "--db",
            db,
            "sub",
            "create",
            "--name",
            name,
            "--event-type",
            event_type,
        ])
        .output()
        .expect("sub create failed");
    assert!(
        out.status.success(),
        "sub create {} failed: {}",
        name,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Create a subscription with delivery mode.
pub fn sub_create_with_delivery(db: &str, name: &str, event_type: &str, delivery: &str) {
    let out = Command::new(bin())
        .args([
            "--db",
            db,
            "sub",
            "create",
            "--name",
            name,
            "--event-type",
            event_type,
            "--delivery",
            delivery,
        ])
        .output()
        .expect("sub create failed");
    assert!(
        out.status.success(),
        "sub create {} (delivery={}) failed: {}",
        name,
        delivery,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Ack a subscription through a given seq number.
pub fn sub_ack(db: &str, name: &str, through_seq: u64) {
    let out = Command::new(bin())
        .args([
            "--db",
            db,
            "sub",
            "ack",
            name,
            "--through-seq",
            &through_seq.to_string(),
        ])
        .output()
        .expect("sub ack failed");
    assert!(
        out.status.success(),
        "sub ack {} through {} failed: {}",
        name,
        through_seq,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Get subscription state as JSON.
pub fn sub_state_json(db: &str, name: &str) -> serde_json::Value {
    let out = Command::new(bin())
        .args(["--db", db, "sub", "state", name, "--json"])
        .output()
        .expect("sub state failed");
    assert!(
        out.status.success(),
        "sub state {} --json failed: {}",
        name,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_default()
}

/// Disable a subscription.
pub fn sub_disable(db: &str, name: &str) {
    let out = Command::new(bin())
        .args(["--db", db, "sub", "disable", "--sub", name])
        .output()
        .expect("sub disable failed");
    assert!(
        out.status.success(),
        "sub disable {} failed: {}",
        name,
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Enable a subscription.
pub fn sub_enable(db: &str, name: &str) {
    let out = Command::new(bin())
        .args(["--db", db, "sub", "enable", "--sub", name])
        .output()
        .expect("sub enable failed");
    assert!(
        out.status.success(),
        "sub enable {} failed: {}",
        name,
        String::from_utf8_lossy(&out.stderr)
    );
}

// ---------------------------------------------------------------------------
// Stats + Replay helpers (Phase 7 test migration)
// ---------------------------------------------------------------------------

/// Run `topo stats --json` and parse the result as a JSON Value.
pub fn stats_json(db: &str) -> serde_json::Value {
    let out = Command::new(bin())
        .args(["--db", db, "stats", "--json"])
        .output()
        .expect("failed to run topo stats --json");
    assert!(
        out.status.success(),
        "topo stats --json failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.trim()).expect("failed to parse stats JSON")
}

/// Run all 4 replay passes and assert fingerprints match.
/// Returns the shared fingerprint string.
pub fn assert_replay_pass(db: &str) -> String {
    let passes = ["forward", "idempotent", "reverse", "shuffle"];
    let mut fingerprints: Vec<(String, String)> = Vec::new();
    for pass in &passes {
        let out = Command::new(bin())
            .args(["--db", db, "replay", pass, "--json"])
            .output()
            .unwrap_or_else(|e| panic!("failed to run topo replay {}: {}", pass, e));
        assert!(
            out.status.success(),
            "topo replay {} failed: {}",
            pass,
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        let data: serde_json::Value =
            serde_json::from_str(stdout.trim()).expect("failed to parse replay JSON");
        let fp = data["fingerprint"]
            .as_str()
            .expect("missing fingerprint field")
            .to_string();
        fingerprints.push((pass.to_string(), fp));
    }
    let base_fp = &fingerprints[0].1;
    for (pass, fp) in &fingerprints[1..] {
        assert_eq!(
            base_fp, fp,
            "replay fingerprint mismatch: forward={} vs {}={}",
            base_fp, pass, fp
        );
    }
    base_fp.clone()
}

/// Run `topo event blocked --json` and return parsed array.
pub fn event_blocked_json(db: &str) -> Vec<serde_json::Value> {
    let out = Command::new(bin())
        .args(["--db", db, "event", "blocked", "--json"])
        .output()
        .expect("failed to run topo event blocked --json");
    assert!(
        out.status.success(),
        "topo event blocked --json failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_default()
}

/// Run `topo event list --fingerprint` and return the fingerprint string.
pub fn event_list_fingerprint(db: &str) -> String {
    let out = Command::new(bin())
        .args(["--db", db, "event", "list", "--fingerprint"])
        .output()
        .expect("failed to run topo event list --fingerprint");
    assert!(
        out.status.success(),
        "topo event list --fingerprint failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if let Some(fp) = line.trim().strip_prefix("fingerprint: ") {
            return fp.to_string();
        }
    }
    panic!(
        "no fingerprint line in event list --fingerprint output: {}",
        stdout
    );
}

/// Run `topo connections --json` and return parsed array.
pub fn connections_json(db: &str) -> Vec<serde_json::Value> {
    let out = Command::new(bin())
        .args(["--db", db, "connections", "--json"])
        .output()
        .expect("failed to run topo connections --json");
    assert!(
        out.status.success(),
        "topo connections --json failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    serde_json::from_str(stdout.trim()).unwrap_or_default()
}
