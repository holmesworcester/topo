use std::net::SocketAddr;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{CommandFactory, Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use topo::db::transport_creds::discover_local_tenants;
use topo::db::{open_connection, schema::create_tables};
use topo::db_registry::DbRegistry;
use topo::rpc::client::{rpc_call, RpcClientError};
use topo::rpc::protocol::RpcMethod;
use topo::rpc::server::{run_rpc_server, DaemonState, RuntimeState};
use topo::service;
use topo::tuning::{apply_low_mem_allocator_tuning, low_mem_mode};

#[derive(Parser)]
#[command(name = "topo")]
#[command(about = "\u{1f42d} Topo \u{2014} peer-to-peer encrypted sync")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Database path
    #[arg(short, long, default_value = "server.db", global = true)]
    db: String,

    /// Custom RPC socket path (default: <db>.topo.sock)
    #[arg(long, global = true)]
    socket: Option<String>,
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
const GLIBC_TCACHE_COUNT_OFF: &str = "glibc.malloc.tcache_count=0";
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const GLIBC_TCACHE_MAX_OFF: &str = "glibc.malloc.tcache_max=0";

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn has_glibc_tunable(existing: &str, needle: &str) -> bool {
    existing.split(':').any(|part| part.trim() == needle)
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn merged_low_mem_glibc_tunables(existing: &str) -> String {
    let mut tunables = existing.to_string();
    if !has_glibc_tunable(&tunables, GLIBC_TCACHE_COUNT_OFF) {
        if !tunables.is_empty() {
            tunables.push(':');
        }
        tunables.push_str(GLIBC_TCACHE_COUNT_OFF);
    }
    if !has_glibc_tunable(&tunables, GLIBC_TCACHE_MAX_OFF) {
        if !tunables.is_empty() {
            tunables.push(':');
        }
        tunables.push_str(GLIBC_TCACHE_MAX_OFF);
    }
    tunables
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn maybe_reexec_low_mem_with_allocator_env() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    if !low_mem_mode() {
        return Ok(());
    }
    if std::env::var_os("_TOPO_LOW_MEM_ALLOC_READY").is_some() {
        return Ok(());
    }
    let tunables = std::env::var("GLIBC_TUNABLES").unwrap_or_default();
    if std::env::var_os("MALLOC_ARENA_MAX").is_some()
        && std::env::var_os("MALLOC_TRIM_THRESHOLD_").is_some()
        && std::env::var_os("MALLOC_MMAP_THRESHOLD_").is_some()
        && has_glibc_tunable(&tunables, GLIBC_TCACHE_COUNT_OFF)
        && has_glibc_tunable(&tunables, GLIBC_TCACHE_MAX_OFF)
    {
        return Ok(());
    }

    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.args(std::env::args_os().skip(1));
    cmd.env("MALLOC_ARENA_MAX", "1");
    cmd.env("MALLOC_TRIM_THRESHOLD_", "0");
    cmd.env("MALLOC_MMAP_THRESHOLD_", "16384");
    cmd.env("MALLOC_TOP_PAD_", "0");
    cmd.env("GLIBC_TUNABLES", merged_low_mem_glibc_tunables(&tunables));
    cmd.env("_TOPO_LOW_MEM_ALLOC_READY", "1");
    let err = cmd.exec();
    Err(format!("low-mem allocator re-exec failed: {err}").into())
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn maybe_reexec_low_mem_with_allocator_env() -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    Ok(())
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon (runs sync + RPC server)
    Start {
        /// Listen address for QUIC sync
        #[arg(short, long, default_value = "127.0.0.1:4433")]
        bind: SocketAddr,
    },

    /// Stop a running daemon
    Stop,

    /// Create a new workspace and identity chain
    #[command(name = "create-workspace")]
    CreateWorkspace {
        /// Display name for the workspace
        #[arg(long, default_value = "workspace")]
        workspace_name: String,
        /// Your username
        #[arg(long, default_value = "user")]
        username: String,
        /// Device name for this peer
        #[arg(long, default_value = "device")]
        device_name: String,
    },

    /// Accept a user invite link (bootstrap sync + identity chain creation)
    #[command(name = "accept-invite")]
    AcceptInvite {
        /// Invite link (topo://invite/...)
        #[arg(long)]
        invite: String,
        /// Username for the new identity
        #[arg(long, default_value = "user")]
        username: String,
        /// Device name for the new identity
        #[arg(long, default_value = "device")]
        devicename: String,
    },

    // -------------------------------------------------------------------
    // Daemon-only commands (require a running daemon)
    // -------------------------------------------------------------------
    /// List peers in this DB with active marker
    Peers,

    /// Switch active peer by number from the peers list
    #[command(name = "use-peer")]
    UsePeer {
        /// Peer number (1-based, from `topo peers`)
        index: usize,
    },

    /// Show currently active peer
    #[command(name = "active-peer")]
    ActivePeer,

    /// Print local transport identity — SPKI fingerprint from TLS cert
    #[command(name = "transport-identity")]
    TransportIdentity,

    /// Combined view: sidebar + messages with inline reactions
    View {
        /// Max messages to show (0 = all)
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// List messages
    Messages {
        /// Max messages to show (0 = all)
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// Send a message (uses active peer's workspace)
    Send {
        /// Message content
        content: String,
    },

    /// Show database status
    Status,

    /// Generate test messages (uses active peer's workspace)
    Generate {
        #[arg(short, long, default_value = "100")]
        count: usize,
    },

    /// Generate synthetic file events (message + attachment + file slices)
    #[command(name = "generate-files")]
    GenerateFiles {
        /// Number of files to generate
        #[arg(short, long, default_value = "10")]
        count: usize,
        /// File size in MiB per file
        #[arg(long, default_value = "1")]
        size_mib: usize,
    },

    /// Assert a predicate holds right now (exit 0 = pass, exit 1 = fail)
    AssertNow {
        /// Predicate: "field op value" (e.g. "store_count >= 10")
        predicate: String,
    },

    /// Assert a predicate eventually holds (exit 0 = pass, exit 1 = timeout)
    AssertEventually {
        /// Predicate: "field op value" (e.g. "message_count == 50")
        predicate: String,
        /// Timeout in milliseconds
        #[arg(long, default_value = "10000")]
        timeout_ms: u64,
        /// Poll interval in milliseconds
        #[arg(long, default_value = "200")]
        interval_ms: u64,
    },

    /// Create a reaction to a message
    React {
        /// Emoji to react with
        emoji: String,
        /// Target: message number (N or #N) or hex event ID
        #[arg(long)]
        target: String,
    },

    /// Delete a message
    #[command(name = "delete-message")]
    DeleteMessage {
        /// Target: message number (N or #N) or hex event ID
        #[arg(long)]
        target: String,
    },

    /// List reactions
    Reactions,

    /// List users from projection
    Users,

    /// List keys from projection
    Keys {
        /// Show summary only
        #[arg(long)]
        summary: bool,
    },

    /// List workspaces from projection
    #[command(alias = "workspaces")]
    Networks,

    /// Send intro offers to two peers so they can hole-punch a direct connection
    Intro {
        /// Peer A hex SPKI fingerprint
        #[arg(long)]
        peer_a: String,
        /// Peer B hex SPKI fingerprint
        #[arg(long)]
        peer_b: String,
        /// Intro TTL in milliseconds
        #[arg(long, default_value = "30000")]
        ttl_ms: u64,
        /// Attempt window in milliseconds
        #[arg(long, default_value = "4000")]
        attempt_window_ms: u32,
    },

    /// Show intro attempt records
    #[command(name = "intro-attempts")]
    IntroAttempts {
        /// Filter by peer SPKI fingerprint (hex)
        #[arg(long)]
        peer: Option<String>,
    },

    /// Create a user invite link for the active workspace
    #[command(name = "create-invite")]
    CreateInvite {
        /// Public address (host:port) to embed in invite link
        #[arg(long, alias = "bootstrap")]
        public_addr: String,
        /// Public SPKI fingerprint (hex) — defaults to local transport SPKI
        #[arg(long)]
        public_spki: Option<String>,
    },

    /// Create a device link invite for the active peer's user
    Link {
        /// Public address (host:port) to embed in link
        #[arg(long, alias = "bootstrap")]
        public_addr: String,
        /// Public SPKI fingerprint (hex) — defaults to local transport SPKI
        #[arg(long)]
        public_spki: Option<String>,
    },

    /// Accept a device link invite
    #[command(name = "accept-link")]
    AcceptLink {
        /// Device link (topo://link/...)
        #[arg(long)]
        invite: String,
        /// Device name for the new identity
        #[arg(long, default_value = "device")]
        devicename: String,
    },

    /// Ban (remove) a user from the workspace
    Ban {
        /// User number (from `topo users`), #N, or hex event ID
        user: String,
    },

    /// Show combined identity info (transport + user + peer)
    Identity,

    /// List channels
    Channels,

    /// Create a new channel
    #[command(name = "new-channel")]
    NewChannel {
        /// Channel name
        name: String,
    },

    /// Switch active channel
    Channel {
        /// Channel number or name
        selector: String,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },

    /// Manage the database registry (aliases, default DB)
    Db {
        #[command(subcommand)]
        action: DbAction,
    },

    /// Attempt UPnP port forwarding for the daemon's QUIC listen port.
    /// Requires daemon listening on non-loopback (for example `--bind 0.0.0.0:...`).
    Upnp,
}

#[derive(Subcommand)]
enum DbAction {
    /// Add a database to the registry
    Add {
        /// Path to the database file
        path: String,
        /// Alias name
        #[arg(long)]
        name: Option<String>,
    },
    /// List registered databases
    List,
    /// Remove a database from the registry
    Remove {
        /// Alias name, index, or path
        selector: String,
    },
    /// Rename a database alias
    Rename {
        /// Current alias name, index, or path
        selector: String,
        /// New alias name
        new_name: String,
    },
    /// Set the default database
    Default {
        /// Alias name, index, or path
        selector: String,
    },
}

// ---------------------------------------------------------------------------
// RPC helpers: auto-start daemon for target DB/socket, then call.
// ---------------------------------------------------------------------------

fn target_socket_path(db: &str, socket: Option<&str>) -> PathBuf {
    socket
        .map(PathBuf::from)
        .unwrap_or_else(|| service::socket_path_for_db(db))
}

fn status_matches_target_db(db: &str, data: Option<&serde_json::Value>) -> bool {
    data.and_then(|v| v.get("daemon_db_path"))
        .and_then(|v| v.as_str())
        .map(|running_db| running_db == db)
        .unwrap_or(true)
}

fn ensure_daemon_running(
    db: &str,
    socket: Option<&str>,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    let sock = target_socket_path(db, socket);

    match rpc_call(&sock, RpcMethod::Status) {
        Ok(resp) => {
            if resp.ok && status_matches_target_db(db, resp.data.as_ref()) {
                return Ok(sock);
            }
            if let Some(err) = resp.error {
                return Err(err.into());
            }
            return Err("daemon status probe failed".into());
        }
        Err(RpcClientError::DaemonNotRunning(_)) => {}
        Err(_) => {
            if sock.exists() {
                let _ = std::fs::remove_file(&sock);
            }
        }
    }

    let mut cmd = std::process::Command::new(std::env::current_exe()?);
    cmd.arg("--db").arg(db);
    if let Some(sock_override) = socket {
        cmd.arg("--socket").arg(sock_override);
    }
    cmd.arg("start")
        .arg("--bind")
        .arg("127.0.0.1:0")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let child = cmd.spawn()?;
    let _pid = child.id();
    drop(child);

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_error = String::from("daemon did not become ready");
    while Instant::now() < deadline {
        match rpc_call(&sock, RpcMethod::Status) {
            Ok(resp) => {
                if resp.ok && status_matches_target_db(db, resp.data.as_ref()) {
                    return Ok(sock);
                }
                if !status_matches_target_db(db, resp.data.as_ref()) {
                    return Err(format!(
                        "daemon socket {} is bound to a different db",
                        sock.display()
                    )
                    .into());
                }
                last_error = resp
                    .error
                    .unwrap_or_else(|| "status probe failed".to_string());
            }
            Err(RpcClientError::DaemonNotRunning(_)) => {
                last_error = "daemon not running yet".to_string();
            }
            Err(e) => {
                last_error = e.to_string();
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    Err(format!(
        "failed to auto-start daemon for {} via {}: {}",
        db,
        sock.display(),
        last_error
    )
    .into())
}

fn rpc_require_daemon(
    db: &str,
    socket: Option<&str>,
    method: RpcMethod,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let sock = ensure_daemon_running(db, socket)?;

    match rpc_call(&sock, method) {
        Ok(resp) => {
            if !resp.ok {
                if let Some(err) = resp.error {
                    return Err(err.into());
                }
            }
            Ok(resp.data.unwrap_or(serde_json::Value::Null))
        }
        Err(RpcClientError::DaemonNotRunning(_)) => Err(format!(
            "daemon failed to start for {} (socket: {})",
            db,
            sock.display()
        )
        .into()),
        Err(e) => Err(e.to_string().into()),
    }
}

/// Resolve the --db argument using the registry:
/// - If --db is the clap default "server.db" and a registry default exists, use it
/// - Otherwise run selector resolution (existing path → alias → index → passthrough)
fn resolve_db_arg(raw: &str) -> Result<String, String> {
    let registry = DbRegistry::load();
    if raw == "server.db" {
        if let Some(default_path) = registry.default_path() {
            return Ok(default_path.to_string());
        }
    }
    // If it parses as a number, it must be a valid registry index — don't fall back.
    if raw.parse::<usize>().is_ok() {
        return registry.resolve(raw);
    }
    // For non-numeric selectors, resolve returns passthrough on miss, so this is fine.
    Ok(registry.resolve(raw).unwrap_or_else(|_| raw.to_string()))
}

struct ManagedRuntime {
    tenants: Vec<String>,
    shutdown_notify: Arc<tokio::sync::Notify>,
    handle: tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
}

fn discover_tenant_peer_ids(
    db_path: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(db_path)?;
    create_tables(&conn)?;
    let mut peers = discover_local_tenants(&conn)?
        .into_iter()
        .map(|t| t.peer_id)
        .collect::<Vec<_>>();
    peers.sort();
    peers.dedup();
    Ok(peers)
}

async fn stop_runtime(runtime: ManagedRuntime) {
    runtime.shutdown_notify.notify_one();
    match tokio::time::timeout(Duration::from_secs(5), runtime.handle).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => tracing::warn!("runtime exited with error during stop: {}", e),
        Ok(Err(e)) => tracing::warn!("runtime task join error during stop: {}", e),
        Err(_) => tracing::warn!("timed out waiting for runtime to stop"),
    }
}

fn spawn_runtime(
    db_path: &str,
    bind: SocketAddr,
    state: Arc<DaemonState>,
    tenants: Vec<String>,
) -> ManagedRuntime {
    // Runtime is Active only after listen_addr is reported.
    *state.runtime_state.write().unwrap() = RuntimeState::IdleNoTenants;
    *state.runtime_net.write().unwrap() = None;

    let runtime_shutdown = Arc::new(tokio::sync::Notify::new());
    let runtime_shutdown_for_task = runtime_shutdown.clone();
    let db_for_task = db_path.to_string();

    let (net_tx, net_rx) = tokio::sync::oneshot::channel::<topo::node::NodeRuntimeNetInfo>();
    let state_for_net = state.clone();
    tokio::spawn(async move {
        if let Ok(info) = net_rx.await {
            println!("listen: {}", info.listen_addr);
            *state_for_net.runtime_net.write().unwrap() = Some(info);
            *state_for_net.runtime_state.write().unwrap() = RuntimeState::Active;
        }
    });

    let handle = tokio::spawn(async move {
        topo::node::run_node(&db_for_task, bind, net_tx, runtime_shutdown_for_task).await
    });

    ManagedRuntime {
        tenants,
        shutdown_notify: runtime_shutdown,
        handle,
    }
}

async fn reevaluate_runtime(
    db_path: &str,
    bind: SocketAddr,
    state: Arc<DaemonState>,
    active_runtime: &mut Option<ManagedRuntime>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if active_runtime
        .as_ref()
        .map(|runtime| runtime.handle.is_finished())
        .unwrap_or(false)
    {
        let finished = active_runtime.take().unwrap();
        match finished.handle.await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => tracing::warn!("runtime exited unexpectedly: {}", e),
            Err(e) => tracing::warn!("runtime task join error: {}", e),
        }
        *state.runtime_net.write().unwrap() = None;
    }

    let tenants = discover_tenant_peer_ids(db_path)?;

    if tenants.is_empty() {
        if let Some(runtime) = active_runtime.take() {
            stop_runtime(runtime).await;
        }
        *state.runtime_state.write().unwrap() = RuntimeState::IdleNoTenants;
        *state.runtime_net.write().unwrap() = None;
        return Ok(());
    }

    let restart_needed = match active_runtime.as_ref() {
        Some(runtime) => runtime.tenants != tenants,
        None => true,
    };
    if restart_needed {
        if let Some(runtime) = active_runtime.take() {
            stop_runtime(runtime).await;
        }
        tracing::info!("activating peering runtime ({} tenant(s))", tenants.len());
        *active_runtime = Some(spawn_runtime(db_path, bind, state, tenants));
    }

    Ok(())
}

async fn run_runtime_manager(
    db_path: &str,
    bind: SocketAddr,
    state: Arc<DaemonState>,
    shutdown_flag: Arc<AtomicBool>,
    daemon_shutdown: Arc<tokio::sync::Notify>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut active_runtime: Option<ManagedRuntime> = None;
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    reevaluate_runtime(db_path, bind, state.clone(), &mut active_runtime).await?;

    loop {
        if shutdown_flag.load(Ordering::Relaxed) {
            if let Some(runtime) = active_runtime.take() {
                stop_runtime(runtime).await;
            }
            return Ok(());
        }
        tokio::select! {
            _ = daemon_shutdown.notified() => {
                if let Some(runtime) = active_runtime.take() {
                    stop_runtime(runtime).await;
                }
                return Ok(());
            }
            _ = state.runtime_recheck.notified() => {
                reevaluate_runtime(db_path, bind, state.clone(), &mut active_runtime).await?;
            }
            _ = interval.tick() => {
                reevaluate_runtime(db_path, bind, state.clone(), &mut active_runtime).await?;
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    maybe_reexec_low_mem_with_allocator_env()?;
    apply_low_mem_allocator_tuning();
    let cli = Cli::parse();
    let db = &resolve_db_arg(&cli.db)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    let socket_override = cli.socket.clone();

    // Init tracing for commands that need it
    match &cli.command {
        Commands::Start { .. } | Commands::Intro { .. } | Commands::AcceptInvite { .. } => {
            let subscriber = FmtSubscriber::builder()
                .with_max_level(Level::INFO)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
        _ => {}
    }

    match cli.command {
        // ---------------------------------------------------------------
        // Daemon lifecycle
        // ---------------------------------------------------------------
        Commands::Start { bind } => {
            let socket_path = socket_override
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| service::socket_path_for_db(db));

            // Idempotent: check if daemon is already running
            if socket_path.exists() {
                match rpc_call(&socket_path, RpcMethod::Status) {
                    Ok(_) => {
                        println!("daemon already running for {}", db);
                        return Ok(());
                    }
                    Err(RpcClientError::DaemonNotRunning(_)) | Err(_) => {
                        // Stale socket — remove it
                        let _ = std::fs::remove_file(&socket_path);
                    }
                }
            }

            // Initialize DB eagerly
            {
                let conn = open_connection(db)?;
                create_tables(&conn)?;
            }

            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_notify = Arc::new(tokio::sync::Notify::new());
            let state = Arc::new(DaemonState::new(db));

            // Start RPC server in a background thread
            let rpc_shutdown = shutdown.clone();
            let rpc_notify = shutdown_notify.clone();
            let rpc_socket = socket_path.clone();
            let rpc_state = state.clone();
            let rpc_handle = std::thread::spawn(move || {
                if let Err(e) = run_rpc_server(&rpc_socket, rpc_state, rpc_shutdown, rpc_notify) {
                    tracing::error!("RPC server error: {}", e);
                }
            });

            info!(
                "\u{1f42d} Topo daemon started (db={}, socket={})",
                db,
                socket_path.display()
            );

            // Foreground Ctrl-C uses the same daemon shutdown path as RPC Shutdown.
            let ctrlc_notify = shutdown_notify.clone();
            tokio::spawn(async move {
                if tokio::signal::ctrl_c().await.is_ok() {
                    info!("Shutdown requested via Ctrl-C");
                    ctrlc_notify.notify_waiters();
                }
            });

            // Runtime manager keeps control daemon alive with explicit lifecycle:
            // IdleNoTenants <-> Active.
            let manager_state = state.clone();
            let manager_shutdown = shutdown_notify.clone();
            let manager_shutdown_flag = shutdown.clone();
            let manager_db = db.to_string();
            let runtime_manager = tokio::spawn(async move {
                if let Err(e) = run_runtime_manager(
                    &manager_db,
                    bind,
                    manager_state,
                    manager_shutdown_flag,
                    manager_shutdown,
                )
                .await
                {
                    tracing::error!("runtime manager error: {}", e);
                }
            });

            // Wait until shutdown is requested by RPC stop or Ctrl-C.
            shutdown_notify.notified().await;

            // Signal RPC server to stop
            shutdown.store(true, Ordering::Relaxed);
            shutdown_notify.notify_waiters();
            let _ = runtime_manager.await;
            let _ = rpc_handle.join();

            info!("\u{1f42d} Topo daemon shut down cleanly");
        }

        Commands::Stop => {
            let socket_path = socket_override
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| service::socket_path_for_db(db));
            let request_deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match rpc_call(&socket_path, RpcMethod::Shutdown) {
                    Ok(_) => {
                        break;
                    }
                    Err(RpcClientError::DaemonNotRunning(_)) if !socket_path.exists() => {
                        println!("no daemon running for {}", db);
                        return Ok(());
                    }
                    Err(RpcClientError::DaemonNotRunning(_)) => {}
                    Err(RpcClientError::Protocol(msg))
                        if msg.contains("Connection reset by peer")
                            || msg.contains("Broken pipe") => {}
                    Err(RpcClientError::Io(e))
                        if e.kind() == std::io::ErrorKind::ConnectionReset
                            || e.kind() == std::io::ErrorKind::ConnectionRefused
                            || e.kind() == std::io::ErrorKind::BrokenPipe => {}
                    Err(e) => {
                        eprintln!("error stopping daemon: {}", e);
                        std::process::exit(1);
                    }
                }

                if Instant::now() >= request_deadline {
                    eprintln!(
                        "error stopping daemon: timed out sending shutdown to {}",
                        socket_path.display()
                    );
                    std::process::exit(1);
                }
                std::thread::sleep(Duration::from_millis(100));
            }

            let down_deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < down_deadline {
                match rpc_call(&socket_path, RpcMethod::Status) {
                    Err(RpcClientError::DaemonNotRunning(_)) if !socket_path.exists() => {
                        println!("daemon stopped");
                        return Ok(());
                    }
                    _ => std::thread::sleep(Duration::from_millis(100)),
                }
            }
            eprintln!(
                "error stopping daemon: timed out waiting for daemon exit ({})",
                socket_path.display()
            );
            std::process::exit(1);
        }

        Commands::CreateWorkspace {
            workspace_name,
            username,
            device_name,
        } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::CreateWorkspace {
                    workspace_name,
                    username,
                    device_name,
                },
            )?;
            println!("peer_id:      {}", data["peer_id"].as_str().unwrap_or(""));
            println!(
                "workspace_id: {}",
                data["workspace_id"].as_str().unwrap_or("")
            );
        }

        Commands::AcceptInvite {
            invite,
            username,
            devicename,
        } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::AcceptInvite {
                    invite,
                    username,
                    devicename,
                },
            )?;
            println!("Accepted invite");
            println!("  peer_id: {}", data["peer_id"].as_str().unwrap_or(""));
            println!(
                "  user:    {}",
                data["user_event_id"].as_str().unwrap_or("")
            );
            println!(
                "  peer:    {}",
                data["peer_shared_event_id"].as_str().unwrap_or("")
            );
        }

        // ---------------------------------------------------------------
        // Daemon-only commands (require running daemon)
        // ---------------------------------------------------------------
        Commands::Peers => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Peers)?;
            println!("PEERS ({}):", db);
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("  (none)");
                } else {
                    for item in items {
                        let marker = if item["active"].as_bool().unwrap_or(false) {
                            "*"
                        } else {
                            " "
                        };
                        let peer_id = item["peer_id"].as_str().unwrap_or("");
                        let ws_id = item["workspace_id"].as_str().unwrap_or("");
                        let idx = item["index"].as_u64().unwrap_or(0);
                        println!(
                            "  {}. {} {} (workspace: {})",
                            idx,
                            marker,
                            short_id(peer_id),
                            short_id(ws_id)
                        );
                    }
                }
            }
        }

        Commands::UsePeer { index } => {
            let data =
                rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::UsePeer { index })?;
            let peer_id = data["peer_id"].as_str().unwrap_or("");
            let ws_id = data["workspace_id"].as_str().unwrap_or("");
            println!(
                "Switched to peer {} (workspace: {})",
                short_id(peer_id),
                short_id(ws_id)
            );
        }

        Commands::ActivePeer => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::ActivePeer)?;
            match data["peer_id"].as_str() {
                Some(peer_id) => println!("{}", peer_id),
                None => println!("(no active peer)"),
            }
        }

        Commands::TransportIdentity => {
            let data =
                rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::TransportIdentity)?;
            let fingerprint = data["fingerprint"].as_str().unwrap_or("");
            println!("{}", fingerprint);
        }

        Commands::View { limit } => {
            let data =
                rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::View { limit })?;
            show_view(&data);
        }

        Commands::Messages { limit } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::Messages { limit },
            )?;
            show_messages_from_json(db, &data);
        }

        Commands::Send { content } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::Send {
                    content: content.clone(),
                },
            )?;
            let event_id = data["event_id"].as_str().unwrap_or("");
            println!("Sent: {}", data["content"].as_str().unwrap_or(&content));
            println!("event_id:{}", event_id);
        }

        Commands::Status => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Status)?;
            println!("STATUS ({}):", db);
            println!("  Events:    {} total", data["events_count"]);
            println!("  Messages:  {} projected", data["messages_count"]);
            println!("  Reactions: {} projected", data["reactions_count"]);
            println!("  Recorded:  {} events", data["recorded_events_count"]);
            println!("  NegItems:  {} indexed", data["neg_items_count"]);
            println!(
                "  Runtime:   {}",
                data["runtime_state"].as_str().unwrap_or("unknown")
            );
            // Runtime networking info.
            if let Some(rt) = data.get("runtime") {
                println!(
                    "  Listen:    {}",
                    rt["listen_addr"].as_str().unwrap_or("unknown")
                );
                if let Some(upnp) = rt.get("upnp") {
                    let status = upnp["status"].as_str().unwrap_or("not_attempted");
                    match status {
                        "success" => {
                            let ext_port = upnp["mapped_external_port"]
                                .as_u64()
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "?".into());
                            let ext_ip = upnp["external_ip"].as_str().unwrap_or("unknown");
                            let nat_tag = if upnp["double_nat"].as_bool().unwrap_or(false) {
                                " (double-NAT!)"
                            } else {
                                ""
                            };
                            println!(
                                "  UPnP:      success udp external_port={} external_ip={}{}",
                                ext_port, ext_ip, nat_tag
                            );
                        }
                        "failed" => {
                            let err = upnp["error"].as_str().unwrap_or("unknown");
                            println!("  UPnP:      failed ({})", err);
                        }
                        "not_attempted" => {
                            let err = upnp["error"].as_str().unwrap_or("unknown");
                            println!("  UPnP:      not attempted ({})", err);
                        }
                        _ => {
                            println!("  UPnP:      not attempted");
                        }
                    }
                } else {
                    println!("  UPnP:      not attempted (run `topo upnp` to try)");
                }
            }
            if data.get("runtime").is_none() {
                let state = data["runtime_state"].as_str().unwrap_or("");
                if state == "IdleNoTenants" {
                    println!("  Listen:    (idle; no tenants)");
                } else {
                    println!("  Listen:    (starting)");
                }
                println!("  UPnP:      not attempted");
            }
        }

        Commands::Generate { count } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::Generate { count },
            )?;
            println!("Generated {} messages in {}", data["count"], db);
        }

        Commands::GenerateFiles { count, size_mib } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::GenerateFiles { count, size_mib },
            )?;
            println!(
                "Generated {} files ({} MiB each, {} slices/file, total slices {}) in {}",
                data["files"],
                data["file_size_mib"],
                data["slices_per_file"],
                data["total_slices"],
                db
            );
        }

        Commands::AssertNow { predicate } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::AssertNow {
                    predicate: predicate.clone(),
                },
            )?;
            let pass = data["pass"].as_bool().unwrap_or(false);
            let field = data["field"].as_str().unwrap_or("");
            let actual = data["actual"].as_i64().unwrap_or(0);
            let op = data["op"].as_str().unwrap_or("");
            let expected = data["expected"].as_i64().unwrap_or(0);
            if pass {
                println!(
                    "PASS: {} = {} (expected {} {})",
                    field, actual, op, expected
                );
                std::process::exit(0);
            } else {
                println!(
                    "FAIL: {} = {} (expected {} {})",
                    field, actual, op, expected
                );
                std::process::exit(1);
            }
        }

        Commands::AssertEventually {
            predicate,
            timeout_ms,
            interval_ms,
        } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::AssertEventually {
                    predicate: predicate.clone(),
                    timeout_ms,
                    interval_ms,
                },
            )?;
            let pass = data["pass"].as_bool().unwrap_or(false);
            let field = data["field"].as_str().unwrap_or("");
            let actual = data["actual"].as_i64().unwrap_or(0);
            let op = data["op"].as_str().unwrap_or("");
            let expected = data["expected"].as_i64().unwrap_or(0);
            if pass {
                println!(
                    "PASS: {} = {} (expected {} {})",
                    field, actual, op, expected
                );
                std::process::exit(0);
            } else {
                println!(
                    "TIMEOUT: {} = {} (expected {} {}) after {}ms",
                    field, actual, op, expected, timeout_ms
                );
                std::process::exit(1);
            }
        }

        Commands::React { emoji, target } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::React {
                    target,
                    emoji: emoji.clone(),
                },
            )?;
            let event_id = data["event_id"].as_str().unwrap_or("");
            let short = &event_id[..event_id.len().min(8)];
            println!(
                "Reacted {} ({})",
                data["emoji"].as_str().unwrap_or(&emoji),
                short
            );
        }

        Commands::DeleteMessage { target } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::DeleteMessage { target },
            )?;
            let target_str = data["target"].as_str().unwrap_or("");
            println!(
                "Deleted message {}",
                &target_str[..target_str.len().min(16)]
            );
        }

        Commands::Reactions => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Reactions)?;
            println!("REACTIONS ({}):", db);
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("  (none)");
                } else {
                    for item in items {
                        println!(
                            "  {} -> {} {}",
                            short_id(item["event_id"].as_str().unwrap_or("")),
                            short_id(item["target_event_id"].as_str().unwrap_or("")),
                            item["emoji"].as_str().unwrap_or("")
                        );
                    }
                }
            } else {
                println!("  (none)");
            }
        }

        Commands::Users => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Users)?;
            println!("USERS:");
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("  (none)");
                } else {
                    for (i, item) in items.iter().enumerate() {
                        let username = item["username"].as_str().unwrap_or("");
                        let eid = item["event_id"].as_str().unwrap_or("");
                        let display = if username.is_empty() {
                            format!("user_{}", short_id(eid))
                        } else {
                            username.to_string()
                        };
                        println!("  {}. {}", i + 1, display);
                    }
                }
            } else {
                println!("  (none)");
            }
        }

        Commands::Keys { summary } => {
            let data =
                rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Keys { summary })?;
            println!("KEYS ({}):", db);
            println!("  Users: {}", data["user_count"]);
            println!("  Peers: {}", data["peer_count"]);
            println!("  Admins: {}", data["admin_count"]);
            if !summary {
                if let Some(users) = data["users"].as_array() {
                    for eid in users {
                        println!("    user {}", short_id(eid.as_str().unwrap_or("")));
                    }
                }
                if let Some(peers) = data["peers"].as_array() {
                    for eid in peers {
                        println!("    peer {}", short_id(eid.as_str().unwrap_or("")));
                    }
                }
            }
        }

        Commands::Networks => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Workspaces)?;
            println!("WORKSPACES ({}):", db);
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("  (none)");
                } else {
                    for (i, item) in items.iter().enumerate() {
                        println!(
                            "  {}. {} ({})",
                            i + 1,
                            item["name"].as_str().unwrap_or(""),
                            short_id(item["event_id"].as_str().unwrap_or(""))
                        );
                    }
                }
            } else {
                println!("  (none)");
            }
        }

        Commands::Intro {
            peer_a,
            peer_b,
            ttl_ms,
            attempt_window_ms,
        } => match service::svc_intro(db, &peer_a, &peer_b, ttl_ms, attempt_window_ms).await {
            Ok(true) => {
                println!("Intro sent to both peers");
            }
            Ok(false) => {
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        },

        Commands::IntroAttempts { peer } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::IntroAttempts { peer },
            )?;
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("No intro attempts recorded.");
                } else {
                    for r in items {
                        let intro_id = r["intro_id"].as_str().unwrap_or("");
                        println!("  intro_id:  {}...", &intro_id[..intro_id.len().min(16)]);
                        let peer_id = r["other_peer_id"].as_str().unwrap_or("");
                        println!("  peer:      {}", &peer_id[..peer_id.len().min(16)]);
                        let intro_by = r["introduced_by_peer_id"].as_str().unwrap_or("");
                        println!("  via:       {}", &intro_by[..intro_by.len().min(16)]);
                        println!(
                            "  endpoint:  {}:{}",
                            r["origin_ip"].as_str().unwrap_or(""),
                            r["origin_port"]
                        );
                        println!("  status:    {}", r["status"].as_str().unwrap_or(""));
                        if let Some(err) = r["error"].as_str() {
                            println!("  error:     {}", err);
                        }
                        println!("  created:   {}", r["created_at"]);
                        println!();
                    }
                }
            } else {
                println!("No intro attempts recorded.");
            }
        }

        Commands::CreateInvite {
            public_addr,
            public_spki,
        } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::CreateInvite {
                    public_addr,
                    public_spki,
                },
            )?;
            println!("{}", data["invite_link"].as_str().unwrap_or(""));
            if let Some(num) = data["invite_ref"].as_u64() {
                eprintln!("Created invite #{}", num);
            }
        }

        Commands::Link {
            public_addr,
            public_spki,
        } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::CreateDeviceLink {
                    public_addr,
                    public_spki,
                },
            )?;
            println!("{}", data["invite_link"].as_str().unwrap_or(""));
            if let Some(num) = data["invite_ref"].as_u64() {
                eprintln!("Created device link #{}", num);
            }
        }

        Commands::AcceptLink { invite, devicename } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::AcceptLink { invite, devicename },
            )?;
            let peer_id = data["peer_id"].as_str().unwrap_or("");
            println!("Accepted device link");
            println!("  peer_id: {}", peer_id);
        }

        Commands::Ban { user } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::Ban { target: user },
            )?;
            let target = data["target"].as_str().unwrap_or("");
            println!("Banned user {}", &target[..target.len().min(16)]);
        }

        Commands::Identity => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Identity)?;
            println!("IDENTITY:");
            println!(
                "  Transport: {}",
                data["transport_fingerprint"].as_str().unwrap_or("")
            );
            match data["user_event_id"].as_str() {
                Some(uid) => println!("  User:      {}", &uid[..uid.len().min(16)]),
                None => println!("  User:      (none)"),
            }
            match data["peer_shared_event_id"].as_str() {
                Some(pid) => println!("  Peer:      {}", &pid[..pid.len().min(16)]),
                None => println!("  Peer:      (none)"),
            }
        }

        Commands::Channels => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Channels)?;
            println!("CHANNELS:");
            if let Some(items) = data.as_array() {
                for item in items {
                    let marker = if item["active"].as_bool().unwrap_or(false) {
                        "*"
                    } else {
                        " "
                    };
                    let idx = item["index"].as_u64().unwrap_or(0);
                    let name = item["name"].as_str().unwrap_or("");
                    println!("  {}{}. #{}", marker, idx, name);
                }
            }
        }

        Commands::NewChannel { name } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::NewChannel { name: name.clone() },
            )?;
            let idx = data["index"].as_u64().unwrap_or(0);
            println!("Created channel #{}: {}", idx, name);
        }

        Commands::Channel { selector } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::UseChannel { selector },
            )?;
            let name = data["name"].as_str().unwrap_or("");
            println!("Switched to channel #{}", name);
        }

        Commands::Completions { shell } => {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "topo", &mut std::io::stdout());
        }

        // ---------------------------------------------------------------
        // DB registry management (no daemon needed)
        // ---------------------------------------------------------------
        Commands::Db { action } => match action {
            DbAction::Add { path, name } => {
                let mut registry = DbRegistry::load();
                registry.add(&path, name.as_deref())?;
                registry.save()?;
                let display_name = name.as_deref().unwrap_or("(none)");
                println!("Added {} (alias: {})", path, display_name);
            }
            DbAction::List => {
                let registry = DbRegistry::load();
                if registry.entries.is_empty() {
                    println!("No databases registered.");
                    println!("  Use `topo db add <path> --name <alias>` to register one.");
                } else {
                    println!("DATABASES:");
                    for (i, entry) in registry.entries.iter().enumerate() {
                        let marker = if entry.is_default { "*" } else { " " };
                        let name = entry.name.as_deref().unwrap_or("-");
                        println!("  {}{}. {} ({})", marker, i + 1, name, entry.path);
                    }
                }
            }
            DbAction::Remove { selector } => {
                let mut registry = DbRegistry::load();
                let removed = registry.remove(&selector)?;
                registry.save()?;
                println!("Removed {}", removed.path);
            }
            DbAction::Rename { selector, new_name } => {
                let mut registry = DbRegistry::load();
                registry.rename(&selector, &new_name)?;
                registry.save()?;
                println!("Renamed to {}", new_name);
            }
            DbAction::Default { selector } => {
                let mut registry = DbRegistry::load();
                registry.set_default(&selector)?;
                registry.save()?;
                println!("Default set to {}", selector);
            }
        },

        Commands::Upnp => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Upnp)?;
            let status = data["status"].as_str().unwrap_or("unknown");
            match status {
                "success" => {
                    let ext_port = data["mapped_external_port"]
                        .as_u64()
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "?".into());
                    let ext_ip = data["external_ip"].as_str().unwrap_or("unknown");
                    println!(
                        "upnp: success udp external_port={} external_ip={}",
                        ext_port, ext_ip
                    );
                    if data["double_nat"].as_bool().unwrap_or(false) {
                        println!("warning: double-NAT detected \u{2014} external IP {} is not publicly routable; port forwarding may not be reachable from the internet", ext_ip);
                    }
                }
                "failed" => {
                    let err = data["error"].as_str().unwrap_or("unknown reason");
                    println!("upnp: failed ({})", err);
                }
                "not_attempted" => {
                    let err = data["error"].as_str().unwrap_or("unknown reason");
                    println!("upnp: not attempted ({})", err);
                }
                other => {
                    println!("upnp: {}", other);
                }
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Display helpers (CLI-only formatting, not business logic)
// ---------------------------------------------------------------------------

fn short_id(b64: &str) -> &str {
    &b64[..b64.len().min(8)]
}

fn format_timestamp(ms: i64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let age_ms = now - ms;

    if age_ms < 0 {
        return format_absolute(ms);
    }

    let secs = age_ms / 1000;
    if secs < 60 {
        return format!("{}s ago", secs);
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{}m ago", mins);
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{}h ago", hours);
    }
    let days = hours / 24;
    if days < 7 {
        return format!("{}d ago", days);
    }

    format_absolute(ms)
}

fn format_absolute(ms: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let dt = UNIX_EPOCH + Duration::from_millis(ms as u64);
    let secs = dt.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;

    let (_year, month, day) = days_to_ymd(days_since_epoch as i64);
    let month_name = match month {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => "???",
    };
    format!("{} {} {:02}:{:02}", month_name, day, hours, minutes)
}

fn days_to_ymd(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

// ---------------------------------------------------------------------------
// Messages display (from JSON data)
// ---------------------------------------------------------------------------

fn show_messages_from_json(_db_path: &str, data: &serde_json::Value) {
    let messages = match data["messages"].as_array() {
        Some(msgs) => msgs,
        None => {
            println!("  (no messages)");
            return;
        }
    };

    if messages.is_empty() {
        println!("  (no messages)");
        return;
    }

    let total = data["total"].as_i64().unwrap_or(0);
    println!("MESSAGES ({} total):\n", total);

    let mut last_author = String::new();
    for (i, msg) in messages.iter().enumerate() {
        let created_at = msg["created_at"].as_i64().unwrap_or(0);
        let ts = format_timestamp(created_at);
        let author_id = msg["author_id"].as_str().unwrap_or("");
        let author_name = msg["author_name"].as_str().unwrap_or("");
        let display_name = if author_name.is_empty() {
            short_id(author_id).to_string()
        } else {
            author_name.to_string()
        };
        let content = msg["content"].as_str().unwrap_or("");

        if author_id != last_author {
            if i > 0 {
                println!();
            }
            println!("  {} [{}]", display_name, ts);
            last_author = author_id.to_string();
        }
        println!("    {}. {}", i + 1, content);
    }
    println!();
}

fn show_view(data: &serde_json::Value) {
    // Sidebar: workspace name
    let workspace_name = data["workspace_name"].as_str().unwrap_or("(unnamed)");
    let own_user_eid = data["own_user_event_id"].as_str().unwrap_or("");

    println!("  {}", workspace_name);

    // Users list
    if let Some(users) = data["users"].as_array() {
        let user_names: Vec<String> = users
            .iter()
            .map(|u| {
                let name = u["username"].as_str().unwrap_or("");
                let eid = u["event_id"].as_str().unwrap_or("");
                let display = if name.is_empty() {
                    short_id(eid).to_string()
                } else {
                    name.to_string()
                };
                if eid == own_user_eid {
                    format!("{} (you)", display)
                } else {
                    display
                }
            })
            .collect();
        println!("    USERS: {}", user_names.join(", "));
    }

    // Accounts list
    if let Some(accounts) = data["accounts"].as_array() {
        let acct_names: Vec<String> = accounts
            .iter()
            .map(|a| {
                let username = a["username"].as_str().unwrap_or("");
                let device_name = a["device_name"].as_str().unwrap_or("");
                let user_eid = a["user_event_id"].as_str().unwrap_or("");
                let user_display = if username.is_empty() {
                    short_id(user_eid).to_string()
                } else {
                    username.to_string()
                };
                let label = if device_name.is_empty() {
                    user_display
                } else {
                    format!("{}/{}", user_display, device_name)
                };
                if user_eid == own_user_eid {
                    format!("{} (you)", label)
                } else {
                    label
                }
            })
            .collect();
        println!("    ACCOUNTS: {}", acct_names.join(", "));
    }

    println!();
    println!("  {}", "\u{2500}".repeat(40));
    println!();

    // Messages with inline reactions
    if let Some(messages) = data["messages"].as_array() {
        if messages.is_empty() {
            println!("    (no messages)");
        } else {
            let mut last_author = String::new();
            for (i, msg) in messages.iter().enumerate() {
                let created_at = msg["created_at"].as_i64().unwrap_or(0);
                let ts = format_timestamp(created_at);
                let author_id = msg["author_id"].as_str().unwrap_or("");
                let author_name = msg["author_name"].as_str().unwrap_or("");
                let display_name = if author_name.is_empty() {
                    short_id(author_id).to_string()
                } else {
                    author_name.to_string()
                };
                let content = msg["content"].as_str().unwrap_or("");

                if author_id != last_author {
                    if i > 0 {
                        println!();
                    }
                    println!("    {} [{}]", display_name, ts);
                    last_author = author_id.to_string();
                }
                println!("      {}. {}", i + 1, content);

                // Inline reactions
                if let Some(reactions) = msg["reactions"].as_array() {
                    if !reactions.is_empty() {
                        for rxn in reactions {
                            let emoji = rxn["emoji"].as_str().unwrap_or("");
                            let reactor = rxn["reactor_name"].as_str().unwrap_or("");
                            if reactor.is_empty() {
                                println!("         {}", emoji);
                            } else {
                                println!("         {} {}", emoji, reactor);
                            }
                        }
                    }
                }
            }
        }
    }
    println!();
}
