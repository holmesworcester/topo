use std::io::{self, IsTerminal};
use std::net::SocketAddr;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use std::os::unix::process::CommandExt;
use std::path::Path;
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
use topo::db::{open_connection, schema::create_tables, sync_log};
use topo::db_registry::DbRegistry;
use topo::rpc::catalog;
use topo::rpc::client::{rpc_call, rpc_call_raw, RpcClientError};
use topo::rpc::protocol::{RpcMethod, PROTOCOL_VERSION};
use topo::rpc::server::{run_rpc_server, DaemonState, RuntimeState};
use topo::service;
use topo::tuning::apply_low_mem_allocator_tuning;
#[cfg(all(target_os = "linux", target_env = "gnu"))]
use topo::tuning::low_mem_mode;

#[derive(Parser)]
#[command(name = "topo")]
#[command(about = "\u{1f42d} Topo \u{2014} peer-to-peer encrypted sync")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Database path
    #[arg(short, long, default_value = "topo.db", global = true)]
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
        #[arg(short, long, default_value = "0.0.0.0:4433")]
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
        /// Device name for this peer (defaults to system hostname)
        #[arg(long)]
        device_name: Option<String>,
        /// Public address to embed in auto-generated invite link
        #[arg(long)]
        public_addr: Option<String>,
    },

    /// Accept a user invite link (bootstrap sync + identity chain creation)
    #[command(name = "accept")]
    AcceptInvite {
        /// Invite link (topo://invite/...)
        invite: String,
        /// Username for the new identity
        #[arg(long, default_value = "user")]
        username: String,
        /// Device name for the new identity (defaults to system hostname)
        #[arg(long)]
        devicename: Option<String>,
    },

    // -------------------------------------------------------------------
    // Daemon-only commands (require a running daemon)
    // -------------------------------------------------------------------
    /// List local tenants (peer identities) in this DB with active marker
    Tenants,

    /// Switch active tenant by number from the tenants list
    #[command(name = "use-tenant")]
    UseTenant {
        /// Tenant number (1-based, from `topo tenants`)
        index: usize,
    },

    /// Show currently active tenant
    #[command(name = "active-tenant")]
    ActiveTenant,

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

    /// List files available to save
    Files {
        /// Max files to show (0 = all)
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// Send a message (uses active peer's workspace)
    Send {
        /// Message content
        content: String,
        /// Client operation ID for local-echo reconciliation
        #[arg(long)]
        client_op_id: Option<String>,
    },

    /// Send a message with a file
    #[command(name = "send-file")]
    SendFile {
        /// Message content
        content: String,
        /// Path to file to attach (reads from stdin or uses placeholder if omitted)
        #[arg(long)]
        file: Option<String>,
        /// Client operation ID for local-echo reconciliation
        #[arg(long)]
        client_op_id: Option<String>,
    },

    /// Save a received file to disk
    #[command(name = "save-file")]
    SaveFile {
        /// File target: number (N or #N from `topo files`) or file event ID (hex)
        /// Defaults to "1" when omitted.
        target: Option<String>,
        /// Deprecated: use positional target instead.
        #[arg(long = "target", hide = true)]
        target_flag: Option<String>,
        /// Output path
        #[arg(long)]
        out: String,
    },

    /// Show database status
    Status,

    /// Generate test messages (uses active peer's workspace)
    Generate {
        #[arg(short, long, default_value = "100")]
        count: usize,
    },

    /// Generate synthetic file events (message + file + file slices)
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
        target: Option<String>,
        /// Deprecated: use positional target instead.
        #[arg(long = "target", hide = true)]
        target_flag: Option<String>,
        /// Client operation ID for local-echo reconciliation
        #[arg(long)]
        client_op_id: Option<String>,
    },

    /// Delete a message
    #[command(name = "delete-message")]
    DeleteMessage {
        /// Target: message number (N or #N) or hex event ID
        target: Option<String>,
        /// Deprecated: use positional target instead.
        #[arg(long = "target", hide = true)]
        target_flag: Option<String>,
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
    Workspaces,

    /// List all known peers (local + remote) with connection endpoint info
    Peers,

    /// Show event dependency tree (requires running daemon)
    #[command(name = "event-tree")]
    EventTree,

    /// List all events with their dependencies (requires running daemon)
    #[command(name = "event-list")]
    EventList,

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
    #[command(name = "invite")]
    CreateInvite {
        /// Public address (host:port) to embed in invite link. Auto-detects if omitted.
        #[arg(long, alias = "bootstrap")]
        public_addr: Option<String>,
        /// Public SPKI fingerprint (hex) — defaults to local transport SPKI
        #[arg(long)]
        public_spki: Option<String>,
    },

    /// Create a device link invite for the active peer's user
    Link {
        /// Public address (host:port) to embed in link. Auto-detects if omitted.
        #[arg(long, alias = "bootstrap")]
        public_addr: Option<String>,
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
        /// Device name for the new identity (defaults to system hostname)
        #[arg(long)]
        devicename: Option<String>,
    },

    /// Ban (remove) a user from the workspace
    Ban {
        /// User number (from `topo users`), #N, or hex event ID
        user: String,
    },

    /// Show combined identity info (transport + user + peer)
    Identity,

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

    /// Subscription commands
    #[command(
        name = "sub",
        visible_alias = "subs",
        after_help = "Examples:\n  topo sub create --name new-messages --event-type message\n  topo sub list\n  topo sub poll new-messages\n  topo sub state              # defaults to the only subscription\n  topo sub disable #1         # by index from `topo sub list`\n  topo sub enable <id>"
    )]
    Sub {
        #[command(subcommand)]
        action: Option<SubAction>,
    },

    /// Deprecated: use `topo sub create`
    #[command(name = "sub-create", hide = true)]
    SubCreate {
        /// Subscription name
        #[arg(long)]
        name: String,
        /// Event type to subscribe to (e.g. "message")
        #[arg(long)]
        event_type: String,
        /// Delivery mode: full|id|has_changed
        #[arg(long, default_value = "full")]
        delivery: String,
        /// Since timestamp (ms) — only match events after this time
        #[arg(long)]
        since_ms: Option<u64>,
        /// Since event ID — only match events after this cursor
        #[arg(long)]
        since_event_id: Option<String>,
        /// JSON spec (overrides --since-ms/--since-event-id if provided)
        #[arg(long)]
        spec: Option<String>,
    },

    /// Deprecated: use `topo sub list`
    #[command(name = "sub-list", hide = true)]
    SubList,

    /// Deprecated: use `topo sub poll`
    #[command(name = "sub-poll", hide = true)]
    SubPoll {
        /// Subscription selector: id, name, or index (#N / N)
        sub: Option<String>,
        /// Deprecated: use positional selector instead.
        #[arg(long = "sub", hide = true)]
        sub_flag: Option<String>,
        /// Only return items after this seq (exclusive)
        #[arg(long, default_value = "0")]
        after_seq: i64,
        /// Max items to return
        #[arg(long, default_value = "50")]
        limit: usize,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Deprecated: use `topo sub state`
    #[command(name = "sub-state", hide = true)]
    SubState {
        /// Subscription selector: id, name, or index (#N / N)
        sub: Option<String>,
        /// Deprecated: use positional selector instead.
        #[arg(long = "sub", hide = true)]
        sub_flag: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Deprecated: use `topo sub ack`
    #[command(name = "sub-ack", hide = true)]
    SubAck {
        /// Subscription selector: id, name, or index (#N / N)
        sub: Option<String>,
        /// Deprecated: use positional selector instead.
        #[arg(long = "sub", hide = true)]
        sub_flag: Option<String>,
        /// Acknowledge through this seq (inclusive)
        #[arg(long)]
        through_seq: i64,
    },

    /// Deprecated: use `topo sub disable`
    #[command(name = "sub-disable", hide = true)]
    SubDisable {
        /// Subscription selector: id, name, or index (#N / N)
        sub: Option<String>,
        /// Deprecated: use positional selector instead.
        #[arg(long = "sub", hide = true)]
        sub_flag: Option<String>,
    },

    /// Deprecated: use `topo sub enable`
    #[command(name = "sub-enable", hide = true)]
    SubEnable {
        /// Subscription selector: id, name, or index (#N / N)
        sub: Option<String>,
        /// Deprecated: use positional selector instead.
        #[arg(long = "sub", hide = true)]
        sub_flag: Option<String>,
    },

    /// Enable persistent sync logging (off by default)
    #[command(name = "sync-log-enable")]
    SyncLogEnable {
        /// Include match-only runs (default stores changed runs only)
        #[arg(long, default_value_t = false)]
        all_runs: bool,
        /// Capture full ID lists in log details (larger DB growth)
        #[arg(long, default_value_t = false)]
        capture_full_ids: bool,
    },

    /// Disable persistent sync logging
    #[command(name = "sync-log-disable")]
    SyncLogDisable,

    /// Show sync logging configuration
    #[command(name = "sync-log-config")]
    SyncLogConfig,

    /// Show sync log trace history
    #[command(name = "sync-log")]
    SyncLog {
        /// Max runs to show
        #[arg(long, default_value = "5")]
        limit: usize,
        /// Show one specific run id
        #[arg(long)]
        run: Option<i64>,
        /// Filter by peer id prefix
        #[arg(long)]
        peer: Option<String>,
        /// Include runs that matched with no data transfer
        #[arg(long)]
        all: bool,
    },

    /// Show sync history in tree form
    #[command(name = "sync-log-tree")]
    SyncLogTree {
        /// Max runs to show
        #[arg(long, default_value = "5")]
        limit: usize,
        /// Show one specific run id
        #[arg(long)]
        run: Option<i64>,
        /// Filter by peer id prefix
        #[arg(long)]
        peer: Option<String>,
        /// Include runs that matched with no data transfer
        #[arg(long)]
        all: bool,
    },

    /// Raw RPC demo surface: list methods, describe parameters, submit raw JSON calls
    #[command(
        after_help = "Examples:\n  # List all available RPC methods\n  topo rpc methods\n  topo rpc methods --json\n\n  # Describe a method and its parameters\n  topo rpc describe Status\n  topo rpc describe Send --json\n\n  # Call an RPC method (inline JSON)\n  topo rpc call --method-json '{\"type\":\"Status\"}'\n  topo rpc call --method-json '{\"type\":\"Send\",\"content\":\"hello\"}'\n  topo rpc call --method-json '{\"type\":\"Messages\",\"limit\":20}'\n  topo rpc call --method-json '{\"type\":\"View\",\"limit\":10}'\n\n  # Call with a full request envelope\n  topo rpc call --request-json '{\"version\":1,\"method\":{\"type\":\"Status\"}}'\n\n  # Call from a file or stdin\n  topo rpc call --file request.json\n  echo '{\"type\":\"Peers\"}' | topo rpc call --stdin"
    )]
    Rpc {
        #[command(subcommand)]
        action: RpcAction,
    },

    /// Attempt UPnP port forwarding for the daemon's QUIC listen port.
    /// Requires daemon listening on non-loopback (for example `--bind 0.0.0.0:...`).
    Upnp,

    /// Reset all local state: stop daemon, delete DB and socket files
    Reset,
}

#[derive(Subcommand)]
enum RpcAction {
    /// List all available RPC methods
    Methods {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Describe a specific RPC method and its parameters
    Describe {
        /// Method name (case-insensitive)
        method: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Submit a raw RPC call using JSON
    Call {
        /// JSON-encoded RpcMethod (auto-wrapped in request envelope)
        #[arg(long, group = "input")]
        method_json: Option<String>,
        /// JSON-encoded full RpcRequest
        #[arg(long, group = "input")]
        request_json: Option<String>,
        /// Read full RpcRequest JSON from a file
        #[arg(long, group = "input")]
        file: Option<String>,
        /// Read full RpcRequest JSON from stdin
        #[arg(long, group = "input")]
        stdin: bool,
    },
}

#[derive(Subcommand)]
enum SubAction {
    /// Create a local subscription
    Create {
        /// Subscription name
        #[arg(long)]
        name: String,
        /// Event type to subscribe to (e.g. "message")
        #[arg(long)]
        event_type: String,
        /// Delivery mode: full|id|has_changed
        #[arg(long, default_value = "full")]
        delivery: String,
        /// Since timestamp (ms) — only match events after this time
        #[arg(long)]
        since_ms: Option<u64>,
        /// Since event ID — only match events after this cursor
        #[arg(long)]
        since_event_id: Option<String>,
        /// JSON spec (overrides --since-ms/--since-event-id if provided)
        #[arg(long)]
        spec: Option<String>,
    },
    /// List subscriptions
    List,
    /// Poll subscription feed
    Poll {
        /// Subscription selector: id, name, or index (#N / N)
        sub: Option<String>,
        /// Deprecated: use positional selector instead.
        #[arg(long = "sub", hide = true)]
        sub_flag: Option<String>,
        /// Only return items after this seq (exclusive)
        #[arg(long, default_value = "0")]
        after_seq: i64,
        /// Max items to return
        #[arg(long, default_value = "50")]
        limit: usize,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Get subscription state (pending count, dirty flag, cursors)
    State {
        /// Subscription selector: id, name, or index (#N / N)
        sub: Option<String>,
        /// Deprecated: use positional selector instead.
        #[arg(long = "sub", hide = true)]
        sub_flag: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Acknowledge feed items through a given seq
    Ack {
        /// Subscription selector: id, name, or index (#N / N)
        sub: Option<String>,
        /// Deprecated: use positional selector instead.
        #[arg(long = "sub", hide = true)]
        sub_flag: Option<String>,
        /// Acknowledge through this seq (inclusive)
        #[arg(long)]
        through_seq: i64,
    },
    /// Disable a subscription
    Disable {
        /// Subscription selector: id, name, or index (#N / N)
        sub: Option<String>,
        /// Deprecated: use positional selector instead.
        #[arg(long = "sub", hide = true)]
        sub_flag: Option<String>,
    },
    /// Enable a subscription
    Enable {
        /// Subscription selector: id, name, or index (#N / N)
        sub: Option<String>,
        /// Deprecated: use positional selector instead.
        #[arg(long = "sub", hide = true)]
        sub_flag: Option<String>,
    },
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

/// Validate that a JSON value looks like an RpcRequest envelope before sending.
fn validate_request_envelope(v: &serde_json::Value) {
    if v.get("version").is_none() {
        eprintln!("error: request JSON must have a \"version\" field");
        eprintln!(
            "  Hint: did you mean --method-json? (auto-wraps in {{\"version\":1,\"method\":...}})"
        );
        eprintln!("  Full request format: {{\"version\":1,\"method\":{{\"type\":\"Status\"}}}}");
        std::process::exit(1);
    }
    if !v["version"].is_number() {
        eprintln!("error: \"version\" must be a number, got: {}", v["version"]);
        std::process::exit(1);
    }
    if v.get("method").is_none() || v["method"].is_null() {
        eprintln!("error: request JSON must have a \"method\" field");
        eprintln!("  Full request format: {{\"version\":1,\"method\":{{\"type\":\"Status\"}}}}");
        std::process::exit(1);
    }
    // Try to deserialize the method portion for better errors.
    if let Err(e) = serde_json::from_value::<RpcMethod>(v["method"].clone()) {
        eprintln!("error: invalid method in request: {}", e);
        if let Some(type_name) = v["method"].get("type").and_then(|t| t.as_str()) {
            eprintln!(
                "  Hint: run `topo rpc describe {}` to see required parameters",
                type_name
            );
        }
        std::process::exit(1);
    }
}

fn target_socket_path(db: &str, socket: Option<&str>) -> PathBuf {
    socket
        .map(PathBuf::from)
        .unwrap_or_else(|| service::socket_path_for_db(db))
}

fn rpc_require_daemon(
    db: &str,
    socket: Option<&str>,
    method: RpcMethod,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let sock = target_socket_path(db, socket);

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
            "daemon is not running for {} — start it with: topo --db {} start",
            db, db
        )
        .into()),
        Err(e) => Err(e.to_string().into()),
    }
}

/// Resolve the --db argument using the registry:
/// - If --db is the clap default "topo.db" and a registry default exists, use it
/// - Otherwise run selector resolution (existing path → alias → index → passthrough)
fn resolve_db_arg(raw: &str) -> Result<String, String> {
    let registry = DbRegistry::load();
    if raw == "topo.db" {
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

fn resolve_send_file_path(
    file: Option<String>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let mut candidate = file
        .map(|path| path.trim().to_string())
        .filter(|p| !p.is_empty());

    // Optional convenience: when --file is omitted, accept a path from piped stdin.
    if candidate.is_none() && !io::stdin().is_terminal() {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        let trimmed = buf.trim();
        if !trimmed.is_empty() {
            candidate = Some(trimmed.to_string());
        }
    }

    match candidate {
        Some(path) => {
            let input = Path::new(&path);
            let abs = if input.is_absolute() {
                input.to_path_buf()
            } else {
                std::env::current_dir()?.join(input)
            };
            if !abs.exists() {
                return Err(format!("file does not exist: {}", abs.display()).into());
            }
            if !abs.is_file() {
                return Err(format!("path is not a file: {}", abs.display()).into());
            }
            Ok(abs.to_string_lossy().to_string())
        }
        None => {
            let tmp = std::env::temp_dir().join("topo-placeholder.txt");
            std::fs::write(&tmp, "placeholder file\n")
                .map_err(|e| format!("failed to create placeholder: {}", e))?;
            Ok(tmp.to_string_lossy().to_string())
        }
    }
}

fn resolve_target_selector(
    positional: Option<String>,
    deprecated_flag: Option<String>,
    command_name: &str,
    default_when_missing: Option<&str>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    match (positional, deprecated_flag) {
        (Some(_), Some(_)) => Err(format!(
            "conflicting target selectors for `{}`: pass either positional target or deprecated --target, not both",
            command_name
        )
        .into()),
        (Some(target), None) => Ok(target),
        (None, Some(target)) => {
            eprintln!(
                "warning: `--target` is deprecated for `{}`; pass target positionally instead",
                command_name
            );
            Ok(target)
        }
        (None, None) => match default_when_missing {
            Some(default_target) => Ok(default_target.to_string()),
            None => Err(format!(
                "missing target for `{}`: pass it positionally (for example `{}`)",
                command_name,
                match command_name {
                    "react" => "topo react thumbsup 1",
                    "delete-message" => "topo delete-message 1",
                    "save-file" => "topo save-file 1 --out /tmp/file.bin",
                    _ => "topo <command> <target>",
                }
            )
            .into()),
        },
    }
}

#[derive(Debug, Clone)]
struct SubscriptionRef {
    subscription_id: String,
    name: String,
}

fn list_subscription_refs(
    db: &str,
    socket: Option<&str>,
) -> Result<Vec<SubscriptionRef>, Box<dyn std::error::Error + Send + Sync>> {
    let data = rpc_require_daemon(db, socket, RpcMethod::SubList)?;
    let items = data
        .as_array()
        .ok_or_else(|| "unexpected sub-list response shape".to_string())?;
    let mut refs = Vec::with_capacity(items.len());
    for item in items {
        let sub_id = item["subscription_id"].as_str().unwrap_or("").to_string();
        if sub_id.is_empty() {
            continue;
        }
        let name = item["name"].as_str().unwrap_or("").to_string();
        refs.push(SubscriptionRef {
            subscription_id: sub_id,
            name,
        });
    }
    Ok(refs)
}

fn resolve_subscription_selector(
    db: &str,
    socket: Option<&str>,
    positional: Option<String>,
    deprecated_flag: Option<String>,
    command_name: &str,
    default_if_single: bool,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let selector = match (positional, deprecated_flag) {
        (Some(_), Some(_)) => {
            return Err(format!(
                "conflicting selectors for `{}`: pass either positional selector or deprecated --sub, not both",
                command_name
            )
            .into())
        }
        (Some(s), None) => Some(s),
        (None, Some(s)) => {
            eprintln!(
                "warning: `--sub` is deprecated for `{}`; pass selector positionally instead",
                command_name
            );
            Some(s)
        }
        (None, None) => None,
    }
    .map(|s| s.trim().to_string())
    .filter(|s| !s.is_empty());

    let refs = list_subscription_refs(db, socket)?;
    if refs.is_empty() {
        return Err(
            "no subscriptions found — run `topo sub create --name ... --event-type message` first"
                .into(),
        );
    }

    let Some(selector) = selector else {
        if default_if_single && refs.len() == 1 {
            return Ok(refs[0].subscription_id.clone());
        }
        return Err(format!(
            "missing subscription selector for `{}`; pass id/name/#N (run `topo sub list`)",
            command_name
        )
        .into());
    };

    let selector_no_hash = selector.strip_prefix('#').unwrap_or(&selector);
    if let Ok(index) = selector_no_hash.parse::<usize>() {
        if index == 0 || index > refs.len() {
            return Err(format!(
                "invalid subscription index {}; available: 1-{}",
                index,
                refs.len()
            )
            .into());
        }
        return Ok(refs[index - 1].subscription_id.clone());
    }

    if let Some(found) = refs.iter().find(|r| r.subscription_id == selector) {
        return Ok(found.subscription_id.clone());
    }

    let matches: Vec<&SubscriptionRef> = refs.iter().filter(|r| r.name == selector).collect();
    match matches.len() {
        1 => Ok(matches[0].subscription_id.clone()),
        0 => Err(format!(
            "subscription selector `{}` not found; run `topo sub list` for available ids/names",
            selector
        )
        .into()),
        _ => Err(format!(
            "subscription name `{}` is ambiguous; use subscription id instead",
            selector
        )
        .into()),
    }
}

fn run_sub_action(
    db: &str,
    socket: Option<&str>,
    action: SubAction,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match action {
        SubAction::Create {
            name,
            event_type,
            delivery,
            since_ms,
            since_event_id,
            spec,
        } => {
            let spec_json = if let Some(raw) = spec {
                raw
            } else {
                let since = if since_ms.is_some() || since_event_id.is_some() {
                    Some(serde_json::json!({
                        "created_at_ms": since_ms.unwrap_or(0),
                        "event_id": since_event_id.unwrap_or_default(),
                    }))
                } else {
                    None
                };
                let spec_obj = serde_json::json!({
                    "event_type": event_type,
                    "since": since,
                    "filters": [],
                });
                serde_json::to_string(&spec_obj).unwrap()
            };
            let data = rpc_require_daemon(
                db,
                socket,
                RpcMethod::SubCreate {
                    name,
                    event_type,
                    delivery_mode: delivery,
                    spec_json,
                },
            )?;
            let sub_id = data["subscription_id"].as_str().unwrap_or("?");
            let sub_name = data["name"].as_str().unwrap_or("?");
            println!("Created subscription \"{}\" (id: {})", sub_name, sub_id);
            Ok(())
        }
        SubAction::List => {
            let data = rpc_require_daemon(db, socket, RpcMethod::SubList)?;
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("No subscriptions.");
                } else {
                    println!("SUBSCRIPTIONS:");
                    for (idx, item) in items.iter().enumerate() {
                        let enabled = if item["enabled"].as_bool().unwrap_or(false) {
                            "on"
                        } else {
                            "off"
                        };
                        let name = item["name"].as_str().unwrap_or("?");
                        let sub_id = item["subscription_id"].as_str().unwrap_or("?");
                        let et = item["event_type"].as_str().unwrap_or("?");
                        let dm = item["delivery_mode"].as_str().unwrap_or("?");
                        println!(
                            "  {}. [{}] \"{}\" type={} delivery={} id={}",
                            idx + 1,
                            enabled,
                            name,
                            et,
                            dm,
                            sub_id
                        );
                    }
                }
            }
            Ok(())
        }
        SubAction::Poll {
            sub,
            sub_flag,
            after_seq,
            limit,
            json,
        } => {
            let sub_id =
                resolve_subscription_selector(db, socket, sub, sub_flag, "sub poll", true)?;
            let data = rpc_require_daemon(
                db,
                socket,
                RpcMethod::SubPoll {
                    subscription_id: sub_id,
                    after_seq,
                    limit,
                },
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_default()
                );
            } else if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("(no new items)");
                } else {
                    for item in items {
                        let seq = item["seq"].as_i64().unwrap_or(0);
                        let etype = item["event_type"].as_str().unwrap_or("?");
                        let eid = item["event_id"].as_str().unwrap_or("?");
                        let payload = &item["payload"];
                        if let Some(content) = payload["content"].as_str() {
                            println!(
                                "  seq={} {} event={} content={:?}",
                                seq,
                                etype,
                                &eid[..eid.len().min(12)],
                                content
                            );
                        } else {
                            println!(
                                "  seq={} {} event={}",
                                seq,
                                etype,
                                &eid[..eid.len().min(12)]
                            );
                        }
                    }
                }
            }
            Ok(())
        }
        SubAction::State {
            sub,
            sub_flag,
            json,
        } => {
            let sub_id =
                resolve_subscription_selector(db, socket, sub, sub_flag, "sub state", true)?;
            let data = rpc_require_daemon(
                db,
                socket,
                RpcMethod::SubState {
                    subscription_id: sub_id,
                },
            )?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&data).unwrap_or_default()
                );
            } else {
                let pending = data["pending_count"].as_i64().unwrap_or(0);
                let dirty = data["dirty"].as_bool().unwrap_or(false);
                let next_seq = data["next_seq"].as_i64().unwrap_or(0);
                let latest = data["latest_event_id"].as_str().unwrap_or("");
                println!(
                    "pending={} dirty={} next_seq={} latest_event={}",
                    pending,
                    dirty,
                    next_seq,
                    if latest.is_empty() {
                        "(none)"
                    } else {
                        &latest[..latest.len().min(12)]
                    },
                );
            }
            Ok(())
        }
        SubAction::Ack {
            sub,
            sub_flag,
            through_seq,
        } => {
            let sub_id = resolve_subscription_selector(db, socket, sub, sub_flag, "sub ack", true)?;
            let _data = rpc_require_daemon(
                db,
                socket,
                RpcMethod::SubAck {
                    subscription_id: sub_id,
                    through_seq,
                },
            )?;
            println!("Acked through seq {}", through_seq);
            Ok(())
        }
        SubAction::Disable { sub, sub_flag } => {
            let sub_id =
                resolve_subscription_selector(db, socket, sub, sub_flag, "sub disable", true)?;
            let _data = rpc_require_daemon(
                db,
                socket,
                RpcMethod::SubDisable {
                    subscription_id: sub_id,
                },
            )?;
            println!("Subscription disabled.");
            Ok(())
        }
        SubAction::Enable { sub, sub_flag } => {
            let sub_id =
                resolve_subscription_selector(db, socket, sub, sub_flag, "sub enable", true)?;
            let _data = rpc_require_daemon(
                db,
                socket,
                RpcMethod::SubEnable {
                    subscription_id: sub_id,
                },
            )?;
            println!("Subscription enabled.");
            Ok(())
        }
    }
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
    // Clear stale UPnP result — the port may change across restarts.
    *state.runtime_state.write().unwrap() = RuntimeState::IdleNoTenants;
    *state.runtime_net.write().unwrap() = None;
    *state.upnp_result.write().unwrap() = None;

    let runtime_shutdown = Arc::new(tokio::sync::Notify::new());
    let runtime_shutdown_for_task = runtime_shutdown.clone();
    let db_for_task = db_path.to_string();

    let (net_tx, net_rx) = tokio::sync::oneshot::channel::<topo::node::NodeRuntimeNetInfo>();
    let state_for_net = state.clone();
    tokio::spawn(async move {
        if let Ok(mut info) = net_rx.await {
            println!("listen: {}", info.listen_addr);
            // Carry forward daemon-level UPnP result only if the port matches.
            if info.upnp.is_none() {
                let prior = state_for_net.upnp_result.read().unwrap().clone();
                if let Some(ref report) = prior {
                    if report.requested_external_port
                        == info
                            .listen_addr
                            .parse::<std::net::SocketAddr>()
                            .map(|a| a.port())
                            .unwrap_or(0)
                    {
                        info.upnp = prior;
                    }
                }
            }
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
        Commands::Start { .. } => {
            let level = match std::env::var("RUST_LOG").ok().as_deref() {
                Some("trace") => Level::TRACE,
                Some("debug") => Level::DEBUG,
                Some("info") => Level::INFO,
                Some("error") => Level::ERROR,
                _ => Level::WARN,
            };
            let subscriber = FmtSubscriber::builder().with_max_level(level).finish();
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

            // Record the bind address early so UPnP can run before any tenants
            // exist.  Only useful for fixed ports — with port 0 the real port
            // is unknown until the QUIC runtime binds, so we leave it as None.
            let resolved_bind: Option<SocketAddr> =
                if bind.port() != 0 { Some(bind) } else { None };

            let shutdown = Arc::new(AtomicBool::new(false));
            let shutdown_notify = Arc::new(tokio::sync::Notify::new());
            let state = Arc::new(DaemonState::new(db));
            *state.bind_addr.write().unwrap() = resolved_bind;

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
            public_addr,
        } => {
            let device_name = device_name.unwrap_or_else(system_hostname);
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::CreateWorkspace {
                    workspace_name,
                    username,
                    device_name,
                },
            )?;
            println!(
                "peer_id:      {}",
                short_id(data["peer_id"].as_str().unwrap_or(""))
            );
            println!(
                "workspace_id: {}",
                short_id(data["workspace_id"].as_str().unwrap_or(""))
            );

            // Server auto-creates an invite with detected IPs
            if let Some(link) = data["invite_link"].as_str() {
                println!("invite:       {}", link);
            } else if let Some(err) = data["invite_error"].as_str() {
                eprintln!("warning: workspace created but auto-invite failed: {}", err);
            }

            // If --public-addr was given, create an additional invite with that address
            if let Some(addr) = public_addr {
                let sock = target_socket_path(db, socket_override.as_deref());
                match rpc_call(
                    &sock,
                    RpcMethod::CreateInvite {
                        public_addr: Some(addr),
                        public_spki: None,
                    },
                ) {
                    Ok(resp) if resp.ok => {
                        if let Some(link) =
                            resp.data.as_ref().and_then(|d| d["invite_link"].as_str())
                        {
                            println!("invite:       {}", link);
                        }
                    }
                    _ => {
                        eprintln!("warning: explicit-addr invite generation failed");
                    }
                }
            }
        }

        Commands::AcceptInvite {
            invite,
            username,
            devicename,
        } => {
            let devicename = devicename.unwrap_or_else(system_hostname);
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
            println!(
                "  peer_id: {}",
                short_id(data["peer_id"].as_str().unwrap_or(""))
            );
            println!(
                "  user:    {}",
                short_id(data["user_event_id"].as_str().unwrap_or(""))
            );
            println!(
                "  peer:    {}",
                short_id(data["peer_shared_event_id"].as_str().unwrap_or(""))
            );
        }

        // ---------------------------------------------------------------
        // Daemon-only commands (require running daemon)
        // ---------------------------------------------------------------
        Commands::Tenants => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Tenants)?;
            println!("TENANTS ({}):", db);
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

        Commands::UseTenant { index } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::UseTenant { index },
            )?;
            let peer_id = data["peer_id"].as_str().unwrap_or("");
            let ws_id = data["workspace_id"].as_str().unwrap_or("");
            println!(
                "Switched to tenant {} (workspace: {})",
                short_id(peer_id),
                short_id(ws_id)
            );
        }

        Commands::ActiveTenant => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::ActiveTenant)?;
            match data["peer_id"].as_str() {
                Some(peer_id) => println!("{}", peer_id),
                None => println!("(no active tenant)"),
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

        Commands::Files { limit } => {
            let data =
                rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Files { limit })?;
            show_files_from_json(&data);
        }

        Commands::Send {
            content,
            client_op_id,
        } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::Send {
                    content: content.clone(),
                    client_op_id,
                },
            )?;
            let event_id = data["event_id"].as_str().unwrap_or("");
            println!("Sent: {}", data["content"].as_str().unwrap_or(&content));
            println!("event_id:{}", event_id);
        }

        Commands::SendFile {
            content,
            file,
            client_op_id,
        } => {
            let file_path = resolve_send_file_path(file)?;
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::SendFile {
                    content: content.clone(),
                    file_path,
                    client_op_id,
                },
            )?;
            let event_id = data["event_id"].as_str().unwrap_or("");
            let filename = data["filename"].as_str().unwrap_or("");
            let file_size = data["file_size"].as_i64().unwrap_or(0);
            println!("Sent: {}", data["content"].as_str().unwrap_or(&content));
            println!("\u{1f4ce} {} ({})", filename, format_byte_size(file_size));
            println!("event_id:{}", event_id);
        }

        Commands::SaveFile {
            target,
            target_flag,
            out,
        } => {
            let target = resolve_target_selector(target, target_flag, "save-file", Some("1"))?;
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::SaveFile {
                    target,
                    output_path: out,
                },
            )?;
            println!(
                "saved {} bytes to {}",
                data["bytes_written"].as_u64().unwrap_or(0),
                data["output_path"].as_str().unwrap_or("")
            );
            println!(
                "file_event_id:{}",
                data["file_event_id"].as_str().unwrap_or("")
            );
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

        Commands::React {
            emoji,
            target,
            target_flag,
            client_op_id,
        } => {
            let target = resolve_target_selector(target, target_flag, "react", None)?;
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::React {
                    target,
                    emoji: emoji.clone(),
                    client_op_id,
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

        Commands::DeleteMessage {
            target,
            target_flag,
        } => {
            let target = resolve_target_selector(target, target_flag, "delete-message", None)?;
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

        Commands::Workspaces => {
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

        Commands::Peers => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::Peers)?;
            println!("PEERS ({}):", db);
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("  (none)");
                } else {
                    for (i, item) in items.iter().enumerate() {
                        let peer_id = item["peer_id"].as_str().unwrap_or("");
                        let device_name = item["device_name"].as_str().unwrap_or("");
                        let username = item["username"].as_str().unwrap_or("");
                        let is_local = item["local"].as_bool().unwrap_or(false);
                        let endpoint = item["endpoint"].as_str();

                        let label = if !username.is_empty() && !device_name.is_empty() {
                            format!("{}@{}", username, device_name)
                        } else if !username.is_empty() {
                            username.to_string()
                        } else if !device_name.is_empty() {
                            device_name.to_string()
                        } else {
                            String::new()
                        };

                        let location = if is_local {
                            "local".to_string()
                        } else if let Some(ep) = endpoint {
                            ep.to_string()
                        } else {
                            "remote".to_string()
                        };

                        if label.is_empty() {
                            println!("  {}. {} [{}]", i + 1, short_id(peer_id), location);
                        } else {
                            println!(
                                "  {}. {} ({}) [{}]",
                                i + 1,
                                label,
                                short_id(peer_id),
                                location
                            );
                        }
                    }
                }
            } else {
                println!("  (none)");
            }
        }

        Commands::EventTree => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::EventList)?;
            let resp: service::EventListResponse = serde_json::from_value(data)?;
            print_event_tree(&resp.events);
        }

        Commands::EventList => {
            let data = rpc_require_daemon(db, socket_override.as_deref(), RpcMethod::EventList)?;
            let resp: service::EventListResponse = serde_json::from_value(data)?;
            print_event_list(&resp.events);
        }

        Commands::Intro {
            peer_a,
            peer_b,
            ttl_ms,
            attempt_window_ms,
        } => {
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::Intro {
                    peer_a,
                    peer_b,
                    ttl_ms,
                    attempt_window_ms,
                },
            )?;
            if data
                .get("sent_to_both")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                println!("Intro sent to both peers");
            } else {
                eprintln!("Intro failed: {}", data);
                std::process::exit(1);
            }
        }

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
            let devicename = devicename.unwrap_or_else(system_hostname);
            let data = rpc_require_daemon(
                db,
                socket_override.as_deref(),
                RpcMethod::AcceptLink { invite, devicename },
            )?;
            let peer_id = data["peer_id"].as_str().unwrap_or("");
            println!("Accepted device link");
            println!("  peer_id: {}", short_id(peer_id));
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

        // ---------------------------------------------------------------
        // Subscription commands
        // ---------------------------------------------------------------
        Commands::Sub { action } => {
            let action = action.unwrap_or(SubAction::List);
            run_sub_action(db, socket_override.as_deref(), action)?;
        }
        Commands::SubCreate {
            name,
            event_type,
            delivery,
            since_ms,
            since_event_id,
            spec,
        } => {
            eprintln!("warning: `topo sub-create` is deprecated; use `topo sub create`");
            run_sub_action(
                db,
                socket_override.as_deref(),
                SubAction::Create {
                    name,
                    event_type,
                    delivery,
                    since_ms,
                    since_event_id,
                    spec,
                },
            )?;
        }
        Commands::SubList => {
            eprintln!("warning: `topo sub-list` is deprecated; use `topo sub list`");
            run_sub_action(db, socket_override.as_deref(), SubAction::List)?;
        }
        Commands::SubPoll {
            sub,
            sub_flag,
            after_seq,
            limit,
            json,
        } => {
            eprintln!("warning: `topo sub-poll` is deprecated; use `topo sub poll`");
            run_sub_action(
                db,
                socket_override.as_deref(),
                SubAction::Poll {
                    sub,
                    sub_flag,
                    after_seq,
                    limit,
                    json,
                },
            )?;
        }
        Commands::SubState {
            sub,
            sub_flag,
            json,
        } => {
            eprintln!("warning: `topo sub-state` is deprecated; use `topo sub state`");
            run_sub_action(
                db,
                socket_override.as_deref(),
                SubAction::State {
                    sub,
                    sub_flag,
                    json,
                },
            )?;
        }
        Commands::SubAck {
            sub,
            sub_flag,
            through_seq,
        } => {
            eprintln!("warning: `topo sub-ack` is deprecated; use `topo sub ack`");
            run_sub_action(
                db,
                socket_override.as_deref(),
                SubAction::Ack {
                    sub,
                    sub_flag,
                    through_seq,
                },
            )?;
        }
        Commands::SubDisable { sub, sub_flag } => {
            eprintln!("warning: `topo sub-disable` is deprecated; use `topo sub disable`");
            run_sub_action(
                db,
                socket_override.as_deref(),
                SubAction::Disable { sub, sub_flag },
            )?;
        }
        Commands::SubEnable { sub, sub_flag } => {
            eprintln!("warning: `topo sub-enable` is deprecated; use `topo sub enable`");
            run_sub_action(
                db,
                socket_override.as_deref(),
                SubAction::Enable { sub, sub_flag },
            )?;
        }

        Commands::SyncLogEnable {
            all_runs,
            capture_full_ids,
        } => {
            let conn = open_connection(db)?;
            create_tables(&conn)?;
            let cfg = sync_log::update_config(
                &conn,
                sync_log::SyncLogConfigPatch {
                    enabled: Some(true),
                    changed_only: Some(!all_runs),
                    capture_full_ids: Some(capture_full_ids),
                    ..Default::default()
                },
            )?;
            print_sync_log_config(&cfg);
        }

        Commands::SyncLogDisable => {
            let conn = open_connection(db)?;
            create_tables(&conn)?;
            let cfg = sync_log::update_config(
                &conn,
                sync_log::SyncLogConfigPatch {
                    enabled: Some(false),
                    ..Default::default()
                },
            )?;
            print_sync_log_config(&cfg);
        }

        Commands::SyncLogConfig => {
            let conn = open_connection(db)?;
            create_tables(&conn)?;
            let cfg = sync_log::load_config(&conn)?;
            print_sync_log_config(&cfg);
        }

        Commands::SyncLog {
            limit,
            run,
            peer,
            all,
        } => {
            let conn = open_connection(db)?;
            create_tables(&conn)?;
            let runs = sync_log::list_runs(&conn, limit, all, run, peer.as_deref())?;
            if runs.is_empty() {
                println!("No sync runs logged.");
            } else {
                if !all {
                    println!("Showing changed/error runs only (use --all for full history).");
                    println!();
                }
                for (idx, r) in runs.iter().enumerate() {
                    let events = sync_log::list_run_events(&conn, r.run_id)?;
                    print_sync_trace_run(r, &events);
                    if idx + 1 < runs.len() {
                        println!();
                    }
                }
            }
        }

        Commands::SyncLogTree {
            limit,
            run,
            peer,
            all,
        } => {
            let conn = open_connection(db)?;
            create_tables(&conn)?;
            let runs = sync_log::list_runs(&conn, limit, all, run, peer.as_deref())?;
            if runs.is_empty() {
                println!("No sync runs logged.");
            } else {
                if !all {
                    println!("Showing changed/error runs only (use --all for full history).");
                    println!();
                }
                let mut run_events = Vec::with_capacity(runs.len());
                for r in runs {
                    let events = sync_log::list_run_events(&conn, r.run_id)?;
                    run_events.push((r, events));
                }
                let groups = group_runs_by_peer(run_events);
                print_sync_tree_groups(&groups);
            }
        }

        // ---------------------------------------------------------------
        // RPC demo surface
        // ---------------------------------------------------------------
        Commands::Rpc { action } => match action {
            RpcAction::Methods { json } => {
                let methods = catalog::all_methods();
                if json {
                    println!("{}", serde_json::to_string_pretty(&methods).unwrap());
                } else {
                    println!("RPC METHODS ({}):\n", methods.len());
                    for m in methods {
                        println!("  {:<22} {}", m.name, m.purpose);
                    }
                }
            }
            RpcAction::Describe { method, json } => {
                let method = method.trim();
                match catalog::describe(method) {
                    Some(info) => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&info).unwrap());
                        } else {
                            println!("{}:", info.name);
                            println!("  {}\n", info.purpose);
                            if info.params.is_empty() {
                                println!("  Parameters: (none)");
                            } else {
                                println!("  Parameters:");
                                for p in info.params {
                                    let req = if p.required { "required" } else { "optional" };
                                    let default = match p.default {
                                        Some(d) => format!(", default={}", d),
                                        None => String::new(),
                                    };
                                    println!(
                                        "    {:<20} {} ({}{})",
                                        p.name, p.param_type, req, default
                                    );
                                }
                            }
                            println!("\n  Example:");
                            println!("    {}", info.example_json);
                        }
                    }
                    None => {
                        eprintln!("error: unknown method {:?}", method);
                        eprintln!("  Run `topo rpc methods` to see available methods.");
                        std::process::exit(1);
                    }
                }
            }
            RpcAction::Call {
                method_json,
                request_json,
                file,
                stdin,
            } => {
                let sock = target_socket_path(db, socket_override.as_deref());

                // Parse the input into a JSON value representing a full RpcRequest.
                let request_value: serde_json::Value = if let Some(mj) = method_json {
                    // method_json: parse as RpcMethod, wrap in request envelope.
                    // Pre-validate by deserializing as RpcMethod — gives specific
                    // serde errors (missing field, wrong type, unknown variant)
                    // instead of a generic "daemon closed connection" later.
                    let _method: RpcMethod = serde_json::from_str(&mj).map_err(|e| {
                        eprintln!("error: invalid method JSON: {}", e);
                        if let Some(type_name) = serde_json::from_str::<serde_json::Value>(&mj)
                            .ok()
                            .and_then(|v| v.get("type").and_then(|t| t.as_str()).map(String::from))
                        {
                            eprintln!("  Hint: run `topo rpc describe {}` to see required parameters", type_name);
                        } else {
                            eprintln!("  Hint: method JSON must have a \"type\" field (e.g. {{\"type\":\"Status\"}})");
                        }
                        std::process::exit(1);
                    }).unwrap();
                    let method_val: serde_json::Value = serde_json::from_str(&mj).unwrap();
                    serde_json::json!({
                        "version": PROTOCOL_VERSION,
                        "method": method_val
                    })
                } else if let Some(rj) = request_json {
                    let v: serde_json::Value = serde_json::from_str(&rj)
                        .map_err(|e| {
                            eprintln!("error: invalid request JSON: {}", e);
                            std::process::exit(1);
                        })
                        .unwrap();
                    validate_request_envelope(&v);
                    v
                } else if let Some(path) = file {
                    let contents = std::fs::read_to_string(&path)
                        .map_err(|e| {
                            eprintln!("error: cannot read file {:?}: {}", path, e);
                            std::process::exit(1);
                        })
                        .unwrap();
                    let v: serde_json::Value = serde_json::from_str(&contents)
                        .map_err(|e| {
                            eprintln!("error: invalid JSON in file {:?}: {}", path, e);
                            std::process::exit(1);
                        })
                        .unwrap();
                    validate_request_envelope(&v);
                    v
                } else if stdin {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
                        .map_err(|e| {
                            eprintln!("error: failed to read stdin: {}", e);
                            std::process::exit(1);
                        })
                        .unwrap();
                    let v: serde_json::Value = serde_json::from_str(&buf)
                        .map_err(|e| {
                            eprintln!("error: invalid JSON from stdin: {}", e);
                            std::process::exit(1);
                        })
                        .unwrap();
                    validate_request_envelope(&v);
                    v
                } else {
                    eprintln!(
                        "error: specify one of --method-json, --request-json, --file, or --stdin"
                    );
                    std::process::exit(1);
                };

                match rpc_call_raw(&sock, &request_value) {
                    Ok(resp) => {
                        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                        if !resp.ok {
                            std::process::exit(1);
                        }
                    }
                    Err(RpcClientError::DaemonNotRunning(_)) => {
                        eprintln!(
                            "daemon is not running for {} — start it with: topo --db {} start",
                            db, db
                        );
                        std::process::exit(1);
                    }
                    Err(RpcClientError::Protocol(msg))
                        if msg.contains("fill whole buffer") || msg.contains("unexpected eof") =>
                    {
                        eprintln!("error: daemon closed connection — the request JSON was likely malformed or unrecognized");
                        eprintln!("  Hint: use --method-json for method-only JSON (auto-wraps in request envelope)");
                        eprintln!("  Hint: use --request-json for full {{\"version\":1,\"method\":...}} envelopes");
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("error: {}", e);
                        std::process::exit(1);
                    }
                }
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

        Commands::Reset => {
            let socket_path = socket_override
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| service::socket_path_for_db(db));

            // Try to stop the daemon if running
            if socket_path.exists() {
                print!("stopping daemon... ");
                let request_deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    match rpc_call(&socket_path, RpcMethod::Shutdown) {
                        Ok(_) => break,
                        Err(RpcClientError::DaemonNotRunning(_)) if !socket_path.exists() => break,
                        Err(RpcClientError::DaemonNotRunning(_)) => {}
                        Err(RpcClientError::Protocol(msg))
                            if msg.contains("Connection reset by peer")
                                || msg.contains("Broken pipe") =>
                        {
                            break;
                        }
                        Err(RpcClientError::Io(e))
                            if e.kind() == std::io::ErrorKind::ConnectionReset
                                || e.kind() == std::io::ErrorKind::ConnectionRefused
                                || e.kind() == std::io::ErrorKind::BrokenPipe =>
                        {
                            break;
                        }
                        Err(e) => {
                            eprintln!("warning: error stopping daemon: {}", e);
                            break;
                        }
                    }
                    if Instant::now() >= request_deadline {
                        eprintln!("warning: timed out stopping daemon");
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }

                // Wait for daemon to fully exit
                let down_deadline = Instant::now() + Duration::from_secs(5);
                while socket_path.exists() && Instant::now() < down_deadline {
                    std::thread::sleep(Duration::from_millis(100));
                }
                println!("done");
            }

            // Delete DB file and associated WAL/SHM files, plus socket
            let db_path = Path::new(db);
            let mut deleted = Vec::new();
            for path in [
                db_path.to_path_buf(),
                db_path.with_extension("db-wal"),
                db_path.with_extension("db-shm"),
                socket_path.clone(),
            ] {
                if path.exists() {
                    match std::fs::remove_file(&path) {
                        Ok(_) => deleted.push(path.display().to_string()),
                        Err(e) => eprintln!("warning: failed to delete {}: {}", path.display(), e),
                    }
                }
            }

            if deleted.is_empty() {
                println!("nothing to clean up");
            } else {
                for f in &deleted {
                    println!("deleted {}", f);
                }
                println!("reset complete");
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

// ---------------------------------------------------------------------------
// event-tree / event-list helpers
// ---------------------------------------------------------------------------

fn print_event_tree(events: &[service::EventListItem]) {
    use std::collections::{HashMap, HashSet};

    if events.is_empty() {
        println!("(no events)");
        return;
    }

    let id_set: HashSet<&str> = events.iter().map(|e| e.id.as_str()).collect();

    // For each event, pick the first dep as tree parent (if it exists in the db).
    // Events with no valid tree parent are roots.
    let mut parent_of: HashMap<&str, &str> = HashMap::new();
    for e in events {
        for (_, dep_id) in &e.deps {
            if id_set.contains(dep_id.as_str()) {
                parent_of.insert(&e.id, dep_id.as_str());
                break;
            }
        }
    }

    // Build children map.
    let mut children: HashMap<&str, Vec<&str>> = HashMap::new();
    for e in events {
        if let Some(&parent) = parent_of.get(e.id.as_str()) {
            children.entry(parent).or_default().push(&e.id);
        }
    }

    // Roots: events with no tree parent.
    let roots: Vec<&str> = events
        .iter()
        .filter(|e| !parent_of.contains_key(e.id.as_str()))
        .map(|e| e.id.as_str())
        .collect();

    let event_map: HashMap<&str, &service::EventListItem> =
        events.iter().map(|e| (e.id.as_str(), e)).collect();

    // Print each root tree, then lone roots.
    let mut first = true;
    for root in &roots {
        let has_children = children.contains_key(root);
        if !first && has_children {
            println!();
        }
        print_tree_node(root, "", true, true, &children, &event_map, &parent_of);
        if has_children {
            first = false;
        }
    }

    println!(
        "\n{} events. Tree parent = first dependency; siblings in insertion order.",
        events.len()
    );
}

fn print_tree_node(
    id: &str,
    prefix: &str,
    is_last: bool,
    is_root: bool,
    children: &std::collections::HashMap<&str, Vec<&str>>,
    event_map: &std::collections::HashMap<&str, &service::EventListItem>,
    parent_of: &std::collections::HashMap<&str, &str>,
) {
    let info = event_map[id];
    let connector = if is_root {
        ""
    } else if is_last {
        "└── "
    } else {
        "├── "
    };

    let short = short_id(&info.id);

    // Collect cross-ref deps (deps that aren't the tree parent).
    let tree_parent = parent_of.get(id).copied();
    let cross_refs: Vec<String> = info
        .deps
        .iter()
        .filter(|(_, dep_id)| Some(dep_id.as_str()) != tree_parent)
        .map(|(field, dep_id)| format!("{}: {}", field, short_id(dep_id)))
        .collect();

    let suffix = if !cross_refs.is_empty() {
        format!("  [{}]", cross_refs.join(", "))
    } else if tree_parent.is_none() {
        " \u{2190} root".to_string()
    } else {
        String::new()
    };

    println!(
        "{}{}({}) {}{}",
        prefix, connector, short, info.event_type, suffix
    );

    if let Some(kids) = children.get(id) {
        let new_prefix = if is_root {
            String::new()
        } else if is_last {
            format!("{}    ", prefix)
        } else {
            format!("{}\u{2502}   ", prefix)
        };
        for (i, kid) in kids.iter().enumerate() {
            let kid_is_last = i == kids.len() - 1;
            print_tree_node(
                kid,
                &new_prefix,
                kid_is_last,
                false,
                children,
                event_map,
                parent_of,
            );
        }
    }
}

fn format_timestamp_ms(ms: u64) -> String {
    // Reject zero or clearly bogus timestamps (before 2020 or after 2100).
    if ms == 0 || ms < 1_577_836_800_000 || ms > 4_102_444_800_000 {
        return "\u{2014}".to_string(); // em-dash
    }
    let secs = (ms / 1000) as i64;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    // Use libc localtime_r for formatting without pulling in chrono.
    let mut tm = std::mem::MaybeUninit::<libc::tm>::uninit();
    let tm = unsafe {
        libc::localtime_r(&secs as *const i64, tm.as_mut_ptr());
        tm.assume_init()
    };

    let mut buf = [0u8; 64];
    let now_year = {
        let mut now_tm = std::mem::MaybeUninit::<libc::tm>::uninit();
        unsafe {
            libc::localtime_r(&now_secs as *const i64, now_tm.as_mut_ptr());
            now_tm.assume_init().tm_year
        }
    };
    let same_year = tm.tm_year == now_year;
    let fmt: &[u8] = if same_year {
        b"%b %d %H:%M:%S\0"
    } else {
        b"%Y %b %d %H:%M:%S\0"
    };
    let len = unsafe {
        libc::strftime(
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            fmt.as_ptr() as *const libc::c_char,
            &tm,
        )
    };
    String::from_utf8_lossy(&buf[..len]).to_string()
}

fn print_event_list(events: &[service::EventListItem]) {
    if events.is_empty() {
        println!("(no events)");
        return;
    }

    for e in events {
        let short = format!("({})", short_id(&e.id));
        let ts = format_timestamp_ms(e.created_at_ms);

        let deps_str = if e.deps.is_empty() {
            String::new()
        } else {
            let d = e
                .deps
                .iter()
                .map(|(field, dep_id)| format!("{}: ({})", field, short_id(dep_id)))
                .collect::<Vec<_>>()
                .join(", ");
            format!("  deps: {}", d)
        };

        println!("{} {} {}  [{} bytes]", short, e.event_type, ts, e.blob_len);
        if !deps_str.is_empty() {
            println!("{}", deps_str);
        }
        for (k, v) in &e.fields {
            println!("  {}: {}", k, v);
        }

        if let Some(dec) = &e.decrypted_inner {
            println!("  --- decrypted: {} ---", dec.inner_type);
            for (k, v) in &dec.fields {
                println!("    {}: {}", k, v);
            }
        } else if e.event_type == "encrypted" {
            println!("  (key not available)");
        }

        println!();
    }
    println!("{} events. Sorted by insertion order.", events.len());
}

fn print_sync_log_config(cfg: &sync_log::SyncLogConfig) {
    println!(
        "sync-log enabled={} changed_only={} capture_full_ids={} max_runs={} max_age_days={}",
        cfg.enabled, cfg.changed_only, cfg.capture_full_ids, cfg.max_runs, cfg.max_age_days
    );
}

fn short_sync_id(raw: &str) -> String {
    let prefix = &raw[..raw.len().min(4)];
    if raw.len() > 4 {
        format!("{}...", prefix)
    } else {
        prefix.to_string()
    }
}

fn run_status(run: &sync_log::SyncRunRow) -> &'static str {
    if run.error.is_some() || run.outcome != "ok" {
        "error"
    } else if run.changed {
        "changed"
    } else {
        "match"
    }
}

fn event_id_prefix_from_detail_json(detail_json: Option<&str>) -> Option<String> {
    let raw = detail_json?;
    let v = serde_json::from_str::<serde_json::Value>(raw).ok()?;
    let eid = v.get("event_id")?.as_str()?;
    Some(short_sync_id(eid))
}

fn summarize_sync_event_detail(frame_type: &str, detail_json: Option<&str>) -> String {
    let Some(raw) = detail_json else {
        return String::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(raw) else {
        return " detail=parse_error".to_string();
    };

    match frame_type {
        "NegOpen" | "NegMsg" => {
            let entries = v["entry_count"].as_u64().unwrap_or(0);
            let fp = v["fingerprint_count"].as_u64().unwrap_or(0);
            let idl = v["idlist_count"].as_u64().unwrap_or(0);
            let skip = v["skip_count"].as_u64().unwrap_or(0);
            if let Some(err) = v["parse_error"].as_str() {
                format!(
                    " detail=neg(entries={} fp={} idlists={} skip={} err={})",
                    entries, fp, idl, skip, err
                )
            } else {
                format!(
                    " detail=neg(entries={} fp={} idlists={} skip={})",
                    entries, fp, idl, skip
                )
            }
        }
        "HaveList" => {
            let count = v["id_count"].as_u64().unwrap_or(0);
            let ids = v["ids"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str())
                        .map(short_sync_id)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let truncated = v["ids_truncated"].as_bool().unwrap_or(false);
            if ids.is_empty() {
                format!(" detail=ids(count={} truncated={})", count, truncated)
            } else {
                let shown = ids.join(",");
                let shown_count = ids.len() as u64;
                let more = count.saturating_sub(shown_count);
                let extra = if more > 0 {
                    format!(" (+{} more)", more)
                } else if truncated {
                    " ...".to_string()
                } else {
                    String::new()
                };
                format!(
                    " detail=ids(count={} truncated={} ids=[{}]{})",
                    count, truncated, shown, extra
                )
            }
        }
        "Event" => {
            let eid = v["event_id"].as_str().unwrap_or("");
            let blob_len = v["blob_len"].as_u64().unwrap_or(0);
            if eid.is_empty() {
                format!(" detail=event(blob_len={})", blob_len)
            } else {
                format!(
                    " detail=event(id={} blob_len={})",
                    short_sync_id(eid),
                    blob_len
                )
            }
        }
        _ => String::new(),
    }
}

#[derive(Debug, Clone)]
struct NegEntryView {
    bound_ts: String,
    bound_id_prefix: String,
    mode: String,
    fingerprint_hex: Option<String>,
    id_count: Option<u64>,
    ids: Vec<String>,
    ids_truncated: bool,
}

#[derive(Debug, Clone)]
struct NegFrameView {
    protocol: Option<u64>,
    entry_count: u64,
    skip_count: u64,
    fingerprint_count: u64,
    idlist_count: u64,
    entries: Vec<NegEntryView>,
    parse_error: Option<String>,
}

fn parse_neg_frame_view(detail_json: Option<&str>) -> Option<NegFrameView> {
    let raw = detail_json?;
    let v = serde_json::from_str::<serde_json::Value>(raw).ok()?;

    let entries = v["entries"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .map(|entry| {
                    let ids = entry["ids"]
                        .as_array()
                        .map(|ids_arr| {
                            ids_arr
                                .iter()
                                .filter_map(|x| x.as_str())
                                .map(|s| s.to_string())
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    NegEntryView {
                        bound_ts: entry["bound_ts"].as_str().unwrap_or("?").to_string(),
                        bound_id_prefix: entry["bound_id_prefix"]
                            .as_str()
                            .unwrap_or("")
                            .to_string(),
                        mode: entry["mode"].as_str().unwrap_or("?").to_string(),
                        fingerprint_hex: entry["fingerprint_hex"].as_str().map(|s| s.to_string()),
                        id_count: entry["id_count"].as_u64(),
                        ids,
                        ids_truncated: entry["ids_truncated"].as_bool().unwrap_or(false),
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(NegFrameView {
        protocol: v["protocol"].as_u64(),
        entry_count: v["entry_count"].as_u64().unwrap_or(0),
        skip_count: v["skip_count"].as_u64().unwrap_or(0),
        fingerprint_count: v["fingerprint_count"].as_u64().unwrap_or(0),
        idlist_count: v["idlist_count"].as_u64().unwrap_or(0),
        entries,
        parse_error: v["parse_error"].as_str().map(|s| s.to_string()),
    })
}

fn neg_entry_depth_hint(prefix_hex: &str) -> usize {
    let bytes = prefix_hex.len() / 2;
    if bytes <= 1 {
        0
    } else if bytes <= 3 {
        1
    } else if bytes <= 7 {
        2
    } else {
        3
    }
}

fn neg_entry_readable_line(round_no: usize, entry_idx: usize, entry: &NegEntryView) -> String {
    let bound_prefix = short_sync_id(&entry.bound_id_prefix);
    let bound = if bound_prefix.is_empty() {
        format!("({})", entry.bound_ts)
    } else {
        format!("({}, {})", entry.bound_ts, bound_prefix)
    };
    let range_label = format!("{}.{}", round_no, entry_idx + 1);
    match entry.mode.as_str() {
        "Skip" => format!("range={} MATCH bound={}", range_label, bound),
        "Fingerprint" => {
            let fp = entry
                .fingerprint_hex
                .as_deref()
                .map(short_sync_id)
                .unwrap_or_else(|| "?".to_string());
            format!(
                "range={} HASH bound={} fp={} (await compare)",
                range_label, bound, fp
            )
        }
        "IdList" => {
            let count = entry.id_count.unwrap_or(0);
            let ids = entry
                .ids
                .iter()
                .take(4)
                .map(|id| short_sync_id(id))
                .collect::<Vec<_>>()
                .join(",");
            if ids.is_empty() {
                format!(
                    "range={} MISMATCH -> IdList count={} truncated={}",
                    range_label, count, entry.ids_truncated
                )
            } else {
                let shown = entry.ids.len().min(4) as u64;
                let more_count = count.saturating_sub(shown);
                let more = if more_count > 0 {
                    format!(" (+{} more)", more_count)
                } else if entry.ids_truncated {
                    " ...".to_string()
                } else {
                    String::new()
                };
                format!(
                    "range={} MISMATCH -> IdList count={} ids=[{}]{} truncated={}",
                    range_label, count, ids, more, entry.ids_truncated
                )
            }
        }
        other => format!("range={} {} bound={}", range_label, other, bound),
    }
}

#[derive(Debug, Clone)]
struct RenderedFrameLine {
    seq_start: u64,
    seq_end: u64,
    dt_start_ms: i64,
    dt_end_ms: i64,
    lane: String,
    direction: String,
    frame_type: String,
    len_label: String,
    detail: String,
    detail_json: Option<String>,
}

impl RenderedFrameLine {
    fn seq_label(&self) -> String {
        if self.seq_start == self.seq_end {
            format!("{:04}", self.seq_start)
        } else {
            format!("{:04}-{:04}", self.seq_start, self.seq_end)
        }
    }

    fn dt_label(&self) -> String {
        if self.dt_start_ms == self.dt_end_ms {
            format!("+{}ms", self.dt_start_ms)
        } else {
            format!("+{}..{}ms", self.dt_start_ms, self.dt_end_ms)
        }
    }
}

fn render_frame_lines(
    run: &sync_log::SyncRunRow,
    events: &[sync_log::SyncRunEventRow],
) -> Vec<RenderedFrameLine> {
    const COLLAPSE_EVENT_BURST_MIN: usize = 3;
    const EVENT_SAMPLE_IDS: usize = 4;

    let mut out = Vec::new();
    let mut i = 0usize;
    while i < events.len() {
        let ev = &events[i];
        if ev.frame_type == "Event" {
            let mut j = i + 1;
            while j < events.len() {
                let nxt = &events[j];
                if nxt.frame_type == "Event" && nxt.lane == ev.lane && nxt.direction == ev.direction
                {
                    j += 1;
                } else {
                    break;
                }
            }

            let burst = &events[i..j];
            if burst.len() >= COLLAPSE_EVENT_BURST_MIN {
                let first = &burst[0];
                let last = &burst[burst.len() - 1];
                let mut total_len: usize = 0;
                let mut min_len: usize = usize::MAX;
                let mut max_len: usize = 0;
                let mut ids: Vec<String> = Vec::new();
                for item in burst {
                    total_len = total_len.saturating_add(item.msg_len);
                    min_len = min_len.min(item.msg_len);
                    max_len = max_len.max(item.msg_len);
                    if ids.len() < EVENT_SAMPLE_IDS {
                        if let Some(id) =
                            event_id_prefix_from_detail_json(item.detail_json.as_deref())
                        {
                            ids.push(id);
                        }
                    }
                }
                if min_len == usize::MAX {
                    min_len = 0;
                }
                let detail = if ids.is_empty() {
                    format!(" detail=events(count={})", burst.len())
                } else {
                    let more_count = burst.len().saturating_sub(ids.len());
                    let more = if more_count > 0 {
                        format!(" (+{} more)", more_count)
                    } else {
                        String::new()
                    };
                    format!(
                        " detail=events(count={} ids=[{}]{})",
                        burst.len(),
                        ids.join(","),
                        more
                    )
                };
                out.push(RenderedFrameLine {
                    seq_start: first.seq,
                    seq_end: last.seq,
                    dt_start_ms: first.ts_ms.saturating_sub(run.started_at_ms),
                    dt_end_ms: last.ts_ms.saturating_sub(run.started_at_ms),
                    lane: first.lane.clone(),
                    direction: first.direction.clone(),
                    frame_type: "Event*".to_string(),
                    len_label: format!(
                        "total:{} range:{}-{} count:{}",
                        total_len,
                        min_len,
                        max_len,
                        burst.len()
                    ),
                    detail,
                    detail_json: None,
                });
                i = j;
                continue;
            }
        }

        out.push(RenderedFrameLine {
            seq_start: ev.seq,
            seq_end: ev.seq,
            dt_start_ms: ev.ts_ms.saturating_sub(run.started_at_ms),
            dt_end_ms: ev.ts_ms.saturating_sub(run.started_at_ms),
            lane: ev.lane.clone(),
            direction: ev.direction.clone(),
            frame_type: ev.frame_type.clone(),
            len_label: ev.msg_len.to_string(),
            detail: summarize_sync_event_detail(&ev.frame_type, ev.detail_json.as_deref()),
            detail_json: ev.detail_json.clone(),
        });
        i += 1;
    }

    out
}

fn print_sync_trace_run(run: &sync_log::SyncRunRow, events: &[sync_log::SyncRunEventRow]) {
    let status = run_status(run);
    let dur_ms = run.ended_at_ms.saturating_sub(run.started_at_ms);
    let frame_lines = render_frame_lines(run, events);
    println!(
        "RUN {} [{}] session={} tenant={} peer={} dir={} role={} remote={} start={} end={} dur_ms={} sync_rounds={} sync_events_tx={} sync_events_rx={} bytes_tx={} bytes_rx={} raw_frames={} frame_lines={} outcome={}",
        run.run_id,
        status,
        run.session_id,
        short_sync_id(&run.tenant_id),
        short_sync_id(&run.peer_id),
        run.direction,
        run.role,
        run.remote_addr,
        format_absolute(run.started_at_ms),
        format_absolute(run.ended_at_ms),
        dur_ms,
        run.rounds,
        run.events_sent,
        run.events_received,
        run.bytes_sent,
        run.bytes_received,
        events.len(),
        frame_lines.len(),
        run.outcome,
    );
    if let Some(err) = &run.error {
        println!("  error: {}", err);
    }
    if events.is_empty() {
        println!("  (no frame events)");
        return;
    }
    for line in frame_lines {
        println!(
            "  [{}] {:>11} {:7} {:2} {:8} len={}{}",
            line.seq_label(),
            line.dt_label(),
            line.lane,
            line.direction,
            line.frame_type,
            line.len_label,
            line.detail
        );
    }
}

#[derive(Debug)]
struct PeerSyncTreeGroup {
    peer_id: String,
    runs: Vec<(sync_log::SyncRunRow, Vec<sync_log::SyncRunEventRow>)>,
}

fn group_runs_by_peer(
    runs: Vec<(sync_log::SyncRunRow, Vec<sync_log::SyncRunEventRow>)>,
) -> Vec<PeerSyncTreeGroup> {
    let mut groups: Vec<PeerSyncTreeGroup> = Vec::new();
    for (run, events) in runs {
        if let Some(group) = groups.iter_mut().find(|g| g.peer_id == run.peer_id) {
            group.runs.push((run, events));
        } else {
            groups.push(PeerSyncTreeGroup {
                peer_id: run.peer_id.clone(),
                runs: vec![(run, events)],
            });
        }
    }
    groups
}

fn print_sync_tree_groups(groups: &[PeerSyncTreeGroup]) {
    for (peer_idx, group) in groups.iter().enumerate() {
        let changed = group
            .runs
            .iter()
            .filter(|(run, _)| run_status(run) == "changed")
            .count();
        let errors = group
            .runs
            .iter()
            .filter(|(run, _)| run_status(run) == "error")
            .count();
        println!(
            "peer={} runs={} changed={} errors={}",
            short_sync_id(&group.peer_id),
            group.runs.len(),
            changed,
            errors
        );

        for (run_idx, (run, events)) in group.runs.iter().enumerate() {
            let run_branch = if run_idx + 1 == group.runs.len() {
                "└─"
            } else {
                "├─"
            };
            let run_pad = if run_idx + 1 == group.runs.len() {
                "  "
            } else {
                "│ "
            };
            let status = run_status(run);
            let dt = run.ended_at_ms.saturating_sub(run.started_at_ms);
            let frame_lines = render_frame_lines(run, events);
            let mut prev_neg_entry_count: Option<u64> = None;
            let mut neg_round_no: usize = 0;
            println!(
            "{} run={} status={} ended_at={} direction={} role={} sync_rounds={} sync_events_tx={} sync_events_rx={} dur_ms={} raw_frames={} frame_lines={} outcome={}",
                run_branch,
                run.run_id,
                status,
                format_compact_datetime(run.ended_at_ms),
                run.direction,
                run.role,
                run.rounds,
                run.events_sent,
                run.events_received,
                dt,
                events.len(),
                frame_lines.len(),
                run.outcome
            );
            if let Some(err) = &run.error {
                println!("{}  error: {}", run_pad, err);
            }

            if events.is_empty() {
                println!("{}  └─ (no frame events)", run_pad);
                continue;
            }

            for (event_idx, line) in frame_lines.iter().enumerate() {
                let ev_branch = if event_idx + 1 == frame_lines.len() {
                    "└─"
                } else {
                    "├─"
                };
                println!(
                    "{}  {} {} seq={} {} {} {} len={}{}",
                    run_pad,
                    ev_branch,
                    line.dt_label(),
                    line.seq_label(),
                    line.lane,
                    line.direction,
                    line.frame_type,
                    line.len_label,
                    line.detail
                );

                if (line.frame_type == "NegOpen" || line.frame_type == "NegMsg")
                    && line.detail_json.is_some()
                {
                    neg_round_no += 1;
                    if let Some(neg) = parse_neg_frame_view(line.detail_json.as_deref()) {
                        let child_stem = if event_idx + 1 == frame_lines.len() {
                            "  "
                        } else {
                            "│ "
                        };
                        let drilldown = prev_neg_entry_count
                            .filter(|prev| neg.entry_count > *prev)
                            .map(|prev| format!(" drilldown={}->{}", prev, neg.entry_count))
                            .unwrap_or_default();
                        println!(
                            "{}  {}    reconcile round={} protocol={} ranges={} hash_match(skip)={} hash_probe(fp)={} idlists={}{}",
                            run_pad,
                            child_stem,
                            neg_round_no,
                            neg.protocol
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "?".to_string()),
                            neg.entry_count,
                            neg.skip_count,
                            neg.fingerprint_count,
                            neg.idlist_count,
                            drilldown
                        );
                        if let Some(err) = &neg.parse_error {
                            println!("{}  {}    parse_error={}", run_pad, child_stem, err);
                        }

                        const MAX_RANGE_LINES: usize = 10;
                        for (entry_idx, entry) in neg.entries.iter().enumerate() {
                            if entry_idx >= MAX_RANGE_LINES {
                                let rem = neg.entries.len() - MAX_RANGE_LINES;
                                println!("{}  {}    (+{} more ranges)", run_pad, child_stem, rem);
                                break;
                            }
                            let depth = neg_entry_depth_hint(&entry.bound_id_prefix);
                            let depth_pad = "  ".repeat(depth);
                            println!(
                                "{}  {}    {}{}",
                                run_pad,
                                child_stem,
                                depth_pad,
                                neg_entry_readable_line(neg_round_no, entry_idx, entry)
                            );
                        }
                        prev_neg_entry_count = Some(neg.entry_count);
                    }
                }
            }
        }

        if peer_idx + 1 < groups.len() {
            println!();
        }
    }
}

fn system_hostname() -> String {
    let mut buf = [0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret == 0 {
        let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        String::from_utf8_lossy(&buf[..len]).into_owned()
    } else {
        "device".to_string()
    }
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

fn format_compact_datetime(ms: i64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let dt = UNIX_EPOCH + Duration::from_millis(ms as u64);
    let total_secs = dt.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let days_since_epoch = total_secs / 86_400;
    let time_of_day = total_secs % 86_400;
    let hours = time_of_day / 3_600;
    let minutes = (time_of_day % 3_600) / 60;
    let seconds = time_of_day % 60;
    let millis = (ms.rem_euclid(1000)) as u32;

    let (year, month, day) = days_to_ymd(days_since_epoch as i64);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        year, month, day, hours, minutes, seconds, millis
    )
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

        // Reactions: Slack-style grouped counts on one line
        if let Some(reactions) = msg["reactions"].as_array() {
            if !reactions.is_empty() {
                let mut counts: std::collections::BTreeMap<String, usize> =
                    std::collections::BTreeMap::new();
                for r in reactions {
                    let emoji = r["emoji"].as_str().unwrap_or("?").to_string();
                    *counts.entry(emoji).or_default() += 1;
                }
                let parts: Vec<String> = counts
                    .iter()
                    .map(|(name, count)| {
                        let glyph = emoji_shortcode_to_unicode(name);
                        if *count > 1 {
                            format!("{} ({})", glyph, count)
                        } else {
                            glyph.to_string()
                        }
                    })
                    .collect();
                println!("        {}", parts.join("  "));
            }
        }

        // Files: ✅ = complete, 🔄 = syncing
        if let Some(files) = msg["files"].as_array() {
            for att in files {
                let filename = att["filename"].as_str().unwrap_or("file");
                let blob_bytes = att["blob_bytes"].as_i64().unwrap_or(0);
                let total = att["total_slices"].as_i64().unwrap_or(0);
                let received = att["slices_received"].as_i64().unwrap_or(0);
                let size = format_byte_size(blob_bytes);
                let status = if total > 0 && received >= total {
                    "\u{2714}" // ✔
                } else {
                    "\u{23f3}" // ⏳
                };
                if total > 0 && received < total {
                    let pct = (received as f64 / total as f64 * 100.0) as u32;
                    println!("        {}  {} ({}, {}%)", status, filename, size, pct);
                } else {
                    println!("        {}  {} ({})", status, filename, size);
                }
            }
        }
    }
    println!();
}

fn show_files_from_json(data: &serde_json::Value) {
    let files = match data["files"].as_array() {
        Some(files) => files,
        None => {
            println!("  (no files)");
            return;
        }
    };
    if files.is_empty() {
        println!("  (no files)");
        return;
    }

    let total = data["total"].as_i64().unwrap_or(0);
    println!("FILES ({} total):\n", total);

    for (i, file) in files.iter().enumerate() {
        let filename = file["filename"].as_str().unwrap_or("file");
        let blob_bytes = file["blob_bytes"].as_i64().unwrap_or(0);
        let total_slices = file["total_slices"].as_i64().unwrap_or(0);
        let slices_received = file["slices_received"].as_i64().unwrap_or(0);
        let created_at = file["created_at"].as_i64().unwrap_or(0);
        let file_event_id = file["file_event_id"].as_str().unwrap_or("");
        let message_id = file["message_id"].as_str().unwrap_or("");
        let complete = file["complete"].as_bool().unwrap_or(false);

        let status = if complete { "\u{2714}" } else { "\u{23f3}" };
        let size = format_byte_size(blob_bytes);
        let ts = format_timestamp(created_at);
        let short_file = &file_event_id[..file_event_id.len().min(12)];
        let short_message = &message_id[..message_id.len().min(12)];
        println!(
            "  {}. {}  {} ({})  [{}/{} slices]  {}",
            i + 1,
            status,
            filename,
            size,
            slices_received,
            total_slices,
            ts
        );
        println!("     file_event:{}  message:{}", short_file, short_message);
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_emoji_shortcode_known() {
        assert_eq!(emoji_shortcode_to_unicode("thumbsup"), "\u{1f44d}");
        assert_eq!(emoji_shortcode_to_unicode("+1"), "\u{1f44d}");
        assert_eq!(emoji_shortcode_to_unicode("heart"), "\u{2764}\u{fe0f}");
        assert_eq!(emoji_shortcode_to_unicode("fire"), "\u{1f525}");
        assert_eq!(emoji_shortcode_to_unicode("rocket"), "\u{1f680}");
        assert_eq!(emoji_shortcode_to_unicode("tada"), "\u{1f389}");
    }

    #[test]
    fn test_emoji_shortcode_unknown_passthrough() {
        assert_eq!(emoji_shortcode_to_unicode("zzz_unknown"), "zzz_unknown");
    }

    #[test]
    fn test_format_byte_size() {
        assert_eq!(format_byte_size(0), "0 B");
        assert_eq!(format_byte_size(512), "512 B");
        assert_eq!(format_byte_size(1024), "1.0 KiB");
        assert_eq!(format_byte_size(1536), "1.5 KiB");
        assert_eq!(format_byte_size(1048576), "1.0 MiB");
        assert_eq!(format_byte_size(1258291), "1.2 MiB");
        assert_eq!(format_byte_size(1073741824), "1.0 GiB");
    }
}

fn emoji_shortcode_to_unicode(name: &str) -> &str {
    match name {
        "thumbsup" | "+1" => "\u{1f44d}",
        "thumbsdown" | "-1" => "\u{1f44e}",
        "heart" | "red_heart" => "\u{2764}\u{fe0f}",
        "laugh" | "joy" => "\u{1f602}",
        "cry" | "sob" => "\u{1f62d}",
        "fire" => "\u{1f525}",
        "rocket" => "\u{1f680}",
        "eyes" => "\u{1f440}",
        "tada" | "party" => "\u{1f389}",
        "100" => "\u{1f4af}",
        "wave" => "\u{1f44b}",
        "clap" => "\u{1f44f}",
        "thinking" | "thinking_face" => "\u{1f914}",
        "pray" | "folded_hands" => "\u{1f64f}",
        "ok_hand" => "\u{1f44c}",
        "raised_hands" => "\u{1f64c}",
        "star" => "\u{2b50}",
        "sparkles" => "\u{2728}",
        "check" | "white_check_mark" => "\u{2705}",
        "x" | "cross_mark" => "\u{274c}",
        "warning" => "\u{26a0}\u{fe0f}",
        "question" => "\u{2753}",
        "exclamation" => "\u{2757}",
        "smile" | "smiley" => "\u{1f604}",
        "wink" => "\u{1f609}",
        "sunglasses" | "cool" => "\u{1f60e}",
        "sad" | "disappointed" => "\u{1f61e}",
        "angry" => "\u{1f620}",
        "scream" => "\u{1f631}",
        "skull" => "\u{1f480}",
        "poop" => "\u{1f4a9}",
        "muscle" => "\u{1f4aa}",
        "brain" => "\u{1f9e0}",
        "bulb" | "light_bulb" => "\u{1f4a1}",
        "memo" => "\u{1f4dd}",
        "pin" | "pushpin" => "\u{1f4cc}",
        "link" => "\u{1f517}",
        "bug" => "\u{1f41b}",
        "wrench" => "\u{1f527}",
        "hammer" => "\u{1f528}",
        "gear" => "\u{2699}\u{fe0f}",
        "lock" => "\u{1f512}",
        "key" => "\u{1f511}",
        "bell" => "\u{1f514}",
        "megaphone" | "loudspeaker" => "\u{1f4e3}",
        _ => name, // pass through unknown shortcodes as-is
    }
}

fn format_byte_size(bytes: i64) -> String {
    const KIB: i64 = 1024;
    const MIB: i64 = 1024 * 1024;
    const GIB: i64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
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
