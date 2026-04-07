use std::net::SocketAddr;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "topo")]
#[command(about = "\u{1f42d} Topo \u{2014} peer-to-peer encrypted sync")]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Database path
    #[arg(short, long, default_value = "topo.db", global = true)]
    pub db: String,

    /// Custom RPC socket path (default: <db>.topo.sock)
    #[arg(long, global = true)]
    pub socket: Option<String>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
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
        /// Seed synthetic messages at workspace creation time
        #[arg(long, default_value_t = 0)]
        message_count: usize,
        /// Historical age for the initial auth graph + seeded messages (for example 30d, 12w, 3y)
        #[arg(long)]
        network_age: Option<String>,
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
    /// Manage tenants (list, use, active)
    #[command(
        after_help = "Examples:\n  topo tenant          # list tenants (default)\n  topo tenant list     # list tenants\n  topo tenant use 2    # switch to tenant 2\n  topo tenant active   # show active tenant"
    )]
    Tenant {
        #[command(subcommand)]
        action: Option<TenantAction>,
    },

    /// List local transport keys (SPKI fingerprints from TLS certs)
    #[command(name = "transport-keys")]
    TransportKeys,

    /// List authorized remote transport fingerprints with projected provenance
    #[command(name = "transport-auth")]
    TransportAuth,

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
        /// Append bogus extra file_slice events after the real slices
        #[arg(long, default_value_t = 0)]
        add_bad_slices: usize,
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
        /// Reaction text (emoji shortcode or unicode)
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

    /// List local content/decryption keys
    #[command(name = "content-keys")]
    ContentKeys {
        /// Show summary only
        #[arg(long)]
        summary: bool,
    },

    /// Show all projection table counts
    Stats {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Run a replay pass: clear projections, reproject, return fingerprint
    Replay {
        /// Pass type: forward, idempotent, reverse, shuffle
        pass: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// List workspaces from projection
    Workspaces,

    /// List all known peers (local + remote) with connection endpoint info
    Peers,

    /// Event inspection commands (tree, list)
    #[command(
        after_help = "Examples:\n  topo event tree                           # show event dependency tree\n  topo event list                           # list all events with dependencies\n  topo event list --type message_deletion   # list only deletion events"
    )]
    Event {
        #[command(subcommand)]
        action: EventAction,
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

    /// Rotate to a fresh content key for the active workspace
    #[command(name = "rotate-key")]
    RotateKey,

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
        invite: String,
        /// Device name for the new identity (defaults to system hostname)
        #[arg(long)]
        devicename: Option<String>,
    },

    /// Show combined identity info (transport + user + peer)
    Identity,

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
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

    /// Sync log management (show, tree, enable, disable, config)
    #[command(
        name = "sync-log",
        after_help = "Examples:\n  topo sync-log              # show recent sync runs (default)\n  topo sync-log show --all   # show all runs including match-only\n  topo sync-log tree          # tree view of sync history\n  topo sync-log enable        # enable persistent sync logging\n  topo sync-log disable       # disable sync logging\n  topo sync-log config        # show current config"
    )]
    SyncLog {
        /// Max runs to show (shorthand for `sync-log show --limit`)
        #[arg(long, default_value = "5")]
        limit: usize,
        /// Show one specific run id (shorthand for `sync-log show --run`)
        #[arg(long)]
        run: Option<i64>,
        /// Filter by peer id prefix (shorthand for `sync-log show --peer`)
        #[arg(long)]
        peer: Option<String>,
        /// Include runs that matched with no data transfer (shorthand for `sync-log show --all`)
        #[arg(long)]
        all: bool,
        #[command(subcommand)]
        action: Option<SyncLogAction>,
    },

    /// Show or suppress noisy iroh/noq transport logs on the next daemon start
    #[command(
        name = "iroh-log",
        after_help = "Examples:\n  topo iroh-log           # show current iroh log mode\n  topo iroh-log show      # allow iroh/noq transport logs on next start\n  topo iroh-log suppress  # suppress iroh/noq transport logs on next start\n  topo iroh-log config    # show current iroh log mode"
    )]
    IrohLog {
        #[command(subcommand)]
        action: Option<IrohLogAction>,
    },

    /// Show or update topo log level; applies immediately when the daemon is running
    #[command(
        name = "topo-log",
        after_help = "Examples:\n  topo topo-log           # show current topo log level\n  topo topo-log debug     # enable debug topo logs now and on next start\n  topo topo-log warn      # return topo logs to warn level\n  topo topo-log config    # show current topo log level"
    )]
    TopoLog {
        #[command(subcommand)]
        action: Option<TopoLogAction>,
    },

    /// Raw RPC demo surface: list methods, describe parameters, submit raw JSON calls
    #[command(
        after_help = "Examples:\n  # List all available RPC methods\n  topo rpc methods\n  topo rpc methods --json\n\n  # Describe a method and its parameters\n  topo rpc describe Status\n  topo rpc describe Send --json\n\n  # Call an RPC method (inline JSON)\n  topo rpc call --method-json '{\"type\":\"Status\"}'\n  topo rpc call --method-json '{\"type\":\"Send\",\"content\":\"hello\"}'\n  topo rpc call --method-json '{\"type\":\"Messages\",\"limit\":20}'\n  topo rpc call --method-json '{\"type\":\"View\",\"limit\":10}'\n\n  # Call with a full request envelope\n  topo rpc call --request-json '{\"version\":1,\"method\":{\"type\":\"Status\"}}'\n\n  # Call from a file or stdin\n  topo rpc call --file request.json\n  echo '{\"type\":\"Peers\"}' | topo rpc call --stdin"
    )]
    Rpc {
        #[command(subcommand)]
        action: RpcAction,
    },

    /// List recent/active peer connections
    Connections {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Browse for peers via mDNS discovery
    #[cfg(feature = "discovery")]
    Discover {
        /// Browse timeout in milliseconds
        #[arg(long, default_value = "5000")]
        timeout_ms: u64,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Manual sync controls
    #[command(
        name = "sync",
        after_help = "Examples:\n  topo sync round peer abc123\n  topo sync round all"
    )]
    Sync {
        #[command(subcommand)]
        action: SyncAction,
    },

    /// Reset all local state: stop daemon, delete DB and socket files
    Reset,
}

#[derive(Subcommand)]
pub(crate) enum RpcAction {
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
pub(crate) enum SyncAction {
    /// Trigger a negentropy discovery round
    Round {
        #[command(subcommand)]
        target: SyncTarget,
    },
}

#[derive(Subcommand)]
pub(crate) enum SyncTarget {
    /// Target a specific peer by hex fingerprint prefix
    Peer {
        /// Peer SPKI fingerprint prefix (hex)
        peer: String,
    },
    /// Target all connected peers
    All,
}

#[derive(Subcommand)]
pub(crate) enum SubAction {
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
    /// Watch a subscription: continuously poll and print new events to stdout
    Watch {
        /// Subscription selector: id, name, or index (#N / N)
        sub: Option<String>,
        /// Deprecated: use positional selector instead.
        #[arg(long = "sub", hide = true)]
        sub_flag: Option<String>,
        /// Poll interval in milliseconds
        #[arg(long, default_value = "500")]
        interval_ms: u64,
        /// Output as JSON (one JSON object per line)
        #[arg(long)]
        json: bool,
        /// Auto-acknowledge items after printing
        #[arg(long)]
        ack: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum TenantAction {
    /// List local tenants (peer identities) in this DB with active marker
    List,
    /// Switch active tenant by number from the tenants list
    Use {
        /// Tenant number (1-based, from `topo tenant list`)
        index: usize,
    },
    /// Show currently active tenant
    Active,
}

#[derive(Subcommand)]
pub(crate) enum EventAction {
    /// Show event dependency tree (requires running daemon)
    Tree,
    /// List all events with their dependencies (requires running daemon)
    List {
        /// Filter by exact event type (for example: message_deletion)
        #[arg(long = "type")]
        event_type: Option<String>,
        /// Print one event ID per line (sorted), no other fields
        #[arg(long)]
        ids_only: bool,
        /// Print a BLAKE2b fingerprint of the sorted event ID set
        #[arg(long)]
        fingerprint: bool,
    },
    /// Show or set event display mode (tree, list, off)
    Display {
        /// Mode to set (tree, list, off). Omit to show current mode.
        mode: Option<String>,
    },
    /// List blocked events with their missing dependencies
    Blocked {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show delivery timeline for a specific event
    Timeline {
        /// Event ID (base64 or hex prefix)
        event_id: String,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show details for events matching an ID prefix
    Show {
        /// Event ID prefix (first few characters of base64 ID)
        prefix: String,
    },
    /// Show reverse dependency tree for an event
    Deps {
        /// Event ID prefix (first few characters of base64 ID)
        prefix: String,
        /// Maximum traversal depth
        #[arg(long, default_value = "5")]
        depth: usize,
    },
}

#[derive(Subcommand)]
pub(crate) enum SyncLogAction {
    /// Show sync log trace history
    Show {
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
    Tree {
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
    /// Enable persistent sync logging
    Enable {
        /// Include match-only runs (default stores changed runs only)
        #[arg(long, default_value_t = false)]
        all_runs: bool,
        /// Capture full ID lists in log details (larger DB growth)
        #[arg(long, default_value_t = false)]
        capture_full_ids: bool,
    },
    /// Disable persistent sync logging
    Disable,
    /// Show sync logging configuration
    Config,
}

#[derive(Subcommand)]
pub(crate) enum IrohLogAction {
    /// Show iroh log mode configuration
    Config,
    /// Allow iroh/noq transport logs on startup
    Show,
    /// Suppress iroh/noq transport logs on startup
    Suppress,
}

#[derive(Subcommand)]
pub(crate) enum TopoLogAction {
    /// Show topo log level configuration
    Config,
    /// Set topo logs to error level
    Error,
    /// Set topo logs to warn level
    Warn,
    /// Set topo logs to info level
    Info,
    /// Set topo logs to debug level
    Debug,
    /// Set topo logs to trace level
    Trace,
}
