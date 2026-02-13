//! p7ctl — thin CLI client for the poc-7 daemon.
//!
//! Maps subcommands to RPC requests, prints JSON responses, uses strict exit codes.
//!
//! Exit codes:
//!   0 — success
//!   1 — assertion failed / command error
//!   2 — daemon not running or connection error

use clap::{Parser, Subcommand};

use poc_7::rpc::client::{rpc_call, RpcClientError};
use poc_7::rpc::protocol::RpcMethod;
use poc_7::service;

#[derive(Parser)]
#[command(name = "p7ctl")]
#[command(about = "poc-7 thin CLI — sends RPC to daemon, prints JSON")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Database path (used to derive socket path)
    #[arg(short, long, default_value = "server.db", global = true)]
    db: String,

    /// Custom RPC socket path (default: derived from --db)
    #[arg(long, global = true)]
    socket: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Show database status
    Status,

    /// List messages
    Messages {
        /// Max messages to show (0 = all)
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// Send a message
    Send {
        /// Message content
        content: String,
        /// Workspace event ID hex
        #[arg(short = 'n', long, default_value = "0102030405060708090a0b0c0d0e0f10")]
        workspace: String,
    },

    /// Generate test messages
    Generate {
        #[arg(short, long, default_value = "100")]
        count: usize,
        #[arg(short = 'n', long, default_value = "0102030405060708090a0b0c0d0e0f10")]
        workspace: String,
    },

    /// Assert a predicate holds right now
    AssertNow {
        /// Predicate: "field op value" (e.g. "store_count >= 10")
        predicate: String,
    },

    /// Assert a predicate eventually holds
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

    /// Print local transport identity (SPKI fingerprint)
    #[command(name = "transport-identity")]
    TransportIdentity,

    /// Create a reaction to a message
    React {
        /// Emoji to react with
        emoji: String,
        /// Target event ID (hex)
        #[arg(long)]
        target: String,
    },

    /// Delete a message
    #[command(name = "delete-message")]
    DeleteMessage {
        /// Target message event ID (hex)
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
    Networks,

    /// Show intro attempt records
    #[command(name = "intro-attempts")]
    IntroAttempts {
        /// Filter by peer SPKI fingerprint (hex)
        #[arg(long)]
        peer: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    let socket_path = cli
        .socket
        .as_ref()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| service::socket_path_for_db(&cli.db));

    let method = match cli.command {
        Commands::Status => RpcMethod::Status,
        Commands::Messages { limit } => RpcMethod::Messages { limit },
        Commands::Send { content, workspace } => RpcMethod::Send { workspace, content },
        Commands::Generate { count, workspace } => RpcMethod::Generate { count, workspace },
        Commands::AssertNow { predicate } => RpcMethod::AssertNow { predicate },
        Commands::AssertEventually {
            predicate,
            timeout_ms,
            interval_ms,
        } => RpcMethod::AssertEventually {
            predicate,
            timeout_ms,
            interval_ms,
        },
        Commands::TransportIdentity => RpcMethod::TransportIdentity,
        Commands::React { emoji, target } => RpcMethod::React { target, emoji },
        Commands::DeleteMessage { target } => RpcMethod::DeleteMessage { target },
        Commands::Reactions => RpcMethod::Reactions,
        Commands::Users => RpcMethod::Users,
        Commands::Keys { summary } => RpcMethod::Keys { summary },
        Commands::Networks => RpcMethod::Workspaces,
        Commands::IntroAttempts { peer } => RpcMethod::IntroAttempts { peer },
    };

    match rpc_call(&socket_path, method) {
        Ok(resp) => {
            // Print the full JSON response.
            let json = serde_json::to_string_pretty(&resp).unwrap_or_else(|_| "{}".to_string());
            println!("{}", json);

            if !resp.ok {
                std::process::exit(1);
            }

            // Special handling for assert commands: exit 1 if assertion failed.
            if let Some(data) = &resp.data {
                if let Some(pass) = data.get("pass") {
                    if pass == &serde_json::Value::Bool(false) {
                        std::process::exit(1);
                    }
                }
            }
        }
        Err(RpcClientError::DaemonNotRunning(path)) => {
            let err = serde_json::json!({
                "ok": false,
                "error": format!("daemon not running (socket: {})", path),
            });
            eprintln!("{}", serde_json::to_string_pretty(&err).unwrap());
            std::process::exit(2);
        }
        Err(e) => {
            let err = serde_json::json!({
                "ok": false,
                "error": e.to_string(),
            });
            eprintln!("{}", serde_json::to_string_pretty(&err).unwrap());
            std::process::exit(2);
        }
    }
}
