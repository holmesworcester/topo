use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use topo::db::{open_connection, schema::create_tables};
use topo::rpc::client::{rpc_call, RpcClientError};
use topo::rpc::protocol::RpcMethod;
use topo::rpc::server::run_rpc_server;
use topo::service;

#[derive(Parser)]
#[command(name = "topo")]
#[command(about = "High-performance QUIC sync system")]
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

    /// Run continuous sync (Ctrl-C to stop)
    Sync {
        /// Listen address
        #[arg(short, long, default_value = "127.0.0.1:4433")]
        bind: SocketAddr,
    },

    /// Print local transport identity — SPKI fingerprint from TLS cert (generates cert if needed)
    #[command(name = "transport-identity")]
    TransportIdentity,

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
        /// Workspace event ID hex (32 bytes)
        #[arg(short = 'n', long, default_value = "0102030405060708090a0b0c0d0e0f10")]
        workspace: String,
    },

    /// Show database status
    Status,

    /// Generate test messages
    Generate {
        #[arg(short, long, default_value = "100")]
        count: usize,
        #[arg(short = 'n', long, default_value = "0102030405060708090a0b0c0d0e0f10")]
        workspace: String,
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

    /// Interactive REPL mode with multi-account support
    Interactive,

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
        /// Bootstrap address (host:port) to embed in invite link
        #[arg(long)]
        bootstrap: String,
    },

    /// Accept a user invite link (bootstrap sync + identity chain creation)
    #[command(name = "accept-invite")]
    AcceptInvite {
        /// Invite link (quiet://invite/...)
        #[arg(long)]
        invite: String,
        /// Username for the new identity
        #[arg(long, default_value = "user")]
        username: String,
        /// Device name for the new identity
        #[arg(long, default_value = "device")]
        devicename: String,
    },
}

// ---------------------------------------------------------------------------
// Command routing
// ---------------------------------------------------------------------------

/// Try RPC to a running daemon; fall back to direct DB access on DaemonNotRunning.
fn try_rpc_or_direct(
    db: &str,
    socket: Option<&str>,
    method: RpcMethod,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let sock = socket
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| service::socket_path_for_db(db));

    match rpc_call(&sock, method.clone()) {
        Ok(resp) => {
            if !resp.ok {
                if let Some(err) = resp.error {
                    return Err(err.into());
                }
            }
            Ok(resp.data.unwrap_or(serde_json::Value::Null))
        }
        Err(RpcClientError::DaemonNotRunning(_)) => {
            // Fall back to direct DB access
            dispatch_direct(db, method)
        }
        Err(e) => Err(e.to_string().into()),
    }
}

/// Execute an RPC method directly against the DB (no daemon).
fn dispatch_direct(
    db: &str,
    method: RpcMethod,
) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
    let val = match method {
        RpcMethod::Status => serde_json::to_value(service::svc_status(db)?)?,
        RpcMethod::Messages { limit } => serde_json::to_value(service::svc_messages(db, limit)?)?,
        RpcMethod::Send { workspace, content } => {
            serde_json::to_value(service::svc_send(db, &workspace, &content)?)?
        }
        RpcMethod::Generate { count, workspace } => {
            serde_json::to_value(service::svc_generate(db, count, &workspace)?)?
        }
        RpcMethod::AssertNow { predicate } => {
            serde_json::to_value(service::svc_assert_now(db, &predicate)?)?
        }
        RpcMethod::AssertEventually {
            predicate,
            timeout_ms,
            interval_ms,
        } => serde_json::to_value(service::svc_assert_eventually(
            db,
            &predicate,
            timeout_ms,
            interval_ms,
        )?)?,
        RpcMethod::TransportIdentity => serde_json::to_value(service::svc_transport_identity(db)?)?,
        RpcMethod::React { target, emoji } => {
            serde_json::to_value(service::svc_react(db, &target, &emoji)?)?
        }
        RpcMethod::DeleteMessage { target } => {
            serde_json::to_value(service::svc_delete_message(db, &target)?)?
        }
        RpcMethod::Reactions => serde_json::to_value(service::svc_reactions(db)?)?,
        RpcMethod::Users => serde_json::to_value(service::svc_users(db)?)?,
        RpcMethod::Keys { summary } => serde_json::to_value(service::svc_keys(db, summary)?)?,
        RpcMethod::Workspaces => serde_json::to_value(service::svc_workspaces(db)?)?,
        RpcMethod::IntroAttempts { peer } => {
            serde_json::to_value(service::svc_intro_attempts(db, peer.as_deref())?)?
        }
        RpcMethod::CreateInvite { bootstrap } => {
            serde_json::to_value(service::svc_create_invite(db, &bootstrap)?)?
        }
        RpcMethod::AcceptInvite {
            invite,
            username,
            devicename,
        } => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            serde_json::to_value(rt.block_on(service::svc_accept_invite(
                db,
                &invite,
                &username,
                &devicename,
            ))?)?
        }
        RpcMethod::Shutdown => {
            return Err("Shutdown cannot be dispatched directly".into());
        }
    };
    Ok(val)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();
    let db = &cli.db;

    // Init tracing for commands that need it
    match &cli.command {
        Commands::Sync { .. }
        | Commands::Start { .. }
        | Commands::Intro { .. }
        | Commands::AcceptInvite { .. } => {
            let subscriber = FmtSubscriber::builder()
                .with_max_level(Level::INFO)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
        _ => {}
    }

    match cli.command {
        // ---------------------------------------------------------------
        // Daemon commands
        // ---------------------------------------------------------------
        Commands::Start { bind } => {
            let socket_path = cli
                .socket
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
            let db_path = Arc::new(db.to_string());

            // Start RPC server in a background thread
            let rpc_shutdown = shutdown.clone();
            let rpc_notify = shutdown_notify.clone();
            let rpc_socket = socket_path.clone();
            let rpc_db = db_path.clone();
            let rpc_handle = std::thread::spawn(move || {
                if let Err(e) = run_rpc_server(&rpc_socket, rpc_db, rpc_shutdown, rpc_notify) {
                    tracing::error!("RPC server error: {}", e);
                }
            });

            info!(
                "topo daemon started (db={}, socket={})",
                db,
                socket_path.display()
            );

            // Wait for either the node to finish (Ctrl-C) or an RPC shutdown signal.
            tokio::select! {
                result = topo::node::run_node(db, bind) => {
                    result?;
                }
                _ = shutdown_notify.notified() => {
                    info!("Shutdown requested via RPC");
                }
            }

            // Signal RPC server to stop
            shutdown.store(true, Ordering::Relaxed);
            let _ = rpc_handle.join();

            // Clean up socket file
            let _ = std::fs::remove_file(&socket_path);

            info!("topo daemon shut down cleanly");
        }

        Commands::Stop => {
            let socket_path = cli
                .socket
                .as_ref()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| service::socket_path_for_db(db));

            match rpc_call(&socket_path, RpcMethod::Shutdown) {
                Ok(_) => {
                    println!("daemon stopped");
                }
                Err(RpcClientError::DaemonNotRunning(_)) => {
                    println!("no daemon running for {}", db);
                }
                Err(e) => {
                    eprintln!("error stopping daemon: {}", e);
                    std::process::exit(1);
                }
            }
        }

        // ---------------------------------------------------------------
        // Direct-only commands
        // ---------------------------------------------------------------
        Commands::Sync { bind } => {
            topo::node::run_node(db, bind).await?;
        }

        Commands::Interactive => {
            topo::interactive::run_interactive()?;
        }

        Commands::Generate { count, workspace } => {
            let resp = service::svc_generate(db, count, &workspace)?;
            println!("Generated {} messages in {}", resp.count, db);
        }

        Commands::CreateInvite { bootstrap } => {
            let result = service::svc_create_invite(db, &bootstrap)?;
            println!("{}", result.invite_link);
        }

        Commands::AcceptInvite {
            invite,
            username,
            devicename,
        } => {
            let result = service::svc_accept_invite(db, &invite, &username, &devicename).await?;
            println!("Accepted invite");
            println!("  peer_id: {}", result.peer_id);
            println!("  user:    {}", result.user_event_id);
            println!("  peer:    {}", result.peer_shared_event_id);
        }

        // ---------------------------------------------------------------
        // Daemon-preferred with direct fallback
        // ---------------------------------------------------------------
        Commands::TransportIdentity => {
            let data = try_rpc_or_direct(db, cli.socket.as_deref(), RpcMethod::TransportIdentity)?;
            let fingerprint = data["fingerprint"].as_str().unwrap_or("");
            println!("{}", fingerprint);
        }

        Commands::Messages { limit } => {
            let data = try_rpc_or_direct(db, cli.socket.as_deref(), RpcMethod::Messages { limit })?;
            show_messages_from_json(db, &data);
        }

        Commands::Send { content, workspace } => {
            let data = try_rpc_or_direct(
                db,
                cli.socket.as_deref(),
                RpcMethod::Send {
                    workspace,
                    content: content.clone(),
                },
            )?;
            let event_id = data["event_id"].as_str().unwrap_or("");
            println!("Sent: {}", data["content"].as_str().unwrap_or(&content));
            println!("event_id:{}", event_id);
        }

        Commands::Status => {
            let data = try_rpc_or_direct(db, cli.socket.as_deref(), RpcMethod::Status)?;
            println!("STATUS ({}):", db);
            println!("  Events:    {} total", data["events_count"]);
            println!("  Messages:  {} projected", data["messages_count"]);
            println!("  Reactions: {} projected", data["reactions_count"]);
            println!("  Recorded:  {} events", data["recorded_events_count"]);
            println!("  NegItems:  {} indexed", data["neg_items_count"]);
        }

        Commands::AssertNow { predicate } => {
            let data = try_rpc_or_direct(
                db,
                cli.socket.as_deref(),
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
            let data = try_rpc_or_direct(
                db,
                cli.socket.as_deref(),
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
            let data = try_rpc_or_direct(
                db,
                cli.socket.as_deref(),
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
            let data = try_rpc_or_direct(
                db,
                cli.socket.as_deref(),
                RpcMethod::DeleteMessage { target },
            )?;
            let target_str = data["target"].as_str().unwrap_or("");
            println!(
                "Deleted message {}",
                &target_str[..target_str.len().min(16)]
            );
        }

        Commands::Reactions => {
            let data = try_rpc_or_direct(db, cli.socket.as_deref(), RpcMethod::Reactions)?;
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
            let data = try_rpc_or_direct(db, cli.socket.as_deref(), RpcMethod::Users)?;
            println!("USERS ({}):", db);
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("  (none)");
                } else {
                    for (i, item) in items.iter().enumerate() {
                        println!(
                            "  {}. user_{}",
                            i + 1,
                            short_id(item["event_id"].as_str().unwrap_or(""))
                        );
                    }
                }
            } else {
                println!("  (none)");
            }
        }

        Commands::Keys { summary } => {
            let data = try_rpc_or_direct(db, cli.socket.as_deref(), RpcMethod::Keys { summary })?;
            println!("KEYS ({}):", db);
            println!("  Users: {}", data["user_count"]);
            println!("  Peers: {}", data["peer_count"]);
            println!("  Admins: {}", data["admin_count"]);
            println!("  TransportKeys: {}", data["transport_count"]);
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
            let data = try_rpc_or_direct(db, cli.socket.as_deref(), RpcMethod::Workspaces)?;
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
            let data =
                try_rpc_or_direct(db, cli.socket.as_deref(), RpcMethod::IntroAttempts { peer })?;
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

fn show_messages_from_json(db_path: &str, data: &serde_json::Value) {
    let messages = match data["messages"].as_array() {
        Some(msgs) => msgs,
        None => {
            println!("MESSAGES ({}):", db_path);
            println!("  (no messages)");
            return;
        }
    };

    if messages.is_empty() {
        println!("MESSAGES ({}):", db_path);
        println!("  (no messages)");
        return;
    }

    let total = data["total"].as_i64().unwrap_or(0);
    println!("MESSAGES ({}, {} total):", db_path, total);
    println!();

    let mut last_author = String::new();
    for (i, msg) in messages.iter().enumerate() {
        let created_at = msg["created_at"].as_i64().unwrap_or(0);
        let ts = format_timestamp(created_at);
        let author_id = msg["author_id"].as_str().unwrap_or("");
        let author = short_id(author_id);
        let content = msg["content"].as_str().unwrap_or("");
        let id = msg["id"].as_str().unwrap_or("");

        if author_id != last_author {
            if i > 0 {
                println!();
            }
            println!("  {} [{}]", author, ts);
            println!("    {}. {}", i + 1, content);
            println!("       id: {}", id);
            last_author = author_id.to_string();
        } else {
            println!("    {}. {}", i + 1, content);
            println!("       id: {}", id);
        }
    }
    println!();
}
