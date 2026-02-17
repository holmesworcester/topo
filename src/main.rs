use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use tracing::{Level};
use tracing_subscriber::FmtSubscriber;

use poc_7::service;

#[derive(Parser)]
#[command(name = "poc-7")]
#[command(about = "High-performance QUIC sync system")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run continuous sync (Ctrl-C to stop)
    Sync {
        /// Listen address
        #[arg(short, long, default_value = "127.0.0.1:4433")]
        bind: SocketAddr,
        /// Peer to connect to (if omitted, just listens)
        #[arg(short = 'r', long)]
        connect: Option<SocketAddr>,
        #[arg(short, long, default_value = "server.db")]
        db: String,
    },

    /// Print local transport identity — SPKI fingerprint from TLS cert (generates cert if needed)
    #[command(name = "transport-identity")]
    TransportIdentity {
        #[arg(short, long, default_value = "server.db")]
        db: String,
    },

    /// List messages
    Messages {
        #[arg(short, long, default_value = "server.db")]
        db: String,
        /// Max messages to show (0 = all)
        #[arg(short, long, default_value = "50")]
        limit: usize,
    },

    /// Send a message
    Send {
        /// Message content
        content: String,
        #[arg(short, long, default_value = "server.db")]
        db: String,
        /// Workspace event ID hex (32 bytes)
        #[arg(short = 'n', long, default_value = "0102030405060708090a0b0c0d0e0f10")]
        workspace: String,
    },

    /// Show database status
    Status {
        #[arg(short, long, default_value = "server.db")]
        db: String,
    },

    /// Generate test messages
    Generate {
        #[arg(short, long, default_value = "100")]
        count: usize,
        #[arg(short, long, default_value = "server.db")]
        db: String,
        #[arg(short = 'n', long, default_value = "0102030405060708090a0b0c0d0e0f10")]
        workspace: String,
    },

    /// Assert a predicate holds right now (exit 0 = pass, exit 1 = fail)
    AssertNow {
        /// Predicate: "field op value" (e.g. "store_count >= 10")
        predicate: String,
        #[arg(short, long, default_value = "server.db")]
        db: String,
    },

    /// Assert a predicate eventually holds (exit 0 = pass, exit 1 = timeout)
    AssertEventually {
        /// Predicate: "field op value" (e.g. "message_count == 50")
        predicate: String,
        #[arg(short, long, default_value = "server.db")]
        db: String,
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
        #[arg(short, long, default_value = "server.db")]
        db: String,
    },

    /// Delete a message
    #[command(name = "delete-message")]
    DeleteMessage {
        /// Target message event ID (hex)
        #[arg(long)]
        target: String,
        #[arg(short, long, default_value = "server.db")]
        db: String,
    },

    /// List reactions
    Reactions {
        #[arg(short, long, default_value = "server.db")]
        db: String,
    },

    /// List users from projection
    Users {
        #[arg(short, long, default_value = "server.db")]
        db: String,
    },

    /// List keys from projection
    Keys {
        #[arg(short, long, default_value = "server.db")]
        db: String,
        /// Show summary only
        #[arg(long)]
        summary: bool,
    },

    /// List workspaces from projection
    Networks {
        #[arg(short, long, default_value = "server.db")]
        db: String,
    },

    /// Send intro offers to two peers so they can hole-punch a direct connection
    Intro {
        #[arg(short, long, default_value = "server.db")]
        db: String,
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
        #[arg(short, long, default_value = "server.db")]
        db: String,
        /// Filter by peer SPKI fingerprint (hex)
        #[arg(long)]
        peer: Option<String>,
    },

    /// Create a user invite link for the active workspace
    #[command(name = "create-invite")]
    CreateInvite {
        #[arg(short, long, default_value = "server.db")]
        db: String,
        /// Bootstrap address (host:port) to embed in invite link
        #[arg(long)]
        bootstrap: String,
    },

    /// Accept a user invite link (bootstrap sync + identity chain creation)
    #[command(name = "accept-invite")]
    AcceptInvite {
        #[arg(short, long, default_value = "server.db")]
        db: String,
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    // Only init tracing for sync commands (avoid polluting message output)
    match &cli.command {
        Commands::Sync { .. } | Commands::Intro { .. } | Commands::AcceptInvite { .. } => {
            let subscriber = FmtSubscriber::builder()
                .with_max_level(Level::INFO)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
        _ => {}
    }

    match cli.command {
        Commands::Sync {
            bind,
            connect,
            db,
        } => {
            service::svc_sync(bind, connect.clone(), &db).await?;
        }
        Commands::TransportIdentity { db } => {
            let resp = service::svc_transport_identity(&db)?;
            println!("{}", resp.fingerprint);
        }
        Commands::Messages { db, limit } => {
            show_messages(&db, limit)?;
        }
        Commands::Send {
            content,
            db,
            workspace,
        } => {
            let resp = service::svc_send(&db, &workspace, &content)?;
            println!("Sent: {}", resp.content);
        }
        Commands::Status { db } => {
            let resp = service::svc_status(&db)?;
            println!("STATUS ({}):", db);
            println!("  Events:    {} total", resp.events_count);
            println!("  Messages:  {} projected", resp.messages_count);
            println!("  Reactions: {} projected", resp.reactions_count);
            println!("  Recorded:  {} events", resp.recorded_events_count);
            println!("  NegItems:  {} indexed", resp.neg_items_count);
        }
        Commands::Generate {
            count,
            db,
            workspace,
        } => {
            let resp = service::svc_generate(&db, count, &workspace)?;
            println!("Generated {} messages in {}", resp.count, db);
        }
        Commands::AssertNow { predicate, db } => {
            let resp = service::svc_assert_now(&db, &predicate)?;
            if resp.pass {
                println!(
                    "PASS: {} = {} (expected {} {})",
                    resp.field, resp.actual, resp.op, resp.expected
                );
                std::process::exit(0);
            } else {
                println!(
                    "FAIL: {} = {} (expected {} {})",
                    resp.field, resp.actual, resp.op, resp.expected
                );
                std::process::exit(1);
            }
        }
        Commands::AssertEventually {
            predicate,
            db,
            timeout_ms,
            interval_ms,
        } => {
            let resp = service::svc_assert_eventually(&db, &predicate, timeout_ms, interval_ms)?;
            if resp.pass {
                println!(
                    "PASS: {} = {} (expected {} {})",
                    resp.field, resp.actual, resp.op, resp.expected
                );
                std::process::exit(0);
            } else {
                println!(
                    "TIMEOUT: {} = {} (expected {} {}) after {}ms",
                    resp.field, resp.actual, resp.op, resp.expected, timeout_ms
                );
                std::process::exit(1);
            }
        }
        Commands::Interactive => {
            poc_7::interactive::run_interactive()?;
        }
        Commands::React { emoji, target, db } => {
            let resp = service::svc_react(&db, &target, &emoji)?;
            println!("Reacted {} ({})", resp.emoji, &resp.event_id[..8]);
        }
        Commands::DeleteMessage { target, db } => {
            let resp = service::svc_delete_message(&db, &target)?;
            println!(
                "Deleted message {}",
                &resp.target[..resp.target.len().min(16)]
            );
        }
        Commands::Reactions { db } => {
            let items = service::svc_reactions(&db)?;
            println!("REACTIONS ({}):", db);
            if items.is_empty() {
                println!("  (none)");
            } else {
                for item in &items {
                    println!(
                        "  {} -> {} {}",
                        short_id(&item.event_id),
                        short_id(&item.target_event_id),
                        item.emoji
                    );
                }
            }
        }
        Commands::Users { db } => {
            let items = service::svc_users(&db)?;
            println!("USERS ({}):", db);
            if items.is_empty() {
                println!("  (none)");
            } else {
                for (i, item) in items.iter().enumerate() {
                    println!("  {}. user_{}", i + 1, short_id(&item.event_id));
                }
            }
        }
        Commands::Keys { db, summary } => {
            let resp = service::svc_keys(&db, summary)?;
            println!("KEYS ({}):", db);
            println!("  Users: {}", resp.user_count);
            println!("  Peers: {}", resp.peer_count);
            println!("  Admins: {}", resp.admin_count);
            println!("  TransportKeys: {}", resp.transport_count);
            if !summary {
                for eid in &resp.users {
                    println!("    user {}", short_id(eid));
                }
                for eid in &resp.peers {
                    println!("    peer {}", short_id(eid));
                }
            }
        }
        Commands::Networks { db } => {
            let items = service::svc_workspaces(&db)?;
            println!("WORKSPACES ({}):", db);
            if items.is_empty() {
                println!("  (none)");
            } else {
                for (i, item) in items.iter().enumerate() {
                    println!(
                        "  {}. {} ({})",
                        i + 1,
                        item.name,
                        short_id(&item.event_id)
                    );
                }
            }
        }
        Commands::Intro {
            db,
            peer_a,
            peer_b,
            ttl_ms,
            attempt_window_ms,
        } => {
            match service::svc_intro(&db, &peer_a, &peer_b, ttl_ms, attempt_window_ms).await {
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
            }
        }
        Commands::IntroAttempts { db, peer } => {
            let items = service::svc_intro_attempts(&db, peer.as_deref())?;
            if items.is_empty() {
                println!("No intro attempts recorded.");
            } else {
                for r in &items {
                    println!("  intro_id:  {}...", &r.intro_id[..16]);
                    println!("  peer:      {}", &r.other_peer_id[..16]);
                    println!("  via:       {}", &r.introduced_by_peer_id[..16]);
                    println!("  endpoint:  {}:{}", r.origin_ip, r.origin_port);
                    println!("  status:    {}", r.status);
                    if let Some(ref err) = r.error {
                        println!("  error:     {}", err);
                    }
                    println!("  created:   {}", r.created_at);
                    println!();
                }
            }
        }
        Commands::CreateInvite { db, bootstrap } => {
            let result = service::svc_create_invite(&db, &bootstrap)?;
            println!("{}", result.invite_link);
        }
        Commands::AcceptInvite {
            db,
            invite,
            username,
            devicename,
        } => {
            let result = service::svc_accept_invite(&db, &invite, &username, &devicename).await?;
            println!("Accepted invite");
            println!("  peer_id: {}", result.peer_id);
            println!("  user:    {}", result.user_event_id);
            println!("  peer:    {}", result.peer_shared_event_id);
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
    // Format as "Jan 15 10:30"
    let secs = dt.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;

    // Simple month/day calculation
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
    // Civil days from epoch to y/m/d (simplified)
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
// Messages display (uses service + CLI formatting)
// ---------------------------------------------------------------------------

fn show_messages(
    db_path: &str,
    limit: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let resp = service::svc_messages(db_path, limit)?;

    if resp.messages.is_empty() {
        println!("MESSAGES ({}):", db_path);
        println!("  (no messages)");
        return Ok(());
    }

    println!("MESSAGES ({}, {} total):", db_path, resp.total);
    println!();

    let mut last_author = String::new();
    for (i, msg) in resp.messages.iter().enumerate() {
        let ts = format_timestamp(msg.created_at);
        let author = short_id(&msg.author_id);

        if msg.author_id != last_author {
            // New author group
            if i > 0 {
                println!();
            }
            println!("  {} [{}]", author, ts);
            println!("    {}. {}", i + 1, msg.content);
            println!("       id: {}", msg.id);
            last_author = msg.author_id.clone();
        } else {
            // Same author, continuation
            println!("    {}. {}", i + 1, msg.content);
            println!("       id: {}", msg.id);
        }
    }
    println!();

    Ok(())
}
