use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use poc_7::db::{open_connection, schema::{create_tables, backfill_legacy_messages, count_legacy_messages}};
use poc_7::events::{MessageEvent, ParsedEvent};
use poc_7::identity::{cert_paths_from_db, load_identity_from_db, local_identity_from_db};
use poc_7::projection::create::create_event_sync;
use poc_7::sync::engine::{accept_loop, connect_loop};
use poc_7::transport::{
    AllowedPeers,
    create_client_endpoint,
    create_server_endpoint,
    extract_spki_fingerprint,
    load_or_generate_cert,
};

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
        /// Allowed peer fingerprints (hex, repeatable)
        #[arg(long = "pin-peer")]
        pin_peer: Vec<String>,
    },

    /// Print local SPKI fingerprint (generates cert if needed)
    Identity {
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
        /// Channel ID hex (16 bytes)
        #[arg(short = 'C', long, default_value = "0102030405060708090a0b0c0d0e0f10")]
        channel: String,
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
        #[arg(short = 'C', long, default_value = "0102030405060708090a0b0c0d0e0f10")]
        channel: String,
    },

    /// Backfill legacy messages (from Phase 0 migration) to the local identity
    BackfillIdentity {
        #[arg(short, long, default_value = "server.db")]
        db: String,
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    // Only init tracing for network commands (avoid polluting message output)
    match &cli.command {
        Commands::Sync { .. } => {
            let subscriber = FmtSubscriber::builder()
                .with_max_level(Level::INFO)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
        }
        _ => {}
    }

    match cli.command {
        Commands::Sync { bind, connect, db, pin_peer } => {
            run_sync(bind, connect, &db, &pin_peer).await?;
        }
        Commands::Identity { db } => {
            run_identity(&db)?;
        }
        Commands::Messages { db, limit } => {
            show_messages(&db, limit)?;
        }
        Commands::Send { content, db, channel } => {
            send_message(&db, &channel, &content)?;
        }
        Commands::Status { db } => {
            show_status(&db)?;
        }
        Commands::Generate { count, db, channel } => {
            generate_messages(&db, count, &channel)?;
        }
        Commands::BackfillIdentity { db } => {
            backfill_identity(&db)?;
        }
        Commands::AssertNow { predicate, db } => {
            let code = run_assert_now(&db, &predicate)?;
            std::process::exit(code);
        }
        Commands::AssertEventually { predicate, db, timeout_ms, interval_ms } => {
            let code = run_assert_eventually(&db, &predicate, timeout_ms, interval_ms)?;
            std::process::exit(code);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

fn run_identity(db_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = cert_paths_from_db(db_path);
    let (cert_der, _) = load_or_generate_cert(&cert_path, &key_path)?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    println!("{}", hex::encode(fp));
    Ok(())
}

fn backfill_identity(db_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = local_identity_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let legacy_count = count_legacy_messages(&db)?;
    if legacy_count == 0 {
        println!("No legacy messages to backfill.");
        return Ok(());
    }

    let updated = backfill_legacy_messages(&db, &recorded_by)?;
    println!("Backfilled {} legacy messages to identity {}", updated, &recorded_by[..16]);
    Ok(())
}

// ---------------------------------------------------------------------------
// Message UI
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
    use std::time::{UNIX_EPOCH, Duration};
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
        1 => "Jan", 2 => "Feb", 3 => "Mar", 4 => "Apr",
        5 => "May", 6 => "Jun", 7 => "Jul", 8 => "Aug",
        9 => "Sep", 10 => "Oct", 11 => "Nov", 12 => "Dec",
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

fn show_messages(db_path: &str, limit: usize) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = load_identity_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let limit_clause = if limit > 0 {
        format!("LIMIT {}", limit)
    } else {
        String::new()
    };

    let query = format!(
        "SELECT message_id, author_id, content, created_at
         FROM messages WHERE recorded_by = ?1 ORDER BY created_at ASC {}",
        limit_clause
    );

    let mut stmt = db.prepare(&query)?;
    let rows: Vec<(String, String, String, i64)> = stmt.query_map(rusqlite::params![&recorded_by], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, i64>(3)?,
        ))
    })?.collect::<Result<Vec<_>, _>>()?;

    let total: i64 = db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![&recorded_by],
        |row| row.get(0),
    )?;

    if rows.is_empty() {
        println!("MESSAGES ({}):", db_path);
        println!("  (no messages)");
        return Ok(());
    }

    println!("MESSAGES ({}, {} total):", db_path, total);
    println!();

    let mut last_author = String::new();
    for (i, (_, author_id, content, created_at)) in rows.iter().enumerate() {
        let ts = format_timestamp(*created_at);
        let author = short_id(author_id);

        if *author_id != last_author {
            // New author group
            if i > 0 { println!(); }
            println!("  {} [{}]", author, ts);
            println!("    {}. {}", i + 1, content);
            last_author = author_id.clone();
        } else {
            // Same author, continuation
            println!("    {}. {}", i + 1, content);
        }
    }
    println!();

    Ok(())
}

fn parse_channel_hex(channel_hex: &str) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let channel_bytes = hex::decode(channel_hex)?;
    if channel_bytes.len() > 32 {
        return Err("Channel ID must be at most 32 bytes".into());
    }
    let mut channel_id = [0u8; 32];
    channel_id[..channel_bytes.len()].copy_from_slice(&channel_bytes);
    Ok(channel_id)
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn send_message(db_path: &str, channel_hex: &str, content: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = local_identity_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let channel_id = parse_channel_hex(channel_hex)?;
    let author_id: [u8; 32] = rand::random();

    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: current_timestamp_ms(),
        channel_id,
        author_id,
        content: content.to_string(),
    });
    create_event_sync(&db, &recorded_by, &msg)
        .map_err(|e| format!("create event error: {}", e))?;

    println!("Sent: {}", content);

    Ok(())
}

fn show_status(db_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = load_identity_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let events_count: i64 = db.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0)).unwrap_or(0);
    let messages_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
        rusqlite::params![&recorded_by],
        |row| row.get(0),
    ).unwrap_or(0);
    let reactions_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
        rusqlite::params![&recorded_by],
        |row| row.get(0),
    ).unwrap_or(0);
    let neg_items_count: i64 = db.query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0)).unwrap_or(0);
    let recorded_events_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
        rusqlite::params![&recorded_by],
        |row| row.get(0),
    ).unwrap_or(0);

    let legacy_count = count_legacy_messages(&db)?;

    println!("STATUS ({}):", db_path);
    println!("  Events:    {} total", events_count);
    println!("  Messages:  {} projected", messages_count);
    println!("  Reactions: {} projected", reactions_count);
    println!("  Recorded:  {} events", recorded_events_count);
    println!("  NegItems:  {} indexed", neg_items_count);
    if legacy_count > 0 {
        println!("  Legacy:    {} unscoped messages (run 'backfill-identity' to assign)", legacy_count);
    }

    Ok(())
}

fn generate_messages(db_path: &str, count: usize, channel_hex: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = local_identity_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let channel_id = parse_channel_hex(channel_hex)?;
    let author_id: [u8; 32] = rand::random();

    db.execute("BEGIN", [])?;
    for i in 0..count {
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: current_timestamp_ms(),
            channel_id,
            author_id,
            content: format!("Message {}", i),
        });
        create_event_sync(&db, &recorded_by, &msg)
            .map_err(|e| format!("create event error: {}", e))?;
    }
    db.execute("COMMIT", [])?;

    println!("Generated {} messages in {}", count, db_path);

    Ok(())
}

// ---------------------------------------------------------------------------
// Assert commands
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Op {
    Eq,
    Ne,
    Ge,
    Le,
    Gt,
    Lt,
}

impl Op {
    fn eval(self, actual: i64, expected: i64) -> bool {
        match self {
            Op::Eq => actual == expected,
            Op::Ne => actual != expected,
            Op::Ge => actual >= expected,
            Op::Le => actual <= expected,
            Op::Gt => actual > expected,
            Op::Lt => actual < expected,
        }
    }

    fn symbol(self) -> &'static str {
        match self {
            Op::Eq => "==",
            Op::Ne => "!=",
            Op::Ge => ">=",
            Op::Le => "<=",
            Op::Gt => ">",
            Op::Lt => "<",
        }
    }
}

fn parse_predicate(s: &str) -> Result<(String, Op, i64), String> {
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(format!(
            "predicate must be \"field op value\", got {} parts: {:?}",
            parts.len(), s
        ));
    }
    let field = parts[0].to_string();
    let op = match parts[1] {
        "==" => Op::Eq,
        "!=" => Op::Ne,
        ">=" => Op::Ge,
        "<=" => Op::Le,
        ">" => Op::Gt,
        "<" => Op::Lt,
        other => return Err(format!("unknown operator: {}", other)),
    };
    let value: i64 = parts[2]
        .parse()
        .map_err(|e| format!("invalid value '{}': {}", parts[2], e))?;
    Ok((field, op, value))
}

fn query_field(db: &rusqlite::Connection, field: &str, recorded_by: &str) -> Result<i64, String> {
    match field {
        "store_count" | "events_count" => db.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .map_err(|e| format!("query failed: {}", e)),
        "message_count" => db.query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        ).map_err(|e| format!("query failed: {}", e)),
        "reaction_count" => db.query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        ).map_err(|e| format!("query failed: {}", e)),
        "neg_items_count" => db.query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0))
            .map_err(|e| format!("query failed: {}", e)),
        "recorded_events_count" => db.query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        ).map_err(|e| format!("query failed: {}", e)),
        other => Err(format!("unknown field: {}", other)),
    }
}

fn run_assert_now(
    db_path: &str,
    predicate_str: &str,
) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = load_identity_from_db(db_path)?;
    let (field, op, expected) = parse_predicate(predicate_str)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;
    let actual = query_field(&db, &field, &recorded_by)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    if op.eval(actual, expected) {
        println!("PASS: {} = {} (expected {} {})", field, actual, op.symbol(), expected);
        Ok(0)
    } else {
        println!("FAIL: {} = {} (expected {} {})", field, actual, op.symbol(), expected);
        Ok(1)
    }
}

fn run_assert_eventually(
    db_path: &str,
    predicate_str: &str,
    timeout_ms: u64,
    interval_ms: u64,
) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = load_identity_from_db(db_path)?;
    let (field, op, expected) = parse_predicate(predicate_str)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;
    let start = Instant::now();
    let timeout = Duration::from_millis(timeout_ms);
    let interval = Duration::from_millis(interval_ms);

    loop {
        let actual = query_field(&db, &field, &recorded_by)
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
        if op.eval(actual, expected) {
            println!("PASS: {} = {} (expected {} {})", field, actual, op.symbol(), expected);
            return Ok(0);
        }
        if start.elapsed() >= timeout {
            println!(
                "TIMEOUT: {} = {} (expected {} {}) after {}ms",
                field, actual, op.symbol(), expected, timeout_ms
            );
            return Ok(1);
        }
        std::thread::sleep(interval);
    }
}

// ---------------------------------------------------------------------------
// Network (sync)
// ---------------------------------------------------------------------------

async fn run_sync(
    bind: SocketAddr,
    connect: Option<SocketAddr>,
    db_path: &str,
    pin_peers: &[String],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if pin_peers.is_empty() {
        return Err("--pin-peer is required: at least one peer fingerprint must be specified. \
            Use `poc-7 identity --db <peer-db>` to get a peer's fingerprint.".into());
    }

    // Initialize DB before spawning concurrent loops (avoids create_tables race)
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    let (cert_path, key_path) = cert_paths_from_db(db_path);
    let (cert, key) = load_or_generate_cert(&cert_path, &key_path)?;
    let recorded_by = {
        let fp = extract_spki_fingerprint(cert.as_ref())?;
        hex::encode(fp)
    };
    let allowed_peers = Arc::new(AllowedPeers::from_hex_strings(pin_peers)?);

    let server_endpoint = create_server_endpoint(bind, cert.clone(), key.clone_key(), allowed_peers.clone())?;
    info!("Listening on {}", server_endpoint.local_addr()?);

    let db_owned = db_path.to_string();
    let recorded_by_clone = recorded_by.clone();
    let accept_handle = tokio::task::spawn_blocking({
        let db = db_owned.clone();
        move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = accept_loop(&db, &recorded_by_clone, server_endpoint).await {
                    tracing::warn!("accept_loop exited: {}", e);
                }
            });
        }
    });

    if let Some(remote) = connect {
        let client_endpoint = create_client_endpoint(
            "0.0.0.0:0".parse()?,
            cert,
            key,
            allowed_peers,
        )?;
        let db = db_owned.clone();
        let recorded_by_clone = recorded_by.clone();
        let connect_handle = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = connect_loop(&db, &recorded_by_clone, client_endpoint, remote).await {
                    tracing::warn!("connect_loop exited: {}", e);
                }
            });
        });

        tokio::select! {
            _ = accept_handle => {}
            _ = connect_handle => {}
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl-C received, shutting down");
            }
        }
    } else {
        tokio::select! {
            _ = accept_handle => {}
            _ = tokio::signal::ctrl_c() => {
                info!("Ctrl-C received, shutting down");
            }
        }
    }

    Ok(())
}
