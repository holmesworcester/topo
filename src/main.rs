use clap::{Parser, Subcommand};
use rusqlite::OptionalExtension;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use ed25519_dalek::SigningKey;
use poc_7::crypto::EventId;
use poc_7::db::{
    open_connection,
    schema::{backfill_legacy_messages, count_legacy_messages, create_tables},
    transport_trust::allowed_peers_combined,
};
use poc_7::events::{
    DeviceInviteFirstEvent, InviteAcceptedEvent, MessageDeletionEvent, MessageEvent, ParsedEvent,
    PeerSharedFirstEvent, ReactionEvent, UserBootEvent, UserInviteBootEvent, WorkspaceEvent,
};
use poc_7::projection::create::{create_event_sync, create_signed_event_sync, event_id_or_blocked};
use poc_7::projection::pipeline::project_one;
use poc_7::sync::engine::{accept_loop, connect_loop};
use poc_7::transport::{
    AllowedPeers,
    create_dual_endpoint,
    extract_spki_fingerprint,
    load_or_generate_cert,
};
use poc_7::transport_identity::{
    ensure_transport_peer_id_from_db, load_transport_peer_id_from_db, transport_cert_paths_from_db,
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

    /// Print local transport identity — SPKI fingerprint from TLS cert (generates cert if needed)
    #[command(name = "transport-identity", alias = "identity")]
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

    /// Backfill legacy messages to the local transport identity (cert/key/SPKI)
    #[command(name = "backfill-transport-identity", alias = "backfill-identity")]
    BackfillTransportIdentity {
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
        /// Allowed peer fingerprints (hex, repeatable)
        #[arg(long = "pin-peer")]
        pin_peer: Vec<String>,
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

}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cli = Cli::parse();

    // Only init tracing for sync commands (avoid polluting message output)
    match &cli.command {
        Commands::Sync { .. } | Commands::Intro { .. } => {
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
            pin_peer,
        } => {
            run_sync(bind, connect, &db, &pin_peer).await?;
        }
        Commands::TransportIdentity { db } => {
            run_identity(&db)?;
        }
        Commands::Messages { db, limit } => {
            show_messages(&db, limit)?;
        }
        Commands::Send { content, db, workspace } => {
            send_message(&db, &workspace, &content)?;
        }
        Commands::Status { db } => {
            show_status(&db)?;
        }
        Commands::Generate { count, db, workspace } => {
            generate_messages(&db, count, &workspace)?;
        }
        Commands::BackfillTransportIdentity { db } => {
            backfill_identity(&db)?;
        }
        Commands::AssertNow { predicate, db } => {
            let code = run_assert_now(&db, &predicate)?;
            std::process::exit(code);
        }
        Commands::AssertEventually {
            predicate,
            db,
            timeout_ms,
            interval_ms,
        } => {
            let code = run_assert_eventually(&db, &predicate, timeout_ms, interval_ms)?;
            std::process::exit(code);
        }
        Commands::Interactive => {
            poc_7::interactive::run_interactive()?;
        }
        Commands::React { emoji, target, db } => {
            cli_react(&db, &target, &emoji)?;
        }
        Commands::DeleteMessage { target, db } => {
            cli_delete_message(&db, &target)?;
        }
        Commands::Reactions { db } => {
            cli_reactions(&db)?;
        }
        Commands::Users { db } => {
            cli_users(&db)?;
        }
        Commands::Keys { db, summary } => {
            cli_keys(&db, summary)?;
        }
        Commands::Networks { db } => {
            cli_workspaces(&db)?;
        }
        Commands::Intro { db, peer_a, peer_b, pin_peer, ttl_ms, attempt_window_ms } => {
            cli_intro(&db, &peer_a, &peer_b, &pin_peer, ttl_ms, attempt_window_ms).await?;
        }
        Commands::IntroAttempts { db, peer } => {
            cli_intro_attempts(&db, peer.as_deref())?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

fn run_identity(db_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, key_path) = transport_cert_paths_from_db(db_path);
    let (cert_der, _) = load_or_generate_cert(&cert_path, &key_path)?;
    let fp = extract_spki_fingerprint(cert_der.as_ref())?;
    println!("{}", hex::encode(fp));
    Ok(())
}

fn backfill_identity(db_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = ensure_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let legacy_count = count_legacy_messages(&db)?;
    if legacy_count == 0 {
        println!("No legacy messages to backfill.");
        return Ok(());
    }

    let updated = backfill_legacy_messages(&db, &recorded_by)?;
    println!(
        "Backfilled {} legacy messages to identity {}",
        updated,
        &recorded_by[..16]
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Message UI
// ---------------------------------------------------------------------------

fn short_id(b64: &str) -> &str {
    &b64[..b64.len().min(8)]
}

fn base64_to_hex(b64: &str) -> String {
    use base64::Engine;
    match base64::engine::general_purpose::STANDARD.decode(b64) {
        Ok(bytes) => hex::encode(bytes),
        Err(_) => b64.to_string(),
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

fn show_messages(
    db_path: &str,
    limit: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
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
    let rows: Vec<(String, String, String, i64)> = stmt
        .query_map(rusqlite::params![&recorded_by], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

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
    for (i, (msg_id_b64, author_id, content, created_at)) in rows.iter().enumerate() {
        let ts = format_timestamp(*created_at);
        let author = short_id(author_id);

        // Convert base64 message_id to hex for use with --target
        let msg_id_hex = base64_to_hex(msg_id_b64);

        if *author_id != last_author {
            // New author group
            if i > 0 {
                println!();
            }
            println!("  {} [{}]", author, ts);
            println!("    {}. {}", i + 1, content);
            println!("       id: {}", msg_id_hex);
            last_author = author_id.clone();
        } else {
            // Same author, continuation
            println!("    {}. {}", i + 1, content);
            println!("       id: {}", msg_id_hex);
        }
    }
    println!();

    Ok(())
}

fn parse_workspace_hex(workspace_hex: &str) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let workspace_bytes = hex::decode(workspace_hex)?;
    if workspace_bytes.len() > 32 {
        return Err("Workspace event ID must be at most 32 bytes".into());
    }
    let mut workspace_event_id = [0u8; 32];
    workspace_event_id[..workspace_bytes.len()].copy_from_slice(&workspace_bytes);
    Ok(workspace_event_id)
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Derive a stable 32-byte author_id from the transport peer identity string.
/// This ensures send and delete-message use the same author, so deletion
/// author-matching works correctly.
fn stable_author_id(peer_id: &str) -> [u8; 32] {
    use blake2::digest::consts::U32;
    use blake2::{Blake2b, Digest};
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(b"author-id:");
    hasher.update(peer_id.as_bytes());
    let hash = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&hash);
    out
}

fn ensure_local_signer_tables(
    db: &rusqlite::Connection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Canonical local signer pointer for this transport identity.
    db.execute(
        "CREATE TABLE IF NOT EXISTS local_peer_signers (
            recorded_by TEXT PRIMARY KEY,
            event_id TEXT NOT NULL,
            signing_key BLOB NOT NULL,
            updated_at INTEGER NOT NULL
        )",
        [],
    )?;
    // Legacy table retained for backward compatibility with older builds.
    db.execute(
        "CREATE TABLE IF NOT EXISTS local_signing_keys (event_id TEXT PRIMARY KEY, signing_key BLOB NOT NULL)",
        [],
    )?;
    Ok(())
}

fn decode_signing_key(
    key_bytes: Vec<u8>,
) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    let key_arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "bad signing key length in local signer table")?;
    Ok(SigningKey::from_bytes(&key_arr))
}

fn persist_local_peer_signer(
    db: &rusqlite::Connection,
    recorded_by: &str,
    event_id_b64: &str,
    signing_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    ensure_local_signer_tables(db)?;
    let now = current_timestamp_ms() as i64;
    db.execute(
        "INSERT INTO local_peer_signers (recorded_by, event_id, signing_key, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(recorded_by)
         DO UPDATE SET event_id = excluded.event_id,
                       signing_key = excluded.signing_key,
                       updated_at = excluded.updated_at",
        rusqlite::params![
            recorded_by,
            event_id_b64,
            signing_key.to_bytes().as_slice(),
            now
        ],
    )?;
    // Keep legacy rows up to date so downgrades remain usable.
    db.execute(
        "INSERT OR REPLACE INTO local_signing_keys (event_id, signing_key) VALUES (?1, ?2)",
        rusqlite::params![event_id_b64, signing_key.to_bytes().as_slice()],
    )?;
    Ok(())
}

fn load_local_peer_signer(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> Result<Option<(EventId, SigningKey)>, Box<dyn std::error::Error + Send + Sync>> {
    ensure_local_signer_tables(db)?;

    // Preferred source: explicit local signer mapping for this transport identity.
    if let Some((eid_b64, key_bytes)) = db
        .query_row(
            "SELECT l.event_id, l.signing_key
             FROM local_peer_signers l
             INNER JOIN peers_shared p
               ON p.recorded_by = l.recorded_by AND p.event_id = l.event_id
             WHERE l.recorded_by = ?1
             LIMIT 1",
            rusqlite::params![recorded_by],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
    {
        let signing_key = decode_signing_key(key_bytes)?;
        let eid = poc_7::crypto::event_id_from_base64(&eid_b64)
            .ok_or("bad local peer signer event_id")?;
        return Ok(Some((eid, signing_key)));
    }

    // Backward-compat: recover from legacy local_signing_keys rows if possible.
    let legacy: Option<(String, Vec<u8>)> = db
        .query_row(
            "SELECT l.event_id, l.signing_key
             FROM local_signing_keys l
             INNER JOIN peers_shared p
               ON p.recorded_by = ?1 AND p.event_id = l.event_id
             ORDER BY p.rowid DESC
             LIMIT 1",
            rusqlite::params![recorded_by],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?;

    if let Some((eid_b64, key_bytes)) = legacy {
        let signing_key = decode_signing_key(key_bytes)?;
        let eid = poc_7::crypto::event_id_from_base64(&eid_b64)
            .ok_or("bad legacy local signer event_id")?;
        persist_local_peer_signer(db, recorded_by, &eid_b64, &signing_key)?;
        return Ok(Some((eid, signing_key)));
    }

    Ok(None)
}

/// Ensure a local identity chain exists for this transport identity.
/// Uses explicit local signer state and never selects from peers_shared by insertion order.
/// If no local signer mapping exists, bootstrap:
/// Workspace → InviteAccepted → UserInviteBoot → UserBoot → DeviceInviteFirst → PeerSharedFirst.
/// Returns (peer_shared_event_id, peer_shared_signing_key).
fn ensure_identity_chain(
    db: &rusqlite::Connection,
    recorded_by: &str,
) -> Result<(EventId, SigningKey), Box<dyn std::error::Error + Send + Sync>> {
    // Only trust explicit local signer mappings, never arbitrary peers_shared rows.
    if let Some((eid, signing_key)) = load_local_peer_signer(db, recorded_by)? {
        return Ok((eid, signing_key));
    }

    // Bootstrap new identity chain
    let mut rng = rand::thread_rng();

    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_id: [u8; 32] = rand::random();
    let ws = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: current_timestamp_ms(),
        public_key: workspace_key.verifying_key().to_bytes(),
        workspace_id,
    });
    let ws_eid = event_id_or_blocked(create_event_sync(db, recorded_by, &ws))
        .map_err(|e| format!("{}", e))?;

    let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: current_timestamp_ms(),
        invite_event_id: ws_eid,
        workspace_id,
    });
    let _ia_eid = create_event_sync(db, recorded_by, &ia).map_err(|e| format!("{}", e))?;
    project_one(db, recorded_by, &ws_eid).map_err(|e| format!("{}", e))?;

    let invite_key = SigningKey::generate(&mut rng);
    let uib = ParsedEvent::UserInviteBoot(UserInviteBootEvent {
        created_at_ms: current_timestamp_ms(),
        public_key: invite_key.verifying_key().to_bytes(),
        workspace_id,
        signed_by: ws_eid,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let uib_eid = create_signed_event_sync(db, recorded_by, &uib, &workspace_key)
        .map_err(|e| format!("{}", e))?;

    let user_key = SigningKey::generate(&mut rng);
    let ub = ParsedEvent::UserBoot(UserBootEvent {
        created_at_ms: current_timestamp_ms(),
        public_key: user_key.verifying_key().to_bytes(),
        signed_by: uib_eid,
        signer_type: 2,
        signature: [0u8; 64],
    });
    let ub_eid = create_signed_event_sync(db, recorded_by, &ub, &invite_key)
        .map_err(|e| format!("{}", e))?;

    let device_invite_key = SigningKey::generate(&mut rng);
    let dif = ParsedEvent::DeviceInviteFirst(DeviceInviteFirstEvent {
        created_at_ms: current_timestamp_ms(),
        public_key: device_invite_key.verifying_key().to_bytes(),
        signed_by: ub_eid,
        signer_type: 4,
        signature: [0u8; 64],
    });
    let dif_eid =
        create_signed_event_sync(db, recorded_by, &dif, &user_key).map_err(|e| format!("{}", e))?;

    let peer_shared_key = SigningKey::generate(&mut rng);
    let psf = ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
        created_at_ms: current_timestamp_ms(),
        public_key: peer_shared_key.verifying_key().to_bytes(),
        signed_by: dif_eid,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let psf_eid = create_signed_event_sync(db, recorded_by, &psf, &device_invite_key)
        .map_err(|e| format!("{}", e))?;

    // Store signing key for future CLI invocations
    let psf_b64 = poc_7::crypto::event_id_to_base64(&psf_eid);
    persist_local_peer_signer(db, recorded_by, &psf_b64, &peer_shared_key)?;

    Ok((psf_eid, peer_shared_key))
}

fn send_message(
    db_path: &str,
    channel_hex: &str,
    content: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = ensure_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let (signer_eid, signing_key) = ensure_identity_chain(&db, &recorded_by)?;
    let channel_id = parse_channel_hex(channel_hex)?;
    let author_id = stable_author_id(&recorded_by);

    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms: current_timestamp_ms(),
        workspace_event_id,
        author_id,
        content: content.to_string(),
        signed_by: signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    create_signed_event_sync(&db, &recorded_by, &msg, &signing_key)
        .map_err(|e| format!("create event error: {}", e))?;

    println!("Sent: {}", content);

    Ok(())
}

fn show_status(db_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let events_count: i64 = db
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap_or(0);
    let messages_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let reactions_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let neg_items_count: i64 = db
        .query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0))
        .unwrap_or(0);
    let recorded_events_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let legacy_count = count_legacy_messages(&db)?;

    println!("STATUS ({}):", db_path);
    println!("  Events:    {} total", events_count);
    println!("  Messages:  {} projected", messages_count);
    println!("  Reactions: {} projected", reactions_count);
    println!("  Recorded:  {} events", recorded_events_count);
    println!("  NegItems:  {} indexed", neg_items_count);
    if legacy_count > 0 {
        println!(
            "  Legacy:    {} unscoped messages (run 'backfill-identity' to assign)",
            legacy_count
        );
    }

    Ok(())
}

fn generate_messages(db_path: &str, count: usize, workspace_hex: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = ensure_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let (signer_eid, signing_key) = ensure_identity_chain(&db, &recorded_by)?;
    let workspace_event_id = parse_workspace_hex(workspace_hex)?;
    let author_id: [u8; 32] = rand::random();

    db.execute("BEGIN", [])?;
    for i in 0..count {
        let msg = ParsedEvent::Message(MessageEvent {
            created_at_ms: current_timestamp_ms(),
            workspace_event_id,
            author_id,
            content: format!("Message {}", i),
            signed_by: signer_eid,
            signer_type: 5,
            signature: [0u8; 64],
        });
        create_signed_event_sync(&db, &recorded_by, &msg, &signing_key)
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
            parts.len(),
            s
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
        "store_count" | "events_count" => db
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .map_err(|e| format!("query failed: {}", e)),
        "message_count" => db
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .map_err(|e| format!("query failed: {}", e)),
        "reaction_count" => db
            .query_row(
                "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .map_err(|e| format!("query failed: {}", e)),
        "neg_items_count" => db
            .query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0))
            .map_err(|e| format!("query failed: {}", e)),
        "recorded_events_count" => db
            .query_row(
                "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1",
                rusqlite::params![recorded_by],
                |row| row.get(0),
            )
            .map_err(|e| format!("query failed: {}", e)),
        other => Err(format!("unknown field: {}", other)),
    }
}

fn run_assert_now(
    db_path: &str,
    predicate_str: &str,
) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let (field, op, expected) = parse_predicate(predicate_str)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;
    let actual = query_field(&db, &field, &recorded_by)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    if op.eval(actual, expected) {
        println!(
            "PASS: {} = {} (expected {} {})",
            field,
            actual,
            op.symbol(),
            expected
        );
        Ok(0)
    } else {
        println!(
            "FAIL: {} = {} (expected {} {})",
            field,
            actual,
            op.symbol(),
            expected
        );
        Ok(1)
    }
}

fn run_assert_eventually(
    db_path: &str,
    predicate_str: &str,
    timeout_ms: u64,
    interval_ms: u64,
) -> Result<i32, Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
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
            println!(
                "PASS: {} = {} (expected {} {})",
                field,
                actual,
                op.symbol(),
                expected
            );
            return Ok(0);
        }
        if start.elapsed() >= timeout {
            println!(
                "TIMEOUT: {} = {} (expected {} {}) after {}ms",
                field,
                actual,
                op.symbol(),
                expected,
                timeout_ms
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
    // Initialize DB before spawning concurrent loops (avoids create_tables race)
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    let (cert_path, key_path) = transport_cert_paths_from_db(db_path);
    let (cert, key) = load_or_generate_cert(&cert_path, &key_path)?;
    let recorded_by = {
        let fp = extract_spki_fingerprint(cert.as_ref())?;
        hex::encode(fp)
    };

    // Build combined trust: CLI pins (bootstrap) + projected transport bindings
    let cli_pins = AllowedPeers::from_hex_strings(pin_peers)?;
    let allowed_peers = {
        let db = open_connection(db_path)?;
        let combined = allowed_peers_combined(&db, &recorded_by, &cli_pins)?;
        if combined.is_empty() {
            return Err("No allowed peers: provide --pin-peer for bootstrap, or ensure identity events have synced. \
                Use `poc-7 transport-identity --db <peer-db>` to get a peer's fingerprint.".into());
        }
        let cli_count = cli_pins.len();
        let total = combined.len();
        if total > cli_count {
            info!(
                "Trust sources: {} from CLI pins, {} from projected bindings",
                cli_count,
                total - cli_count
            );
        }
        Arc::new(combined)
    };

    // Single dual-role endpoint: same UDP socket for accept + connect (required for hole punching)
    let allowed_peers_inner = (*allowed_peers).clone();
    let endpoint = create_dual_endpoint(bind, cert, key, allowed_peers)?;
    info!("Listening on {}", endpoint.local_addr()?);

    let db_owned = db_path.to_string();
    let recorded_by_clone = recorded_by.clone();
    let accept_endpoint = endpoint.clone();
    let accept_allowed = allowed_peers_inner.clone();
    let accept_handle = tokio::task::spawn_blocking({
        let db = db_owned.clone();
        move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = accept_loop(&db, &recorded_by_clone, accept_endpoint, Some(accept_allowed)).await {
                    tracing::warn!("accept_loop exited: {}", e);
                }
            });
        }
    });

    if let Some(remote) = connect {
        let connect_endpoint = endpoint.clone();
        let connect_allowed = allowed_peers_inner.clone();
        let db = db_owned.clone();
        let recorded_by_clone = recorded_by.clone();
        let connect_handle = tokio::task::spawn_blocking(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Err(e) = connect_loop(&db, &recorded_by_clone, connect_endpoint, remote, Some(connect_allowed)).await {
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

// ---------------------------------------------------------------------------
// New non-interactive subcommands
// ---------------------------------------------------------------------------

fn parse_hex_event_id(hex_str: &str) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 32 {
        return Err(format!("Event ID must be 32 bytes, got {}", bytes.len()).into());
    }
    let mut eid = [0u8; 32];
    eid.copy_from_slice(&bytes);
    Ok(eid)
}

fn cli_react(
    db_path: &str,
    target_hex: &str,
    emoji: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = ensure_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let (signer_eid, signing_key) = ensure_identity_chain(&db, &recorded_by)?;
    let target_event_id = parse_hex_event_id(target_hex)?;
    let author_id = stable_author_id(&recorded_by);

    let rxn = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms: current_timestamp_ms(),
        target_event_id,
        author_id,
        emoji: emoji.to_string(),
        signed_by: signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = event_id_or_blocked(create_signed_event_sync(
        &db,
        &recorded_by,
        &rxn,
        &signing_key,
    ))?;
    println!("Reacted {} ({})", emoji, hex::encode(&eid[..4]));

    Ok(())
}

fn cli_delete_message(
    db_path: &str,
    target_hex: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = ensure_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let (signer_eid, signing_key) = ensure_identity_chain(&db, &recorded_by)?;
    let target_event_id = parse_hex_event_id(target_hex)?;
    let author_id = stable_author_id(&recorded_by);

    let del = ParsedEvent::MessageDeletion(MessageDeletionEvent {
        created_at_ms: current_timestamp_ms(),
        target_event_id,
        author_id,
        signed_by: signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    event_id_or_blocked(create_signed_event_sync(
        &db,
        &recorded_by,
        &del,
        &signing_key,
    ))?;
    println!(
        "Deleted message {}",
        &target_hex[..target_hex.len().min(16)]
    );

    Ok(())
}

fn cli_reactions(db_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let mut stmt = db
        .prepare("SELECT event_id, target_event_id, emoji FROM reactions WHERE recorded_by = ?1")?;
    let rows: Vec<(String, String, String)> = stmt
        .query_map(rusqlite::params![&recorded_by], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    println!("REACTIONS ({}):", db_path);
    if rows.is_empty() {
        println!("  (none)");
    } else {
        for (eid, target, emoji) in &rows {
            println!("  {} -> {} {}", short_id(eid), short_id(target), emoji);
        }
    }

    Ok(())
}

fn cli_users(db_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let mut stmt = db.prepare("SELECT event_id FROM users WHERE recorded_by = ?1")?;
    let users: Vec<String> = stmt
        .query_map(rusqlite::params![&recorded_by], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;

    println!("USERS ({}):", db_path);
    if users.is_empty() {
        println!("  (none)");
    } else {
        for (i, eid) in users.iter().enumerate() {
            println!("  {}. user_{}", i + 1, short_id(eid));
        }
    }

    Ok(())
}

fn cli_keys(db_path: &str, summary: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let user_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM users WHERE recorded_by = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let peer_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let admin_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM admins WHERE recorded_by = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let transport_count: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM transport_keys WHERE recorded_by = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);

    println!("KEYS ({}):", db_path);
    println!("  Users: {}", user_count);
    println!("  Peers: {}", peer_count);
    println!("  Admins: {}", admin_count);
    println!("  TransportKeys: {}", transport_count);

    if !summary {
        let mut stmt = db.prepare("SELECT event_id FROM users WHERE recorded_by = ?1")?;
        let users: Vec<String> = stmt
            .query_map(rusqlite::params![&recorded_by], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for eid in &users {
            println!("    user {}", short_id(eid));
        }

        let mut stmt = db.prepare("SELECT event_id FROM peers_shared WHERE recorded_by = ?1")?;
        let peers: Vec<String> = stmt
            .query_map(rusqlite::params![&recorded_by], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?;
        for eid in &peers {
            println!("    peer {}", short_id(eid));
        }
    }

    Ok(())
}

fn cli_workspaces(db_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let recorded_by = load_transport_peer_id_from_db(db_path)?;
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let mut stmt = db.prepare(
        "SELECT event_id, workspace_id FROM workspaces WHERE recorded_by = ?1",
    )?;
    let workspaces: Vec<(String, String)> = stmt
        .query_map(rusqlite::params![&recorded_by], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    println!("WORKSPACES ({}):", db_path);
    if workspaces.is_empty() {
        println!("  (none)");
    } else {
        use base64::Engine;
        for (i, (eid, ws_id_b64)) in workspaces.iter().enumerate() {
            let name = if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(ws_id_b64) {
                String::from_utf8_lossy(&bytes).trim_end_matches('\0').to_string()
            } else {
                ws_id_b64.clone()
            };
            println!("  {}. {} ({})", i + 1, name, short_id(eid));
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Intro commands
// ---------------------------------------------------------------------------

async fn cli_intro(
    db_path: &str,
    peer_a: &str,
    peer_b: &str,
    pin_peers: &[String],
    ttl_ms: u64,
    attempt_window_ms: u32,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    create_tables(&db)?;
    drop(db);

    let (cert_path, key_path) = transport_cert_paths_from_db(db_path);
    let (cert, key) = load_or_generate_cert(&cert_path, &key_path)?;
    let recorded_by = {
        let fp = extract_spki_fingerprint(cert.as_ref())?;
        hex::encode(fp)
    };

    // Build allowed peers: must include both target peers
    let mut all_pins = pin_peers.to_vec();
    if !all_pins.contains(&peer_a.to_string()) {
        all_pins.push(peer_a.to_string());
    }
    if !all_pins.contains(&peer_b.to_string()) {
        all_pins.push(peer_b.to_string());
    }
    let cli_pins = AllowedPeers::from_hex_strings(&all_pins)?;
    let db = open_connection(db_path)?;
    let allowed = allowed_peers_combined(&db, &recorded_by, &cli_pins)?;
    drop(db);

    let endpoint = create_dual_endpoint(
        "0.0.0.0:0".parse()?,
        cert,
        key,
        Arc::new(allowed),
    )?;

    let result = poc_7::sync::intro::run_intro(
        &endpoint, db_path, &recorded_by,
        peer_a, peer_b, ttl_ms, attempt_window_ms,
    ).await?;

    if result.sent_to_a && result.sent_to_b {
        println!("Intro sent to both peers");
    } else {
        for e in &result.errors {
            eprintln!("Error: {}", e);
        }
        if !result.sent_to_a && !result.sent_to_b {
            std::process::exit(1);
        }
    }

    endpoint.close(0u32.into(), b"done");
    Ok(())
}

fn cli_intro_attempts(
    db_path: &str,
    peer: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let recorded_by = {
        let (cert_path, key_path) = transport_cert_paths_from_db(db_path);
        let (cert, _) = load_or_generate_cert(&cert_path, &key_path)?;
        let fp = extract_spki_fingerprint(cert.as_ref())?;
        hex::encode(fp)
    };

    let rows = poc_7::db::intro::list_intro_attempts(&db, &recorded_by, peer)?;
    if rows.is_empty() {
        println!("No intro attempts recorded.");
        return Ok(());
    }

    for r in &rows {
        let intro_id_hex = hex::encode(&r.intro_id);
        println!("  intro_id:  {}...", &intro_id_hex[..16]);
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

    Ok(())
}
