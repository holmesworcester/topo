mod crypto;
mod db;
mod runtime;
mod sync;
mod transport;
mod wire;

use clap::{Parser, Subcommand};
use negentropy::{Negentropy, Id};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{info, warn, error, debug, Level};
use tracing_subscriber::FmtSubscriber;

use crate::crypto::{hash_event, EventId};
use crate::db::{open_connection, schema::create_tables, shareable::Shareable, store::Store};
use crate::runtime::SyncStats;
use crate::sync::{SyncMessage, load_negentropy_items, build_negentropy_storage, neg_id_to_event_id};
use crate::transport::{Connection, create_client_endpoint, create_server_endpoint, generate_keypair, generate_self_signed_cert};
use crate::wire::Envelope;

#[derive(Parser)]
#[command(name = "poc-7")]
#[command(about = "High-performance QUIC sync system")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as a listening server
    Listen {
        /// Address to bind to
        #[arg(short, long, default_value = "127.0.0.1:4433")]
        bind: SocketAddr,

        /// Database path
        #[arg(short, long, default_value = "server.db")]
        db: String,

        /// Run duration in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },

    /// Connect to a remote peer
    Connect {
        /// Remote address to connect to
        #[arg(short, long)]
        remote: SocketAddr,

        /// Database path
        #[arg(short, long, default_value = "client.db")]
        db: String,

        /// Run duration in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u64,
    },

    /// Generate test events in a database
    Generate {
        /// Database path
        #[arg(short, long, default_value = "test.db")]
        db: String,

        /// Number of events to generate
        #[arg(short, long, default_value = "100")]
        count: usize,

        /// Channel ID (hex, 16 bytes)
        #[arg(short = 'C', long, default_value = "0102030405060708090a0b0c0d0e0f10")]
        channel: String,
    },

    /// Show database stats
    Stats {
        /// Database path
        #[arg(short, long, default_value = "test.db")]
        db: String,
    },

    /// Demo: run two peers locally and sync events
    Demo {
        /// Number of events to generate per peer
        #[arg(short, long, default_value = "50")]
        events: usize,

        /// Run duration in seconds
        #[arg(short, long, default_value = "10")]
        timeout: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Initialize tracing
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let cli = Cli::parse();

    match cli.command {
        Commands::Listen { bind, db, timeout } => {
            run_server(bind, &db, timeout).await?;
        }
        Commands::Connect { remote, db, timeout } => {
            run_client(remote, &db, timeout).await?;
        }
        Commands::Generate { db, count, channel } => {
            generate_events(&db, count, &channel)?;
        }
        Commands::Stats { db } => {
            show_stats(&db)?;
        }
        Commands::Demo { events, timeout } => {
            run_demo(events, timeout).await?;
        }
    }

    Ok(())
}

async fn run_server(
    bind: SocketAddr,
    db_path: &str,
    timeout_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Starting server on {}", bind);

    // Generate keypair and certificate
    let (signing_key, _) = generate_keypair();
    let (cert, key) = generate_self_signed_cert(&signing_key)?;

    // Create server endpoint
    let endpoint = create_server_endpoint(bind, cert, key)?;
    info!("Server listening on {}", endpoint.local_addr()?);

    // Open database
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    // Accept connection
    let incoming = endpoint.accept().await.ok_or("No connection")?;
    let connection = incoming.await?;
    info!("Accepted connection from {}", connection.remote_address());

    // Open bidirectional stream
    let (send, recv) = connection.accept_bi().await?;
    let mut conn = Connection::new(send, recv);

    // Run sync as responder (server waits for client to initiate)
    run_sync_responder(&mut conn, &db, timeout_secs).await?;

    // Close connection
    connection.close(0u32.into(), b"done");

    Ok(())
}

async fn run_client(
    remote: SocketAddr,
    db_path: &str,
    timeout_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Connecting to {}", remote);

    // Create client endpoint
    let endpoint = create_client_endpoint("0.0.0.0:0".parse()?)?;

    // Connect to server
    let connection = endpoint.connect(remote, "localhost")?.await?;
    info!("Connected to {}", connection.remote_address());

    // Open database
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    // Open bidirectional stream
    let (send, recv) = connection.open_bi().await?;
    let mut conn = Connection::new(send, recv);

    // Run sync as initiator (client starts the reconciliation)
    run_sync_initiator(&mut conn, &db, timeout_secs).await?;

    // Close connection
    connection.close(0u32.into(), b"done");

    Ok(())
}

/// Run sync as the initiator (client role)
/// Interleaves reconciliation with event transfer for maximum throughput
async fn run_sync_initiator(
    conn: &mut Connection,
    db: &rusqlite::Connection,
    timeout_secs: u64,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>> {
    let mut stats = SyncStats::default();
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    info!("Starting negentropy sync (initiator) for {} seconds", timeout_secs);

    let items = load_negentropy_items(db)?;
    info!("Loaded {} items for negentropy", items.len());

    let storage = build_negentropy_storage(&items)?;
    // Use frame_size_limit to get incremental results (enables pipelining)
    let mut neg = Negentropy::owned(storage, 64 * 1024)?; // 64KB frames

    let store = Store::new(db);
    let shareable = Shareable::new(db);

    // Track discovered IDs and what we've already processed
    let mut have_ids: Vec<Id> = Vec::new();
    let mut need_ids: Vec<Id> = Vec::new();
    let mut have_sent: HashSet<EventId> = HashSet::new();
    let mut need_requested: HashSet<EventId> = HashSet::new();
    let mut need_received: HashSet<EventId> = HashSet::new();

    // Initiate reconciliation
    let initial_msg = neg.initiate()?;
    conn.send(&SyncMessage::NegOpen { msg: initial_msg }).await?;
    conn.flush().await?;
    debug!("Sent NegOpen");

    let mut reconciliation_done = false;
    let mut rounds = 0;

    // Main loop: interleave reconciliation with event transfer
    loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }

        // Send events for any NEW have_ids (events we have that they need)
        for neg_id in &have_ids {
            let event_id = neg_id_to_event_id(neg_id);
            if !have_sent.contains(&event_id) {
                if let Ok(Some(blob)) = store.get(&event_id) {
                    if conn.send(&SyncMessage::Event { blob }).await.is_ok() {
                        stats.events_sent += 1;
                        have_sent.insert(event_id);
                    }
                } else {
                    have_sent.insert(event_id); // Mark as "sent" even if missing
                }
            }
        }

        // Request any NEW need_ids (events they have that we need)
        let mut new_needs: Vec<EventId> = Vec::new();
        for neg_id in &need_ids {
            let event_id = neg_id_to_event_id(neg_id);
            if !need_requested.contains(&event_id) {
                new_needs.push(event_id);
                need_requested.insert(event_id);
            }
        }
        if !new_needs.is_empty() {
            debug!("Requesting {} new events", new_needs.len());
            conn.send(&SyncMessage::HaveList { ids: new_needs }).await?;
        }

        let _ = conn.flush().await;

        // Check completion AFTER sending: reconciliation complete AND all requested events received
        if reconciliation_done && need_requested.len() == need_received.len() {
            info!("Sync complete: sent {}, received {}", stats.events_sent, stats.events_received);
            break;
        }

        // Receive and handle messages
        match tokio::time::timeout(Duration::from_millis(50), conn.recv()).await {
            Ok(Ok(SyncMessage::NegMsg { msg })) => {
                rounds += 1;
                let prev_have = have_ids.len();
                let prev_need = need_ids.len();

                match neg.reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)? {
                    Some(next_msg) => {
                        conn.send(&SyncMessage::NegMsg { msg: next_msg }).await?;
                        debug!("Round {}: +{} have, +{} need",
                            rounds, have_ids.len() - prev_have, need_ids.len() - prev_need);
                    }
                    None => {
                        info!("Reconciliation complete in {} rounds: {} have, {} need",
                            rounds, have_ids.len(), need_ids.len());
                        reconciliation_done = true;
                    }
                }
            }
            Ok(Ok(SyncMessage::Event { blob })) => {
                let event_id = hash_event(&blob);
                let prev_id = Envelope::extract_prev_id(&blob);

                let _ = store.put(&event_id, &blob);
                let _ = shareable.insert(&event_id, prev_id.as_ref());

                if let Some(prev) = prev_id {
                    let _ = shareable.mark_not_tip(&prev);
                }

                if need_requested.contains(&event_id) {
                    need_received.insert(event_id);
                }
                stats.events_received += 1;
            }
            Ok(Ok(_)) => {} // Ignore other messages
            Ok(Err(transport::connection::ConnectionError::Closed)) => {
                info!("Connection closed by peer");
                break;
            }
            Ok(Err(e)) => {
                warn!("Connection error: {}", e);
                break;
            }
            Err(_) => {} // Timeout, continue loop
        }
    }

    info!("Sync stats: {:?}", stats);
    Ok(stats)
}

/// Run sync as the responder (server role)
/// Interleaves reconciliation with event transfer for maximum throughput
async fn run_sync_responder(
    conn: &mut Connection,
    db: &rusqlite::Connection,
    timeout_secs: u64,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>> {
    let mut stats = SyncStats::default();
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    info!("Starting negentropy sync (responder) for {} seconds", timeout_secs);

    let items = load_negentropy_items(db)?;
    info!("Loaded {} items for negentropy", items.len());

    let storage = build_negentropy_storage(&items)?;
    // Use frame_size_limit to match initiator (enables pipelining)
    let mut neg = Negentropy::owned(storage, 64 * 1024)?;

    let store = Store::new(db);
    let shareable = Shareable::new(db);

    let mut reconciliation_done = false;
    let mut rounds = 0;
    let mut idle_count = 0;
    const MAX_IDLE: u32 = 20; // Exit after 20 idle iterations (1 second)

    // Unified loop: handle all message types as they arrive
    loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }

        // Exit if reconciliation is done and we've been idle
        if reconciliation_done && idle_count >= MAX_IDLE {
            debug!("Sync complete after idle period");
            break;
        }

        match tokio::time::timeout(Duration::from_millis(50), conn.recv()).await {
            Ok(Ok(SyncMessage::NegOpen { msg })) | Ok(Ok(SyncMessage::NegMsg { msg })) => {
                idle_count = 0;
                rounds += 1;
                debug!("Received negentropy message (round {})", rounds);

                // Use reconcile (not reconcile_with_ids) for responder
                let response = neg.reconcile(&msg)?;
                if response.is_empty() {
                    info!("Reconciliation complete in {} rounds", rounds);
                    reconciliation_done = true;
                } else {
                    conn.send(&SyncMessage::NegMsg { msg: response }).await?;
                    conn.flush().await?;
                    debug!("Sent NegMsg response");
                }
            }
            Ok(Ok(SyncMessage::HaveList { ids })) => {
                // Client is telling us what events to send - this means reconciliation is done
                idle_count = 0;
                reconciliation_done = true;
                debug!("Received HaveList with {} IDs", ids.len());

                // Send requested events immediately
                for id in &ids {
                    if let Ok(Some(blob)) = store.get(id) {
                        if conn.send(&SyncMessage::Event { blob }).await.is_ok() {
                            stats.events_sent += 1;
                        }
                    }
                }
                let _ = conn.flush().await;
            }
            Ok(Ok(SyncMessage::Event { blob })) => {
                // Receiving an event from the initiator
                idle_count = 0;
                let event_id = hash_event(&blob);
                let prev_id = Envelope::extract_prev_id(&blob);

                let _ = store.put(&event_id, &blob);
                let _ = shareable.insert(&event_id, prev_id.as_ref());

                if let Some(prev) = prev_id {
                    let _ = shareable.mark_not_tip(&prev);
                }

                stats.events_received += 1;
            }
            Ok(Err(transport::connection::ConnectionError::Closed)) => {
                info!("Connection closed by peer");
                break;
            }
            Ok(Err(e)) => {
                warn!("Connection error: {}", e);
                break;
            }
            Err(_) => {
                // Timeout - increment idle counter
                if reconciliation_done {
                    idle_count += 1;
                }
            }
        }
    }

    info!("Sync stats: {:?}", stats);
    Ok(stats)
}

fn generate_events(db_path: &str, count: usize, channel_hex: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    // Parse channel ID (pad to 32 bytes if needed)
    let channel_bytes = hex::decode(channel_hex)?;
    if channel_bytes.len() > 32 {
        return Err("Channel ID must be at most 32 bytes (64 hex chars)".into());
    }
    let mut channel_id = [0u8; 32];
    channel_id[..channel_bytes.len()].copy_from_slice(&channel_bytes);

    // Generate random author ID
    let author_id: [u8; 32] = rand::random();
    let signer_id: [u8; 32] = rand::random();

    let store = Store::new(&db);
    let shareable = Shareable::new(&db);

    let mut prev_id: Option<[u8; 32]> = None;

    info!("Generating {} events...", count);

    for i in 0..count {
        let content = format!("Message {} from peer", i);
        let envelope = Envelope::new_message(
            signer_id,
            channel_id,
            author_id,
            prev_id,
            content,
        );

        let blob = envelope.encode();
        let event_id = hash_event(&blob);

        store.put(&event_id, &blob)?;
        shareable.insert(&event_id, prev_id.as_ref())?;

        // Mark previous as not a tip
        if let Some(prev) = prev_id {
            shareable.mark_not_tip(&prev)?;
        }

        prev_id = Some(event_id);
    }

    info!("Generated {} events in {}", count, db_path);
    show_stats(db_path)?;

    Ok(())
}

fn show_stats(db_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;

    let store_count: i64 = db.query_row("SELECT COUNT(*) FROM store", [], |row| row.get(0)).unwrap_or(0);
    let shareable_count: i64 = db.query_row("SELECT COUNT(*) FROM shareable_events", [], |row| row.get(0)).unwrap_or(0);
    let tips_count: i64 = db.query_row("SELECT COUNT(*) FROM shareable_events WHERE is_tip = 1", [], |row| row.get(0)).unwrap_or(0);
    let wanted_count: i64 = db.query_row("SELECT COUNT(*) FROM wanted_events", [], |row| row.get(0)).unwrap_or(0);
    let incoming_count: i64 = db.query_row("SELECT COUNT(*) FROM incoming_queue WHERE processed = 0", [], |row| row.get(0)).unwrap_or(0);
    let messages_count: i64 = db.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0)).unwrap_or(0);

    println!("Database: {}", db_path);
    println!("  Store:     {} events", store_count);
    println!("  Shareable: {} events ({} tips)", shareable_count, tips_count);
    println!("  Wanted:    {} events", wanted_count);
    println!("  Incoming:  {} pending", incoming_count);
    println!("  Messages:  {} projected", messages_count);

    Ok(())
}

async fn run_demo(events_per_peer: usize, timeout_secs: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("=== QUIC Sync Demo ===");
    info!("Generating {} events per peer, running for {} seconds", events_per_peer, timeout_secs);

    // Clean up old databases
    let _ = std::fs::remove_file("demo_server.db");
    let _ = std::fs::remove_file("demo_server.db-shm");
    let _ = std::fs::remove_file("demo_server.db-wal");
    let _ = std::fs::remove_file("demo_client.db");
    let _ = std::fs::remove_file("demo_client.db-shm");
    let _ = std::fs::remove_file("demo_client.db-wal");

    // Generate events for server (32 hex chars = 16 bytes)
    info!("Generating events for server...");
    generate_events("demo_server.db", events_per_peer, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;

    // Generate events for client (32 hex chars = 16 bytes)
    info!("Generating events for client...");
    generate_events("demo_client.db", events_per_peer, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?;

    // Run server and client sequentially - server first, then client connects
    // Use a channel to coordinate startup
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let server_timeout = timeout_secs;
    let client_timeout = timeout_secs;

    // Start server task
    let server_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let bind: SocketAddr = "127.0.0.1:4433".parse().unwrap();
            // Signal that server is starting
            let _ = tx.send(());
            if let Err(e) = run_server(bind, "demo_server.db", server_timeout).await {
                error!("Server error: {}", e);
            }
        });
    });

    // Wait for server to signal it's ready
    let _ = rx.await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Start client task
    let client_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let remote: SocketAddr = "127.0.0.1:4433".parse().unwrap();
            if let Err(e) = run_client(remote, "demo_client.db", client_timeout).await {
                error!("Client error: {}", e);
            }
        });
    });

    // Wait for both to complete
    let _ = server_handle.join();
    let _ = client_handle.join();

    info!("=== Demo Complete ===");

    // Show final stats
    println!("\nServer database:");
    show_stats("demo_server.db")?;

    println!("\nClient database:");
    show_stats("demo_client.db")?;

    // Verify sync
    let server_db = open_connection("demo_server.db")?;
    let client_db = open_connection("demo_client.db")?;

    let server_store: i64 = server_db.query_row("SELECT COUNT(*) FROM store", [], |row| row.get(0))?;
    let client_store: i64 = client_db.query_row("SELECT COUNT(*) FROM store", [], |row| row.get(0))?;

    println!("\n=== Sync Verification ===");
    println!("Server has {} events, Client has {} events", server_store, client_store);

    let expected = events_per_peer * 2; // Both peers should have all events
    if server_store >= expected as i64 && client_store >= expected as i64 {
        println!("SUCCESS: Both peers have all {} events!", expected);
    } else {
        println!("Sync incomplete - expected {} events each", expected);
    }

    Ok(())
}
