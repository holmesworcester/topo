use poc7_lib::crypto;
use poc7_lib::db;
use poc7_lib::runtime;
use poc7_lib::sync;
use poc7_lib::transport;
use poc7_lib::wire;

use clap::{Parser, Subcommand};
use negentropy::{Negentropy, Id, NegentropyStorageBase, Storage};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

use crypto::{hash_event, event_id_to_base64, EventId};
use db::{open_connection, schema::create_tables, shareable::Shareable, store::Store, PendingSend, Wanted};
use runtime::SyncStats;
use sync::{SyncMessage, load_negentropy_items, build_negentropy_storage, neg_id_to_event_id, NegentropyStorageSqlite};
use transport::{Connection, DualConnection, create_client_endpoint, create_server_endpoint, generate_keypair, generate_self_signed_cert};
use wire::Envelope;

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

    // Initialize database
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    // Accept connection
    let incoming = endpoint.accept().await.ok_or("No connection")?;
    let connection = incoming.await?;
    info!("Accepted connection from {}", connection.remote_address());

    // Accept two bidirectional streams: control first, then data
    let (control_send, control_recv) = connection.accept_bi().await?;
    let (data_send, data_recv) = connection.accept_bi().await?;
    let mut conn = DualConnection::new(control_send, control_recv, data_send, data_recv);
    info!("Accepted control and data streams");

    // Run sync as responder (server waits for client to initiate)
    run_sync_responder_dual(conn, db_path, timeout_secs).await?;

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

    // Initialize database
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    // Open two bidirectional streams: control first, then data
    let (control_send, control_recv) = connection.open_bi().await?;
    let (data_send, data_recv) = connection.open_bi().await?;
    let mut conn = DualConnection::new(control_send, control_recv, data_send, data_recv);

    // Send ping on both streams to establish them (QUIC streams are lazy)
    conn.control.send(&SyncMessage::Ping).await?;
    conn.data.send(&SyncMessage::Ping).await?;
    conn.flush_control().await?;
    conn.flush_data().await?;
    info!("Opened and established control and data streams");

    // Run sync as initiator (client starts the reconciliation)
    run_sync_initiator_dual(conn, db_path, timeout_secs).await?;

    // Close connection
    connection.close(0u32.into(), b"done");

    Ok(())
}

/// Run sync as the initiator (client role)
/// Uses channels and batching for high throughput
async fn run_sync_initiator(
    conn: &mut Connection,
    db_path: &str,
    timeout_secs: u64,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    info!("Starting negentropy sync (initiator) for {} seconds", timeout_secs);

    // Phase 1: Load data and prefetch blobs into memory
    let db = open_connection(db_path)?;
    let items = load_negentropy_items(&db)?;
    info!("Loaded {} items for negentropy", items.len());

    let storage = build_negentropy_storage(&items)?;
    let mut neg = Negentropy::owned(storage, 64 * 1024)?;

    let store = Store::new(&db);
    let mut blob_cache: HashMap<EventId, Vec<u8>> = HashMap::new();
    for item in &items {
        if let Ok(Some(blob)) = store.get(&item.id) {
            blob_cache.insert(item.id, blob);
        }
    }
    info!("Prefetched {} blobs into cache", blob_cache.len());
    drop(db);

    // Phase 2: Set up channel for incoming events
    let (tx, rx) = mpsc::channel::<(EventId, Vec<u8>)>(100_000);
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();

    let db_path_owned = db_path.to_string();
    let writer_handle = tokio::task::spawn_blocking(move || {
        batch_writer(db_path_owned, rx, events_received_writer)
    });

    // Phase 3: Network I/O
    let mut have_ids: Vec<Id> = Vec::new();
    let mut need_ids: Vec<Id> = Vec::new();
    let mut have_sent: HashSet<EventId> = HashSet::new();
    let mut need_requested: HashSet<EventId> = HashSet::new();
    let mut events_sent: u64 = 0;

    let initial_msg = neg.initiate()?;
    conn.send(&SyncMessage::NegOpen { msg: initial_msg }).await?;
    conn.flush().await?;

    let mut reconciliation_done = false;
    let mut rounds = 0;

    loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }

        // First: drain all pending receives (non-blocking)
        loop {
            match tokio::time::timeout(Duration::from_millis(1), conn.recv()).await {
                Ok(Ok(SyncMessage::NegMsg { msg })) => {
                    rounds += 1;
                    match neg.reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)? {
                        Some(next_msg) => {
                            conn.send(&SyncMessage::NegMsg { msg: next_msg }).await?;
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
                    let _ = tx.try_send((event_id, blob));
                }
                Ok(Ok(_)) => {}
                Ok(Err(transport::connection::ConnectionError::Closed)) => {
                    info!("Connection closed by peer");
                    drop(tx);
                    let _ = writer_handle.await;
                    return Ok(SyncStats { events_sent, events_received: events_received.load(Ordering::Relaxed), neg_rounds: rounds });
                }
                Ok(Err(e)) => {
                    warn!("Connection error: {}", e);
                    drop(tx);
                    let _ = writer_handle.await;
                    return Ok(SyncStats { events_sent, events_received: events_received.load(Ordering::Relaxed), neg_rounds: rounds });
                }
                Err(_) => break, // Timeout - no more pending receives
            }
        }

        // Second: send a batch of events
        let mut sent_this_round = 0;
        for neg_id in &have_ids {
            let event_id = neg_id_to_event_id(neg_id);
            if !have_sent.contains(&event_id) {
                if let Some(blob) = blob_cache.get(&event_id) {
                    if conn.send(&SyncMessage::Event { blob: blob.clone() }).await.is_ok() {
                        events_sent += 1;
                        have_sent.insert(event_id);
                        sent_this_round += 1;
                        if sent_this_round >= 500 {
                            break; // Send batch, then check for receives again
                        }
                    }
                } else {
                    have_sent.insert(event_id);
                }
            }
        }

        // Third: send HaveList for events we need
        let mut new_needs: Vec<EventId> = Vec::new();
        for neg_id in &need_ids {
            let event_id = neg_id_to_event_id(neg_id);
            if !need_requested.contains(&event_id) {
                new_needs.push(event_id);
                need_requested.insert(event_id);
            }
        }
        if !new_needs.is_empty() {
            conn.send(&SyncMessage::HaveList { ids: new_needs }).await?;
        }

        let _ = conn.flush().await;

        // Check completion
        let received = events_received.load(Ordering::Relaxed);
        if reconciliation_done
            && have_sent.len() == have_ids.len()
            && need_requested.len() as u64 == received
        {
            info!("Sync complete: sent {}, received {}", events_sent, received);
            break;
        }
    }

    drop(tx);
    let _ = writer_handle.await;

    let stats = SyncStats {
        events_sent,
        events_received: events_received.load(Ordering::Relaxed),
        neg_rounds: rounds,
    };
    info!("Sync stats: {:?}", stats);
    Ok(stats)
}

/// Batch writer task - drains channel and writes to SQLite in batches
/// Projects messages inline for atomicity: if in shareable, it's projected
///
/// NOTE: Projection may require reading dependencies (e.g., parent messages, thread roots).
/// We simulate this with 10 random reads per event. In production, these would be real
/// dependency lookups based on event content (reply_to, thread_id, etc.).
///
/// Set NAIVE_DEPS=1 to use unbatched reads (slower) for comparison.
/// Set NO_DEPS=1 to skip dependency reads entirely (baseline).
fn batch_writer(
    db_path: String,
    mut rx: mpsc::Receiver<(EventId, Vec<u8>)>,
    events_received: Arc<AtomicU64>,
) {
    let use_naive = std::env::var("NAIVE_DEPS").is_ok();
    let no_deps = std::env::var("NO_DEPS").is_ok();

    let db = match open_connection(&db_path) {
        Ok(db) => db,
        Err(e) => {
            error!("Writer failed to open db: {}", e);
            return;
        }
    };

    let store = Store::new(&db);
    let shareable = Shareable::new(&db);

    // Prepare projection statement
    let mut project_stmt = match db.prepare(
        "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)"
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare projection statement: {}", e);
            return;
        }
    };

    // Prepare dependency read statement (simulates looking up parent/thread events)
    let mut dep_read_stmt = match db.prepare(
        "SELECT content FROM messages WHERE message_id = ?1"
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare dependency read statement: {}", e);
            return;
        }
    };

    // Prepare neg_items insertion (raw 32-byte blob id)
    let mut neg_items_stmt = match db.prepare(
        "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)"
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare neg_items statement: {}", e);
            return;
        }
    };

    loop {
        // Block waiting for first item
        let first = match rx.blocking_recv() {
            Some(item) => item,
            None => break, // Channel closed
        };

        // Collect batch
        let mut batch = vec![first];
        while let Ok(item) = rx.try_recv() {
            batch.push(item);
            if batch.len() >= 1000 {
                break;
            }
        }

        // Get real message IDs to use as fake dependencies (if not NO_DEPS mode)
        let real_dep_ids: Vec<String> = if no_deps {
            Vec::new()
        } else {
            // Fetch up to 1000 random real message IDs to use as dependencies
            let mut ids = Vec::new();
            if let Ok(mut stmt) = db.prepare("SELECT message_id FROM messages ORDER BY RANDOM() LIMIT 1000") {
                if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                    ids = rows.flatten().collect();
                }
            }
            ids
        };

        if no_deps {
            // NO_DEPS: Skip dependency reads (baseline)
            if db.execute("BEGIN", []).is_ok() {
                for (event_id, blob) in &batch {
                    let _ = store.put(event_id, blob);
                    let _ = shareable.insert(event_id);

                    if let Ok((_, envelope)) = Envelope::parse(blob) {
                        let created_at_ms = envelope.payload.created_at_ms;

                        // Insert into neg_items (raw blob id)
                        let _ = neg_items_stmt.execute(rusqlite::params![
                            created_at_ms as i64,
                            event_id.as_slice()
                        ]);

                        let message_id = event_id_to_base64(event_id);
                        let channel_id = event_id_to_base64(&envelope.payload.channel_id);
                        let author_id = event_id_to_base64(&envelope.payload.author_id);
                        let _ = project_stmt.execute(rusqlite::params![
                            message_id,
                            channel_id,
                            author_id,
                            &envelope.payload.content,
                            created_at_ms as i64
                        ]);
                    }
                }
                let _ = db.execute("COMMIT", []);
            }
        } else if use_naive {
            // NAIVE: Read dependencies inside projection loop (slower)
            if db.execute("BEGIN", []).is_ok() {
                for (idx, (event_id, blob)) in batch.iter().enumerate() {
                    let _ = store.put(event_id, blob);
                    let _ = shareable.insert(event_id);

                    if let Ok((_, envelope)) = Envelope::parse(blob) {
                        let created_at_ms = envelope.payload.created_at_ms;

                        // Insert into neg_items (raw blob id)
                        let _ = neg_items_stmt.execute(rusqlite::params![
                            created_at_ms as i64,
                            event_id.as_slice()
                        ]);

                        // Naive: 10 individual reads per event during projection
                        // Use real message IDs as dependencies
                        if !real_dep_ids.is_empty() {
                            for i in 0..10usize {
                                let dep_idx = (idx * 10 + i) % real_dep_ids.len();
                                let dep_id_str = &real_dep_ids[dep_idx];
                                let _content: Option<String> = dep_read_stmt
                                    .query_row([dep_id_str], |row| row.get(0))
                                    .ok();
                            }
                        }

                        let message_id = event_id_to_base64(event_id);
                        let channel_id = event_id_to_base64(&envelope.payload.channel_id);
                        let author_id = event_id_to_base64(&envelope.payload.author_id);
                        let _ = project_stmt.execute(rusqlite::params![
                            message_id,
                            channel_id,
                            author_id,
                            &envelope.payload.content,
                            created_at_ms as i64
                        ]);
                    }
                }
                let _ = db.execute("COMMIT", []);
            }
        } else {
            // BATCHED: Pre-fetch all dependencies with single IN query (faster)

            // Phase 1: Collect unique dependency IDs (real message IDs)
            let mut all_dep_ids: HashSet<String> = HashSet::with_capacity(batch.len() * 10);
            if !real_dep_ids.is_empty() {
                for (idx, _) in batch.iter().enumerate() {
                    for i in 0..10usize {
                        let dep_idx = (idx * 10 + i) % real_dep_ids.len();
                        all_dep_ids.insert(real_dep_ids[dep_idx].clone());
                    }
                }
            }

            // Phase 2: Batch fetch with single IN query
            let mut dep_cache: HashMap<String, String> = HashMap::with_capacity(all_dep_ids.len());
            if !all_dep_ids.is_empty() {
                let placeholders: String = all_dep_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                let query = format!("SELECT message_id, content FROM messages WHERE message_id IN ({})", placeholders);
                if let Ok(mut stmt) = db.prepare(&query) {
                    let params: Vec<&dyn rusqlite::ToSql> = all_dep_ids.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
                    if let Ok(rows) = stmt.query_map(params.as_slice(), |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    }) {
                        for row in rows.flatten() {
                            dep_cache.insert(row.0, row.1);
                        }
                    }
                }
            }

            // Phase 3: Write batch in single transaction
            if db.execute("BEGIN", []).is_ok() {
                for (idx, (event_id, blob)) in batch.iter().enumerate() {
                    let _ = store.put(event_id, blob);
                    let _ = shareable.insert(event_id);

                    if let Ok((_, envelope)) = Envelope::parse(blob) {
                        let created_at_ms = envelope.payload.created_at_ms;

                        // Insert into neg_items (raw blob id)
                        let _ = neg_items_stmt.execute(rusqlite::params![
                            created_at_ms as i64,
                            event_id.as_slice()
                        ]);

                        // Access pre-fetched dependencies
                        if !real_dep_ids.is_empty() {
                            for i in 0..10usize {
                                let dep_idx = (idx * 10 + i) % real_dep_ids.len();
                                let _content = dep_cache.get(&real_dep_ids[dep_idx]);
                            }
                        }

                        let message_id = event_id_to_base64(event_id);
                        let channel_id = event_id_to_base64(&envelope.payload.channel_id);
                        let author_id = event_id_to_base64(&envelope.payload.author_id);
                        let _ = project_stmt.execute(rusqlite::params![
                            message_id,
                            channel_id,
                            author_id,
                            &envelope.payload.content,
                            created_at_ms as i64
                        ]);
                    }
                }
                let _ = db.execute("COMMIT", []);
            }
        }

        events_received.fetch_add(batch.len() as u64, Ordering::Relaxed);
    }
}

/// Run sync as the responder (server role)
/// Uses channels and batching for high throughput
async fn run_sync_responder(
    conn: &mut Connection,
    db_path: &str,
    timeout_secs: u64,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    info!("Starting negentropy sync (responder) for {} seconds", timeout_secs);

    // Phase 1: Load data and prefetch blobs into memory
    let db = open_connection(db_path)?;
    let items = load_negentropy_items(&db)?;
    info!("Loaded {} items for negentropy", items.len());

    let storage = build_negentropy_storage(&items)?;
    let mut neg = Negentropy::owned(storage, 64 * 1024)?;

    let store = Store::new(&db);
    let mut blob_cache: HashMap<EventId, Vec<u8>> = HashMap::new();
    for item in &items {
        if let Ok(Some(blob)) = store.get(&item.id) {
            blob_cache.insert(item.id, blob);
        }
    }
    info!("Prefetched {} blobs into cache", blob_cache.len());
    drop(db);

    // Phase 2: Set up channel for incoming events
    let (tx, rx) = mpsc::channel::<(EventId, Vec<u8>)>(100_000);
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();

    let db_path_owned = db_path.to_string();
    let writer_handle = tokio::task::spawn_blocking(move || {
        batch_writer(db_path_owned, rx, events_received_writer)
    });

    // Phase 3: Network I/O loop
    let mut events_sent: u64 = 0;
    let mut reconciliation_done = false;
    let mut rounds = 0;
    let mut idle_count = 0;
    const MAX_IDLE: u32 = 10000; // Allow more idle rounds for large transfers

    // Queue of events to send (from HaveList requests)
    let mut send_queue: Vec<Vec<u8>> = Vec::new();

    loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }

        if reconciliation_done && send_queue.is_empty() && idle_count >= MAX_IDLE {
            break;
        }

        // First: drain all pending receives
        loop {
            match tokio::time::timeout(Duration::from_millis(1), conn.recv()).await {
                Ok(Ok(SyncMessage::NegOpen { msg })) | Ok(Ok(SyncMessage::NegMsg { msg })) => {
                    idle_count = 0;
                    rounds += 1;

                    let response = neg.reconcile(&msg)?;
                    if response.is_empty() {
                        info!("Reconciliation complete in {} rounds", rounds);
                        reconciliation_done = true;
                    } else {
                        conn.send(&SyncMessage::NegMsg { msg: response }).await?;
                        conn.flush().await?;
                    }
                }
                Ok(Ok(SyncMessage::HaveList { ids })) => {
                    idle_count = 0;
                    reconciliation_done = true;

                    // Queue events for sending
                    for id in &ids {
                        if let Some(blob) = blob_cache.get(id) {
                            send_queue.push(blob.clone());
                        }
                    }
                }
                Ok(Ok(SyncMessage::Event { blob })) => {
                    idle_count = 0;
                    let event_id = hash_event(&blob);
                    let _ = tx.try_send((event_id, blob));
                }
                Ok(Ok(SyncMessage::Ping)) => {
                    // Ignore ping messages (used for stream establishment)
                }
                Ok(Ok(SyncMessage::WillSend { count: _ })) => {
                    // Non-dual responder doesn't need this
                }
                Ok(Err(transport::connection::ConnectionError::Closed)) => {
                    info!("Connection closed by peer");
                    drop(tx);
                    let _ = writer_handle.await;
                    return Ok(SyncStats { events_sent, events_received: events_received.load(Ordering::Relaxed), neg_rounds: rounds });
                }
                Ok(Err(e)) => {
                    warn!("Connection error: {}", e);
                    drop(tx);
                    let _ = writer_handle.await;
                    return Ok(SyncStats { events_sent, events_received: events_received.load(Ordering::Relaxed), neg_rounds: rounds });
                }
                Err(_) => break, // Timeout - no more pending
            }
        }

        // Second: send a batch from queue
        let mut sent_this_round = 0;
        while let Some(blob) = send_queue.pop() {
            if conn.send(&SyncMessage::Event { blob }).await.is_ok() {
                events_sent += 1;
                sent_this_round += 1;
                if sent_this_round >= 500 {
                    break;
                }
            }
        }

        if sent_this_round > 0 {
            let _ = conn.flush().await;
            idle_count = 0;
        } else if reconciliation_done {
            idle_count += 1;
        }
    }

    drop(tx);
    let _ = writer_handle.await;

    let stats = SyncStats {
        events_sent,
        events_received: events_received.load(Ordering::Relaxed),
        neg_rounds: rounds,
    };
    info!("Sync stats: {:?}", stats);
    Ok(stats)
}

/// Run sync as the initiator (client role) with dual streams
/// Control stream: NegOpen, NegMsg, HaveList
/// Data stream: Event blobs
///
/// Architecture:
/// - Main task: control stream (negentropy) + data sending
/// - Data receiver task: receives events, send().await for backpressure
/// - Ingest worker (spawn_blocking): batch writes to SQLite
/// - NO blob prefetch: fetches from SQLite on-demand
async fn run_sync_initiator_dual(
    conn: DualConnection,
    db_path: &str,
    timeout_secs: u64,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    info!("Starting negentropy sync (initiator, dual-stream) for {} seconds", timeout_secs);

    // Phase 1: Set up SQLite-backed negentropy storage
    let db = open_connection(db_path)?;
    let neg_storage = NegentropyStorageSqlite::new(&db);
    neg_storage.rebuild_blocks().map_err(|e| format!("Failed to rebuild blocks: {}", e))?;

    let item_count = neg_storage.size().map_err(|e| format!("Failed to get size: {:?}", e))?;
    info!("Loaded {} items for negentropy (SQLite-backed, no prefetch)", item_count);

    let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), 64 * 1024)?;
    let store = Store::new(&db);

    // Phase 2: Set up ingest channel with backpressure
    let (ingest_tx, ingest_rx) = mpsc::channel::<(EventId, Vec<u8>)>(5000);
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();

    let db_path_owned = db_path.to_string();
    let writer_handle = tokio::task::spawn_blocking(move || {
        batch_writer(db_path_owned, ingest_rx, events_received_writer)
    });

    // Split connection for concurrent send/recv
    let split = conn.split();
    let mut ctrl_send = split.control_send;
    let mut ctrl_recv = split.control_recv;
    let data_send = split.data_send;
    let mut data_recv = split.data_recv;

    // Phase 3: Spawn dedicated sender task to avoid send/recv deadlock
    let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(1000);
    let events_sent = Arc::new(AtomicU64::new(0));
    let events_sent_sender = events_sent.clone();

    let sender_handle = tokio::spawn(async move {
        let mut data_send = data_send;
        let mut batch = Vec::with_capacity(100);

        loop {
            // Collect a batch of events
            match send_rx.recv().await {
                Some(blob) => batch.push(blob),
                None => break, // Channel closed
            }

            // Drain more if available (non-blocking)
            while batch.len() < 100 {
                match send_rx.try_recv() {
                    Ok(blob) => batch.push(blob),
                    Err(_) => break,
                }
            }

            // Send the batch
            for blob in batch.drain(..) {
                if data_send.send(&SyncMessage::Event { blob }).await.is_ok() {
                    events_sent_sender.fetch_add(1, Ordering::Relaxed);
                }
            }
            data_send.flush().await.ok();
        }
    });

    // Phase 4: Set up DB-backed ID storage (O(1) memory)
    let pending_send = PendingSend::new(&db);
    let wanted = Wanted::new(&db);
    pending_send.clear()?;
    wanted.clear()?;

    // State for sync (counts instead of vectors)
    let mut total_to_send: i64 = 0;
    let mut total_to_recv: i64 = 0;
    let mut reconciliation_done = false;
    let mut rounds = 0;
    let mut peer_done = false;
    let mut sent_done = false;

    // Temporary vectors for reconcile_with_ids (cleared after writing to DB)
    let mut have_ids: Vec<Id> = Vec::new();
    let mut need_ids: Vec<Id> = Vec::new();

    // Send initial negentropy message
    let initial_msg = neg.initiate()?;
    ctrl_send.send(&SyncMessage::NegOpen { msg: initial_msg }).await?;
    ctrl_send.flush().await?;

    // Track pending count locally to avoid DB queries in hot loop
    let mut pending_count: i64 = 0;
    const SEND_BATCH_SIZE: usize = 1000;

    // Main loop using select! for true concurrent I/O
    loop {
        if start.elapsed() >= timeout {
            warn!("Timeout after {:?}", start.elapsed());
            break;
        }

        // Check completion
        let received = events_received.load(Ordering::Relaxed);
        let sent = events_sent.load(Ordering::Relaxed);
        // all_sent means events have actually been transmitted, not just queued
        let all_sent = total_to_send == 0 || sent >= total_to_send as u64;
        let all_received = total_to_recv == 0 || received >= total_to_recv as u64;

        if reconciliation_done && all_sent && all_received && peer_done {
            info!("Sync complete: sent {}, received {}", sent, received);
            break;
        }

        // Progress log every 5 seconds
        if start.elapsed().as_secs() % 5 == 0 && start.elapsed().subsec_millis() < 10 {
            info!("Progress: sent={}/{}, recv={}/{}, recon={}, peer_done={}",
                sent, total_to_send, received, total_to_recv, reconciliation_done, peer_done);
        }

        // Still have pending events to queue to sender
        let has_pending_send = reconciliation_done && pending_count > 0;

        tokio::select! {
            biased;

            // Always have a timeout to check completion conditions
            _ = tokio::time::sleep(Duration::from_micros(100)) => {}

            ctrl_result = ctrl_recv.recv() => {
                match ctrl_result {
                    Ok(SyncMessage::NegMsg { msg }) => {
                        rounds += 1;
                        // Clear vectors before each round to avoid accumulation
                        have_ids.clear();
                        need_ids.clear();

                        match neg.reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)? {
                            Some(next_msg) => {
                                // Insert this round's IDs directly to database (dedup via INSERT OR IGNORE)
                                if !have_ids.is_empty() {
                                    let event_ids: Vec<EventId> = have_ids.iter()
                                        .map(|id| neg_id_to_event_id(id))
                                        .collect();
                                    pending_send.insert_batch(&event_ids)?;
                                }
                                if !need_ids.is_empty() {
                                    let event_ids: Vec<EventId> = need_ids.iter()
                                        .map(|id| neg_id_to_event_id(id))
                                        .collect();
                                    wanted.insert_batch(&event_ids)?;
                                }

                                ctrl_send.send(&SyncMessage::NegMsg { msg: next_msg }).await?;
                                ctrl_send.flush().await?;
                            }
                            None => {
                                // Final round - insert remaining IDs
                                if !have_ids.is_empty() {
                                    let event_ids: Vec<EventId> = have_ids.iter()
                                        .map(|id| neg_id_to_event_id(id))
                                        .collect();
                                    pending_send.insert_batch(&event_ids)?;
                                }
                                if !need_ids.is_empty() {
                                    let event_ids: Vec<EventId> = need_ids.iter()
                                        .map(|id| neg_id_to_event_id(id))
                                        .collect();
                                    wanted.insert_batch(&event_ids)?;
                                }

                                // Get counts from database (reflects deduplication)
                                total_to_send = pending_send.count()?;
                                total_to_recv = wanted.count()?;
                                pending_count = total_to_send;

                                info!("Reconciliation complete in {} rounds: {} have, {} need",
                                    rounds, total_to_send, total_to_recv);
                                reconciliation_done = true;

                                // Clear vectors to free memory
                                have_ids.clear();
                                need_ids.clear();
                                have_ids.shrink_to_fit();
                                need_ids.shrink_to_fit();

                                // Stream HaveList in chunks to avoid loading all IDs into memory
                                // HaveLists tell peer what we need FROM them
                                const HAVELIST_BATCH: usize = 5000;
                                let mut offset = 0;
                                loop {
                                    let batch = wanted.get_batch(HAVELIST_BATCH, offset)?;
                                    if batch.is_empty() {
                                        break;
                                    }
                                    ctrl_send.send(&SyncMessage::HaveList { ids: batch }).await?;
                                    offset += HAVELIST_BATCH;
                                }

                                // WillSend comes LAST - tells peer how many events we will send TO them
                                // This also signals end of HaveList stream
                                ctrl_send.send(&SyncMessage::WillSend { count: total_to_send as u64 }).await?;
                                ctrl_send.flush().await?;
                            }
                        }
                    }
                    Ok(SyncMessage::HaveList { ids: _ }) => {
                        peer_done = true;
                    }
                    Ok(_) => {}
                    Err(transport::connection::ConnectionError::Closed) => {
                        peer_done = true;
                    }
                    Err(e) => {
                        warn!("Control error: {}", e);
                        break;
                    }
                }
            }

            data_result = data_recv.recv() => {
                match data_result {
                    Ok(SyncMessage::Event { blob }) => {
                        let event_id = hash_event(&blob);
                        if ingest_tx.send((event_id, blob)).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(transport::connection::ConnectionError::Closed) => {
                        peer_done = true;
                    }
                    Err(e) => {
                        warn!("Data error: {}", e);
                        break;
                    }
                }
            }

        }

        // Queue events to sender task (from database)
        if has_pending_send {
            // Get batch from database
            if let Ok(batch) = pending_send.get_batch(SEND_BATCH_SIZE) {
                let mut sent_ids = Vec::new();
                for event_id in &batch {
                    if let Ok(Some(blob)) = store.get(event_id) {
                        if send_tx.try_send(blob).is_err() {
                            break; // Channel full, try again next iteration
                        }
                        sent_ids.push(*event_id);
                    } else {
                        // Event not found, still mark as sent to avoid infinite loop
                        sent_ids.push(*event_id);
                    }
                }
                // Delete sent IDs from pending and update local count
                let deleted = sent_ids.len() as i64;
                pending_send.delete_batch(&sent_ids).ok();
                pending_count -= deleted;
            }
        }

        // Signal done when we've sent all our events
        if reconciliation_done && all_sent && !sent_done {
            ctrl_send.send(&SyncMessage::HaveList { ids: vec![] }).await.ok();
            ctrl_send.flush().await.ok();
            sent_done = true;
        }
    }

    // Send done signal if not already sent
    if !sent_done {
        ctrl_send.send(&SyncMessage::HaveList { ids: vec![] }).await.ok();
        ctrl_send.flush().await.ok();
    }

    // Cleanup: close channels and wait for tasks
    drop(send_tx);
    drop(ingest_tx);
    let _ = sender_handle.await;
    let _ = writer_handle.await;

    let stats = SyncStats {
        events_sent: events_sent.load(Ordering::Relaxed),
        events_received: events_received.load(Ordering::Relaxed),
        neg_rounds: rounds,
    };
    info!("Sync stats: {:?}", stats);
    Ok(stats)
}

/// Run sync as the responder (server role) with dual streams
///
/// Architecture:
/// - Uses select! for concurrent control/data handling
/// - Ingest worker (spawn_blocking): batch writes to SQLite
/// - NO blob prefetch: fetches from SQLite on-demand
async fn run_sync_responder_dual(
    conn: DualConnection,
    db_path: &str,
    timeout_secs: u64,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    info!("Starting negentropy sync (responder, dual-stream) for {} seconds", timeout_secs);

    // Phase 1: Set up SQLite-backed negentropy storage
    let db = open_connection(db_path)?;
    let neg_storage = NegentropyStorageSqlite::new(&db);
    neg_storage.rebuild_blocks().map_err(|e| format!("Failed to rebuild blocks: {}", e))?;

    let item_count = neg_storage.size().map_err(|e| format!("Failed to get size: {:?}", e))?;
    info!("Loaded {} items for negentropy (SQLite-backed, no prefetch)", item_count);

    let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), 64 * 1024)?;
    let store = Store::new(&db);

    // Phase 2: Set up ingest channel with backpressure
    let (ingest_tx, ingest_rx) = mpsc::channel::<(EventId, Vec<u8>)>(5000);
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();

    let db_path_owned = db_path.to_string();
    let writer_handle = tokio::task::spawn_blocking(move || {
        batch_writer(db_path_owned, ingest_rx, events_received_writer)
    });

    // Split connection for concurrent send/recv
    let split = conn.split();
    let mut ctrl_send = split.control_send;
    let mut ctrl_recv = split.control_recv;
    let data_send = split.data_send;
    let mut data_recv = split.data_recv;

    // Phase 3: Spawn dedicated sender task to avoid send/recv deadlock
    let (send_tx, mut send_rx) = mpsc::channel::<Vec<u8>>(1000);
    let events_sent = Arc::new(AtomicU64::new(0));
    let events_sent_sender = events_sent.clone();

    let sender_handle = tokio::spawn(async move {
        let mut data_send = data_send;
        let mut batch = Vec::with_capacity(100);

        loop {
            match send_rx.recv().await {
                Some(blob) => batch.push(blob),
                None => break,
            }

            while batch.len() < 100 {
                match send_rx.try_recv() {
                    Ok(blob) => batch.push(blob),
                    Err(_) => break,
                }
            }

            for blob in batch.drain(..) {
                if data_send.send(&SyncMessage::Event { blob }).await.is_ok() {
                    events_sent_sender.fetch_add(1, Ordering::Relaxed);
                }
            }
            data_send.flush().await.ok();
        }
    });

    // Phase 4: Set up DB-backed ID storage (O(1) memory)
    let pending_send = PendingSend::new(&db);
    pending_send.clear()?;

    // State for sync
    let mut total_to_send: i64 = 0;
    let mut total_to_recv: i64 = 0;  // Learned from HaveList received from initiator (count of events we need to receive)
    let mut reconciliation_done = false;
    let mut rounds = 0;
    let mut peer_done = false;
    let mut peer_done_time: Option<std::time::Instant> = None;
    let mut last_event_time: Option<std::time::Instant> = None;
    let mut sent_done = false;

    // Track pending count locally to avoid DB queries in hot loop
    let mut pending_count: i64 = 0;
    const SEND_BATCH_SIZE: usize = 1000;

    // Main loop using select! for true concurrent I/O
    loop {
        if start.elapsed() >= timeout {
            warn!("Timeout after {:?}", start.elapsed());
            break;
        }

        let sent = events_sent.load(Ordering::Relaxed);
        let received = events_received.load(Ordering::Relaxed);
        // all_sent means events have actually been transmitted, not just queued
        let all_sent = total_to_send == 0 || sent >= total_to_send as u64;
        let all_received = total_to_recv == 0 || received >= total_to_recv as u64;
        // Exit conditions:
        // 1. Reconciliation is done
        // 2. We've sent all our events (actually transmitted, not just queued)
        // 3. We've received all expected events
        // 4. Peer signaled done
        if reconciliation_done && all_sent && all_received && peer_done {
            info!("Sync complete: sent {}, received {}", sent, received);
            break;
        }

        // Progress log every 5 seconds
        if start.elapsed().as_secs() % 5 == 0 && start.elapsed().subsec_millis() < 10 {
            info!("Responder progress: sent={}/{}, recv={}, recon={}, peer_done={}",
                sent, total_to_send, events_received.load(Ordering::Relaxed), reconciliation_done, peer_done);
        }

        // Still have pending events to queue to sender
        let has_pending_send = reconciliation_done && pending_count > 0;

        tokio::select! {
            biased;

            // Timeout to prevent blocking
            _ = tokio::time::sleep(Duration::from_millis(1)) => {
                // Continue to send code below
            }

            ctrl_result = ctrl_recv.recv() => {
                match ctrl_result {
                    Ok(SyncMessage::NegOpen { msg }) | Ok(SyncMessage::NegMsg { msg }) => {
                        rounds += 1;
                        let response = neg.reconcile(&msg)?;
                        if response.is_empty() {
                            info!("Reconciliation complete in {} rounds", rounds);
                            reconciliation_done = true;
                        } else {
                            ctrl_send.send(&SyncMessage::NegMsg { msg: response }).await?;
                            ctrl_send.flush().await?;
                        }
                    }
                    Ok(SyncMessage::HaveList { ids }) => {
                        if ids.is_empty() {
                            // Empty HaveList = peer done sending
                            peer_done = true;
                            peer_done_time = Some(std::time::Instant::now());
                        } else {
                            // Accumulate HaveList batches to pending_send
                            pending_send.insert_batch(&ids)?;
                        }
                    }
                    Ok(SyncMessage::WillSend { count }) => {
                        // WillSend marks end of HaveList stream and start of data transfer
                        total_to_recv = count as i64;
                        total_to_send = pending_send.count()?;
                        pending_count = total_to_send;
                        reconciliation_done = true;
                        info!("Peer will send {} events, we will send {}", count, total_to_send);
                    }
                    Ok(_) => {}
                    Err(transport::connection::ConnectionError::Closed) => {
                        peer_done = true;
                        peer_done_time = Some(std::time::Instant::now());
                    }
                    Err(e) => {
                        warn!("Control error: {}", e);
                        break;
                    }
                }
            }

            data_result = data_recv.recv() => {
                match data_result {
                    Ok(SyncMessage::Event { blob }) => {
                        last_event_time = Some(std::time::Instant::now());
                        let event_id = hash_event(&blob);
                        if ingest_tx.send((event_id, blob)).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {}
                    Err(transport::connection::ConnectionError::Closed) => {
                        peer_done = true;
                        peer_done_time = Some(std::time::Instant::now());
                    }
                    Err(e) => {
                        warn!("Data error: {}", e);
                        break;
                    }
                }
            }

        }

        // Queue events to sender task (from database)
        if has_pending_send {
            if let Ok(batch) = pending_send.get_batch(SEND_BATCH_SIZE) {
                let mut sent_ids = Vec::new();
                for event_id in &batch {
                    if let Ok(Some(blob)) = store.get(event_id) {
                        if send_tx.try_send(blob).is_err() {
                            break; // Channel full, try again next iteration
                        }
                        sent_ids.push(*event_id);
                    } else {
                        // Event not found, still mark as sent
                        sent_ids.push(*event_id);
                    }
                }
                // Delete sent IDs from pending and update local count
                let deleted = sent_ids.len() as i64;
                pending_send.delete_batch(&sent_ids).ok();
                pending_count -= deleted;
            }
        }

        // Signal done when we've sent all our events
        if reconciliation_done && all_sent && !sent_done {
            ctrl_send.send(&SyncMessage::HaveList { ids: vec![] }).await.ok();
            ctrl_send.flush().await.ok();
            sent_done = true;
        }
    }

    // Send done signal if not already sent
    if !sent_done {
        ctrl_send.send(&SyncMessage::HaveList { ids: vec![] }).await.ok();
        ctrl_send.flush().await.ok();
    }

    // Cleanup: close channels and wait for tasks
    drop(send_tx);
    drop(ingest_tx);
    let _ = sender_handle.await;
    let _ = writer_handle.await;

    let stats = SyncStats {
        events_sent: events_sent.load(Ordering::Relaxed),
        events_received: events_received.load(Ordering::Relaxed),
        neg_rounds: rounds,
    };
    info!("Sync stats (responder): {:?}", stats);
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

    // Prepare projection statement
    let mut project_stmt = db.prepare(
        "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)"
    )?;

    // Prepare neg_items insertion (raw 32-byte blob id)
    let mut neg_items_stmt = db.prepare(
        "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)"
    )?;

    info!("Generating {} events...", count);

    for i in 0..count {
        let content = format!("Message {} from peer", i);
        let envelope = Envelope::new_message(
            signer_id,
            channel_id,
            author_id,
            content.clone(),
        );

        let blob = envelope.encode();
        let event_id = hash_event(&blob);
        let created_at_ms = envelope.payload.created_at_ms;

        store.put(&event_id, &blob)?;
        shareable.insert(&event_id)?;

        // Insert into neg_items for negentropy (raw blob id, not base64)
        neg_items_stmt.execute(rusqlite::params![
            created_at_ms as i64,
            event_id.as_slice()
        ])?;

        // Project inline
        let message_id = event_id_to_base64(&event_id);
        let channel_id_b64 = event_id_to_base64(&channel_id);
        let author_id_b64 = event_id_to_base64(&author_id);
        project_stmt.execute(rusqlite::params![
            message_id,
            channel_id_b64,
            author_id_b64,
            content,
            created_at_ms as i64
        ])?;
    }

    info!("Generated {} events in {}", count, db_path);
    show_stats(db_path)?;

    Ok(())
}

fn show_stats(db_path: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;

    let store_count: i64 = db.query_row("SELECT COUNT(*) FROM store", [], |row| row.get(0)).unwrap_or(0);
    let shareable_count: i64 = db.query_row("SELECT COUNT(*) FROM shareable_events", [], |row| row.get(0)).unwrap_or(0);
    let wanted_count: i64 = db.query_row("SELECT COUNT(*) FROM wanted_events", [], |row| row.get(0)).unwrap_or(0);
    let incoming_count: i64 = db.query_row("SELECT COUNT(*) FROM incoming_queue WHERE processed = 0", [], |row| row.get(0)).unwrap_or(0);
    let messages_count: i64 = db.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0)).unwrap_or(0);
    let neg_items_count: i64 = db.query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0)).unwrap_or(0);

    println!("Database: {}", db_path);
    println!("  Store:     {} events", store_count);
    println!("  Shareable: {} events", shareable_count);
    println!("  Wanted:    {} events", wanted_count);
    println!("  Incoming:  {} pending", incoming_count);
    println!("  Messages:  {} projected", messages_count);
    println!("  NegItems:  {} indexed", neg_items_count);

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
