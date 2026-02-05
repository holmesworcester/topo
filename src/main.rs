mod crypto;
mod db;
mod runtime;
mod sync;
mod transport;
mod wire;

use clap::{Parser, Subcommand};
use negentropy::{Negentropy, Id, NegentropyStorageBase, Storage};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

use crate::crypto::{hash_event, event_id_to_base64, EventId};
use crate::db::{open_connection, schema::create_tables, shareable::Shareable, store::Store, outgoing::OutgoingQueue, wanted::WantedEvents};
use crate::runtime::SyncStats;
use crate::sync::{SyncMessage, neg_id_to_event_id, NegentropyStorageSqlite};
use crate::transport::{
    DualConnection,
    StreamConn,
    StreamRecv,
    StreamSend,
    create_client_endpoint,
    create_server_endpoint,
    create_sim_pair,
    create_sim_split_pair,
    generate_keypair,
    generate_self_signed_cert,
    SimConfig,
};
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

    /// Simulate network with latency and bandwidth (no real sockets)
    Sim {
        /// Number of events to generate per peer
        #[arg(short, long, default_value = "50")]
        events: usize,

        /// Run duration in seconds
        #[arg(short, long, default_value = "10")]
        timeout: u64,

        /// One-way latency in milliseconds
        #[arg(long, default_value = "10")]
        latency_ms: u64,

        /// Bandwidth in KiB/s per direction
        #[arg(long, default_value = "50000")]
        bandwidth_kib: u64,

        /// Reuse existing sim_server.db/sim_client.db and skip generation
        #[arg(long, default_value_t = false)]
        no_generate: bool,
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
        Commands::Sim { events, timeout, latency_ms, bandwidth_kib, no_generate } => {
            run_sim(events, timeout, latency_ms, bandwidth_kib, no_generate).await?;
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
    let peer_id = connection.remote_address().to_string();
    info!("Accepted connection from {}", peer_id);

    // Accept two bidirectional streams: control first, then data
    let (control_send, control_recv) = connection.accept_bi().await?;
    let (data_send, data_recv) = connection.accept_bi().await?;
    let conn = DualConnection::new(control_send, control_recv, data_send, data_recv);
    info!("Accepted control and data streams");

    // Run sync as responder (server waits for client to initiate)
    run_sync_responder_dual(conn, db_path, timeout_secs, &peer_id).await?;

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
    let peer_id = connection.remote_address().to_string();
    info!("Connected to {}", peer_id);

    // Initialize database
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    // Open two bidirectional streams: control first, then data
    let (control_send, control_recv) = connection.open_bi().await?;
    let (data_send, data_recv) = connection.open_bi().await?;
    let mut conn = DualConnection::new(control_send, control_recv, data_send, data_recv);

    // Send markers on both streams to establish them (QUIC streams are lazy)
    conn.control.send(&SyncMessage::HaveList { ids: vec![] }).await?;
    conn.data_send.send(&SyncMessage::HaveList { ids: vec![] }).await?;
    conn.flush_control().await?;
    conn.flush_data().await?;
    info!("Opened and established control and data streams");

    // Run sync as initiator (client starts the reconciliation)
    run_sync_initiator_dual(conn, db_path, timeout_secs, &peer_id).await?;

    // Close connection
    connection.close(0u32.into(), b"done");

    Ok(())
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
    let wanted = WantedEvents::new(&db);

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
                    let _ = wanted.remove(event_id);

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
                    let _ = wanted.remove(event_id);

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
                    let _ = wanted.remove(event_id);

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

/// Run sync as the initiator (client role) with dual streams
/// Control stream: NegOpen, NegMsg, HaveList
/// Data stream: Event blobs
///
/// Architecture:
/// - Main task: control stream (negentropy) + data sending
/// - Data receiver task: receives events, send().await for backpressure
/// - Ingest worker (spawn_blocking): batch writes to SQLite
/// - NO blob prefetch: fetches from SQLite on-demand
async fn run_sync_initiator_dual<C, S, R>(
    conn: DualConnection<C, S, R>,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>>
where
    C: StreamConn,
    S: StreamSend,
    R: StreamRecv + Send + 'static,
{
    let DualConnection {
        mut control,
        mut data_send,
        mut data_recv,
    } = conn;
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    info!("Starting negentropy sync (initiator, dual-stream) for {} seconds", timeout_secs);

    // Phase 1: Set up SQLite-backed negentropy storage (no blob prefetch!)
    let db = open_connection(db_path)?;
    let neg_db = open_connection(db_path)?;

    // Outgoing queue + wanted tracking (per peer)
    let outgoing = OutgoingQueue::new(&db);
    let wanted = WantedEvents::new(&db);
    let _ = outgoing.clear_peer(peer_id);
    let _ = wanted.clear();

    // Rebuild block index for efficient negentropy queries (before snapshot)
    let neg_storage = NegentropyStorageSqlite::new(&neg_db);
    neg_storage.rebuild_blocks().map_err(|e| format!("Failed to rebuild blocks: {}", e))?;

    // Begin snapshot transaction for stable reconciliation view
    neg_db.execute("BEGIN", []).map_err(|e| format!("Failed to begin snapshot: {}", e))?;

    let item_count = neg_storage.size().map_err(|e| format!("Failed to get size: {:?}", e))?;
    info!("Loaded {} items for negentropy (SQLite-backed, no prefetch)", item_count);

    let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), 64 * 1024)?;

    // Store for on-demand blob fetching (no cache!)
    let store = Store::new(&db);

    // Phase 2: Set up bounded ingest channel (small for memory efficiency)
    // send().await provides backpressure when writer is slow
    let ingest_cap = if std::env::var("LOW_MEM").is_ok() { 1000 } else { 5000 };
    let (ingest_tx, ingest_rx) = mpsc::channel::<(EventId, Vec<u8>)>(ingest_cap);
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();
    let bytes_received = Arc::new(AtomicU64::new(0));

    // Spawn ingest worker (writes to SQLite)
    let db_path_owned = db_path.to_string();
    let writer_handle =
        tokio::task::spawn_blocking(move || batch_writer(db_path_owned, ingest_rx, events_received_writer));

    // Phase 3: Network I/O with dedicated tasks
    let mut have_ids: Vec<Id> = Vec::new();
    let mut need_ids: Vec<Id> = Vec::new();
    let mut events_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let bytes_received_worker = bytes_received.clone();

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let recv_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                msg = data_recv.recv() => {
                    match msg {
                        Ok(SyncMessage::Event { blob }) => {
                            bytes_received_worker.fetch_add(blob.len() as u64, Ordering::Relaxed);
                            let event_id = hash_event(&blob);
                            if ingest_tx.send((event_id, blob)).await.is_err() {
                                warn!("Ingest channel closed");
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(transport::connection::ConnectionError::Closed) => {
                            info!("Data stream closed by peer");
                            break;
                        }
                        Err(e) => {
                            warn!("Data stream error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    // Send initial negentropy message on control stream
    let initial_msg = neg.initiate()?;
    control.send(&SyncMessage::NegOpen { msg: initial_msg }).await?;
    control.flush().await?;

    let mut reconciliation_done = false;
    let mut rounds = 0;
    const HAVE_CHUNK: usize = 1000;
    const NEED_CHUNK: usize = 1000;

    let mut completed = false;
    let sync_start = Instant::now();

    // Main loop: handle control + send data
    // Data receiving happens inline but uses send().await for backpressure
    loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }

        // First: check control stream for negentropy messages (non-blocking)
        match tokio::time::timeout(Duration::from_millis(1), control.recv()).await {
            Ok(Ok(SyncMessage::NegMsg { msg })) => {
                rounds += 1;
                match neg.reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)? {
                    Some(next_msg) => {
                        control.send(&SyncMessage::NegMsg { msg: next_msg }).await?;
                        control.flush().await?;
                    }
                    None => {
                        reconciliation_done = true;
                    }
                }

                if !have_ids.is_empty() {
                    let mut batch: Vec<EventId> = Vec::with_capacity(HAVE_CHUNK);
                    for neg_id in have_ids.drain(..) {
                        batch.push(neg_id_to_event_id(&neg_id));
                        if batch.len() >= HAVE_CHUNK {
                            let _ = outgoing.enqueue_batch(peer_id, &batch);
                            batch.clear();
                        }
                    }
                    if !batch.is_empty() {
                        let _ = outgoing.enqueue_batch(peer_id, &batch);
                    }
                }

                if !need_ids.is_empty() {
                    let mut batch: Vec<EventId> = Vec::with_capacity(NEED_CHUNK);
                    for neg_id in need_ids.drain(..) {
                        let event_id = neg_id_to_event_id(&neg_id);
                        if wanted.insert(&event_id).unwrap_or(false) {
                            batch.push(event_id);
                        }
                        if batch.len() >= NEED_CHUNK {
                            control.send(&SyncMessage::HaveList { ids: batch }).await?;
                            control.flush().await?;
                            batch = Vec::with_capacity(NEED_CHUNK);
                        }
                    }
                    if !batch.is_empty() {
                        control.send(&SyncMessage::HaveList { ids: batch }).await?;
                        control.flush().await?;
                    }
                }

                if reconciliation_done {
                    let pending_out = outgoing.count_pending(peer_id).unwrap_or(0);
                    let pending_in = wanted.count().unwrap_or(0);
                    info!(
                        "Reconciliation complete in {} rounds: outgoing={}, wanted={}",
                        rounds, pending_out, pending_in
                    );
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(transport::connection::ConnectionError::Closed)) => {
                info!("Control stream closed by peer");
                break;
            }
            Ok(Err(e)) => {
                warn!("Control stream error: {}", e);
                break;
            }
            Err(_) => {} // Timeout
        }

        // Third: stream events from DB queue on data stream until blocked or empty
        let mut sent_this_round = 0;
        let mut blocked = false;
        while !blocked {
            let batch = outgoing.dequeue_batch(peer_id, 500).unwrap_or_default();
            if batch.is_empty() {
                break;
            }

            let mut sent_rowids: Vec<i64> = Vec::with_capacity(batch.len());
            for (rowid, event_id) in batch {
                if let Ok(Some(blob)) = store.get(&event_id) {
                    let blob_len = blob.len() as u64;
                    if data_send.send(&SyncMessage::Event { blob }).await.is_ok() {
                        events_sent += 1;
                        bytes_sent += blob_len;
                        sent_this_round += 1;
                        sent_rowids.push(rowid);
                    } else {
                        blocked = true;
                        break;
                    }
                } else {
                    // Blob not found, drop from queue
                    sent_rowids.push(rowid);
                }
            }
            let _ = outgoing.mark_sent_batch(&sent_rowids);
        }

        if sent_this_round > 0 {
            let _ = data_send.flush().await;
        }

        // Check completion
        let received = events_received.load(Ordering::Relaxed);
        if reconciliation_done {
            let pending_out = outgoing.count_pending(peer_id).unwrap_or(0);
            let pending_in = wanted.count().unwrap_or(0);
            if pending_out == 0 && pending_in == 0 {
                info!("Sync complete: sent {}, received {}", events_sent, received);
                completed = true;
                break;
            }
        }
    }

    if completed {
        let _ = outgoing.clear_peer(peer_id);
        let _ = wanted.clear();
    }
    let _ = neg_db.execute("COMMIT", []);
    let _ = neg_db.execute("COMMIT", []);
    let _ = shutdown_tx.send(true);
    let _ = recv_handle.await;
    let _ = writer_handle.await;

    let stats = SyncStats {
        events_sent,
        events_received: events_received.load(Ordering::Relaxed),
        neg_rounds: rounds,
        bytes_sent,
        bytes_received: bytes_received.load(Ordering::Relaxed),
        duration_ms: sync_start.elapsed().as_millis(),
    };
    info!("Sync stats: {:?}", stats);
    Ok(stats)
}

/// Run sync as the responder (server role) with dual streams
///
/// Architecture:
/// - Main task: control stream (negentropy) + data sending
/// - Ingest worker (spawn_blocking): batch writes to SQLite
/// - Uses send().await for backpressure on ingest channel
/// - NO blob prefetch: fetches from SQLite on-demand
async fn run_sync_responder_dual<C, S, R>(
    conn: DualConnection<C, S, R>,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>>
where
    C: StreamConn,
    S: StreamSend,
    R: StreamRecv + Send + 'static,
{
    let DualConnection {
        mut control,
        mut data_send,
        mut data_recv,
    } = conn;
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    info!("Starting negentropy sync (responder, dual-stream) for {} seconds", timeout_secs);

    // Phase 1: Set up SQLite-backed negentropy storage (no blob prefetch!)
    let db = open_connection(db_path)?;
    let neg_db = open_connection(db_path)?;

    // Outgoing queue (per peer)
    let outgoing = OutgoingQueue::new(&db);
    let _ = outgoing.clear_peer(peer_id);

    // Rebuild block index for efficient negentropy queries (before snapshot)
    let neg_storage = NegentropyStorageSqlite::new(&neg_db);
    neg_storage.rebuild_blocks().map_err(|e| format!("Failed to rebuild blocks: {}", e))?;

    // Begin snapshot transaction for stable reconciliation view
    neg_db.execute("BEGIN", []).map_err(|e| format!("Failed to begin snapshot: {}", e))?;

    let item_count = neg_storage.size().map_err(|e| format!("Failed to get size: {:?}", e))?;
    info!("Loaded {} items for negentropy (SQLite-backed, no prefetch)", item_count);

    let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), 64 * 1024)?;

    // Store for on-demand blob fetching (no cache!)
    let store = Store::new(&db);

    // Phase 2: Set up bounded ingest channel (small for memory efficiency)
    let ingest_cap = if std::env::var("LOW_MEM").is_ok() { 1000 } else { 5000 };
    let (ingest_tx, ingest_rx) = mpsc::channel::<(EventId, Vec<u8>)>(ingest_cap);
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();
    let bytes_received = Arc::new(AtomicU64::new(0));

    let db_path_owned = db_path.to_string();
    let writer_handle =
        tokio::task::spawn_blocking(move || batch_writer(db_path_owned, ingest_rx, events_received_writer));

    let bytes_received_worker = bytes_received.clone();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let recv_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                msg = data_recv.recv() => {
                    match msg {
                        Ok(SyncMessage::Event { blob }) => {
                            bytes_received_worker.fetch_add(blob.len() as u64, Ordering::Relaxed);
                            let event_id = hash_event(&blob);
                            if ingest_tx.send((event_id, blob)).await.is_err() {
                                warn!("Ingest channel closed");
                                break;
                            }
                        }
                        Ok(_) => {}
                        Err(transport::connection::ConnectionError::Closed) => {
                            info!("Data stream closed by peer");
                            break;
                        }
                        Err(e) => {
                            warn!("Data stream error: {}", e);
                            break;
                        }
                    }
                }
            }
        }
    });

    // Phase 3: Network I/O loop with dual streams
    let mut events_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let mut reconciliation_done = false;
    let mut rounds = 0;
    let mut idle_count = 0;
    const MAX_IDLE: u32 = 100;
    let mut completed = false;
    let sync_start = Instant::now();

    loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }

        if reconciliation_done {
            let pending_out = outgoing.count_pending(peer_id).unwrap_or(0);
            if pending_out == 0 && idle_count >= MAX_IDLE {
                completed = true;
                break;
            }
        }

        // First: check control stream (non-blocking)
        match tokio::time::timeout(Duration::from_millis(1), control.recv()).await {
            Ok(Ok(SyncMessage::NegOpen { msg })) | Ok(Ok(SyncMessage::NegMsg { msg })) => {
                idle_count = 0;
                rounds += 1;

                let response = neg.reconcile(&msg)?;
                if response.is_empty() {
                    info!("Reconciliation complete in {} rounds", rounds);
                    reconciliation_done = true;
                } else {
                    control.send(&SyncMessage::NegMsg { msg: response }).await?;
                    control.flush().await?;
                }
            }
            Ok(Ok(SyncMessage::HaveList { ids })) => {
                // Ignore empty HaveList (used for stream establishment)
                if ids.is_empty() {
                    continue;
                }
                idle_count = 0;
                reconciliation_done = true;

                // Queue event IDs for sending (blobs fetched on-demand)
                let _ = outgoing.enqueue_batch(peer_id, &ids);
            }
            Ok(Ok(_)) => {}
            Ok(Err(transport::connection::ConnectionError::Closed)) => {
                info!("Control stream closed by peer");
                break;
            }
            Ok(Err(e)) => {
                warn!("Control stream error: {}", e);
                break;
            }
            Err(_) => {} // Timeout
        }

        // Third: stream events from DB queue on data stream until blocked or empty
        let mut sent_this_round = 0;
        let mut blocked = false;
        while !blocked {
            let batch = outgoing.dequeue_batch(peer_id, 500).unwrap_or_default();
            if batch.is_empty() {
                break;
            }

            let mut sent_rowids: Vec<i64> = Vec::with_capacity(batch.len());
            for (rowid, event_id) in batch {
                if let Ok(Some(blob)) = store.get(&event_id) {
                    let blob_len = blob.len() as u64;
                    if data_send.send(&SyncMessage::Event { blob }).await.is_ok() {
                        events_sent += 1;
                        bytes_sent += blob_len;
                        sent_this_round += 1;
                        sent_rowids.push(rowid);
                    } else {
                        blocked = true;
                        break;
                    }
                } else {
                    sent_rowids.push(rowid);
                }
            }
            let _ = outgoing.mark_sent_batch(&sent_rowids);
        }

        if sent_this_round > 0 {
            let _ = data_send.flush().await;
            idle_count = 0;
        } else if reconciliation_done {
            idle_count += 1;
        }
    }

    if completed {
        let _ = outgoing.clear_peer(peer_id);
    }
    let _ = shutdown_tx.send(true);
    let _ = recv_handle.await;
    let _ = writer_handle.await;

    let stats = SyncStats {
        events_sent,
        events_received: events_received.load(Ordering::Relaxed),
        neg_rounds: rounds,
        bytes_sent,
        bytes_received: bytes_received.load(Ordering::Relaxed),
        duration_ms: sync_start.elapsed().as_millis(),
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
    let outgoing_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM outgoing_queue WHERE sent_at IS NULL",
        [],
        |row| row.get(0),
    ).unwrap_or(0);
    let incoming_count: i64 = db.query_row("SELECT COUNT(*) FROM incoming_queue WHERE processed = 0", [], |row| row.get(0)).unwrap_or(0);
    let messages_count: i64 = db.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0)).unwrap_or(0);
    let neg_items_count: i64 = db.query_row("SELECT COUNT(*) FROM neg_items", [], |row| row.get(0)).unwrap_or(0);

    println!("Database: {}", db_path);
    println!("  Store:     {} events", store_count);
    println!("  Shareable: {} events", shareable_count);
    println!("  Wanted:    {} events", wanted_count);
    println!("  Outgoing:  {} queued", outgoing_count);
    println!("  Incoming:  {} pending", incoming_count);
    println!("  Messages:  {} projected", messages_count);
    println!("  NegItems:  {} indexed", neg_items_count);

    Ok(())
}

fn read_vm_hwm_kb() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmHWM:") {
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if let Some(kb_str) = parts.first() {
                if let Ok(kb) = kb_str.parse::<u64>() {
                    return Some(kb);
                }
            }
        }
    }
    None
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

async fn run_sim(
    events_per_peer: usize,
    timeout_secs: u64,
    latency_ms: u64,
    bandwidth_kib: u64,
    no_generate: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("=== Simulated Sync Demo ===");
    if no_generate {
        info!("Reusing existing databases; running for {} seconds", timeout_secs);
        if !std::path::Path::new("sim_server.db").exists()
            || !std::path::Path::new("sim_client.db").exists()
        {
            return Err("sim_server.db or sim_client.db missing; run generate or omit --no-generate".into());
        }
    } else {
        info!("Generating {} events per peer, running for {} seconds", events_per_peer, timeout_secs);

        // Clean up old databases
        let _ = std::fs::remove_file("sim_server.db");
        let _ = std::fs::remove_file("sim_server.db-shm");
        let _ = std::fs::remove_file("sim_server.db-wal");
        let _ = std::fs::remove_file("sim_client.db");
        let _ = std::fs::remove_file("sim_client.db-shm");
        let _ = std::fs::remove_file("sim_client.db-wal");

        // Generate events for server and client
        info!("Generating events for server...");
        generate_events("sim_server.db", events_per_peer, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;
        info!("Generating events for client...");
        generate_events("sim_client.db", events_per_peer, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?;
    }

    let config = SimConfig {
        latency_ms,
        bandwidth_bytes_per_sec: bandwidth_kib.saturating_mul(1024),
    };

    // Simulated dual streams: control and data
    let (server_ctrl, client_ctrl) = create_sim_pair(config);
    let (server_data, client_data) = create_sim_split_pair(config);

    let server_conn = DualConnection {
        control: server_ctrl,
        data_send: server_data.0,
        data_recv: server_data.1,
    };
    let client_conn = DualConnection {
        control: client_ctrl,
        data_send: client_data.0,
        data_recv: client_data.1,
    };

    let server_fut = async move {
        run_sync_responder_dual(server_conn, "sim_server.db", timeout_secs, "sim-client").await
    };

    let client_fut = async move {
        run_sync_initiator_dual(client_conn, "sim_client.db", timeout_secs, "sim-server").await
    };

    let (server_res, client_res) = tokio::join!(server_fut, client_fut);
    let server_stats = match server_res {
        Ok(stats) => Some(stats),
        Err(e) => {
            error!("Sim server error: {}", e);
            None
        }
    };
    let client_stats = match client_res {
        Ok(stats) => Some(stats),
        Err(e) => {
            error!("Sim client error: {}", e);
            None
        }
    };

    info!("=== Sim Demo Complete ===");

    if let (Some(server), Some(client)) = (&server_stats, &client_stats) {
        let server_secs = (server.duration_ms as f64) / 1000.0;
        let client_secs = (client.duration_ms as f64) / 1000.0;
        let server_tx = (server.bytes_sent as f64) / (1024.0 * 1024.0) / server_secs.max(0.001);
        let server_rx = (server.bytes_received as f64) / (1024.0 * 1024.0) / server_secs.max(0.001);
        let client_tx = (client.bytes_sent as f64) / (1024.0 * 1024.0) / client_secs.max(0.001);
        let client_rx = (client.bytes_received as f64) / (1024.0 * 1024.0) / client_secs.max(0.001);

        println!("\n=== Throughput (data stream only) ===");
        println!("Server:  sent {:.2} MiB/s, recv {:.2} MiB/s over {:.2}s", server_tx, server_rx, server_secs);
        println!("Client:  sent {:.2} MiB/s, recv {:.2} MiB/s over {:.2}s", client_tx, client_rx, client_secs);

        let total_bytes = server.bytes_sent + client.bytes_sent;
        let total_secs = server_secs.max(client_secs).max(0.001);
        let total_mib_s = (total_bytes as f64) / (1024.0 * 1024.0) / total_secs;
        println!("Total:   {:.2} MiB/s (combined send) over {:.2}s", total_mib_s, total_secs);
    }

    if let Some(hwm_kb) = read_vm_hwm_kb() {
        let hwm_mib = (hwm_kb as f64) / 1024.0;
        println!("\nPeak RSS (VmHWM): {:.2} MiB", hwm_mib);
    }

    println!("\nServer database:");
    show_stats("sim_server.db")?;

    println!("\nClient database:");
    show_stats("sim_client.db")?;

    // Verify sync
    let server_db = open_connection("sim_server.db")?;
    let client_db = open_connection("sim_client.db")?;

    let server_store: i64 = server_db.query_row("SELECT COUNT(*) FROM store", [], |row| row.get(0))?;
    let client_store: i64 = client_db.query_row("SELECT COUNT(*) FROM store", [], |row| row.get(0))?;

    println!("\n=== Sim Sync Verification ===");
    println!("Server has {} events, Client has {} events", server_store, client_store);

    let expected = events_per_peer * 2; // Both peers should have all events
    if server_store >= expected as i64 && client_store >= expected as i64 {
        println!("SUCCESS: Both peers have all {} events!", expected);
    } else {
        println!("Sync incomplete - expected {} events each", expected);
    }

    Ok(())
}
