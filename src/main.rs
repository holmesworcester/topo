mod crypto;
mod db;
mod runtime;
mod sync;
mod transport;
mod wire;

use clap::{Parser, Subcommand};
use negentropy::{Negentropy, Id, NegentropyStorageBase};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

use crate::crypto::{hash_event, event_id_to_base64, EventId};
use crate::db::{
    open_connection,
    schema::create_tables,
    shareable::Shareable,
    store::Store,
    wanted::WantedEvents,
    outgoing::OutgoingQueue,
    sent::SentEvents,
    projection::ProjectionQueue,
};
use crate::runtime::SyncStats;
use crate::sync::{
    SyncMessage,
    ensure_negentropy_index,
    NegentropyStorageSqlite,
    reset_negentropy_profile,
    log_negentropy_profile,
    neg_block_size,
    neg_max_bytes,
    neg_rebuild_threshold,
    neg_id_to_event_id,
    encode_sync_message,
    sync_message_len,
    NegentropyBatchInserter,
};
use crate::transport::{
    Connection,
    create_client_endpoint,
    create_server_endpoint,
    generate_self_signed_cert,
    spki_from_base64,
    spki_to_base64,
    PeerKeyStore,
    StaticPeerKeyStore,
};
use crate::transport::{create_sim_pair, SimConfig, SimConnection, SyncConnection};
use crate::wire::Envelope;

const IO_CTRL_CAP: usize = 1024;
const IO_DATA_CAP: usize = 8192;
const IO_IN_CAP: usize = 8192;
const EVENT_CHAN_CAP: usize = 4096;
const DATA_BATCH_BYTES: usize = 64 * 1024;
const DATA_FLUSH_MS: u64 = 2;
const MEM_SAMPLE_MS: u64 = 500;

fn low_mem_enabled() -> bool {
    std::env::var("LOW_MEM")
        .ok()
        .map(|v| v != "0")
        .unwrap_or(false)
}

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|v| *v > 0)
}

fn io_ctrl_cap() -> usize {
    env_usize("IO_CTRL_CAP").unwrap_or_else(|| if low_mem_enabled() { 256 } else { IO_CTRL_CAP })
}

fn io_data_cap() -> usize {
    env_usize("IO_DATA_CAP").unwrap_or_else(|| if low_mem_enabled() { 1024 } else { IO_DATA_CAP })
}

fn io_in_cap() -> usize {
    env_usize("IO_IN_CAP").unwrap_or_else(|| if low_mem_enabled() { 1024 } else { IO_IN_CAP })
}

fn data_batch_bytes() -> usize {
    env_usize("DATA_BATCH_BYTES").unwrap_or_else(|| if low_mem_enabled() { 16 * 1024 } else { DATA_BATCH_BYTES })
}

fn event_chan_cap() -> usize {
    env_usize("EVENT_CHAN_CAP")
        .unwrap_or_else(|| if low_mem_enabled() { 1024 } else { EVENT_CHAN_CAP })
}

#[derive(Default)]
struct ByteCounters {
    sent: AtomicU64,
    recv: AtomicU64,
}

impl ByteCounters {
    fn add_sent(&self, n: usize) {
        self.sent.fetch_add(n as u64, Ordering::Relaxed);
    }

    fn add_recv(&self, n: usize) {
        self.recv.fetch_add(n as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (u64, u64) {
        (
            self.sent.load(Ordering::Relaxed),
            self.recv.load(Ordering::Relaxed),
        )
    }
}

fn read_rss_bytes() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let mut parts = rest.split_whitespace();
            if let Some(kb_str) = parts.next() {
                if let Ok(kb) = kb_str.parse::<u64>() {
                    return Some(kb.saturating_mul(1024));
                }
            }
        }
    }
    None
}

fn update_max_rss(max: &AtomicU64, value: u64) {
    let mut cur = max.load(Ordering::Relaxed);
    while value > cur {
        match max.compare_exchange(cur, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(next) => cur = next,
        }
    }
}

async fn enqueue_event(
    tx: &mpsc::Sender<(EventId, Vec<u8>)>,
    event_id: EventId,
    blob: Vec<u8>,
) {
    match tx.try_send((event_id, blob)) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full((event_id, blob))) => {
            let _ = tx.send((event_id, blob)).await;
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {}
    }
}

struct SyncIo {
    ctrl_tx: mpsc::Sender<SyncMessage>,
    data_tx: mpsc::Sender<SyncMessage>,
    inbound_rx: mpsc::Receiver<SyncMessage>,
    _handle: tokio::task::JoinHandle<()>,
}

struct IoSingle {
    tx: mpsc::Sender<SyncMessage>,
    rx: mpsc::Receiver<SyncMessage>,
    _handle: tokio::task::JoinHandle<()>,
}

fn start_io(
    mut conn: Box<dyn SyncConnection>,
) -> SyncIo {
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<SyncMessage>(io_ctrl_cap());
    let (data_tx, mut data_rx) = mpsc::channel::<SyncMessage>(io_data_cap());
    let (in_tx, inbound_rx) = mpsc::channel::<SyncMessage>(io_in_cap());

    let handle = tokio::spawn(async move {
        let batch_bytes = data_batch_bytes();
        let mut data_buf: Vec<u8> = Vec::with_capacity(batch_bytes * 2);
        let mut last_flush = Instant::now();

        loop {
            if !data_buf.is_empty()
                && (data_buf.len() >= batch_bytes
                    || last_flush.elapsed() >= Duration::from_millis(DATA_FLUSH_MS))
            {
                if conn.send_bytes(&data_buf).await.is_err() {
                    return;
                }
                let _ = conn.flush().await;
                data_buf.clear();
                last_flush = Instant::now();
                continue;
            }

            tokio::select! {
                msg = conn.recv() => {
                    match msg {
                        Ok(m) => {
                            if in_tx.send(m).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
                Some(msg) = ctrl_rx.recv() => {
                    let data = encode_sync_message(&msg);
                    if conn.send_bytes(&data).await.is_err() {
                        return;
                    }
                    let _ = conn.flush().await;
                }
                Some(msg) = data_rx.recv() => {
                    let data = encode_sync_message(&msg);
                    data_buf.extend_from_slice(&data);
                }
                _ = tokio::time::sleep(Duration::from_millis(DATA_FLUSH_MS)), if !data_buf.is_empty() => {
                    if conn.send_bytes(&data_buf).await.is_err() {
                        return;
                    }
                    let _ = conn.flush().await;
                    data_buf.clear();
                    last_flush = Instant::now();
                }
            }
        }
    });

    SyncIo {
        ctrl_tx,
        data_tx,
        inbound_rx,
        _handle: handle,
    }
}

fn start_ctrl_io(mut conn: Box<dyn SyncConnection>) -> IoSingle {
    let (tx, mut out_rx) = mpsc::channel::<SyncMessage>(io_ctrl_cap());
    let (in_tx, rx) = mpsc::channel::<SyncMessage>(io_in_cap());

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = conn.recv() => {
                    match msg {
                        Ok(m) => {
                            if in_tx.send(m).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
                Some(msg) = out_rx.recv() => {
                    let data = encode_sync_message(&msg);
                    if conn.send_bytes(&data).await.is_err() {
                        return;
                    }
                    let _ = conn.flush().await;
                }
            }
        }
    });

    IoSingle { tx, rx, _handle: handle }
}

fn start_data_io(mut conn: Box<dyn SyncConnection>) -> IoSingle {
    let (tx, mut out_rx) = mpsc::channel::<SyncMessage>(io_data_cap());
    let (in_tx, rx) = mpsc::channel::<SyncMessage>(io_in_cap());

    let handle = tokio::spawn(async move {
        let batch_bytes = data_batch_bytes();
        let mut data_buf: Vec<u8> = Vec::with_capacity(batch_bytes * 2);
        let mut last_flush = Instant::now();

        loop {
            if !data_buf.is_empty()
                && (data_buf.len() >= batch_bytes
                    || last_flush.elapsed() >= Duration::from_millis(DATA_FLUSH_MS))
            {
                if conn.send_bytes(&data_buf).await.is_err() {
                    return;
                }
                let _ = conn.flush().await;
                data_buf.clear();
                last_flush = Instant::now();
                continue;
            }

            tokio::select! {
                biased;
                Some(msg) = out_rx.recv() => {
                    let data = encode_sync_message(&msg);
                    data_buf.extend_from_slice(&data);
                }
                _ = tokio::time::sleep(Duration::from_millis(DATA_FLUSH_MS)), if !data_buf.is_empty() => {
                    if conn.send_bytes(&data_buf).await.is_err() {
                        return;
                    }
                    let _ = conn.flush().await;
                    data_buf.clear();
                    last_flush = Instant::now();
                }
                msg = conn.recv() => {
                    match msg {
                        Ok(m) => {
                            if in_tx.send(m).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            }
        }
    });

    IoSingle { tx, rx, _handle: handle }
}

fn start_data_sender(mut conn: Box<dyn SyncConnection>) -> (mpsc::Sender<SyncMessage>, tokio::task::JoinHandle<()>) {
    let (tx, mut out_rx) = mpsc::channel::<SyncMessage>(io_data_cap());

    let handle = tokio::spawn(async move {
        let batch_bytes = data_batch_bytes();
        let mut data_buf: Vec<u8> = Vec::with_capacity(batch_bytes * 2);
        let mut last_flush = Instant::now();

        loop {
            if !data_buf.is_empty()
                && (data_buf.len() >= batch_bytes
                    || last_flush.elapsed() >= Duration::from_millis(DATA_FLUSH_MS))
            {
                if conn.send_bytes(&data_buf).await.is_err() {
                    return;
                }
                let _ = conn.flush().await;
                data_buf.clear();
                last_flush = Instant::now();
                continue;
            }

            tokio::select! {
                Some(msg) = out_rx.recv() => {
                    let data = encode_sync_message(&msg);
                    data_buf.extend_from_slice(&data);
                }
                _ = tokio::time::sleep(Duration::from_millis(DATA_FLUSH_MS)), if !data_buf.is_empty() => {
                    if conn.send_bytes(&data_buf).await.is_err() {
                        return;
                    }
                    let _ = conn.flush().await;
                    data_buf.clear();
                    last_flush = Instant::now();
                }
                else => {
                    return;
                }
            }
        }
    });

    (tx, handle)
}

fn start_data_receiver(mut conn: Box<dyn SyncConnection>) -> (mpsc::Receiver<SyncMessage>, tokio::task::JoinHandle<()>) {
    let (in_tx, rx) = mpsc::channel::<SyncMessage>(io_in_cap());

    let handle = tokio::spawn(async move {
        loop {
            match conn.recv().await {
                Ok(m) => {
                    if in_tx.send(m).await.is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });

    (rx, handle)
}

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

        /// Base64-encoded peer SPKI (public key) to accept (enables mTLS pinning)
        #[arg(long)]
        peer_spki: Option<String>,

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

        /// Base64-encoded peer SPKI (public key) to accept (enables mTLS pinning)
        #[arg(long)]
        peer_spki: Option<String>,

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
        Commands::Listen { bind, peer_spki, db, timeout } => {
            let peer_spki = match peer_spki {
                Some(spki_b64) => Some(spki_from_base64(&spki_b64)?),
                None => None,
            };
            run_server(bind, &db, timeout, peer_spki).await?;
        }
        Commands::Connect { remote, peer_spki, db, timeout } => {
            let peer_spki = match peer_spki {
                Some(spki_b64) => Some(spki_from_base64(&spki_b64)?),
                None => None,
            };
            run_client(remote, &db, timeout, peer_spki).await?;
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
        Commands::Sim { events, timeout, latency_ms, bandwidth_kib } => {
            run_sim(events, timeout, latency_ms, bandwidth_kib).await?;
        }
    }

    Ok(())
}

async fn run_server(
    bind: SocketAddr,
    db_path: &str,
    timeout_secs: u64,
    peer_spki: Option<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Starting server on {}", bind);

    // Generate certificate identity
    let identity = generate_self_signed_cert()?;
    info!("Server SPKI (base64): {}", spki_to_base64(&identity.spki_der));

    // Create server endpoint
    let peer_store: Option<Arc<dyn PeerKeyStore>> = peer_spki.map(|spki| {
        Arc::new(StaticPeerKeyStore::new(vec![spki])) as Arc<dyn PeerKeyStore>
    });
    if peer_store.is_none() {
        warn!("mTLS pinning disabled: accepting any peer certificate");
    }
    let endpoint = create_server_endpoint(bind, identity.cert_der, identity.key_der, peer_store)?;
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

    // Open bidirectional stream
    let (send, recv) = connection.accept_bi().await?;
    let mut conn = Connection::new(send, recv);

    // Run sync as responder (server waits for client to initiate)
    run_sync_responder(Box::new(conn), db_path, timeout_secs, None).await?;

    // Close connection
    connection.close(0u32.into(), b"done");

    Ok(())
}

async fn run_client(
    remote: SocketAddr,
    db_path: &str,
    timeout_secs: u64,
    peer_spki: Option<Vec<u8>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("Connecting to {}", remote);

    // Create client endpoint
    let identity = generate_self_signed_cert()?;
    info!("Client SPKI (base64): {}", spki_to_base64(&identity.spki_der));
    let peer_store: Option<Arc<dyn PeerKeyStore>> = peer_spki.map(|spki| {
        Arc::new(StaticPeerKeyStore::new(vec![spki])) as Arc<dyn PeerKeyStore>
    });
    if peer_store.is_none() {
        warn!("mTLS pinning disabled: accepting any peer certificate");
    }
    let endpoint = create_client_endpoint(
        "0.0.0.0:0".parse()?,
        identity.cert_der,
        identity.key_der,
        peer_store,
    )?;

    // Connect to server
    let connection = endpoint.connect(remote, "localhost")?.await?;
    info!("Connected to {}", connection.remote_address());

    // Initialize database
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    // Open bidirectional stream
    let (send, recv) = connection.open_bi().await?;
    let mut conn = Connection::new(send, recv);

    // Run sync as initiator (client starts the reconciliation)
    run_sync_initiator(Box::new(conn), db_path, timeout_secs, None).await?;

    // Close connection
    connection.close(0u32.into(), b"done");

    Ok(())
}

/// Run sync as the initiator (client role)
/// Uses channels and batching for high throughput
async fn run_sync_initiator(
    conn: Box<dyn SyncConnection>,
    db_path: &str,
    timeout_secs: u64,
    bytes: Option<Arc<ByteCounters>>,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let recon_only = std::env::var("RECON_ONLY").is_ok();

    info!("Starting negentropy sync (initiator) for {} seconds", timeout_secs);

    // Phase 1: Initialize negentropy storage
    let db = open_connection(db_path)?;
    let block_size = neg_block_size();
    let rebuild_threshold = neg_rebuild_threshold(block_size);
    let max_bytes = neg_max_bytes() as u64;
    ensure_negentropy_index(&db, block_size, rebuild_threshold)?;
    let storage = NegentropyStorageSqlite::new(&db, block_size)?;
    let item_count = storage.size().unwrap_or(0);
    info!("Negentropy items: {}", item_count);
    let mut neg = Negentropy::borrowed(&storage, max_bytes)?;

    let store = Store::new(&db);
    let wanted = WantedEvents::new(&db);
    let outgoing = OutgoingQueue::new(&db);
    let sent = SentEvents::new(&db);
    let _ = outgoing.clear();
    let _ = wanted.clear();
    let _ = sent.clear();

    // Phase 2: Set up channel for incoming events
    let (tx, rx) = mpsc::channel::<(EventId, Vec<u8>)>(event_chan_cap());
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();

    let db_path_owned = db_path.to_string();
    let writer_handle = tokio::task::spawn_blocking(move || {
        batch_writer(db_path_owned, rx, events_received_writer)
    });
    let proj_inline = std::env::var("PROJ_INLINE").is_ok();
    let proj_off = std::env::var("PROJ_OFF").is_ok();
    let proj_stop = if !proj_inline && !proj_off {
        Some(Arc::new(AtomicBool::new(false)))
    } else {
        None
    };
    let proj_handle = if let Some(stop) = proj_stop.clone() {
        let db_path_proj = db_path.to_string();
        Some(tokio::task::spawn_blocking(move || {
            projection_worker(db_path_proj, stop)
        }))
    } else {
        None
    };
    // Phase 3: Network I/O
    let mut have_ids: Vec<Id> = Vec::new();
    let mut need_ids: Vec<Id> = Vec::new();
    let mut events_sent: u64 = 0;

    let mut io = start_io(conn);

    let initial_msg = neg.initiate()?;
    let open_msg = SyncMessage::NegOpen { msg: initial_msg };
    if let Some(b) = bytes.as_ref() {
        b.add_sent(sync_message_len(&open_msg));
    }
    io.ctrl_tx.send(open_msg).await?;

    let mut reconciliation_done = false;
    let mut rounds = 0;

    'sync_loop: loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }

        // First: drain all pending receives (non-blocking)
        loop {
            match tokio::time::timeout(Duration::from_millis(1), io.inbound_rx.recv()).await {
                Ok(Some(msg)) => {
                    if let Some(b) = bytes.as_ref() {
                        b.add_recv(sync_message_len(&msg));
                    }
                    match msg {
                        SyncMessage::NegMsg { msg } => {
                            rounds += 1;
                            match neg.reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)? {
                                Some(next_msg) => {
                                    let neg_msg = SyncMessage::NegMsg { msg: next_msg };
                                    if let Some(b) = bytes.as_ref() {
                                        b.add_sent(sync_message_len(&neg_msg));
                                    }
                                    io.ctrl_tx.send(neg_msg).await?;
                                }
                                None => {
                                    info!(
                                        "Reconciliation complete in {} rounds: {} have, {} need",
                                        rounds,
                                        have_ids.len(),
                                        need_ids.len()
                                    );
                                    reconciliation_done = true;
                                }
                            }

                            if !have_ids.is_empty() {
                                let mut batch: Vec<EventId> = Vec::with_capacity(have_ids.len());
                                for neg_id in &have_ids {
                                    let event_id = neg_id_to_event_id(neg_id);
                                    if sent.insert(&event_id).unwrap_or(false) {
                                        batch.push(event_id);
                                    }
                                }
                                let _ = outgoing.enqueue_batch(&batch);
                                have_ids.clear();
                            }

                            if !need_ids.is_empty() {
                                let mut new_needs: Vec<EventId> = Vec::with_capacity(need_ids.len());
                                for neg_id in &need_ids {
                                    let event_id = neg_id_to_event_id(neg_id);
                                    if wanted.insert(&event_id).unwrap_or(false) {
                                        new_needs.push(event_id);
                                    }
                                }
                                if !new_needs.is_empty() {
                                    let have_msg = SyncMessage::HaveList { ids: new_needs };
                                    if let Some(b) = bytes.as_ref() {
                                        b.add_sent(sync_message_len(&have_msg));
                                    }
                                    io.ctrl_tx.send(have_msg).await?;
                                }
                                need_ids.clear();
                            }

                            if reconciliation_done && recon_only {
                                info!("Reconcile-only mode: stopping after reconciliation");
                                break 'sync_loop;
                            }
                        }
                        SyncMessage::Event { blob } => {
                            let event_id = hash_event(&blob);
                            enqueue_event(&tx, event_id, blob).await;
                        }
                        _ => {}
                    }
                }
                Ok(None) => {
                    info!("Connection closed by peer");
                    drop(tx);
                    let _ = writer_handle.await;
                    if let Some(stop) = proj_stop.clone() {
                        stop.store(true, Ordering::Relaxed);
                    }
                    if let Some(handle) = proj_handle {
                        let _ = handle.await;
                    }
                    return Ok(SyncStats { events_sent, events_received: events_received.load(Ordering::Relaxed), neg_rounds: rounds });
                }
                Err(_) => break, // Timeout - no more pending receives
            }
        }

        // Second: send a batch of events
        let mut sent_this_round = 0;
        let batch = outgoing.dequeue_batch(500).unwrap_or_default();
        let mut sent_ids: Vec<EventId> = Vec::with_capacity(batch.len());
        for event_id in batch {
            match store.get(&event_id) {
                Ok(Some(blob)) => {
                    let msg_len = 1 + blob.len();
                    if io.data_tx.send(SyncMessage::Event { blob }).await.is_ok() {
                        if let Some(b) = bytes.as_ref() {
                            b.add_sent(msg_len);
                        }
                        events_sent += 1;
                        sent_ids.push(event_id);
                        sent_this_round += 1;
                        if sent_this_round >= 500 {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                Ok(None) => {
                    sent_ids.push(event_id);
                }
                Err(e) => {
                    warn!("Failed to load blob for {:?}: {}", event_id, e);
                    sent_ids.push(event_id);
                }
            }
        }
        let _ = outgoing.remove_batch(&sent_ids);

        if reconciliation_done {
            let pending_out = outgoing.count().unwrap_or(0);
            let pending_in = wanted.count().unwrap_or(0);
            if pending_out == 0 && pending_in == 0 {
                info!("Sync complete: sent {}, received {}", events_sent, events_received.load(Ordering::Relaxed));
                break;
            }
        }
    }

    drop(tx);
    let _ = writer_handle.await;
    if let Some(stop) = proj_stop {
        stop.store(true, Ordering::Relaxed);
    }
    if let Some(handle) = proj_handle {
        let _ = handle.await;
    }
    let stats = SyncStats {
        events_sent,
        events_received: events_received.load(Ordering::Relaxed),
        neg_rounds: rounds,
    };
    info!("Sync stats: {:?}", stats);
    Ok(stats)
}

async fn run_sync_initiator_dual(
    ctrl_conn: Box<dyn SyncConnection>,
    data_out_conn: Box<dyn SyncConnection>,
    data_in_conn: Box<dyn SyncConnection>,
    db_path: &str,
    timeout_secs: u64,
    bytes: Option<Arc<ByteCounters>>,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let recon_only = std::env::var("RECON_ONLY").is_ok();

    info!("Starting negentropy sync (initiator) for {} seconds", timeout_secs);

    let db = open_connection(db_path)?;
    let block_size = neg_block_size();
    let rebuild_threshold = neg_rebuild_threshold(block_size);
    let max_bytes = neg_max_bytes() as u64;
    ensure_negentropy_index(&db, block_size, rebuild_threshold)?;
    let storage = NegentropyStorageSqlite::new(&db, block_size)?;
    let item_count = storage.size().unwrap_or(0);
    info!("Negentropy items: {}", item_count);
    let mut neg = Negentropy::borrowed(&storage, max_bytes)?;

    let store = Store::new(&db);
    let wanted = WantedEvents::new(&db);
    let outgoing = OutgoingQueue::new(&db);
    let sent = SentEvents::new(&db);
    let _ = outgoing.clear();
    let _ = wanted.clear();
    let _ = sent.clear();

    let (tx, rx) = mpsc::channel::<(EventId, Vec<u8>)>(event_chan_cap());
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();

    let db_path_owned = db_path.to_string();
    let writer_handle = tokio::task::spawn_blocking(move || {
        batch_writer(db_path_owned, rx, events_received_writer)
    });
    let proj_inline = std::env::var("PROJ_INLINE").is_ok();
    let proj_off = std::env::var("PROJ_OFF").is_ok();
    let proj_stop = if !proj_inline && !proj_off {
        Some(Arc::new(AtomicBool::new(false)))
    } else {
        None
    };
    let proj_handle = if let Some(stop) = proj_stop.clone() {
        let db_path_proj = db_path.to_string();
        Some(tokio::task::spawn_blocking(move || {
            projection_worker(db_path_proj, stop)
        }))
    } else {
        None
    };

    let mut ctrl_io = start_ctrl_io(ctrl_conn);
    let (data_tx, _data_send_handle) = start_data_sender(data_out_conn);
    let (mut data_rx, _data_recv_handle) = start_data_receiver(data_in_conn);

    let mut have_ids: Vec<Id> = Vec::new();
    let mut need_ids: Vec<Id> = Vec::new();
    let mut events_sent: u64 = 0;

    let initial_msg = neg.initiate()?;
    let open_msg = SyncMessage::NegOpen { msg: initial_msg };
    if let Some(b) = bytes.as_ref() {
        b.add_sent(sync_message_len(&open_msg));
    }
    ctrl_io.tx.send(open_msg).await?;

    let mut reconciliation_done = false;
    let mut rounds = 0;

    'sync_loop: loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }

        loop {
            let recv_fut = async {
                tokio::select! {
                    msg = ctrl_io.rx.recv() => msg,
                    msg = data_rx.recv() => msg,
                }
            };
            match tokio::time::timeout(Duration::from_millis(1), recv_fut).await {
                Ok(Some(msg)) => {
                    if let Some(b) = bytes.as_ref() {
                        b.add_recv(sync_message_len(&msg));
                    }
                    match msg {
                        SyncMessage::NegMsg { msg } => {
                            rounds += 1;
                            match neg.reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)? {
                                Some(next_msg) => {
                                    let neg_msg = SyncMessage::NegMsg { msg: next_msg };
                                    if let Some(b) = bytes.as_ref() {
                                        b.add_sent(sync_message_len(&neg_msg));
                                    }
                                    ctrl_io.tx.send(neg_msg).await?;
                                }
                                None => {
                                    info!(
                                        "Reconciliation complete in {} rounds: {} have, {} need",
                                        rounds,
                                        have_ids.len(),
                                        need_ids.len()
                                    );
                                    reconciliation_done = true;
                                }
                            }

                            if !have_ids.is_empty() {
                                let mut batch: Vec<EventId> = Vec::with_capacity(have_ids.len());
                                for neg_id in &have_ids {
                                    let event_id = neg_id_to_event_id(neg_id);
                                    if sent.insert(&event_id).unwrap_or(false) {
                                        batch.push(event_id);
                                    }
                                }
                                let _ = outgoing.enqueue_batch(&batch);
                                have_ids.clear();
                            }

                            if !need_ids.is_empty() {
                                let mut new_needs: Vec<EventId> = Vec::with_capacity(need_ids.len());
                                for neg_id in &need_ids {
                                    let event_id = neg_id_to_event_id(neg_id);
                                    if wanted.insert(&event_id).unwrap_or(false) {
                                        new_needs.push(event_id);
                                    }
                                }
                                if !new_needs.is_empty() {
                                    let have_msg = SyncMessage::HaveList { ids: new_needs };
                                    if let Some(b) = bytes.as_ref() {
                                        b.add_sent(sync_message_len(&have_msg));
                                    }
                                    ctrl_io.tx.send(have_msg).await?;
                                }
                                need_ids.clear();
                            }

                            if reconciliation_done && recon_only {
                                info!("Reconcile-only mode: stopping after reconciliation");
                                break 'sync_loop;
                            }
                        }
                        SyncMessage::Event { blob } => {
                            let event_id = hash_event(&blob);
                            enqueue_event(&tx, event_id, blob).await;
                        }
                        _ => {}
                    }
                }
                Ok(None) => {
                    info!("Connection closed by peer");
                    drop(tx);
                    let _ = writer_handle.await;
                    if let Some(stop) = proj_stop.clone() {
                        stop.store(true, Ordering::Relaxed);
                    }
                    if let Some(handle) = proj_handle {
                        let _ = handle.await;
                    }
                    return Ok(SyncStats { events_sent, events_received: events_received.load(Ordering::Relaxed), neg_rounds: rounds });
                }
                Err(_) => break,
            }
        }

        let mut sent_this_round = 0;
        let batch = outgoing.dequeue_batch(500).unwrap_or_default();
        let mut sent_ids: Vec<EventId> = Vec::with_capacity(batch.len());
        for event_id in batch {
            match store.get(&event_id) {
                Ok(Some(blob)) => {
                    let msg_len = 1 + blob.len();
                    if data_tx.send(SyncMessage::Event { blob }).await.is_ok() {
                        if let Some(b) = bytes.as_ref() {
                            b.add_sent(msg_len);
                        }
                        events_sent += 1;
                        sent_ids.push(event_id);
                        sent_this_round += 1;
                        if sent_this_round >= 500 {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                Ok(None) => {
                    sent_ids.push(event_id);
                }
                Err(e) => {
                    warn!("Failed to load blob for {:?}: {}", event_id, e);
                    sent_ids.push(event_id);
                }
            }
        }
        let _ = outgoing.remove_batch(&sent_ids);

        if reconciliation_done {
            let pending_out = outgoing.count().unwrap_or(0);
            let pending_in = wanted.count().unwrap_or(0);
            if pending_out == 0 && pending_in == 0 {
                info!("Sync complete: sent {}, received {}", events_sent, events_received.load(Ordering::Relaxed));
                break;
            }
        }
    }

    drop(tx);
    let _ = writer_handle.await;
    if let Some(stop) = proj_stop {
        stop.store(true, Ordering::Relaxed);
    }
    if let Some(handle) = proj_handle {
        let _ = handle.await;
    }
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
    let wanted = WantedEvents::new(&db);
    let projection = ProjectionQueue::new(&db);
    let proj_inline = std::env::var("PROJ_INLINE").is_ok();
    let proj_off = std::env::var("PROJ_OFF").is_ok();
    let neg_off = std::env::var("NEG_UPDATE_OFF").is_ok();
    let shareable_off = std::env::var("SHAREABLE_OFF").is_ok();

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

        if !proj_inline {
            let block_size = neg_block_size();
            let mut neg_inserter = if neg_off {
                None
            } else {
                match NegentropyBatchInserter::new(&db, block_size) {
                    Ok(inserter) => Some(inserter),
                    Err(e) => {
                        error!("Failed to init negentropy inserter: {}", e);
                        None
                    }
                }
            };
            let mut proj_batch: Vec<EventId> = Vec::with_capacity(batch.len());
            if db.execute("BEGIN", []).is_ok() {
                for (event_id, blob) in &batch {
                    let _ = store.put(event_id, blob);
                    if !shareable_off {
                        let _ = shareable.insert(event_id);
                    }
                    let _ = wanted.remove(event_id);

                    if !neg_off {
                        if let Some(ts) = Envelope::extract_created_at(blob) {
                            if let Some(inserter) = neg_inserter.as_mut() {
                                if let Err(e) = inserter.insert(ts, event_id) {
                                    error!("Failed to insert negentropy item: {}", e);
                                }
                            }
                        }
                    }
                    if !proj_off {
                        proj_batch.push(*event_id);
                    }
                }
                if let Some(inserter) = neg_inserter {
                    if let Err(e) = inserter.finish() {
                        error!("Failed to finalize negentropy batch: {}", e);
                    }
                }
                let _ = db.execute("COMMIT", []);
            }

            if !proj_off {
                let _ = projection.enqueue_batch(&proj_batch);
            }

            events_received.fetch_add(batch.len() as u64, Ordering::Relaxed);
            continue;
        }

        if proj_off {
            // Inline projection disabled; just store + neg + shareable
            let block_size = neg_block_size();
            let mut neg_inserter = if neg_off {
                None
            } else {
                match NegentropyBatchInserter::new(&db, block_size) {
                    Ok(inserter) => Some(inserter),
                    Err(e) => {
                        error!("Failed to init negentropy inserter: {}", e);
                        None
                    }
                }
            };
            if db.execute("BEGIN", []).is_ok() {
                for (event_id, blob) in &batch {
                    let _ = store.put(event_id, blob);
                    if !shareable_off {
                        let _ = shareable.insert(event_id);
                    }
                    let _ = wanted.remove(event_id);

                    if !neg_off {
                        if let Some(ts) = Envelope::extract_created_at(blob) {
                            if let Some(inserter) = neg_inserter.as_mut() {
                                if let Err(e) = inserter.insert(ts, event_id) {
                                    error!("Failed to insert negentropy item: {}", e);
                                }
                            }
                        }
                    }
                }
                if let Some(inserter) = neg_inserter {
                    if let Err(e) = inserter.finish() {
                        error!("Failed to finalize negentropy batch: {}", e);
                    }
                }
                let _ = db.execute("COMMIT", []);
            }

            events_received.fetch_add(batch.len() as u64, Ordering::Relaxed);
            continue;
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
            let block_size = neg_block_size();
            let mut neg_inserter = if neg_off {
                None
            } else {
                match NegentropyBatchInserter::new(&db, block_size) {
                    Ok(inserter) => Some(inserter),
                    Err(e) => {
                        error!("Failed to init negentropy inserter: {}", e);
                        None
                    }
                }
            };
            if db.execute("BEGIN", []).is_ok() {
                for (event_id, blob) in &batch {
                    let _ = store.put(event_id, blob);
                    if !shareable_off {
                        let _ = shareable.insert(event_id);
                    }
                    let _ = wanted.remove(event_id);

                    if !neg_off {
                        if let Some(ts) = Envelope::extract_created_at(blob) {
                            if let Some(inserter) = neg_inserter.as_mut() {
                                if let Err(e) = inserter.insert(ts, event_id) {
                                    error!("Failed to insert negentropy item: {}", e);
                                }
                            }
                        }
                    }

                    if let Ok((_, envelope)) = Envelope::parse(blob) {
                        let message_id = event_id_to_base64(event_id);
                        let channel_id = event_id_to_base64(&envelope.payload.channel_id);
                        let author_id = event_id_to_base64(&envelope.payload.author_id);
                        let _ = project_stmt.execute(rusqlite::params![
                            message_id,
                            channel_id,
                            author_id,
                            &envelope.payload.content,
                            envelope.payload.created_at_ms as i64
                        ]);
                    }
                }
                if let Some(inserter) = neg_inserter {
                    if let Err(e) = inserter.finish() {
                        error!("Failed to finalize negentropy batch: {}", e);
                    }
                }
                let _ = db.execute("COMMIT", []);
            }
        } else if use_naive {
            // NAIVE: Read dependencies inside projection loop (slower)
            let block_size = neg_block_size();
            let mut neg_inserter = if neg_off {
                None
            } else {
                match NegentropyBatchInserter::new(&db, block_size) {
                    Ok(inserter) => Some(inserter),
                    Err(e) => {
                        error!("Failed to init negentropy inserter: {}", e);
                        None
                    }
                }
            };
            if db.execute("BEGIN", []).is_ok() {
                for (idx, (event_id, blob)) in batch.iter().enumerate() {
                    let _ = store.put(event_id, blob);
                    if !shareable_off {
                        let _ = shareable.insert(event_id);
                    }
                    let _ = wanted.remove(event_id);

                    if !neg_off {
                        if let Some(ts) = Envelope::extract_created_at(blob) {
                            if let Some(inserter) = neg_inserter.as_mut() {
                                if let Err(e) = inserter.insert(ts, event_id) {
                                    error!("Failed to insert negentropy item: {}", e);
                                }
                            }
                        }
                    }

                    if let Ok((_, envelope)) = Envelope::parse(blob) {
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
                            envelope.payload.created_at_ms as i64
                        ]);
                    }
                }
                if let Some(inserter) = neg_inserter {
                    if let Err(e) = inserter.finish() {
                        error!("Failed to finalize negentropy batch: {}", e);
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
            let block_size = neg_block_size();
            let mut neg_inserter = if neg_off {
                None
            } else {
                match NegentropyBatchInserter::new(&db, block_size) {
                    Ok(inserter) => Some(inserter),
                    Err(e) => {
                        error!("Failed to init negentropy inserter: {}", e);
                        None
                    }
                }
            };
            if db.execute("BEGIN", []).is_ok() {
                for (idx, (event_id, blob)) in batch.iter().enumerate() {
                    let _ = store.put(event_id, blob);
                    if !shareable_off {
                        let _ = shareable.insert(event_id);
                    }
                    let _ = wanted.remove(event_id);

                    if !neg_off {
                        if let Some(ts) = Envelope::extract_created_at(blob) {
                            if let Some(inserter) = neg_inserter.as_mut() {
                                if let Err(e) = inserter.insert(ts, event_id) {
                                    error!("Failed to insert negentropy item: {}", e);
                                }
                            }
                        }
                    }

                    if let Ok((_, envelope)) = Envelope::parse(blob) {
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
                            envelope.payload.created_at_ms as i64
                        ]);
                    }
                }
                if let Some(inserter) = neg_inserter {
                    if let Err(e) = inserter.finish() {
                        error!("Failed to finalize negentropy batch: {}", e);
                    }
                }
                let _ = db.execute("COMMIT", []);
            }
        }

        events_received.fetch_add(batch.len() as u64, Ordering::Relaxed);
    }
}

fn projection_worker(db_path: String, stop: Arc<AtomicBool>) {
    let use_naive = std::env::var("NAIVE_DEPS").is_ok();
    let no_deps = std::env::var("NO_DEPS").is_ok();

    let db = match open_connection(&db_path) {
        Ok(db) => db,
        Err(e) => {
            error!("Projection worker failed to open db: {}", e);
            return;
        }
    };

    let store = Store::new(&db);
    let projection = ProjectionQueue::new(&db);

    let mut project_stmt = match db.prepare(
        "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Projection worker failed to prepare projection statement: {}", e);
            return;
        }
    };

    let mut dep_read_stmt = match db.prepare("SELECT content FROM messages WHERE message_id = ?1") {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Projection worker failed to prepare dependency read statement: {}", e);
            return;
        }
    };

    loop {
        let batch = match projection.dequeue_batch(1000) {
            Ok(items) => items,
            Err(e) => {
                error!("Projection worker dequeue failed: {}", e);
                return;
            }
        };

        if batch.is_empty() {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
            continue;
        }

        let real_dep_ids: Vec<String> = if no_deps {
            Vec::new()
        } else {
            let mut ids = Vec::new();
            if let Ok(mut stmt) = db.prepare("SELECT message_id FROM messages ORDER BY RANDOM() LIMIT 1000") {
                if let Ok(rows) = stmt.query_map([], |row| row.get::<_, String>(0)) {
                    ids = rows.flatten().collect();
                }
            }
            ids
        };

        let mut dep_cache: HashMap<String, String> = HashMap::new();
        if !no_deps && !use_naive {
            let mut all_dep_ids: HashSet<String> = HashSet::with_capacity(batch.len() * 10);
            if !real_dep_ids.is_empty() {
                for (idx, _) in batch.iter().enumerate() {
                    for i in 0..10usize {
                        let dep_idx = (idx * 10 + i) % real_dep_ids.len();
                        all_dep_ids.insert(real_dep_ids[dep_idx].clone());
                    }
                }
            }

            if !all_dep_ids.is_empty() {
                let placeholders: String = all_dep_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                let query = format!("SELECT message_id, content FROM messages WHERE message_id IN ({})", placeholders);
                if let Ok(mut stmt) = db.prepare(&query) {
                    let params: Vec<&dyn rusqlite::ToSql> =
                        all_dep_ids.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
                    if let Ok(rows) = stmt.query_map(params.as_slice(), |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    }) {
                        for row in rows.flatten() {
                            dep_cache.insert(row.0, row.1);
                        }
                    }
                }
            }
        }

        let mut last_lock_warn = Instant::now() - Duration::from_secs(2);
        let mut lock_backoff_ms = 1u64;
        let mut began = false;
        loop {
            match db.execute("BEGIN IMMEDIATE", []) {
                Ok(_) => {
                    began = true;
                    lock_backoff_ms = 1;
                    break;
                }
                Err(e) => {
                    let is_busy = matches!(
                        e,
                        rusqlite::Error::SqliteFailure(err, _)
                            if err.code == rusqlite::ErrorCode::DatabaseBusy
                                || err.code == rusqlite::ErrorCode::DatabaseLocked
                    );
                    if is_busy {
                        if last_lock_warn.elapsed() >= Duration::from_secs(1) {
                            warn!("Projection worker waiting on writer lock");
                            last_lock_warn = Instant::now();
                        }
                        std::thread::sleep(Duration::from_millis(lock_backoff_ms));
                        lock_backoff_ms = (lock_backoff_ms * 2).min(50);
                        continue;
                    }
                    warn!("Projection worker failed to start transaction: {}", e);
                    std::thread::sleep(Duration::from_millis(5));
                    break;
                }
            }
        }

        if !began {
            continue;
        }

        let mut processed: Vec<EventId> = Vec::with_capacity(batch.len());
        for (idx, event_id) in batch.iter().enumerate() {
            let blob = match store.get(event_id) {
                Ok(Some(blob)) => blob,
                Ok(None) => {
                    warn!("Projection worker missing blob for {:?}", event_id);
                    processed.push(*event_id);
                    continue;
                }
                Err(e) => {
                    warn!("Projection worker failed to load blob for {:?}: {}", event_id, e);
                    continue;
                }
            };

            let envelope = match Envelope::parse(&blob) {
                Ok((_, envelope)) => envelope,
                Err(e) => {
                    warn!("Projection worker failed to parse blob for {:?}: {}", event_id, e);
                    processed.push(*event_id);
                    continue;
                }
            };

            if !no_deps {
                if use_naive {
                    if !real_dep_ids.is_empty() {
                        for i in 0..10usize {
                            let dep_idx = (idx * 10 + i) % real_dep_ids.len();
                            let dep_id_str = &real_dep_ids[dep_idx];
                            let _content: Option<String> = dep_read_stmt
                                .query_row([dep_id_str], |row| row.get(0))
                                .ok();
                        }
                    }
                } else if !real_dep_ids.is_empty() {
                    for i in 0..10usize {
                        let dep_idx = (idx * 10 + i) % real_dep_ids.len();
                        let _content = dep_cache.get(&real_dep_ids[dep_idx]);
                    }
                }
            }

            let message_id = event_id_to_base64(event_id);
            let channel_id = event_id_to_base64(&envelope.payload.channel_id);
            let author_id = event_id_to_base64(&envelope.payload.author_id);
            match project_stmt.execute(rusqlite::params![
                message_id,
                channel_id,
                author_id,
                &envelope.payload.content,
                envelope.payload.created_at_ms as i64
            ]) {
                Ok(_) => processed.push(*event_id),
                Err(e) => warn!("Projection worker failed to insert {:?}: {}", event_id, e),
            }
        }

        match db.execute("COMMIT", []) {
            Ok(_) => {
                let _ = projection.remove_batch(&processed);
            }
            Err(e) => {
                warn!("Projection worker commit failed; leaving {} items queued: {}", processed.len(), e);
                let _ = db.execute("ROLLBACK", []);
            }
        }
    }
}

/// Run sync as the responder (server role)
/// Uses channels and batching for high throughput
async fn run_sync_responder(
    conn: Box<dyn SyncConnection>,
    db_path: &str,
    timeout_secs: u64,
    bytes: Option<Arc<ByteCounters>>,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let recon_only = std::env::var("RECON_ONLY").is_ok();

    info!("Starting negentropy sync (responder) for {} seconds", timeout_secs);

    // Phase 1: Initialize negentropy storage
    let db = open_connection(db_path)?;
    let block_size = neg_block_size();
    let rebuild_threshold = neg_rebuild_threshold(block_size);
    let max_bytes = neg_max_bytes() as u64;
    ensure_negentropy_index(&db, block_size, rebuild_threshold)?;
    let storage = NegentropyStorageSqlite::new(&db, block_size)?;
    let item_count = storage.size().unwrap_or(0);
    info!("Negentropy items: {}", item_count);
    let mut neg = Negentropy::borrowed(&storage, max_bytes)?;

    let store = Store::new(&db);
    let outgoing = OutgoingQueue::new(&db);
    let sent = SentEvents::new(&db);
    let _ = outgoing.clear();
    let _ = sent.clear();

    // Phase 2: Set up channel for incoming events
    let (tx, rx) = mpsc::channel::<(EventId, Vec<u8>)>(event_chan_cap());
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();

    let db_path_owned = db_path.to_string();
    let writer_handle = tokio::task::spawn_blocking(move || {
        batch_writer(db_path_owned, rx, events_received_writer)
    });
    let proj_inline = std::env::var("PROJ_INLINE").is_ok();
    let proj_off = std::env::var("PROJ_OFF").is_ok();
    let proj_stop = if !proj_inline && !proj_off {
        Some(Arc::new(AtomicBool::new(false)))
    } else {
        None
    };
    let proj_handle = if let Some(stop) = proj_stop.clone() {
        let db_path_proj = db_path.to_string();
        Some(tokio::task::spawn_blocking(move || {
            projection_worker(db_path_proj, stop)
        }))
    } else {
        None
    };

    let mut io = start_io(conn);

    // Phase 3: Network I/O loop
    let mut events_sent: u64 = 0;
    let mut rounds = 0;

    'sync_loop: loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }


        // First: drain all pending receives
        loop {
            match tokio::time::timeout(Duration::from_millis(1), io.inbound_rx.recv()).await {
                Ok(Some(msg)) => {
                    if let Some(b) = bytes.as_ref() {
                        b.add_recv(sync_message_len(&msg));
                    }
                    match msg {
                        SyncMessage::NegOpen { msg } | SyncMessage::NegMsg { msg } => {
                            rounds += 1;

                            let response = neg.reconcile(&msg)?;
                            if response.is_empty() {
                                info!("Reconciliation complete in {} rounds", rounds);
                                if recon_only {
                                    info!("Reconcile-only mode: stopping after reconciliation");
                                    break 'sync_loop;
                                }
                            } else {
                                let neg_msg = SyncMessage::NegMsg { msg: response };
                                if let Some(b) = bytes.as_ref() {
                                    b.add_sent(sync_message_len(&neg_msg));
                                }
                                io.ctrl_tx.send(neg_msg).await?;
                            }
                        }
                        SyncMessage::HaveList { ids } => {
                            let mut batch: Vec<EventId> = Vec::with_capacity(ids.len());
                            for id in ids {
                                if sent.insert(&id).unwrap_or(false) {
                                    batch.push(id);
                                }
                            }
                            let _ = outgoing.enqueue_batch(&batch);
                        }
                        SyncMessage::Event { blob } => {
                            let event_id = hash_event(&blob);
                            enqueue_event(&tx, event_id, blob).await;
                        }
                    }
                }
                Ok(None) => {
                    info!("Connection closed by peer");
                    drop(tx);
                    let _ = writer_handle.await;
                    if let Some(stop) = proj_stop.clone() {
                        stop.store(true, Ordering::Relaxed);
                    }
                    if let Some(handle) = proj_handle {
                        let _ = handle.await;
                    }
                    return Ok(SyncStats { events_sent, events_received: events_received.load(Ordering::Relaxed), neg_rounds: rounds });
                }
                Err(_) => break, // Timeout - no more pending
            }
        }

        // Second: send a batch from queue
        let mut sent_this_round = 0;
        let batch = outgoing.dequeue_batch(500).unwrap_or_default();
        let mut sent_ids: Vec<EventId> = Vec::with_capacity(batch.len());
        for id in batch {
            match store.get(&id) {
                Ok(Some(blob)) => {
                    let msg_len = 1 + blob.len();
                    if io.data_tx.send(SyncMessage::Event { blob }).await.is_ok() {
                        if let Some(b) = bytes.as_ref() {
                            b.add_sent(msg_len);
                        }
                        events_sent += 1;
                        sent_ids.push(id);
                        sent_this_round += 1;
                        if sent_this_round >= 500 {
                            break;
                        }
                    }
                }
                Ok(None) => {
                    sent_ids.push(id);
                }
                Err(e) => warn!("Failed to load blob for {:?}: {}", id, e),
            }
        }
        let _ = outgoing.remove_batch(&sent_ids);

        let _ = sent_this_round;
    }

    drop(tx);
    let _ = writer_handle.await;
    if let Some(stop) = proj_stop {
        stop.store(true, Ordering::Relaxed);
    }
    if let Some(handle) = proj_handle {
        let _ = handle.await;
    }
    let stats = SyncStats {
        events_sent,
        events_received: events_received.load(Ordering::Relaxed),
        neg_rounds: rounds,
    };
    info!("Sync stats: {:?}", stats);
    Ok(stats)
}

async fn run_sync_responder_dual(
    ctrl_conn: Box<dyn SyncConnection>,
    data_out_conn: Box<dyn SyncConnection>,
    data_in_conn: Box<dyn SyncConnection>,
    db_path: &str,
    timeout_secs: u64,
    bytes: Option<Arc<ByteCounters>>,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let recon_only = std::env::var("RECON_ONLY").is_ok();

    info!("Starting negentropy sync (responder) for {} seconds", timeout_secs);

    let db = open_connection(db_path)?;
    let block_size = neg_block_size();
    let rebuild_threshold = neg_rebuild_threshold(block_size);
    let max_bytes = neg_max_bytes() as u64;
    ensure_negentropy_index(&db, block_size, rebuild_threshold)?;
    let storage = NegentropyStorageSqlite::new(&db, block_size)?;
    let item_count = storage.size().unwrap_or(0);
    info!("Negentropy items: {}", item_count);
    let mut neg = Negentropy::borrowed(&storage, max_bytes)?;

    let store = Store::new(&db);
    let outgoing = OutgoingQueue::new(&db);
    let sent = SentEvents::new(&db);
    let _ = outgoing.clear();
    let _ = sent.clear();

    let (tx, rx) = mpsc::channel::<(EventId, Vec<u8>)>(event_chan_cap());
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();

    let db_path_owned = db_path.to_string();
    let writer_handle = tokio::task::spawn_blocking(move || {
        batch_writer(db_path_owned, rx, events_received_writer)
    });
    let proj_inline = std::env::var("PROJ_INLINE").is_ok();
    let proj_off = std::env::var("PROJ_OFF").is_ok();
    let proj_stop = if !proj_inline && !proj_off {
        Some(Arc::new(AtomicBool::new(false)))
    } else {
        None
    };
    let proj_handle = if let Some(stop) = proj_stop.clone() {
        let db_path_proj = db_path.to_string();
        Some(tokio::task::spawn_blocking(move || {
            projection_worker(db_path_proj, stop)
        }))
    } else {
        None
    };

    let mut ctrl_io = start_ctrl_io(ctrl_conn);
    let (data_tx, _data_send_handle) = start_data_sender(data_out_conn);
    let (mut data_rx, _data_recv_handle) = start_data_receiver(data_in_conn);

    let mut events_sent: u64 = 0;
    let mut rounds = 0;

    'sync_loop: loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }

        loop {
            let recv_fut = async {
                tokio::select! {
                    msg = ctrl_io.rx.recv() => msg,
                    msg = data_rx.recv() => msg,
                }
            };
            match tokio::time::timeout(Duration::from_millis(1), recv_fut).await {
                Ok(Some(msg)) => {
                    if let Some(b) = bytes.as_ref() {
                        b.add_recv(sync_message_len(&msg));
                    }
                    match msg {
                        SyncMessage::NegOpen { msg } | SyncMessage::NegMsg { msg } => {
                            rounds += 1;

                            let response = neg.reconcile(&msg)?;
                            if response.is_empty() {
                                info!("Reconciliation complete in {} rounds", rounds);
                                if recon_only {
                                    info!("Reconcile-only mode: stopping after reconciliation");
                                    break 'sync_loop;
                                }
                            } else {
                                let neg_msg = SyncMessage::NegMsg { msg: response };
                                if let Some(b) = bytes.as_ref() {
                                    b.add_sent(sync_message_len(&neg_msg));
                                }
                                ctrl_io.tx.send(neg_msg).await?;
                            }
                        }
                        SyncMessage::HaveList { ids } => {
                            let mut batch: Vec<EventId> = Vec::with_capacity(ids.len());
                            for id in ids {
                                if sent.insert(&id).unwrap_or(false) {
                                    batch.push(id);
                                }
                            }
                            let _ = outgoing.enqueue_batch(&batch);
                        }
                        SyncMessage::Event { blob } => {
                            let event_id = hash_event(&blob);
                            enqueue_event(&tx, event_id, blob).await;
                        }
                        _ => {}
                    }
                }
                Ok(None) => {
                    info!("Connection closed by peer");
                    drop(tx);
                    let _ = writer_handle.await;
                    if let Some(stop) = proj_stop.clone() {
                        stop.store(true, Ordering::Relaxed);
                    }
                    if let Some(handle) = proj_handle {
                        let _ = handle.await;
                    }
                    return Ok(SyncStats { events_sent, events_received: events_received.load(Ordering::Relaxed), neg_rounds: rounds });
                }
                Err(_) => break,
            }
        }

        let mut sent_this_round = 0;
        let batch = outgoing.dequeue_batch(500).unwrap_or_default();
        let mut sent_ids: Vec<EventId> = Vec::with_capacity(batch.len());
        for id in batch {
            match store.get(&id) {
                Ok(Some(blob)) => {
                    let msg_len = 1 + blob.len();
                    if data_tx.send(SyncMessage::Event { blob }).await.is_ok() {
                        if let Some(b) = bytes.as_ref() {
                            b.add_sent(msg_len);
                        }
                        events_sent += 1;
                        sent_ids.push(id);
                        sent_this_round += 1;
                        if sent_this_round >= 500 {
                            break;
                        }
                    }
                }
                Ok(None) => {
                    sent_ids.push(id);
                }
                Err(e) => warn!("Failed to load blob for {:?}: {}", id, e),
            }
        }
        let _ = outgoing.remove_batch(&sent_ids);

        let _ = sent_this_round;
    }

    drop(tx);
    let _ = writer_handle.await;
    if let Some(stop) = proj_stop {
        stop.store(true, Ordering::Relaxed);
    }
    if let Some(handle) = proj_handle {
        let _ = handle.await;
    }
    let stats = SyncStats {
        events_sent,
        events_received: events_received.load(Ordering::Relaxed),
        neg_rounds: rounds,
    };
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
    let block_size = neg_block_size();
    let mut neg_inserter = NegentropyBatchInserter::new(&db, block_size)?;

    // Prepare projection statement
    let mut project_stmt = db.prepare(
        "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)"
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

        store.put(&event_id, &blob)?;
        shareable.insert(&event_id)?;
        neg_inserter.insert(envelope.header.created_at_ms, &event_id)?;

        // Project inline
        let message_id = event_id_to_base64(&event_id);
        let channel_id_b64 = event_id_to_base64(&channel_id);
        let author_id_b64 = event_id_to_base64(&author_id);
        project_stmt.execute(rusqlite::params![
            message_id,
            channel_id_b64,
            author_id_b64,
            content,
            envelope.payload.created_at_ms as i64
        ])?;
    }

    neg_inserter.finish()?;

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

    println!("Database: {}", db_path);
    println!("  Store:     {} events", store_count);
    println!("  Shareable: {} events", shareable_count);
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
            if let Err(e) = run_server(bind, "demo_server.db", server_timeout, None).await {
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
            if let Err(e) = run_client(remote, "demo_client.db", client_timeout, None).await {
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
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    info!("=== Simulated Sync Demo ===");
    info!(
        "Generating {} events per peer, latency {} ms, bandwidth {} KiB/s, timeout {} seconds",
        events_per_peer, latency_ms, bandwidth_kib, timeout_secs
    );

    // Clean up old databases
    let _ = std::fs::remove_file("sim_server.db");
    let _ = std::fs::remove_file("sim_server.db-shm");
    let _ = std::fs::remove_file("sim_server.db-wal");
    let _ = std::fs::remove_file("sim_client.db");
    let _ = std::fs::remove_file("sim_client.db-shm");
    let _ = std::fs::remove_file("sim_client.db-wal");

    info!("Generating events for server...");
    generate_events("sim_server.db", events_per_peer, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")?;

    info!("Generating events for client...");
    generate_events("sim_client.db", events_per_peer, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")?;

    let bandwidth_bytes = bandwidth_kib.saturating_mul(1024);
    let config = SimConfig {
        latency_ms,
        bandwidth_bytes_per_sec: bandwidth_bytes.max(1),
    };

    let (server_ctrl, client_ctrl) = create_sim_pair(config);
    // One-way data links to avoid full-duplex contention in the simulator
    let (client_data_out, server_data_in) = create_sim_pair(config);
    let (server_data_out, client_data_in) = create_sim_pair(config);

    reset_negentropy_profile();
    negentropy::reset_negentropy_algo_profile();
    let bytes = Arc::new(ByteCounters::default());
    let bytes_task = bytes.clone();
    let rss_max = Arc::new(AtomicU64::new(0));
    let rss_max_task = rss_max.clone();
    let start = std::time::Instant::now();
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let (mem_tx, mut mem_rx) = tokio::sync::oneshot::channel::<()>();
            let mem_task = tokio::task::spawn_local(async move {
                let mut interval = tokio::time::interval(Duration::from_millis(MEM_SAMPLE_MS));
                loop {
                    tokio::select! {
                        _ = &mut mem_rx => break,
                        _ = interval.tick() => {
                            if let Some(rss) = read_rss_bytes() {
                                update_max_rss(&rss_max_task, rss);
                            }
                        }
                    }
                }
            });

            let bytes_server = bytes_task.clone();
            let bytes_client = bytes_task.clone();

            let server_task = tokio::task::spawn_local(async move {
                let ctrl: SimConnection = server_ctrl;
                let data_out: SimConnection = server_data_out;
                let data_in: SimConnection = server_data_in;
                if let Err(e) = run_sync_responder_dual(
                    Box::new(ctrl),
                    Box::new(data_out),
                    Box::new(data_in),
                    "sim_server.db",
                    timeout_secs,
                    Some(bytes_server),
                )
                .await {
                    error!("Sim server error: {}", e);
                }
            });

            let client_task = tokio::task::spawn_local(async move {
                let ctrl: SimConnection = client_ctrl;
                let data_out: SimConnection = client_data_out;
                let data_in: SimConnection = client_data_in;
                if let Err(e) = run_sync_initiator_dual(
                    Box::new(ctrl),
                    Box::new(data_out),
                    Box::new(data_in),
                    "sim_client.db",
                    timeout_secs,
                    Some(bytes_client),
                )
                .await {
                    error!("Sim client error: {}", e);
                }
            });

            let _ = tokio::join!(server_task, client_task);
            let _ = mem_tx.send(());
            let _ = mem_task.await;
        })
        .await;

    let elapsed = start.elapsed();
    let (bytes_sent, bytes_recv) = bytes.snapshot();
    let total_mb = (bytes_sent as f64) / (1024.0 * 1024.0);
    let mb_per_sec = if elapsed.as_secs_f64() > 0.0 {
        total_mb / elapsed.as_secs_f64()
    } else {
        0.0
    };
    info!(
        "Sim throughput: {:.2} MB/s over {:.2}s (sent={} bytes, recv={} bytes)",
        mb_per_sec,
        elapsed.as_secs_f64(),
        bytes_sent,
        bytes_recv
    );
    let rss_max_bytes = rss_max.load(Ordering::Relaxed);
    if rss_max_bytes > 0 {
        info!("Sim max RSS: {:.2} MB", (rss_max_bytes as f64) / (1024.0 * 1024.0));
    }

    log_negentropy_profile("sim");
    negentropy::log_negentropy_algo_profile("sim");

    info!("=== Sim Demo Complete ===");

    println!("\nServer database:");
    show_stats("sim_server.db")?;

    println!("\nClient database:");
    show_stats("sim_client.db")?;

    let server_db = open_connection("sim_server.db")?;
    let client_db = open_connection("sim_client.db")?;

    let server_store: i64 = server_db.query_row("SELECT COUNT(*) FROM store", [], |row| row.get(0))?;
    let client_store: i64 = client_db.query_row("SELECT COUNT(*) FROM store", [], |row| row.get(0))?;

    println!("\n=== Sim Sync Verification ===");
    println!("Server has {} events, Client has {} events", server_store, client_store);

    let expected = events_per_peer * 2;
    if server_store >= expected as i64 && client_store >= expected as i64 {
        println!("SUCCESS: Both peers have all {} events!", expected);
    } else {
        println!("Sync incomplete - expected {} events each", expected);
    }

    Ok(())
}
