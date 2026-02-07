// Peer authentication: peer_id is the hex-encoded SPKI fingerprint from
// the peer's TLS certificate, verified via PinnedCertVerifier during handshake.
//
// Shutdown protocol (prevents data loss under cross-stream reordering):
// 1. Each side sends DataDone on the data stream after flushing all events.
// 2. Initiator sends Done on control after its DataDone.
// 3. Responder receives Done, finishes sending, sends DataDone on data,
//    waits for initiator's DataDone to be consumed, then sends DoneAck.
// 4. Initiator receives DoneAck, waits for responder's DataDone, exits.
// Both sides gate exit on data-plane drain confirmation, not just control.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use negentropy::{Negentropy, Id, NegentropyStorageBase, Storage};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn, error};

use crate::crypto::{hash_event, event_id_to_base64, EventId};
use crate::db::{open_connection, schema::create_tables, store::Store, outgoing::OutgoingQueue, wanted::WantedEvents};
use crate::events::{self, registry, ShareScope};
use crate::projection::pipeline::project_one;
use crate::runtime::SyncStats;
use crate::sync::{SyncMessage, neg_id_to_event_id, NegentropyStorageSqlite};
use crate::transport::{
    DualConnection,
    StreamConn,
    StreamRecv,
    StreamSend,
    peer_identity_from_connection,
};
use crate::transport::connection::ConnectionError;

fn low_mem_mode() -> bool {
    read_bool_env("LOW_MEM_IOS") || read_bool_env("LOW_MEM")
}

fn read_bool_env(name: &str) -> bool {
    match std::env::var(name) {
        Ok(v) => v != "0" && v.to_lowercase() != "false",
        Err(_) => false,
    }
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Batch writer task - drains channel and writes to SQLite in batches.
/// Writes event blob/neg_items/recorded_events, then delegates projection
/// to `project_one` which handles deps, terminal state, and cascading.
pub fn batch_writer(
    db_path: String,
    recorded_by: String,
    mut rx: mpsc::Receiver<(EventId, Vec<u8>)>,
    events_received: Arc<AtomicU64>,
) {
    let db = match open_connection(&db_path) {
        Ok(db) => db,
        Err(e) => {
            error!("Writer failed to open db: {}", e);
            return;
        }
    };

    let wanted = WantedEvents::new(&db);

    let mut neg_items_stmt = match db.prepare(
        "INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)"
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare neg_items statement: {}", e);
            return;
        }
    };

    let mut recorded_stmt = match db.prepare(
        "INSERT OR IGNORE INTO recorded_events (peer_id, event_id, recorded_at, source)
         VALUES (?1, ?2, ?3, ?4)"
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare recorded_events statement: {}", e);
            return;
        }
    };

    let mut events_stmt = match db.prepare(
        "INSERT OR IGNORE INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)"
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare events statement: {}", e);
            return;
        }
    };

    let reg = registry();

    loop {
        let first = match rx.blocking_recv() {
            Some(item) => item,
            None => break,
        };

        let mut batch = vec![first];
        while let Ok(item) = rx.try_recv() {
            batch.push(item);
            if batch.len() >= 1000 {
                break;
            }
        }

        if db.execute("BEGIN", []).is_ok() {
            // First pass: write blob storage, neg_items, recorded_events
            let mut event_ids_to_project: Vec<EventId> = Vec::with_capacity(batch.len());
            let mut event_ids_to_remove: Vec<EventId> = Vec::with_capacity(batch.len());
            for (event_id, blob) in &batch {
                event_ids_to_remove.push(*event_id);

                let event_id_b64 = event_id_to_base64(event_id);

                if let Some(created_at_ms) = events::extract_created_at_ms(blob) {
                    if let Some(type_code) = events::extract_event_type(blob) {
                        if let Some(meta) = reg.lookup(type_code) {
                            // Only insert into neg_items for shared events (defense-in-depth)
                            if meta.share_scope == ShareScope::Shared {
                                if let Err(e) = neg_items_stmt.execute(rusqlite::params![
                                    created_at_ms as i64,
                                    event_id.as_slice()
                                ]) {
                                    warn!("neg_items insert error for {}: {}", event_id_b64, e);
                                    continue;
                                }
                            }

                            if let Err(e) = events_stmt.execute(rusqlite::params![
                                &event_id_b64,
                                meta.type_name,
                                blob.as_slice(),
                                meta.share_scope.as_str(),
                                created_at_ms as i64,
                                current_timestamp_ms()
                            ]) {
                                warn!("events insert error for {}: {}", event_id_b64, e);
                                continue;
                            }

                            let recorded_at = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as i64;
                            if let Err(e) = recorded_stmt.execute(rusqlite::params![
                                &recorded_by,
                                &event_id_b64,
                                recorded_at,
                                "quic_recv"
                            ]) {
                                warn!("recorded_events insert error for {}: {}", event_id_b64, e);
                                continue;
                            }

                            event_ids_to_project.push(*event_id);
                        }
                    }
                }
            }
            match db.execute("COMMIT", []) {
                Ok(_) => {
                    // Remove from wanted only after durable commit
                    for event_id in &event_ids_to_remove {
                        let _ = wanted.remove(event_id);
                    }

                    // Second pass: project each event (handles deps + cascade)
                    for event_id in &event_ids_to_project {
                        if let Err(e) = project_one(&db, &recorded_by, event_id) {
                            warn!("projection error for {}: {}", event_id_to_base64(event_id), e);
                        }
                    }
                }
                Err(e) => {
                    warn!("COMMIT failed: {}", e);
                    continue; // retry in next batch
                }
            }
        }

        events_received.fetch_add(batch.len() as u64, Ordering::Relaxed);
    }
}

/// Spawn data receiver task. Returns:
/// - `shutdown_tx`: forced shutdown (timeout fallback only)
/// - `data_drained_rx`: signals when peer's DataDone marker is received (all data consumed)
/// - `JoinHandle`: task handle
pub fn spawn_data_receiver<R>(
    mut data_recv: R,
    ingest_tx: mpsc::Sender<(EventId, Vec<u8>)>,
    bytes_received: Arc<AtomicU64>,
) -> (oneshot::Sender<()>, oneshot::Receiver<()>, tokio::task::JoinHandle<()>)
where
    R: StreamRecv + Send + 'static,
{
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let (data_done_tx, data_done_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let mut data_done_tx = Some(data_done_tx);
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                msg = data_recv.recv() => {
                    match msg {
                        Ok(SyncMessage::Event { blob }) => {
                            bytes_received.fetch_add(blob.len() as u64, Ordering::Relaxed);
                            let event_id = hash_event(&blob);
                            if ingest_tx.send((event_id, blob)).await.is_err() {
                                warn!("Ingest channel closed");
                                break;
                            }
                        }
                        Ok(SyncMessage::DataDone) => {
                            info!("Received DataDone from peer — all data consumed");
                            if let Some(tx) = data_done_tx.take() {
                                let _ = tx.send(());
                            }
                            break;
                        }
                        Ok(_) => {}
                        Err(ConnectionError::Closed) => {
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

    (shutdown_tx, data_done_rx, handle)
}

/// Run sync as the initiator (client role) with dual streams.
/// Control stream: NegOpen, NegMsg, HaveList
/// Data stream: Event blobs
pub async fn run_sync_initiator_dual<C, S, R>(
    conn: DualConnection<C, S, R>,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
    recorded_by: &str,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>>
where
    C: StreamConn,
    S: StreamSend,
    R: StreamRecv + Send + 'static,
{
    let DualConnection {
        mut control,
        mut data_send,
        data_recv,
    } = conn;
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    info!("Starting negentropy sync (initiator, dual-stream) for {} seconds", timeout_secs);

    let db = open_connection(db_path)?;
    let neg_db = open_connection(db_path)?;

    let outgoing = OutgoingQueue::new(&db);
    let wanted = WantedEvents::new(&db);
    let _ = outgoing.clear_peer(peer_id);
    let _ = wanted.clear();

    let neg_storage = NegentropyStorageSqlite::new(&neg_db);
    neg_storage.rebuild_blocks().map_err(|e| format!("Failed to rebuild blocks: {}", e))?;

    neg_db.execute("BEGIN", []).map_err(|e| format!("Failed to begin snapshot: {}", e))?;

    let item_count = neg_storage.size().map_err(|e| format!("Failed to get size: {:?}", e))?;
    info!("Loaded {} items for negentropy (SQLite-backed)", item_count);

    let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), 64 * 1024)?;

    let store = Store::new(&db);
    let reg = registry();

    let ingest_cap = if low_mem_mode() { 1000 } else { 5000 };
    let (ingest_tx, ingest_rx) = mpsc::channel::<(EventId, Vec<u8>)>(ingest_cap);
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();
    let bytes_received = Arc::new(AtomicU64::new(0));

    let db_path_owned = db_path.to_string();
    let recorded_by_owned = recorded_by.to_string();
    let writer_handle =
        tokio::task::spawn_blocking(move || batch_writer(db_path_owned, recorded_by_owned, ingest_rx, events_received_writer));

    let mut have_ids: Vec<Id> = Vec::new();
    let mut need_ids: Vec<Id> = Vec::new();
    let mut events_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let (shutdown_tx, data_drained_rx, recv_handle) =
        spawn_data_receiver(data_recv, ingest_tx.clone(), bytes_received.clone());

    let initial_msg = neg.initiate()?;
    control.send(&SyncMessage::NegOpen { msg: initial_msg }).await?;
    control.flush().await?;

    let mut reconciliation_done = false;
    let mut rounds = 0;
    const HAVE_CHUNK: usize = 1000;
    const NEED_CHUNK: usize = 1000;

    let mut completed = false;
    let mut done_sent = false;
    let sync_start = Instant::now();

    loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }

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
            Ok(Ok(SyncMessage::DoneAck)) => {
                info!("Received DoneAck from responder");
                completed = true;
                break;
            }
            Ok(Ok(_)) => {}
            Ok(Err(ConnectionError::Closed)) => {
                info!("Control stream closed by peer");
                break;
            }
            Ok(Err(e)) => {
                warn!("Control stream error: {}", e);
                break;
            }
            Err(_) => {}
        }

        // Stream events from DB queue on data stream
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
                    // Defense-in-depth: skip local-only events
                    if let Some(type_code) = events::extract_event_type(&blob) {
                        if let Some(meta) = reg.lookup(type_code) {
                            if meta.share_scope == ShareScope::Local {
                                sent_rowids.push(rowid);
                                continue;
                            }
                        }
                    }
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
        }

        // Once reconciliation is done and outgoing queue is drained,
        // send DataDone on data stream then Done on control.
        if reconciliation_done && !done_sent {
            let pending_out = outgoing.count_pending(peer_id).unwrap_or(0);
            if pending_out == 0 {
                let _ = data_send.flush().await;
                data_send.send(&SyncMessage::DataDone).await?;
                data_send.flush().await?;
                control.send(&SyncMessage::Done).await?;
                control.flush().await?;
                done_sent = true;
                info!("Sent DataDone+Done, waiting for DoneAck (sent {}, received {})",
                    events_sent, events_received.load(Ordering::Relaxed));
            }
        }
    }

    if completed {
        let _ = outgoing.clear_peer(peer_id);
        let _ = wanted.clear();
    }
    let _ = neg_db.execute("COMMIT", []);

    // Wait for inbound data drain: data receiver exits on peer's DataDone.
    // Use timeout fallback to avoid hanging if peer misbehaves.
    if completed {
        let drain_timeout = Duration::from_secs(5);
        match tokio::time::timeout(drain_timeout, data_drained_rx).await {
            Ok(Ok(())) => info!("Inbound data fully drained"),
            Ok(Err(_)) => info!("Data drain channel dropped (receiver already exited)"),
            Err(_) => warn!("Timed out waiting for inbound data drain"),
        }
    }
    let _ = shutdown_tx.send(());
    let _ = recv_handle.await;
    // Drop ingest_tx so batch_writer sees channel close and drains
    drop(ingest_tx);
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

/// Run sync as the responder (server role) with dual streams.
pub async fn run_sync_responder_dual<C, S, R>(
    conn: DualConnection<C, S, R>,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
    recorded_by: &str,
) -> Result<SyncStats, Box<dyn std::error::Error + Send + Sync>>
where
    C: StreamConn,
    S: StreamSend,
    R: StreamRecv + Send + 'static,
{
    let DualConnection {
        mut control,
        mut data_send,
        data_recv,
    } = conn;
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    info!("Starting negentropy sync (responder, dual-stream) for {} seconds", timeout_secs);

    let db = open_connection(db_path)?;
    let neg_db = open_connection(db_path)?;

    let outgoing = OutgoingQueue::new(&db);
    let _ = outgoing.clear_peer(peer_id);

    let neg_storage = NegentropyStorageSqlite::new(&neg_db);
    neg_storage.rebuild_blocks().map_err(|e| format!("Failed to rebuild blocks: {}", e))?;

    neg_db.execute("BEGIN", []).map_err(|e| format!("Failed to begin snapshot: {}", e))?;

    let item_count = neg_storage.size().map_err(|e| format!("Failed to get size: {:?}", e))?;
    info!("Loaded {} items for negentropy (SQLite-backed)", item_count);

    let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), 64 * 1024)?;

    let store = Store::new(&db);
    let reg = registry();

    let ingest_cap = if low_mem_mode() { 1000 } else { 5000 };
    let (ingest_tx, ingest_rx) = mpsc::channel::<(EventId, Vec<u8>)>(ingest_cap);
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();
    let bytes_received = Arc::new(AtomicU64::new(0));

    let db_path_owned = db_path.to_string();
    let recorded_by_owned = recorded_by.to_string();
    let writer_handle =
        tokio::task::spawn_blocking(move || batch_writer(db_path_owned, recorded_by_owned, ingest_rx, events_received_writer));

    let (shutdown_tx, data_drained_rx, recv_handle) =
        spawn_data_receiver(data_recv, ingest_tx.clone(), bytes_received.clone());

    let mut events_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let mut rounds = 0;
    let mut peer_done = false;
    let mut completed = false;
    let sync_start = Instant::now();

    loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }

        match tokio::time::timeout(Duration::from_millis(1), control.recv()).await {
            Ok(Ok(SyncMessage::NegOpen { msg })) | Ok(Ok(SyncMessage::NegMsg { msg })) => {
                rounds += 1;

                let response = neg.reconcile(&msg)?;
                if response.is_empty() {
                    info!("Reconciliation complete in {} rounds", rounds);
                } else {
                    control.send(&SyncMessage::NegMsg { msg: response }).await?;
                    control.flush().await?;
                }
            }
            Ok(Ok(SyncMessage::HaveList { ids })) => {
                if ids.is_empty() {
                    continue;
                }

                let _ = outgoing.enqueue_batch(peer_id, &ids);
            }
            Ok(Ok(SyncMessage::Done)) => {
                info!("Received Done from initiator");
                peer_done = true;
            }
            Ok(Ok(_)) => {}
            Ok(Err(ConnectionError::Closed)) => {
                info!("Control stream closed by peer");
                break;
            }
            Ok(Err(e)) => {
                warn!("Control stream error: {}", e);
                break;
            }
            Err(_) => {}
        }

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
                    // Defense-in-depth: skip local-only events
                    if let Some(type_code) = events::extract_event_type(&blob) {
                        if let Some(meta) = reg.lookup(type_code) {
                            if meta.share_scope == ShareScope::Local {
                                sent_rowids.push(rowid);
                                continue;
                            }
                        }
                    }
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
        }

        // After peer signalled Done and our outgoing queue is drained:
        // 1. Send DataDone on data stream (signals peer's data receiver)
        // 2. Wait for peer's DataDone to be consumed by our data receiver
        // 3. Only then send DoneAck on control
        if peer_done {
            let pending_out = outgoing.count_pending(peer_id).unwrap_or(0);
            if pending_out == 0 {
                // Signal peer's data receiver that we're done sending events
                let _ = data_send.flush().await;
                data_send.send(&SyncMessage::DataDone).await?;
                data_send.flush().await?;

                // Wait for our data receiver to confirm peer's DataDone
                let drain_timeout = Duration::from_secs(5);
                match tokio::time::timeout(drain_timeout, data_drained_rx).await {
                    Ok(Ok(())) => info!("Inbound data fully drained"),
                    Ok(Err(_)) => info!("Data drain channel dropped (receiver already exited)"),
                    Err(_) => warn!("Timed out waiting for inbound data drain"),
                }

                control.send(&SyncMessage::DoneAck).await?;
                control.flush().await?;
                info!("Sent DoneAck (sent {}, received {})",
                    events_sent, events_received.load(Ordering::Relaxed));
                completed = true;
                break;
            }
        }
    }

    if completed {
        let _ = outgoing.clear_peer(peer_id);
    }
    let _ = neg_db.execute("COMMIT", []);
    let _ = shutdown_tx.send(());
    let _ = recv_handle.await;
    // Drop ingest_tx so batch_writer sees channel close and drains
    drop(ingest_tx);
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

/// Accept incoming connections and run responder sync sessions.
///
/// Outer loop reconnects on connection drop. Inner loop runs repeated
/// sync sessions on the same connection.
pub async fn accept_loop(
    db_path: &str,
    recorded_by: &str,
    endpoint: quinn::Endpoint,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    loop {
        info!("Waiting for incoming connection...");
        let incoming = match endpoint.accept().await {
            Some(inc) => inc,
            None => {
                info!("Endpoint closed, stopping accept_loop");
                return Ok(());
            }
        };
        let connection = match incoming.await {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to accept connection: {}", e);
                continue;
            }
        };
        let peer_id = match peer_identity_from_connection(&connection) {
            Some(id) => id,
            None => {
                warn!("Rejected connection: could not extract peer identity");
                continue;
            }
        };
        info!("Accepted connection from {}", peer_id);

        // Inner loop: repeated sync sessions on this connection
        loop {
            let (ctrl_send, ctrl_recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(e) => {
                    info!("Connection dropped (control accept): {}", e);
                    break;
                }
            };
            let (data_send, data_recv) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(e) => {
                    info!("Connection dropped (data accept): {}", e);
                    break;
                }
            };
            let conn = DualConnection::new(ctrl_send, ctrl_recv, data_send, data_recv);

            if let Err(e) = run_sync_responder_dual(conn, db_path, 60, &peer_id, recorded_by).await {
                warn!("Responder session error: {}", e);
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

/// Connect to a remote peer and run initiator sync sessions.
///
/// Outer loop reconnects on connection drop. Inner loop runs repeated
/// sync sessions on the same connection.
pub async fn connect_loop(
    db_path: &str,
    recorded_by: &str,
    endpoint: quinn::Endpoint,
    remote: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    loop {
        info!("Connecting to {}...", remote);
        let connection = match endpoint.connect(remote, "localhost") {
            Ok(connecting) => match connecting.await {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to connect to {}: {}", remote, e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            },
            Err(e) => {
                warn!("Failed to initiate connection to {}: {}", remote, e);
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let peer_id = match peer_identity_from_connection(&connection) {
            Some(id) => id,
            None => {
                warn!("Could not extract peer identity, retrying...");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        info!("Connected to {}", peer_id);

        // Inner loop: repeated sync sessions on this connection
        loop {
            let (ctrl_send, ctrl_recv) = match connection.open_bi().await {
                Ok(streams) => streams,
                Err(e) => {
                    info!("Connection dropped (control open): {}", e);
                    break;
                }
            };
            let (data_send, data_recv) = match connection.open_bi().await {
                Ok(streams) => streams,
                Err(e) => {
                    info!("Connection dropped (data open): {}", e);
                    break;
                }
            };
            let mut conn = DualConnection::new(ctrl_send, ctrl_recv, data_send, data_recv);

            // Send markers to materialize lazy QUIC streams on the receiver
            conn.control.send(&SyncMessage::HaveList { ids: vec![] }).await?;
            conn.data_send.send(&SyncMessage::HaveList { ids: vec![] }).await?;
            conn.flush_control().await?;
            conn.flush_data().await?;

            if let Err(e) = run_sync_initiator_dual(conn, db_path, 60, &peer_id, recorded_by).await {
                warn!("Initiator session error: {}", e);
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}
