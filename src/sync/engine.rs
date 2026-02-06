use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use negentropy::{Negentropy, Id, NegentropyStorageBase, Storage};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn, error};

use crate::crypto::{hash_event, event_id_to_base64, EventId};
use crate::db::{open_connection, schema::create_tables, shareable::Shareable, store::Store, outgoing::OutgoingQueue, wanted::WantedEvents};
use crate::runtime::SyncStats;
use crate::sync::{SyncMessage, neg_id_to_event_id, NegentropyStorageSqlite};
use crate::transport::{
    DualConnection,
    StreamConn,
    StreamRecv,
    StreamSend,
};
use crate::transport::connection::ConnectionError;
use crate::wire::Envelope;

/// Batch writer task - drains channel and writes to SQLite in batches.
/// Naive projection: receive batches -> BEGIN -> store.put + shareable.insert
/// + wanted.remove + neg_items + messages -> COMMIT.
pub fn batch_writer(
    db_path: String,
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

    let store = Store::new(&db);
    let shareable = Shareable::new(&db);
    let wanted = WantedEvents::new(&db);

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
            for (event_id, blob) in &batch {
                let _ = store.put(event_id, blob);
                let _ = shareable.insert(event_id);
                let _ = wanted.remove(event_id);

                if let Ok((_, envelope)) = Envelope::parse(blob) {
                    let created_at_ms = envelope.payload.created_at_ms;

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

        events_received.fetch_add(batch.len() as u64, Ordering::Relaxed);
    }
}

pub fn spawn_data_receiver<R>(
    mut data_recv: R,
    ingest_tx: mpsc::Sender<(EventId, Vec<u8>)>,
    bytes_received: Arc<AtomicU64>,
) -> (oneshot::Sender<()>, tokio::task::JoinHandle<()>)
where
    R: StreamRecv + Send + 'static,
{
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
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

    (shutdown_tx, handle)
}

/// Run sync as the initiator (client role) with dual streams.
/// Control stream: NegOpen, NegMsg, HaveList
/// Data stream: Event blobs
pub async fn run_sync_initiator_dual<C, S, R>(
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

    let ingest_cap = if std::env::var("LOW_MEM").is_ok() { 1000 } else { 5000 };
    let (ingest_tx, ingest_rx) = mpsc::channel::<(EventId, Vec<u8>)>(ingest_cap);
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();
    let bytes_received = Arc::new(AtomicU64::new(0));

    let db_path_owned = db_path.to_string();
    let writer_handle =
        tokio::task::spawn_blocking(move || batch_writer(db_path_owned, ingest_rx, events_received_writer));

    let mut have_ids: Vec<Id> = Vec::new();
    let mut need_ids: Vec<Id> = Vec::new();
    let mut events_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let (shutdown_tx, recv_handle) =
        spawn_data_receiver(data_recv, ingest_tx, bytes_received.clone());

    let initial_msg = neg.initiate()?;
    control.send(&SyncMessage::NegOpen { msg: initial_msg }).await?;
    control.flush().await?;

    let mut reconciliation_done = false;
    let mut rounds = 0;
    const HAVE_CHUNK: usize = 1000;
    const NEED_CHUNK: usize = 1000;

    let mut completed = false;
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

        let received = events_received.load(Ordering::Relaxed);
        let _ = received; // suppress unused warning
        if reconciliation_done {
            let pending_out = outgoing.count_pending(peer_id).unwrap_or(0);
            let pending_in = wanted.count().unwrap_or(0);
            if pending_out == 0 && pending_in == 0 {
                info!("Sync complete: sent {}, received {}", events_sent, events_received.load(Ordering::Relaxed));
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
    let _ = shutdown_tx.send(());
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

/// Run sync as the responder (server role) with dual streams.
pub async fn run_sync_responder_dual<C, S, R>(
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

    let ingest_cap = if std::env::var("LOW_MEM").is_ok() { 1000 } else { 5000 };
    let (ingest_tx, ingest_rx) = mpsc::channel::<(EventId, Vec<u8>)>(ingest_cap);
    let events_received = Arc::new(AtomicU64::new(0));
    let events_received_writer = events_received.clone();
    let bytes_received = Arc::new(AtomicU64::new(0));

    let db_path_owned = db_path.to_string();
    let writer_handle =
        tokio::task::spawn_blocking(move || batch_writer(db_path_owned, ingest_rx, events_received_writer));

    let (shutdown_tx, recv_handle) =
        spawn_data_receiver(data_recv, ingest_tx, bytes_received.clone());

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
                if ids.is_empty() {
                    continue;
                }
                idle_count = 0;
                reconciliation_done = true;

                let _ = outgoing.enqueue_batch(peer_id, &ids);
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
    let _ = neg_db.execute("COMMIT", []);
    let _ = shutdown_tx.send(());
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

/// Run continuous sync sessions between two peers over a persistent QUIC connection.
///
/// Both peers are equal. Each session is a complete negentropy reconciliation
/// from a fresh DB snapshot. Sessions are strictly serialized.
pub async fn sync_loop(
    listener_db: String,
    connector_db: String,
    listener_endpoint: quinn::Endpoint,
    connector_endpoint: quinn::Endpoint,
    listener_addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Ensure both DBs are initialized
    {
        let db = open_connection(&listener_db)?;
        create_tables(&db)?;
    }
    {
        let db = open_connection(&connector_db)?;
        create_tables(&db)?;
    }

    // Connect and accept must happen concurrently (handshake requires both sides)
    let connect_fut = connector_endpoint.connect(listener_addr, "localhost")?;
    let (connection, listener_connection) = tokio::try_join!(
        async {
            connect_fut.await.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
        },
        async {
            let incoming = listener_endpoint.accept().await
                .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> { "No connection".into() })?;
            incoming.await.map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
        },
    )?;
    info!("QUIC connection established");

    let peer_id_connector = "connector";
    let peer_id_listener = "listener";

    // Loop: run repeated sync sessions
    loop {
        // Connector opens streams and sends markers first (QUIC streams are lazy -
        // they only materialize on the receiver when data is sent)
        let (ctrl_send_c, ctrl_recv_c) = connection.open_bi().await?;
        let (data_send_c, data_recv_c) = connection.open_bi().await?;
        let mut conn_initiator = DualConnection::new(ctrl_send_c, ctrl_recv_c, data_send_c, data_recv_c);

        // Send markers to materialize streams on the listener side
        conn_initiator.control.send(&SyncMessage::HaveList { ids: vec![] }).await?;
        conn_initiator.data_send.send(&SyncMessage::HaveList { ids: vec![] }).await?;
        conn_initiator.flush_control().await?;
        conn_initiator.flush_data().await?;

        // Now listener can accept the materialized streams
        let (ctrl_send_l, ctrl_recv_l) = listener_connection.accept_bi().await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
        let (data_send_l, data_recv_l) = listener_connection.accept_bi().await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
        let conn_responder = DualConnection::new(ctrl_send_l, ctrl_recv_l, data_send_l, data_recv_l);

        // Run one complete sync session: initiator + responder in parallel
        let connector_db_clone = connector_db.clone();
        let listener_db_clone = listener_db.clone();

        let (init_res, resp_res) = tokio::join!(
            run_sync_initiator_dual(conn_initiator, &connector_db_clone, 60, peer_id_listener),
            run_sync_responder_dual(conn_responder, &listener_db_clone, 60, peer_id_connector),
        );

        if let Err(e) = &init_res {
            warn!("Initiator session error: {}", e);
        }
        if let Err(e) = &resp_res {
            warn!("Responder session error: {}", e);
        }

        // Sleep before next session
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
