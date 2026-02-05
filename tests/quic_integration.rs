//! QUIC Integration Tests
//!
//! Tests the full sync flow over real QUIC transport (localhost).
//! Run with: cargo test --release quic_ -- --nocapture

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use poc_7::crypto::{hash_event, event_id_to_base64};
use poc_7::db::{open_connection, schema::create_tables, shareable::Shareable, store::Store};
use poc_7::wire::Envelope;

/// Generate test events in a database
fn generate_test_events(db_path: &str, count: usize, channel_id: [u8; 32]) {
    let db = open_connection(db_path).unwrap();
    create_tables(&db).unwrap();

    let author_id: [u8; 32] = rand::random();
    let signer_id: [u8; 32] = rand::random();

    let store = Store::new(&db);
    let shareable = Shareable::new(&db);

    let mut project_stmt = db
        .prepare(
            "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .unwrap();

    let mut neg_items_stmt = db
        .prepare("INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)")
        .unwrap();

    for i in 0..count {
        let content = format!("Test message {}", i);
        let envelope = Envelope::new_message(signer_id, channel_id, author_id, content.clone());

        let blob = envelope.encode();
        let event_id = hash_event(&blob);
        let created_at_ms = envelope.payload.created_at_ms;

        store.put(&event_id, &blob).unwrap();
        shareable.insert(&event_id).unwrap();

        neg_items_stmt
            .execute(rusqlite::params![created_at_ms as i64, event_id.as_slice()])
            .unwrap();

        let message_id = event_id_to_base64(&event_id);
        let channel_id_b64 = event_id_to_base64(&channel_id);
        let author_id_b64 = event_id_to_base64(&author_id);
        project_stmt
            .execute(rusqlite::params![
                message_id,
                channel_id_b64,
                author_id_b64,
                content,
                created_at_ms as i64
            ])
            .unwrap();
    }
}

/// Count events in store table
fn count_store_events(db_path: &str) -> i64 {
    let db = open_connection(db_path).unwrap();
    db.query_row("SELECT COUNT(*) FROM store", [], |row| row.get(0))
        .unwrap_or(0)
}

/// Clean up test database files
fn cleanup_db(path: &str) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(format!("{}-shm", path));
    let _ = std::fs::remove_file(format!("{}-wal", path));
}

#[test]
fn quic_sync_1000_events() {
    // Use unique port based on process ID to avoid conflicts
    let port = 14433 + (std::process::id() % 1000) as u16;
    let bind_addr: SocketAddr = format!("127.0.0.1:{}", port).parse().unwrap();

    let server_db = format!("/tmp/quic_test_server_{}.db", port);
    let client_db = format!("/tmp/quic_test_client_{}.db", port);

    // Cleanup any previous test files
    cleanup_db(&server_db);
    cleanup_db(&client_db);

    // Generate 1000 events per peer with different channel IDs
    let server_channel: [u8; 32] = [0xAA; 32];
    let client_channel: [u8; 32] = [0xBB; 32];

    generate_test_events(&server_db, 1000, server_channel);
    generate_test_events(&client_db, 1000, client_channel);

    // Verify initial state
    assert_eq!(count_store_events(&server_db), 1000);
    assert_eq!(count_store_events(&client_db), 1000);

    // Channel to signal server is ready
    let (tx, rx) = std::sync::mpsc::channel::<()>();

    let server_db_clone = server_db.clone();
    let server_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            run_server(bind_addr, &server_db_clone, 30, tx).await
        })
    });

    // Wait for server to signal it's ready
    let _ = rx.recv_timeout(Duration::from_secs(5));
    std::thread::sleep(Duration::from_millis(50));

    let client_db_clone = client_db.clone();
    let client_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async move {
            run_client(bind_addr, &client_db_clone, 30).await
        })
    });

    // Wait for both to complete
    let server_result = server_handle.join();
    let client_result = client_handle.join();

    assert!(server_result.is_ok(), "Server thread panicked");
    assert!(client_result.is_ok(), "Client thread panicked");

    // Verify sync completed - both should have 2000 events
    let server_count = count_store_events(&server_db);
    let client_count = count_store_events(&client_db);

    println!(
        "QUIC sync complete: Server={} events, Client={} events",
        server_count, client_count
    );

    assert_eq!(server_count, 2000, "Server should have 2000 events");
    assert_eq!(client_count, 2000, "Client should have 2000 events");

    // Cleanup
    cleanup_db(&server_db);
    cleanup_db(&client_db);
}

// ============================================================================
// Server and Client implementations (simplified from main.rs)
// ============================================================================

use negentropy::{Negentropy, Storage};
use poc_7::db::{outgoing::OutgoingQueue, wanted::WantedEvents};
use poc_7::sync::{neg_id_to_event_id, NegentropyStorageSqlite, SyncMessage};
use poc_7::transport::{
    connection::{Connection, SendConnection, RecvConnection},
    create_client_endpoint, create_server_endpoint, generate_keypair,
    generate_self_signed_cert, DualConnection, StreamConn, StreamSend, StreamRecv,
};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;

async fn run_server(
    bind: SocketAddr,
    db_path: &str,
    timeout_secs: u64,
    ready_tx: std::sync::mpsc::Sender<()>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (signing_key, _) = generate_keypair();
    let (cert, key) = generate_self_signed_cert(&signing_key)?;
    let endpoint = create_server_endpoint(bind, cert, key)?;

    // Signal that server is ready
    let _ = ready_tx.send(());

    let incoming = endpoint.accept().await.ok_or("No connection")?;
    let connection = incoming.await?;
    let peer_id = connection.remote_address().to_string();

    let (control_send, control_recv) = connection.accept_bi().await?;
    let (data_send, data_recv) = connection.accept_bi().await?;
    let conn = DualConnection::new(control_send, control_recv, data_send, data_recv);

    run_sync_responder(conn, db_path, timeout_secs, &peer_id).await?;

    connection.close(0u32.into(), b"done");
    Ok(())
}

async fn run_client(
    remote: SocketAddr,
    db_path: &str,
    timeout_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let endpoint = create_client_endpoint("0.0.0.0:0".parse()?)?;
    let connection = endpoint.connect(remote, "localhost")?.await?;
    let peer_id = connection.remote_address().to_string();

    let (control_send, control_recv) = connection.open_bi().await?;
    let (data_send, data_recv) = connection.open_bi().await?;
    let mut conn = DualConnection::new(control_send, control_recv, data_send, data_recv);

    // Send stream establishment markers
    conn.control.send(&SyncMessage::HaveList { ids: vec![] }).await?;
    conn.data_send.send(&SyncMessage::HaveList { ids: vec![] }).await?;
    conn.flush_control().await?;
    conn.flush_data().await?;

    run_sync_initiator(conn, db_path, timeout_secs, &peer_id).await?;

    connection.close(0u32.into(), b"done");
    Ok(())
}

async fn run_sync_initiator<C, S, R>(
    conn: DualConnection<C, S, R>,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
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
    let timeout = Duration::from_secs(timeout_secs);
    let db = open_connection(db_path)?;
    let neg_db = open_connection(db_path)?;

    let outgoing = OutgoingQueue::new(&db);
    let wanted = WantedEvents::new(&db);
    let _ = outgoing.clear_peer(peer_id);
    let _ = wanted.clear();

    let neg_storage = NegentropyStorageSqlite::new(&neg_db);
    neg_storage.rebuild_blocks()?;
    neg_db.execute("BEGIN", [])?;

    let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), 64 * 1024)?;
    let store = Store::new(&db);

    let (ingest_tx, ingest_rx) = mpsc::channel(1000);
    let events_received = Arc::new(AtomicU64::new(0));

    let db_path_owned = db_path.to_string();
    let events_received_clone = events_received.clone();
    let writer_handle = tokio::task::spawn_blocking(move || {
        batch_writer(db_path_owned, ingest_rx, events_received_clone)
    });

    // Spawn dedicated data receiver task
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let recv_handle = {
        let mut data_recv = data_recv;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    msg = data_recv.recv() => {
                        match msg {
                            Ok(SyncMessage::Event { blob }) => {
                                let event_id = hash_event(&blob);
                                if ingest_tx.send((event_id, blob)).await.is_err() {
                                    break;
                                }
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                }
            }
        })
    };

    let mut have_ids = Vec::new();
    let mut need_ids = Vec::new();

    let initial_msg = neg.initiate()?;
    control.send(&SyncMessage::NegOpen { msg: initial_msg }).await?;
    control.flush().await?;

    let mut reconciliation_done = false;
    let timeout_at = tokio::time::Instant::now() + timeout;
    let mut send_interval = tokio::time::interval(Duration::from_millis(5));

    loop {
        tokio::select! {
            biased;

            ctrl_result = control.recv() => {
                match ctrl_result {
                    Ok(SyncMessage::NegMsg { msg }) => {
                        match neg.reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)? {
                            Some(next_msg) => {
                                control.send(&SyncMessage::NegMsg { msg: next_msg }).await?;
                                control.flush().await?;
                            }
                            None => reconciliation_done = true,
                        }

                        if !have_ids.is_empty() {
                            let batch: Vec<_> = have_ids.drain(..).map(|id| neg_id_to_event_id(&id)).collect();
                            let _ = outgoing.enqueue_batch(peer_id, &batch);
                        }

                        if !need_ids.is_empty() {
                            let mut batch = Vec::new();
                            for neg_id in need_ids.drain(..) {
                                let event_id = neg_id_to_event_id(&neg_id);
                                if wanted.insert(&event_id).unwrap_or(false) {
                                    batch.push(event_id);
                                }
                            }
                            if !batch.is_empty() {
                                control.send(&SyncMessage::HaveList { ids: batch }).await?;
                                control.flush().await?;
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }

            _ = send_interval.tick() => {
                let batch = outgoing.dequeue_batch(peer_id, 500).unwrap_or_default();
                if !batch.is_empty() {
                    let event_ids: Vec<_> = batch.iter().map(|(_, id)| *id).collect();
                    let blobs = store.get_batch(&event_ids).unwrap_or_default();
                    let mut sent_rowids = Vec::new();
                    for (rowid, event_id) in batch {
                        if let Some(blob) = blobs.get(&event_id) {
                            let _ = data_send.send(&SyncMessage::Event { blob: blob.clone() }).await;
                            sent_rowids.push(rowid);
                        } else {
                            sent_rowids.push(rowid);
                        }
                    }
                    let _ = outgoing.mark_sent_batch(&sent_rowids);
                    let _ = data_send.flush().await;
                }

                if reconciliation_done {
                    let pending_out = outgoing.count_pending(peer_id).unwrap_or(0);
                    let pending_in = wanted.count().unwrap_or(0);
                    if pending_out == 0 && pending_in == 0 {
                        break;
                    }
                }
            }

            _ = tokio::time::sleep_until(timeout_at) => break,
        }
    }

    let _ = neg_db.execute("COMMIT", []);
    let _ = shutdown_tx.send(true);
    let _ = recv_handle.await;
    let _ = writer_handle.await;
    Ok(())
}

async fn run_sync_responder<C, S, R>(
    conn: DualConnection<C, S, R>,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
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
    let timeout = Duration::from_secs(timeout_secs);
    let db = open_connection(db_path)?;
    let neg_db = open_connection(db_path)?;

    let outgoing = OutgoingQueue::new(&db);
    let _ = outgoing.clear_peer(peer_id);

    let neg_storage = NegentropyStorageSqlite::new(&neg_db);
    neg_storage.rebuild_blocks()?;
    neg_db.execute("BEGIN", [])?;

    let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), 64 * 1024)?;
    let store = Store::new(&db);

    let (ingest_tx, ingest_rx) = mpsc::channel(1000);
    let events_received = Arc::new(AtomicU64::new(0));

    let db_path_owned = db_path.to_string();
    let events_received_clone = events_received.clone();
    let writer_handle = tokio::task::spawn_blocking(move || {
        batch_writer(db_path_owned, ingest_rx, events_received_clone)
    });

    // Spawn dedicated data receiver task
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let recv_handle = {
        let mut data_recv = data_recv;
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    msg = data_recv.recv() => {
                        match msg {
                            Ok(SyncMessage::Event { blob }) => {
                                let event_id = hash_event(&blob);
                                if ingest_tx.send((event_id, blob)).await.is_err() {
                                    break;
                                }
                            }
                            Ok(_) => {}
                            Err(_) => break,
                        }
                    }
                }
            }
        })
    };

    let mut reconciliation_done = false;
    let mut idle_count = 0;
    let timeout_at = tokio::time::Instant::now() + timeout;
    let mut send_interval = tokio::time::interval(Duration::from_millis(5));

    loop {
        tokio::select! {
            biased;

            ctrl_result = control.recv() => {
                match ctrl_result {
                    Ok(SyncMessage::NegOpen { msg }) | Ok(SyncMessage::NegMsg { msg }) => {
                        idle_count = 0;
                        let response = neg.reconcile(&msg)?;
                        if response.is_empty() {
                            reconciliation_done = true;
                        } else {
                            control.send(&SyncMessage::NegMsg { msg: response }).await?;
                            control.flush().await?;
                        }
                    }
                    Ok(SyncMessage::HaveList { ids }) => {
                        if !ids.is_empty() {
                            idle_count = 0;
                            reconciliation_done = true;
                            let _ = outgoing.enqueue_batch(peer_id, &ids);
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }

            _ = send_interval.tick() => {
                let batch = outgoing.dequeue_batch(peer_id, 500).unwrap_or_default();
                if !batch.is_empty() {
                    idle_count = 0;
                    let event_ids: Vec<_> = batch.iter().map(|(_, id)| *id).collect();
                    let blobs = store.get_batch(&event_ids).unwrap_or_default();
                    let mut sent_rowids = Vec::new();
                    for (rowid, event_id) in batch {
                        if let Some(blob) = blobs.get(&event_id) {
                            let _ = data_send.send(&SyncMessage::Event { blob: blob.clone() }).await;
                            sent_rowids.push(rowid);
                        } else {
                            sent_rowids.push(rowid);
                        }
                    }
                    let _ = outgoing.mark_sent_batch(&sent_rowids);
                    let _ = data_send.flush().await;
                } else if reconciliation_done {
                    idle_count += 1;
                }

                if reconciliation_done && idle_count >= 100 {
                    let pending = outgoing.count_pending(peer_id).unwrap_or(0);
                    if pending == 0 {
                        break;
                    }
                }
            }

            _ = tokio::time::sleep_until(timeout_at) => break,
        }
    }

    let _ = neg_db.execute("COMMIT", []);
    let _ = shutdown_tx.send(true);
    let _ = recv_handle.await;
    let _ = writer_handle.await;
    Ok(())
}

fn batch_writer(
    db_path: String,
    mut rx: mpsc::Receiver<([u8; 32], Vec<u8>)>,
    events_received: Arc<AtomicU64>,
) {
    let db = match open_connection(&db_path) {
        Ok(db) => db,
        Err(_) => return,
    };

    let store = Store::new(&db);
    let shareable = Shareable::new(&db);
    let wanted = WantedEvents::new(&db);

    let mut project_stmt = match db.prepare(
        "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
    ) {
        Ok(s) => s,
        Err(_) => return,
    };

    let mut neg_items_stmt = match db.prepare("INSERT OR IGNORE INTO neg_items (ts, id) VALUES (?1, ?2)") {
        Ok(s) => s,
        Err(_) => return,
    };

    while let Some(first) = rx.blocking_recv() {
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
