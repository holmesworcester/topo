//! Sync responder (server role) with dual-stream transport.
//!
//! Handles incoming negentropy reconciliation, serves requested events
//! from the egress queue, and follows the shutdown protocol (DataDone / DoneAck).
//!
//! Reconciliation runs on a dedicated OS thread so the main loop can
//! continue draining the egress queue during the 100-400ms reconcile() calls.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use negentropy::{Negentropy, NegentropyStorageBase, Storage};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::db::{
    egress_queue::EgressQueue,
    open_connection,
    store::{lookup_workspace_id, Store},
};
use crate::protocol::Frame;
use crate::runtime::memtrace;
use crate::runtime::SyncStats;
use crate::sync::negentropy_sqlite::NegentropyStorageSqlite;
use crate::transport::connection::ConnectionError;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};
use crate::tuning::{low_mem_memtrace, low_mem_mode};

use super::control_plane::send_done_ack;
use super::data_plane::{drain_egress_to_data_stream, send_data_done, spawn_data_receiver};
use super::{negentropy_frame_size, CONTROL_POLL_TIMEOUT, DATA_DRAIN_TIMEOUT, EGRESS_SENT_TTL_MS};

/// Run sync as the responder (server role) with dual streams.
///
/// Callers must provide a `shared_ingest` sender connected to a shared
/// batch_writer. The session never spawns its own writer thread.
/// This eliminates SQLite write contention when multiple sources sync
/// concurrently.
pub async fn run_sync_responder<C, S, R>(
    conn: DualConnection<C, S, R>,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
    recorded_by: &str,
    ingress_source_tag: &str,
    shared_ingest: mpsc::Sender<IngestItem>,
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
    let activity_timeout = Duration::from_secs(timeout_secs);
    let mut last_activity = Instant::now();

    info!(
        "Starting negentropy sync (responder, dual-stream), activity timeout {}s",
        timeout_secs
    );

    let db = open_connection(db_path)?;
    let use_snapshot = !low_mem_mode();

    let egress = EgressQueue::new(&db);
    let _ = egress.clear_connection(peer_id);

    let ws_id = lookup_workspace_id(&db, recorded_by).ok_or_else(|| {
        format!(
            "no accepted workspace binding for peer_id={}, cannot start sync",
            recorded_by
        )
    })?;

    // Spawn reconciliation on a dedicated OS thread.
    // neg_db, neg_storage, neg are !Send (SQLite + RefCell) so they must
    // live entirely on one thread. The worker receives NegMsg bytes, runs
    // reconcile(), and sends the response bytes back.
    let db_path_for_neg = db_path.to_string();
    let ws_id_for_neg = ws_id.clone();
    let (neg_req_tx, neg_req_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    let (neg_resp_tx, neg_resp_rx) = std::sync::mpsc::channel::<Result<Vec<u8>, String>>();

    let neg_worker = std::thread::spawn(move || {
        let neg_db = open_connection(&db_path_for_neg).expect("neg worker: open_connection");
        let neg_storage = NegentropyStorageSqlite::new(&neg_db, &ws_id_for_neg);
        if use_snapshot {
            neg_db.execute("BEGIN", []).expect("neg worker: BEGIN");
        }
        neg_storage
            .rebuild_blocks()
            .expect("neg worker: rebuild_blocks");

        let item_count = neg_storage.size().unwrap_or(0);
        info!("Negentropy storage has {} items (responder)", item_count);

        let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), negentropy_frame_size())
            .expect("neg worker: Negentropy::new");

        while let Ok(msg) = neg_req_rx.recv() {
            let result = neg.reconcile(&msg).map_err(|e| format!("{}", e));
            if neg_resp_tx.send(result).is_err() {
                break;
            }
        }

        if use_snapshot {
            let _ = neg_db.execute("COMMIT", []);
        }
    });

    let store = Store::new(&db);

    let events_received = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));

    let ingest_tx = shared_ingest;

    let (shutdown_tx, data_drained_rx, recv_handle) = spawn_data_receiver(
        data_recv,
        ingest_tx.clone(),
        bytes_received.clone(),
        recorded_by.to_string(),
        ingress_source_tag.to_string(),
    );

    let mut events_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let mut rounds = 0;
    let mut peer_done = false;
    let mut completed = false;
    let sync_start = Instant::now();
    let reconcile_start = Instant::now();
    let mut last_bytes_received = 0u64;
    let mut reconciling = false;
    let memtrace_enabled = low_mem_memtrace();
    let memtrace_interval = Duration::from_secs(2);
    let memtrace_file = std::env::var("LOW_MEM_MEMTRACE_FILE").ok();
    let mut last_memtrace = Instant::now();
    let mut last_alloc_trim = Instant::now();

    loop {
        // Data receiver runs in a separate task — check if it received data
        let current_bytes = bytes_received.load(Ordering::Relaxed);
        if current_bytes > last_bytes_received {
            last_activity = Instant::now();
            last_bytes_received = current_bytes;
        }
        if last_activity.elapsed() >= activity_timeout {
            warn!(
                "Activity timeout ({}s idle, {}s total)",
                activity_timeout.as_secs(),
                start.elapsed().as_secs()
            );
            break;
        }

        // Check for reconciliation response from worker thread
        if reconciling {
            match neg_resp_rx.try_recv() {
                Ok(Ok(response)) => {
                    reconciling = false;
                    last_activity = Instant::now();
                    if response.is_empty() {
                        info!(
                            "Reconciliation complete: {} rounds, {}ms",
                            rounds,
                            reconcile_start.elapsed().as_millis()
                        );
                    } else {
                        control.send(&Frame::NegMsg { msg: response }).await?;
                        control.flush().await?;
                    }
                }
                Ok(Err(e)) => {
                    return Err(e.into());
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    // Worker still processing — continue draining egress
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    return Err("neg worker disconnected".into());
                }
            }
        }

        match tokio::time::timeout(CONTROL_POLL_TIMEOUT, control.recv()).await {
            Ok(Ok(Frame::NegOpen { msg })) | Ok(Ok(Frame::NegMsg { msg })) => {
                last_activity = Instant::now();
                rounds += 1;
                // Hand off to worker thread — non-blocking
                neg_req_tx
                    .send(msg)
                    .map_err(|_| "neg worker channel closed".to_string())?;
                reconciling = true;
            }
            Ok(Ok(Frame::HaveList { ids })) => {
                last_activity = Instant::now();
                if ids.is_empty() {
                    continue;
                }
                let _ = egress.enqueue_events(peer_id, &ids);
            }
            Ok(Ok(Frame::Done)) => {
                last_activity = Instant::now();
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

        // Drain egress to data stream — runs even while worker is reconciling
        let send_stats =
            drain_egress_to_data_stream(&egress, &store, peer_id, &mut data_send).await;
        events_sent += send_stats.events_sent_delta;
        bytes_sent += send_stats.bytes_sent_delta;
        if send_stats.events_sent_delta > 0 {
            last_activity = Instant::now();
        }

        if low_mem_mode() && last_alloc_trim.elapsed() >= Duration::from_millis(100) {
            let _ = memtrace::allocator_trim();
            last_alloc_trim = Instant::now();
        }

        if memtrace_enabled && last_memtrace.elapsed() >= memtrace_interval {
            let egress_pending = egress.count_pending(peer_id).unwrap_or(-1);
            let ingest_cap = ingest_tx.max_capacity();
            let ingest_used = ingest_cap.saturating_sub(ingest_tx.capacity());
            let sqlite_global = memtrace::sqlite_global_memory();
            let sqlite_db = memtrace::sqlite_db_memory(&db);
            let allocator = memtrace::allocator_memory();
            let line = format!(
                "LOWMEM_MEMTRACE responder peer={} rounds={} reconciling={} peer_done={} egress_pending={} ingest_used={}/{} sqlite_mem_cur={} sqlite_mem_high={} sqlite_pcache_ovfl_cur={} sqlite_pcache_ovfl_high={} db_cache={} db_schema={} db_stmt={} mall_arena={} mall_used={} mall_free={} mall_mmap={} bytes_rx={} bytes_tx={}",
                peer_id,
                rounds,
                reconciling,
                peer_done,
                egress_pending,
                ingest_used,
                ingest_cap,
                sqlite_global.map(|s| s.memory_used_bytes).unwrap_or(-1),
                sqlite_global.map(|s| s.memory_high_bytes).unwrap_or(-1),
                sqlite_global
                    .map(|s| s.pagecache_overflow_bytes)
                    .unwrap_or(-1),
                sqlite_global
                    .map(|s| s.pagecache_overflow_high_bytes)
                    .unwrap_or(-1),
                sqlite_db.map(|s| s.cache_used_bytes).unwrap_or(-1),
                sqlite_db.map(|s| s.schema_used_bytes).unwrap_or(-1),
                sqlite_db.map(|s| s.stmt_used_bytes).unwrap_or(-1),
                allocator.map(|s| s.arena_bytes).unwrap_or(-1),
                allocator.map(|s| s.used_bytes).unwrap_or(-1),
                allocator.map(|s| s.free_bytes).unwrap_or(-1),
                allocator.map(|s| s.mmap_bytes).unwrap_or(-1),
                bytes_received.load(Ordering::Relaxed),
                bytes_sent,
            );
            memtrace::emit(&line, memtrace_file.as_deref());
            last_memtrace = Instant::now();
        }

        // After peer signalled Done and our egress queue is drained:
        // 1. Send DataDone on data stream (signals peer's data receiver)
        // 2. Wait for peer's DataDone to be consumed by our data receiver
        // 3. Only then send DoneAck on control
        if peer_done && !reconciling {
            let pending_out = egress.count_pending(peer_id).unwrap_or(0);
            if pending_out == 0 {
                send_data_done(&mut data_send).await?;

                let drain_timeout = DATA_DRAIN_TIMEOUT;
                match tokio::time::timeout(drain_timeout, data_drained_rx).await {
                    Ok(Ok(())) => info!("Inbound data fully drained"),
                    Ok(Err(_)) => info!("Data drain channel dropped (receiver already exited)"),
                    Err(_) => warn!("Timed out waiting for inbound data drain"),
                }

                send_done_ack(&mut control).await?;
                info!(
                    "Sent DoneAck (sent {}, received {})",
                    events_sent,
                    events_received.load(Ordering::Relaxed)
                );
                completed = true;
                break;
            }
        }
    }

    if completed {
        let _ = egress.clear_connection(peer_id);
        let _ = egress.cleanup_sent(EGRESS_SENT_TTL_MS);
    }
    // Drop the request channel to signal the worker to exit
    drop(neg_req_tx);
    let _ = neg_worker.join();
    let _ = shutdown_tx.send(());
    let _ = recv_handle.await;
    drop(ingest_tx);

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
