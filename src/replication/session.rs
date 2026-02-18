// Replication session logic: initiator and responder sync loops.
//
// Extracted from sync/engine.rs (Phase 3 of Option B refactor).
// Wire protocol behavior is unchanged — this is a pure code-movement extraction.
//
// Shutdown protocol (preserved):
// 1. Each side sends DataDone on the data stream after flushing all events.
// 2. Initiator sends Done on control after its DataDone.
// 3. Responder receives Done, finishes sending, sends DataDone on data,
//    waits for initiator's DataDone to be consumed, then sends DoneAck.
// 4. Initiator receives DoneAck, waits for responder's DataDone, exits.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use negentropy::{Id, Negentropy, Storage};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::crypto::{hash_event, EventId};
use crate::db::{
    egress_queue::EgressQueue,
    open_connection,
    store::{lookup_workspace_id, Store},
    wanted::WantedEvents,
};
use crate::event_runtime::{batch_writer, IngestItem};
use crate::runtime::SyncStats;
use crate::sync::{neg_id_to_event_id, NegentropyStorageSqlite, SyncMessage};
use crate::transport::connection::ConnectionError;
use crate::transport::{DualConnection, StreamConn, StreamRecv, StreamSend};

// ---------------------------------------------------------------------------
// Session tuning constants
// ---------------------------------------------------------------------------

/// Negentropy frame size limit.
const NEGENTROPY_FRAME_SIZE: u64 = 64 * 1024;

/// Max event IDs sent per HaveList message during reconciliation.
const HAVE_CHUNK: usize = 1000;

/// Max event IDs sent per NeedList/HaveList request during reconciliation.
const NEED_CHUNK: usize = 1000;

/// Max events to enqueue into the egress queue per main-loop iteration.
const ENQUEUE_BATCH: usize = 5000;

/// Max events per egress claim (one send batch to the data stream).
const EGRESS_CLAIM_COUNT: usize = 500;

/// Lease duration (ms) for claimed egress events.
const EGRESS_CLAIM_LEASE_MS: i64 = 30_000;

/// Max age (ms) for sent egress entries before cleanup.
const EGRESS_SENT_TTL_MS: i64 = 300_000;

/// Time to wait for inbound data stream drain at session end.
const DATA_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Non-blocking poll timeout for the control stream receive.
const CONTROL_POLL_TIMEOUT: Duration = Duration::from_millis(1);

// -- Coordinator timing (B-coordinated / download_from_sources) --

/// How long the coordinator waits (after the first peer reports) for
/// remaining peers to finish reconciliation and report their need_ids.
const COORDINATOR_COLLECTION_WINDOW: Duration = Duration::from_millis(500);

/// Coordinator busy-poll interval while waiting for the first peer report.
const COORDINATOR_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Coordinator poll interval within the collection window.
const COORDINATOR_COLLECTION_POLL: Duration = Duration::from_millis(2);

// -- Ingest channel sizing --

fn low_mem_mode() -> bool {
    match std::env::var("LOW_MEM_IOS") {
        Ok(v) if v != "0" && v.to_lowercase() != "false" => return true,
        _ => {}
    }
    match std::env::var("LOW_MEM") {
        Ok(v) if v != "0" && v.to_lowercase() != "false" => true,
        _ => false,
    }
}

/// Async channel capacity for per-session ingest (initiator/responder).
fn session_ingest_cap() -> usize {
    if low_mem_mode() {
        1000
    } else {
        5000
    }
}

// ---------------------------------------------------------------------------
// Data receiver
// ---------------------------------------------------------------------------

/// Spawn data receiver task. Returns:
/// - `shutdown_tx`: forced shutdown (timeout fallback only)
/// - `data_drained_rx`: signals when peer's DataDone marker is received (all data consumed)
/// - `JoinHandle`: task handle
///
/// Each received event is tagged with `recorded_by` before being sent to the
/// ingest channel, so the batch_writer can route it to the correct tenant.
pub fn spawn_data_receiver<R>(
    mut data_recv: R,
    ingest_tx: mpsc::Sender<IngestItem>,
    bytes_received: Arc<AtomicU64>,
    recorded_by: String,
) -> (
    oneshot::Sender<()>,
    oneshot::Receiver<()>,
    tokio::task::JoinHandle<()>,
)
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
                            if ingest_tx.send((event_id, blob, recorded_by.clone())).await.is_err() {
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

// ---------------------------------------------------------------------------
// Multi-source coordination
// ---------------------------------------------------------------------------

/// Per-peer coordination handles for coordinated multi-source download.
///
/// Held by the peer thread, reused across sessions. The peer sends its
/// discovered need_ids to the coordinator via `report_tx`, then polls
/// `assign_rx` for its assigned subset.
pub struct PeerCoord {
    pub peer_idx: usize,
    pub report_tx: std::sync::mpsc::Sender<Vec<EventId>>,
    pub assign_rx: std::sync::Mutex<std::sync::mpsc::Receiver<Vec<EventId>>>,
}

/// Assign events to peers using greedy load balancing.
///
/// Takes `(peer_idx, Vec<EventId>)` pairs from all reporting peers.
/// Builds an `event_id -> Vec<peer_idx>` availability map, sorts by
/// availability ascending (unique events first), then assigns each event
/// to the least-loaded peer that has it.
///
/// Returns indexed `Vec` where `result[peer_idx]` = events assigned to that peer.
fn assign_events(reports: &[(usize, Vec<EventId>)], total_peers: usize) -> Vec<Vec<EventId>> {
    use std::collections::HashMap;

    // Build event -> available peers map
    let mut availability: HashMap<EventId, Vec<usize>> = HashMap::new();
    for (peer_idx, events) in reports {
        for eid in events {
            availability.entry(*eid).or_default().push(*peer_idx);
        }
    }

    // Sort by availability ascending (unique events assigned first)
    let mut events_sorted: Vec<(EventId, Vec<usize>)> = availability.into_iter().collect();
    events_sorted.sort_by_key(|(_, peers)| peers.len());

    // Greedy assignment: least-loaded peer that has the event
    let mut loads = vec![0usize; total_peers];
    let mut assignments: Vec<Vec<EventId>> = vec![Vec::new(); total_peers];

    for (eid, peers) in events_sorted {
        let best = peers.iter().copied().min_by_key(|&p| loads[p]).unwrap();
        assignments[best].push(eid);
        loads[best] += 1;
    }

    assignments
}

/// Coordinator thread for multi-source download rounds.
///
/// Each iteration is one round:
/// 1. Block until the first peer reports its need_ids.
/// 2. Start a 500ms collection window for remaining peers.
/// 3. Call assign_events with collected reports.
/// 4. Send assigned Vec<EventId> to each reporting peer.
/// 5. Send empty Vec to non-reporting peers (unblocks their session).
pub fn run_coordinator(
    report_rxs: Vec<std::sync::mpsc::Receiver<Vec<EventId>>>,
    assign_txs: Vec<std::sync::mpsc::Sender<Vec<EventId>>>,
) {
    let total_peers = report_rxs.len();
    loop {
        // Phase 1: Block until at least one peer reports
        let mut reports: Vec<Option<Vec<EventId>>> = vec![None; total_peers];
        let mut reported_count = 0;
        let mut any_alive = false;

        loop {
            let mut all_disconnected = true;
            for (i, rx) in report_rxs.iter().enumerate() {
                if reports[i].is_some() {
                    continue;
                }
                match rx.try_recv() {
                    Ok(need_ids) => {
                        reports[i] = Some(need_ids);
                        reported_count += 1;
                        any_alive = true;
                        all_disconnected = false;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {
                        all_disconnected = false;
                    }
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {}
                }
            }
            if reported_count > 0 || all_disconnected {
                break;
            }
            std::thread::sleep(COORDINATOR_POLL_INTERVAL);
        }

        if !any_alive && reported_count == 0 {
            return;
        }

        // Phase 2: Collection window for remaining peers
        let deadline = Instant::now() + COORDINATOR_COLLECTION_WINDOW;
        while reported_count < total_peers && Instant::now() < deadline {
            for (i, rx) in report_rxs.iter().enumerate() {
                if reports[i].is_some() {
                    continue;
                }
                match rx.try_recv() {
                    Ok(need_ids) => {
                        reports[i] = Some(need_ids);
                        reported_count += 1;
                    }
                    Err(_) => {}
                }
            }
            if reported_count < total_peers {
                std::thread::sleep(COORDINATOR_COLLECTION_POLL);
            }
        }

        // Phase 3: Assign events
        let collected: Vec<(usize, Vec<EventId>)> = reports
            .iter()
            .enumerate()
            .filter_map(|(i, r)| r.as_ref().map(|ids| (i, ids.clone())))
            .collect();
        let assignments = assign_events(&collected, total_peers);

        // Phase 4: Send assignments only to peers that reported this round
        for (i, tx) in assign_txs.iter().enumerate() {
            if reports[i].is_some() {
                let assigned = assignments[i].clone();
                if tx.send(assigned).is_err() {
                    // Peer disconnected; continue with remaining peers
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Initiator
// ---------------------------------------------------------------------------

/// Run sync as the initiator (client role) with dual streams.
/// Control stream: NegOpen, NegMsg, HaveList
/// Data stream: Event blobs
///
/// Push (have_ids): always sends everything the peer needs.
/// Pull (need_ids): when `coordination` is set, buffers need_ids and sends
/// them to the coordinator for load-balanced assignment across peers.
/// When coordination is None, requests all need_ids directly.
///
/// When `shared_ingest` is provided, events are sent to the shared channel
/// instead of spawning a per-session batch_writer.
pub async fn run_sync_initiator_dual<C, S, R>(
    conn: DualConnection<C, S, R>,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
    recorded_by: &str,
    coordination: Option<&PeerCoord>,
    shared_ingest: Option<mpsc::Sender<IngestItem>>,
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

    info!(
        "Starting negentropy sync (initiator, dual-stream) for {} seconds",
        timeout_secs
    );

    let db = open_connection(db_path)?;
    let neg_db = open_connection(db_path)?;

    let egress = EgressQueue::new(&db);
    let wanted = WantedEvents::new(&db);
    let _ = egress.clear_connection(peer_id);
    let _ = wanted.clear();

    let ws_id = lookup_workspace_id(&db, recorded_by);
    let neg_storage = NegentropyStorageSqlite::new(&neg_db, &ws_id);

    neg_db
        .execute("BEGIN", [])
        .map_err(|e| format!("Failed to begin snapshot: {}", e))?;
    neg_storage
        .rebuild_blocks()
        .map_err(|e| format!("Failed to rebuild blocks: {}", e))?;

    let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), NEGENTROPY_FRAME_SIZE)?;

    let store = Store::new(&db);

    let events_received = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));

    // Use shared ingest channel if provided, otherwise create per-session batch_writer
    let (ingest_tx, writer_handle) = if let Some(shared_tx) = shared_ingest {
        (shared_tx, None)
    } else {
        let ingest_cap = session_ingest_cap();
        let (tx, rx) = mpsc::channel::<IngestItem>(ingest_cap);
        let events_received_writer = events_received.clone();
        let db_path_owned = db_path.to_string();
        let handle = tokio::task::spawn_blocking(move || {
            batch_writer(db_path_owned, rx, events_received_writer)
        });
        (tx, Some(handle))
    };

    let mut have_ids: Vec<Id> = Vec::new();
    let mut need_ids: Vec<Id> = Vec::new();
    let mut events_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;
    let (shutdown_tx, data_drained_rx, recv_handle) = spawn_data_receiver(
        data_recv,
        ingest_tx.clone(),
        bytes_received.clone(),
        recorded_by.to_string(),
    );

    let initial_msg = neg.initiate()?;
    control
        .send(&SyncMessage::NegOpen { msg: initial_msg })
        .await?;
    control.flush().await?;

    let mut reconciliation_done = false;
    let mut rounds = 0;

    let mut completed = false;
    let mut done_sent = false;
    let sync_start = Instant::now();
    // Pending have_ids buffer: populated by reconciliation, drained incrementally
    let mut pending_have: Vec<EventId> = Vec::new();

    // Coordination state: buffer need_ids during reconciliation, send to coordinator after
    let mut coordinated_need_ids: Vec<EventId> = Vec::new();
    let mut coordination_pending = coordination.is_some();
    let mut coordination_reported = false;

    loop {
        if start.elapsed() >= timeout {
            warn!("Timeout");
            break;
        }

        match tokio::time::timeout(CONTROL_POLL_TIMEOUT, control.recv()).await {
            Ok(Ok(SyncMessage::NegMsg { msg })) => {
                rounds += 1;
                match neg.reconcile_with_ids(&msg, &mut have_ids, &mut need_ids)? {
                    Some(next_msg) => {
                        control.send(&SyncMessage::NegMsg { msg: next_msg }).await?;
                        control.flush().await?;
                    }
                    None => {
                        info!("Reconciliation complete in {} rounds", rounds);
                        reconciliation_done = true;
                    }
                }

                // Convert have_ids to EventIds and add to pending buffer
                if !have_ids.is_empty() {
                    pending_have.reserve(have_ids.len());
                    for neg_id in have_ids.drain(..) {
                        pending_have.push(neg_id_to_event_id(&neg_id));
                    }
                }

                if !need_ids.is_empty() {
                    if coordination.is_some() {
                        // Buffer need_ids for coordinator assignment
                        for neg_id in need_ids.drain(..) {
                            coordinated_need_ids.push(neg_id_to_event_id(&neg_id));
                        }
                    } else {
                        // No coordination: send HaveList immediately
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

        // Coordination: after reconciliation, send need_ids to coordinator
        if let Some(coord) = coordination {
            if reconciliation_done && !coordination_reported {
                let report = std::mem::take(&mut coordinated_need_ids);
                info!(
                    "Reporting {} need_ids to coordinator (peer {})",
                    report.len(),
                    coord.peer_idx
                );
                let _ = coord.report_tx.send(report);
                coordination_reported = true;
            }

            // Poll for assignment (non-blocking so push path continues)
            if coordination_pending && coordination_reported {
                let assign_result = match coord.assign_rx.lock() {
                    Ok(rx) => rx.try_recv(),
                    Err(_) => Err(std::sync::mpsc::TryRecvError::Disconnected),
                };
                match assign_result {
                    Ok(assigned) => {
                        info!(
                            "Received {} assigned events from coordinator (peer {})",
                            assigned.len(),
                            coord.peer_idx
                        );
                        // Send HaveList for assigned events
                        let mut batch: Vec<EventId> = Vec::with_capacity(NEED_CHUNK);
                        for event_id in assigned {
                            if wanted.insert(&event_id).unwrap_or(false) {
                                batch.push(event_id);
                            }
                            if batch.len() >= NEED_CHUNK {
                                let _ = control.send(&SyncMessage::HaveList { ids: batch }).await;
                                let _ = control.flush().await;
                                batch = Vec::with_capacity(NEED_CHUNK);
                            }
                        }
                        if !batch.is_empty() {
                            let _ = control.send(&SyncMessage::HaveList { ids: batch }).await;
                            let _ = control.flush().await;
                        }
                        coordination_pending = false;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        coordination_pending = false;
                    }
                }
            }
        }

        // Incrementally enqueue pending have_ids to egress queue
        if !pending_have.is_empty() {
            let drain_count = pending_have.len().min(ENQUEUE_BATCH);
            let to_enqueue: Vec<EventId> = pending_have.drain(..drain_count).collect();
            for chunk in to_enqueue.chunks(HAVE_CHUNK) {
                let _ = egress.enqueue_events(peer_id, chunk);
            }
        }

        // Stream events from DB queue on data stream
        let mut sent_this_round = 0;
        let mut blocked = false;
        while !blocked {
            let batch = egress
                .claim_batch(peer_id, EGRESS_CLAIM_COUNT, EGRESS_CLAIM_LEASE_MS)
                .unwrap_or_default();
            if batch.is_empty() {
                break;
            }

            let mut sent_rowids: Vec<i64> = Vec::with_capacity(batch.len());
            for (rowid, event_id) in batch {
                if let Ok(Some(blob)) = store.get_shared(&event_id) {
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
            let _ = egress.mark_sent(&sent_rowids);
        }

        if sent_this_round > 0 {
            let _ = data_send.flush().await;
        }

        // Once reconciliation is done, coordination resolved, pending_have drained,
        // and egress queue empty, send DataDone on data stream then Done on control.
        if reconciliation_done && !coordination_pending && pending_have.is_empty() && !done_sent {
            let pending_out = egress.count_pending(peer_id).unwrap_or(0);
            if pending_out == 0 {
                let _ = data_send.flush().await;
                data_send.send(&SyncMessage::DataDone).await?;
                data_send.flush().await?;
                control.send(&SyncMessage::Done).await?;
                control.flush().await?;
                done_sent = true;
                info!(
                    "Sent DataDone+Done, waiting for DoneAck (sent {}, received {})",
                    events_sent,
                    events_received.load(Ordering::Relaxed)
                );
            }
        }
    }

    if completed {
        let _ = egress.clear_connection(peer_id);
        let _ = wanted.clear();
        let _ = egress.cleanup_sent(EGRESS_SENT_TTL_MS);
    }
    let _ = neg_db.execute("COMMIT", []);

    // Wait for inbound data drain: data receiver exits on peer's DataDone.
    if completed {
        let drain_timeout = DATA_DRAIN_TIMEOUT;
        match tokio::time::timeout(drain_timeout, data_drained_rx).await {
            Ok(Ok(())) => info!("Inbound data fully drained"),
            Ok(Err(_)) => info!("Data drain channel dropped (receiver already exited)"),
            Err(_) => warn!("Timed out waiting for inbound data drain"),
        }
    }
    let _ = shutdown_tx.send(());
    let _ = recv_handle.await;
    drop(ingest_tx);
    if let Some(handle) = writer_handle {
        let _ = handle.await;
    }

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

// ---------------------------------------------------------------------------
// Responder
// ---------------------------------------------------------------------------

/// Run sync as the responder (server role) with dual streams.
///
/// When `shared_ingest` is provided, events are sent to the shared channel
/// instead of spawning a per-session batch_writer. This eliminates SQLite
/// write contention when multiple sources sync concurrently.
pub async fn run_sync_responder_dual<C, S, R>(
    conn: DualConnection<C, S, R>,
    db_path: &str,
    timeout_secs: u64,
    peer_id: &str,
    recorded_by: &str,
    shared_ingest: Option<mpsc::Sender<IngestItem>>,
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

    info!(
        "Starting negentropy sync (responder, dual-stream) for {} seconds",
        timeout_secs
    );

    let db = open_connection(db_path)?;
    let neg_db = open_connection(db_path)?;

    let egress = EgressQueue::new(&db);
    let _ = egress.clear_connection(peer_id);

    let ws_id = lookup_workspace_id(&db, recorded_by);
    let neg_storage = NegentropyStorageSqlite::new(&neg_db, &ws_id);

    neg_db
        .execute("BEGIN", [])
        .map_err(|e| format!("Failed to begin snapshot: {}", e))?;
    neg_storage
        .rebuild_blocks()
        .map_err(|e| format!("Failed to rebuild blocks: {}", e))?;

    let mut neg = Negentropy::new(Storage::Borrowed(&neg_storage), NEGENTROPY_FRAME_SIZE)?;

    let store = Store::new(&db);

    let events_received = Arc::new(AtomicU64::new(0));
    let bytes_received = Arc::new(AtomicU64::new(0));

    // Use shared ingest channel if provided, otherwise create per-session batch_writer
    let (ingest_tx, writer_handle) = if let Some(shared_tx) = shared_ingest {
        (shared_tx, None)
    } else {
        let ingest_cap = session_ingest_cap();
        let (tx, rx) = mpsc::channel::<IngestItem>(ingest_cap);
        let events_received_writer = events_received.clone();
        let db_path_owned = db_path.to_string();
        let handle = tokio::task::spawn_blocking(move || {
            batch_writer(db_path_owned, rx, events_received_writer)
        });
        (tx, Some(handle))
    };

    let (shutdown_tx, data_drained_rx, recv_handle) = spawn_data_receiver(
        data_recv,
        ingest_tx.clone(),
        bytes_received.clone(),
        recorded_by.to_string(),
    );

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

        match tokio::time::timeout(CONTROL_POLL_TIMEOUT, control.recv()).await {
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

                let _ = egress.enqueue_events(peer_id, &ids);
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
            let batch = egress
                .claim_batch(peer_id, EGRESS_CLAIM_COUNT, EGRESS_CLAIM_LEASE_MS)
                .unwrap_or_default();
            if batch.is_empty() {
                break;
            }

            let mut sent_rowids: Vec<i64> = Vec::with_capacity(batch.len());
            for (rowid, event_id) in batch {
                if let Ok(Some(blob)) = store.get_shared(&event_id) {
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
            let _ = egress.mark_sent(&sent_rowids);
        }

        if sent_this_round > 0 {
            let _ = data_send.flush().await;
        }

        // After peer signalled Done and our egress queue is drained:
        // 1. Send DataDone on data stream (signals peer's data receiver)
        // 2. Wait for peer's DataDone to be consumed by our data receiver
        // 3. Only then send DoneAck on control
        if peer_done {
            let pending_out = egress.count_pending(peer_id).unwrap_or(0);
            if pending_out == 0 {
                let _ = data_send.flush().await;
                data_send.send(&SyncMessage::DataDone).await?;
                data_send.flush().await?;

                let drain_timeout = DATA_DRAIN_TIMEOUT;
                match tokio::time::timeout(drain_timeout, data_drained_rx).await {
                    Ok(Ok(())) => info!("Inbound data fully drained"),
                    Ok(Err(_)) => info!("Data drain channel dropped (receiver already exited)"),
                    Err(_) => warn!("Timed out waiting for inbound data drain"),
                }

                control.send(&SyncMessage::DoneAck).await?;
                control.flush().await?;
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
    let _ = neg_db.execute("COMMIT", []);
    let _ = shutdown_tx.send(());
    let _ = recv_handle.await;
    drop(ingest_tx);
    if let Some(handle) = writer_handle {
        let _ = handle.await;
    }

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
