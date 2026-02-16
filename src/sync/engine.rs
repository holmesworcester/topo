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

use negentropy::{Negentropy, Id, Storage};
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn, error};

use crate::crypto::{hash_event, event_id_to_base64, event_id_from_base64, EventId};
use crate::db::{
    egress_queue::EgressQueue,
    open_connection,
    project_queue::ProjectQueue,
    schema::create_tables,
    store::{Store, SQL_INSERT_EVENT, SQL_INSERT_NEG_ITEM, SQL_INSERT_RECORDED_EVENT, lookup_workspace_id},
    wanted::WantedEvents,
};
use crate::db::health::{purge_expired_endpoints, record_endpoint_observation};
use crate::db::transport_trust::record_transport_binding;
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

/// Ingest channel item: (event_id, blob, recorded_by).
/// The `recorded_by` field allows a shared batch_writer to route events
/// to the correct tenant's projection pipeline.
pub type IngestItem = (EventId, Vec<u8>, String);

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

// ---------------------------------------------------------------------------
// Tuning constants
// ---------------------------------------------------------------------------

/// Endpoint observation TTL: 24 hours in milliseconds.
const ENDPOINT_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Negentropy frame size limit. Controls the maximum message size for
/// set reconciliation rounds. Larger = fewer rounds, more memory per round.
const NEGENTROPY_FRAME_SIZE: u64 = 64 * 1024;

/// Max event IDs sent per HaveList message during reconciliation.
/// Limits wire message size for the "I have these events" announcements.
const HAVE_CHUNK: usize = 1000;

/// Max event IDs sent per NeedList/HaveList request during reconciliation.
/// Limits wire message size for the "I need these events" announcements.
const NEED_CHUNK: usize = 1000;

/// Max events to enqueue into the egress queue per main-loop iteration.
/// Keeps the loop responsive by interleaving reconciliation with streaming.
const ENQUEUE_BATCH: usize = 5000;

/// Max events per egress claim (one send batch to the data stream).
const EGRESS_CLAIM_COUNT: usize = 500;

/// Lease duration (ms) for claimed egress events. If not sent within this
/// window, events become available for re-claim. 30s is generous — avoids
/// spurious re-sends while allowing recovery from stuck sessions.
const EGRESS_CLAIM_LEASE_MS: i64 = 30_000;

/// Negentropy session timeout for initiator and responder (seconds).
pub const SYNC_SESSION_TIMEOUT_SECS: u64 = 60;

/// Time to wait for inbound data stream drain at session end.
const DATA_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Sleep between consecutive sync sessions on the same connection.
/// Prevents busy-looping when sessions complete instantly.
const SESSION_GAP: Duration = Duration::from_millis(100);

/// Sleep after a failed QUIC connection attempt before retrying.
const CONNECT_RETRY_DELAY: Duration = Duration::from_secs(1);

/// Max age (ms) for sent egress entries before cleanup.
const EGRESS_SENT_TTL_MS: i64 = 300_000;

/// Non-blocking poll timeout for the control stream receive.
/// Effectively a busy-poll interval — the main loop does useful egress
/// work between polls so 1ms doesn't waste CPU in practice.
const CONTROL_POLL_TIMEOUT: Duration = Duration::from_millis(1);

// -- Coordinator timing (B-coordinated / download_from_sources) --

/// How long the coordinator waits (after the first peer reports) for
/// remaining peers to finish reconciliation and report their need_ids.
/// Must exceed typical network RTT (50-200ms) so that all peers can
/// participate in each round's assignment. Peers that miss the window
/// get assigned work in the next round.
const COORDINATOR_COLLECTION_WINDOW: Duration = Duration::from_millis(500);

/// Coordinator busy-poll interval while waiting for the first peer report.
const COORDINATOR_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Coordinator poll interval within the collection window.
const COORDINATOR_COLLECTION_POLL: Duration = Duration::from_millis(2);

// -- Batch writer sizing --

/// Batch writer drain batch size: 100 normal, 50 in low_mem.
fn drain_batch_size() -> usize {
    if low_mem_mode() { 50 } else { 100 }
}

/// Batch writer write batch cap: 1000 normal, 500 in low_mem.
fn write_batch_cap() -> usize {
    if low_mem_mode() { 500 } else { 1000 }
}

/// Async channel capacity for per-session ingest (initiator/responder).
fn session_ingest_cap() -> usize {
    if low_mem_mode() { 1000 } else { 5000 }
}

/// Async channel capacity for shared ingest (accept_loop / download_from_sources).
fn shared_ingest_cap() -> usize {
    if low_mem_mode() { 1000 } else { 10000 }
}

/// Batch writer task - drains channel and writes to SQLite in batches.
/// Writes event blob/neg_items/recorded_events, enqueues into project_queue,
/// then drains the queue via `project_one` for crash-recoverable projection.
///
/// Each item carries its own `recorded_by`, enabling a single writer to serve
/// multiple tenants sharing one DB.
pub fn batch_writer(
    db_path: String,
    mut rx: mpsc::Receiver<IngestItem>,
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

    let mut neg_items_stmt = match db.prepare(SQL_INSERT_NEG_ITEM) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare neg_items statement: {}", e);
            return;
        }
    };

    let mut recorded_stmt = match db.prepare(SQL_INSERT_RECORDED_EVENT) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare recorded_events statement: {}", e);
            return;
        }
    };

    let mut events_stmt = match db.prepare(SQL_INSERT_EVENT) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare events statement: {}", e);
            return;
        }
    };

    let reg = registry();
    let pq = ProjectQueue::new(&db);
    // Cache workspace_id per recorded_by to avoid repeated lookups
    let mut workspace_cache: std::collections::HashMap<String, String> = std::collections::HashMap::new();

    let mut enqueue_stmt = match db.prepare(
        "INSERT OR IGNORE INTO project_queue (peer_id, event_id, available_at)
         SELECT ?1, ?2, ?3
         WHERE NOT EXISTS (SELECT 1 FROM valid_events WHERE peer_id=?1 AND event_id=?2)
         AND NOT EXISTS (SELECT 1 FROM rejected_events WHERE peer_id=?1 AND event_id=?2)
         AND NOT EXISTS (SELECT 1 FROM blocked_event_deps WHERE peer_id=?1 AND event_id=?2)"
    ) {
        Ok(stmt) => stmt,
        Err(e) => {
            error!("Failed to prepare enqueue statement: {}", e);
            return;
        }
    };

    loop {
        let first = match rx.blocking_recv() {
            Some(item) => item,
            None => break,
        };

        let cap = write_batch_cap();
        let mut batch = vec![first];
        while let Ok(item) = rx.try_recv() {
            batch.push(item);
            if batch.len() >= cap {
                break;
            }
        }

        // Pre-warm workspace_id cache for all recorded_by values in this batch
        // BEFORE the transaction — avoids SHARED→EXCLUSIVE lock upgrade inside BEGIN.
        for (_, _, rb) in &batch {
            if !workspace_cache.contains_key(rb) {
                let ws = lookup_workspace_id(&db, rb);
                if !ws.is_empty() {
                    workspace_cache.insert(rb.clone(), ws);
                }
            }
        }

        // BEGIN with retry+backoff — do not drain batch on failure
        let mut begin_ok = false;
        for attempt in 0..3 {
            match db.execute("BEGIN IMMEDIATE", []) {
                Ok(_) => { begin_ok = true; break; }
                Err(e) => {
                    warn!("BEGIN failed (attempt {}): {}", attempt + 1, e);
                    // Ensure no leftover transaction state
                    let _ = db.execute("ROLLBACK", []);
                    std::thread::sleep(Duration::from_millis(50 * (1 << attempt)));
                }
            }
        }
        if !begin_ok {
            error!("BEGIN failed after retries, preserving {} items for next batch", batch.len());
            // Items remain in wanted — they will be re-requested on next sync
            continue;
        }

        // First pass: write blob storage, neg_items, recorded_events, enqueue for projection
        let mut event_ids_persisted: Vec<EventId> = Vec::with_capacity(batch.len());
        // Collect distinct tenants seen in this batch for per-tenant drain
        let mut tenants_seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (event_id, blob, recorded_by) in &batch {
            let event_id_b64 = event_id_to_base64(event_id);

            if let Some(created_at_ms) = events::extract_created_at_ms(blob) {
                if let Some(type_code) = events::extract_event_type(blob) {
                    if let Some(meta) = reg.lookup(type_code) {
                        // Only insert into neg_items for shared events (defense-in-depth)
                        if meta.share_scope == ShareScope::Shared {
                            // Look up workspace_id; cache only non-empty values
                            // (empty means trust anchor not yet projected).
                            let ws_id = if let Some(cached) = workspace_cache.get(recorded_by) {
                                cached.clone()
                            } else {
                                let ws = lookup_workspace_id(&db, recorded_by);
                                if !ws.is_empty() {
                                    workspace_cache.insert(recorded_by.clone(), ws.clone());
                                }
                                ws
                            };
                            if let Err(e) = neg_items_stmt.execute(rusqlite::params![
                                &ws_id,
                                created_at_ms as i64,
                                event_id.as_slice()
                            ]) {
                                // Non-fatal: neg_items is a reconciliation cache;
                                // event will be re-added on next sync session.
                                warn!("neg_items insert error for {}: {}", event_id_b64, e);
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
                            recorded_by,
                            &event_id_b64,
                            recorded_at,
                            "quic_recv"
                        ]) {
                            warn!("recorded_events insert error for {}: {}", event_id_b64, e);
                            continue;
                        }

                        // Enqueue for durable projection (atomicity boundary 1)
                        if let Err(e) = enqueue_stmt.execute(rusqlite::params![
                            recorded_by,
                            &event_id_b64,
                            current_timestamp_ms()
                        ]) {
                            warn!("project_queue enqueue error for {}: {}", event_id_b64, e);
                        }

                        tenants_seen.insert(recorded_by.clone());
                        event_ids_persisted.push(*event_id);
                    }
                }
            }
        }
        match db.execute("COMMIT", []) {
            Ok(_) => {
                // Remove from wanted only for successfully persisted items
                for event_id in &event_ids_persisted {
                    let _ = wanted.remove(event_id);
                }

                // Second pass: drain project_queue per tenant
                let batch_sz = drain_batch_size();
                for rb in &tenants_seen {
                    if let Err(e) = pq.drain_with_limit(rb, batch_sz, |conn, event_id_b64| {
                        if let Some(eid) = event_id_from_base64(event_id_b64) {
                            project_one(conn, rb, &eid)
                                .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
                        }
                        Ok(())
                    }) {
                        warn!("project_queue drain error for {}: {}", rb, e);
                    }
                    if let Ok(h) = pq.health(rb) {
                        if h.pending > 0 || h.max_attempts > 0 {
                            tracing::debug!(tenant=%rb, pending=%h.pending, max_attempts=%h.max_attempts, oldest_age_ms=%h.oldest_age_ms, "project_queue health");
                        }
                    }
                }
            }
            Err(e) => {
                warn!("COMMIT failed, rolling back: {}", e);
                let _ = db.execute("ROLLBACK", []);
                // Items remain in wanted — they will be re-requested on next sync
                continue;
            }
        }

        events_received.fetch_add(event_ids_persisted.len() as u64, Ordering::Relaxed);
    }
}

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

/// Per-peer coordination handles for coordinated multi-source download.
///
/// Held by the peer thread, reused across sessions. The peer sends its
/// discovered need_ids to the coordinator via `report_tx`, then polls
/// `assign_rx` for its assigned subset.
pub struct PeerCoord {
    pub peer_idx: usize,
    pub report_tx: std::sync::mpsc::Sender<Vec<EventId>>,
    pub assign_rx: std::sync::mpsc::Receiver<Vec<EventId>>,
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
        // Pick peer with minimum load among those that have this event
        let best = peers.iter()
            .copied()
            .min_by_key(|&p| loads[p])
            .unwrap(); // peers is non-empty by construction
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
fn run_coordinator(
    report_rxs: Vec<std::sync::mpsc::Receiver<Vec<EventId>>>,
    assign_txs: Vec<std::sync::mpsc::Sender<Vec<EventId>>>,
) {
    let total_peers = report_rxs.len();
    loop {
        // Phase 1: Block until at least one peer reports
        let mut reports: Vec<Option<Vec<EventId>>> = vec![None; total_peers];
        let mut reported_count = 0;
        let mut any_alive = false;

        // Busy-poll until we get the first report (or all peers are dead)
        loop {
            let mut all_disconnected = true;
            for (i, rx) in report_rxs.iter().enumerate() {
                if reports[i].is_some() { continue; }
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
            if reported_count > 0 || all_disconnected { break; }
            std::thread::sleep(COORDINATOR_POLL_INTERVAL);
        }

        if !any_alive && reported_count == 0 {
            // All peers disconnected
            return;
        }

        // Phase 2: Collection window for remaining peers.
        // After the first report arrives, wait for others to finish reconciliation.
        // 500ms accommodates real-network RTTs (50-200ms) while keeping round
        // cadence reasonable. Stragglers report in the next round.
        let deadline = Instant::now() + COORDINATOR_COLLECTION_WINDOW;
        while reported_count < total_peers && Instant::now() < deadline {
            for (i, rx) in report_rxs.iter().enumerate() {
                if reports[i].is_some() { continue; }
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
        let collected: Vec<(usize, Vec<EventId>)> = reports.iter().enumerate()
            .filter_map(|(i, r)| r.as_ref().map(|ids| (i, ids.clone())))
            .collect();
        let assignments = assign_events(&collected, total_peers);

        // Phase 4: Send assignments only to peers that reported this round.
        // Non-reporting peers are still in reconciliation or between sessions;
        // sending to them would queue a stale assignment consumed by the wrong session.
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

    info!("Starting negentropy sync (initiator, dual-stream) for {} seconds", timeout_secs);

    let db = open_connection(db_path)?;
    let neg_db = open_connection(db_path)?;

    let egress = EgressQueue::new(&db);
    let wanted = WantedEvents::new(&db);
    let _ = egress.clear_connection(peer_id);
    let _ = wanted.clear();

    let ws_id = lookup_workspace_id(&db, recorded_by);
    let neg_storage = NegentropyStorageSqlite::new(&neg_db, &ws_id);

    neg_db.execute("BEGIN", []).map_err(|e| format!("Failed to begin snapshot: {}", e))?;
    neg_storage.rebuild_blocks().map_err(|e| format!("Failed to rebuild blocks: {}", e))?;

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
    let (shutdown_tx, data_drained_rx, recv_handle) =
        spawn_data_receiver(data_recv, ingest_tx.clone(), bytes_received.clone(), recorded_by.to_string());

    let initial_msg = neg.initiate()?;
    control.send(&SyncMessage::NegOpen { msg: initial_msg }).await?;
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
    let mut coordination_pending = coordination.is_some(); // waiting for assignment
    let mut coordination_reported = false; // already sent report to coordinator

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
                info!("Reporting {} need_ids to coordinator (peer {})", report.len(), coord.peer_idx);
                let _ = coord.report_tx.send(report);
                coordination_reported = true;
            }

            // Poll for assignment (non-blocking so push path continues)
            if coordination_pending && coordination_reported {
                match coord.assign_rx.try_recv() {
                    Ok(assigned) => {
                        info!("Received {} assigned events from coordinator (peer {})",
                            assigned.len(), coord.peer_idx);
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
                        // Coordinator gone; proceed without assignment
                        coordination_pending = false;
                    }
                }
            }
        }

        // Incrementally enqueue pending have_ids to egress queue.
        // Processes up to ENQUEUE_BATCH per iteration so streaming can interleave.
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
            let batch = egress.claim_batch(peer_id, EGRESS_CLAIM_COUNT, EGRESS_CLAIM_LEASE_MS).unwrap_or_default();
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
                info!("Sent DataDone+Done, waiting for DoneAck (sent {}, received {})",
                    events_sent, events_received.load(Ordering::Relaxed));
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
    // Use timeout fallback to avoid hanging if peer misbehaves.
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
    // Drop ingest_tx so batch_writer sees channel close and drains
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

    info!("Starting negentropy sync (responder, dual-stream) for {} seconds", timeout_secs);

    let db = open_connection(db_path)?;
    let neg_db = open_connection(db_path)?;

    let egress = EgressQueue::new(&db);
    let _ = egress.clear_connection(peer_id);

    let ws_id = lookup_workspace_id(&db, recorded_by);
    let neg_storage = NegentropyStorageSqlite::new(&neg_db, &ws_id);

    neg_db.execute("BEGIN", []).map_err(|e| format!("Failed to begin snapshot: {}", e))?;
    neg_storage.rebuild_blocks().map_err(|e| format!("Failed to rebuild blocks: {}", e))?;

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

    let (shutdown_tx, data_drained_rx, recv_handle) =
        spawn_data_receiver(data_recv, ingest_tx.clone(), bytes_received.clone(), recorded_by.to_string());

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
            let batch = egress.claim_batch(peer_id, EGRESS_CLAIM_COUNT, EGRESS_CLAIM_LEASE_MS).unwrap_or_default();
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
                // Signal peer's data receiver that we're done sending events
                let _ = data_send.flush().await;
                data_send.send(&SyncMessage::DataDone).await?;
                data_send.flush().await?;

                // Wait for our data receiver to confirm peer's DataDone
                let drain_timeout = DATA_DRAIN_TIMEOUT;
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
        let _ = egress.clear_connection(peer_id);
        let _ = egress.cleanup_sent(EGRESS_SENT_TTL_MS);
    }
    let _ = neg_db.execute("COMMIT", []);
    let _ = shutdown_tx.send(());
    let _ = recv_handle.await;
    // Drop ingest_tx so batch_writer sees channel close and drains
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

/// Accept incoming connections and run responder sync sessions.
///
/// Each incoming connection is handled on its own thread so multiple sources
/// can sync simultaneously. A shared ingress dedup set prevents redundant
/// batch_writer processing when multiple sources offer the same event.
pub async fn accept_loop(
    db_path: &str,
    recorded_by: &str,
    endpoint: quinn::Endpoint,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Shared batch_writer: single writer thread for all concurrent responder sessions.
    // Eliminates SQLite WAL contention from multiple writers hitting the same DB.
    let ingest_cap = shared_ingest_cap();
    let (shared_ingest_tx, shared_ingest_rx) = mpsc::channel::<IngestItem>(ingest_cap);
    let shared_events_received = Arc::new(AtomicU64::new(0));
    let writer_events = shared_events_received.clone();
    let writer_db_path = db_path.to_string();
    let _writer_handle = std::thread::spawn(move || {
        batch_writer(writer_db_path, shared_ingest_rx, writer_events);
    });

    let tenant_ids = vec![recorded_by.to_string()];
    accept_loop_with_ingest(db_path, &tenant_ids, endpoint, None, shared_ingest_tx).await
}

/// Accept incoming connections using an externally-provided ingest channel.
///
/// Same as `accept_loop` but takes a pre-existing `Sender<IngestItem>` instead
/// of spawning its own batch_writer. Used by the multi-tenant node daemon so
/// all tenants share a single writer thread.
///
/// `tenant_peer_ids` lists local tenants. After TLS handshake, the remote
/// peer's SPKI fingerprint is checked against each tenant's trust set to
/// determine the `recorded_by` for that connection.
pub async fn accept_loop_with_ingest(
    db_path: &str,
    tenant_peer_ids: &[String],
    endpoint: quinn::Endpoint,
    _allowed_peers: Option<crate::transport::AllowedPeers>,
    shared_ingest_tx: mpsc::Sender<IngestItem>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
        let purged = purge_expired_endpoints(&db, current_timestamp_ms()).unwrap_or(0);
        if purged > 0 {
            info!("Purged {} expired endpoint observations", purged);
        }
        let pq = ProjectQueue::new(&db);
        let recovered = pq.recover_expired().unwrap_or(0);
        if recovered > 0 {
            info!("Recovered {} expired project_queue leases", recovered);
        }
        // Drain pending project_queue items for ALL tenants
        let batch_sz = drain_batch_size();
        for tenant_id in tenant_peer_ids {
            let tid = tenant_id.clone();
            let drained = pq.drain_with_limit(&tid, batch_sz, |conn, event_id_b64| {
                if let Some(eid) = event_id_from_base64(event_id_b64) {
                    project_one(conn, &tid, &eid)
                        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
                }
                Ok(())
            }).unwrap_or(0);
            if drained > 0 {
                info!("Processed {} pending project_queue items for tenant {}", drained, &tenant_id[..16.min(tenant_id.len())]);
            }
        }
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

        // Resolve which local tenant trusts this peer (post-handshake routing)
        let recorded_by = resolve_tenant_for_peer(db_path, tenant_peer_ids, &peer_id);
        let recorded_by = match recorded_by {
            Some(rb) => rb,
            None => {
                // TLS already verified trust at the transport level, so this
                // shouldn't happen in normal operation. Fall back to first tenant.
                warn!("No tenant matched peer {} post-handshake, using first tenant", &peer_id[..16.min(peer_id.len())]);
                tenant_peer_ids[0].clone()
            }
        };

        // Record endpoint observation, transport binding, and purge expired
        {
            let remote = connection.remote_address();
            let now = current_timestamp_ms();
            if let Ok(db) = open_connection(db_path) {
                let _ = record_endpoint_observation(
                    &db,
                    &recorded_by,
                    &peer_id,
                    &remote.ip().to_string(),
                    remote.port(),
                    now,
                    ENDPOINT_TTL_MS,
                );
                if let Ok(spki_bytes) = hex::decode(&peer_id) {
                    if spki_bytes.len() == 32 {
                        let mut fp = [0u8; 32];
                        fp.copy_from_slice(&spki_bytes);
                        let _ = record_transport_binding(&db, &recorded_by, &peer_id, &fp);
                    }
                }
                let purged = purge_expired_endpoints(&db, now).unwrap_or(0);
                if purged > 0 {
                    info!("Purged {} expired endpoint observations", purged);
                }
            }
        }

        // Spawn a thread for this connection so multiple sources sync concurrently.
        // Uses LocalSet so the intro listener (spawn_local) can run alongside
        // the responder sync sessions on the same runtime.
        let db_path_owned = db_path.to_string();
        let recorded_by_owned = recorded_by;
        let ingest_clone = shared_ingest_tx.clone();
        let intro_endpoint = endpoint.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let local = tokio::task::LocalSet::new();
            rt.block_on(local.run_until(async move {
                // Spawn intro listener for uni-streams on this connection
                crate::sync::punch::spawn_intro_listener(
                    connection.clone(),
                    db_path_owned.clone(),
                    recorded_by_owned.clone(),
                    peer_id.clone(),
                    intro_endpoint,
                );

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

                    if let Err(e) = run_sync_responder_dual(
                        conn, &db_path_owned, SYNC_SESSION_TIMEOUT_SECS, &peer_id, &recorded_by_owned,
                        Some(ingest_clone.clone()),
                    ).await {
                        warn!("Responder session error: {}", e);
                    }

                    tokio::time::sleep(SESSION_GAP).await;
                }
            }));
        });
    }
}

/// Resolve which local tenant trusts a given remote peer.
///
/// Checks `is_peer_allowed` for each tenant. Returns the first tenant that
/// trusts the peer, or `None` if no tenant matches.
fn resolve_tenant_for_peer(
    db_path: &str,
    tenant_peer_ids: &[String],
    remote_peer_id: &str,
) -> Option<String> {
    let peer_fp_bytes = hex::decode(remote_peer_id).ok()?;
    if peer_fp_bytes.len() != 32 {
        return None;
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&peer_fp_bytes);

    let db = open_connection(db_path).ok()?;
    for tenant_id in tenant_peer_ids {
        if crate::db::transport_trust::is_peer_allowed(&db, tenant_id, &fp).unwrap_or(false) {
            return Some(tenant_id.clone());
        }
    }
    None
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
        let purged = purge_expired_endpoints(&db, current_timestamp_ms()).unwrap_or(0);
        if purged > 0 {
            info!("Purged {} expired endpoint observations", purged);
        }
        let pq = ProjectQueue::new(&db);
        let recovered = pq.recover_expired().unwrap_or(0);
        if recovered > 0 {
            info!("Recovered {} expired project_queue leases", recovered);
        }
        let recorded_by_str = recorded_by.to_string();
        let batch_sz = drain_batch_size();
        let drained = pq.drain_with_limit(&recorded_by_str, batch_sz, |conn, event_id_b64| {
            if let Some(eid) = event_id_from_base64(event_id_b64) {
                project_one(conn, &recorded_by_str, &eid)
                    .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
            }
            Ok(())
        }).unwrap_or(0);
        if drained > 0 {
            info!("Processed {} pending project_queue items from previous session", drained);
        }
    }

    // Use LocalSet so the intro listener (spawn_intro_listener uses spawn_local)
    // can run on the same runtime that drives the endpoint I/O.
    let local = tokio::task::LocalSet::new();
    local.run_until(connect_loop_inner(db_path, recorded_by, endpoint, remote)).await
}

async fn connect_loop_inner(
    db_path: &str,
    recorded_by: &str,
    endpoint: quinn::Endpoint,
    remote: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Look up workspace SNI for this tenant (falls back to "localhost" if no trust anchor)
    let sni = {
        let db = open_connection(db_path)?;
        let ws_id = lookup_workspace_id(&db, recorded_by);
        if ws_id.is_empty() {
            "localhost".to_string()
        } else {
            crate::transport::multi_workspace::workspace_sni(&ws_id)
        }
    };

    loop {
        info!("Connecting to {}...", remote);
        let connection = match endpoint.connect(remote, &sni) {
            Ok(connecting) => match connecting.await {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to connect to {}: {}", remote, e);
                    tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                    continue;
                }
            },
            Err(e) => {
                warn!("Failed to initiate connection to {}: {}", remote, e);
                tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                continue;
            }
        };
        let peer_id = match peer_identity_from_connection(&connection) {
            Some(id) => id,
            None => {
                warn!("Could not extract peer identity, retrying...");
                tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                continue;
            }
        };
        info!("Connected to {}", peer_id);

        // Record endpoint observation, transport binding, and purge expired
        {
            let remote_addr = connection.remote_address();
            let now = current_timestamp_ms();
            if let Ok(db) = open_connection(db_path) {
                let _ = record_endpoint_observation(
                    &db,
                    recorded_by,
                    &peer_id,
                    &remote_addr.ip().to_string(),
                    remote_addr.port(),
                    now,
                    ENDPOINT_TTL_MS,
                );
                // Record transport binding (peer_id is hex SPKI fingerprint)
                if let Ok(spki_bytes) = hex::decode(&peer_id) {
                    if spki_bytes.len() == 32 {
                        let mut fp = [0u8; 32];
                        fp.copy_from_slice(&spki_bytes);
                        let _ = record_transport_binding(&db, recorded_by, &peer_id, &fp);
                    }
                }
                let purged = purge_expired_endpoints(&db, now).unwrap_or(0);
                if purged > 0 {
                    info!("Purged {} expired endpoint observations", purged);
                }
            }
        }

        // Spawn intro listener for uni-streams on this connection
        let _intro_handle = crate::sync::punch::spawn_intro_listener(
            connection.clone(),
            db_path.to_string(),
            recorded_by.to_string(),
            peer_id.clone(),
            endpoint.clone(),
        );

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

            if let Err(e) = run_sync_initiator_dual(
                conn, db_path, SYNC_SESSION_TIMEOUT_SECS, &peer_id, recorded_by, None, None,
            ).await {
                warn!("Initiator session error: {}", e);
            }

            tokio::time::sleep(SESSION_GAP).await;
        }
    }
}

/// Download from multiple sources concurrently (sink as initiator).
///
/// Uses coordinated round-based assignment: each sync round, peers report
/// their discovered need_ids to a coordinator thread, which assigns events
/// to peers using greedy load balancing (least-loaded peer that has the event).
/// Undelivered events re-appear as need_ids in the next round and get
/// reassigned — slow peers don't block downloads permanently.
///
/// A shared batch_writer handles all incoming events from all sources.
pub async fn download_from_sources(
    db_path: &str,
    recorded_by: &str,
    endpoints: Vec<(quinn::Endpoint, SocketAddr)>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
    }

    let total = endpoints.len();

    // Shared batch_writer: single writer for all source connections
    let ingest_cap = shared_ingest_cap();
    let (shared_tx, shared_rx) = mpsc::channel::<IngestItem>(ingest_cap);
    let shared_events = Arc::new(AtomicU64::new(0));
    let writer_events = shared_events.clone();
    let writer_db_path = db_path.to_string();
    let _writer_handle = std::thread::spawn(move || {
        batch_writer(writer_db_path, shared_rx, writer_events);
    });

    // Create per-peer coordination channels
    let mut peer_coords = Vec::new();
    let mut report_rxs = Vec::new();
    let mut assign_txs = Vec::new();

    for i in 0..total {
        let (report_tx, report_rx) = std::sync::mpsc::channel::<Vec<EventId>>();
        let (assign_tx, assign_rx) = std::sync::mpsc::channel::<Vec<EventId>>();
        peer_coords.push(PeerCoord {
            peer_idx: i,
            report_tx,
            assign_rx,
        });
        report_rxs.push(report_rx);
        assign_txs.push(assign_tx);
    }

    // Spawn coordinator thread
    let _coord_handle = std::thread::spawn(move || {
        run_coordinator(report_rxs, assign_txs);
    });

    let mut handles = Vec::new();

    // Look up workspace SNI once for all peers
    let download_sni = {
        let db = open_connection(db_path)?;
        let ws_id = lookup_workspace_id(&db, recorded_by);
        if ws_id.is_empty() {
            "localhost".to_string()
        } else {
            crate::transport::multi_workspace::workspace_sni(&ws_id)
        }
    };

    for (peer_coord, (endpoint, remote)) in peer_coords.into_iter().zip(endpoints.into_iter()) {
        let db_path = db_path.to_string();
        let recorded_by = recorded_by.to_string();
        let ingest_tx = shared_tx.clone();
        let sni = download_sni.clone();

        handles.push(std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                loop {
                    let connection = match endpoint.connect(remote, &sni) {
                        Ok(connecting) => match connecting.await {
                            Ok(c) => c,
                            Err(e) => {
                                warn!("Failed to connect to {}: {}", remote, e);
                                tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                                continue;
                            }
                        },
                        Err(e) => {
                            warn!("Failed to initiate connection to {}: {}", remote, e);
                            tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                            continue;
                        }
                    };
                    let peer_id = match peer_identity_from_connection(&connection) {
                        Some(id) => id,
                        None => {
                            warn!("Could not extract peer identity, retrying...");
                            tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                            continue;
                        }
                    };
                    info!("Connected to {} for download", peer_id);

                    // Inner loop: repeated sync sessions
                    loop {
                        let (ctrl_send, ctrl_recv) = match connection.open_bi().await {
                            Ok(s) => s,
                            Err(e) => {
                                info!("Connection dropped (control): {}", e);
                                break;
                            }
                        };
                        let (data_send, data_recv) = match connection.open_bi().await {
                            Ok(s) => s,
                            Err(e) => {
                                info!("Connection dropped (data): {}", e);
                                break;
                            }
                        };
                        let mut conn = DualConnection::new(
                            ctrl_send, ctrl_recv, data_send, data_recv,
                        );

                        let _ = conn.control.send(&SyncMessage::HaveList { ids: vec![] }).await;
                        let _ = conn.data_send.send(&SyncMessage::HaveList { ids: vec![] }).await;
                        let _ = conn.flush_control().await;
                        let _ = conn.flush_data().await;

                        if let Err(e) = run_sync_initiator_dual(
                            conn, &db_path, SYNC_SESSION_TIMEOUT_SECS, &peer_id, &recorded_by,
                            Some(&peer_coord), Some(ingest_tx.clone()),
                        ).await {
                            warn!("Download session error: {}", e);
                        }

                        tokio::time::sleep(SESSION_GAP).await;
                    }
                }
            });
        }));
    }

    // Drop our copy so writer exits when all sessions drop theirs
    drop(shared_tx);

    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}
