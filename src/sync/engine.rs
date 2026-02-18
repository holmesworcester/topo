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
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::network_contract::{
    PeerFingerprint, SessionDirection, SessionHandler, SessionMeta, TenantId, TrustDecision,
};
use crate::crypto::EventId;
use crate::db::health::{purge_expired_endpoints, record_endpoint_observation};
use crate::db::removal_watch::is_peer_removed;
use crate::db::transport_trust::record_transport_binding;
use crate::db::{
    open_connection,
    project_queue::ProjectQueue,
    schema::create_tables,
    store::lookup_workspace_id,
};
use crate::event_runtime::drain_project_queue;
use crate::sync::session_handler::{next_session_id, LegacySyncSessionHandler};
use crate::sync::SyncMessage;
use crate::transport::{
    peer_identity_from_connection, DualConnection, SqliteTrustOracle, SyncSessionIo,
};

// TRANSITIONAL: re-exports from event_runtime for existing test callers
pub use crate::event_runtime::{batch_writer, IngestItem};

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

fn peer_fingerprint_from_hex(peer_id: &str) -> Option<[u8; 32]> {
    let peer_fp_bytes = hex::decode(peer_id).ok()?;
    if peer_fp_bytes.len() != 32 {
        return None;
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&peer_fp_bytes);
    Some(fp)
}

fn spawn_peer_removal_cancellation_watch(
    db_path: String,
    recorded_by: String,
    peer_fp: [u8; 32],
    cancel: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::task::spawn_local(async move {
        loop {
            if cancel.is_cancelled() {
                break;
            }
            if let Ok(db) = open_connection(&db_path) {
                if is_peer_removed(&db, &recorded_by, &peer_fp).unwrap_or(false) {
                    cancel.cancel();
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
}

// ---------------------------------------------------------------------------
// Tuning constants (orchestration-level only; session constants live in
// replication::session)
// ---------------------------------------------------------------------------

/// Endpoint observation TTL: 24 hours in milliseconds.
const ENDPOINT_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Negentropy session timeout for initiator and responder (seconds).
pub const SYNC_SESSION_TIMEOUT_SECS: u64 = 60;

/// Sleep between consecutive sync sessions on the same connection.
const SESSION_GAP: Duration = Duration::from_millis(100);

/// Sleep after a failed QUIC connection attempt before retrying.
const CONNECT_RETRY_DELAY: Duration = Duration::from_secs(1);

// -- Batch writer sizing --

/// Batch writer drain batch size: 100 normal, 50 in low_mem.
fn drain_batch_size() -> usize {
    if low_mem_mode() {
        50
    } else {
        100
    }
}

/// Async channel capacity for shared ingest (accept_loop / download_from_sources).
fn shared_ingest_cap() -> usize {
    if low_mem_mode() {
        1000
    } else {
        10000
    }
}

// TRANSITIONAL: re-exports from replication::session for existing callers
pub use crate::replication::session::{
    run_sync_initiator_dual, run_sync_responder_dual, spawn_data_receiver, PeerCoord,
};
use crate::replication::session::run_coordinator;

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
    accept_loop_with_ingest(
        db_path,
        &tenant_ids,
        endpoint,
        None,
        shared_ingest_tx,
        std::collections::HashMap::new(),
    )
    .await
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
    tenant_client_configs: std::collections::HashMap<String, quinn::ClientConfig>,
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
            let drained = drain_project_queue(db_path, tenant_id, batch_sz);
            if drained > 0 {
                info!(
                    "Processed {} pending project_queue items for tenant {}",
                    drained,
                    &tenant_id[..16.min(tenant_id.len())]
                );
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

        // Resolve which local tenant owns this connection.
        // Single-tenant: TLS already verified trust; only one routing choice.
        // Multi-tenant: check SQL trust tables to determine which tenant.
        let recorded_by = if tenant_peer_ids.len() == 1 {
            tenant_peer_ids[0].clone()
        } else {
            match resolve_tenant_for_peer(db_path, tenant_peer_ids, &peer_id) {
                Some(rb) => rb,
                None => {
                    warn!(
                        "Rejected peer {}: no local tenant trusts this fingerprint",
                        &peer_id[..16.min(peer_id.len())]
                    );
                    connection.close(1u32.into(), b"no matching tenant");
                    continue;
                }
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
                if let Some(fp) = peer_fingerprint_from_hex(&peer_id) {
                    let _ = record_transport_binding(&db, &recorded_by, &peer_id, &fp);
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
        let intro_client_cfg = tenant_client_configs.get(&recorded_by_owned).cloned();
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
                    intro_client_cfg,
                );

                let peer_fp = match peer_fingerprint_from_hex(&peer_id) {
                    Some(fp) => fp,
                    None => {
                        warn!(
                            "Invalid peer fingerprint on accepted connection: {}",
                            &peer_id[..16.min(peer_id.len())]
                        );
                        connection.close(1u32.into(), b"invalid peer fingerprint");
                        return;
                    }
                };
                let responder_handler = LegacySyncSessionHandler::responder_with_shared_ingest(
                    db_path_owned.clone(),
                    SYNC_SESSION_TIMEOUT_SECS,
                    ingest_clone.clone(),
                );

                loop {
                    // Check if peer has been removed — deny further sessions
                    // and close the connection.
                    if let Ok(db) = open_connection(&db_path_owned) {
                        if is_peer_removed(&db, &recorded_by_owned, &peer_fp).unwrap_or(false) {
                            warn!(
                                "Peer {} has been removed — closing connection",
                                &peer_id[..16.min(peer_id.len())]
                            );
                            connection.close(2u32.into(), b"peer removed");
                            break;
                        }
                    }

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
                    let session_id = next_session_id();
                    let meta = SessionMeta {
                        session_id,
                        tenant: TenantId(recorded_by_owned.clone()),
                        peer: PeerFingerprint(peer_fp),
                        remote_addr: connection.remote_address(),
                        direction: SessionDirection::Inbound,
                    };
                    let io = SyncSessionIo::new(session_id, conn);
                    let cancel = CancellationToken::new();
                    let watch = spawn_peer_removal_cancellation_watch(
                        db_path_owned.clone(),
                        recorded_by_owned.clone(),
                        peer_fp,
                        cancel.clone(),
                    );

                    if let Err(e) = responder_handler
                        .on_session(meta, Box::new(io), cancel.clone())
                        .await
                    {
                        warn!("Responder session error: {}", e);
                    }
                    cancel.cancel();
                    let _ = watch.await;

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
    let fp = peer_fingerprint_from_hex(remote_peer_id)?;
    let oracle = SqliteTrustOracle::new(db_path);
    for tenant_id in tenant_peer_ids {
        if matches!(
            oracle.check_sync(&TenantId(tenant_id.clone()), &PeerFingerprint(fp)),
            Ok(TrustDecision::Allow)
        ) {
            return Some(tenant_id.clone());
        }
    }
    None
}

/// Connect to a remote peer and run initiator sync sessions.
///
/// Outer loop reconnects on connection drop. Inner loop runs repeated
/// sync sessions on the same connection.
///
/// When `client_config` is `Some`, outbound dials use `endpoint.connect_with()`
/// to present the correct per-tenant cert and tenant-scoped trust.
pub async fn connect_loop(
    db_path: &str,
    recorded_by: &str,
    endpoint: quinn::Endpoint,
    remote: SocketAddr,
    client_config: Option<quinn::ClientConfig>,
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
        let batch_sz = drain_batch_size();
        let drained = drain_project_queue(db_path, recorded_by, batch_sz);
        if drained > 0 {
            info!(
                "Processed {} pending project_queue items from previous session",
                drained
            );
        }
    }

    // Use LocalSet so the intro listener (spawn_intro_listener uses spawn_local)
    // can run on the same runtime that drives the endpoint I/O.
    let local = tokio::task::LocalSet::new();
    local
        .run_until(connect_loop_inner(
            db_path,
            recorded_by,
            endpoint,
            remote,
            client_config,
        ))
        .await
}

async fn connect_loop_inner(
    db_path: &str,
    recorded_by: &str,
    endpoint: quinn::Endpoint,
    remote: SocketAddr,
    client_config: Option<quinn::ClientConfig>,
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
    let initiator_handler =
        LegacySyncSessionHandler::initiator(db_path.to_string(), SYNC_SESSION_TIMEOUT_SECS);

    loop {
        info!("Connecting to {}...", remote);
        let connection = match if let Some(ref cfg) = client_config {
            endpoint.connect_with(cfg.clone(), remote, &sni)
        } else {
            endpoint.connect(remote, &sni)
        } {
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
        let peer_fp = match peer_fingerprint_from_hex(&peer_id) {
            Some(fp) => fp,
            None => {
                warn!(
                    "Could not decode peer fingerprint from identity {}, retrying...",
                    &peer_id[..16.min(peer_id.len())]
                );
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
                let _ = record_transport_binding(&db, recorded_by, &peer_id, &peer_fp);
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
            client_config.clone(),
        );

        // Inner loop: repeated sync sessions on this connection
        loop {
            // Check if peer has been removed — deny further sessions
            if let Ok(db) = open_connection(db_path) {
                if is_peer_removed(&db, recorded_by, &peer_fp).unwrap_or(false) {
                    warn!(
                        "Peer {} has been removed — closing connection",
                        &peer_id[..16.min(peer_id.len())]
                    );
                    connection.close(2u32.into(), b"peer removed");
                    break;
                }
            }

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
            conn.control
                .send(&SyncMessage::HaveList { ids: vec![] })
                .await?;
            conn.data_send
                .send(&SyncMessage::HaveList { ids: vec![] })
                .await?;
            conn.flush_control().await?;
            conn.flush_data().await?;

            let session_id = next_session_id();
            let meta = SessionMeta {
                session_id,
                tenant: TenantId(recorded_by.to_string()),
                peer: PeerFingerprint(peer_fp),
                remote_addr: connection.remote_address(),
                direction: SessionDirection::Outbound,
            };
            let io = SyncSessionIo::new(session_id, conn);
            let cancel = CancellationToken::new();
            let watch = spawn_peer_removal_cancellation_watch(
                db_path.to_string(),
                recorded_by.to_string(),
                peer_fp,
                cancel.clone(),
            );

            if let Err(e) = initiator_handler
                .on_session(meta, Box::new(io), cancel.clone())
                .await
            {
                warn!("Initiator session error: {}", e);
            }
            cancel.cancel();
            let _ = watch.await;

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
            assign_rx: std::sync::Mutex::new(assign_rx),
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
        let peer_coord = std::sync::Arc::new(peer_coord);
        let db_path = db_path.to_string();
        let recorded_by = recorded_by.to_string();
        let ingest_tx = shared_tx.clone();
        let sni = download_sni.clone();
        let handler = LegacySyncSessionHandler::initiator_with_coordination(
            db_path.clone(),
            SYNC_SESSION_TIMEOUT_SECS,
            peer_coord.clone(),
            Some(ingest_tx.clone()),
        );

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
                    let peer_fp = match peer_fingerprint_from_hex(&peer_id) {
                        Some(fp) => fp,
                        None => {
                            warn!(
                                "Invalid peer fingerprint {}, retrying",
                                &peer_id[..16.min(peer_id.len())]
                            );
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
                        let mut conn =
                            DualConnection::new(ctrl_send, ctrl_recv, data_send, data_recv);

                        let _ = conn
                            .control
                            .send(&SyncMessage::HaveList { ids: vec![] })
                            .await;
                        let _ = conn
                            .data_send
                            .send(&SyncMessage::HaveList { ids: vec![] })
                            .await;
                        let _ = conn.flush_control().await;
                        let _ = conn.flush_data().await;

                        let session_id = next_session_id();
                        let meta = SessionMeta {
                            session_id,
                            tenant: TenantId(recorded_by.clone()),
                            peer: PeerFingerprint(peer_fp),
                            remote_addr: connection.remote_address(),
                            direction: SessionDirection::Outbound,
                        };
                        let io = SyncSessionIo::new(session_id, conn);

                        if let Err(e) = handler
                            .on_session(meta, Box::new(io), CancellationToken::new())
                            .await
                        {
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
