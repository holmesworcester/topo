//! Connect-side loops: outbound QUIC connections and initiator sync sessions.

use std::net::SocketAddr;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::event_runtime_contract::{BatchWriterFn, IngestFns};
use crate::contracts::network_contract::{
    next_session_id, PeerFingerprint, SessionDirection, SessionHandler, SessionMeta, TenantId,
};
use crate::db::health::{purge_expired_endpoints, record_endpoint_observation};
use crate::db::open_connection;
use crate::db::project_queue::ProjectQueue;
use crate::db::removal_watch::is_peer_removed;
use crate::db::schema::create_tables;
use crate::db::store::lookup_workspace_id;
use crate::db::transport_trust::record_transport_binding;
use crate::sync::ReplicationSessionHandler;
use crate::transport::{peer_identity_from_connection, DualConnection, QuicTransportSessionIo};

use super::{
    current_timestamp_ms, drain_batch_size, peer_fingerprint_from_hex,
    spawn_peer_removal_cancellation_watch, IntroSpawnerFn, CONNECT_RETRY_DELAY, ENDPOINT_TTL_MS,
    SESSION_GAP, SYNC_SESSION_TIMEOUT_SECS,
};

// ---------------------------------------------------------------------------
// Connect loops
// ---------------------------------------------------------------------------

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
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
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
        let drained = (ingest.drain_queue)(db_path, recorded_by, batch_sz);
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
            intro_spawner,
            ingest.batch_writer,
        ))
        .await
}

async fn connect_loop_inner(
    db_path: &str,
    recorded_by: &str,
    endpoint: quinn::Endpoint,
    remote: SocketAddr,
    client_config: Option<quinn::ClientConfig>,
    intro_spawner: IntroSpawnerFn,
    batch_writer_fn: BatchWriterFn,
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
        ReplicationSessionHandler::initiator(db_path.to_string(), SYNC_SESSION_TIMEOUT_SECS, batch_writer_fn);

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
        let _intro_handle = intro_spawner(
            connection.clone(),
            db_path.to_string(),
            recorded_by.to_string(),
            peer_id.clone(),
            endpoint.clone(),
            client_config.clone(),
            batch_writer_fn,
        );

        // Inner loop: repeated sync sessions on this connection
        loop {
            // Check if peer has been removed -- deny further sessions
            if let Ok(db) = open_connection(db_path) {
                if is_peer_removed(&db, recorded_by, &peer_fp).unwrap_or(false) {
                    warn!(
                        "Peer {} has been removed -- closing connection",
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
            let conn = DualConnection::new(ctrl_send, ctrl_recv, data_send, data_recv);

            let session_id = next_session_id();
            let meta = SessionMeta {
                session_id,
                tenant: TenantId(recorded_by.to_string()),
                peer: PeerFingerprint(peer_fp),
                remote_addr: connection.remote_address(),
                direction: SessionDirection::Outbound,
            };
            let io = QuicTransportSessionIo::new(session_id, conn);
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
