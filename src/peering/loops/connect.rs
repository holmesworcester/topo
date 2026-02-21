//! Connect-side loops: outbound QUIC connections and initiator sync sessions.

use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::{IngestFns, IngestItem};
use crate::contracts::peering_contract::SessionDirection;
use crate::db::health::{purge_expired_endpoints, record_endpoint_observation};
use crate::db::open_connection;
use crate::db::project_queue::ProjectQueue;
use crate::db::removal_watch::is_peer_removed;
use crate::db::schema::create_tables;
use crate::db::store::lookup_workspace_id;
use crate::db::transport_trust::record_transport_binding;
use crate::sync::SyncSessionHandler;
use crate::transport::peer_identity_from_connection;

use super::{
    current_timestamp_ms, drain_batch_size, peer_fingerprint_from_hex, run_session,
    shared_ingest_cap, IntroSpawnerFn, CONNECT_RETRY_DELAY, ENDPOINT_TTL_MS,
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

    // Shared batch_writer: single writer thread for all outbound initiator
    // sessions on this connect loop. Eliminates per-session writer overhead
    // and SQLite WAL contention.
    let ingest_cap = shared_ingest_cap();
    let (shared_tx, shared_rx) = mpsc::channel::<IngestItem>(ingest_cap);
    let shared_events = Arc::new(AtomicU64::new(0));
    let writer_events = shared_events.clone();
    let writer_db = db_path.to_string();
    let bw = ingest.batch_writer;
    let _writer_handle = std::thread::spawn(move || {
        bw(writer_db, shared_rx, writer_events);
    });

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
            shared_tx,
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
    shared_ingest: mpsc::Sender<IngestItem>,
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
        SyncSessionHandler::initiator(db_path.to_string(), SYNC_SESSION_TIMEOUT_SECS, shared_ingest.clone());

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
            shared_ingest.clone(),
        );

        // Inner loop: repeated sync sessions on this connection
        loop {
            // Reload current transport peer_id: after identity transition
            // (invite-derived → PeerShared-derived), migrate_recorded_by moves
            // all rows to the new peer_id. The sync session must use the
            // current peer_id to find events.
            let current_rb = if let Ok(db) = open_connection(db_path) {
                crate::transport::identity::load_transport_peer_id(&db)
                    .unwrap_or_else(|_| recorded_by.to_string())
            } else {
                recorded_by.to_string()
            };

            // Check if peer has been removed -- deny further sessions
            if let Ok(db) = open_connection(db_path) {
                if is_peer_removed(&db, &current_rb, &peer_fp).unwrap_or(false) {
                    warn!(
                        "Peer {} has been removed -- closing connection",
                        &peer_id[..16.min(peer_id.len())]
                    );
                    connection.close(2u32.into(), b"peer removed");
                    break;
                }
            }

            let ctrl = match connection.open_bi().await {
                Ok(streams) => streams,
                Err(e) => {
                    info!("Connection dropped (control open): {}", e);
                    break;
                }
            };
            let data = match connection.open_bi().await {
                Ok(streams) => streams,
                Err(e) => {
                    info!("Connection dropped (data open): {}", e);
                    break;
                }
            };

            run_session(
                &initiator_handler,
                ctrl,
                data,
                &current_rb,
                peer_fp,
                connection.remote_address(),
                SessionDirection::Outbound,
                db_path,
            )
            .await;

            tokio::time::sleep(SESSION_GAP).await;
        }
    }
}
