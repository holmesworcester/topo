//! Accept-side connection loops: incoming QUIC connections and responder
//! sync sessions.

use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::health::{purge_expired_endpoints, record_endpoint_observation};
use crate::db::open_connection;
use crate::db::transport_trust::record_transport_binding;
use crate::sync::SyncSessionHandler;
use crate::transport::{
    accept_session_provider, resolve_trusting_tenant, TransportClientConfig, TransportEndpoint,
};

use super::supervisor::{
    run_startup_preflight, spawn_shared_ingest_writer, supervise_connection_sessions,
    SessionTenantResolver,
};
use super::{
    current_timestamp_ms, peer_fingerprint_from_hex, IntroSpawnerFn, ENDPOINT_TTL_MS,
    SYNC_SESSION_TIMEOUT_SECS,
};

// ---------------------------------------------------------------------------
// Accept loops
// ---------------------------------------------------------------------------

/// Accept incoming connections and run responder sync sessions.
///
/// Each incoming connection is handled on its own thread so multiple sources
/// can sync simultaneously. A shared ingress dedup set prevents redundant
/// batch_writer processing when multiple sources offer the same event.
pub async fn accept_loop(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Shared batch_writer: single writer thread for all concurrent responder sessions.
    let shared_ingest_tx = spawn_shared_ingest_writer(db_path, ingest);

    let tenant_ids = vec![recorded_by.to_string()];
    accept_loop_with_ingest(
        db_path,
        &tenant_ids,
        endpoint,
        None,
        shared_ingest_tx,
        std::collections::HashMap::new(),
        intro_spawner,
        ingest,
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
    endpoint: TransportEndpoint,
    _allowed_peers: Option<crate::transport::AllowedPeers>,
    shared_ingest_tx: tokio::sync::mpsc::Sender<
        crate::contracts::event_pipeline_contract::IngestItem,
    >,
    tenant_client_configs: std::collections::HashMap<String, TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_startup_preflight(db_path, tenant_peer_ids, ingest)?;

    loop {
        info!("Waiting for incoming connection...");
        let provider = match accept_session_provider(&endpoint).await {
            Ok(Some(p)) => p,
            Ok(None) => {
                info!("Endpoint closed, stopping accept_loop");
                return Ok(());
            }
            Err(e) => {
                warn!("Failed to accept connection: {}", e);
                continue;
            }
        };
        let connection = provider.connection();
        let peer_id = provider.peer_id().to_string();
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
                intro_spawner(
                    connection.clone(),
                    db_path_owned.clone(),
                    recorded_by_owned.clone(),
                    peer_id.clone(),
                    intro_endpoint,
                    intro_client_cfg,
                    ingest_clone.clone(),
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
                let responder_handler = SyncSessionHandler::responder(
                    db_path_owned.clone(),
                    SYNC_SESSION_TIMEOUT_SECS,
                    ingest_clone.clone(),
                );
                let tenant_resolver = SessionTenantResolver::Fixed(recorded_by_owned.clone());

                supervise_connection_sessions(
                    &db_path_owned,
                    &peer_id,
                    peer_fp,
                    &provider,
                    &responder_handler,
                    SessionDirection::Inbound,
                    &tenant_resolver,
                )
                .await;
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
    resolve_trusting_tenant(db_path, tenant_peer_ids, fp)
        .ok()
        .flatten()
}
