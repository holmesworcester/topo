//! Connect-side loops: outbound QUIC connections and initiator sync sessions.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::health::{purge_expired_endpoints, record_endpoint_observation};
use crate::db::open_connection;
use crate::db::store::lookup_workspace_id;
use crate::db::transport_trust::record_transport_binding;
use crate::sync::CoordinationManager;
use crate::sync::SyncSessionHandler;
use crate::transport::{
    dial_session_provider, derive_bootstrap_dial_context, BootstrapDialMode,
    ConnectionLifecycleError, SessionProvider, TransportClientConfig, TransportEndpoint,
};

use super::supervisor::{
    run_startup_preflight, spawn_shared_ingest_writer, supervise_connection_sessions,
    SessionTenantResolver,
};
use super::{
    current_timestamp_ms, peer_fingerprint_from_hex, IntroSpawnerFn, CONNECT_RETRY_DELAY,
    ENDPOINT_TTL_MS, SYNC_SESSION_TIMEOUT_SECS,
};

// ---------------------------------------------------------------------------
// Connect loops
// ---------------------------------------------------------------------------

/// Connect to a remote peer and run initiator sync sessions.
///
/// Outer loop reconnects on connection drop. Inner loop runs repeated
/// sync sessions on the same connection.
///
/// When `client_config` is `Some`, outbound dials present the correct per-tenant
/// cert and tenant-scoped trust.
///
/// The initiator participates in coordinated multi-source download: need_ids
/// are reported to a coordinator thread that assigns events via greedy load
/// balancing across all peers sharing the same coordinator. For single-peer
/// scenarios the coordinator degenerates to pass-through assignment.
pub async fn connect_loop(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    remote: SocketAddr,
    client_config: Option<TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Default connect loop path is coordinated as well: a single-peer
    // coordinator degenerates to pass-through assignment but keeps one
    // initiator behavior across tests and runtime.
    let coordination_manager = Arc::new(CoordinationManager::new());
    connect_loop_with_coordination(
        db_path,
        recorded_by,
        endpoint,
        remote,
        client_config,
        intro_spawner,
        ingest,
        coordination_manager,
    )
    .await
}

/// Coordinated connect loop variant used by runtime target planners.
pub async fn connect_loop_with_coordination(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    remote: SocketAddr,
    client_config: Option<TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    coordination_manager: Arc<CoordinationManager>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    connect_loop_with_coordination_until_cancel(
        db_path,
        recorded_by,
        endpoint,
        remote,
        client_config,
        intro_spawner,
        ingest,
        coordination_manager,
        CancellationToken::new(),
    )
    .await
}

/// Coordinated connect loop with explicit cancellation.
pub async fn connect_loop_with_coordination_until_cancel(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    remote: SocketAddr,
    client_config: Option<TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    coordination_manager: Arc<CoordinationManager>,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    connect_loop_with_coordination_until_cancel_with_fallback(
        db_path,
        recorded_by,
        endpoint,
        remote,
        client_config,
        intro_spawner,
        ingest,
        coordination_manager,
        shutdown,
        None,
    )
    .await
}

/// Coordinated connect loop with explicit cancellation and an optional
/// bootstrap-fallback client config.
pub async fn connect_loop_with_coordination_until_cancel_with_fallback(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    remote: SocketAddr,
    client_config: Option<TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    coordination_manager: Arc<CoordinationManager>,
    shutdown: CancellationToken,
    bootstrap_fallback_client_config: Option<TransportClientConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tenants = vec![recorded_by.to_string()];
    run_startup_preflight(db_path, &tenants, ingest)?;

    // Shared batch_writer: single writer thread for all outbound initiator
    // sessions on this connect loop.
    let shared_ingest = spawn_shared_ingest_writer(db_path, ingest);

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
            shared_ingest,
            coordination_manager,
            shutdown,
            bootstrap_fallback_client_config,
        ))
        .await
}

async fn connect_loop_inner(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    remote: SocketAddr,
    client_config: Option<TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    shared_ingest: tokio::sync::mpsc::Sender<crate::contracts::event_pipeline_contract::IngestItem>,
    coordination_manager: Arc<CoordinationManager>,
    shutdown: CancellationToken,
    bootstrap_fallback_client_config: Option<TransportClientConfig>,
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
    let initiator_handler = SyncSessionHandler::outbound(
        db_path.to_string(),
        SYNC_SESSION_TIMEOUT_SECS,
        coordination_manager,
        shared_ingest.clone(),
    );

    loop {
        if shutdown.is_cancelled() {
            break;
        }

        info!("Connecting to {}...", remote);
        let dial_outcome = match tokio::select! {
            _ = shutdown.cancelled() => {
                break;
            }
            outcome = dial_provider_ongoing_first(
                &endpoint,
                remote,
                &sni,
                client_config.as_ref(),
                bootstrap_fallback_client_config.as_ref(),
            ) => outcome,
        } {
            Ok(outcome) => outcome,
            Err(e) => {
                warn!("Failed to connect to {}: {}", remote, e);
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(CONNECT_RETRY_DELAY) => {}
                }
                continue;
            }
        };
        let provider = dial_outcome.provider;
        let used_bootstrap_fallback = dial_outcome.used_bootstrap_fallback;
        let connection = provider.connection();
        let peer_id = provider.peer_id().to_string();
        let peer_fp = match peer_fingerprint_from_hex(&peer_id) {
            Some(fp) => fp,
            None => {
                warn!(
                    "Could not decode peer fingerprint from identity {}, retrying...",
                    &peer_id[..16.min(peer_id.len())]
                );
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    _ = tokio::time::sleep(CONNECT_RETRY_DELAY) => {}
                }
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
            if used_bootstrap_fallback {
                bootstrap_fallback_client_config.clone()
            } else {
                client_config.clone()
            },
            shared_ingest.clone(),
        );

        // Keep session scope pinned to the planner-assigned tenant.
        // Transport cert rotation can lag tenant scoping during bootstrap.
        let tenant_resolver = SessionTenantResolver::Fixed(recorded_by.to_string());
        let max_sessions = if used_bootstrap_fallback {
            Some(1usize)
        } else {
            None
        };
        supervise_connection_sessions(
            db_path,
            &peer_id,
            peer_fp,
            &provider,
            &initiator_handler,
            SessionDirection::Outbound,
            &tenant_resolver,
            shutdown.clone(),
            max_sessions,
        )
        .await;
    }

    Ok(())
}

struct DialOutcome {
    provider: SessionProvider,
    used_bootstrap_fallback: bool,
}

async fn dial_provider_ongoing_first(
    endpoint: &TransportEndpoint,
    remote: SocketAddr,
    sni: &str,
    ongoing_client_config: Option<&TransportClientConfig>,
    bootstrap_fallback_client_config: Option<&TransportClientConfig>,
) -> Result<DialOutcome, ConnectionLifecycleError> {
    match dial_session_provider(endpoint, remote, sni, ongoing_client_config).await {
        Ok(provider) => Ok(DialOutcome {
            provider,
            used_bootstrap_fallback: false,
        }),
        Err(primary_err) => {
            let decision = derive_bootstrap_dial_context(
                Some(&primary_err),
                bootstrap_fallback_client_config.is_some(),
            );
            if decision.mode != BootstrapDialMode::BootstrapFallback {
                return Err(primary_err);
            }
            let Some(fallback_cfg) = bootstrap_fallback_client_config else {
                return Err(primary_err);
            };
            info!(
                "Primary mTLS dial to {} rejected by trust policy; retrying with bootstrap fallback cert",
                remote
            );
            match dial_session_provider(endpoint, remote, sni, Some(fallback_cfg)).await {
                Ok(provider) => Ok(DialOutcome {
                    provider,
                    used_bootstrap_fallback: true,
                }),
                Err(fallback_err) => Err(ConnectionLifecycleError::Dial(format!(
                    "primary and bootstrap-fallback dials failed to {}: primary={}, fallback={}",
                    remote, primary_err, fallback_err
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_policy_allows_typed_trust_rejection_with_fallback_cfg() {
        let err = ConnectionLifecycleError::DialTrustRejected(
            "handshake to 127.0.0.1:4433: trust_rejected: peer fingerprint deadbeef not in allowed set".to_string()
        );
        let decision = derive_bootstrap_dial_context(Some(&err), true);
        assert_eq!(decision.mode, BootstrapDialMode::BootstrapFallback);
    }

    #[test]
    fn fallback_policy_denies_generic_dial_errors() {
        let err =
            ConnectionLifecycleError::Dial("handshake to 127.0.0.1:4433: connection refused".to_string());
        let decision = derive_bootstrap_dial_context(Some(&err), true);
        assert_eq!(decision.mode, BootstrapDialMode::Deny);
    }

    #[test]
    fn fallback_policy_denies_trust_rejection_without_cfg() {
        let err = ConnectionLifecycleError::DialTrustRejected(
            "handshake to 127.0.0.1:4433: trust_rejected: peer fingerprint deadbeef not in allowed set".to_string()
        );
        let decision = derive_bootstrap_dial_context(Some(&err), false);
        assert_eq!(decision.mode, BootstrapDialMode::Deny);
    }
}
