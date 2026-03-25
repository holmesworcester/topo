//! Accept-side connection loops: incoming QUIC connections and responder
//! sync runs.

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::health::{purge_expired_endpoints, record_endpoint_observation};
use crate::db::open_connection;
use crate::db::transport_trust::record_transport_binding;
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::sync::SyncConnectionHandler;
use crate::transport::{
    accept_session_provider, read_inbound_session_auth, send_inbound_session_auth_ack,
    TransportClientConfig, TransportEndpoint,
};

use super::supervisor::{
    run_startup_preflight, supervise_connection_sessions, SessionTenantResolver,
};
use super::{
    claim_live_connection_slot, current_timestamp_ms, peer_fingerprint_from_hex, IntroSpawnerFn,
    ENDPOINT_TTL_MS, SYNC_SESSION_TIMEOUT_SECS,
};

const REPEATED_WARNING_WINDOW: Duration = Duration::from_secs(300);

// ---------------------------------------------------------------------------
// Accept loops
// ---------------------------------------------------------------------------

/// Accept incoming connections and run responder sync on each connection.
///
/// Each incoming connection is handled concurrently. A shared ingest writer
/// is used for all responder sessions.
pub async fn accept_loop(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tenant_ids = vec![recorded_by.to_string()];
    accept_loop_until_cancel_inner(
        db_path,
        &tenant_ids,
        endpoint,
        CancellationToken::new(),
        std::collections::HashMap::new(),
        intro_spawner,
        ingest,
        None,
    )
    .await
}

/// Cancellation-aware variant of [`accept_loop`] used by runtime supervision
/// so shutdown can deterministically await all workers.
///
/// `tenant_peer_ids` lists local tenants for startup preflight. After TLS
/// handshake, the requested local transport fingerprint from SNI is resolved
/// to exactly one tenant from projected local SQL state, and only that tenant
/// authorizes the authenticated remote fingerprint.
pub async fn accept_loop_until_cancel(
    db_path: &str,
    tenant_peer_ids: &[String],
    endpoint: TransportEndpoint,
    shutdown: CancellationToken,
    tenant_client_configs: std::collections::HashMap<String, TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    accept_loop_until_cancel_inner(
        db_path,
        tenant_peer_ids,
        endpoint,
        shutdown,
        tenant_client_configs,
        intro_spawner,
        ingest,
        sync_control,
    )
    .await
}

async fn accept_loop_until_cancel_inner(
    db_path: &str,
    tenant_peer_ids: &[String],
    endpoint: TransportEndpoint,
    shutdown: CancellationToken,
    tenant_client_configs: std::collections::HashMap<String, TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    struct ConnectionWorker {
        cancel: CancellationToken,
        join: std::thread::JoinHandle<()>,
    }

    run_startup_preflight(db_path, tenant_peer_ids, ingest)?;

    let mut connection_workers: Vec<ConnectionWorker> = Vec::new();
    let mut warning_gate = RepeatedWarningGate::new(REPEATED_WARNING_WINDOW);
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        info!("Waiting for incoming connection...");
        let mut provider = match tokio::select! {
            _ = shutdown.cancelled() => {
                break;
            }
            provider = accept_session_provider(&endpoint) => provider,
        } {
            Ok(Some(p)) => p,
            Ok(None) => {
                info!("Endpoint closed, stopping accept_loop");
                break;
            }
            Err(e) => {
                let message = describe_accept_failure(&e);
                if warning_gate.should_emit(message.clone())
                    && should_emit_globally(format!("accept:{message}"))
                {
                    warn!("{}", message);
                }
                continue;
            }
        };

        let connection = provider.connection();
        let auth_context = match read_inbound_session_auth(&connection, db_path).await {
            Ok(context) => context,
            Err(err) => {
                let message = format!(
                    "Rejected inbound session on connection {}: {}",
                    connection.stable_id(),
                    err
                );
                if warning_gate.should_emit(message.clone())
                    && should_emit_globally(format!("accept:{message}"))
                {
                    warn!("{}", message);
                }
                connection.close(1u32.into(), b"tenant-scoped auth failed");
                continue;
            }
        };
        if let Err(err) = send_inbound_session_auth_ack(&connection, &auth_context.tenant_id).await
        {
            let message = format!(
                "Rejected inbound session on connection {}: failed to send session auth ack: {}",
                connection.stable_id(),
                err
            );
            if warning_gate.should_emit(message.clone())
                && should_emit_globally(format!("accept:{message}"))
            {
                warn!("{}", message);
            }
            connection.close(1u32.into(), b"tenant-scoped auth ack failed");
            continue;
        }
        provider = provider.with_peer_id(auth_context.remote_peer_id.clone());
        let peer_id = provider.peer_id().to_string();
        info!(
            "Accepted connection from peer {} via daemon {} on connection {}",
            peer_id,
            auth_context.remote_daemon_peer_id,
            connection.stable_id()
        );
        let recorded_by = auth_context.tenant_id.clone();
        let connection_lease = match claim_live_connection_slot(
            db_path,
            &recorded_by,
            &peer_id,
            SessionDirection::Inbound,
            connection.clone(),
        ) {
            super::LiveConnectionClaim::Acquired(lease) => Some(lease),
            super::LiveConnectionClaim::Occupied(occupied) => {
                info!(
                    "Closing duplicate inbound connection from {} (active_direction={:?}, preferred_direction={:?})",
                    peer_id,
                    occupied.active_direction,
                    occupied.preferred_direction
                );
                connection.close(0u32.into(), b"duplicate peer connection");
                continue;
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
                if let Some(remote_daemon_fp) =
                    peer_fingerprint_from_hex(&auth_context.remote_daemon_peer_id)
                {
                    let _ =
                        record_transport_binding(&db, &recorded_by, &peer_id, &remote_daemon_fp);
                }
                let purged = purge_expired_endpoints(&db, now).unwrap_or(0);
                if purged > 0 {
                    info!("Purged {} expired endpoint observations", purged);
                }
            }
        }

        // Spawn a supervised worker for this accepted connection.
        let db_path_owned = db_path.to_string();
        let recorded_by_owned = recorded_by;
        let intro_endpoint = endpoint.clone();
        let intro_client_cfg = tenant_client_configs
            .get(&recorded_by_owned)
            .cloned()
            .or_else(|| {
                // Fallback: build config from DB for dynamically added tenants
                // whose client config wasn't in the startup-time map.
                crate::transport::build_tenant_client_config_from_db(db_path, &recorded_by_owned)
                    .ok()
            });
        let provider_owned = provider.clone();
        let peer_id_owned = peer_id.clone();
        let worker_shutdown = shutdown.child_token();
        let worker_cancel = worker_shutdown.clone();
        let sync_control_clone = sync_control.clone();

        let join = std::thread::spawn(move || {
            let _connection_lease = connection_lease;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("accept connection worker runtime");
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(async move {
                let mut worker_warning_gate = RepeatedWarningGate::new(REPEATED_WARNING_WINDOW);
                // Spawn intro listener for uni-streams on this connection.
                intro_spawner(
                    connection.clone(),
                    db_path_owned.clone(),
                    recorded_by_owned.clone(),
                    peer_id_owned.clone(),
                    intro_endpoint,
                    intro_client_cfg,
                );

                let peer_fp = match peer_fingerprint_from_hex(&peer_id_owned) {
                    Some(fp) => fp,
                    None => {
                        let message = format!(
                            "Invalid peer fingerprint on accepted connection: {}",
                            &peer_id_owned[..16.min(peer_id_owned.len())]
                        );
                        if worker_warning_gate.should_emit(message.clone())
                            && should_emit_globally(format!("accept:{message}"))
                        {
                            warn!("{}", message);
                        }
                        connection.close(1u32.into(), b"invalid peer fingerprint");
                        return;
                    }
                };

                let responder_handler = SyncConnectionHandler::responder(
                    db_path_owned.clone(),
                    SYNC_SESSION_TIMEOUT_SECS,
                )
                .with_sync_control(sync_control_clone.clone());
                let tenant_resolver = SessionTenantResolver::Fixed(recorded_by_owned.clone());

                supervise_connection_sessions(
                    &db_path_owned,
                    &peer_id_owned,
                    peer_fp,
                    &provider_owned,
                    &responder_handler,
                    SessionDirection::Inbound,
                    &tenant_resolver,
                    worker_shutdown,
                )
                .await;
            }));
        });

        connection_workers.push(ConnectionWorker {
            cancel: worker_cancel,
            join,
        });
    }

    endpoint.close(0u32.into(), b"runtime shutdown");
    for worker in connection_workers {
        worker.cancel.cancel();
        let join_result = tokio::task::spawn_blocking(move || worker.join.join()).await;
        match join_result {
            Ok(Ok(())) => {}
            Ok(Err(_)) => warn!("accept connection worker panicked"),
            Err(e) => warn!("accept connection worker join task error: {}", e),
        }
    }

    Ok(())
}

/// Produce a human-readable diagnosis for an inbound connection failure.
fn describe_accept_failure(err: &crate::transport::ConnectionLifecycleError) -> String {
    let msg = err.to_string();
    let m = msg.to_ascii_lowercase();
    if m.contains("trust_rejected") {
        // Extract the fingerprint
        let fp = msg
            .split("peer fingerprint ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("unknown");
        format!(
            "Rejected incoming connection: remote peer presented TLS fingerprint {} \
             which is not trusted by any local workspace. This is normal during bootstrap \
             when the remote peer's transport identity has not been derived yet",
            fp
        )
    } else if m.contains("connection reset") {
        "Incoming connection was reset by the remote peer before handshake completed".to_string()
    } else {
        format!("Failed to accept incoming connection: {}", msg)
    }
}
