//! Accept-side connection loops: incoming QUIC connections and responder
//! sync runs.

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::health::{purge_expired_endpoints, record_endpoint_observation};
use crate::db::open_connection;
use crate::db::transport_creds::resolve_local_transport_target;
use crate::db::transport_trust::{is_authorized_for_tenant, record_transport_binding};
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::sync::{CoordinationManager, SyncSessionHandler};
use crate::transport::{
    accept_session_provider, requested_server_name_from_connection, TransportClientConfig,
    TransportEndpoint,
};

use super::supervisor::{
    run_startup_preflight, spawn_shared_ingest_writer, supervise_connection_sessions,
    SessionTenantResolver,
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
    // Shared batch_writer: single writer thread for all concurrent responder sessions.
    let shared_ingest_tx = spawn_shared_ingest_writer(db_path, ingest);

    let tenant_ids = vec![recorded_by.to_string()];
    accept_loop_with_ingest_until_cancel_inner(
        db_path,
        &tenant_ids,
        endpoint,
        CancellationToken::new(),
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
/// `tenant_peer_ids` lists local tenants for startup preflight. After TLS
/// handshake, the requested local transport fingerprint from SNI is resolved
/// to exactly one tenant from projected local SQL state, and only that tenant
/// authorizes the authenticated remote fingerprint.
pub async fn accept_loop_with_ingest(
    db_path: &str,
    tenant_peer_ids: &[String],
    endpoint: TransportEndpoint,
    shared_ingest_tx: tokio::sync::mpsc::Sender<
        crate::contracts::event_pipeline_contract::IngestItem,
    >,
    tenant_client_configs: std::collections::HashMap<String, TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    accept_loop_with_ingest_until_cancel_inner(
        db_path,
        tenant_peer_ids,
        endpoint,
        CancellationToken::new(),
        shared_ingest_tx,
        tenant_client_configs,
        intro_spawner,
        ingest,
    )
    .await
}

/// Cancellation-aware variant of [`accept_loop_with_ingest`] used by runtime
/// supervision so shutdown can deterministically await all workers.
pub async fn accept_loop_with_ingest_until_cancel(
    db_path: &str,
    tenant_peer_ids: &[String],
    endpoint: TransportEndpoint,
    shutdown: CancellationToken,
    shared_ingest_tx: tokio::sync::mpsc::Sender<
        crate::contracts::event_pipeline_contract::IngestItem,
    >,
    tenant_client_configs: std::collections::HashMap<String, TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    accept_loop_with_ingest_until_cancel_inner(
        db_path,
        tenant_peer_ids,
        endpoint,
        shutdown,
        shared_ingest_tx,
        tenant_client_configs,
        intro_spawner,
        ingest,
    )
    .await
}

async fn accept_loop_with_ingest_until_cancel_inner(
    db_path: &str,
    tenant_peer_ids: &[String],
    endpoint: TransportEndpoint,
    shutdown: CancellationToken,
    shared_ingest_tx: tokio::sync::mpsc::Sender<
        crate::contracts::event_pipeline_contract::IngestItem,
    >,
    tenant_client_configs: std::collections::HashMap<String, TransportClientConfig>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    struct ConnectionWorker {
        cancel: CancellationToken,
        join: std::thread::JoinHandle<()>,
    }

    run_startup_preflight(db_path, tenant_peer_ids, ingest)?;

    let mut connection_workers: Vec<ConnectionWorker> = Vec::new();
    let mut warning_gate = RepeatedWarningGate::new(REPEATED_WARNING_WINDOW);
    let coordination_manager = std::sync::Arc::new(CoordinationManager::new());

    loop {
        if shutdown.is_cancelled() {
            break;
        }

        info!("Waiting for incoming connection...");
        let provider = match tokio::select! {
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
        let peer_id = provider.peer_id().to_string();
        info!(
            "Accepted connection from {} on connection {}",
            peer_id,
            connection.stable_id()
        );

        // Resolve which local tenant owns this connection.
        // Always resolve via trust tables — new tenants may have been
        // registered on the live endpoint since the accept loop started.
        let auth_context = match resolve_inbound_auth_context(db_path, &connection, &peer_id) {
            Ok(context) => context,
            Err(message) => {
                if warning_gate.should_emit(message.clone())
                    && should_emit_globally(format!("accept:{message}"))
                {
                    warn!("{}", message);
                }
                connection.close(1u32.into(), b"tenant-scoped auth failed");
                continue;
            }
        };
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
                if let Some(fp) = peer_fingerprint_from_hex(&peer_id) {
                    let _ = record_transport_binding(&db, &recorded_by, &peer_id, &fp);
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
        let ingest_clone = shared_ingest_tx.clone();
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
        let coordination_manager = coordination_manager.clone();

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
                    ingest_clone.clone(),
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

                let responder_handler = SyncSessionHandler::responder(
                    db_path_owned.clone(),
                    SYNC_SESSION_TIMEOUT_SECS,
                    coordination_manager.register_peer(),
                    ingest_clone.clone(),
                );
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct InboundAuthContext {
    requested_local_transport_peer_id: String,
    authenticated_remote_transport_peer_id: String,
    tenant_id: String,
}

/// Resolve the authenticated inbound transport boundary context.
///
/// The client must request one exact local transport fingerprint in SNI.
/// That fingerprint is resolved to one local tenant, and authorization is
/// checked only for that tenant using the authenticated remote certificate
/// fingerprint from the completed handshake.
fn resolve_inbound_auth_context(
    db_path: &str,
    connection: &crate::transport::TransportConnection,
    remote_peer_id: &str,
) -> Result<InboundAuthContext, String> {
    let requested = requested_transport_from_connection(connection).ok_or_else(|| {
        format!(
            "Rejected peer {}: missing exact transport-target SNI",
            short_peer_id(remote_peer_id)
        )
    })?;
    resolve_requested_tenant_for_peer(db_path, &requested, remote_peer_id)
}

fn requested_transport_from_connection(
    connection: &crate::transport::TransportConnection,
) -> Option<crate::transport::multi_workspace::TransportSniTarget> {
    let sni = requested_server_name_from_connection(connection)?;
    crate::transport::multi_workspace::parse_transport_sni(&sni)
}

fn resolve_requested_tenant_for_peer(
    db_path: &str,
    requested: &crate::transport::multi_workspace::TransportSniTarget,
    remote_peer_id: &str,
) -> Result<InboundAuthContext, String> {
    let remote_fp = peer_fingerprint_from_hex(remote_peer_id).ok_or_else(|| {
        format!(
            "Rejected peer {}: invalid transport fingerprint for tenant-scoped auth",
            short_peer_id(remote_peer_id)
        )
    })?;
    let db = open_connection(db_path).map_err(|e| {
        format!(
            "Failed to open auth DB for inbound tenant-scoped auth: {}",
            e
        )
    })?;
    let tenant = resolve_local_transport_target(&db, &requested.transport_peer_id)
        .map_err(|e| format!("Failed to resolve requested local transport target: {}", e))?
        .ok_or_else(|| {
            format!(
                "Rejected peer {}: requested local transport fingerprint {} is not present on this node",
                short_peer_id(remote_peer_id),
                short_peer_id(&requested.transport_peer_id)
            )
        })?;
    let authorized = is_authorized_for_tenant(&db, &tenant.tenant_id, &remote_fp)
        .map_err(|e| format!("Inbound tenant-scoped auth query failed: {}", e))?;
    if !authorized {
        return Err(format!(
            "Rejected peer {}: local tenant {} does not authorize this fingerprint",
            short_peer_id(remote_peer_id),
            short_peer_id(&tenant.tenant_id)
        ));
    }
    Ok(InboundAuthContext {
        requested_local_transport_peer_id: requested.transport_peer_id.clone(),
        authenticated_remote_transport_peer_id: remote_peer_id.to_string(),
        tenant_id: tenant.tenant_id.clone(),
    })
}

fn short_peer_id(peer_id: &str) -> &str {
    &peer_id[..16.min(peer_id.len())]
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::db::schema::create_tables;
    use crate::db::transport_creds::{set_local_transport_target, CRED_SOURCE_PEER_SHARED};
    use crate::db::transport_trust::record_pending_invite_bootstrap_trust;

    fn setup_db() -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("accept-loop-test.db");
        let db_path = db_path.to_string_lossy().to_string();
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();
        (dir, db_path)
    }

    fn insert_tenant(conn: &rusqlite::Connection, tenant_id: &str, workspace_id: &str, n: i64) {
        conn.execute(
            "INSERT INTO invites_accepted (
                recorded_by,
                event_id,
                tenant_event_id,
                invite_event_id,
                workspace_id,
                created_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                tenant_id,
                format!("accepted-event-{n}"),
                format!("tenant-event-{n}"),
                format!("invite-event-{n}"),
                workspace_id,
                n
            ],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO local_transport_creds (
                peer_id,
                cert_der,
                key_der,
                created_at,
                source
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                tenant_id,
                vec![1u8],
                vec![2u8],
                n,
                crate::db::transport_creds::CRED_SOURCE_PEER_SHARED
            ],
        )
        .unwrap();
        set_local_transport_target(conn, tenant_id, tenant_id, CRED_SOURCE_PEER_SHARED).unwrap();
    }

    #[test]
    fn requested_tenant_auth_accepts_when_that_tenant_authorizes_remote_peer() {
        let (_dir, db_path) = setup_db();
        let conn = open_connection(&db_path).unwrap();
        let tenant_a =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let workspace_id = "ws-requested-tenant";
        let remote_fp = [0x11; 32];

        insert_tenant(&conn, &tenant_a, workspace_id, 1);
        record_pending_invite_bootstrap_trust(
            &conn,
            &tenant_a,
            "invite-a",
            workspace_id,
            &remote_fp,
        )
        .unwrap();

        let requested = crate::transport::multi_workspace::TransportSniTarget {
            transport_peer_id: tenant_a.clone(),
        };

        let resolved =
            resolve_requested_tenant_for_peer(&db_path, &requested, &hex::encode(remote_fp))
                .unwrap();
        assert_eq!(
            resolved,
            InboundAuthContext {
                requested_local_transport_peer_id: tenant_a.clone(),
                authenticated_remote_transport_peer_id: hex::encode(remote_fp),
                tenant_id: tenant_a,
            }
        );
    }

    #[test]
    fn requested_tenant_auth_does_not_fallback_to_other_authorizing_tenants() {
        let (_dir, db_path) = setup_db();
        let conn = open_connection(&db_path).unwrap();
        let tenant_a =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let tenant_b =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
        let workspace_id = "ws-shared";
        let remote_fp = [0x22; 32];
        let remote_peer_id = hex::encode(remote_fp);

        insert_tenant(&conn, &tenant_a, workspace_id, 1);
        insert_tenant(&conn, &tenant_b, workspace_id, 2);
        record_pending_invite_bootstrap_trust(
            &conn,
            &tenant_b,
            "invite-b",
            workspace_id,
            &remote_fp,
        )
        .unwrap();

        let requested = crate::transport::multi_workspace::TransportSniTarget {
            transport_peer_id: tenant_a.clone(),
        };

        let err =
            resolve_requested_tenant_for_peer(&db_path, &requested, &remote_peer_id).unwrap_err();
        assert!(
            err.contains("does not authorize this fingerprint"),
            "unexpected error: {err}"
        );
    }
}
