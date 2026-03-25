//! Accept-side connection loops: incoming QUIC connections and responder
//! sync runs.

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::event_modules::operational::connection_runtime::peer_fingerprint_from_hex;
use crate::event_modules::operational::inbound_connection_authenticated::{
    describe_accept_failure, observe_inbound_connection, InboundConnectionObservation,
};
use crate::event_modules::operational::inbound_connection_closed::record_inbound_connection_closed;
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::state::startup_reconcile::run_startup_preflight;
use crate::sync::SyncConnectionHandler;
use crate::transport::{accept_session_provider, TransportClientConfig, TransportEndpoint};

use super::supervisor::{supervise_connection_sessions, SessionTenantResolver};
use super::{IntroSpawnerFn, SYNC_SESSION_TIMEOUT_SECS};

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
        let (recorded_by, inbound_connection_id, connection_lease) =
            match observe_inbound_connection(db_path, &connection, &peer_id) {
                Ok(InboundConnectionObservation::Authenticated {
                    recorded_by,
                    connection_id,
                    lease,
                }) => (recorded_by, connection_id, lease),
                Ok(InboundConnectionObservation::Rejected {
                    close_code,
                    close_reason,
                }) => {
                    connection.close(close_code.into(), close_reason.as_bytes());
                    continue;
                }
                Err(err) => {
                    warn!(
                        "failed to observe inbound connection for peer {}: {}",
                        short_peer_id(&peer_id),
                        err
                    );
                    connection.close(1u32.into(), b"inbound connection event authoring failed");
                    continue;
                }
            };

        // Spawn a supervised worker for this accepted connection.
        let db_path_owned = db_path.to_string();
        let recorded_by_owned = recorded_by;
        let inbound_connection_id_owned = inbound_connection_id.clone();
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
                        if let Err(err) = record_inbound_connection_closed(
                            &db_path_owned,
                            &inbound_connection_id_owned,
                            Some(message.as_str()),
                        ) {
                            warn!(
                                "failed to record inbound_connection_closed for {}: {}",
                                inbound_connection_id_owned, err
                            );
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

                let outcome = supervise_connection_sessions(
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

                if let Err(err) = record_inbound_connection_closed(
                    &db_path_owned,
                    &inbound_connection_id_owned,
                    Some(outcome.close_reason()),
                ) {
                    warn!(
                        "failed to record inbound_connection_closed for {}: {}",
                        inbound_connection_id_owned, err
                    );
                }
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

fn short_peer_id(peer_id: &str) -> &str {
    &peer_id[..16.min(peer_id.len())]
}

#[cfg(test)]
mod tests {
    use crate::db::open_connection;
    use crate::db::schema::create_tables;
    use crate::db::transport_creds::{
        set_local_transport_target, CRED_SOURCE_BOOTSTRAP, CRED_SOURCE_PEER_SHARED,
    };
    use crate::db::transport_trust::record_pending_invite_bootstrap_trust;
    use crate::event_modules::operational::inbound_connection_authenticated::{
        resolve_requested_tenant_for_peer, InboundAuthContext,
    };

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
        assert!(err.contains("no local tenant"), "unexpected error: {err}");
    }

    #[test]
    fn requested_tenant_auth_selects_authorized_tenant_when_bootstrap_target_is_shared() {
        let (_dir, db_path) = setup_db();
        let conn = open_connection(&db_path).unwrap();
        let tenant_a =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string();
        let tenant_b =
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string();
        let shared_transport_peer_id =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string();
        let workspace_id = "ws-shared-bootstrap";
        let remote_fp = [0x33; 32];

        insert_tenant(&conn, &tenant_a, workspace_id, 1);
        insert_tenant(&conn, &tenant_b, workspace_id, 2);
        conn.execute(
            "DELETE FROM local_transport_targets WHERE tenant_id IN (?1, ?2)",
            rusqlite::params![&tenant_a, &tenant_b],
        )
        .unwrap();
        set_local_transport_target(
            &conn,
            &tenant_a,
            &shared_transport_peer_id,
            CRED_SOURCE_BOOTSTRAP,
        )
        .unwrap();
        set_local_transport_target(
            &conn,
            &tenant_b,
            &shared_transport_peer_id,
            CRED_SOURCE_BOOTSTRAP,
        )
        .unwrap();
        record_pending_invite_bootstrap_trust(
            &conn,
            &tenant_b,
            "invite-b",
            workspace_id,
            &remote_fp,
        )
        .unwrap();

        let requested = crate::transport::multi_workspace::TransportSniTarget {
            transport_peer_id: shared_transport_peer_id.clone(),
        };

        let resolved =
            resolve_requested_tenant_for_peer(&db_path, &requested, &hex::encode(remote_fp))
                .unwrap();
        assert_eq!(
            resolved,
            InboundAuthContext {
                requested_local_transport_peer_id: shared_transport_peer_id,
                authenticated_remote_transport_peer_id: hex::encode(remote_fp),
                tenant_id: tenant_b,
            }
        );
    }
}
