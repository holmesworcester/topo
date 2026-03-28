//! Accept-side connection loops: incoming daemon connections and responder
//! sync runs.

use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::sync::SyncConnectionHandler;
use crate::transport::{accept_daemon_connection, load_daemon_identity_from_db, TransportEndpoint};

use super::supervisor::{run_startup_preflight, supervise_inbound_daemon_connection};
use super::{claim_live_daemon_connection_slot, SYNC_SESSION_TIMEOUT_SECS};

const REPEATED_WARNING_WINDOW: Duration = Duration::from_secs(300);

pub async fn accept_loop(
    db_path: &str,
    recorded_by: &str,
    endpoint: TransportEndpoint,
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tenant_ids = vec![recorded_by.to_string()];
    accept_loop_until_cancel_inner(
        db_path,
        &tenant_ids,
        endpoint,
        CancellationToken::new(),
        ingest,
        None,
    )
    .await
}

pub async fn accept_loop_until_cancel(
    db_path: &str,
    tenant_peer_ids: &[String],
    endpoint: TransportEndpoint,
    shutdown: CancellationToken,
    ingest: IngestFns,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    accept_loop_until_cancel_inner(
        db_path,
        tenant_peer_ids,
        endpoint,
        shutdown,
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
    ingest: IngestFns,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    struct ConnectionWorker {
        cancel: CancellationToken,
        join: std::thread::JoinHandle<()>,
    }

    run_startup_preflight(db_path, tenant_peer_ids, ingest)?;
    let (local_daemon_peer_id, _cert, _key) = load_daemon_identity_from_db(db_path)?;

    let mut connection_workers: Vec<ConnectionWorker> = Vec::new();
    let mut warning_gate = RepeatedWarningGate::new(REPEATED_WARNING_WINDOW);
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        info!("Waiting for incoming daemon connection...");
        let daemon_connection = match tokio::select! {
            _ = shutdown.cancelled() => {
                break;
            }
            daemon_connection = accept_daemon_connection(&endpoint) => daemon_connection,
        } {
            Ok(Some(daemon_connection)) => daemon_connection,
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

        let remote_daemon_peer_id = daemon_connection.remote_daemon_peer_id().to_string();
        let connection = daemon_connection.connection();
        let connection_lease = match claim_live_daemon_connection_slot(
            db_path,
            &local_daemon_peer_id,
            &remote_daemon_peer_id,
            SessionDirection::Inbound,
            daemon_connection.clone(),
        ) {
            super::LiveDaemonConnectionClaim::Acquired(lease) => Some(lease),
            super::LiveDaemonConnectionClaim::Occupied(occupied) => {
                info!(
                    "Closing duplicate inbound daemon connection from {} (active_direction={:?}, preferred_direction={:?})",
                    super::short_peer_id(&remote_daemon_peer_id),
                    occupied.active_direction,
                    occupied.preferred_direction
                );
                connection.close(0u32.into(), b"duplicate daemon connection");
                continue;
            }
        };

        let db_path_owned = db_path.to_string();
        let daemon_connection_owned = daemon_connection.clone();
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
                let responder_handler = SyncConnectionHandler::responder(
                    db_path_owned.clone(),
                    SYNC_SESSION_TIMEOUT_SECS,
                )
                .with_sync_control(sync_control_clone.clone());

                supervise_inbound_daemon_connection(
                    &db_path_owned,
                    &daemon_connection_owned,
                    &responder_handler,
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

fn describe_accept_failure(err: &crate::transport::ConnectionLifecycleError) -> String {
    let msg = err.to_string();
    let m = msg.to_ascii_lowercase();
    if m.contains("connection reset") {
        "Incoming daemon connection was reset before handshake completed".to_string()
    } else {
        format!("Failed to accept incoming daemon connection: {}", msg)
    }
}
