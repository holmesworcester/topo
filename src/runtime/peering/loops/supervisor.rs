//! Unified connect/accept supervision core.
//!
//! This module owns shared loop orchestration:
//! - startup preflight/recovery
//! - inbound logical-session supervision on a shared daemon connection

use std::collections::HashMap;

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::health::{purge_expired_endpoints, record_endpoint_observation};
use crate::db::open_connection;
use crate::db::projection_queue::ProjectionQueue;
use crate::db::schema::create_tables;
use crate::db::transport_trust::record_transport_binding;
use crate::runtime::build_mismatch::note_build_mismatch;
use crate::runtime::repeated_warning::should_emit_globally;
use crate::sync::SyncConnectionHandler;
use crate::transport::session_factory::extract_build_mismatch_reason;
use crate::transport::{
    read_inbound_session_auth_for_connection, send_inbound_session_auth_ack, DaemonConnection,
};

use super::{
    claim_live_session_peer, current_timestamp_ms, drain_batch_size, peer_fingerprint_from_hex,
    run_session, short_peer_id, ENDPOINT_TTL_MS,
};

#[cfg(feature = "iroh-transport")]
const FIRST_SESSION_AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
#[cfg(feature = "tor-transport")]
const FIRST_SESSION_AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DaemonConnectionAdmission {
    RequireFirstSessionAuth,
    KnownDaemonRoute,
}

fn requires_first_session_auth_timeout(
    connection_admitted: bool,
    initial_admission: DaemonConnectionAdmission,
) -> bool {
    !connection_admitted
        && matches!(
            initial_admission,
            DaemonConnectionAdmission::RequireFirstSessionAuth
        )
}

/// Shared startup preflight:
/// - `create_tables`
/// - purge expired endpoint observations
/// - recover expired project-queue leases
/// - initial project-queue drain per tenant
pub(super) fn run_startup_preflight(
    db_path: &str,
    tenant_ids: &[String],
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let purged = purge_expired_endpoints(&db, current_timestamp_ms()).unwrap_or(0);
    if purged > 0 {
        info!("Purged {} expired endpoint observations", purged);
    }

    let project_queue = ProjectionQueue::new(&db);
    let recovered = project_queue.recover_expired().unwrap_or(0);
    if recovered > 0 {
        info!("Recovered {} expired project_queue leases", recovered);
    }

    let batch_sz = drain_batch_size();
    for tenant_id in tenant_ids {
        let drained = (ingest.drain_queue)(db_path, tenant_id, batch_sz);
        if drained > 0 {
            info!(
                "Processed {} pending project_queue items for tenant {}",
                drained,
                short_peer_id(tenant_id)
            );
        }
    }

    match crate::state::shared_workspace_fanout::take_pending_fanouts(&db) {
        Ok(pending) if !pending.is_empty() => {
            info!("Recovering {} pending shared-event fanouts", pending.len());
            for fanout in &pending {
                match crate::state::shared_workspace_fanout::fanout_shared_event_enqueue(
                    &db, fanout,
                ) {
                    Ok(_) => {
                        let _ = crate::state::shared_workspace_fanout::delete_pending_fanout(
                            &db, fanout,
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            "startup fanout recovery failed for {}: {}",
                            short_peer_id(&fanout.origin_peer_id),
                            e
                        );
                    }
                }
            }
            for tenant_id in tenant_ids {
                let drained = (ingest.drain_queue)(db_path, tenant_id, batch_sz);
                if drained > 0 {
                    info!(
                        "Processed {} recovered fanout items for tenant {}",
                        drained,
                        short_peer_id(tenant_id)
                    );
                }
            }
        }
        Ok(_) => {}
        Err(e) => tracing::warn!("take_pending_fanouts at startup: {}", e),
    }

    Ok(())
}

pub(super) async fn supervise_inbound_daemon_connection(
    db_path: &str,
    daemon_connection: &DaemonConnection,
    handler: &SyncConnectionHandler,
    shutdown: CancellationToken,
    initial_admission: DaemonConnectionAdmission,
) {
    let connection = daemon_connection.connection();
    let remote_daemon_peer_id = daemon_connection.remote_daemon_peer_id().to_string();
    let mut connection_admitted = matches!(
        initial_admission,
        DaemonConnectionAdmission::KnownDaemonRoute
    );
    let mut live_session_peer_registrations = HashMap::new();

    loop {
        if shutdown.is_cancelled() {
            connection.close(0u32.into(), b"runtime shutdown");
            return;
        }

        let session_result =
            if !requires_first_session_auth_timeout(connection_admitted, initial_admission) {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        connection.close(0u32.into(), b"runtime shutdown");
                        return;
                    }
                    session = daemon_connection.accept_inbound_session() => Ok(session),
                }
            } else {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        connection.close(0u32.into(), b"runtime shutdown");
                        return;
                    }
                    session = tokio::time::timeout(
                        FIRST_SESSION_AUTH_TIMEOUT,
                        daemon_connection.accept_inbound_session(),
                    ) => {
                        match session {
                            Ok(session) => Ok(session),
                            Err(_) => Err("first session auth timeout".to_string()),
                        }
                    }
                }
            };
        let mut session = match session_result {
            Ok(session) => match session {
                Ok(session) => session,
                Err(e) => {
                    if let Some(reason) = extract_build_mismatch_reason(&e.to_string()) {
                        note_build_mismatch(&remote_daemon_peer_id, reason);
                        let key = format!(
                            "session-build-mismatch:{:?}:{}",
                            SessionDirection::Inbound,
                            remote_daemon_peer_id
                        );
                        if should_emit_globally(key) {
                            warn!(
                                "Peer {} rejected {:?} session on connection {}: {}",
                                short_peer_id(&remote_daemon_peer_id),
                                SessionDirection::Inbound,
                                connection.stable_id(),
                                reason
                            );
                        }
                    } else {
                        info!(
                            "Connection {} dropped while accepting inbound session: {}",
                            connection.stable_id(),
                            e
                        );
                    }
                    return;
                }
            },
            Err(message) => {
                warn!(
                    "Closing unauthenticated daemon connection {} daemon={}: {}",
                    connection.stable_id(),
                    short_peer_id(&remote_daemon_peer_id),
                    message
                );
                connection.close(1u32.into(), message.as_bytes());
                return;
            }
        };

        let auth_future = read_inbound_session_auth_for_connection(
            session.io.as_mut(),
            db_path,
            daemon_connection,
        );
        let auth_context = if connection_admitted {
            auth_future.await
        } else {
            match tokio::time::timeout(FIRST_SESSION_AUTH_TIMEOUT, auth_future).await {
                Ok(result) => result,
                Err(_) => {
                    let message = format!(
                        "Inbound session {} auth timed out on connection {} daemon={}",
                        session.session_id,
                        connection.stable_id(),
                        short_peer_id(&remote_daemon_peer_id)
                    );
                    warn!("{}", message);
                    connection.close(1u32.into(), b"session auth timeout");
                    return;
                }
            }
        };

        let auth_context = match auth_context {
            Ok(session) => session,
            Err(err) => {
                warn!(
                    "Inbound session {} auth failed on connection {} daemon={}: {}",
                    session.session_id,
                    connection.stable_id(),
                    short_peer_id(&remote_daemon_peer_id),
                    err
                );
                if !connection_admitted {
                    connection.close(1u32.into(), b"session auth rejected");
                    return;
                }
                continue;
            }
        };
        connection_admitted = true;
        if let Err(err) =
            send_inbound_session_auth_ack(session.io.as_mut(), &auth_context.tenant_id).await
        {
            warn!(
                "Inbound session {} ack failed on connection {} daemon={} tenant={} peer={} bootstrap_auth={}: {}",
                session.session_id,
                connection.stable_id(),
                short_peer_id(&remote_daemon_peer_id),
                short_peer_id(&auth_context.tenant_id),
                short_peer_id(&auth_context.remote_peer_id),
                auth_context.used_bootstrap_auth,
                err
            );
            continue;
        }

        let peer_fp = match peer_fingerprint_from_hex(&auth_context.remote_peer_id) {
            Some(peer_fp) => peer_fp,
            None => {
                warn!(
                    "Inbound session {} used invalid remote peer id {}",
                    session.session_id,
                    short_peer_id(&auth_context.remote_peer_id)
                );
                continue;
            }
        };
        live_session_peer_registrations
            .entry((
                auth_context.tenant_id.clone(),
                auth_context.remote_peer_id.clone(),
            ))
            .or_insert_with(|| {
                claim_live_session_peer(
                    db_path,
                    &auth_context.tenant_id,
                    &auth_context.remote_peer_id,
                )
            });

        let now = current_timestamp_ms();
        if let Ok(db) = open_connection(db_path) {
            if let Some(remote_addr) = session.remote_addr {
                let _ = record_endpoint_observation(
                    &db,
                    &auth_context.tenant_id,
                    &auth_context.remote_peer_id,
                    &remote_addr.ip().to_string(),
                    remote_addr.port(),
                    now,
                    ENDPOINT_TTL_MS,
                );
            }
            if let Some(remote_daemon_fp) =
                peer_fingerprint_from_hex(daemon_connection.remote_daemon_peer_id())
            {
                let _ = record_transport_binding(
                    &db,
                    &auth_context.tenant_id,
                    &auth_context.remote_peer_id,
                    &remote_daemon_fp,
                );
            }
        }

        info!(
            "Starting inbound session {} on connection {} tenant={} peer={} daemon={}",
            session.session_id,
            connection.stable_id(),
            short_peer_id(&auth_context.tenant_id),
            short_peer_id(&auth_context.remote_peer_id),
            short_peer_id(&remote_daemon_peer_id)
        );

        let handler = handler.clone();
        let db_path = db_path.to_string();
        let tenant_id = auth_context.tenant_id.clone();
        let remote_peer_id = auth_context.remote_peer_id.clone();
        let remote_label = session.remote_label.clone();
        let session_start = std::time::Instant::now();
        let connection_id = connection.stable_id();
        tokio::task::spawn_local(async move {
            let session_stats = run_session(
                &handler,
                session.session_id,
                session.io,
                &tenant_id,
                peer_fp,
                remote_label,
                SessionDirection::Inbound,
                &db_path,
            )
            .await;

            info!(
                "Inbound session {} on connection {} finished in {}ms peer={}",
                session.session_id,
                connection_id,
                session_start.elapsed().as_millis(),
                short_peer_id(&remote_peer_id)
            );

            if session_stats.is_none() {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use tokio::sync::mpsc;

    use super::*;
    use crate::contracts::event_pipeline_contract::IngestItem;

    static DRAIN_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn noop_batch_writer(
        _db_path: String,
        _rx: mpsc::Receiver<IngestItem>,
        _events: Arc<AtomicU64>,
    ) {
    }

    fn counting_drain_queue(_db_path: &str, _tenant_id: &str, _batch_size: usize) -> usize {
        DRAIN_CALLS.fetch_add(1, Ordering::Relaxed);
        0
    }

    #[test]
    fn startup_preflight_drains_once_per_tenant() {
        DRAIN_CALLS.store(0, Ordering::Relaxed);
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("preflight.sqlite3");
        let tenants = vec!["tenant-a".to_string(), "tenant-b".to_string()];
        let ingest = IngestFns {
            batch_writer: noop_batch_writer,
            drain_queue: counting_drain_queue,
        };

        run_startup_preflight(db_path.to_str().unwrap(), &tenants, ingest).unwrap();

        assert_eq!(DRAIN_CALLS.load(Ordering::Relaxed), tenants.len());
    }

    #[test]
    fn short_peer_id_truncates_to_sixteen_chars() {
        assert_eq!(
            short_peer_id("0123456789abcdefdeadbeef"),
            "0123456789abcdef"
        );
        assert_eq!(short_peer_id("short"), "short");
    }

    #[test]
    fn known_daemon_route_skips_first_session_auth_timeout() {
        assert!(requires_first_session_auth_timeout(
            false,
            DaemonConnectionAdmission::RequireFirstSessionAuth
        ));
        assert!(!requires_first_session_auth_timeout(
            false,
            DaemonConnectionAdmission::KnownDaemonRoute
        ));
        assert!(!requires_first_session_auth_timeout(
            true,
            DaemonConnectionAdmission::RequireFirstSessionAuth
        ));
    }
}
