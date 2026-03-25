//! Unified connect/accept supervision core.
//!
//! This module owns shared loop orchestration:
//! - startup preflight/recovery
//! - one long-lived sync connection scope per authenticated connection

use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::health::purge_expired_endpoints;
use crate::db::open_connection;
use crate::db::project_queue::ProjectQueue;
use crate::db::schema::create_tables;
use crate::runtime::build_mismatch::note_build_mismatch;
use crate::runtime::repeated_warning::should_emit_globally;
use crate::sync::session::dependency_session::run_dependency_session;
use crate::sync::session::receive_log::recover_receive_logs;
use crate::sync::SyncConnectionHandler;
use crate::transport::session_factory::extract_build_mismatch_reason;
use crate::transport::{SessionClass, SessionProvider};

use super::{current_timestamp_ms, drain_batch_size, run_session, short_peer_id};

/// How a session loop resolves the tenant (`recorded_by`) for each session.
pub(super) enum SessionTenantResolver {
    /// Use a fixed tenant for all sessions on this connection.
    Fixed(String),
}

impl SessionTenantResolver {
    fn resolve(&self, _db_path: &str) -> String {
        match self {
            Self::Fixed(tenant_id) => tenant_id.clone(),
        }
    }
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

    let recovered_receive_logs = recover_receive_logs(db_path).unwrap_or_else(|e| {
        tracing::warn!("receive log recovery failed: {}", e);
        0
    });
    if recovered_receive_logs > 0 {
        info!(
            "Recovered {} event(s) from receive logs",
            recovered_receive_logs
        );
    }

    let purged = purge_expired_endpoints(&db, current_timestamp_ms()).unwrap_or(0);
    if purged > 0 {
        info!("Purged {} expired endpoint observations", purged);
    }

    let project_queue = ProjectQueue::new(&db);
    let recovered = project_queue.recover_expired().unwrap_or(0);
    if recovered > 0 {
        info!("Recovered {} expired project_queue leases", recovered);
    }

    let batch_sz = drain_batch_size();
    // Drain origin queues first before we recover pending fanouts.
    // Note: `tenant_ids` includes accepted tenants using bootstrap
    // transport identity (via discover_local_tenants fallback), so
    // seed replay work enqueued before a crash is recovered here.
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

    // Recover any pending shared-event fanouts from a prior crash.
    // This runs after draining origin queues so fanout recovery sees
    // the latest projection state.
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
            // Drain sibling queues that were just enqueued by recovery.
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

/// Shared per-connection supervision loop for both connect and accept modes.
pub(super) async fn supervise_connection_sessions(
    db_path: &str,
    peer_id: &str,
    peer_fp: [u8; 32],
    provider: &SessionProvider,
    handler: &SyncConnectionHandler,
    direction: SessionDirection,
    tenant_resolver: &SessionTenantResolver,
    shutdown: CancellationToken,
) {
    let connection = provider.connection();
    let recorded_by = tenant_resolver.resolve(db_path);
    loop {
        if shutdown.is_cancelled() {
            connection.close(0u32.into(), b"runtime shutdown");
            return;
        }

        let session = match tokio::select! {
            _ = shutdown.cancelled() => {
                connection.close(0u32.into(), b"runtime shutdown");
                return;
            }
            session = provider.next_session() => session,
        } {
            Ok(session) => session,
            Err(e) => {
                if let Some(reason) = extract_build_mismatch_reason(&e.to_string()) {
                    note_build_mismatch(peer_id, reason);
                    let key = format!(
                        "session-build-mismatch:{:?}:{}:{}",
                        direction, recorded_by, peer_id
                    );
                    if should_emit_globally(key) {
                        warn!(
                            "Peer {} rejected {:?} session on connection {}: {}",
                            short_peer_id(peer_id),
                            direction,
                            connection.stable_id(),
                            reason
                        );
                    }
                } else {
                    info!(
                        "Connection {} dropped while opening {:?} session: {}",
                        connection.stable_id(),
                        direction,
                        e
                    );
                }
                return;
            }
        };

        let session_start = std::time::Instant::now();
        if session.class == SessionClass::Dependency {
            let db_path = db_path.to_string();
            let recorded_by = recorded_by.clone();
            let peer_id = peer_id.to_string();
            let remote_addr = session.remote_addr;
            let dep_shutdown = shutdown.child_token();
            tokio::task::spawn_local(async move {
                if let Err(err) = run_dependency_session(
                    session.io,
                    db_path,
                    recorded_by,
                    peer_id.clone(),
                    remote_addr,
                    dep_shutdown,
                )
                .await
                {
                    warn!(
                        "Dependency session {} error peer={}: {}",
                        session.session_id,
                        short_peer_id(&peer_id),
                        err
                    );
                }
            });
            continue;
        }
        info!(
            "Starting session {} ({:?}) on connection {}",
            session.session_id,
            direction,
            connection.stable_id()
        );

        let session_ok = run_session(
            handler,
            session.session_id,
            session.io,
            &recorded_by,
            peer_fp,
            session.remote_addr,
            direction,
            db_path,
        )
        .await;

        info!(
            "Session {} ({:?}) on connection {} finished in {}ms",
            session.session_id,
            direction,
            connection.stable_id(),
            session_start.elapsed().as_millis()
        );

        if !session_ok {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    connection.close(0u32.into(), b"runtime shutdown");
                    return;
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {}
            }
        }
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
    fn fixed_tenant_resolver_always_returns_same_value() {
        let resolver = SessionTenantResolver::Fixed("tenant-fixed".to_string());
        assert_eq!(resolver.resolve("/tmp/does-not-matter"), "tenant-fixed");
    }

    #[test]
    fn short_peer_id_truncates_to_sixteen_chars() {
        assert_eq!(
            short_peer_id("0123456789abcdefdeadbeef"),
            "0123456789abcdef"
        );
        assert_eq!(short_peer_id("short"), "short");
    }
}
