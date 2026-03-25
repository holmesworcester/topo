use tracing::info;

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::db::health::purge_expired_endpoints;
use crate::db::open_connection;
use crate::db::project_queue::ProjectQueue;
use crate::db::schema::create_tables;
use crate::runtime::peering::loops::current_timestamp_ms;
use crate::state::shared_workspace_fanout;

fn short_peer_id(peer_id: &str) -> &str {
    &peer_id[..16.min(peer_id.len())]
}

/// Shared startup preflight:
/// - `create_tables`
/// - purge expired endpoint observations
/// - recover expired project-queue leases
/// - initial project-queue drain per tenant
pub fn run_startup_preflight(
    db_path: &str,
    tenant_ids: &[String],
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = open_connection(db_path)?;
    create_tables(&db)?;

    let recovered_receive_logs = crate::sync::session::receive_log::recover_receive_logs(db_path)
        .unwrap_or_else(|e| {
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

    let batch_sz = crate::tuning::drain_batch_size();
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

    match shared_workspace_fanout::take_pending_fanouts(&db) {
        Ok(pending) if !pending.is_empty() => {
            info!("Recovering {} pending shared-event fanouts", pending.len());
            for fanout in &pending {
                match shared_workspace_fanout::fanout_shared_event_enqueue(&db, fanout) {
                    Ok(_) => {
                        let _ = shared_workspace_fanout::delete_pending_fanout(&db, fanout);
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use tokio::sync::mpsc;

    use super::run_startup_preflight;
    use crate::contracts::event_pipeline_contract::{IngestFns, IngestItem};

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
}
