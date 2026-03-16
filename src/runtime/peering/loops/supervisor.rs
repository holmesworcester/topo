//! Unified connect/accept supervision core.
//!
//! This module owns shared loop orchestration:
//! - startup preflight/recovery
//! - shared ingest writer setup
//! - one long-lived sync connection scope per authenticated connection

use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::{IngestFns, IngestItem};
use crate::contracts::peering_contract::SessionDirection;
use crate::db::health::purge_expired_endpoints;
use crate::db::open_connection;
use crate::db::project_queue::ProjectQueue;
use crate::db::schema::create_tables;
use crate::runtime::build_mismatch::note_build_mismatch;
use crate::runtime::memtrace;
use crate::runtime::repeated_warning::should_emit_globally;
use crate::sync::SyncSessionHandler;
use crate::transport::session_factory::extract_build_mismatch_reason;
use crate::transport::SessionProvider;
use crate::tuning::{low_mem_memtrace, low_mem_mode};

use super::{current_timestamp_ms, drain_batch_size, run_session, shared_ingest_cap};

static PEER_SESSION_GATES: OnceLock<Mutex<HashMap<String, Arc<AsyncMutex<()>>>>> = OnceLock::new();

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

/// Shared ingest writer setup used by wrapper loops that own their writer.
pub(super) fn spawn_shared_ingest_writer(
    db_path: &str,
    ingest: IngestFns,
) -> mpsc::Sender<IngestItem> {
    let ingest_cap = shared_ingest_cap();
    if low_mem_memtrace() {
        let line = format!(
            "LOWMEM_MEMTRACE shared_ingest_config cap={} low_mem={}",
            ingest_cap,
            low_mem_mode()
        );
        let memtrace_file = std::env::var("LOW_MEM_MEMTRACE_FILE").ok();
        memtrace::emit(&line, memtrace_file.as_deref());
    }
    let (shared_tx, shared_rx) = mpsc::channel::<IngestItem>(ingest_cap);
    let writer_events = Arc::new(AtomicU64::new(0));
    let writer_db = db_path.to_string();
    let batch_writer = ingest.batch_writer;
    let _writer_handle = std::thread::spawn(move || {
        batch_writer(writer_db, shared_rx, writer_events);
    });
    shared_tx
}

/// Shared per-connection supervision loop for both connect and accept modes.
pub(super) async fn supervise_connection_sessions(
    db_path: &str,
    peer_id: &str,
    peer_fp: [u8; 32],
    provider: &SessionProvider,
    handler: &SyncSessionHandler,
    direction: SessionDirection,
    tenant_resolver: &SessionTenantResolver,
    shutdown: CancellationToken,
) {
    let connection = provider.connection();
    let recorded_by = tenant_resolver.resolve(db_path);
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
    let gate = peer_session_gate(db_path, &recorded_by, peer_id);
    let gate_wait_start = std::time::Instant::now();
    let session_slot = match gate.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            info!(
                "Session {} ({:?}) on connection {} waiting for peer session slot tenant={} peer={}",
                session.session_id,
                direction,
                connection.stable_id(),
                short_peer_id(&recorded_by),
                short_peer_id(peer_id)
            );
            let guard = gate.lock().await;
            info!(
                "Session {} ({:?}) on connection {} acquired peer session slot after {}ms tenant={} peer={}",
                session.session_id,
                direction,
                connection.stable_id(),
                gate_wait_start.elapsed().as_millis(),
                short_peer_id(&recorded_by),
                short_peer_id(peer_id)
            );
            guard
        }
    };
    info!(
        "Starting session {} ({:?}) on connection {}",
        session.session_id,
        direction,
        connection.stable_id()
    );

    run_session(
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
    drop(session_slot);

    info!(
        "Session {} ({:?}) on connection {} finished in {}ms",
        session.session_id,
        direction,
        connection.stable_id(),
        session_start.elapsed().as_millis()
    );
}

fn short_peer_id(peer_id: &str) -> &str {
    &peer_id[..16.min(peer_id.len())]
}

fn peer_session_gate(db_path: &str, tenant_id: &str, peer_id: &str) -> Arc<AsyncMutex<()>> {
    let key = format!("{db_path}|{tenant_id}|{peer_id}");
    let registry = PEER_SESSION_GATES.get_or_init(|| Mutex::new(HashMap::new()));
    let mut registry = registry.lock().expect("peer session gate registry");
    registry
        .entry(key)
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use super::*;

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

    #[tokio::test]
    async fn peer_session_gate_serializes_same_peer_key() {
        let gate_a = peer_session_gate("/tmp/a.db", "tenant-a", "peer-a");
        let gate_b = peer_session_gate("/tmp/a.db", "tenant-a", "peer-a");

        let _guard = gate_a.lock().await;
        assert!(
            gate_b.try_lock().is_err(),
            "same db/tenant/peer should share one gate"
        );
    }

    #[tokio::test]
    async fn peer_session_gate_is_tenant_scoped() {
        let gate_a = peer_session_gate("/tmp/a.db", "tenant-a", "peer-a");
        let gate_b = peer_session_gate("/tmp/a.db", "tenant-b", "peer-a");

        let _guard = gate_a.lock().await;
        assert!(
            gate_b.try_lock().is_ok(),
            "different tenants should not serialize each other"
        );
    }
}
