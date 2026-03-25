//! Unified target ingress dispatcher and connect-worker lifecycle.
//!
//! This module owns the `run_target_dispatcher` loop that receives target
//! ingress events from bootstrap/observed/discovery refreshers and spawns
//! one `run_connect_worker` per unique dispatch key.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::bootstrap_auth::{
    is_tenant_in_bootstrap_phase, resolve_active_bootstrap_session_fallback,
    should_initiate_connect_for_source_with_db, BootstrapSessionFallback,
};
use super::target_planner::{
    bootstrap_dispatch_key, bootstrap_dispatch_key_prefix, dispatch_bootstrap_target,
    dispatch_discovery_target, dispatch_observed_endpoint_target, discovery_dispatch_key,
    PeerDispatcher,
};
use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::open_connection;
use crate::peering::loops::{
    connect_loop, preferred_connection_direction, short_peer_id, ConnectLoopConfig, IntroSpawnerFn,
    STALE_DIAL_TARGET_MARKER,
};
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::transport::{
    build_tenant_bootstrap_fallback_client_config_for_invite_from_db,
    build_tenant_client_config_from_db, resolve_bound_daemon_peer_id, OutboundSessionAuthPlan,
    TransportClientConfig, TransportEndpoint,
};

// ---- Types visible within engine/ ----------------------------------------

#[derive(Clone)]
pub(super) struct TenantDispatchContext {
    pub(super) client_config: TransportClientConfig,
}

#[derive(Clone, Debug)]
pub(crate) enum TargetIngressSource {
    Bootstrap {
        daemon_peer_id: String,
        invite_event_id: String,
    },
    ObservedPeer {
        peer_id: String,
    },
    Discovery {
        peer_id: String,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct TargetIngressEvent {
    pub(crate) tenant_id: String,
    pub(crate) remote: SocketAddr,
    pub(crate) source: TargetIngressSource,
}

pub(super) struct ActiveConnectWorker {
    pub(super) cancel: CancellationToken,
    pub(super) join: std::thread::JoinHandle<()>,
    pub(super) source: TargetIngressSource,
}

// ---- Dispatch helpers ----------------------------------------------------

pub(super) fn build_tenant_contexts(
    db_path: &str,
    tenant_ids: &[String],
) -> HashMap<String, TenantDispatchContext> {
    let mut out = HashMap::new();
    for tenant_id in tenant_ids {
        let client_config = match build_tenant_client_config_from_db(db_path, tenant_id) {
            Ok(cfg) => cfg,
            Err(e) => {
                warn!(
                    "Skipping tenant {} for outbound dispatch: {}",
                    short_peer_id(tenant_id),
                    e
                );
                continue;
            }
        };

        out.insert(tenant_id.clone(), TenantDispatchContext { client_config });
    }
    out
}

fn source_precedence(source: &TargetIngressSource) -> u8 {
    match source {
        TargetIngressSource::Bootstrap { .. } => 0,
        TargetIngressSource::ObservedPeer { .. } | TargetIngressSource::Discovery { .. } => 1,
    }
}

pub(super) fn should_ignore_target_event(
    existing: &TargetIngressSource,
    incoming: &TargetIngressSource,
) -> bool {
    source_precedence(existing) > source_precedence(incoming)
}

pub(super) fn should_keep_existing_bootstrap_worker(
    db_path: &str,
    tenant_id: &str,
    existing: &TargetIngressSource,
    incoming: &TargetIngressSource,
) -> bool {
    is_tenant_in_bootstrap_phase(db_path, tenant_id)
        && matches!(existing, TargetIngressSource::Bootstrap { .. })
        && matches!(
            incoming,
            TargetIngressSource::ObservedPeer { .. } | TargetIngressSource::Discovery { .. }
        )
}

fn preferred_outbound_only_peer_id(source: &TargetIngressSource) -> Option<&str> {
    match source {
        TargetIngressSource::Discovery { peer_id } => Some(peer_id),
        TargetIngressSource::Bootstrap { .. } | TargetIngressSource::ObservedPeer { .. } => None,
    }
}

pub(super) fn should_initiate_connect_for_source(
    tenant_id: &str,
    source: &TargetIngressSource,
) -> bool {
    match source {
        TargetIngressSource::Bootstrap { .. } => true,
        TargetIngressSource::ObservedPeer { peer_id }
        | TargetIngressSource::Discovery { peer_id } => matches!(
            preferred_connection_direction(tenant_id, peer_id),
            Some(SessionDirection::Outbound)
        ),
    }
}

// ---- Worker lifecycle helpers --------------------------------------------

async fn join_connect_worker(worker: ActiveConnectWorker) {
    let _ = tokio::task::spawn_blocking(move || {
        let _ = worker.join.join();
    })
    .await;
}

fn known_peer_key_for_event(event: &TargetIngressEvent) -> String {
    match &event.source {
        TargetIngressSource::Bootstrap {
            daemon_peer_id: peer_id,
            ..
        }
        | TargetIngressSource::ObservedPeer { peer_id }
        | TargetIngressSource::Discovery { peer_id } => {
            discovery_dispatch_key(&event.tenant_id, peer_id)
        }
    }
}

fn bootstrap_worker_prefix_for_event(event: &TargetIngressEvent) -> String {
    match &event.source {
        TargetIngressSource::Bootstrap {
            daemon_peer_id: peer_id,
            ..
        }
        | TargetIngressSource::ObservedPeer { peer_id }
        | TargetIngressSource::Discovery { peer_id } => {
            bootstrap_dispatch_key_prefix(&event.tenant_id, peer_id)
        }
    }
}

async fn cancel_bootstrap_workers_for_prefix(
    active_workers: &mut HashMap<String, ActiveConnectWorker>,
    dispatcher: &mut PeerDispatcher,
    prefix: &str,
) {
    let keys: Vec<String> = active_workers
        .keys()
        .filter(|key| key.starts_with(prefix))
        .cloned()
        .collect();
    for key in keys {
        if let Some(worker) = active_workers.remove(&key) {
            worker.cancel.cancel();
            join_connect_worker(worker).await;
            dispatcher.forget(&key);
        }
    }
}

async fn reap_finished_connect_workers(
    active_workers: &mut HashMap<String, ActiveConnectWorker>,
    dispatcher: &mut PeerDispatcher,
) {
    let finished_keys: Vec<String> = active_workers
        .iter()
        .filter_map(|(key, worker)| worker.join.is_finished().then_some(key.clone()))
        .collect();

    for key in finished_keys {
        if let Some(worker) = active_workers.remove(&key) {
            join_connect_worker(worker).await;
            dispatcher.forget(&key);
            warn!(
                "connect worker {} exited; cleared dispatch slot for fresh target ingress",
                key
            );
        }
    }
}

// ---- Main dispatcher + connect worker ------------------------------------

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_target_dispatcher(
    db_path: String,
    endpoint: TransportEndpoint,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    tenant_contexts: HashMap<String, TenantDispatchContext>,
    mut ingress_rx: mpsc::UnboundedReceiver<TargetIngressEvent>,
    shutdown: CancellationToken,
    sync_control: Option<Arc<crate::runtime::sync_control::SyncControlRegistry>>,
) -> Result<(), String> {
    let mut dispatcher = PeerDispatcher::new();
    let mut tenant_contexts = tenant_contexts;
    let mut active_workers: HashMap<String, ActiveConnectWorker> = HashMap::new();

    loop {
        let event = tokio::select! {
            _ = shutdown.cancelled() => break,
            event = ingress_rx.recv() => event,
        };

        let Some(event) = event else {
            break;
        };

        reap_finished_connect_workers(&mut active_workers, &mut dispatcher).await;

        let dispatch_key = match &event.source {
            TargetIngressSource::Bootstrap { daemon_peer_id, .. } => {
                bootstrap_dispatch_key(&event.tenant_id, daemon_peer_id, event.remote)
            }
            TargetIngressSource::ObservedPeer { peer_id } => {
                discovery_dispatch_key(&event.tenant_id, peer_id)
            }
            TargetIngressSource::Discovery { peer_id } => {
                discovery_dispatch_key(&event.tenant_id, peer_id)
            }
        };

        if !should_initiate_connect_for_source_with_db(&db_path, &event.tenant_id, &event.source) {
            if let Some(peer_id) = preferred_outbound_only_peer_id(&event.source) {
                info!(
                    "Skipping non-preferred {:?} dial key={} tenant={} peer={}",
                    event.source,
                    dispatch_key,
                    short_peer_id(&event.tenant_id),
                    short_peer_id(peer_id)
                );
            }
            continue;
        }

        if matches!(event.source, TargetIngressSource::Bootstrap { .. }) {
            let known_peer_key = known_peer_key_for_event(&event);
            if let Some(existing) = active_workers.get(&known_peer_key) {
                if should_ignore_target_event(&existing.source, &event.source) {
                    // During bootstrap phase the Bootstrap worker carries the
                    // only cert the inviter will accept.  Don't let a Discovery
                    // worker (which lacks the bootstrap fallback cert) suppress it.
                    if is_tenant_in_bootstrap_phase(&db_path, &event.tenant_id) {
                        info!(
                            "Allowing Bootstrap worker despite existing {:?} worker (tenant still bootstrapping) key={} tenant={} remote={}",
                            existing.source,
                            known_peer_key,
                            short_peer_id(&event.tenant_id),
                            event.remote
                        );
                    } else {
                        info!(
                            "Keeping existing higher-priority {:?} worker over {:?} key={} tenant={} remote={}",
                            existing.source,
                            event.source,
                            known_peer_key,
                            short_peer_id(&event.tenant_id),
                            event.remote
                        );
                        continue;
                    }
                }
            }
        }

        if let Some(existing) = active_workers.get(&dispatch_key) {
            if should_keep_existing_bootstrap_worker(
                &db_path,
                &event.tenant_id,
                &existing.source,
                &event.source,
            ) {
                info!(
                    "Keeping existing bootstrap worker over {:?} during bootstrap phase key={} tenant={} remote={}",
                    event.source,
                    dispatch_key,
                    short_peer_id(&event.tenant_id),
                    event.remote
                );
                continue;
            }
            if should_ignore_target_event(&existing.source, &event.source) {
                info!(
                    "Keeping existing higher-priority {:?} worker over {:?} key={} tenant={} remote={}",
                    existing.source,
                    event.source,
                    dispatch_key,
                    short_peer_id(&event.tenant_id),
                    event.remote
                );
                continue;
            }
        }

        let should_spawn = match &event.source {
            TargetIngressSource::Bootstrap {
                daemon_peer_id: peer_id,
                ..
            } => {
                dispatch_bootstrap_target(&mut dispatcher, &event.tenant_id, peer_id, event.remote)
            }
            TargetIngressSource::ObservedPeer { peer_id } => dispatch_observed_endpoint_target(
                &mut dispatcher,
                &event.tenant_id,
                peer_id,
                event.remote,
            ),
            TargetIngressSource::Discovery { peer_id } => {
                dispatch_discovery_target(&mut dispatcher, &event.tenant_id, peer_id, event.remote)
            }
        };

        if !should_spawn {
            continue;
        }

        if matches!(
            event.source,
            TargetIngressSource::ObservedPeer { .. } | TargetIngressSource::Discovery { .. }
        ) {
            // During bootstrap phase, keep bootstrap workers alive — they carry
            // the only cert the inviter will accept.
            if !is_tenant_in_bootstrap_phase(&db_path, &event.tenant_id) {
                let prefix = bootstrap_worker_prefix_for_event(&event);
                cancel_bootstrap_workers_for_prefix(&mut active_workers, &mut dispatcher, &prefix)
                    .await;
            }
        }

        if let Some(existing) = active_workers.remove(&dispatch_key) {
            info!(
                "Cancelling existing connect worker key={} tenant={} remote={} source={:?}",
                dispatch_key,
                short_peer_id(&event.tenant_id),
                event.remote,
                event.source
            );
            existing.cancel.cancel();
            join_connect_worker(existing).await;
        }

        let context = if let Some(context) = tenant_contexts.get(&event.tenant_id).cloned() {
            context
        } else {
            match build_tenant_client_config_from_db(&db_path, &event.tenant_id) {
                Ok(client_config) => {
                    let context = TenantDispatchContext { client_config };
                    tenant_contexts.insert(event.tenant_id.clone(), context.clone());
                    context
                }
                Err(e) => {
                    warn!(
                        "Dropping target for tenant {}: no dispatch context ({})",
                        short_peer_id(&event.tenant_id),
                        e
                    );
                    continue;
                }
            }
        };

        let bootstrap_fallback_client_config = match &event.source {
            TargetIngressSource::Bootstrap {
                invite_event_id, ..
            } => {
                match build_tenant_bootstrap_fallback_client_config_for_invite_from_db(
                    &db_path,
                    &event.tenant_id,
                    invite_event_id,
                ) {
                    Ok(cfg) => cfg,
                    Err(err) => {
                        warn!(
                            "Bootstrap fallback config unavailable for tenant {} invite {}: {}",
                            short_peer_id(&event.tenant_id),
                            short_peer_id(invite_event_id),
                            err
                        );
                        None
                    }
                }
            }
            TargetIngressSource::ObservedPeer { .. } => None,
            TargetIngressSource::Discovery { .. } => None,
        };

        let bootstrap_session_fallback = match &event.source {
            TargetIngressSource::Bootstrap {
                daemon_peer_id,
                invite_event_id,
            } => Some(BootstrapSessionFallback {
                daemon_peer_id: daemon_peer_id.clone(),
                invite_event_id: invite_event_id.clone(),
            }),
            TargetIngressSource::ObservedPeer { .. } => {
                resolve_active_bootstrap_session_fallback(&db_path, &event.tenant_id, false)
            }
            TargetIngressSource::Discovery { .. } => {
                resolve_active_bootstrap_session_fallback(&db_path, &event.tenant_id, true)
            }
        };

        let worker_cancel = shutdown.child_token();
        let remote_peer_id = match &event.source {
            TargetIngressSource::Bootstrap { daemon_peer_id, .. } => daemon_peer_id.clone(),
            TargetIngressSource::ObservedPeer { peer_id }
            | TargetIngressSource::Discovery { peer_id } => peer_id.clone(),
        };
        let expected_remote_daemon_peer_id = match &event.source {
            TargetIngressSource::ObservedPeer { peer_id }
            | TargetIngressSource::Discovery { peer_id } => {
                let conn = open_connection(&db_path).ok();
                conn.and_then(|conn| {
                    resolve_bound_daemon_peer_id(&conn, &event.tenant_id, peer_id)
                        .ok()
                        .flatten()
                })
            }
            TargetIngressSource::Bootstrap { .. } => None,
        };
        let expected_remote_daemon_peer_id = expected_remote_daemon_peer_id.or_else(|| {
            bootstrap_session_fallback
                .as_ref()
                .map(|fallback| fallback.daemon_peer_id.clone())
        });
        let Some(expected_remote_daemon_peer_id) = expected_remote_daemon_peer_id else {
            warn!(
                "Skipping connect worker for tenant {} source {:?}: no bound daemon fingerprint",
                short_peer_id(&event.tenant_id),
                event.source
            );
            continue;
        };
        let tenant_in_bootstrap_phase = is_tenant_in_bootstrap_phase(&db_path, &event.tenant_id);
        let auth_plan = if matches!(event.source, TargetIngressSource::Bootstrap { .. })
            || (tenant_in_bootstrap_phase && bootstrap_session_fallback.is_some())
        {
            let Some(fallback) = bootstrap_session_fallback.as_ref() else {
                unreachable!("bootstrap source must always have a bootstrap session fallback")
            };
            OutboundSessionAuthPlan::InviteBootstrap {
                invite_event_id: fallback.invite_event_id.clone(),
            }
        } else {
            let peer_id = match &event.source {
                TargetIngressSource::ObservedPeer { peer_id }
                | TargetIngressSource::Discovery { peer_id } => peer_id,
                TargetIngressSource::Bootstrap { .. } => {
                    unreachable!("bootstrap source handled by invite bootstrap auth")
                }
            };
            OutboundSessionAuthPlan::PeerShared {
                target_peer_id: peer_id.clone(),
            }
        };
        info!(
            "Spawning connect worker key={} tenant={} remote={} source={:?}",
            dispatch_key,
            short_peer_id(&event.tenant_id),
            event.remote,
            event.source
        );
        let worker = std::thread::spawn({
            let db_path = db_path.clone();
            let tenant_id = event.tenant_id.clone();
            let remote_peer_id = remote_peer_id.clone();
            let expected_remote_daemon_peer_id = expected_remote_daemon_peer_id.clone();
            let auth_plan = auth_plan.clone();
            let endpoint = endpoint.clone();
            let worker_cancel = worker_cancel.clone();
            let dispatch_key = dispatch_key.clone();
            let bootstrap_fallback_client_config = bootstrap_fallback_client_config.clone();
            let sync_control = sync_control.clone();
            move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("connect worker runtime");
                runtime.block_on(run_connect_worker(
                    db_path,
                    tenant_id,
                    event.remote,
                    remote_peer_id,
                    expected_remote_daemon_peer_id,
                    auth_plan,
                    endpoint,
                    context,
                    intro_spawner,
                    ingest,
                    worker_cancel,
                    dispatch_key,
                    bootstrap_fallback_client_config,
                    sync_control,
                ));
            }
        });

        active_workers.insert(
            dispatch_key,
            ActiveConnectWorker {
                cancel: worker_cancel,
                join: worker,
                source: event.source,
            },
        );
    }

    for (_, worker) in active_workers {
        worker.cancel.cancel();
        join_connect_worker(worker).await;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_connect_worker(
    db_path: String,
    tenant_id: String,
    remote: SocketAddr,
    remote_peer_id: String,
    expected_remote_daemon_peer_id: String,
    auth_plan: OutboundSessionAuthPlan,
    endpoint: TransportEndpoint,
    context: TenantDispatchContext,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    shutdown: CancellationToken,
    dispatch_key: String,
    bootstrap_fallback_client_config: Option<TransportClientConfig>,
    sync_control: Option<Arc<crate::runtime::sync_control::SyncControlRegistry>>,
) {
    let mut warning_gate = RepeatedWarningGate::new(Duration::from_secs(300));
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        let result = connect_loop(ConnectLoopConfig {
            db_path: db_path.clone(),
            recorded_by: tenant_id.clone(),
            endpoint: endpoint.clone(),
            remote,
            remote_transport_peer_id: remote_peer_id.clone(),
            client_config: Some(context.client_config.clone()),
            intro_spawner,
            ingest,
            shutdown: Some(shutdown.clone()),
            bootstrap_fallback_client_config: bootstrap_fallback_client_config.clone(),
            sync_control: sync_control.clone(),
            auth_plan: Some(auth_plan.clone()),
            expected_remote_daemon_peer_id: Some(expected_remote_daemon_peer_id.clone()),
        })
        .await;

        if shutdown.is_cancelled() {
            break;
        }

        let stale_target = match &result {
            Ok(()) => {
                let message = format!("connect worker {} exited unexpectedly", dispatch_key);
                if warning_gate.should_emit(message.clone())
                    && should_emit_globally(format!("engine:{message}"))
                {
                    warn!("{}", message);
                }
                false
            }
            Err(e) => {
                let stale_target = e.to_string().contains(STALE_DIAL_TARGET_MARKER);
                if !stale_target {
                    let message = format!(
                        "connect worker {} failed: {}; restarting with backoff",
                        dispatch_key, e
                    );
                    if warning_gate.should_emit(message.clone())
                        && should_emit_globally(format!("engine:{message}"))
                    {
                        warn!("{}", message);
                    }
                }
                stale_target
            }
        };
        if stale_target {
            info!(
                "connect worker {} marked dial target stale; exiting for fresh target resolution",
                dispatch_key
            );
            break;
        }

        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_millis(1000)) => {}
        }
    }
}

// ---- Tests ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_connection;
    use crate::db::schema::create_tables;
    use crate::db::transport_creds::{set_local_transport_target, CRED_SOURCE_BOOTSTRAP, CRED_SOURCE_PEER_SHARED};

    #[test]
    fn discovery_and_observed_targets_follow_preferred_side_gate() {
        let lower = "0000000000000000000000000000000000000000000000000000000000000001";
        let higher = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        assert!(should_initiate_connect_for_source(
            lower,
            &TargetIngressSource::Discovery {
                peer_id: higher.to_string(),
            }
        ));
        assert!(!should_initiate_connect_for_source(
            higher,
            &TargetIngressSource::Discovery {
                peer_id: lower.to_string(),
            }
        ));
        assert!(should_initiate_connect_for_source(
            lower,
            &TargetIngressSource::ObservedPeer {
                peer_id: higher.to_string(),
            }
        ));
        assert!(!should_initiate_connect_for_source(
            higher,
            &TargetIngressSource::ObservedPeer {
                peer_id: lower.to_string(),
            }
        ));
    }

    #[test]
    fn bootstrap_targets_always_allow_connect_initiation() {
        let tenant = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let peer = "0000000000000000000000000000000000000000000000000000000000000001";

        assert!(should_initiate_connect_for_source(
            tenant,
            &TargetIngressSource::Bootstrap {
                daemon_peer_id: peer.to_string(),
                invite_event_id: "invite".to_string(),
            }
        ));
    }

    #[test]
    fn discovery_source_beats_bootstrap_source_for_same_peer() {
        let bootstrap = TargetIngressSource::Bootstrap {
            daemon_peer_id: "peer".to_string(),
            invite_event_id: "invite".to_string(),
        };
        let discovery = TargetIngressSource::Discovery {
            peer_id: "peer".to_string(),
        };
        let observed = TargetIngressSource::ObservedPeer {
            peer_id: "peer".to_string(),
        };

        assert!(
            should_ignore_target_event(&discovery, &bootstrap),
            "stale bootstrap targets must not replace a live discovery worker for the same peer"
        );
        assert!(
            should_ignore_target_event(&observed, &bootstrap),
            "stale bootstrap targets must not replace a live observed-endpoint worker for the same peer"
        );
        assert!(
            !should_ignore_target_event(&bootstrap, &discovery),
            "discovery must be able to supersede a stale bootstrap worker"
        );
    }

    #[test]
    fn bootstrap_phase_keeps_existing_bootstrap_worker_over_discovery_and_observed() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bs-existing-worker-guard.db");
        let db_str = db_path.to_str().expect("db path");
        let conn = open_connection(db_str).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let peer = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_BOOTSTRAP)
            .expect("set bootstrap target");
        drop(conn);

        let existing = TargetIngressSource::Bootstrap {
            daemon_peer_id: peer.to_string(),
            invite_event_id: "invite".to_string(),
        };
        let discovery = TargetIngressSource::Discovery {
            peer_id: peer.to_string(),
        };
        let observed = TargetIngressSource::ObservedPeer {
            peer_id: peer.to_string(),
        };

        assert!(
            should_keep_existing_bootstrap_worker(db_str, tenant, &existing, &discovery),
            "bootstrap phase must keep the bootstrap worker over discovery"
        );
        assert!(
            should_keep_existing_bootstrap_worker(db_str, tenant, &existing, &observed),
            "bootstrap phase must keep the bootstrap worker over observed reconnects"
        );

        let conn = open_connection(db_str).expect("open db");
        set_local_transport_target(&conn, tenant, tenant, CRED_SOURCE_PEER_SHARED)
            .expect("transition to peershared");
        drop(conn);

        assert!(
            !should_keep_existing_bootstrap_worker(db_str, tenant, &existing, &discovery),
            "after bootstrap, discovery may replace stale bootstrap workers"
        );
        assert!(
            !should_keep_existing_bootstrap_worker(db_str, tenant, &existing, &observed),
            "after bootstrap, observed reconnects may replace stale bootstrap workers"
        );
    }
}
