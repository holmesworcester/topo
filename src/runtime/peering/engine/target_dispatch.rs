//! Unified target ingress dispatcher and connect-worker lifecycle.
//!
//! Runtime inputs now collapse to:
//! - bootstrap daemon targets from invite state
//! - known-peer targets from projected peer state, optionally with a stored
//!   observed endpoint

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
    dispatch_known_peer_target, known_peer_dispatch_key, PeerDispatcher,
};
use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::open_connection;
use crate::peering::loops::{
    connect_loop, preferred_connection_direction, short_peer_id, ConnectLoopConfig,
    STALE_DIAL_TARGET_MARKER,
};
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::transport::{resolve_bound_daemon_peer_id, OutboundSessionAuthPlan, TransportEndpoint};

#[derive(Clone, Debug)]
pub(crate) enum TargetIngressSource {
    Bootstrap {
        daemon_peer_id: String,
        invite_event_id: String,
    },
    KnownPeer {
        peer_id: String,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct TargetIngressEvent {
    pub(crate) tenant_id: String,
    pub(crate) remote: Option<SocketAddr>,
    pub(crate) relay_url: Option<String>,
    pub(crate) source: TargetIngressSource,
}

pub(super) struct ActiveConnectWorker {
    pub(super) cancel: CancellationToken,
    pub(super) join: std::thread::JoinHandle<()>,
    pub(super) source: TargetIngressSource,
}

fn source_precedence(source: &TargetIngressSource) -> u8 {
    match source {
        TargetIngressSource::Bootstrap { .. } => 0,
        TargetIngressSource::KnownPeer { .. } => 1,
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
        && matches!(incoming, TargetIngressSource::KnownPeer { .. })
}

fn preferred_outbound_only_peer_id(source: &TargetIngressSource) -> Option<&str> {
    match source {
        TargetIngressSource::KnownPeer { peer_id } => Some(peer_id),
        TargetIngressSource::Bootstrap { .. } => None,
    }
}

fn select_outbound_session_auth_plan(
    source: &TargetIngressSource,
    bootstrap_session_fallback: Option<&BootstrapSessionFallback>,
) -> OutboundSessionAuthPlan {
    match source {
        TargetIngressSource::Bootstrap { .. } => {
            let fallback = bootstrap_session_fallback
                .expect("bootstrap source must always have a bootstrap session fallback");
            OutboundSessionAuthPlan::InviteBootstrap {
                invite_event_id: fallback.invite_event_id.clone(),
            }
        }
        TargetIngressSource::KnownPeer { peer_id } => {
            if let Some(fallback) = bootstrap_session_fallback {
                OutboundSessionAuthPlan::InviteBootstrap {
                    invite_event_id: fallback.invite_event_id.clone(),
                }
            } else {
                OutboundSessionAuthPlan::PeerShared {
                    target_peer_id: peer_id.clone(),
                }
            }
        }
    }
}

pub(super) fn should_initiate_connect_for_source(
    tenant_id: &str,
    source: &TargetIngressSource,
) -> bool {
    match source {
        TargetIngressSource::Bootstrap { .. } => true,
        TargetIngressSource::KnownPeer { peer_id } => matches!(
            preferred_connection_direction(tenant_id, peer_id),
            Some(SessionDirection::Outbound)
        ),
    }
}

async fn join_connect_worker(worker: ActiveConnectWorker) {
    let _ = tokio::task::spawn_blocking(move || {
        let _ = worker.join.join();
    })
    .await;
}

fn known_peer_key_for_event(event: &TargetIngressEvent) -> String {
    match &event.source {
        TargetIngressSource::Bootstrap { daemon_peer_id, .. } => {
            known_peer_dispatch_key(&event.tenant_id, daemon_peer_id)
        }
        TargetIngressSource::KnownPeer { peer_id } => {
            known_peer_dispatch_key(&event.tenant_id, peer_id)
        }
    }
}

fn format_target(
    remote: Option<SocketAddr>,
    relay_url: Option<&str>,
    daemon_peer_id: Option<&str>,
) -> String {
    match remote {
        Some(remote) => remote.to_string(),
        None => {
            if let Some(relay_url) = relay_url {
                daemon_peer_id
                    .map(|peer_id| format!("relay({relay_url}, {})", short_peer_id(peer_id)))
                    .unwrap_or_else(|| format!("relay({relay_url})"))
            } else {
                daemon_peer_id
                    .map(|peer_id| format!("lookup({})", short_peer_id(peer_id)))
                    .unwrap_or_else(|| "lookup".to_string())
            }
        }
    }
}

fn describe_outbound_session_auth_plan(plan: &OutboundSessionAuthPlan) -> String {
    match plan {
        OutboundSessionAuthPlan::PeerShared { target_peer_id } => {
            format!("peer_shared(peer={})", short_peer_id(target_peer_id))
        }
        OutboundSessionAuthPlan::InviteBootstrap { invite_event_id } => {
            let short_invite = &invite_event_id[..16.min(invite_event_id.len())];
            format!("invite_bootstrap(invite={short_invite})")
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

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_target_dispatcher(
    db_path: String,
    endpoint: TransportEndpoint,
    ingest: IngestFns,
    mut ingress_rx: mpsc::UnboundedReceiver<TargetIngressEvent>,
    shutdown: CancellationToken,
    sync_control: Option<Arc<crate::runtime::sync_control::SyncControlRegistry>>,
) -> Result<(), String> {
    let mut dispatcher = PeerDispatcher::new();
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
            TargetIngressSource::Bootstrap { daemon_peer_id, .. } => bootstrap_dispatch_key(
                &event.tenant_id,
                daemon_peer_id,
                event.remote,
                event.relay_url.as_deref(),
            ),
            TargetIngressSource::KnownPeer { peer_id } => {
                known_peer_dispatch_key(&event.tenant_id, peer_id)
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
                    if is_tenant_in_bootstrap_phase(&db_path, &event.tenant_id) {
                        info!(
                            "Allowing bootstrap worker despite existing {:?} worker key={} tenant={}",
                            existing.source,
                            known_peer_key,
                            short_peer_id(&event.tenant_id)
                        );
                    } else {
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
                continue;
            }
            if should_ignore_target_event(&existing.source, &event.source) {
                continue;
            }
        }

        let should_spawn = match &event.source {
            TargetIngressSource::Bootstrap { daemon_peer_id, .. } => dispatch_bootstrap_target(
                &mut dispatcher,
                &event.tenant_id,
                daemon_peer_id,
                event.remote,
                event.relay_url.as_deref(),
            ),
            TargetIngressSource::KnownPeer { peer_id } => {
                dispatch_known_peer_target(&mut dispatcher, &event.tenant_id, peer_id, event.remote)
            }
        };
        if !should_spawn {
            continue;
        }

        if let Some(existing) = active_workers.remove(&dispatch_key) {
            existing.cancel.cancel();
            join_connect_worker(existing).await;
        }

        let bootstrap_session_fallback = match &event.source {
            TargetIngressSource::Bootstrap {
                daemon_peer_id,
                invite_event_id,
            } => Some(BootstrapSessionFallback {
                daemon_peer_id: daemon_peer_id.clone(),
                invite_event_id: invite_event_id.clone(),
            }),
            TargetIngressSource::KnownPeer { .. } => {
                resolve_active_bootstrap_session_fallback(&db_path, &event.tenant_id, false)
            }
        };

        let remote_peer_id = match &event.source {
            TargetIngressSource::Bootstrap { daemon_peer_id, .. } => daemon_peer_id.clone(),
            TargetIngressSource::KnownPeer { peer_id } => peer_id.clone(),
        };
        let expected_remote_daemon_peer_id = match &event.source {
            TargetIngressSource::Bootstrap { .. } => None,
            TargetIngressSource::KnownPeer { peer_id } => {
                let conn = open_connection(&db_path).ok();
                conn.and_then(|conn| {
                    resolve_bound_daemon_peer_id(&conn, &event.tenant_id, peer_id)
                        .ok()
                        .flatten()
                })
            }
        }
        .or_else(|| {
            bootstrap_session_fallback
                .as_ref()
                .map(|fallback| fallback.daemon_peer_id.clone())
        });
        let Some(expected_remote_daemon_peer_id) = expected_remote_daemon_peer_id else {
            continue;
        };

        let auth_plan =
            select_outbound_session_auth_plan(&event.source, bootstrap_session_fallback.as_ref());
        let worker_cancel = shutdown.child_token();
        let target_label = format_target(
            event.remote,
            event.relay_url.as_deref(),
            Some(&expected_remote_daemon_peer_id),
        );

        if matches!(event.source, TargetIngressSource::KnownPeer { .. }) {
            if let Some(fallback) = bootstrap_session_fallback.as_ref() {
                let bootstrap_phase = is_tenant_in_bootstrap_phase(&db_path, &event.tenant_id);
                let key = format!(
                    "known-peer-bootstrap-fallback:{}:{}:{}:{}",
                    event.tenant_id,
                    remote_peer_id,
                    expected_remote_daemon_peer_id,
                    bootstrap_phase
                );
                if should_emit_globally(key) {
                    warn!(
                        "Known-peer target tenant={} peer={} target={} selected {} because bootstrap fallback invite={} daemon={} remains active (bootstrap_phase={})",
                        short_peer_id(&event.tenant_id),
                        short_peer_id(&remote_peer_id),
                        target_label,
                        describe_outbound_session_auth_plan(&auth_plan),
                        &fallback.invite_event_id[..16.min(fallback.invite_event_id.len())],
                        short_peer_id(&fallback.daemon_peer_id),
                        bootstrap_phase
                    );
                }
            }
        }

        if matches!(event.source, TargetIngressSource::KnownPeer { .. })
            && !is_tenant_in_bootstrap_phase(&db_path, &event.tenant_id)
        {
            let prefix =
                bootstrap_dispatch_key_prefix(&event.tenant_id, &expected_remote_daemon_peer_id);
            cancel_bootstrap_workers_for_prefix(&mut active_workers, &mut dispatcher, &prefix)
                .await;
        }

        info!(
            "Spawning connect worker key={} tenant={} target={} source={:?}",
            dispatch_key,
            short_peer_id(&event.tenant_id),
            target_label,
            event.source
        );

        let worker = std::thread::spawn({
            let db_path = db_path.clone();
            let tenant_id = event.tenant_id.clone();
            let remote = event.remote;
            let relay_url = event.relay_url.clone();
            let remote_peer_id = remote_peer_id.clone();
            let expected_remote_daemon_peer_id = expected_remote_daemon_peer_id.clone();
            let auth_plan = auth_plan.clone();
            let endpoint = endpoint.clone();
            let worker_cancel = worker_cancel.clone();
            let dispatch_key = dispatch_key.clone();
            let sync_control = sync_control.clone();
            move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("connect worker runtime");
                runtime.block_on(run_connect_worker(
                    db_path,
                    tenant_id,
                    remote,
                    relay_url,
                    remote_peer_id,
                    expected_remote_daemon_peer_id,
                    auth_plan,
                    endpoint,
                    ingest,
                    worker_cancel,
                    dispatch_key,
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
    remote: Option<SocketAddr>,
    relay_url: Option<String>,
    remote_peer_id: String,
    expected_remote_daemon_peer_id: String,
    auth_plan: OutboundSessionAuthPlan,
    endpoint: TransportEndpoint,
    ingest: IngestFns,
    shutdown: CancellationToken,
    dispatch_key: String,
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
            relay_url: relay_url.clone(),
            remote_session_peer_id: remote_peer_id.clone(),
            ingest,
            shutdown: Some(shutdown.clone()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_peer_targets_follow_preferred_side_gate() {
        let lower = "0000000000000000000000000000000000000000000000000000000000000001";
        let higher = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        assert!(should_initiate_connect_for_source(
            lower,
            &TargetIngressSource::KnownPeer {
                peer_id: higher.to_string(),
            }
        ));
        assert!(!should_initiate_connect_for_source(
            higher,
            &TargetIngressSource::KnownPeer {
                peer_id: lower.to_string(),
            }
        ));
    }
}
