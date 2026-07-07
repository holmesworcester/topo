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
use tracing::{debug, info, warn};

use super::bootstrap_auth::{
    is_tenant_in_bootstrap_phase, resolve_active_bootstrap_session_fallback,
    should_initiate_connect_for_source_with_db, BootstrapSessionFallback,
};
use super::target_planner::{
    bootstrap_dispatch_action, bootstrap_dispatch_key, bootstrap_dispatch_key_prefix,
    dispatch_bootstrap_target, dispatch_known_peer_target, known_peer_dispatch_action,
    known_peer_dispatch_key, DispatchAction, PeerDispatcher,
};
use crate::contracts::event_pipeline_contract::IngestFns;
use crate::db::open_connection;
use crate::peering::loops::{
    connect_loop, short_peer_id, ConnectLoopConfig, STALE_DIAL_TARGET_MARKER,
};
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::transport::{resolve_bound_daemon_peer_id, OutboundSessionAuthPlan, TransportEndpoint};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TargetIngressSource {
    Bootstrap {
        daemon_peer_id: String,
        invite_event_id: String,
    },
    KnownPeer {
        peer_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TargetIngressSourceKind {
    Bootstrap,
    KnownPeer,
}

impl TargetIngressSource {
    fn kind(&self) -> TargetIngressSourceKind {
        match self {
            TargetIngressSource::Bootstrap { .. } => TargetIngressSourceKind::Bootstrap,
            TargetIngressSource::KnownPeer { .. } => TargetIngressSourceKind::KnownPeer,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TargetDispatchRawRows {
    pub(super) incoming_source: TargetIngressSourceKind,
    pub(super) should_initiate_connect: bool,
    pub(super) bootstrap_phase: bool,
    pub(super) has_active_higher_precedence_worker: bool,
    pub(super) dispatch_action: DispatchAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TargetDispatchDecisionContext {
    pub(super) incoming_source: TargetIngressSourceKind,
    pub(super) should_initiate_connect: bool,
    pub(super) bootstrap_phase: bool,
    pub(super) has_active_higher_precedence_worker: bool,
    pub(super) dispatch_action: DispatchAction,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum TargetDispatchSkipReason {
    SourceNotInitiated,
    LowerPrecedenceThanActiveWorker,
    DispatcherNoop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct TargetDispatchSpawnPlan {
    pub(super) cancel_existing_dispatch_key: bool,
    pub(super) cancel_bootstrap_prefix: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum TargetDispatchPlan {
    Skip(TargetDispatchSkipReason),
    Spawn(TargetDispatchSpawnPlan),
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

pub(super) fn normalize_target_dispatch_decision_context(
    raw_rows: TargetDispatchRawRows,
) -> TargetDispatchDecisionContext {
    TargetDispatchDecisionContext {
        incoming_source: raw_rows.incoming_source,
        should_initiate_connect: raw_rows.should_initiate_connect,
        bootstrap_phase: raw_rows.bootstrap_phase,
        has_active_higher_precedence_worker: raw_rows.has_active_higher_precedence_worker,
        dispatch_action: raw_rows.dispatch_action,
    }
}

/// Runtime wrapper: projects the runtime's richer types into the Verus-verified core,
/// calls the SMT-checked decision, then lifts the core plan back into runtime enum variants.
/// The decision logic (Skip-reason classification, Spawn boolean fields) is verified.
pub(super) fn decide_target_dispatch_plan(
    context: &TargetDispatchDecisionContext,
) -> TargetDispatchPlan {
    use topo_verus_proofs::runtime::peering::engine::target_dispatch as v;
    let core_action = match context.dispatch_action {
        DispatchAction::Skip => v::CoreDispatchAction::Skip,
        DispatchAction::Connect => v::CoreDispatchAction::Connect,
        DispatchAction::Reconnect => v::CoreDispatchAction::Reconnect,
    };
    let core_source = match context.incoming_source {
        TargetIngressSourceKind::Bootstrap => v::TargetSourceKind::Bootstrap,
        TargetIngressSourceKind::KnownPeer => v::TargetSourceKind::KnownPeer,
    };
    let core_ctx = v::TargetDispatchCoreContext {
        incoming_source: core_source,
        should_initiate_connect: context.should_initiate_connect,
        bootstrap_phase: context.bootstrap_phase,
        has_active_higher_precedence_worker: context.has_active_higher_precedence_worker,
        dispatch_action: core_action,
    };
    match v::decide_target_dispatch_core_plan(&core_ctx) {
        v::TargetDispatchCorePlan::Skip(v::TargetDispatchCoreSkipReason::SourceNotInitiated) => {
            TargetDispatchPlan::Skip(TargetDispatchSkipReason::SourceNotInitiated)
        }
        v::TargetDispatchCorePlan::Skip(
            v::TargetDispatchCoreSkipReason::LowerPrecedenceThanActiveWorker,
        ) => TargetDispatchPlan::Skip(TargetDispatchSkipReason::LowerPrecedenceThanActiveWorker),
        v::TargetDispatchCorePlan::Skip(v::TargetDispatchCoreSkipReason::DispatcherNoop) => {
            TargetDispatchPlan::Skip(TargetDispatchSkipReason::DispatcherNoop)
        }
        v::TargetDispatchCorePlan::Spawn(spawn) => {
            TargetDispatchPlan::Spawn(TargetDispatchSpawnPlan {
                cancel_existing_dispatch_key: spawn.cancel_existing_dispatch_key,
                cancel_bootstrap_prefix: spawn.cancel_bootstrap_prefix,
            })
        }
    }
}

fn known_peer_id(source: &TargetIngressSource) -> Option<&str> {
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
        TargetIngressSource::KnownPeer { peer_id } => OutboundSessionAuthPlan::PeerShared {
            target_peer_id: peer_id.clone(),
        },
    }
}

pub(super) fn should_initiate_connect_for_source(
    _tenant_id: &str,
    _source: &TargetIngressSource,
) -> bool {
    true
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

fn dispatch_action_for_event(
    dispatcher: &PeerDispatcher,
    event: &TargetIngressEvent,
) -> DispatchAction {
    match &event.source {
        TargetIngressSource::Bootstrap { daemon_peer_id, .. } => bootstrap_dispatch_action(
            dispatcher,
            &event.tenant_id,
            daemon_peer_id,
            event.remote,
            event.relay_url.as_deref(),
        ),
        TargetIngressSource::KnownPeer { peer_id } => {
            known_peer_dispatch_action(dispatcher, &event.tenant_id, peer_id, event.remote)
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

        let bootstrap_phase = is_tenant_in_bootstrap_phase(&db_path, &event.tenant_id);
        let should_initiate_connect =
            should_initiate_connect_for_source_with_db(&db_path, &event.tenant_id, &event.source);
        let has_active_higher_precedence_worker =
            matches!(event.source, TargetIngressSource::Bootstrap { .. })
                && active_workers
                    .get(&known_peer_key_for_event(&event))
                    .map(|existing| should_ignore_target_event(&existing.source, &event.source))
                    .unwrap_or(false);
        let dispatch_action = dispatch_action_for_event(&dispatcher, &event);
        let dispatch_plan = decide_target_dispatch_plan(
            &normalize_target_dispatch_decision_context(TargetDispatchRawRows {
                incoming_source: event.source.kind(),
                should_initiate_connect,
                bootstrap_phase,
                has_active_higher_precedence_worker,
                dispatch_action,
            }),
        );
        debug!(
            target: "topo::connection",
            "target_dispatch plan key={} tenant={} source={:?} should_initiate={} bootstrap_phase={} active_higher_precedence={} action={:?} plan={:?}",
            dispatch_key,
            short_peer_id(&event.tenant_id),
            event.source,
            should_initiate_connect,
            bootstrap_phase,
            has_active_higher_precedence_worker,
            dispatch_action,
            dispatch_plan,
        );

        if matches!(
            dispatch_plan,
            TargetDispatchPlan::Skip(TargetDispatchSkipReason::SourceNotInitiated)
        ) {
            if let Some(peer_id) = known_peer_id(&event.source) {
                info!(
                    "Skipping disabled {:?} dial key={} tenant={} peer={}",
                    event.source,
                    dispatch_key,
                    short_peer_id(&event.tenant_id),
                    short_peer_id(peer_id)
                );
            }
            continue;
        }

        if matches!(event.source, TargetIngressSource::Bootstrap { .. })
            && has_active_higher_precedence_worker
            && bootstrap_phase
        {
            info!(
                "Allowing bootstrap worker despite active known-peer worker key={} tenant={}",
                known_peer_key_for_event(&event),
                short_peer_id(&event.tenant_id)
            );
        }

        let spawn_plan = match dispatch_plan {
            TargetDispatchPlan::Skip(_) => continue,
            TargetDispatchPlan::Spawn(plan) => plan,
        };

        let did_dispatch = match &event.source {
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
        if !did_dispatch {
            continue;
        }

        if spawn_plan.cancel_existing_dispatch_key {
            if let Some(existing) = active_workers.remove(&dispatch_key) {
                existing.cancel.cancel();
                join_connect_worker(existing).await;
            }
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
                    debug!(
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

        if spawn_plan.cancel_bootstrap_prefix {
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

    fn bootstrap_context(
        bootstrap_phase: bool,
        has_active_higher_precedence_worker: bool,
        dispatch_action: DispatchAction,
    ) -> TargetDispatchDecisionContext {
        normalize_target_dispatch_decision_context(TargetDispatchRawRows {
            incoming_source: TargetIngressSourceKind::Bootstrap,
            should_initiate_connect: true,
            bootstrap_phase,
            has_active_higher_precedence_worker,
            dispatch_action,
        })
    }

    #[test]
    fn target_dispatch_plan_skips_when_source_is_not_initiated() {
        let context = normalize_target_dispatch_decision_context(TargetDispatchRawRows {
            incoming_source: TargetIngressSourceKind::KnownPeer,
            should_initiate_connect: false,
            bootstrap_phase: false,
            has_active_higher_precedence_worker: false,
            dispatch_action: DispatchAction::Connect,
        });

        assert_eq!(
            decide_target_dispatch_plan(&context),
            TargetDispatchPlan::Skip(TargetDispatchSkipReason::SourceNotInitiated)
        );
    }

    #[test]
    fn bootstrap_is_suppressed_by_active_known_peer_outside_bootstrap_phase() {
        assert_eq!(
            decide_target_dispatch_plan(&bootstrap_context(false, true, DispatchAction::Connect)),
            TargetDispatchPlan::Skip(TargetDispatchSkipReason::LowerPrecedenceThanActiveWorker)
        );
    }

    #[test]
    fn bootstrap_phase_allows_bootstrap_worker_despite_known_peer_worker() {
        assert_eq!(
            decide_target_dispatch_plan(&bootstrap_context(true, true, DispatchAction::Connect)),
            TargetDispatchPlan::Spawn(TargetDispatchSpawnPlan {
                cancel_existing_dispatch_key: false,
                cancel_bootstrap_prefix: false,
            })
        );
    }

    #[test]
    fn dispatcher_noop_skips_spawning() {
        assert_eq!(
            decide_target_dispatch_plan(&bootstrap_context(false, false, DispatchAction::Skip)),
            TargetDispatchPlan::Skip(TargetDispatchSkipReason::DispatcherNoop)
        );
    }

    #[test]
    fn known_peer_spawn_outside_bootstrap_phase_cancels_bootstrap_prefix() {
        let context = normalize_target_dispatch_decision_context(TargetDispatchRawRows {
            incoming_source: TargetIngressSourceKind::KnownPeer,
            should_initiate_connect: true,
            bootstrap_phase: false,
            has_active_higher_precedence_worker: false,
            dispatch_action: DispatchAction::Reconnect,
        });

        assert_eq!(
            decide_target_dispatch_plan(&context),
            TargetDispatchPlan::Spawn(TargetDispatchSpawnPlan {
                cancel_existing_dispatch_key: true,
                cancel_bootstrap_prefix: true,
            })
        );
    }

    #[test]
    fn target_dispatch_normalizer_preserves_raw_rows_for_planner() {
        let raw = TargetDispatchRawRows {
            incoming_source: TargetIngressSourceKind::KnownPeer,
            should_initiate_connect: true,
            bootstrap_phase: false,
            has_active_higher_precedence_worker: false,
            dispatch_action: DispatchAction::Reconnect,
        };

        let context = normalize_target_dispatch_decision_context(raw.clone());

        assert_eq!(
            context,
            TargetDispatchDecisionContext {
                incoming_source: raw.incoming_source,
                should_initiate_connect: raw.should_initiate_connect,
                bootstrap_phase: raw.bootstrap_phase,
                has_active_higher_precedence_worker: raw.has_active_higher_precedence_worker,
                dispatch_action: raw.dispatch_action,
            }
        );
        assert_eq!(
            decide_target_dispatch_plan(&context),
            TargetDispatchPlan::Spawn(TargetDispatchSpawnPlan {
                cancel_existing_dispatch_key: true,
                cancel_bootstrap_prefix: true,
            })
        );
    }

    #[test]
    fn target_dispatch_spawn_requires_runnable_non_suppressed_source() {
        for incoming_source in [
            TargetIngressSourceKind::Bootstrap,
            TargetIngressSourceKind::KnownPeer,
        ] {
            for should_initiate_connect in [false, true] {
                for bootstrap_phase in [false, true] {
                    for has_active_higher_precedence_worker in [false, true] {
                        for dispatch_action in [
                            DispatchAction::Skip,
                            DispatchAction::Connect,
                            DispatchAction::Reconnect,
                        ] {
                            let context = TargetDispatchDecisionContext {
                                incoming_source,
                                should_initiate_connect,
                                bootstrap_phase,
                                has_active_higher_precedence_worker,
                                dispatch_action,
                            };
                            if matches!(
                                decide_target_dispatch_plan(&context),
                                TargetDispatchPlan::Spawn(_)
                            ) {
                                assert!(should_initiate_connect);
                                assert_ne!(dispatch_action, DispatchAction::Skip);
                                assert!(
                                    !(matches!(
                                        incoming_source,
                                        TargetIngressSourceKind::Bootstrap
                                    ) && has_active_higher_precedence_worker
                                        && !bootstrap_phase)
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn bootstrap_source_uses_invite_bootstrap_auth() {
        let fallback = BootstrapSessionFallback {
            daemon_peer_id: "daemon".to_string(),
            invite_event_id: "invite".to_string(),
        };
        let plan = select_outbound_session_auth_plan(
            &TargetIngressSource::Bootstrap {
                daemon_peer_id: "daemon".to_string(),
                invite_event_id: "invite".to_string(),
            },
            Some(&fallback),
        );
        assert_eq!(
            plan,
            OutboundSessionAuthPlan::InviteBootstrap {
                invite_event_id: "invite".to_string(),
            }
        );
    }

    #[test]
    fn known_peer_requests_peer_shared_even_with_bootstrap_fallback() {
        let fallback = BootstrapSessionFallback {
            daemon_peer_id: "daemon".to_string(),
            invite_event_id: "invite".to_string(),
        };
        let plan = select_outbound_session_auth_plan(
            &TargetIngressSource::KnownPeer {
                peer_id: "peer".to_string(),
            },
            Some(&fallback),
        );
        assert_eq!(
            plan,
            OutboundSessionAuthPlan::PeerShared {
                target_peer_id: "peer".to_string(),
            }
        );
    }

    #[test]
    fn known_peer_targets_allow_either_side_to_initiate() {
        let lower = "0000000000000000000000000000000000000000000000000000000000000001";
        let higher = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        assert!(should_initiate_connect_for_source(
            lower,
            &TargetIngressSource::KnownPeer {
                peer_id: higher.to_string(),
            }
        ));
        assert!(should_initiate_connect_for_source(
            higher,
            &TargetIngressSource::KnownPeer {
                peer_id: lower.to_string(),
            }
        ));
    }
}
