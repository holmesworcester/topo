//! Runtime task-graph supervisor.
//!
//! This module is the single owner of long-lived runtime workers:
//! - shared ingest writer
//! - accept loop
//! - unified target ingress/dispatch
//! - bootstrap refresher
//! - observed-endpoint refresher
//! - discovery ingress workers (feature-gated)

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Notify;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::target_planner::{
    collect_all_bootstrap_targets, collect_all_observed_endpoint_targets,
    dispatch_bootstrap_target, dispatch_discovery_target, dispatch_observed_endpoint_target,
    normalize_discovered_addr_for_local_bind, PeerDispatcher,
};
use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::open_connection;
use crate::db::transport_creds::{
    resolve_tenant_transport_target, TenantInfo, CRED_SOURCE_BOOTSTRAP,
};
use crate::db::transport_trust::is_peer_shared_transport_fingerprint;
use crate::event_modules::operational::connection_plan_transitioned::record_connection_plan_transition;
use crate::event_modules::operational::connection_planned::{
    dispatch_target_from_row, existing_source_has_higher_precedence, load as load_connection_plan,
    load_due_effects, record_connection_planned, ConnectionPlanSourceKind, ConnectionPlanStatus,
};
use crate::event_modules::operational::connection_runtime::preferred_connection_direction;
#[cfg(feature = "discovery")]
use crate::event_modules::operational::mdns_peer_observed::record_mdns_peer_observed;
use crate::peering::loops::{
    accept_loop_until_cancel, connect_loop_with_coordination_until_cancel_with_fallback,
    IntroSpawnerFn,
};
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::transport::{
    build_tenant_bootstrap_fallback_client_config_for_invite_from_db,
    build_tenant_client_config_from_db, TenantClientConfigs, TransportClientConfig,
    TransportEndpoint,
};

const STALE_DIAL_TARGET_MARKER: &str = "stale_dial_target";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RuntimeState {
    IdleNoTenants,
    Active,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeEvent {
    TenantSetChanged(usize),
    ShutdownRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerKind {
    AcceptLoop,
    TargetDispatcher,
    BootstrapRefresher,
    ObservedEndpointRefresher,
    #[cfg(feature = "discovery")]
    DiscoveryIngress,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkerFailurePolicy {
    FailRuntime,
}

#[derive(Debug)]
struct WorkerExit {
    kind: WorkerKind,
    name: String,
    result: Result<(), String>,
    cancelled: bool,
}

#[derive(Debug)]
enum WorkerExitDisposition {
    Expected,
    Fatal(String),
}

#[derive(Clone)]
struct TenantDispatchContext {
    client_config: TransportClientConfig,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
enum TargetIngressSource {
    Bootstrap {
        peer_id: String,
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
struct TargetIngressEvent {
    tenant_id: String,
    remote: SocketAddr,
    source: TargetIngressSource,
}

struct ActiveConnectWorker {
    cancel: CancellationToken,
    join: std::thread::JoinHandle<()>,
    // source_kind removed — precedence is now derived from
    // connection_plan_history via load_connection_plan().source_kind
}

fn author_connection_planned(db_path: &str, event: &TargetIngressEvent) {
    let (remote_peer_id, source_kind, invite_event_id) = match &event.source {
        TargetIngressSource::Bootstrap {
            peer_id,
            invite_event_id,
        } => (
            peer_id.as_str(),
            ConnectionPlanSourceKind::Bootstrap,
            Some(invite_event_id.as_str()),
        ),
        TargetIngressSource::ObservedPeer { peer_id } => (
            peer_id.as_str(),
            ConnectionPlanSourceKind::ObservedPeer,
            None,
        ),
        TargetIngressSource::Discovery { peer_id } => {
            (peer_id.as_str(), ConnectionPlanSourceKind::Discovery, None)
        }
    };
    if let Err(err) = record_connection_planned(
        db_path,
        &event.tenant_id,
        remote_peer_id,
        event.remote,
        source_kind,
        invite_event_id,
    ) {
        warn!(
            "failed to author connection_planned for tenant {} peer {}: {}",
            short_peer_id(&event.tenant_id),
            short_peer_id(remote_peer_id),
            err
        );
    }
}

fn emit_connection_plan_transition(
    db_path: &str,
    connection_plan_id: &str,
    status: ConnectionPlanStatus,
    decision_reason: &str,
    retry_after_ms: u64,
) -> Result<(), String> {
    record_connection_plan_transition(
        db_path,
        connection_plan_id,
        status,
        Some(decision_reason),
        retry_after_ms,
    )
}

pub(crate) struct RuntimeSupervisor {
    db_path: String,
    endpoint: TransportEndpoint,
    local_addr: SocketAddr,
    tenants: Vec<TenantInfo>,
    tenant_client_configs: TenantClientConfigs,
    local_peer_ids: HashSet<String>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    state: RuntimeState,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
}

impl RuntimeSupervisor {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        db_path: String,
        endpoint: TransportEndpoint,
        local_addr: SocketAddr,
        tenants: Vec<TenantInfo>,
        tenant_client_configs: TenantClientConfigs,
        local_peer_ids: HashSet<String>,
        intro_spawner: IntroSpawnerFn,
        ingest: IngestFns,
        sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
    ) -> Self {
        Self {
            db_path,
            endpoint,
            local_addr,
            tenants,
            tenant_client_configs,
            local_peer_ids,
            intro_spawner,
            ingest,
            state: RuntimeState::IdleNoTenants,
            sync_control,
        }
    }

    pub(crate) async fn run_until_shutdown(
        &mut self,
        shutdown_notify: Arc<Notify>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.state = transition_state(
            self.state,
            RuntimeEvent::TenantSetChanged(self.tenants.len()),
        );
        info!("runtime supervisor state: {:?}", self.state);

        let root_cancel = CancellationToken::new();
        let mut workers = JoinSet::<WorkerExit>::new();

        let tenant_ids: Vec<String> = self.tenants.iter().map(|t| t.peer_id.clone()).collect();
        let tenant_contexts = build_tenant_contexts(&self.db_path, &tenant_ids);

        // Accept worker: inbound transport sessions for all known tenants.
        {
            let db_path = self.db_path.clone();
            let endpoint = self.endpoint.clone();
            let tenant_ids = tenant_ids.clone();
            let tenant_cfgs = self.tenant_client_configs.clone();
            let intro_spawner = self.intro_spawner;
            let ingest = self.ingest;
            let cancel = root_cancel.child_token();
            let sync_control = self.sync_control.clone();
            spawn_worker(
                &mut workers,
                WorkerKind::AcceptLoop,
                "accept-loop",
                cancel.clone(),
                async move {
                    accept_loop_until_cancel(
                        &db_path,
                        &tenant_ids,
                        endpoint,
                        cancel,
                        tenant_cfgs,
                        intro_spawner,
                        ingest,
                        sync_control,
                    )
                    .await
                    .map_err(|e| e.to_string())
                },
            );
        }

        // Unified target dispatcher: one owner for connect-loop worker lifecycle.
        {
            let db_path = self.db_path.clone();
            let endpoint = self.endpoint.clone();
            let intro_spawner = self.intro_spawner;
            let ingest = self.ingest;
            let cancel = root_cancel.child_token();
            let sync_control = self.sync_control.clone();
            spawn_worker(
                &mut workers,
                WorkerKind::TargetDispatcher,
                "target-dispatcher",
                cancel.clone(),
                async move {
                    run_target_dispatcher(
                        db_path,
                        endpoint,
                        intro_spawner,
                        ingest,
                        tenant_contexts,
                        cancel,
                        sync_control,
                    )
                    .await
                },
            );
        }

        // Bootstrap refresher authors connection_planned local events.
        if env_flag("TOPO_DISABLE_PLACEHOLDER_AUTODIAL") {
            warn!("BOOTSTRAP AUTODIAL DISABLED by TOPO_DISABLE_PLACEHOLDER_AUTODIAL");
        } else {
            let db_path = self.db_path.clone();
            let cancel = root_cancel.child_token();
            spawn_worker(
                &mut workers,
                WorkerKind::BootstrapRefresher,
                "bootstrap-refresher",
                cancel.clone(),
                async move { run_bootstrap_refresher(db_path, cancel).await },
            );
        }

        {
            let db_path = self.db_path.clone();
            let cancel = root_cancel.child_token();
            spawn_worker(
                &mut workers,
                WorkerKind::ObservedEndpointRefresher,
                "observed-endpoint-refresher",
                cancel.clone(),
                async move { run_observed_endpoint_refresher(db_path, cancel).await },
            );
        }

        #[cfg(feature = "discovery")]
        let mut discovery_handles = Vec::new();

        #[cfg(feature = "discovery")]
        if env_flag("TOPO_DISABLE_DISCOVERY") {
            warn!("mDNS discovery disabled by TOPO_DISABLE_DISCOVERY");
        } else {
            let setup = super::discovery::prepare_mdns_discovery(
                &self.tenants,
                self.local_addr,
                &self.local_peer_ids,
                &self.tenant_client_configs,
            );
            discovery_handles = setup.handles;

            for source in setup.ingress_sources {
                let db_path = self.db_path.clone();
                let cancel = root_cancel.child_token();
                let worker_name = format!("discovery-ingress-{}", short_peer_id(&source.tenant_id));
                spawn_worker(
                    &mut workers,
                    WorkerKind::DiscoveryIngress,
                    worker_name,
                    cancel.clone(),
                    async move { run_discovery_ingress_worker(source, db_path.clone(), cancel).await },
                );
            }
        }

        let mut fatal_error: Option<String> = None;

        loop {
            tokio::select! {
                _ = shutdown_notify.notified() => {
                    self.state = transition_state(self.state, RuntimeEvent::ShutdownRequested);
                    break;
                }
                joined = workers.join_next() => {
                    let Some(joined) = joined else {
                        fatal_error = Some("runtime worker set terminated unexpectedly".to_string());
                        break;
                    };

                    let exit = match joined {
                        Ok(exit) => exit,
                        Err(e) => {
                            fatal_error = Some(format!("runtime worker join failure: {}", e));
                            break;
                        }
                    };

                    match classify_worker_exit(&exit) {
                        WorkerExitDisposition::Expected => {}
                        WorkerExitDisposition::Fatal(msg) => {
                            fatal_error = Some(msg);
                            break;
                        }
                    }
                }
            }
        }

        root_cancel.cancel();
        self.endpoint.close(0u32.into(), b"runtime shutdown");

        while let Some(joined) = workers.join_next().await {
            match joined {
                Ok(exit) => match classify_worker_exit(&exit) {
                    WorkerExitDisposition::Expected => {}
                    WorkerExitDisposition::Fatal(msg) => {
                        if fatal_error.is_none() {
                            fatal_error = Some(msg);
                        }
                    }
                },
                Err(e) => {
                    if fatal_error.is_none() {
                        fatal_error =
                            Some(format!("runtime worker join failure during drain: {}", e));
                    }
                }
            }
        }

        #[cfg(feature = "discovery")]
        drop(discovery_handles);

        if let Some(err) = fatal_error {
            return Err(err.into());
        }

        Ok(())
    }
}

fn env_flag(name: &str) -> bool {
    std::env::var(name)
        .ok()
        .map(|v| {
            let lowered = v.to_ascii_lowercase();
            lowered == "1" || lowered == "true" || lowered == "yes"
        })
        .unwrap_or(false)
}

fn build_tenant_contexts(
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

fn spawn_worker<F>(
    workers: &mut JoinSet<WorkerExit>,
    kind: WorkerKind,
    name: impl Into<String>,
    cancel: CancellationToken,
    fut: F,
) where
    F: std::future::Future<Output = Result<(), String>> + Send + 'static,
{
    let name = name.into();
    workers.spawn(async move {
        let result = fut.await;
        WorkerExit {
            kind,
            name,
            result,
            cancelled: cancel.is_cancelled(),
        }
    });
}

fn worker_failure_policy(kind: WorkerKind) -> WorkerFailurePolicy {
    match kind {
        WorkerKind::AcceptLoop
        | WorkerKind::TargetDispatcher
        | WorkerKind::BootstrapRefresher
        | WorkerKind::ObservedEndpointRefresher => WorkerFailurePolicy::FailRuntime,
        #[cfg(feature = "discovery")]
        WorkerKind::DiscoveryIngress => WorkerFailurePolicy::FailRuntime,
    }
}

fn classify_worker_exit(exit: &WorkerExit) -> WorkerExitDisposition {
    let policy = worker_failure_policy(exit.kind);

    let message = match &exit.result {
        Ok(()) if exit.cancelled => return WorkerExitDisposition::Expected,
        Ok(()) => format!(
            "worker {} ({:?}) exited unexpectedly without shutdown",
            exit.name, exit.kind
        ),
        Err(err) => format!("worker {} ({:?}) failed: {}", exit.name, exit.kind, err),
    };

    match policy {
        WorkerFailurePolicy::FailRuntime => WorkerExitDisposition::Fatal(message),
    }
}

fn transition_state(_state: RuntimeState, event: RuntimeEvent) -> RuntimeState {
    match event {
        RuntimeEvent::TenantSetChanged(count) if count == 0 => RuntimeState::IdleNoTenants,
        RuntimeEvent::TenantSetChanged(_) => RuntimeState::Active,
        RuntimeEvent::ShutdownRequested => RuntimeState::IdleNoTenants,
    }
}

/// Generic durable-job-driven refresh loop. Replaces per-job async loops
/// with a single executor that: polls for due job → runs the refresh
/// function → marks complete. The refresh function authors events; this
/// loop only handles timing and error suppression.
async fn run_job_driven_refresh(
    db_path: String,
    job_kind: crate::event_modules::operational::durable_jobs::DurableJobKind,
    label: &str,
    refresh: impl Fn(&str) -> Result<(), String>,
    shutdown: CancellationToken,
) -> Result<(), String> {
    use crate::event_modules::operational::durable_jobs::{
        complete_job, next_due_at, poll_due_jobs,
    };
    let mut warning_gate = RepeatedWarningGate::new(Duration::from_secs(300));
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        let sleep_ms = {
            let conn = open_connection(&db_path).map_err(|e| e.to_string())?;
            let is_due = poll_due_jobs(&conn, 1)
                .map_err(|e| e.to_string())?
                .iter()
                .any(|j| j.kind == job_kind);
            if !is_due {
                let next = next_due_at(&conn).map_err(|e| e.to_string())?;
                let now = crate::db::queue::current_timestamp_ms();
                next.map(|t| (t - now).max(50)).unwrap_or(1000) as u64
            } else {
                0
            }
        };

        if sleep_ms > 0 {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(sleep_ms)) => {}
            }
            continue;
        }

        match refresh(&db_path) {
            Ok(()) => warning_gate.clear(),
            Err(e) => {
                let message = format!("{label} failed: {e}");
                if warning_gate.should_emit(message.clone())
                    && should_emit_globally(format!("engine:{message}"))
                {
                    warn!("{}", message);
                }
            }
        }

        if let Ok(conn) = open_connection(&db_path) {
            let _ = complete_job(&conn, &client_id_for_db(&db_path), job_kind);
        }

        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }
    }
    Ok(())
}

fn refresh_bootstrap_targets(db_path: &str) -> Result<(), String> {
    for (tenant_id, peer_id, invite_event_id, remote) in
        collect_all_bootstrap_targets(db_path).map_err(|e| e.to_string())?
    {
        author_connection_planned(
            db_path,
            &TargetIngressEvent {
                tenant_id,
                remote,
                source: TargetIngressSource::Bootstrap {
                    peer_id,
                    invite_event_id,
                },
            },
        );
    }
    Ok(())
}

fn refresh_observed_endpoint_targets(db_path: &str) -> Result<(), String> {
    for (tenant_id, peer_id, remote) in
        collect_all_observed_endpoint_targets(db_path).map_err(|e| e.to_string())?
    {
        author_connection_planned(
            db_path,
            &TargetIngressEvent {
                tenant_id,
                remote,
                source: TargetIngressSource::ObservedPeer { peer_id },
            },
        );
    }
    Ok(())
}

async fn run_bootstrap_refresher(
    db_path: String,
    shutdown: CancellationToken,
) -> Result<(), String> {
    run_job_driven_refresh(
        db_path,
        crate::event_modules::operational::durable_jobs::DurableJobKind::BootstrapRefresh,
        "BOOTSTRAP AUTODIAL REFRESH",
        refresh_bootstrap_targets,
        shutdown,
    )
    .await
}

async fn run_observed_endpoint_refresher(
    db_path: String,
    shutdown: CancellationToken,
) -> Result<(), String> {
    run_job_driven_refresh(
        db_path,
        crate::event_modules::operational::durable_jobs::DurableJobKind::ObservedEndpointRefresh,
        "OBSERVED ENDPOINT REFRESH",
        refresh_observed_endpoint_targets,
        shutdown,
    )
    .await
}

fn client_id_for_db(db_path: &str) -> String {
    crate::event_modules::operational::client_lifecycle::client_id_for_db_path(db_path)
}

#[cfg(feature = "discovery")]
async fn run_discovery_ingress_worker(
    source: super::discovery::DiscoveryIngressSource,
    db_path: String,
    shutdown: CancellationToken,
) -> Result<(), String> {
    tokio::task::spawn_blocking(move || {
        use std::sync::mpsc::RecvTimeoutError;

        loop {
            if shutdown.is_cancelled() {
                break;
            }

            match source.rx.recv_timeout(Duration::from_millis(250)) {
                Ok(peer) => {
                    let dial_addr =
                        normalize_discovered_addr_for_local_bind(source.local_listen_ip, peer.addr);
                    if let Err(err) = record_mdns_peer_observed(
                        &db_path,
                        &source.tenant_id,
                        &peer.peer_id,
                        dial_addr,
                    ) {
                        warn!(
                            "failed to author mdns_peer_observed for tenant {} peer {}: {}",
                            short_peer_id(&source.tenant_id),
                            short_peer_id(&peer.peer_id),
                            err
                        );
                    }
                }
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }

        Ok::<(), String>(())
    })
    .await
    .map_err(|e| format!("discovery ingress worker join error: {}", e))?
}

async fn run_target_dispatcher(
    db_path: String,
    endpoint: TransportEndpoint,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    tenant_contexts: HashMap<String, TenantDispatchContext>,
    shutdown: CancellationToken,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
) -> Result<(), String> {
    let mut dispatcher = PeerDispatcher::new();
    let mut tenant_contexts = tenant_contexts;
    let mut reconciler = super::reconciler::ConnectionReconciler::new();
    let (mut wake_rx, _wake_guard) = crate::state::operational_wake::register(&db_path);

    loop {
        {
            let finished = reconciler.reap_finished();
            for conn_id in &finished {
                dispatcher.forget(conn_id);
                let _ = emit_connection_plan_transition(
                    &db_path,
                    conn_id,
                    ConnectionPlanStatus::Finished,
                    "worker_completed",
                    0,
                );
            }
        }
        let conn = open_connection(&db_path).map_err(|e| e.to_string())?;
        let claimed = load_due_effects(&conn, 16).map_err(|e| e.to_string())?;
        drop(conn);

        if claimed.is_empty() {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                wake = wake_rx.recv() => {
                    match wake {
                        Ok(crate::state::operational_wake::OperationalWake::ConnectionPlan { .. }) => {}
                        Ok(crate::state::operational_wake::OperationalWake::ClientRuntime { .. }) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
            continue;
        }

        for effect in claimed {
            let conn = open_connection(&db_path).map_err(|e| e.to_string())?;
            let Some(plan) =
                load_connection_plan(&conn, &effect.connection_id).map_err(|e| e.to_string())?
            else {
                continue;
            };
            drop(conn);

            let target = match dispatch_target_from_row(&plan) {
                Ok(target) => target,
                Err(err) => {
                    warn!("invalid connection plan {}: {}", effect.connection_id, err);
                    let _ = emit_connection_plan_transition(
                        &db_path,
                        &effect.connection_id,
                        ConnectionPlanStatus::Superseded,
                        "invalid_connection_plan_state",
                        0,
                    );
                    continue;
                }
            };

            let connection_plan_id = effect.connection_id.clone();

            let should_activate = {
                let conn = open_connection(&db_path).map_err(|e| e.to_string())?;
                crate::event_modules::operational::connection_planned::should_activate_plan(
                    &conn,
                    &target.tenant_id,
                    target.source_kind,
                    &target.remote_peer_id,
                )
            };
            if !should_activate {
                let _ = emit_connection_plan_transition(
                    &db_path,
                    &connection_plan_id,
                    ConnectionPlanStatus::Deferred,
                    "policy_skipped_non_preferred_direction",
                    1_000,
                );
                continue;
            }

            if matches!(target.source_kind, ConnectionPlanSourceKind::Bootstrap) {
                let known_peer_key = target.known_peer_key();
                if reconciler.has_worker(&known_peer_key) {
                    // Query the existing plan's source_kind from projected state
                    // instead of keeping it in the worker handle.
                    let existing_source = {
                        let conn = open_connection(&db_path).map_err(|e| e.to_string())?;
                        load_connection_plan(&conn, &known_peer_key)
                            .map_err(|e| e.to_string())?
                            .map(|plan| plan.source_kind)
                    };
                    if let Some(existing_source) = existing_source {
                        if existing_source_has_higher_precedence(
                            existing_source,
                            target.source_kind,
                        ) {
                            let _ = emit_connection_plan_transition(
                                &db_path,
                                &connection_plan_id,
                                ConnectionPlanStatus::Deferred,
                                "existing_worker_has_higher_precedence",
                                1_000,
                            );
                            continue;
                        }
                    }
                }
            }

            if reconciler.has_worker(&connection_plan_id) {
                let existing_source = {
                    let conn = open_connection(&db_path).map_err(|e| e.to_string())?;
                    load_connection_plan(&conn, &connection_plan_id)
                        .map_err(|e| e.to_string())?
                        .map(|plan| plan.source_kind)
                };
                if let Some(existing_source) = existing_source {
                    if existing_source_has_higher_precedence(existing_source, target.source_kind) {
                        let _ = emit_connection_plan_transition(
                            &db_path,
                            &connection_plan_id,
                            ConnectionPlanStatus::Deferred,
                            "existing_worker_has_higher_precedence",
                            1_000,
                        );
                        continue;
                    }
                }
            }

            let should_spawn = match target.source_kind {
                ConnectionPlanSourceKind::Bootstrap => dispatch_bootstrap_target(
                    &mut dispatcher,
                    &target.tenant_id,
                    &target.remote_peer_id,
                    target.remote,
                ),
                ConnectionPlanSourceKind::ObservedPeer => dispatch_observed_endpoint_target(
                    &mut dispatcher,
                    &target.tenant_id,
                    &target.remote_peer_id,
                    target.remote,
                ),
                ConnectionPlanSourceKind::Discovery => dispatch_discovery_target(
                    &mut dispatcher,
                    &target.tenant_id,
                    &target.remote_peer_id,
                    target.remote,
                ),
            };

            if !should_spawn {
                let _ = emit_connection_plan_transition(
                    &db_path,
                    &connection_plan_id,
                    ConnectionPlanStatus::Deferred,
                    "dispatcher_deduped_target",
                    1_000,
                );
                continue;
            }

            if matches!(
                target.source_kind,
                ConnectionPlanSourceKind::ObservedPeer | ConnectionPlanSourceKind::Discovery
            ) {
                let prefix = target.bootstrap_worker_prefix();
                for key in reconciler.keys_with_prefix(&prefix) {
                    if let Some(handle) = reconciler.take(&key) {
                        let _ = emit_connection_plan_transition(
                            &db_path,
                            &key,
                            ConnectionPlanStatus::Superseded,
                            "steady_state_target_replaced_bootstrap",
                            0,
                        );
                        handle.cancel.cancel();
                        let _ = tokio::task::spawn_blocking(move || { let _ = handle.join.join(); }).await;
                        dispatcher.forget(&key);
                    }
                }
            }

            if let Some(existing) = reconciler.take(&connection_plan_id) {
                let _ = emit_connection_plan_transition(
                    &db_path,
                    &connection_plan_id,
                    ConnectionPlanStatus::Superseded,
                    "replaced_by_new_target_ingress",
                    0,
                );
                existing.cancel.cancel();
                let _ = tokio::task::spawn_blocking(move || { let _ = existing.join.join(); }).await;
            }

            let context = if let Some(context) = tenant_contexts.get(&target.tenant_id).cloned() {
                context
            } else {
                match build_tenant_client_config_from_db(&db_path, &target.tenant_id) {
                    Ok(client_config) => {
                        let context = TenantDispatchContext { client_config };
                        tenant_contexts.insert(target.tenant_id.clone(), context.clone());
                        context
                    }
                    Err(e) => {
                        let _ = emit_connection_plan_transition(
                            &db_path,
                            &connection_plan_id,
                            ConnectionPlanStatus::Deferred,
                            "missing_dispatch_context",
                            1_000,
                        );
                        warn!(
                            "Dropping target for tenant {}: no dispatch context ({})",
                            short_peer_id(&target.tenant_id),
                            e
                        );
                        continue;
                    }
                }
            };

            let bootstrap_fallback_client_config =
                match target.source_kind {
                    ConnectionPlanSourceKind::Bootstrap => {
                        match build_tenant_bootstrap_fallback_client_config_for_invite_from_db(
                            &db_path,
                            &target.tenant_id,
                            target.invite_event_id.as_deref().unwrap_or_default(),
                        ) {
                            Ok(cfg) => cfg,
                            Err(err) => {
                                warn!(
                            "Bootstrap fallback config unavailable for tenant {} invite {}: {}",
                            short_peer_id(&target.tenant_id),
                            short_peer_id(target.invite_event_id.as_deref().unwrap_or_default()),
                            err
                        );
                                None
                            }
                        }
                    }
                    ConnectionPlanSourceKind::ObservedPeer
                    | ConnectionPlanSourceKind::Discovery => None,
                };

            let worker_cancel = shutdown.child_token();
            let worker = std::thread::spawn({
                let db_path = db_path.clone();
                let tenant_id = target.tenant_id.clone();
                let remote_peer_id = target.remote_peer_id.clone();
                let endpoint = endpoint.clone();
                let worker_cancel = worker_cancel.clone();
                let connection_plan_id = connection_plan_id.clone();
                let bootstrap_fallback_client_config = bootstrap_fallback_client_config.clone();
                let sync_control = sync_control.clone();
                let remote = target.remote;
                move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("connect worker runtime");
                    runtime.block_on(run_connect_worker(
                        db_path,
                        tenant_id,
                        remote,
                        remote_peer_id,
                        endpoint,
                        context,
                        intro_spawner,
                        ingest,
                        worker_cancel,
                        connection_plan_id,
                        bootstrap_fallback_client_config,
                        sync_control,
                    ));
                }
            });

            reconciler.register(
                connection_plan_id.clone(),
                super::reconciler::WorkerHandle {
                    cancel: worker_cancel,
                    join: worker,
                },
            );
            let _ = emit_connection_plan_transition(
                &db_path,
                &connection_plan_id,
                ConnectionPlanStatus::Active,
                "connect_worker_spawned",
                0,
            );
        }
    }

    for (_, handle) in reconciler.drain() {
        handle.cancel.cancel();
        let _ = tokio::task::spawn_blocking(move || {
            let _ = handle.join.join();
        })
        .await;
    }

    Ok(())
}

// Test-only legacy helper — production code uses
// connection_planned::should_activate_plan from the event family.
#[cfg(test)]
fn should_initiate_connect_for_source(
    tenant_id: &str,
    source_kind: ConnectionPlanSourceKind,
    peer_id: &str,
) -> bool {
    match source_kind {
        ConnectionPlanSourceKind::Bootstrap => true,
        ConnectionPlanSourceKind::ObservedPeer | ConnectionPlanSourceKind::Discovery => matches!(
            preferred_connection_direction(tenant_id, peer_id),
            Some(SessionDirection::Outbound)
        ),
    }
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapDiscoveryAuth {
    None,
    AcceptedDiscoveryAndObserved,
    AcceptedObservedOnly,
    PendingOnly,
    SteadyStateOrMixed,
}

#[cfg(test)]
fn local_transport_target_is_bootstrap(conn: &rusqlite::Connection, tenant_id: &str) -> bool {
    resolve_tenant_transport_target(conn, tenant_id)
        .ok()
        .flatten()
        .map(|target| target.source == CRED_SOURCE_BOOTSTRAP)
        .unwrap_or(false)
}

#[cfg(test)]
fn classify_bootstrap_discovery_auth(
    db_path: &str,
    tenant_id: &str,
    peer_id: &str,
) -> BootstrapDiscoveryAuth {
    let Ok(fp_bytes) = hex::decode(peer_id) else {
        return BootstrapDiscoveryAuth::None;
    };
    if fp_bytes.len() != 32 {
        return BootstrapDiscoveryAuth::None;
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&fp_bytes);

    let Ok(conn) = open_connection(db_path) else {
        return BootstrapDiscoveryAuth::None;
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    let accepted_bootstrap_authorized = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM invite_bootstrap_trust
                 WHERE recorded_by = ?1
                   AND bootstrap_spki_fingerprint = ?2
                   AND expires_at > ?3
             )",
            rusqlite::params![tenant_id, fp.as_slice(), now_ms],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false);
    let pending_bootstrap_authorized = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM pending_invite_bootstrap_trust
                 WHERE recorded_by = ?1
                   AND expected_bootstrap_spki_fingerprint = ?2
                   AND expires_at > ?3
             )",
            rusqlite::params![tenant_id, fp.as_slice(), now_ms],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false);
    let steady_state = is_peer_shared_transport_fingerprint(&conn, tenant_id, &fp).unwrap_or(false);
    let local_bootstrap_target = local_transport_target_is_bootstrap(&conn, tenant_id);

    match (
        accepted_bootstrap_authorized,
        pending_bootstrap_authorized,
        steady_state,
        local_bootstrap_target,
    ) {
        (_, _, true, _) => BootstrapDiscoveryAuth::SteadyStateOrMixed,
        (true, false, false, true) => BootstrapDiscoveryAuth::AcceptedDiscoveryAndObserved,
        (true, false, false, false) => BootstrapDiscoveryAuth::AcceptedObservedOnly,
        (false, true, false, _) => BootstrapDiscoveryAuth::PendingOnly,
        (false, false, false, _) => BootstrapDiscoveryAuth::None,
        (true, true, false, _) => BootstrapDiscoveryAuth::SteadyStateOrMixed,
    }
}

#[cfg(test)]
fn should_initiate_connect_for_source_with_db(
    db_path: &str,
    tenant_id: &str,
    source_kind: ConnectionPlanSourceKind,
    peer_id: &str,
) -> bool {
    match source_kind {
        ConnectionPlanSourceKind::Discovery => {
            match classify_bootstrap_discovery_auth(db_path, tenant_id, peer_id) {
                BootstrapDiscoveryAuth::AcceptedDiscoveryAndObserved => true,
                BootstrapDiscoveryAuth::PendingOnly => false,
                BootstrapDiscoveryAuth::AcceptedObservedOnly
                | BootstrapDiscoveryAuth::None
                | BootstrapDiscoveryAuth::SteadyStateOrMixed => {
                    should_initiate_connect_for_source(tenant_id, source_kind, peer_id)
                }
            }
        }
        ConnectionPlanSourceKind::ObservedPeer | ConnectionPlanSourceKind::Bootstrap => true,
    }
}

async fn join_connect_worker(worker: ActiveConnectWorker) {
    let _ = tokio::task::spawn_blocking(move || {
        let _ = worker.join.join();
    })
    .await;
}

async fn cancel_bootstrap_workers_for_prefix(
    db_path: &str,
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
            let _ = emit_connection_plan_transition(
                db_path,
                &key,
                ConnectionPlanStatus::Superseded,
                "steady_state_target_replaced_bootstrap",
                0,
            );
            worker.cancel.cancel();
            join_connect_worker(worker).await;
            dispatcher.forget(&key);
        }
    }
}

async fn reap_finished_connect_workers(
    db_path: &str,
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
            let _ = emit_connection_plan_transition(
                db_path,
                &key,
                ConnectionPlanStatus::Finished,
                "connect_worker_exited",
                1_000,
            );
        }
    }
}

async fn run_connect_worker(
    db_path: String,
    tenant_id: String,
    remote: SocketAddr,
    remote_peer_id: String,
    endpoint: TransportEndpoint,
    context: TenantDispatchContext,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    shutdown: CancellationToken,
    connection_plan_id: String,
    bootstrap_fallback_client_config: Option<TransportClientConfig>,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
) {
    let mut warning_gate = RepeatedWarningGate::new(Duration::from_secs(300));
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        let result = connect_loop_with_coordination_until_cancel_with_fallback(
            &db_path,
            &tenant_id,
            endpoint.clone(),
            remote,
            &remote_peer_id,
            Some(context.client_config.clone()),
            intro_spawner,
            ingest,
            shutdown.clone(),
            bootstrap_fallback_client_config.clone(),
            Some(connection_plan_id.clone()),
            sync_control.clone(),
        )
        .await;

        if shutdown.is_cancelled() {
            break;
        }

        let stale_target = match &result {
            Ok(()) => {
                let message = format!("connect worker {} exited unexpectedly", connection_plan_id);
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
                        connection_plan_id, e
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
                connection_plan_id
            );
            break;
        }

        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_millis(1000)) => {}
        }
    }
}

fn short_peer_id(peer_id: &str) -> &str {
    &peer_id[..16.min(peer_id.len())]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::create_tables;
    use crate::db::transport_creds::{set_local_transport_target, CRED_SOURCE_PEER_SHARED};
    use crate::db::transport_trust::{
        record_invite_bootstrap_trust, record_pending_invite_bootstrap_trust,
    };

    #[test]
    fn transition_to_active_when_tenants_present() {
        assert_eq!(
            transition_state(
                RuntimeState::IdleNoTenants,
                RuntimeEvent::TenantSetChanged(1)
            ),
            RuntimeState::Active
        );
    }

    #[test]
    fn transition_to_idle_when_no_tenants() {
        assert_eq!(
            transition_state(RuntimeState::Active, RuntimeEvent::TenantSetChanged(0)),
            RuntimeState::IdleNoTenants
        );
    }

    #[test]
    fn shutdown_event_forces_idle_state() {
        assert_eq!(
            transition_state(RuntimeState::Active, RuntimeEvent::ShutdownRequested),
            RuntimeState::IdleNoTenants
        );
    }

    #[test]
    fn cancelled_worker_exit_is_expected() {
        let exit = WorkerExit {
            kind: WorkerKind::AcceptLoop,
            name: "accept".to_string(),
            result: Ok(()),
            cancelled: true,
        };
        match classify_worker_exit(&exit) {
            WorkerExitDisposition::Expected => {}
            other => panic!("unexpected classification: {:?}", other),
        }
    }

    #[test]
    fn accept_worker_unexpected_exit_is_fatal() {
        let exit = WorkerExit {
            kind: WorkerKind::AcceptLoop,
            name: "accept".to_string(),
            result: Ok(()),
            cancelled: false,
        };
        match classify_worker_exit(&exit) {
            WorkerExitDisposition::Fatal(msg) => {
                assert!(msg.contains("exited unexpectedly"));
            }
            other => panic!("unexpected classification: {:?}", other),
        }
    }

    #[test]
    fn worker_failure_policy_is_explicit_per_kind() {
        assert_eq!(
            worker_failure_policy(WorkerKind::AcceptLoop),
            WorkerFailurePolicy::FailRuntime
        );
        assert_eq!(
            worker_failure_policy(WorkerKind::BootstrapRefresher),
            WorkerFailurePolicy::FailRuntime
        );
        assert_eq!(
            worker_failure_policy(WorkerKind::ObservedEndpointRefresher),
            WorkerFailurePolicy::FailRuntime
        );
    }

    #[test]
    fn discovery_and_observed_targets_follow_preferred_side_gate() {
        let lower = "0000000000000000000000000000000000000000000000000000000000000001";
        let higher = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        assert!(should_initiate_connect_for_source(
            lower,
            ConnectionPlanSourceKind::Discovery,
            higher,
        ));
        assert!(!should_initiate_connect_for_source(
            higher,
            ConnectionPlanSourceKind::Discovery,
            lower,
        ));
        assert!(should_initiate_connect_for_source(
            lower,
            ConnectionPlanSourceKind::ObservedPeer,
            higher,
        ));
        assert!(!should_initiate_connect_for_source(
            higher,
            ConnectionPlanSourceKind::ObservedPeer,
            lower,
        ));
    }

    #[test]
    fn bootstrap_targets_always_allow_connect_initiation() {
        let tenant = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let peer = "0000000000000000000000000000000000000000000000000000000000000001";

        assert!(should_initiate_connect_for_source(
            tenant,
            ConnectionPlanSourceKind::Bootstrap,
            peer,
        ));
    }

    #[test]
    fn bootstrap_authorized_discovery_targets_override_preferred_side_gate() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bootstrap-discovery.db");
        let conn = open_connection(db_path.to_str().expect("db path")).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let peer = "0000000000000000000000000000000000000000000000000000000000000001";
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_BOOTSTRAP)
            .expect("set bootstrap local transport target");
        let fp = hex::decode(peer).expect("peer hex");
        let mut fp_arr = [0u8; 32];
        fp_arr.copy_from_slice(&fp);
        record_invite_bootstrap_trust(
            &conn,
            tenant,
            "invite-accepted",
            "invite-event",
            "workspace",
            "",
            &fp_arr,
        )
        .expect("record invite bootstrap trust");
        drop(conn);

        assert!(
            !should_initiate_connect_for_source(tenant, ConnectionPlanSourceKind::Discovery, peer,),
            "pure preferred-side gating should reject the non-preferred bootstrap peer"
        );
        assert!(
            should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                ConnectionPlanSourceKind::Discovery,
                peer,
            ),
            "bootstrap-authorized discovery peer should be allowed to connect until steady-state trust supersedes it"
        );
    }

    #[test]
    fn pending_bootstrap_discovery_targets_stay_bottlenecked() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("pending-bootstrap-discovery.db");
        let conn = open_connection(db_path.to_str().expect("db path")).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "0000000000000000000000000000000000000000000000000000000000000001";
        let peer = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let fp = hex::decode(peer).expect("peer hex");
        let mut fp_arr = [0u8; 32];
        fp_arr.copy_from_slice(&fp);
        record_pending_invite_bootstrap_trust(&conn, tenant, "invite-event", "workspace", &fp_arr)
            .expect("record pending invite bootstrap trust");
        drop(conn);

        assert!(
            should_initiate_connect_for_source(tenant, ConnectionPlanSourceKind::Discovery, peer,),
            "pure preferred-side gating would allow the inviter side to dial here"
        );
        assert!(
            !should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                ConnectionPlanSourceKind::Discovery,
                peer,
            ),
            "pending bootstrap trust should keep the inviter side bottlenecked"
        );
    }

    #[test]
    fn pending_bootstrap_observed_targets_can_reconnect_exact_peer() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("pending-bootstrap-observed.db");
        let conn = open_connection(db_path.to_str().expect("db path")).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "0000000000000000000000000000000000000000000000000000000000000001";
        let peer = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let fp = hex::decode(peer).expect("peer hex");
        let mut fp_arr = [0u8; 32];
        fp_arr.copy_from_slice(&fp);
        record_pending_invite_bootstrap_trust(&conn, tenant, "invite-event", "workspace", &fp_arr)
            .expect("record pending invite bootstrap trust");
        drop(conn);

        assert!(
            should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                ConnectionPlanSourceKind::ObservedPeer,
                peer,
            ),
            "pending bootstrap trust should still allow exact observed-endpoint reconnects"
        );
        assert!(
            !should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                ConnectionPlanSourceKind::Discovery,
                peer,
            ),
            "pending bootstrap trust must continue bottlenecking broad discovery dialing"
        );
    }

    #[test]
    fn discovery_source_beats_bootstrap_source_for_same_peer() {
        assert!(
            existing_source_has_higher_precedence(
                ConnectionPlanSourceKind::Discovery,
                ConnectionPlanSourceKind::Bootstrap,
            ),
            "stale bootstrap targets must not replace a live discovery worker for the same peer"
        );
        assert!(
            existing_source_has_higher_precedence(
                ConnectionPlanSourceKind::ObservedPeer,
                ConnectionPlanSourceKind::Bootstrap,
            ),
            "stale bootstrap targets must not replace a live observed-endpoint worker for the same peer"
        );
        assert!(
            !existing_source_has_higher_precedence(
                ConnectionPlanSourceKind::Bootstrap,
                ConnectionPlanSourceKind::Discovery,
            ),
            "discovery must be able to supersede a stale bootstrap worker"
        );
    }

    #[test]
    fn bootstrap_authorized_observed_targets_override_preferred_side_gate() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bootstrap-observed.db");
        let conn = open_connection(db_path.to_str().expect("db path")).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let peer = "0000000000000000000000000000000000000000000000000000000000000001";
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_BOOTSTRAP)
            .expect("set bootstrap local transport target");
        let fp = hex::decode(peer).expect("peer hex");
        let mut fp_arr = [0u8; 32];
        fp_arr.copy_from_slice(&fp);
        record_invite_bootstrap_trust(
            &conn,
            tenant,
            "invite-accepted",
            "invite-event",
            "workspace",
            "",
            &fp_arr,
        )
        .expect("record invite bootstrap trust");
        drop(conn);

        assert!(
            !matches!(
                preferred_connection_direction(tenant, peer),
                Some(SessionDirection::Outbound)
            ),
            "test setup requires the observed peer to be non-preferred"
        );
        assert!(
            !should_initiate_connect_for_source(
                tenant,
                ConnectionPlanSourceKind::ObservedPeer,
                peer,
            ),
            "pure preferred-side gating should reject the non-preferred observed peer"
        );
        assert!(
            should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                ConnectionPlanSourceKind::ObservedPeer,
                peer,
            ),
            "bootstrap-authorized observed endpoints should be allowed until steady-state trust supersedes them"
        );
    }

    #[test]
    fn converged_local_transport_target_keeps_bootstrap_authorized_discovery_bottlenecked() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bootstrap-discovery-converged.db");
        let conn = open_connection(db_path.to_str().expect("db path")).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let peer = "0000000000000000000000000000000000000000000000000000000000000001";
        set_local_transport_target(&conn, tenant, tenant, CRED_SOURCE_PEER_SHARED)
            .expect("set peershared local transport target");
        let fp = hex::decode(peer).expect("peer hex");
        let mut fp_arr = [0u8; 32];
        fp_arr.copy_from_slice(&fp);
        record_invite_bootstrap_trust(
            &conn,
            tenant,
            "invite-accepted",
            "invite-event",
            "workspace",
            "",
            &fp_arr,
        )
        .expect("record invite bootstrap trust");
        drop(conn);

        assert!(
            !should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                ConnectionPlanSourceKind::Discovery,
                peer,
            ),
            "once local transport has converged to peershared, bootstrap trust must not re-enable non-preferred discovery dialing"
        );
    }

    #[test]
    fn converged_local_transport_target_still_allows_bootstrap_authorized_observed_reconnects() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bootstrap-observed-converged.db");
        let conn = open_connection(db_path.to_str().expect("db path")).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        let peer = "0000000000000000000000000000000000000000000000000000000000000001";
        set_local_transport_target(&conn, tenant, tenant, CRED_SOURCE_PEER_SHARED)
            .expect("set peershared local transport target");
        let fp = hex::decode(peer).expect("peer hex");
        let mut fp_arr = [0u8; 32];
        fp_arr.copy_from_slice(&fp);
        record_invite_bootstrap_trust(
            &conn,
            tenant,
            "invite-accepted",
            "invite-event",
            "workspace",
            "",
            &fp_arr,
        )
        .expect("record invite bootstrap trust");
        drop(conn);

        assert!(
            should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                ConnectionPlanSourceKind::ObservedPeer,
                peer,
            ),
            "exact observed-endpoint reconnects should stay allowed until steady-state peer trust supersedes bootstrap auth"
        );
        assert!(
            !should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                ConnectionPlanSourceKind::Discovery,
                peer,
            ),
            "broad discovery should still stay bottlenecked after local transport convergence"
        );
    }
}
