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

use tokio::sync::{mpsc, Notify};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::target_planner::{
    bootstrap_dispatch_key, bootstrap_dispatch_key_prefix, collect_all_bootstrap_targets,
    collect_all_observed_endpoint_targets, discovery_dispatch_key, dispatch_bootstrap_target,
    dispatch_discovery_target, dispatch_observed_endpoint_target,
    normalize_discovered_addr_for_local_bind, PeerDispatcher,
};
use crate::contracts::event_pipeline_contract::IngestFns;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::open_connection;
use crate::db::transport_creds::{
    resolve_tenant_transport_target, TenantInfo, CRED_SOURCE_BOOTSTRAP,
};
use crate::db::transport_trust::is_peer_shared_transport_fingerprint;
use crate::peering::loops::{
    accept_loop_until_cancel, connect_loop_with_coordination_until_cancel_with_fallback,
    preferred_connection_direction, IntroSpawnerFn,
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
    source: TargetIngressSource,
}

fn source_precedence(source: &TargetIngressSource) -> u8 {
    match source {
        TargetIngressSource::Bootstrap { .. } => 0,
        TargetIngressSource::ObservedPeer { .. } | TargetIngressSource::Discovery { .. } => 1,
    }
}

fn should_ignore_target_event(
    existing: &TargetIngressSource,
    incoming: &TargetIngressSource,
) -> bool {
    source_precedence(existing) > source_precedence(incoming)
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

        let (target_tx, target_rx) = mpsc::unbounded_channel::<TargetIngressEvent>();

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
                        target_rx,
                        cancel,
                        sync_control,
                    )
                    .await
                },
            );
        }

        // Bootstrap refresher emits into unified target ingress channel.
        if env_flag("TOPO_DISABLE_PLACEHOLDER_AUTODIAL") {
            warn!("BOOTSTRAP AUTODIAL DISABLED by TOPO_DISABLE_PLACEHOLDER_AUTODIAL");
        } else {
            let db_path = self.db_path.clone();
            let ingress = target_tx.clone();
            let cancel = root_cancel.child_token();
            spawn_worker(
                &mut workers,
                WorkerKind::BootstrapRefresher,
                "bootstrap-refresher",
                cancel.clone(),
                async move { run_bootstrap_refresher(db_path, ingress, cancel).await },
            );
        }

        {
            let db_path = self.db_path.clone();
            let ingress = target_tx.clone();
            let cancel = root_cancel.child_token();
            spawn_worker(
                &mut workers,
                WorkerKind::ObservedEndpointRefresher,
                "observed-endpoint-refresher",
                cancel.clone(),
                async move { run_observed_endpoint_refresher(db_path, ingress, cancel).await },
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
                let ingress = target_tx.clone();
                let cancel = root_cancel.child_token();
                let worker_name = format!("discovery-ingress-{}", short_peer_id(&source.tenant_id));
                spawn_worker(
                    &mut workers,
                    WorkerKind::DiscoveryIngress,
                    worker_name,
                    cancel.clone(),
                    async move { run_discovery_ingress_worker(source, ingress, cancel).await },
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

        drop(target_tx);

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

async fn run_bootstrap_refresher(
    db_path: String,
    ingress_tx: mpsc::UnboundedSender<TargetIngressEvent>,
    shutdown: CancellationToken,
) -> Result<(), String> {
    let mut warning_gate = RepeatedWarningGate::new(Duration::from_secs(300));
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        match collect_all_bootstrap_targets(&db_path) {
            Ok(targets) => {
                warning_gate.clear();
                for (tenant_id, peer_id, invite_event_id, remote) in targets {
                    if ingress_tx
                        .send(TargetIngressEvent {
                            tenant_id,
                            remote,
                            source: TargetIngressSource::Bootstrap {
                                peer_id,
                                invite_event_id,
                            },
                        })
                        .is_err()
                    {
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                let message = format!("BOOTSTRAP AUTODIAL REFRESH failed: {}", e);
                if warning_gate.should_emit(message.clone())
                    && should_emit_globally(format!("engine:{message}"))
                {
                    warn!("{}", message);
                }
            }
        }

        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_millis(1000)) => {}
        }
    }

    Ok(())
}

async fn run_observed_endpoint_refresher(
    db_path: String,
    ingress_tx: mpsc::UnboundedSender<TargetIngressEvent>,
    shutdown: CancellationToken,
) -> Result<(), String> {
    let mut warning_gate = RepeatedWarningGate::new(Duration::from_secs(300));
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        match collect_all_observed_endpoint_targets(&db_path) {
            Ok(targets) => {
                warning_gate.clear();
                for (tenant_id, peer_id, remote) in targets {
                    if ingress_tx
                        .send(TargetIngressEvent {
                            tenant_id,
                            remote,
                            source: TargetIngressSource::ObservedPeer { peer_id },
                        })
                        .is_err()
                    {
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                let message = format!("OBSERVED ENDPOINT REFRESH failed: {}", e);
                if warning_gate.should_emit(message.clone())
                    && should_emit_globally(format!("engine:{message}"))
                {
                    warn!("{}", message);
                }
            }
        }

        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_millis(1000)) => {}
        }
    }

    Ok(())
}

#[cfg(feature = "discovery")]
async fn run_discovery_ingress_worker(
    source: super::discovery::DiscoveryIngressSource,
    ingress_tx: mpsc::UnboundedSender<TargetIngressEvent>,
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
                    if ingress_tx
                        .send(TargetIngressEvent {
                            tenant_id: source.tenant_id.clone(),
                            remote: dial_addr,
                            source: TargetIngressSource::Discovery {
                                peer_id: peer.peer_id,
                            },
                        })
                        .is_err()
                    {
                        break;
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
    mut ingress_rx: mpsc::UnboundedReceiver<TargetIngressEvent>,
    shutdown: CancellationToken,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
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
            TargetIngressSource::Bootstrap { peer_id, .. } => {
                bootstrap_dispatch_key(&event.tenant_id, peer_id, event.remote)
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
            TargetIngressSource::Bootstrap { peer_id, .. } => {
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

        let worker_cancel = shutdown.child_token();
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
            let remote_peer_id = match &event.source {
                TargetIngressSource::Bootstrap { peer_id, .. }
                | TargetIngressSource::ObservedPeer { peer_id }
                | TargetIngressSource::Discovery { peer_id } => peer_id.clone(),
            };
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

fn preferred_outbound_only_peer_id(source: &TargetIngressSource) -> Option<&str> {
    match source {
        TargetIngressSource::Discovery { peer_id } => Some(peer_id),
        TargetIngressSource::Bootstrap { .. } | TargetIngressSource::ObservedPeer { .. } => None,
    }
}

fn should_initiate_connect_for_source(tenant_id: &str, source: &TargetIngressSource) -> bool {
    match source {
        TargetIngressSource::Bootstrap { .. } => true,
        TargetIngressSource::ObservedPeer { peer_id }
        | TargetIngressSource::Discovery { peer_id } => matches!(
            preferred_connection_direction(tenant_id, peer_id),
            Some(SessionDirection::Outbound)
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BootstrapDiscoveryAuth {
    None,
    AcceptedDiscoveryAndObserved,
    AcceptedObservedOnly,
    PendingOnly,
    SteadyStateOrMixed,
}

fn local_transport_target_is_bootstrap(conn: &rusqlite::Connection, tenant_id: &str) -> bool {
    resolve_tenant_transport_target(conn, tenant_id)
        .ok()
        .flatten()
        .map(|target| target.source == CRED_SOURCE_BOOTSTRAP)
        .unwrap_or(false)
}

/// Check whether a tenant is still in bootstrap phase (its local transport
/// credential comes from an invite rather than steady-state PeerShared).
fn is_tenant_in_bootstrap_phase(db_path: &str, tenant_id: &str) -> bool {
    open_connection(db_path)
        .ok()
        .map(|conn| local_transport_target_is_bootstrap(&conn, tenant_id))
        .unwrap_or(false)
}

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

fn should_initiate_connect_for_source_with_db(
    db_path: &str,
    tenant_id: &str,
    source: &TargetIngressSource,
) -> bool {
    match source {
        TargetIngressSource::Discovery { peer_id } => {
            match classify_bootstrap_discovery_auth(db_path, tenant_id, peer_id) {
                BootstrapDiscoveryAuth::AcceptedDiscoveryAndObserved => true,
                BootstrapDiscoveryAuth::PendingOnly => false,
                BootstrapDiscoveryAuth::AcceptedObservedOnly
                | BootstrapDiscoveryAuth::None
                | BootstrapDiscoveryAuth::SteadyStateOrMixed => {
                    should_initiate_connect_for_source(tenant_id, source)
                }
            }
        }
        TargetIngressSource::ObservedPeer { .. } => true,
        TargetIngressSource::Bootstrap { .. } => true,
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
        TargetIngressSource::Bootstrap { peer_id, .. }
        | TargetIngressSource::ObservedPeer { peer_id }
        | TargetIngressSource::Discovery { peer_id } => {
            discovery_dispatch_key(&event.tenant_id, peer_id)
        }
    }
}

fn bootstrap_worker_prefix_for_event(event: &TargetIngressEvent) -> String {
    match &event.source {
        TargetIngressSource::Bootstrap { peer_id, .. }
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
    dispatch_key: String,
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
            sync_control.clone(),
        )
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
                peer_id: peer.to_string(),
                invite_event_id: "invite".to_string(),
            }
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
            !should_initiate_connect_for_source(
                tenant,
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
            ),
            "pure preferred-side gating should reject the non-preferred bootstrap peer"
        );
        assert!(
            should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
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
            should_initiate_connect_for_source(
                tenant,
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
            ),
            "pure preferred-side gating would allow the inviter side to dial here"
        );
        assert!(
            !should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
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
                &TargetIngressSource::ObservedPeer {
                    peer_id: peer.to_string(),
                }
            ),
            "pending bootstrap trust should still allow exact observed-endpoint reconnects"
        );
        assert!(
            !should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
            ),
            "pending bootstrap trust must continue bottlenecking broad discovery dialing"
        );
    }

    #[test]
    fn discovery_source_beats_bootstrap_source_for_same_peer() {
        let bootstrap = TargetIngressSource::Bootstrap {
            peer_id: "peer".to_string(),
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
                &TargetIngressSource::ObservedPeer {
                    peer_id: peer.to_string(),
                }
            ),
            "pure preferred-side gating should reject the non-preferred observed peer"
        );
        assert!(
            should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                &TargetIngressSource::ObservedPeer {
                    peer_id: peer.to_string(),
                }
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
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
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
                &TargetIngressSource::ObservedPeer {
                    peer_id: peer.to_string(),
                }
            ),
            "exact observed-endpoint reconnects should stay allowed until steady-state peer trust supersedes bootstrap auth"
        );
        assert!(
            !should_initiate_connect_for_source_with_db(
                db_path.to_str().expect("db path"),
                tenant,
                &TargetIngressSource::Discovery {
                    peer_id: peer.to_string(),
                }
            ),
            "broad discovery should still stay bottlenecked after local transport convergence"
        );
    }

    // -----------------------------------------------------------------------
    // Bootstrap-phase guards: during bootstrap, no source may suppress or
    // cancel Bootstrap workers because only Bootstrap carries the invite
    // fallback cert that the inviter will accept.
    // -----------------------------------------------------------------------

    #[test]
    fn bootstrap_phase_detected_for_bootstrap_transport_target() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bs-phase-detect.db");
        let db_str = db_path.to_str().expect("db path");
        let conn = open_connection(db_str).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let peer = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        // No transport target → not in bootstrap phase
        assert!(
            !is_tenant_in_bootstrap_phase(db_str, tenant),
            "tenant with no transport target should not be in bootstrap phase"
        );

        // Bootstrap transport target → in bootstrap phase
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_BOOTSTRAP)
            .expect("set bootstrap target");
        drop(conn);
        assert!(
            is_tenant_in_bootstrap_phase(db_str, tenant),
            "tenant with bootstrap transport target must be detected as bootstrap phase"
        );

        // PeerShared transport target → no longer in bootstrap phase
        let conn = open_connection(db_str).expect("open db");
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_PEER_SHARED)
            .expect("set peershared target");
        drop(conn);
        assert!(
            !is_tenant_in_bootstrap_phase(db_str, tenant),
            "tenant with peershared transport target must not be in bootstrap phase"
        );
    }

    /// During bootstrap phase, a Bootstrap connect event must never be
    /// suppressed by an existing Discovery or ObservedPeer worker.
    ///
    /// Only the Bootstrap source carries the invite fallback TLS cert.
    /// If Discovery or ObservedPeer suppress it, the invitee is stuck
    /// because those sources use the PeerShared cert the inviter does
    /// not yet trust.
    #[test]
    fn bootstrap_events_never_suppressed_during_bootstrap_phase() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bs-suppress-guard.db");
        let db_str = db_path.to_str().expect("db path");
        let conn = open_connection(db_str).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let peer = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        // Put tenant in bootstrap phase
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_BOOTSTRAP)
            .expect("set bootstrap target");
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

        let bootstrap = TargetIngressSource::Bootstrap {
            peer_id: peer.to_string(),
            invite_event_id: "invite".to_string(),
        };

        // Test against every non-Bootstrap source type
        let competing_sources = [
            TargetIngressSource::Discovery {
                peer_id: peer.to_string(),
            },
            TargetIngressSource::ObservedPeer {
                peer_id: peer.to_string(),
            },
        ];

        for existing in &competing_sources {
            // Precondition: the competing source has higher precedence
            assert!(
                should_ignore_target_event(existing, &bootstrap),
                "{:?} should have higher static precedence than Bootstrap",
                existing
            );

            // The dispatcher's combined suppression decision mirrors:
            //   suppress = should_ignore(existing, bootstrap)
            //              && !is_tenant_in_bootstrap_phase(db, tenant)
            let would_suppress = should_ignore_target_event(existing, &bootstrap)
                && !is_tenant_in_bootstrap_phase(db_str, tenant);
            assert!(
                !would_suppress,
                "during bootstrap phase, {:?} must NOT suppress Bootstrap events",
                existing
            );
        }

        // The dispatcher's cancellation decision mirrors:
        //   cancel_bootstrap = is_non_bootstrap_source
        //                      && !is_tenant_in_bootstrap_phase(db, tenant)
        assert!(
            !(!is_tenant_in_bootstrap_phase(db_str, tenant)),
            "during bootstrap phase, non-bootstrap events must not cancel bootstrap workers"
        );

        // After bootstrap completes, normal precedence resumes
        let conn = open_connection(db_str).expect("open db");
        set_local_transport_target(&conn, tenant, tenant, CRED_SOURCE_PEER_SHARED)
            .expect("transition to peershared");
        drop(conn);

        assert!(
            !is_tenant_in_bootstrap_phase(db_str, tenant),
            "tenant should have exited bootstrap phase"
        );
        for existing in &competing_sources {
            // After bootstrap, suppression IS allowed
            let would_suppress = should_ignore_target_event(existing, &bootstrap)
                && !is_tenant_in_bootstrap_phase(db_str, tenant);
            assert!(
                would_suppress,
                "after bootstrap, {:?} SHOULD suppress stale Bootstrap events",
                existing
            );
        }
        // After bootstrap, cancellation IS allowed
        assert!(
            !is_tenant_in_bootstrap_phase(db_str, tenant),
            "after bootstrap, non-bootstrap events may cancel bootstrap workers"
        );
    }

    /// During bootstrap phase, Discovery/ObservedPeer events must not
    /// cancel running Bootstrap workers.
    ///
    /// The dispatcher decides whether to cancel bootstrap workers via:
    ///   cancel = is_non_bootstrap_source && !is_tenant_in_bootstrap_phase(..)
    #[test]
    fn bootstrap_workers_not_cancelled_during_bootstrap_phase() {
        let tmpdir = tempfile::tempdir().expect("tempdir");
        let db_path = tmpdir.path().join("bs-cancel-guard.db");
        let db_str = db_path.to_str().expect("db path");
        let conn = open_connection(db_str).expect("open db");
        create_tables(&conn).expect("create tables");

        let tenant = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let peer = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

        let non_bootstrap_sources = [
            TargetIngressSource::Discovery {
                peer_id: peer.to_string(),
            },
            TargetIngressSource::ObservedPeer {
                peer_id: peer.to_string(),
            },
        ];

        // Bootstrap phase: cancellation must be blocked
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_BOOTSTRAP)
            .expect("set bootstrap target");
        drop(conn);

        for source in &non_bootstrap_sources {
            let would_cancel = matches!(
                source,
                TargetIngressSource::ObservedPeer { .. } | TargetIngressSource::Discovery { .. }
            ) && !is_tenant_in_bootstrap_phase(db_str, tenant);
            assert!(
                !would_cancel,
                "during bootstrap phase, {:?} must NOT cancel bootstrap workers",
                source
            );
        }

        // Steady state: cancellation is allowed
        let conn = open_connection(db_str).expect("open db");
        set_local_transport_target(&conn, tenant, peer, CRED_SOURCE_PEER_SHARED)
            .expect("transition to peershared");
        drop(conn);

        for source in &non_bootstrap_sources {
            let would_cancel = matches!(
                source,
                TargetIngressSource::ObservedPeer { .. } | TargetIngressSource::Discovery { .. }
            ) && !is_tenant_in_bootstrap_phase(db_str, tenant);
            assert!(
                would_cancel,
                "after bootstrap, {:?} SHOULD cancel stale bootstrap workers",
                source
            );
        }
    }
}
