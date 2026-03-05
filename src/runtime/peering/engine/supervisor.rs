//! Runtime task-graph supervisor.
//!
//! This module is the single owner of long-lived runtime workers:
//! - shared ingest writer
//! - accept loop
//! - unified target ingress/dispatch
//! - bootstrap refresher
//! - discovery ingress workers (feature-gated)

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Notify};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::contracts::event_pipeline_contract::{IngestFns, IngestItem};
use crate::db::transport_creds::TenantInfo;
use crate::peering::loops::{
    accept_loop_with_ingest_until_cancel,
    connect_loop_with_coordination_until_cancel_with_fallback, IntroSpawnerFn,
};
use crate::sync::CoordinationManager;
use crate::transport::{
    build_tenant_bootstrap_fallback_client_config_from_db, build_tenant_client_config_from_db,
    TenantClientConfigs, TransportClientConfig, TransportEndpoint,
};
use crate::tuning::shared_ingest_cap;

use super::target_planner::{
    bootstrap_dispatch_key, collect_all_bootstrap_targets, discovery_dispatch_key,
    dispatch_bootstrap_target, dispatch_discovery_target, normalize_discovered_addr_for_local_bind,
    PeerDispatcher,
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
    BatchWriter,
    AcceptLoop,
    TargetDispatcher,
    BootstrapRefresher,
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
    bootstrap_fallback_client_config: Option<TransportClientConfig>,
    coordination_manager: Arc<CoordinationManager>,
}

#[derive(Clone, Debug)]
enum TargetIngressSource {
    Bootstrap,
    Discovery { peer_id: String },
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
        }
    }

    pub(crate) async fn run_until_shutdown(
        &mut self,
        shutdown_notify: Arc<Notify>,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        self.state = transition_state(
            self.state,
            RuntimeEvent::TenantSetChanged(self.tenants.len()),
        );
        info!("runtime supervisor state: {:?}", self.state);

        let root_cancel = CancellationToken::new();
        let mut workers = JoinSet::<WorkerExit>::new();

        let tenant_ids: Vec<String> = self.tenants.iter().map(|t| t.peer_id.clone()).collect();
        let tenant_contexts = build_tenant_contexts(&self.db_path, &tenant_ids);

        let ingest_cap = shared_ingest_cap();
        let (shared_tx, shared_rx) = mpsc::channel::<IngestItem>(ingest_cap);
        let events_received = Arc::new(AtomicU64::new(0));

        spawn_batch_writer_worker(
            &mut workers,
            self.ingest,
            self.db_path.clone(),
            shared_rx,
            events_received.clone(),
            root_cancel.child_token(),
        );

        let (target_tx, target_rx) = mpsc::unbounded_channel::<TargetIngressEvent>();

        // Accept worker: inbound transport sessions for all known tenants.
        {
            let db_path = self.db_path.clone();
            let endpoint = self.endpoint.clone();
            let tenant_ids = tenant_ids.clone();
            let shared_ingest = shared_tx.clone();
            let tenant_cfgs = self.tenant_client_configs.clone();
            let intro_spawner = self.intro_spawner;
            let ingest = self.ingest;
            let cancel = root_cancel.child_token();
            spawn_worker(
                &mut workers,
                WorkerKind::AcceptLoop,
                "accept-loop",
                cancel.clone(),
                async move {
                    accept_loop_with_ingest_until_cancel(
                        &db_path,
                        &tenant_ids,
                        endpoint,
                        cancel,
                        None,
                        shared_ingest,
                        tenant_cfgs,
                        intro_spawner,
                        ingest,
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
                    )
                    .await
                },
            );
        }

        // Bootstrap refresher emits into unified target ingress channel.
        if env_flag("P7_DISABLE_PLACEHOLDER_AUTODIAL") {
            warn!("BOOTSTRAP AUTODIAL DISABLED by P7_DISABLE_PLACEHOLDER_AUTODIAL");
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

        #[cfg(feature = "discovery")]
        let mut discovery_handles = Vec::new();

        #[cfg(feature = "discovery")]
        if env_flag("P7_DISABLE_DISCOVERY") {
            warn!("mDNS discovery disabled by P7_DISABLE_DISCOVERY");
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

        // Let the writer drain and stop.
        drop(target_tx);
        drop(shared_tx);

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

        Ok(events_received.load(Ordering::Relaxed))
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

        out.insert(
            tenant_id.clone(),
            TenantDispatchContext {
                client_config,
                bootstrap_fallback_client_config:
                    match build_tenant_bootstrap_fallback_client_config_from_db(db_path, tenant_id)
                    {
                        Ok(cfg) => cfg,
                        Err(e) => {
                            warn!(
                                "Bootstrap fallback config unavailable for tenant {}: {}",
                                short_peer_id(tenant_id),
                                e
                            );
                            None
                        }
                    },
                coordination_manager: Arc::new(CoordinationManager::new()),
            },
        );
    }
    out
}

fn spawn_batch_writer_worker(
    workers: &mut JoinSet<WorkerExit>,
    ingest: IngestFns,
    db_path: String,
    rx: mpsc::Receiver<IngestItem>,
    events_received: Arc<AtomicU64>,
    cancel: CancellationToken,
) {
    let writer = ingest.batch_writer;
    spawn_worker(
        workers,
        WorkerKind::BatchWriter,
        "shared-batch-writer",
        cancel,
        async move {
            tokio::task::spawn_blocking(move || {
                writer(db_path, rx, events_received);
            })
            .await
            .map_err(|e| format!("batch_writer worker join error: {}", e))?;
            Ok(())
        },
    );
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
        WorkerKind::BatchWriter
        | WorkerKind::AcceptLoop
        | WorkerKind::TargetDispatcher
        | WorkerKind::BootstrapRefresher => WorkerFailurePolicy::FailRuntime,
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
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        match collect_all_bootstrap_targets(&db_path) {
            Ok(targets) => {
                for (tenant_id, remote) in targets {
                    if ingress_tx
                        .send(TargetIngressEvent {
                            tenant_id,
                            remote,
                            source: TargetIngressSource::Bootstrap,
                        })
                        .is_err()
                    {
                        return Ok(());
                    }
                }
            }
            Err(e) => warn!("BOOTSTRAP AUTODIAL REFRESH failed: {}", e),
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
            TargetIngressSource::Bootstrap => bootstrap_dispatch_key(&event.tenant_id),
            TargetIngressSource::Discovery { peer_id } => {
                discovery_dispatch_key(&event.tenant_id, peer_id)
            }
        };

        let should_spawn = match &event.source {
            TargetIngressSource::Bootstrap => {
                dispatch_bootstrap_target(&mut dispatcher, &event.tenant_id, event.remote)
            }
            TargetIngressSource::Discovery { peer_id } => {
                dispatch_discovery_target(&mut dispatcher, &event.tenant_id, peer_id, event.remote)
            }
        };
        let allow_bootstrap_fallback = matches!(&event.source, TargetIngressSource::Bootstrap);

        if !should_spawn {
            continue;
        }

        if let Some(existing) = active_workers.remove(&dispatch_key) {
            existing.cancel.cancel();
            join_connect_worker(existing).await;
        }

        let context = if let Some(context) = tenant_contexts.get(&event.tenant_id).cloned() {
            context
        } else {
            match build_tenant_client_config_from_db(&db_path, &event.tenant_id) {
                Ok(client_config) => {
                    let context = TenantDispatchContext {
                        client_config,
                        bootstrap_fallback_client_config:
                            match build_tenant_bootstrap_fallback_client_config_from_db(
                                &db_path,
                                &event.tenant_id,
                            ) {
                                Ok(cfg) => cfg,
                                Err(err) => {
                                    warn!(
                                        "Bootstrap fallback config unavailable for tenant {}: {}",
                                        short_peer_id(&event.tenant_id),
                                        err
                                    );
                                    None
                                }
                            },
                        coordination_manager: Arc::new(CoordinationManager::new()),
                    };
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

        let worker_cancel = shutdown.child_token();
        let worker = std::thread::spawn({
            let db_path = db_path.clone();
            let tenant_id = event.tenant_id.clone();
            let endpoint = endpoint.clone();
            let worker_cancel = worker_cancel.clone();
            let dispatch_key = dispatch_key.clone();
            move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("connect worker runtime");
                runtime.block_on(run_connect_worker(
                    db_path,
                    tenant_id,
                    event.remote,
                    endpoint,
                    context,
                    intro_spawner,
                    ingest,
                    worker_cancel,
                    dispatch_key,
                    allow_bootstrap_fallback,
                ));
            }
        });

        active_workers.insert(
            dispatch_key,
            ActiveConnectWorker {
                cancel: worker_cancel,
                join: worker,
            },
        );
    }

    for (_, worker) in active_workers {
        worker.cancel.cancel();
        join_connect_worker(worker).await;
    }

    Ok(())
}

async fn join_connect_worker(worker: ActiveConnectWorker) {
    let _ = tokio::task::spawn_blocking(move || {
        let _ = worker.join.join();
    })
    .await;
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
    endpoint: TransportEndpoint,
    context: TenantDispatchContext,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
    shutdown: CancellationToken,
    dispatch_key: String,
    allow_bootstrap_fallback: bool,
) {
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        let result = connect_loop_with_coordination_until_cancel_with_fallback(
            &db_path,
            &tenant_id,
            endpoint.clone(),
            remote,
            Some(context.client_config.clone()),
            intro_spawner,
            ingest,
            context.coordination_manager.clone(),
            shutdown.clone(),
            if allow_bootstrap_fallback {
                context.bootstrap_fallback_client_config.clone()
            } else {
                None
            },
        )
        .await;

        if shutdown.is_cancelled() {
            break;
        }

        let stale_target = match &result {
            Ok(()) => {
                warn!("connect worker {} exited unexpectedly", dispatch_key);
                false
            }
            Err(e) => {
                warn!(
                    "connect worker {} failed: {}; restarting with backoff",
                    dispatch_key, e
                );
                e.to_string().contains(STALE_DIAL_TARGET_MARKER)
            }
        };
        if stale_target {
            warn!(
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
    }
}
