//! Runtime task-graph supervisor.
//!
//! This module is the single owner of long-lived runtime workers:
//! - shared ingest writer
//! - accept loop
//! - unified target ingress/dispatch
//! - bootstrap refresher
//! - observed-endpoint refresher
//! - discovery ingress workers (feature-gated)

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Notify};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::target_dispatch::{
    build_tenant_contexts, run_target_dispatcher, TargetIngressEvent, TargetIngressSource,
};
use super::target_planner::{
    collect_all_bootstrap_targets, collect_all_observed_endpoint_targets,
    normalize_discovered_addr_for_local_bind,
};
use crate::contracts::event_pipeline_contract::IngestFns;
use crate::db::transport_creds::TenantInfo;
use crate::peering::loops::{accept_loop_until_cancel, short_peer_id, IntroSpawnerFn};
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::transport::{TenantClientConfigs, TransportEndpoint};

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

// ---- Refresher loops -----------------------------------------------------

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
                                daemon_peer_id: peer_id,
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

// ---- Discovery ingress ---------------------------------------------------

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

// ---- Tests ---------------------------------------------------------------

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
        assert_eq!(
            worker_failure_policy(WorkerKind::ObservedEndpointRefresher),
            WorkerFailurePolicy::FailRuntime
        );
    }
}
