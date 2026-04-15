//! Runtime task-graph supervisor.
//!
//! This module is the single owner of long-lived runtime workers:
//! - shared ingest writer
//! - accept loop
//! - unified target ingress/dispatch
//! - key repair loop
//! - outbound target planner refresher

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, Notify};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::target_dispatch::{run_target_dispatcher, TargetIngressEvent};
use super::target_planner::{collect_desired_outbound_targets, TargetPlannerOptions};
use crate::contracts::event_pipeline_contract::IngestFns;
use crate::db::transport_creds::TenantInfo;
use crate::peering::loops::accept_loop_until_cancel;
use crate::runtime::key_repair::run_periodic_key_repair;
use crate::runtime::repeated_warning::{should_emit_globally, RepeatedWarningGate};
use crate::transport::TransportEndpoint;

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
    KeyRepairLoop,
    PlannerRefresher,
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
    tenants: Vec<TenantInfo>,
    ingest: IngestFns,
    state: RuntimeState,
    sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
}

impl RuntimeSupervisor {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        db_path: String,
        endpoint: TransportEndpoint,
        tenants: Vec<TenantInfo>,
        ingest: IngestFns,
        sync_control: Option<std::sync::Arc<crate::runtime::sync_control::SyncControlRegistry>>,
    ) -> Self {
        Self {
            db_path,
            endpoint,
            tenants,
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
        let (target_tx, target_rx) = mpsc::unbounded_channel::<TargetIngressEvent>();

        {
            let db_path = self.db_path.clone();
            let endpoint = self.endpoint.clone();
            let tenant_ids = tenant_ids.clone();
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
                        ingest,
                        sync_control,
                    )
                    .await
                    .map_err(|e| e.to_string())
                },
            );
        }

        {
            let db_path = self.db_path.clone();
            let endpoint = self.endpoint.clone();
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
                        ingest,
                        target_rx,
                        cancel,
                        sync_control,
                    )
                    .await
                },
            );
        }

        {
            let db_path = self.db_path.clone();
            let cancel = root_cancel.child_token();
            spawn_worker(
                &mut workers,
                WorkerKind::KeyRepairLoop,
                "key-repair-loop",
                cancel.clone(),
                async move { run_periodic_key_repair(db_path, cancel).await },
            );
        }

        if env_flag("TOPO_DISABLE_PLACEHOLDER_AUTODIAL") {
            warn!("BOOTSTRAP AUTODIAL DISABLED by TOPO_DISABLE_PLACEHOLDER_AUTODIAL");
        }

        let db_path = self.db_path.clone();
        let ingress = target_tx.clone();
        let cancel = root_cancel.child_token();
        let discovery_disabled = env_flag("TOPO_DISABLE_DISCOVERY");
        if discovery_disabled {
            warn!("iroh address lookup disabled by TOPO_DISABLE_DISCOVERY");
        }
        let planner_options = TargetPlannerOptions {
            include_bootstrap_targets: !env_flag("TOPO_DISABLE_PLACEHOLDER_AUTODIAL"),
            allow_lookup_known_peers: !discovery_disabled,
            known_peer_target_degree: crate::shared::hash_graph::DEFAULT_HASH_GRAPH_DEGREE,
        };
        spawn_worker(
            &mut workers,
            WorkerKind::PlannerRefresher,
            "planner-refresher",
            cancel.clone(),
            async move { run_planner_refresher(db_path, ingress, cancel, planner_options).await },
        );

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
        self.endpoint.close_gracefully().await;
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
        | WorkerKind::KeyRepairLoop
        | WorkerKind::PlannerRefresher => WorkerFailurePolicy::FailRuntime,
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

async fn run_planner_refresher(
    db_path: String,
    ingress_tx: mpsc::UnboundedSender<TargetIngressEvent>,
    shutdown: CancellationToken,
    planner_options: TargetPlannerOptions,
) -> Result<(), String> {
    let mut warning_gate = RepeatedWarningGate::new(Duration::from_secs(300));
    loop {
        if shutdown.is_cancelled() {
            break;
        }

        match collect_desired_outbound_targets(&db_path, &planner_options) {
            Ok(targets) => {
                warning_gate.clear();
                for event in targets {
                    if ingress_tx.send(event).is_err() {
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                let message = format!("OUTBOUND TARGET PLANNER REFRESH failed: {}", e);
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
    fn worker_failure_policy_is_explicit_per_kind() {
        assert_eq!(
            worker_failure_policy(WorkerKind::AcceptLoop),
            WorkerFailurePolicy::FailRuntime
        );
        assert_eq!(
            worker_failure_policy(WorkerKind::KeyRepairLoop),
            WorkerFailurePolicy::FailRuntime
        );
        assert_eq!(
            worker_failure_policy(WorkerKind::PlannerRefresher),
            WorkerFailurePolicy::FailRuntime
        );
    }
}
