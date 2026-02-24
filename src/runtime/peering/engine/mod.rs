//! Peering runtime: daemon lifecycle, discovery, and peer dispatch.
//!
//! Runtime worker ownership is centralized in `supervisor.rs`.

mod discovery;
mod startup;
pub(crate) mod supervisor;
pub(crate) mod target_planner;

use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::peering::loops::IntroSpawnerFn;

use startup::setup_endpoint_and_tenants;

/// Runtime networking information collected during node startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRuntimeNetInfo {
    /// Actual bound listen address (after OS port assignment).
    pub listen_addr: String,
    /// UPnP port mapping attempt result (None until `topo upnp` is run).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upnp: Option<crate::peering::nat::upnp::UpnpMappingReport>,
}

/// Run the sync node.
///
/// Discovers local tenants, creates a shared endpoint + ingest path, then
/// delegates long-lived task ownership to `RuntimeSupervisor`.
pub async fn run_node(
    db_path: &str,
    bind: SocketAddr,
    net_info_tx: tokio::sync::oneshot::Sender<NodeRuntimeNetInfo>,
    shutdown_notify: Arc<tokio::sync::Notify>,
    intro_spawner: IntroSpawnerFn,
    ingest: IngestFns,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let startup::StartupResult {
        endpoint,
        local_addr,
        tenants,
        tenant_client_configs,
        local_peer_ids,
    } = setup_endpoint_and_tenants(db_path, bind, net_info_tx)?;

    let mut runtime_supervisor = supervisor::RuntimeSupervisor::new(
        db_path.to_string(),
        endpoint,
        local_addr,
        tenants,
        tenant_client_configs,
        local_peer_ids,
        intro_spawner,
        ingest,
    );

    let events_received = runtime_supervisor
        .run_until_shutdown(shutdown_notify)
        .await?;
    info!("Shutting down ({} events received)", events_received);
    Ok(())
}
