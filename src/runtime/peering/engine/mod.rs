//! Peering runtime: daemon lifecycle and peer dispatch.
//!
//! Runtime worker ownership is centralized in `supervisor.rs`.

mod bootstrap_auth;
mod startup;
pub(crate) mod supervisor;
pub(crate) mod target_dispatch;
pub(crate) mod target_planner;

use std::net::SocketAddr;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::contracts::event_pipeline_contract::IngestFns;
use crate::runtime::sync_control::SyncControlRegistry;
use crate::transport::TransportEndpoint;

use startup::setup_endpoint_and_tenants;

/// Runtime networking information collected during node startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRuntimeNetInfo {
    /// Actual bound listen address (after OS port assignment).
    pub listen_addr: String,
    /// Hex-encoded daemon-scoped iroh endpoint id.
    pub daemon_peer_id: String,
    /// Current direct addresses published by the endpoint.
    #[serde(default)]
    pub published_addrs: Vec<String>,
    /// Whether daemon-scoped mDNS discovery is mounted on the endpoint.
    pub mdns_enabled: bool,
    /// Live endpoint handle for RPC surfaces such as `discover` and `status`.
    #[serde(skip_serializing, skip_deserializing, default)]
    pub endpoint: Option<TransportEndpoint>,
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
    ingest: IngestFns,
    sync_control: Option<Arc<SyncControlRegistry>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let startup::StartupResult { endpoint, tenants } =
        setup_endpoint_and_tenants(db_path, bind, net_info_tx).await?;

    let mut runtime_supervisor = supervisor::RuntimeSupervisor::new(
        db_path.to_string(),
        endpoint,
        tenants,
        ingest,
        sync_control,
    );

    runtime_supervisor
        .run_until_shutdown(shutdown_notify)
        .await?;
    info!("Shutting down");
    Ok(())
}
