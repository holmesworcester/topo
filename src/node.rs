//! Multi-tenant node daemon — composition root.
//!
//! Wires the sync/punch intro listener into the network runtime.
//! Callers use `run_node` which delegates to `network::runtime::run_node`
//! with the intro spawner injected.

use std::net::SocketAddr;

pub use crate::peering::runtime::NodeRuntimeNetInfo;

pub async fn run_node(
    db_path: &str,
    bind: SocketAddr,
    net_info_tx: Option<tokio::sync::oneshot::Sender<NodeRuntimeNetInfo>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::contracts::event_runtime_contract::IngestFns;
    crate::peering::runtime::run_node(
        db_path,
        bind,
        net_info_tx,
        crate::sync::punch::spawn_intro_listener,
        IngestFns {
            batch_writer: crate::event_pipeline::batch_writer,
            drain_queue: crate::event_pipeline::drain_project_queue,
        },
    )
    .await
}
