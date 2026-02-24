//! Multi-tenant node daemon — composition root.
//!
//! Wires the sync/punch intro listener into the peering runtime.
//! Callers use `run_node` which delegates to `peering::runtime::run_node`
//! with the intro spawner injected.

use std::net::SocketAddr;
use std::sync::Arc;

pub use crate::peering::runtime::NodeRuntimeNetInfo;

pub async fn run_node(
    db_path: &str,
    bind: SocketAddr,
    net_info_tx: tokio::sync::oneshot::Sender<NodeRuntimeNetInfo>,
    shutdown_notify: Arc<tokio::sync::Notify>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::contracts::event_pipeline_contract::IngestFns;
    crate::peering::runtime::run_node(
        db_path,
        bind,
        net_info_tx,
        shutdown_notify,
        crate::peering::workflows::punch::spawn_intro_listener,
        IngestFns {
            batch_writer: crate::event_pipeline::batch_writer,
            drain_queue: crate::event_pipeline::drain_project_queue,
        },
    )
    .await
}
