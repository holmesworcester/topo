pub mod loops;
pub mod runtime;

// Public API re-exports for the network boundary
pub use loops::{
    accept_loop, accept_loop_with_ingest, connect_loop, download_from_sources,
    SYNC_SESSION_TIMEOUT_SECS,
};
pub use runtime::{run_node, NodeRuntimeNetInfo};
