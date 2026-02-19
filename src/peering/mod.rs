pub mod discovery;
pub mod loops;
pub mod nat;
pub mod runtime;

// Public API re-exports for the network boundary
pub use loops::{
    accept_loop, accept_loop_with_ingest, connect_loop, download_from_sources,
    IntroSpawnerFn, SYNC_SESSION_TIMEOUT_SECS,
};
pub use runtime::{run_node, NodeRuntimeNetInfo};
