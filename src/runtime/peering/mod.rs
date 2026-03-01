pub mod discovery;
pub mod engine;
pub mod loops;
pub mod nat;
pub mod workflows;

pub use engine as runtime;

// Public API re-exports for the peering boundary
pub use engine::{run_node, NodeRuntimeNetInfo};
pub use loops::{
    accept_loop, accept_loop_with_ingest, connect_loop, IntroSpawnerFn, SYNC_SESSION_TIMEOUT_SECS,
};
