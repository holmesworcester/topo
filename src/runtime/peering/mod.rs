//! Peering runtime — the connection-orchestration layer above the transport. [`engine`]
//! runs the per-node state machine (spawned via `run_node`); [`loops`] hosts the accept
//! and connect loops that drive it. Transport-layer concerns (QUIC, mTLS, NAT traversal)
//! stay inside `runtime::transport`.

pub mod engine;
pub mod loops;

pub use engine as runtime;

// Public API re-exports for the peering boundary
pub use engine::{run_node, NodeRuntimeNetInfo};
pub use loops::{accept_loop, connect_loop, ConnectLoopConfig, SYNC_SESSION_TIMEOUT_SECS};
