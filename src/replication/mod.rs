pub mod session;

// Only re-export types needed by other crate modules via the replication:: path.
// run_coordinator and spawn_data_receiver are internal to the replication boundary
// and accessed directly as replication::session::* by callers that need them.
pub use session::PeerCoord;
