// TRANSITIONAL: sync/engine.rs is now a re-export shim.
// All orchestration code has moved to crate::network::loops (Phase 4).
// All session code has moved to crate::replication::session (Phase 3).
// This module exists only so existing callers (tests, testutil, session_handler)
// continue to compile without source changes. Remove in Phase 5.

// Network orchestration re-exports
pub use crate::network::loops::{
    accept_loop, accept_loop_with_ingest, connect_loop, download_from_sources,
    SYNC_SESSION_TIMEOUT_SECS,
};

// Replication session re-exports
pub use crate::replication::session::{
    run_sync_initiator_dual, run_sync_responder_dual, PeerCoord,
};

// Event runtime re-exports (used by tests/scenario_test.rs)
pub use crate::event_runtime::{batch_writer, IngestItem};
