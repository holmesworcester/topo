//! Sync session logic: initiator and responder range sessions.

pub mod connection_scope;
pub mod control_plane;
pub mod coordinator;
pub mod data_plane;
pub mod initiator;
pub mod logging;
pub mod range_session;
pub mod receive_log;
pub mod responder;
pub mod windowing;

use std::time::Duration;

use crate::tuning::low_mem_mode;

// ---------------------------------------------------------------------------
// Re-exports — preserve the existing public API surface
// ---------------------------------------------------------------------------
pub use connection_scope::{
    ConnectionRequestState, ConnectionResponseState, RequestWindowSnapshot, RequestWindowStats,
    ResponseQueueStats,
};
pub use coordinator::{CoordinationManager, PeerCoord};
pub use data_plane::spawn_data_receiver;
pub use initiator::run_sync_initiator;
pub use responder::run_sync_responder;

// ---------------------------------------------------------------------------
// Session tuning constants (shared across sub-modules)
// ---------------------------------------------------------------------------

/// Negentropy frame size limit.
/// Low-memory mode uses a smaller frame to reduce peak control-buffer pressure.
pub(super) fn negentropy_frame_size() -> u64 {
    if low_mem_mode() {
        16 * 1024
    } else {
        256 * 1024
    }
}

/// Max discovery hints or request IDs sent in one control-frame batch.
pub(super) fn need_chunk() -> usize {
    if low_mem_mode() {
        8
    } else {
        1000
    }
}
/// Time to wait for a single data-stream send/flush before treating it as stalled.
pub(super) const DATA_SEND_STALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum time a session may sit without any initial control-round progress.
/// If a session never gets past the first negentropy exchange, restarting it is
/// better than blocking the connection supervisor for the full activity timeout.
pub(super) const INITIAL_CONTROL_PROGRESS_TIMEOUT: Duration = Duration::from_secs(5);
