//! Sync session logic: initiator and responder range sessions.

pub mod dependency_session;
pub mod initiator;
pub mod logging;
pub mod range_session;
pub mod receive_log;
pub mod responder;
pub mod windowing;

use crate::tuning::low_mem_mode;

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
/// Maximum time a session may sit without any initial control-round progress.
/// If a session never gets past the first negentropy exchange, restarting it is
/// better than blocking the connection supervisor for the full activity timeout.
pub(super) const INITIAL_CONTROL_PROGRESS_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);
