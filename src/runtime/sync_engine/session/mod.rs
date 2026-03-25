//! Sync session logic: initiator and responder range sessions.

pub mod dependency_session;
pub mod initiator;
pub mod logging;
pub mod range_session;
pub mod receive_log;
pub mod responder;
pub mod windowing;

use crate::sync::session::windowing::SyncWindow;

pub use initiator::run_sync_initiator;
pub use responder::run_sync_responder;

// ---------------------------------------------------------------------------
// Session tuning constants (shared across sub-modules)
// ---------------------------------------------------------------------------

/// Negentropy frame size limit.
/// All windows now use the same in-memory storage path, so there is no longer
/// a low-memory cold-range special case here.
pub(super) fn negentropy_frame_size(_window: SyncWindow) -> u64 {
    256 * 1024
}
/// Maximum time a session may sit without any initial control-round progress.
/// If a session never gets past the first negentropy exchange, restarting it is
/// better than blocking the connection supervisor for the full activity timeout.
pub(super) const INITIAL_CONTROL_PROGRESS_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::session::windowing::SyncWindowKind;

    fn window(kind: SyncWindowKind) -> SyncWindow {
        SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(1),
            ts_max_exclusive_ms: Some(2),
        }
    }

    #[test]
    fn frame_size_is_uniform_across_windows() {
        std::env::set_var("LOW_MEM_IOS", "1");
        assert_eq!(
            negentropy_frame_size(window(SyncWindowKind::LastDay)),
            256 * 1024
        );
        assert_eq!(
            negentropy_frame_size(window(SyncWindowKind::LastWeek)),
            256 * 1024
        );
        assert_eq!(
            negentropy_frame_size(window(SyncWindowKind::LastTwelveWeeks)),
            256 * 1024
        );
        assert_eq!(
            negentropy_frame_size(window(SyncWindowKind::Full)),
            256 * 1024
        );
        std::env::remove_var("LOW_MEM_IOS");
    }
}
