//! Sync session logic: initiator and responder range sessions.

pub mod admission;
pub mod data_plane;
pub mod depsync;
pub mod initiator;
pub mod live_suppression;
pub mod logging;
pub mod range_session;
pub mod receive;
pub mod receive_task;
pub mod responder;
pub mod windowing;

pub use initiator::run_sync_initiator;
pub use responder::run_sync_responder;

// ---------------------------------------------------------------------------
// Session tuning constants (shared across sub-modules)
// ---------------------------------------------------------------------------

/// Negentropy frame size limit for all range sessions.
///
/// Set to 0 (unlimited) because we run over QUIC streams which handle flow
/// control natively.  A non-zero limit forces the protocol into many small
/// round-trips (one per 256 KB of reconciliation data), causing multi-session
/// churn at scale.  With 0, the full reconciliation completes in 3-5 rounds
/// regardless of set size.
pub(super) const NEGENTROPY_FRAME_SIZE_LIMIT: u64 = 0;
/// Maximum time a session may sit without any initial control-round progress.
/// Invite bootstrap and first-range planning now stage 8k-slot `key_rotation`
/// and `key_history` payloads, so the first control reply can take far longer
/// than the pre-change small-event baseline. Keep this comfortably above the
/// largest expected first-session planning + transfer spike while still below
/// the general activity timeout for genuinely dead sessions.
pub(super) const INITIAL_CONTROL_PROGRESS_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(120);
