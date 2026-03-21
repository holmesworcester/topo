//! Sync session logic: initiator and responder sync loops.
//!
//! Discovery remains round-scoped, but one transport session now stays alive
//! for the lifetime of the authenticated connection:
//! - initiator starts repeated negentropy rounds over the same control stream
//! - responder answers those rounds over the same control stream
//! - request credit, request issuance, and response sends stay connection-scoped
//! - there is no per-round data-plane drain handshake

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

fn read_u64_env(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.parse::<u64>().ok()
}

/// Gap between initiator-driven discovery rounds on an established connection.
///
/// Default 100 ms.  Rounds run serially — if a round takes longer than the gap,
/// the next one starts immediately after the previous completes.  At large scale
/// (1M+ events) a single round can take seconds (SQLite snapshot + multiple
/// RTTs), so the effective cadence self-limits under load without configuration.
/// With forward-on-have handling the low-latency path for freshly created events,
/// most rounds discover nothing and complete in single-digit ms.  The first round
/// always fires immediately on connection regardless of this gap.
pub(super) fn discovery_round_gap() -> Duration {
    Duration::from_millis(read_u64_env("TOPO_DISCOVERY_ROUND_GAP_MS").unwrap_or(100))
}

pub(super) fn forward_on_have_enabled() -> bool {
    crate::state::live_hints::forward_on_have_enabled()
}

/// Non-blocking poll timeout for the control stream receive.
pub(super) const CONTROL_POLL_TIMEOUT: Duration = Duration::from_millis(1);

pub(super) fn send_idle_capture_enabled() -> bool {
    std::env::var("SYNC_SEND_IDLE_LOG")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false)
}
