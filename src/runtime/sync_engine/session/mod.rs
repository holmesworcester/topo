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

/// Max event IDs sent per NeedList/HaveList request during reconciliation.
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

/// Non-blocking poll timeout for the control stream receive.
pub(super) const CONTROL_POLL_TIMEOUT: Duration = Duration::from_millis(1);

fn read_u64_env(name: &str) -> Option<u64> {
    std::env::var(name).ok()?.parse::<u64>().ok()
}

/// Gap between initiator-driven discovery rounds on an established connection.
pub(super) fn discovery_round_gap() -> Duration {
    Duration::from_millis(read_u64_env("P7_DISCOVERY_ROUND_GAP_MS").unwrap_or(100))
}

pub(super) fn forward_on_have_enabled() -> bool {
    crate::state::live_hints::forward_on_have_enabled()
}

pub(super) fn send_idle_capture_enabled() -> bool {
    std::env::var("SYNC_SEND_IDLE_LOG")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false)
}
