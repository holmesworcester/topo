//! Sync session logic: initiator and responder sync loops.
//!
//! Extracted from sync/engine.rs (Phase 3 of Option B refactor).
//! Wire protocol behavior is unchanged -- this is a pure code-movement extraction.
//!
//! Shutdown protocol (preserved):
//! 1. Each side sends DataDone on the data stream after flushing all events.
//! 2. Initiator sends Done on control after its DataDone.
//! 3. Responder receives Done, finishes sending, sends DataDone on data,
//!    waits for initiator's DataDone to be consumed, then sends DoneAck.
//! 4. Initiator receives DoneAck, waits for responder's DataDone, exits.

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

/// Max event IDs sent per HaveList message during reconciliation.
pub(super) fn have_chunk() -> usize {
    if low_mem_mode() {
        8
    } else {
        1000
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

/// Max events to enqueue into the egress queue per main-loop iteration.
pub(super) fn enqueue_batch() -> usize {
    if low_mem_mode() {
        8
    } else {
        5000
    }
}

/// Max events per egress claim (one send batch to the data stream).
pub(super) fn egress_claim_count() -> usize {
    if let Ok(v) = std::env::var("P7_EGRESS_CLAIM_COUNT") {
        if let Ok(parsed) = v.parse::<usize>() {
            return parsed.max(1);
        }
    }
    if low_mem_mode() {
        8
    } else {
        32
    }
}

/// Max age (ms) for sent egress entries before cleanup.
pub(super) const EGRESS_SENT_TTL_MS: i64 = 300_000;
/// Lease duration for one egress claim batch.
pub(super) const EGRESS_LEASE_MS: i64 = 30_000;
/// Small quiet period before declaring a session's outbound egress drained.
pub(super) const EGRESS_QUIET_WINDOW: Duration = Duration::from_millis(500);

/// Time to wait for inbound data stream drain at session end.
pub(super) const DATA_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Time to wait for a single data-stream send/flush before treating it as stalled.
pub(super) const DATA_SEND_STALL_TIMEOUT: Duration = Duration::from_secs(10);
/// Maximum time a session may sit without any initial control-round progress.
/// If a session never gets past the first negentropy exchange, restarting it is
/// better than blocking the connection supervisor for the full activity timeout.
pub(super) const INITIAL_CONTROL_PROGRESS_TIMEOUT: Duration = Duration::from_secs(5);

/// Non-blocking poll timeout for the control stream receive.
pub(super) const CONTROL_POLL_TIMEOUT: Duration = Duration::from_millis(1);

pub(super) fn send_idle_capture_enabled() -> bool {
    std::env::var("SYNC_SEND_IDLE_LOG")
        .map(|v| v != "0" && v.to_lowercase() != "false")
        .unwrap_or(false)
}
