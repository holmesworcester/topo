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
pub mod responder;

use std::time::Duration;

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
/// Larger frames pack more range fingerprints per round, reducing round count
/// at the cost of larger per-round messages. 256 KB is the sweet spot:
/// per-round cost scales super-linearly, so 512 KB gains ~10% on 500k but
/// regresses 50k by ~7%, and 1 MB is catastrophic (34s/round).
pub(super) const NEGENTROPY_FRAME_SIZE: u64 = 256 * 1024;

/// Max event IDs sent per HaveList message during reconciliation.
pub(super) const HAVE_CHUNK: usize = 1000;

/// Max event IDs sent per NeedList/HaveList request during reconciliation.
pub(super) const NEED_CHUNK: usize = 1000;

/// Max events to enqueue into the egress queue per main-loop iteration.
pub(super) const ENQUEUE_BATCH: usize = 5000;

/// Max events per egress claim (one send batch to the data stream).
pub(super) const EGRESS_CLAIM_COUNT: usize = 500;

/// Max age (ms) for sent egress entries before cleanup.
pub(super) const EGRESS_SENT_TTL_MS: i64 = 300_000;

/// Time to wait for inbound data stream drain at session end.
pub(super) const DATA_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Non-blocking poll timeout for the control stream receive.
pub(super) const CONTROL_POLL_TIMEOUT: Duration = Duration::from_millis(1);

// -- Coordinator timing (advisory, not on pull-dispatch hot path) --
// The coordinator thread still runs for health/metrics but does not gate
// HaveList dispatch.  Pull work division uses deterministic ownership
// (hash-based split in control_plane::is_event_owned).

/// How long the coordinator waits (after the first peer reports) for
/// remaining peers to finish reconciliation and report their need_ids.
pub(super) const COORDINATOR_COLLECTION_WINDOW: Duration = Duration::from_secs(2);

/// Coordinator busy-poll interval while waiting for the first peer report.
pub(super) const COORDINATOR_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Coordinator poll interval within the collection window.
pub(super) const COORDINATOR_COLLECTION_POLL: Duration = Duration::from_millis(2);

/// Timeout for waiting on coordinator assignment of fallback events.
/// After this duration, the session proceeds without the fallback subset.
pub(super) const FALLBACK_ASSIGNMENT_TIMEOUT: Duration = Duration::from_secs(5);
