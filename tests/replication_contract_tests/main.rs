//! Replication contract tests: verify protocol correctness via FakeSessionIo
//! without any QUIC transport or real network.
//!
//! Workstream E of the Option B Phase 6 hardening plan.

mod fake_session_io;
mod initiator_protocol_ordering;
mod responder_protocol_ordering;
mod cancellation_semantics;
mod error_mapping;
