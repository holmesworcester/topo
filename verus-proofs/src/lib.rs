//! Formal verification proofs for the Topo event-sourced pipeline.
//!
//! Core: projection decisions, pipeline, projectors, cascade, dispatch, commands
//! Extended: context loading, project_one algorithm, tenant isolation, files, idempotency
//! Security: session auth, transport trust, sync protocol, connections, data ingestion

use vstd::prelude::*;

// Core pipeline proofs
pub mod decision;
pub mod contract;
pub mod pipeline;
pub mod projectors;
pub mod cascade;
pub mod dispatch;
pub mod commands;

// Extended proofs
pub mod context_loading;
pub mod project_one;
pub mod tenant_isolation;
pub mod file_projectors;
pub mod idempotency;
pub mod persist_phase;

// Security proofs
pub mod session_auth;
pub mod transport_trust;
pub mod bootstrap_dialer;
pub mod bootstrap_auth;
pub mod sync_admission;
pub mod sync_protocol;
pub mod connection_security;
pub mod data_ingestion;
pub mod sync_security;
pub mod connection_lifecycle;
pub mod target_dispatch;
pub mod inbound_session_auth;
pub mod range_session;
pub mod shared_workspace_fanout;
pub mod projection_stages;
pub mod deletion_purge;

// Bug-hunting proofs
pub mod bug_hunt;

verus! {
    proof fn system_invariants_hold() { }
}
