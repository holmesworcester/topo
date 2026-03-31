//! Formal verification proofs for the Topo event-sourced pipeline.
//!
//! 7 modules model the core pipeline logic, 5 modules model extended properties.
//! All proofs assume external dependencies (SQLite, crypto) behave correctly.

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

verus! {
    proof fn system_invariants_hold() { }
}
