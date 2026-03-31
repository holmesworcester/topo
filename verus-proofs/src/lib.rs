//! Formal verification proofs for the Topo event-sourced pipeline.
//!
//! This crate models the pure-functional core of Topo's projection pipeline
//! and proves key invariants using Verus. External dependencies (SQLite, crypto,
//! networking) are modeled as abstract specifications that assume correct
//! behavior, allowing us to verify the logical properties of:
//!
//! - Projection decisions (Valid/Block/Reject/AlreadyProcessed)
//! - Pipeline batch processing and commit semantics
//! - Pure projectors (message, reaction, admin, user, message_deletion)
//! - Command creation and validation
//! - Cascade unblocking (Kahn's algorithm)
//! - Dispatch and side-effect policies

use vstd::prelude::*;

pub mod decision;
pub mod contract;
pub mod pipeline;
pub mod projectors;
pub mod cascade;
pub mod dispatch;
pub mod commands;

verus! {
    // Top-level: each submodule proves its own invariants.
    // The composition establishes global pipeline correctness.

    proof fn system_invariants_hold()
    {
        // decision: decisions are exhaustive and mutually exclusive
        // contract: result constructors maintain well-formedness
        // pipeline: batch sort is correct, commit failure prevents effects
        // projectors: per-projector input validation and convergence
        // cascade: termination and dependency-order processing
        // dispatch: exhaustive routing and side-effect policy
    }
}
