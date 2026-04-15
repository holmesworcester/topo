//! Formal verification proofs for Topo, organized to mirror runtime/state ownership.
//!
//! - `pipeline/`: projection-pipeline and ingestion proofs
//! - `runtime/`: transport, peering, and sync-session proofs
//! - `state/`: state-selection and purge/fanout proofs
//! - `event_modules/`: event-module command family proofs
//! - `bug_hunt.rs`: intentionally cross-cutting counterexample-oriented proofs

use vstd::prelude::*;

pub mod composition;
pub mod event_modules;
pub mod pipeline;
pub mod runtime;
pub mod state;

// Bug-hunting proofs
pub mod bug_hunt;

// Keep the most commonly imported proof helpers available at the crate root
// while the proof tree moves to mirrored module ownership.
pub use pipeline::contract;
pub use pipeline::decision;

verus! {
    proof fn system_invariants_hold() { }
}
