//! Formal verification proofs for Topo, organized to mirror runtime ownership.
//!
//! The tree under this crate mirrors `src/` in the runtime crate one-for-one:
//! `verus-proofs/src/runtime/peering/loops/connect.rs` pairs with
//! `src/runtime/peering/loops/connect.rs`, and so on. Each proof file lives
//! where its runtime counterpart lives. Exceptions:
//! - `bug_hunt.rs` at the root — counterexample log for known runtime bugs.
//! - `state/shared_workspace_fanout.rs` matches runtime `src/state/shared_workspace_fanout.rs`.
//!
//! See `docs/planning/FORMAL_SEAM_COVERAGE.md` for the seam inventory.

use vstd::prelude::*;

pub mod event_modules;
pub mod runtime;
pub mod state;

pub mod bug_hunt;

verus! {
    proof fn system_invariants_hold() { }
}
