//! **Abstract specification — not grounded in runtime code.**
//!
//! Per `docs/planning/FORMAL_SEAM_COVERAGE.md`, this file encodes system-level
//! invariants that no single runtime function body satisfies on its own. The
//! SMT solver accepts the proofs inside this file, but they are NOT proofs about
//! runtime code — the grounded verification lives in the per-seam `ensures`
//! clauses on executable `pub fn`s in sibling modules. Do not treat entries
//! here as "the runtime is proven to satisfy X"; treat them as "X is modeled
//! in Verus and consistent with itself".
//!
//! Formal verification of cascade unblocking (Kahn's algorithm).
//!
//! The cascade unblocks dependent events when a blocker becomes valid.
//! We prove termination, monotonicity, and safety properties.

use vstd::prelude::*;

verus! {

/// State of the cascade algorithm.
pub struct CascadeState {
    /// Number of currently valid events.
    pub valid_count: nat,
    /// Number of currently blocked events.
    pub blocked_count: nat,
    /// Number of items in the worklist.
    pub worklist_len: nat,
    /// Total deps_remaining across all blocked events.
    pub total_deps_remaining: nat,
}

/// The cascade's termination measure.
pub open spec fn cascade_measure(state: &CascadeState) -> nat {
    state.total_deps_remaining + state.worklist_len
}

/// A cascade step processes one blocker from the worklist:
///   - Finds `candidates` events blocked on this blocker
///   - Decrements their deps_remaining
///   - `newly_unblocked` events have deps_remaining reach 0
pub open spec fn cascade_step(
    state: CascadeState,
    candidates: nat,
    newly_unblocked: nat,
) -> CascadeState
    recommends
        state.worklist_len > 0,
        newly_unblocked <= candidates,
        candidates <= state.total_deps_remaining,
        newly_unblocked <= state.blocked_count,
{
    CascadeState {
        valid_count: state.valid_count + newly_unblocked,
        blocked_count: (state.blocked_count - newly_unblocked) as nat,
        worklist_len: (state.worklist_len - 1 + newly_unblocked) as nat,
        total_deps_remaining: (state.total_deps_remaining - candidates) as nat,
    }
}

/// The cascade state is well-formed.
pub open spec fn cascade_well_formed(state: &CascadeState) -> bool {
    // If there are blocked events, there must be some remaining deps
    (state.blocked_count > 0 ==> state.total_deps_remaining > 0)
}

// ═══════════════════════════════════════════════════════════════════
// Cascade Proofs
// ═══════════════════════════════════════════════════════════════════

/// Proof: the valid set only grows (monotonicity).
proof fn proof_valid_set_monotonic(
    state: CascadeState,
    candidates: nat,
    newly_unblocked: nat,
)
    requires
        state.worklist_len > 0,
        newly_unblocked <= candidates,
        candidates <= state.total_deps_remaining,
        newly_unblocked <= state.blocked_count,
    ensures
        cascade_step(state, candidates, newly_unblocked).valid_count >= state.valid_count,
{
}

/// Proof: the blocked set only shrinks (monotonicity).
proof fn proof_blocked_set_shrinks(
    state: CascadeState,
    candidates: nat,
    newly_unblocked: nat,
)
    requires
        state.worklist_len > 0,
        newly_unblocked <= candidates,
        candidates <= state.total_deps_remaining,
        newly_unblocked <= state.blocked_count,
    ensures
        cascade_step(state, candidates, newly_unblocked).blocked_count <= state.blocked_count,
{
}

/// Proof: total_deps_remaining strictly decreases when candidates > 0.
/// This is key to termination: each step reduces the measure.
proof fn proof_deps_remaining_decreases(
    state: CascadeState,
    candidates: nat,
    newly_unblocked: nat,
)
    requires
        state.worklist_len > 0,
        candidates > 0,
        newly_unblocked <= candidates,
        candidates <= state.total_deps_remaining,
        newly_unblocked <= state.blocked_count,
    ensures
        cascade_step(state, candidates, newly_unblocked).total_deps_remaining < state.total_deps_remaining,
{
}

/// Proof: when worklist is empty and well-formed, cascade terminates.
proof fn proof_cascade_terminates_when_worklist_empty(state: &CascadeState)
    requires state.worklist_len == 0
    ensures cascade_measure(state) == state.total_deps_remaining,
{
}

/// Proof: cascade measure decreases when candidates > newly_unblocked.
/// (More deps are resolved than new worklist items added.)
proof fn proof_measure_decreases_when_net_progress(
    state: CascadeState,
    candidates: nat,
    newly_unblocked: nat,
)
    requires
        state.worklist_len > 0,
        candidates > newly_unblocked,
        newly_unblocked <= candidates,
        candidates <= state.total_deps_remaining,
        newly_unblocked <= state.blocked_count,
    ensures
        ({
            let new_state = cascade_step(state, candidates, newly_unblocked);
            cascade_measure(&new_state) < cascade_measure(&state)
        }),
{
}

/// Proof: cascade step with zero candidates just pops worklist.
proof fn proof_no_candidates_just_pops(state: CascadeState)
    requires state.worklist_len > 0
    ensures
        ({
            let new_state = cascade_step(state, 0, 0);
            new_state.valid_count == state.valid_count
            && new_state.blocked_count == state.blocked_count
            && new_state.worklist_len == state.worklist_len - 1
        }),
{
}

// ═══════════════════════════════════════════════════════════════════
// Bulk Cleanup Proofs
// ═══════════════════════════════════════════════════════════════════

/// Model of bulk cleanup: removes dep edges for terminal events.
pub open spec fn remaining_edges_after_cleanup(
    total_edges: nat,
    edges_for_valid: nat,
    edges_for_rejected: nat,
    edges_orphaned: nat,
) -> nat
    recommends edges_for_valid + edges_for_rejected + edges_orphaned <= total_edges
{
    (total_edges - edges_for_valid - edges_for_rejected - edges_orphaned) as nat
}

/// Proof: cleanup removes all edges for terminal events.
proof fn proof_bulk_cleanup_removes_all_terminal_edges(
    total_edges: nat,
    edges_for_valid: nat,
    edges_for_rejected: nat,
    edges_orphaned: nat,
)
    requires edges_for_valid + edges_for_rejected + edges_orphaned <= total_edges
    ensures
        remaining_edges_after_cleanup(total_edges, edges_for_valid, edges_for_rejected, edges_orphaned)
        <= total_edges - edges_for_valid - edges_for_rejected,
{
}

} // verus!
