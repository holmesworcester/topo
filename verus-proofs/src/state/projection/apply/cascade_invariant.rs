//! Cascade dep-counter consistency — verified invariant.
//!
//! Projection blocks an event on a set of missing dependency event-ids. Runtime stores
//! this in two places: `blocked_event_deps` (one row per (blocked_event, missing_dep))
//! and `blocked_events.deps_remaining` (a single integer). The invariant is simple:
//! `deps_remaining` must equal the number of rows in `blocked_event_deps` for the same
//! (peer_id, event_id) key at every transition.
//!
//! Bug-hunt finding #3 (since fixed) described a desync scenario where the counter
//! drifted from the edge count. The fix used `DELETE + INSERT OR REPLACE` instead of
//! `INSERT OR IGNORE`. The verified predicate here, combined with a runtime assertion
//! immediately after `record_block_rows`, locks the fix in: a future edit that
//! reintroduces drift fires the assertion.

use vstd::prelude::*;

verus! {

/// True iff `deps_remaining` equals the number of `blocked_event_deps` rows for the
/// same block (for a given (peer_id, event_id) pair).
pub fn cascade_counter_consistent(deps_remaining: u32, dep_edge_count: u32) -> (ok: bool)
    ensures ok == (deps_remaining == dep_edge_count),
{
    deps_remaining == dep_edge_count
}

/// True iff unblocking a dependency *decreases* `deps_remaining` by exactly one
/// whenever the corresponding edge row existed, and leaves it unchanged otherwise.
/// This captures the `UPDATE blocked_events SET deps_remaining = deps_remaining - 1
/// WHERE ... AND deps_remaining > 0` guard in `cascade_unblocked_inner`.
pub fn cascade_decrement_step_valid(
    prior_remaining: u32,
    edge_was_present: bool,
    new_remaining: u32,
) -> (ok: bool)
    ensures
        ok == (if edge_was_present && prior_remaining > 0 {
            new_remaining == prior_remaining - 1
        } else {
            new_remaining == prior_remaining
        }),
{
    if edge_was_present && prior_remaining > 0 {
        new_remaining == prior_remaining - 1
    } else {
        new_remaining == prior_remaining
    }
}

} // verus!
