//! Formal verification of same-workspace fanout target selection.
//!
//! Every `pub fn` below is executable Rust consumed by `src/state/shared_workspace_fanout.rs`.
//! Postconditions (`ensures`) are SMT-checked against the function body by `cargo-verus verify`.
//!
//! Runtime carries `Vec<Sibling>`. This Verus core reduces the 4-branch dispatch to a
//! boolean summary (`has_any_eligible_sibling`). The runtime computes the summary from
//! its sibling vector, calls the verified core, and then rehydrates the concrete
//! `Vec<String>` of eligible peer ids on the `FanoutToTargets` branch.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFanoutRawRowsCore {
    pub origin_rejected: bool,
    pub origin_removed: bool,
    pub removal_event: bool,
    pub has_any_eligible_sibling: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFanoutDecisionContextCore {
    pub origin_rejected: bool,
    pub origin_removed: bool,
    pub removal_event: bool,
    pub has_any_eligible_sibling: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SharedFanoutPlanCore {
    SkipOriginRejected,
    SkipOriginRemoved,
    NoTargets,
    FanoutToTargets,
}

pub fn normalize_shared_fanout_core(
    raw_rows: SharedFanoutRawRowsCore,
) -> (context: SharedFanoutDecisionContextCore)
    ensures
        context.origin_rejected == raw_rows.origin_rejected,
        context.origin_removed == raw_rows.origin_removed,
        context.removal_event == raw_rows.removal_event,
        context.has_any_eligible_sibling == raw_rows.has_any_eligible_sibling,
{
    SharedFanoutDecisionContextCore {
        origin_rejected: raw_rows.origin_rejected,
        origin_removed: raw_rows.origin_removed,
        removal_event: raw_rows.removal_event,
        has_any_eligible_sibling: raw_rows.has_any_eligible_sibling,
    }
}

/// Eligibility predicate used by the runtime when computing `has_any_eligible_sibling`.
/// Verified here so the runtime's sibling-filter logic can delegate per-sibling.
pub fn sibling_is_eligible_for_fanout(
    sibling_removed: bool,
    event_predates_removal: bool,
    removal_targets_sibling: bool,
) -> (eligible: bool)
    ensures eligible == (!sibling_removed || event_predates_removal || removal_targets_sibling),
{
    !sibling_removed || event_predates_removal || removal_targets_sibling
}

pub fn decide_shared_fanout_plan_core(
    context: &SharedFanoutDecisionContextCore,
) -> (plan: SharedFanoutPlanCore)
    ensures
        context.origin_rejected ==> plan == SharedFanoutPlanCore::SkipOriginRejected,
        (!context.origin_rejected && context.origin_removed && !context.removal_event)
            ==> plan == SharedFanoutPlanCore::SkipOriginRemoved,
        (!context.origin_rejected
         && !(context.origin_removed && !context.removal_event)
         && context.has_any_eligible_sibling)
            ==> plan == SharedFanoutPlanCore::FanoutToTargets,
        (!context.origin_rejected
         && !(context.origin_removed && !context.removal_event)
         && !context.has_any_eligible_sibling)
            ==> plan == SharedFanoutPlanCore::NoTargets,
        // Inverse direction: FanoutToTargets implies both preconditions hold.
        plan == SharedFanoutPlanCore::FanoutToTargets
            ==> !context.origin_rejected
                && !(context.origin_removed && !context.removal_event)
                && context.has_any_eligible_sibling,
{
    if context.origin_rejected {
        SharedFanoutPlanCore::SkipOriginRejected
    } else if context.origin_removed && !context.removal_event {
        SharedFanoutPlanCore::SkipOriginRemoved
    } else if context.has_any_eligible_sibling {
        SharedFanoutPlanCore::FanoutToTargets
    } else {
        SharedFanoutPlanCore::NoTargets
    }
}

} // verus!
