//! Formal verification of same-workspace fanout target selection.

use vstd::prelude::*;

verus! {

pub struct SharedFanoutRawRows {
    pub origin_rejected: bool,
    pub origin_removed: bool,
    pub removal_event: bool,
    pub has_any_eligible_sibling: bool,
}

pub struct SharedFanoutDecisionContext {
    pub origin_rejected: bool,
    pub origin_removed: bool,
    pub removal_event: bool,
    pub has_any_eligible_sibling: bool,
}

pub enum SharedFanoutPlan {
    SkipOriginRejected,
    SkipOriginRemoved,
    NoTargets,
    FanoutToTargets,
}

pub open spec fn normalize_shared_fanout(
    raw_rows: SharedFanoutRawRows,
) -> SharedFanoutDecisionContext {
    SharedFanoutDecisionContext {
        origin_rejected: raw_rows.origin_rejected,
        origin_removed: raw_rows.origin_removed,
        removal_event: raw_rows.removal_event,
        has_any_eligible_sibling: raw_rows.has_any_eligible_sibling,
    }
}

pub open spec fn sibling_is_eligible_for_fanout(
    sibling_removed: bool,
    event_predates_removal: bool,
    removal_targets_sibling: bool,
) -> bool {
    !sibling_removed || event_predates_removal || removal_targets_sibling
}

pub open spec fn decide_shared_fanout_plan(
    context: &SharedFanoutDecisionContext,
) -> SharedFanoutPlan {
    if context.origin_rejected {
        SharedFanoutPlan::SkipOriginRejected
    } else if context.origin_removed && !context.removal_event {
        SharedFanoutPlan::SkipOriginRemoved
    } else if context.has_any_eligible_sibling {
        SharedFanoutPlan::FanoutToTargets
    } else {
        SharedFanoutPlan::NoTargets
    }
}

proof fn shared_fanout_normalizer_preserves_query_facts(
    origin_rejected: bool,
    origin_removed: bool,
    removal_event: bool,
    has_any_eligible_sibling: bool,
)
    ensures
        normalize_shared_fanout(SharedFanoutRawRows {
            origin_rejected,
            origin_removed,
            removal_event,
            has_any_eligible_sibling,
        }) == (SharedFanoutDecisionContext {
            origin_rejected,
            origin_removed,
            removal_event,
            has_any_eligible_sibling,
        }),
{
}

proof fn removed_origin_cannot_fanout_non_removal_events()
    ensures
        decide_shared_fanout_plan(&SharedFanoutDecisionContext {
            origin_rejected: false,
            origin_removed: true,
            removal_event: false,
            has_any_eligible_sibling: true,
        }) == SharedFanoutPlan::SkipOriginRemoved,
{
}

proof fn targeted_removal_can_reach_removed_sibling()
    ensures
        sibling_is_eligible_for_fanout(true, false, true),
        decide_shared_fanout_plan(&SharedFanoutDecisionContext {
            origin_rejected: false,
            origin_removed: false,
            removal_event: true,
            has_any_eligible_sibling: true,
        }) == SharedFanoutPlan::FanoutToTargets,
{
}

proof fn origin_rejection_blocks_all_fanout()
    ensures
        decide_shared_fanout_plan(&SharedFanoutDecisionContext {
            origin_rejected: true,
            origin_removed: false,
            removal_event: true,
            has_any_eligible_sibling: true,
        }) == SharedFanoutPlan::SkipOriginRejected,
{
}

proof fn no_eligible_sibling_produces_no_targets()
    ensures
        decide_shared_fanout_plan(&SharedFanoutDecisionContext {
            origin_rejected: false,
            origin_removed: false,
            removal_event: false,
            has_any_eligible_sibling: false,
        }) == SharedFanoutPlan::NoTargets,
{
}

proof fn fanout_to_targets_requires_unblocked_origin_and_eligible_sibling(
    context: SharedFanoutDecisionContext,
)
    ensures
        decide_shared_fanout_plan(&context) == SharedFanoutPlan::FanoutToTargets
            ==> !context.origin_rejected
                && !(context.origin_removed && !context.removal_event)
                && context.has_any_eligible_sibling,
{
}

} // verus!
