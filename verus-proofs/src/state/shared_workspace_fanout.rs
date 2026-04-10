//! Formal verification of same-workspace fanout target selection.

use vstd::prelude::*;

verus! {

pub enum SharedFanoutPlan {
    SkipOriginRejected,
    SkipOriginRemoved,
    NoTargets,
    FanoutToTargets,
}

pub open spec fn sibling_is_eligible_for_fanout(
    sibling_removed: bool,
    event_predates_removal: bool,
    removal_targets_sibling: bool,
) -> bool {
    !sibling_removed || event_predates_removal || removal_targets_sibling
}

pub open spec fn decide_shared_fanout_plan(
    origin_rejected: bool,
    origin_removed: bool,
    removal_event: bool,
    has_any_eligible_sibling: bool,
) -> SharedFanoutPlan {
    if origin_rejected {
        SharedFanoutPlan::SkipOriginRejected
    } else if origin_removed && !removal_event {
        SharedFanoutPlan::SkipOriginRemoved
    } else if has_any_eligible_sibling {
        SharedFanoutPlan::FanoutToTargets
    } else {
        SharedFanoutPlan::NoTargets
    }
}

proof fn removed_origin_cannot_fanout_non_removal_events()
    ensures
        decide_shared_fanout_plan(false, true, false, true)
            == SharedFanoutPlan::SkipOriginRemoved,
{
}

proof fn targeted_removal_can_reach_removed_sibling()
    ensures
        sibling_is_eligible_for_fanout(true, false, true),
        decide_shared_fanout_plan(false, false, true, true)
            == SharedFanoutPlan::FanoutToTargets,
{
}

proof fn origin_rejection_blocks_all_fanout()
    ensures
        decide_shared_fanout_plan(true, false, true, true)
            == SharedFanoutPlan::SkipOriginRejected,
{
}

} // verus!
