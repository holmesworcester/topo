//! Formal verification of outbound sync-window scheduler decisions.

use vstd::prelude::*;

verus! {

pub enum ColdTierPlan {
    Default,
    LowMemOnly,
}

pub struct ColdTierDecisionContext {
    pub global_low_mem_mode: bool,
    pub restrict_to_low_mem_windows: bool,
}

pub enum SelectOutboundWindowPlan {
    LastDayOnly,
    SinglePeer,
    MultiPeerPriorityOwner,
    MultiPeerCold,
}

pub struct SelectOutboundWindowDecisionContext {
    pub last_day_only_mode: bool,
    pub normalized_live_peer_count: nat,
    pub peer_is_priority_owner: bool,
}

pub open spec fn decide_cold_tier_plan(context: &ColdTierDecisionContext) -> ColdTierPlan {
    if context.global_low_mem_mode || context.restrict_to_low_mem_windows {
        ColdTierPlan::LowMemOnly
    } else {
        ColdTierPlan::Default
    }
}

pub open spec fn decide_select_outbound_window_plan(
    context: &SelectOutboundWindowDecisionContext,
) -> SelectOutboundWindowPlan {
    if context.last_day_only_mode {
        SelectOutboundWindowPlan::LastDayOnly
    } else if context.normalized_live_peer_count <= 1 {
        SelectOutboundWindowPlan::SinglePeer
    } else if context.peer_is_priority_owner {
        SelectOutboundWindowPlan::MultiPeerPriorityOwner
    } else {
        SelectOutboundWindowPlan::MultiPeerCold
    }
}

proof fn low_mem_or_peer_restriction_uses_low_mem_cold_tier()
    ensures
        decide_cold_tier_plan(&ColdTierDecisionContext {
            global_low_mem_mode: true,
            restrict_to_low_mem_windows: false,
        }) == ColdTierPlan::LowMemOnly,
        decide_cold_tier_plan(&ColdTierDecisionContext {
            global_low_mem_mode: false,
            restrict_to_low_mem_windows: true,
        }) == ColdTierPlan::LowMemOnly,
        decide_cold_tier_plan(&ColdTierDecisionContext {
            global_low_mem_mode: false,
            restrict_to_low_mem_windows: false,
        }) == ColdTierPlan::Default,
{
}

proof fn last_day_only_mode_overrides_peer_count_and_owner()
    ensures
        decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
            last_day_only_mode: true,
            normalized_live_peer_count: 3,
            peer_is_priority_owner: false,
        }) == SelectOutboundWindowPlan::LastDayOnly,
        decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
            last_day_only_mode: true,
            normalized_live_peer_count: 1,
            peer_is_priority_owner: true,
        }) == SelectOutboundWindowPlan::LastDayOnly,
{
}

proof fn single_peer_selects_single_peer_plan()
    ensures
        decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
            last_day_only_mode: false,
            normalized_live_peer_count: 1,
            peer_is_priority_owner: false,
        }) == SelectOutboundWindowPlan::SinglePeer,
{
}

proof fn multi_peer_owner_gets_priority_window()
    ensures
        decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
            last_day_only_mode: false,
            normalized_live_peer_count: 3,
            peer_is_priority_owner: true,
        }) == SelectOutboundWindowPlan::MultiPeerPriorityOwner,
{
}

proof fn multi_peer_non_owner_gets_cold_window()
    ensures
        decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
            last_day_only_mode: false,
            normalized_live_peer_count: 3,
            peer_is_priority_owner: false,
        }) == SelectOutboundWindowPlan::MultiPeerCold,
{
}

} // verus!
