//! Formal verification of outbound sync-window scheduler decisions.

use vstd::prelude::*;

verus! {

pub enum ColdTierPlan {
    Default,
    LowMemOnly,
}

pub struct ColdTierRawRows {
    pub global_low_mem_mode: bool,
    pub restrict_to_low_mem_windows: bool,
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

pub struct SelectOutboundWindowRawRows {
    pub last_day_only_mode: bool,
    pub normalized_live_peer_count: nat,
    pub peer_is_priority_owner: bool,
}

pub struct SelectOutboundWindowDecisionContext {
    pub last_day_only_mode: bool,
    pub normalized_live_peer_count: nat,
    pub peer_is_priority_owner: bool,
}

pub open spec fn normalize_cold_tier_context(
    raw_rows: ColdTierRawRows,
) -> ColdTierDecisionContext {
    ColdTierDecisionContext {
        global_low_mem_mode: raw_rows.global_low_mem_mode,
        restrict_to_low_mem_windows: raw_rows.restrict_to_low_mem_windows,
    }
}

pub open spec fn decide_cold_tier_plan(context: &ColdTierDecisionContext) -> ColdTierPlan {
    if context.global_low_mem_mode || context.restrict_to_low_mem_windows {
        ColdTierPlan::LowMemOnly
    } else {
        ColdTierPlan::Default
    }
}

pub open spec fn normalize_select_outbound_window_context(
    raw_rows: SelectOutboundWindowRawRows,
) -> SelectOutboundWindowDecisionContext {
    SelectOutboundWindowDecisionContext {
        last_day_only_mode: raw_rows.last_day_only_mode,
        normalized_live_peer_count: raw_rows.normalized_live_peer_count,
        peer_is_priority_owner: raw_rows.peer_is_priority_owner,
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

proof fn cold_tier_normalizer_preserves_query_facts(
    global_low_mem_mode: bool,
    restrict_to_low_mem_windows: bool,
)
    ensures
        normalize_cold_tier_context(ColdTierRawRows {
            global_low_mem_mode,
            restrict_to_low_mem_windows,
        }) == (ColdTierDecisionContext {
            global_low_mem_mode,
            restrict_to_low_mem_windows,
        }),
{
}

proof fn select_outbound_window_normalizer_preserves_query_facts(
    last_day_only_mode: bool,
    normalized_live_peer_count: nat,
    peer_is_priority_owner: bool,
)
    ensures
        normalize_select_outbound_window_context(SelectOutboundWindowRawRows {
            last_day_only_mode,
            normalized_live_peer_count,
            peer_is_priority_owner,
        }) == (SelectOutboundWindowDecisionContext {
            last_day_only_mode,
            normalized_live_peer_count,
            peer_is_priority_owner,
        }),
{
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

proof fn last_day_only_mode_is_peer_state_noninterfering(
    normalized_live_peer_count: nat,
    peer_is_priority_owner: bool,
)
    ensures
        decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
            last_day_only_mode: true,
            normalized_live_peer_count,
            peer_is_priority_owner,
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

proof fn non_last_day_single_peer_counts_select_single_peer(normalized_live_peer_count: nat)
    requires normalized_live_peer_count <= 1
    ensures
        decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
            last_day_only_mode: false,
            normalized_live_peer_count,
            peer_is_priority_owner: true,
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
