//! Formal verification of outbound sync-window scheduler decisions.
//!
//! Every `pub fn` below is executable Rust consumed by
//! `src/runtime/sync_engine/session/windowing.rs`. Postconditions (`ensures`) are SMT-checked
//! against the function body by `cargo-verus verify`.

use vstd::prelude::*;

verus! {

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdTierPlan {
    Default,
    LowMemOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColdTierRawRows {
    pub global_low_mem_mode: bool,
    pub restrict_to_low_mem_windows: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ColdTierDecisionContext {
    pub global_low_mem_mode: bool,
    pub restrict_to_low_mem_windows: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectOutboundWindowPlan {
    LastDayOnly,
    PerPeerCadence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectOutboundWindowRawRows {
    pub last_day_only_mode: bool,
    pub normalized_live_peer_count: u32,
    pub peer_is_priority_owner: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectOutboundWindowDecisionContext {
    pub last_day_only_mode: bool,
    pub normalized_live_peer_count: u32,
    pub peer_is_priority_owner: bool,
}

pub fn normalize_cold_tier_context(
    raw_rows: ColdTierRawRows,
) -> (context: ColdTierDecisionContext)
    ensures
        context.global_low_mem_mode == raw_rows.global_low_mem_mode,
        context.restrict_to_low_mem_windows == raw_rows.restrict_to_low_mem_windows,
{
    ColdTierDecisionContext {
        global_low_mem_mode: raw_rows.global_low_mem_mode,
        restrict_to_low_mem_windows: raw_rows.restrict_to_low_mem_windows,
    }
}

pub fn decide_cold_tier_plan(context: &ColdTierDecisionContext) -> (plan: ColdTierPlan)
    ensures
        (context.global_low_mem_mode || context.restrict_to_low_mem_windows)
            ==> plan == ColdTierPlan::LowMemOnly,
        (!context.global_low_mem_mode && !context.restrict_to_low_mem_windows)
            ==> plan == ColdTierPlan::Default,
{
    if context.global_low_mem_mode || context.restrict_to_low_mem_windows {
        ColdTierPlan::LowMemOnly
    } else {
        ColdTierPlan::Default
    }
}

pub fn normalize_select_outbound_window_context(
    raw_rows: SelectOutboundWindowRawRows,
) -> (context: SelectOutboundWindowDecisionContext)
    ensures
        context.last_day_only_mode == raw_rows.last_day_only_mode,
        context.normalized_live_peer_count == raw_rows.normalized_live_peer_count,
        context.peer_is_priority_owner == raw_rows.peer_is_priority_owner,
{
    SelectOutboundWindowDecisionContext {
        last_day_only_mode: raw_rows.last_day_only_mode,
        normalized_live_peer_count: raw_rows.normalized_live_peer_count,
        peer_is_priority_owner: raw_rows.peer_is_priority_owner,
    }
}

pub fn decide_select_outbound_window_plan(
    context: &SelectOutboundWindowDecisionContext,
) -> (plan: SelectOutboundWindowPlan)
    ensures
        context.last_day_only_mode ==> plan == SelectOutboundWindowPlan::LastDayOnly,
        !context.last_day_only_mode ==> plan == SelectOutboundWindowPlan::PerPeerCadence,
{
    if context.last_day_only_mode {
        SelectOutboundWindowPlan::LastDayOnly
    } else {
        SelectOutboundWindowPlan::PerPeerCadence
    }
}

} // verus!
