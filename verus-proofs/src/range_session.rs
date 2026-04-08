//! Formal verification of range-session index and send-order policy selection.

use vstd::prelude::*;

verus! {

pub enum SyncWindowKind {
    Full,
    LastDay,
    LastWeek,
    LastTwelveWeeks,
    AuthGraph,
    KeyGraph,
}

pub enum SharedIndexLoadPlan {
    PriorityLaneAuth,
    PriorityLaneKey,
    TimeWindow,
}

pub enum SharedSendOrderPolicy {
    PreserveInput,
    OldestFirst,
    NewestFirst,
}

pub open spec fn decide_shared_index_load_plan(kind: SyncWindowKind) -> SharedIndexLoadPlan {
    match kind {
        SyncWindowKind::AuthGraph => SharedIndexLoadPlan::PriorityLaneAuth,
        SyncWindowKind::KeyGraph => SharedIndexLoadPlan::PriorityLaneKey,
        SyncWindowKind::Full
        | SyncWindowKind::LastDay
        | SyncWindowKind::LastWeek
        | SyncWindowKind::LastTwelveWeeks => SharedIndexLoadPlan::TimeWindow,
    }
}

pub open spec fn decide_shared_send_order_policy(
    kind: SyncWindowKind,
) -> SharedSendOrderPolicy {
    match kind {
        SyncWindowKind::AuthGraph => SharedSendOrderPolicy::OldestFirst,
        SyncWindowKind::KeyGraph | SyncWindowKind::LastDay => {
            SharedSendOrderPolicy::NewestFirst
        }
        SyncWindowKind::Full | SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks => {
            SharedSendOrderPolicy::PreserveInput
        }
    }
}

proof fn auth_and_key_graphs_use_priority_lanes()
    ensures
        decide_shared_index_load_plan(SyncWindowKind::AuthGraph)
            == SharedIndexLoadPlan::PriorityLaneAuth,
        decide_shared_index_load_plan(SyncWindowKind::KeyGraph)
            == SharedIndexLoadPlan::PriorityLaneKey,
{
}

proof fn cold_windows_use_time_window_index()
    ensures
        decide_shared_index_load_plan(SyncWindowKind::Full) == SharedIndexLoadPlan::TimeWindow,
        decide_shared_index_load_plan(SyncWindowKind::LastDay)
            == SharedIndexLoadPlan::TimeWindow,
{
}

proof fn send_order_policy_matches_window_kind()
    ensures
        decide_shared_send_order_policy(SyncWindowKind::AuthGraph)
            == SharedSendOrderPolicy::OldestFirst,
        decide_shared_send_order_policy(SyncWindowKind::KeyGraph)
            == SharedSendOrderPolicy::NewestFirst,
        decide_shared_send_order_policy(SyncWindowKind::LastDay)
            == SharedSendOrderPolicy::NewestFirst,
        decide_shared_send_order_policy(SyncWindowKind::Full)
            == SharedSendOrderPolicy::PreserveInput,
{
}

} // verus!
