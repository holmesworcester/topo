//! Formal verification of range-session index and send-order policy selection.

use vstd::prelude::*;

verus! {

pub enum SyncWindowKind {
    Full,
    LastDay,
    LastWeek,
    LastTwelveWeeks,
}

pub enum SharedSendOrderPolicy {
    PreserveInput,
    NewestFirst,
}

pub open spec fn decide_shared_send_order_policy(
    kind: SyncWindowKind,
) -> SharedSendOrderPolicy {
    match kind {
        SyncWindowKind::LastDay => SharedSendOrderPolicy::NewestFirst,
        SyncWindowKind::Full | SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks => {
            SharedSendOrderPolicy::PreserveInput
        }
    }
}

proof fn send_order_policy_matches_window_kind()
    ensures
        decide_shared_send_order_policy(SyncWindowKind::LastDay)
            == SharedSendOrderPolicy::NewestFirst,
        decide_shared_send_order_policy(SyncWindowKind::Full)
            == SharedSendOrderPolicy::PreserveInput,
{
}

} // verus!
