//! Range-session shared-send eligibility planner — verified core.
//!
//! Each `pub fn` below is executable Rust consumed by
//! `src/runtime/sync_engine/session/range_session.rs`. Postconditions (`ensures`) are
//! SMT-checked against the function body by `cargo-verus verify`.

use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------------
// Shared-send eligibility planner — verified exec fn.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedSendEligibilityRawRows {
    pub requested_by_reconciliation: bool,
    pub present_in_workspace_index: bool,
    pub shared_blob_available: bool,
    pub transport_shareable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedSendEligibilityDecisionContext {
    pub requested_by_reconciliation: bool,
    pub present_in_workspace_index: bool,
    pub shared_blob_available: bool,
    pub transport_shareable: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedSendEligibilityPlan {
    SendRoot,
    SkipRoot,
}

pub fn normalize_shared_send_eligibility_context(
    raw_rows: SharedSendEligibilityRawRows,
) -> (context: SharedSendEligibilityDecisionContext)
    ensures
        context.requested_by_reconciliation == raw_rows.requested_by_reconciliation,
        context.present_in_workspace_index == raw_rows.present_in_workspace_index,
        context.shared_blob_available == raw_rows.shared_blob_available,
        context.transport_shareable == raw_rows.transport_shareable,
{
    SharedSendEligibilityDecisionContext {
        requested_by_reconciliation: raw_rows.requested_by_reconciliation,
        present_in_workspace_index: raw_rows.present_in_workspace_index,
        shared_blob_available: raw_rows.shared_blob_available,
        transport_shareable: raw_rows.transport_shareable,
    }
}

pub fn decide_shared_send_eligibility_plan(
    context: &SharedSendEligibilityDecisionContext,
) -> (plan: SharedSendEligibilityPlan)
    ensures
        (context.requested_by_reconciliation
            && context.present_in_workspace_index
            && context.shared_blob_available
            && context.transport_shareable)
            ==> plan == SharedSendEligibilityPlan::SendRoot,
        (!context.requested_by_reconciliation
            || !context.present_in_workspace_index
            || !context.shared_blob_available
            || !context.transport_shareable)
            ==> plan == SharedSendEligibilityPlan::SkipRoot,
{
    if context.requested_by_reconciliation
        && context.present_in_workspace_index
        && context.shared_blob_available
        && context.transport_shareable
    {
        SharedSendEligibilityPlan::SendRoot
    } else {
        SharedSendEligibilityPlan::SkipRoot
    }
}

} // verus!
