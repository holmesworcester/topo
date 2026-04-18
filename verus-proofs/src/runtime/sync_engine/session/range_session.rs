//! Range-session index and send-order policy selection — verified core.
//!
//! Each `pub fn` below is executable Rust consumed by
//! `src/runtime/sync_engine/session/range_session.rs`. Postconditions (`ensures`) are
//! SMT-checked against the function body by `cargo-verus verify`.
//!
//! The runtime defines its own `SyncWindowKind` enum (in `session::windowing`) that this
//! crate cannot import without a dependency cycle. The verified order-policy planner here
//! takes a boolean `is_last_day` flag instead; the runtime wraps it with a `matches!()`
//! adapter.

use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------------
// Shared send-order policy — verified exec fn over a boolean flag.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedSendOrderPolicy {
    PreserveInput,
    NewestFirst,
}

pub fn decide_shared_send_order_policy(
    is_last_day: bool,
) -> (policy: SharedSendOrderPolicy)
    ensures
        is_last_day ==> policy == SharedSendOrderPolicy::NewestFirst,
        !is_last_day ==> policy == SharedSendOrderPolicy::PreserveInput,
{
    if is_last_day {
        SharedSendOrderPolicy::NewestFirst
    } else {
        SharedSendOrderPolicy::PreserveInput
    }
}

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

// ---------------------------------------------------------------------------
// Selected dep-order planner — verified exec fn.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedDepOrderRawRows {
    pub dep_is_selected: bool,
    pub dep_already_emitted: bool,
    pub dep_currently_visiting: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedDepOrderDecisionContext {
    pub dep_is_selected: bool,
    pub dep_already_emitted: bool,
    pub dep_currently_visiting: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectedDepOrderPlan {
    EmitDepBeforeRoot,
    SkipDepEdge,
}

pub fn normalize_selected_dep_order_context(
    raw_rows: SelectedDepOrderRawRows,
) -> (context: SelectedDepOrderDecisionContext)
    ensures
        context.dep_is_selected == raw_rows.dep_is_selected,
        context.dep_already_emitted == raw_rows.dep_already_emitted,
        context.dep_currently_visiting == raw_rows.dep_currently_visiting,
{
    SelectedDepOrderDecisionContext {
        dep_is_selected: raw_rows.dep_is_selected,
        dep_already_emitted: raw_rows.dep_already_emitted,
        dep_currently_visiting: raw_rows.dep_currently_visiting,
    }
}

pub fn decide_selected_dep_order_plan(
    context: &SelectedDepOrderDecisionContext,
) -> (plan: SelectedDepOrderPlan)
    ensures
        (context.dep_is_selected
            && !context.dep_already_emitted
            && !context.dep_currently_visiting)
            ==> plan == SelectedDepOrderPlan::EmitDepBeforeRoot,
        (!context.dep_is_selected
            || context.dep_already_emitted
            || context.dep_currently_visiting)
            ==> plan == SelectedDepOrderPlan::SkipDepEdge,
{
    if context.dep_is_selected
        && !context.dep_already_emitted
        && !context.dep_currently_visiting
    {
        SelectedDepOrderPlan::EmitDepBeforeRoot
    } else {
        SelectedDepOrderPlan::SkipDepEdge
    }
}

} // verus!
