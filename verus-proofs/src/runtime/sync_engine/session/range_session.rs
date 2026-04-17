//! Formal verification of range-session index and send-order policy selection — verified core.
//!
//! Each `pub fn` below is executable Rust consumed by
//! `src/runtime/sync_engine/session/range_session.rs`. Postconditions (`ensures`) are
//! SMT-checked against the function body by `cargo-verus verify`.
//!
//! The runtime defines its own `SyncWindowKind` enum (in `session::windowing`) that this
//! crate cannot import without a dependency cycle. The verified order-policy planner here
//! takes a boolean `is_last_day` flag instead; the runtime wraps it with a thin matches!()
//! adapter. The SharedSyncEntry abstract spec models an in-process cache snapshot that is
//! not yet directly consumed from the runtime; it remains declarative.

use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------------
// Abstract window-kind model (declarative; used by spec-only obligations).

pub enum SyncWindowKind {
    Old,
    LastDay,
    LastWeek,
    LastTwelveWeeks,
}

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

// ---------------------------------------------------------------------------
// SharedSyncEntry cache-reuse decision — spec-only design contract.
//
// This planner is not directly invoked from the runtime today but records the
// SMT-checked intent that a cached negentropy snapshot is reused iff the cache
// epoch and bounds both match the requested window. It is kept as a spec fn so
// its obligations compose with spec-only proof tests below.

pub struct SharedSyncEntryRawRows {
    pub window_kind: SyncWindowKind,
    pub root_entry_count: nat,
    pub cache_epoch_matches: bool,
    pub cache_bounds_match: bool,
}

pub struct SharedSyncEntryDecisionContext {
    pub window_kind: SyncWindowKind,
    pub root_entry_count: nat,
    pub cache_epoch_matches: bool,
    pub cache_bounds_match: bool,
}

pub struct SharedSyncEntryPlan {
    pub dep_search_enabled: bool,
    pub candidate_root_count: nat,
    pub reuse_cached_snapshot: bool,
}

pub open spec fn should_search_deps(kind: SyncWindowKind) -> bool {
    match kind {
        SyncWindowKind::LastDay | SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks => {
            true
        }
        SyncWindowKind::Old => false,
    }
}

pub open spec fn normalize_shared_sync_entry_context(
    raw_rows: SharedSyncEntryRawRows,
) -> SharedSyncEntryDecisionContext {
    SharedSyncEntryDecisionContext {
        window_kind: raw_rows.window_kind,
        root_entry_count: raw_rows.root_entry_count,
        cache_epoch_matches: raw_rows.cache_epoch_matches,
        cache_bounds_match: raw_rows.cache_bounds_match,
    }
}

pub open spec fn decide_shared_sync_entry_plan(
    context: &SharedSyncEntryDecisionContext,
) -> SharedSyncEntryPlan {
    SharedSyncEntryPlan {
        dep_search_enabled: should_search_deps(context.window_kind),
        candidate_root_count: context.root_entry_count,
        reuse_cached_snapshot: context.cache_epoch_matches && context.cache_bounds_match,
    }
}

proof fn shared_sync_entry_normalizer_preserves_query_facts(
    root_count: nat,
    cache_epoch_matches: bool,
    cache_bounds_match: bool,
)
    ensures
        normalize_shared_sync_entry_context(SharedSyncEntryRawRows {
            window_kind: SyncWindowKind::LastDay,
            root_entry_count: root_count,
            cache_epoch_matches,
            cache_bounds_match,
        }) == (SharedSyncEntryDecisionContext {
            window_kind: SyncWindowKind::LastDay,
            root_entry_count: root_count,
            cache_epoch_matches,
            cache_bounds_match,
        }),
{
}

proof fn old_window_disables_dep_search(root_count: nat)
    ensures
        decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
            window_kind: SyncWindowKind::Old,
            root_entry_count: root_count,
            cache_epoch_matches: false,
            cache_bounds_match: false,
        }) == (SharedSyncEntryPlan {
            dep_search_enabled: false,
            candidate_root_count: root_count,
            reuse_cached_snapshot: false,
        }),
{
}

proof fn hot_windows_enable_dep_search(root_count: nat)
    ensures
        decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
            window_kind: SyncWindowKind::LastDay,
            root_entry_count: root_count,
            cache_epoch_matches: false,
            cache_bounds_match: false,
        }) == (SharedSyncEntryPlan {
            dep_search_enabled: true,
            candidate_root_count: root_count,
            reuse_cached_snapshot: false,
        }),
        decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
            window_kind: SyncWindowKind::LastWeek,
            root_entry_count: root_count,
            cache_epoch_matches: false,
            cache_bounds_match: false,
        }).dep_search_enabled,
        decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
            window_kind: SyncWindowKind::LastTwelveWeeks,
            root_entry_count: root_count,
            cache_epoch_matches: false,
            cache_bounds_match: false,
        }).dep_search_enabled,
{
}

proof fn cache_reuse_requires_epoch_and_bounds_match(root_count: nat, kind: SyncWindowKind)
    ensures
        decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
            window_kind: kind,
            root_entry_count: root_count,
            cache_epoch_matches: true,
            cache_bounds_match: true,
        }).reuse_cached_snapshot,
        !decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
            window_kind: kind,
            root_entry_count: root_count,
            cache_epoch_matches: false,
            cache_bounds_match: true,
        }).reuse_cached_snapshot,
        !decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
            window_kind: kind,
            root_entry_count: root_count,
            cache_epoch_matches: true,
            cache_bounds_match: false,
        }).reuse_cached_snapshot,
{
}

} // verus!
