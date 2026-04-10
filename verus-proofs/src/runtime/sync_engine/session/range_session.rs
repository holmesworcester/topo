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

pub struct SharedSyncEntryRawRows {
    pub window_kind: SyncWindowKind,
    pub base_entry_count: nat,
    pub hot_week_dep_entry_count: nat,
}

pub struct SharedSyncEntryDecisionContext {
    pub window_kind: SyncWindowKind,
    pub base_entry_count: nat,
    pub hot_week_dep_entry_count: nat,
}

pub struct SharedSyncEntryPlan {
    pub include_hot_week_deps: bool,
    pub candidate_entry_count: nat,
}

pub struct SharedSendEligibilityRawRows {
    pub requested_by_reconciliation: bool,
    pub present_in_workspace_index: bool,
    pub shared_blob_available: bool,
    pub used_bootstrap_auth: bool,
    pub used_peer_shared_auth: bool,
}

pub struct SharedSendEligibilityDecisionContext {
    pub requested_by_reconciliation: bool,
    pub present_in_workspace_index: bool,
    pub shared_blob_available: bool,
}

pub enum SharedSendEligibilityPlan {
    SendRoot,
    SkipRoot,
}

pub struct SelectedDepOrderRawRows {
    pub dep_is_selected: bool,
    pub dep_already_emitted: bool,
    pub dep_currently_visiting: bool,
}

pub struct SelectedDepOrderDecisionContext {
    pub dep_is_selected: bool,
    pub dep_already_emitted: bool,
    pub dep_currently_visiting: bool,
}

pub enum SelectedDepOrderPlan {
    EmitDepBeforeRoot,
    SkipDepEdge,
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

pub open spec fn should_include_hot_week_deps(kind: SyncWindowKind) -> bool {
    match kind {
        SyncWindowKind::LastDay | SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks => {
            true
        }
        SyncWindowKind::Full => false,
    }
}

pub open spec fn normalize_shared_sync_entry_context(
    raw_rows: SharedSyncEntryRawRows,
) -> SharedSyncEntryDecisionContext {
    SharedSyncEntryDecisionContext {
        window_kind: raw_rows.window_kind,
        base_entry_count: raw_rows.base_entry_count,
        hot_week_dep_entry_count: raw_rows.hot_week_dep_entry_count,
    }
}

pub open spec fn decide_shared_sync_entry_plan(
    context: &SharedSyncEntryDecisionContext,
) -> SharedSyncEntryPlan {
    let include_hot_week_deps = should_include_hot_week_deps(context.window_kind);
    SharedSyncEntryPlan {
        include_hot_week_deps,
        candidate_entry_count: if include_hot_week_deps {
            context.base_entry_count + context.hot_week_dep_entry_count
        } else {
            context.base_entry_count
        },
    }
}

pub open spec fn normalize_shared_send_eligibility_context(
    raw_rows: SharedSendEligibilityRawRows,
) -> SharedSendEligibilityDecisionContext {
    SharedSendEligibilityDecisionContext {
        requested_by_reconciliation: raw_rows.requested_by_reconciliation,
        present_in_workspace_index: raw_rows.present_in_workspace_index,
        shared_blob_available: raw_rows.shared_blob_available,
    }
}

pub open spec fn decide_shared_send_eligibility_plan(
    context: &SharedSendEligibilityDecisionContext,
) -> SharedSendEligibilityPlan {
    if context.requested_by_reconciliation
        && context.present_in_workspace_index
        && context.shared_blob_available
    {
        SharedSendEligibilityPlan::SendRoot
    } else {
        SharedSendEligibilityPlan::SkipRoot
    }
}

pub open spec fn normalize_selected_dep_order_context(
    raw_rows: SelectedDepOrderRawRows,
) -> SelectedDepOrderDecisionContext {
    SelectedDepOrderDecisionContext {
        dep_is_selected: raw_rows.dep_is_selected,
        dep_already_emitted: raw_rows.dep_already_emitted,
        dep_currently_visiting: raw_rows.dep_currently_visiting,
    }
}

pub open spec fn decide_selected_dep_order_plan(
    context: &SelectedDepOrderDecisionContext,
) -> SelectedDepOrderPlan {
    if context.dep_is_selected
        && !context.dep_already_emitted
        && !context.dep_currently_visiting
    {
        SelectedDepOrderPlan::EmitDepBeforeRoot
    } else {
        SelectedDepOrderPlan::SkipDepEdge
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

proof fn shared_sync_entry_normalizer_preserves_query_facts(
    base_count: nat,
    hot_dep_count: nat,
)
    ensures
        normalize_shared_sync_entry_context(SharedSyncEntryRawRows {
            window_kind: SyncWindowKind::LastDay,
            base_entry_count: base_count,
            hot_week_dep_entry_count: hot_dep_count,
        }) == (SharedSyncEntryDecisionContext {
            window_kind: SyncWindowKind::LastDay,
            base_entry_count: base_count,
            hot_week_dep_entry_count: hot_dep_count,
        }),
{
}

proof fn selected_dep_order_normalizer_preserves_query_facts(
    dep_is_selected: bool,
    dep_already_emitted: bool,
    dep_currently_visiting: bool,
)
    ensures
        normalize_selected_dep_order_context(SelectedDepOrderRawRows {
            dep_is_selected,
            dep_already_emitted,
            dep_currently_visiting,
        }) == (SelectedDepOrderDecisionContext {
            dep_is_selected,
            dep_already_emitted,
            dep_currently_visiting,
        }),
{
}

proof fn shared_send_eligibility_requires_request_workspace_index_and_shared_blob(
    context: SharedSendEligibilityDecisionContext,
)
    ensures
        decide_shared_send_eligibility_plan(&context) == SharedSendEligibilityPlan::SendRoot
            ==> context.requested_by_reconciliation
                && context.present_in_workspace_index
                && context.shared_blob_available,
{
}

proof fn shared_send_eligibility_blocks_local_only_or_wrong_workspace()
    ensures
        decide_shared_send_eligibility_plan(&SharedSendEligibilityDecisionContext {
            requested_by_reconciliation: true,
            present_in_workspace_index: true,
            shared_blob_available: false,
        }) == SharedSendEligibilityPlan::SkipRoot,
        decide_shared_send_eligibility_plan(&SharedSendEligibilityDecisionContext {
            requested_by_reconciliation: true,
            present_in_workspace_index: false,
            shared_blob_available: true,
        }) == SharedSendEligibilityPlan::SkipRoot,
{
}

proof fn shared_send_eligibility_auth_path_noninterference(
    requested_by_reconciliation: bool,
    present_in_workspace_index: bool,
    shared_blob_available: bool,
    bootstrap_a: bool,
    peer_shared_a: bool,
    bootstrap_b: bool,
    peer_shared_b: bool,
)
    ensures
        decide_shared_send_eligibility_plan(&normalize_shared_send_eligibility_context(
            SharedSendEligibilityRawRows {
                requested_by_reconciliation,
                present_in_workspace_index,
                shared_blob_available,
                used_bootstrap_auth: bootstrap_a,
                used_peer_shared_auth: peer_shared_a,
            },
        )) == decide_shared_send_eligibility_plan(&normalize_shared_send_eligibility_context(
            SharedSendEligibilityRawRows {
                requested_by_reconciliation,
                present_in_workspace_index,
                shared_blob_available,
                used_bootstrap_auth: bootstrap_b,
                used_peer_shared_auth: peer_shared_b,
            },
        )),
{
}

proof fn full_window_does_not_expand_hot_week_deps(base_count: nat, hot_dep_count: nat)
    ensures
        decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
            window_kind: SyncWindowKind::Full,
            base_entry_count: base_count,
            hot_week_dep_entry_count: hot_dep_count,
        }) == (SharedSyncEntryPlan {
            include_hot_week_deps: false,
            candidate_entry_count: base_count,
        }),
{
}

proof fn hot_windows_expand_hot_week_deps(base_count: nat, hot_dep_count: nat)
    ensures
        decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
            window_kind: SyncWindowKind::LastDay,
            base_entry_count: base_count,
            hot_week_dep_entry_count: hot_dep_count,
        }) == (SharedSyncEntryPlan {
            include_hot_week_deps: true,
            candidate_entry_count: base_count + hot_dep_count,
        }),
        decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
            window_kind: SyncWindowKind::LastWeek,
            base_entry_count: base_count,
            hot_week_dep_entry_count: hot_dep_count,
        }).include_hot_week_deps,
        decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
            window_kind: SyncWindowKind::LastTwelveWeeks,
            base_entry_count: base_count,
            hot_week_dep_entry_count: hot_dep_count,
        }).include_hot_week_deps,
{
}

proof fn selected_unemitted_dep_is_emitted_before_root()
    ensures
        decide_selected_dep_order_plan(&SelectedDepOrderDecisionContext {
            dep_is_selected: true,
            dep_already_emitted: false,
            dep_currently_visiting: false,
        }) == SelectedDepOrderPlan::EmitDepBeforeRoot,
{
}

proof fn emit_dep_before_root_requires_selected_unemitted_nonvisiting(
    context: SelectedDepOrderDecisionContext,
)
    ensures
        decide_selected_dep_order_plan(&context) == SelectedDepOrderPlan::EmitDepBeforeRoot
            ==> context.dep_is_selected
                && !context.dep_already_emitted
                && !context.dep_currently_visiting,
{
}

proof fn unselected_or_cycle_dep_edge_is_skipped()
    ensures
        decide_selected_dep_order_plan(&SelectedDepOrderDecisionContext {
            dep_is_selected: false,
            dep_already_emitted: false,
            dep_currently_visiting: false,
        }) == SelectedDepOrderPlan::SkipDepEdge,
        decide_selected_dep_order_plan(&SelectedDepOrderDecisionContext {
            dep_is_selected: true,
            dep_already_emitted: true,
            dep_currently_visiting: false,
        }) == SelectedDepOrderPlan::SkipDepEdge,
        decide_selected_dep_order_plan(&SelectedDepOrderDecisionContext {
            dep_is_selected: true,
            dep_already_emitted: false,
            dep_currently_visiting: true,
        }) == SelectedDepOrderPlan::SkipDepEdge,
{
}

} // verus!
