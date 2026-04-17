//! Formal verification of durable range-session index and send-order policy selection.

use vstd::prelude::*;

verus! {

pub enum SyncWindowKind {
    Old,
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
        SyncWindowKind::Old | SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks => {
            SharedSendOrderPolicy::PreserveInput
        }
    }
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
        decide_shared_send_order_policy(SyncWindowKind::Old)
            == SharedSendOrderPolicy::PreserveInput,
{
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

proof fn shared_sync_entry_plan_candidate_count_is_durable_root_count(
    context: SharedSyncEntryDecisionContext,
)
    ensures
        decide_shared_sync_entry_plan(&context).candidate_root_count == context.root_entry_count,
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
