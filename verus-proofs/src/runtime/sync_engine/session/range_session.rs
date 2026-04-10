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
