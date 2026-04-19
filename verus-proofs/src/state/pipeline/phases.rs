//! Formal verification of the persist phase properties.
//!
//! The persist phase writes events to the database inside a transaction.
//! Key properties:
//! - Shared events get shared_event_index entries
//! - Secret (local-scope) events do NOT get shared_event_index entries
//! - File slices get priority_lane=2 (bulk), everything else gets 1
//! - endpoint_shared events don't get live hints or fanouts
//! - Fanout entries are persisted durably inside the transaction
//!
//! Every `pub fn` below is an executable Rust abstract model of the corresponding
//! runtime composition in `src/state/pipeline/phases.rs`. Postconditions (`ensures`)
//! are SMT-checked against the function body by `cargo-verus verify`.
//!
//! Runtime carries `workspace_binding: Option<String>`; the verified core reduces
//! that to `has_workspace_binding: bool` — the runtime wrapper keeps the concrete
//! workspace_id locally and only consults the core for the tag-level dispatch.
//!
//! The current runtime additionally persists large shared `key_rotation` / `key_history`
//! events through the same persist-phase dispatch, so these workspace-target and
//! fanout rules remain the governing abstraction for the new key-delivery model too.

use vstd::prelude::*;

verus! {

/// Share scope determines event visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareScopeCore {
    Shared,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceTargetCore {
    Skip,
    MissingBinding,
    EventId,
    WorkspaceBinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistEventRawRowsCore {
    pub share_scope: ShareScopeCore,
    pub type_name_is_endpoint_shared: bool,
    pub type_name_is_workspace: bool,
    pub is_file_slice: bool,
    pub has_workspace_binding: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistEventDecisionContextCore {
    pub share_scope: ShareScopeCore,
    pub type_name_is_endpoint_shared: bool,
    pub type_name_is_workspace: bool,
    pub is_file_slice: bool,
    pub has_workspace_binding: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PersistDecisionsCore {
    pub write_shared_index: bool,
    pub shared_index_workspace: WorkspaceTargetCore,
    pub priority_lane: u32,
    pub emit_live_hint: bool,
    pub emit_fanout: bool,
    pub fanout_workspace: WorkspaceTargetCore,
}

pub fn normalize_persist_event_core(
    raw_rows: PersistEventRawRowsCore,
) -> (context: PersistEventDecisionContextCore)
    ensures
        context.share_scope == raw_rows.share_scope,
        context.type_name_is_endpoint_shared == raw_rows.type_name_is_endpoint_shared,
        context.type_name_is_workspace == raw_rows.type_name_is_workspace,
        context.is_file_slice == raw_rows.is_file_slice,
        context.has_workspace_binding == raw_rows.has_workspace_binding,
{
    PersistEventDecisionContextCore {
        share_scope: raw_rows.share_scope,
        type_name_is_endpoint_shared: raw_rows.type_name_is_endpoint_shared,
        type_name_is_workspace: raw_rows.type_name_is_workspace,
        is_file_slice: raw_rows.is_file_slice,
        has_workspace_binding: raw_rows.has_workspace_binding,
    }
}

pub fn decide_persist_event_plan_core(
    context: &PersistEventDecisionContextCore,
) -> (plan: PersistDecisionsCore)
    ensures
        // Delegation: shape is identical to persist_decisions_for_event_core.
        // File slices get bulk priority (2), everything else foreground (1).
        context.is_file_slice ==> plan.priority_lane == 2,
        !context.is_file_slice ==> plan.priority_lane == 1,
        context.share_scope == ShareScopeCore::Secret ==> !plan.write_shared_index,
        context.share_scope == ShareScopeCore::Secret ==> plan.shared_index_workspace == WorkspaceTargetCore::Skip,
        context.share_scope == ShareScopeCore::Secret ==> !plan.emit_live_hint,
        context.share_scope == ShareScopeCore::Secret ==> !plan.emit_fanout,
{
    persist_decisions_for_event_core(
        context.share_scope,
        context.type_name_is_endpoint_shared,
        context.type_name_is_workspace,
        context.is_file_slice,
        context.has_workspace_binding,
    )
}

/// Persist phase decision model for a single event (executable core).
pub fn persist_decisions_for_event_core(
    share_scope: ShareScopeCore,
    type_name_is_endpoint_shared: bool,
    type_name_is_workspace: bool,
    is_file_slice: bool,
    has_workspace_binding: bool,
) -> (plan: PersistDecisionsCore)
    ensures
        // File slices get bulk priority (2), everything else foreground (1).
        is_file_slice ==> plan.priority_lane == 2,
        !is_file_slice ==> plan.priority_lane == 1,
        // Secret (local-scope) events: no shared index, no live hint, no fanout.
        share_scope == ShareScopeCore::Secret ==> !plan.write_shared_index,
        share_scope == ShareScopeCore::Secret ==> plan.shared_index_workspace == WorkspaceTargetCore::Skip,
        share_scope == ShareScopeCore::Secret ==> !plan.emit_live_hint,
        share_scope == ShareScopeCore::Secret ==> !plan.emit_fanout,
        // endpoint_shared under Shared scope is excluded from hints/fanouts.
        (share_scope == ShareScopeCore::Shared && type_name_is_endpoint_shared) ==> {
            &&& !plan.write_shared_index
            &&& plan.shared_index_workspace == WorkspaceTargetCore::Skip
            &&& !plan.emit_live_hint
            &&& !plan.emit_fanout
            &&& plan.fanout_workspace == WorkspaceTargetCore::Skip
        },
        // Workspace events are self-referencing even without an existing binding.
        (share_scope == ShareScopeCore::Shared
         && !type_name_is_endpoint_shared
         && type_name_is_workspace) ==> {
            &&& plan.shared_index_workspace == WorkspaceTargetCore::EventId
            &&& plan.write_shared_index
        },
        // Regular shared events with workspace bindings are indexed + fanned out.
        (share_scope == ShareScopeCore::Shared
         && !type_name_is_endpoint_shared
         && !type_name_is_workspace
         && has_workspace_binding) ==> {
            &&& plan.shared_index_workspace == WorkspaceTargetCore::WorkspaceBinding
            &&& plan.write_shared_index
            &&& plan.emit_fanout
        },
        // Regular shared events without a workspace binding: indexed as missing.
        (share_scope == ShareScopeCore::Shared
         && !type_name_is_endpoint_shared
         && !type_name_is_workspace
         && !has_workspace_binding) ==> {
            &&& plan.shared_index_workspace == WorkspaceTargetCore::MissingBinding
            &&& !plan.write_shared_index
            &&& !plan.emit_fanout
            &&& plan.fanout_workspace == WorkspaceTargetCore::MissingBinding
        },
{
    let share_is_shared = match share_scope {
        ShareScopeCore::Shared => true,
        ShareScopeCore::Secret => false,
    };
    let workspace_target = if !share_is_shared || type_name_is_endpoint_shared {
        WorkspaceTargetCore::Skip
    } else if type_name_is_workspace {
        WorkspaceTargetCore::EventId
    } else if has_workspace_binding {
        WorkspaceTargetCore::WorkspaceBinding
    } else {
        WorkspaceTargetCore::MissingBinding
    };
    let write_shared_index = share_is_shared
        && (has_workspace_binding || type_name_is_workspace)
        && !type_name_is_endpoint_shared;
    let emit_live_hint = share_is_shared && !type_name_is_endpoint_shared;
    let emit_fanout = match workspace_target {
        WorkspaceTargetCore::EventId | WorkspaceTargetCore::WorkspaceBinding => true,
        _ => false,
    };
    PersistDecisionsCore {
        write_shared_index,
        shared_index_workspace: workspace_target,
        priority_lane: if is_file_slice { 2 } else { 1 },
        emit_live_hint,
        emit_fanout,
        fanout_workspace: workspace_target,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Durable Fanout Entries
// ═══════════════════════════════════════════════════════════════════

/// Executable model: fanout entries are persisted INSIDE the transaction.
/// If the transaction commits, fanouts are durable.
/// If it rolls back, fanouts are lost (but so are the events).
pub fn fanout_durability_model(
    tx_committed: bool,
    fanout_entries_written: u64,
) -> (out: u64)
    ensures
        tx_committed ==> out == fanout_entries_written,
        !tx_committed ==> out == 0,
{
    if tx_committed {
        fanout_entries_written
    } else {
        0  // rolled back
    }
}

} // verus!
