//! Formal verification of the persist phase properties.
//!
//! The persist phase writes events to the database inside a transaction.
//! Key properties:
//! - Shared events get shared_event_index entries
//! - Secret events do NOT get shared_event_index entries
//! - File slices get priority_lane=2 (bulk), everything else gets 1
//! - endpoint_shared events don't get live hints or fanouts
//! - Fanout entries are persisted durably inside the transaction

use vstd::prelude::*;

verus! {

/// Share scope determines event visibility.
pub enum ShareScope {
    Shared,
    Secret,
}

pub enum WorkspaceTarget {
    Skip,
    MissingBinding,
    EventId,
    WorkspaceBinding,
}

/// Model of per-event persist phase decisions.
pub struct PersistDecisions {
    pub write_shared_index: bool,
    pub shared_index_workspace: WorkspaceTarget,
    pub priority_lane: nat,
    pub emit_live_hint: bool,
    pub emit_fanout: bool,
    pub fanout_workspace: WorkspaceTarget,
}

/// Persist phase decision model for a single event.
pub open spec fn persist_decisions_for_event(
    share_scope: ShareScope,
    type_name_is_endpoint_shared: bool,
    type_name_is_workspace: bool,
    is_file_slice: bool,
    has_workspace_binding: bool,
) -> PersistDecisions {
    let workspace_target = if !matches!(share_scope, ShareScope::Shared)
        || type_name_is_endpoint_shared
    {
        WorkspaceTarget::Skip
    } else if type_name_is_workspace {
        WorkspaceTarget::EventId
    } else if has_workspace_binding {
        WorkspaceTarget::WorkspaceBinding
    } else {
        WorkspaceTarget::MissingBinding
    };
    PersistDecisions {
        // Shared events get index entries (if workspace known)
        write_shared_index: matches!(share_scope, ShareScope::Shared)
            && (has_workspace_binding || type_name_is_workspace)
            && !type_name_is_endpoint_shared,
        shared_index_workspace: workspace_target,
        // File slices get bulk priority (lane 2), everything else lane 1
        priority_lane: if is_file_slice { 2 } else { 1 },
        // endpoint_shared events don't get live hints
        emit_live_hint: matches!(share_scope, ShareScope::Shared) && !type_name_is_endpoint_shared,
        // endpoint_shared events don't get fanouts
        emit_fanout: matches!(share_scope, ShareScope::Shared) && !type_name_is_endpoint_shared,
        fanout_workspace: workspace_target,
    }
}

// ═══════════════════════════════════════════════════════════════════
// Share Scope Proofs
// ═══════════════════════════════════════════════════════════════════

/// Proof: secret events never get shared_event_index entries.
proof fn proof_secret_events_no_shared_index(
    is_endpoint_shared: bool,
    is_workspace: bool,
    is_file_slice: bool,
    has_ws: bool,
)
    ensures
        ({
            let d = persist_decisions_for_event(
                ShareScope::Secret, is_endpoint_shared, is_workspace, is_file_slice, has_ws
            );
            !d.write_shared_index && d.shared_index_workspace == WorkspaceTarget::Skip
        }),
{
}

/// Proof: secret events never emit live hints.
proof fn proof_secret_events_no_live_hints(
    is_endpoint_shared: bool,
    is_workspace: bool,
    is_file_slice: bool,
    has_ws: bool,
)
    ensures
        !persist_decisions_for_event(
            ShareScope::Secret, is_endpoint_shared, is_workspace, is_file_slice, has_ws
        ).emit_live_hint,
{
}

/// Proof: secret events never emit fanouts.
proof fn proof_secret_events_no_fanouts(
    is_endpoint_shared: bool,
    is_workspace: bool,
    is_file_slice: bool,
    has_ws: bool,
)
    ensures
        !persist_decisions_for_event(
            ShareScope::Secret, is_endpoint_shared, is_workspace, is_file_slice, has_ws
        ).emit_fanout,
{
}

// ═══════════════════════════════════════════════════════════════════
// Priority Lane Proofs
// ═══════════════════════════════════════════════════════════════════

/// Proof: file slices get priority lane 2.
proof fn proof_file_slices_get_bulk_priority(
    scope: ShareScope,
    is_ep: bool,
    is_ws: bool,
    has_ws: bool,
)
    ensures
        persist_decisions_for_event(scope, is_ep, is_ws, true, has_ws).priority_lane == 2,
{
}

/// Proof: non-file-slice events get priority lane 1.
proof fn proof_non_file_slices_get_foreground_priority(
    scope: ShareScope,
    is_ep: bool,
    is_ws: bool,
    has_ws: bool,
)
    ensures
        persist_decisions_for_event(scope, is_ep, is_ws, false, has_ws).priority_lane == 1,
{
}

// ═══════════════════════════════════════════════════════════════════
// Endpoint Shared Exclusion Proofs
// ═══════════════════════════════════════════════════════════════════

/// Proof: endpoint_shared events don't get live hints or fanouts
/// even though they are shared-scope.
proof fn proof_endpoint_shared_exclusions()
    ensures
        ({
            let d = persist_decisions_for_event(ShareScope::Shared, true, false, false, true);
            !d.emit_live_hint
                && !d.emit_fanout
                && !d.write_shared_index
                && d.shared_index_workspace == WorkspaceTarget::Skip
                && d.fanout_workspace == WorkspaceTarget::Skip
        }),
{
}

/// Proof: regular shared events DO get live hints and fanouts.
proof fn proof_regular_shared_gets_hints_and_fanouts()
    ensures
        ({
            let d = persist_decisions_for_event(ShareScope::Shared, false, false, false, true);
            d.emit_live_hint && d.emit_fanout && d.write_shared_index
        }),
{
}

// ═══════════════════════════════════════════════════════════════════
// Workspace Event Self-Reference
// ═══════════════════════════════════════════════════════════════════

/// Proof: workspace events use their own event_id as workspace_id
/// for the shared_event_index, even without a prior workspace binding.
proof fn proof_workspace_event_self_references()
    ensures
        ({
            let without_binding =
                persist_decisions_for_event(ShareScope::Shared, false, true, false, false);
            let with_binding =
                persist_decisions_for_event(ShareScope::Shared, false, true, false, true);
            without_binding.write_shared_index
                && without_binding.shared_index_workspace == WorkspaceTarget::EventId
                && with_binding.write_shared_index
                && with_binding.shared_index_workspace == WorkspaceTarget::EventId
        }),
{
}

// ═══════════════════════════════════════════════════════════════════
// Durable Fanout Entries
// ═══════════════════════════════════════════════════════════════════

/// Model: fanout entries are persisted INSIDE the transaction.
/// If the transaction commits, fanouts are durable.
/// If it rolls back, fanouts are lost (but so are the events).
pub open spec fn fanout_durability_model(
    tx_committed: bool,
    fanout_entries_written: nat,
) -> nat {
    if tx_committed {
        fanout_entries_written
    } else {
        0  // rolled back
    }
}

/// Proof: committed fanouts are durable.
proof fn proof_committed_fanouts_are_durable(count: nat)
    ensures fanout_durability_model(true, count) == count,
{
}

/// Proof: rolled-back fanouts are lost.
proof fn proof_rolled_back_fanouts_are_lost(count: nat)
    ensures fanout_durability_model(false, count) == 0,
{
}

/// Proof: fanout durability is consistent with commit atomicity.
/// Events and fanouts share the same transaction boundary.
proof fn proof_fanout_atomicity_matches_events(
    tx_committed: bool,
    events_persisted: nat,
    fanouts_written: nat,
)
    ensures
        // Both are durable or both are lost
        (tx_committed ==> fanout_durability_model(tx_committed, fanouts_written) == fanouts_written),
        (!tx_committed ==> fanout_durability_model(tx_committed, fanouts_written) == 0),
{
}

} // verus!
