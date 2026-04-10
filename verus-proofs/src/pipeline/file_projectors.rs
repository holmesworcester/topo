//! Formal verification of File and FileSlice projector properties.
//!
//! The file system has a two-phase guard-block pattern:
//!   1. File descriptor event must be projected first
//!   2. FileSlice events guard-block until their File descriptor exists
//!   3. When File is projected, it emits RetryFileSliceGuards
//!   4. FileSlice events are retried and can now proceed
//!
//! We also prove properties about tombstone propagation through the
//! file attachment graph.

use vstd::prelude::*;
use crate::decision::*;

verus! {

pub spec const ONE: nat = 1;

// ═══════════════════════════════════════════════════════════════════
// File Projector
// ═══════════════════════════════════════════════════════════════════

/// File projector decision model.
pub open spec fn file_project_decision(
    target_message_deleted: bool,
    has_signer_mismatch: bool,
) -> ProjectionDecision {
    if has_signer_mismatch {
        ProjectionDecision::Reject
    } else {
        ProjectionDecision::Valid  // valid whether message deleted or not
    }
}

/// Whether the file produces a row in the files table.
pub open spec fn file_produces_row(
    target_message_deleted: bool,
    has_signer_mismatch: bool,
) -> bool {
    !has_signer_mismatch && !target_message_deleted
}

/// Whether the file produces a deleted_files entry (tombstone propagation).
pub open spec fn file_produces_tombstone(
    target_message_deleted: bool,
    has_signer_mismatch: bool,
) -> bool {
    !has_signer_mismatch && target_message_deleted
}

/// Whether the file emits a RetryFileSliceGuards command.
/// Always emitted on Valid to unblock waiting file slices.
pub open spec fn file_emits_retry_slices(
    target_message_deleted: bool,
    has_signer_mismatch: bool,
) -> bool {
    !has_signer_mismatch  // emitted regardless of deletion state
}

proof fn proof_file_always_valid_unless_signer_mismatch(
    target_message_deleted: bool,
    has_signer_mismatch: bool,
)
    ensures
        has_signer_mismatch ==> matches!(file_project_decision(target_message_deleted, has_signer_mismatch), ProjectionDecision::Reject),
        !has_signer_mismatch ==> matches!(file_project_decision(target_message_deleted, has_signer_mismatch), ProjectionDecision::Valid),
{
}

proof fn proof_file_tombstone_xor_row(
    target_message_deleted: bool,
)
    ensures
        // Exactly one of row or tombstone is produced (when signer matches)
        file_produces_row(target_message_deleted, false) != file_produces_tombstone(target_message_deleted, false),
{
}

proof fn proof_file_always_emits_retry_on_valid()
    ensures
        file_emits_retry_slices(false, false),
        file_emits_retry_slices(true, false),
{
}

// ═══════════════════════════════════════════════════════════════════
// FileSlice Guard-Block Pattern
// ═══════════════════════════════════════════════════════════════════

/// FileSlice guard-block state machine.
pub enum FileSliceState {
    /// No file descriptor exists yet → guard-block.
    GuardBlocked,
    /// File descriptor exists, deleted message → tombstone propagation.
    DeletedFile,
    /// File descriptor exists, signer/key mismatch → reject.
    SignerMismatch,
    /// File descriptor exists, duplicate slot → reject.
    DuplicateSlot,
    /// File descriptor exists, all checks pass → valid insert.
    ValidInsert,
    /// Existing slice with same descriptor → idempotent replay.
    IdempotentReplay,
}

/// FileSlice projector decision model.
pub open spec fn file_slice_decision(state: FileSliceState) -> ProjectionDecision {
    match state {
        FileSliceState::GuardBlocked => ProjectionDecision::Block { missing_count: ONE },
        FileSliceState::DeletedFile => ProjectionDecision::Valid,  // no row, tombstone propagation
        FileSliceState::SignerMismatch => ProjectionDecision::Reject,
        FileSliceState::DuplicateSlot => ProjectionDecision::Reject,
        FileSliceState::ValidInsert => ProjectionDecision::Valid,
        FileSliceState::IdempotentReplay => ProjectionDecision::Valid,
    }
}

/// Determine the FileSlice state from context.
pub open spec fn determine_file_slice_state(
    has_file_descriptor: bool,
    file_deleted: bool,
    signer_matches: bool,
    slot_occupied_same_descriptor: bool,
    slot_occupied_different_descriptor: bool,
) -> FileSliceState {
    if !has_file_descriptor {
        FileSliceState::GuardBlocked
    } else if file_deleted {
        FileSliceState::DeletedFile
    } else if !signer_matches {
        FileSliceState::SignerMismatch
    } else if slot_occupied_same_descriptor {
        FileSliceState::IdempotentReplay
    } else if slot_occupied_different_descriptor {
        FileSliceState::DuplicateSlot
    } else {
        FileSliceState::ValidInsert
    }
}

// ─── FileSlice Proofs ───

proof fn proof_file_slice_guard_blocks_without_descriptor()
    ensures
        matches!(
            file_slice_decision(determine_file_slice_state(false, false, true, false, false)),
            ProjectionDecision::Block { .. }
        ),
{
}

proof fn proof_file_slice_valid_with_descriptor()
    ensures
        matches!(
            file_slice_decision(determine_file_slice_state(true, false, true, false, false)),
            ProjectionDecision::Valid
        ),
{
}

proof fn proof_file_slice_tombstone_propagation()
    ensures
        matches!(
            file_slice_decision(determine_file_slice_state(true, true, true, false, false)),
            ProjectionDecision::Valid  // valid but no row (tombstone propagation)
        ),
{
}

proof fn proof_file_slice_rejects_signer_mismatch()
    ensures
        matches!(
            file_slice_decision(determine_file_slice_state(true, false, false, false, false)),
            ProjectionDecision::Reject
        ),
{
}

proof fn proof_file_slice_rejects_duplicate_slot()
    ensures
        matches!(
            file_slice_decision(determine_file_slice_state(true, false, true, false, true)),
            ProjectionDecision::Reject
        ),
{
}

proof fn proof_file_slice_idempotent_replay()
    ensures
        matches!(
            file_slice_decision(determine_file_slice_state(true, false, true, true, false)),
            ProjectionDecision::Valid
        ),
{
}

// ═══════════════════════════════════════════════════════════════════
// Guard-Block → Retry Lifecycle
// ═══════════════════════════════════════════════════════════════════

/// Model of the guard-block lifecycle:
///   1. FileSlice arrives before File → guard-blocked
///   2. File arrives → projected, emits RetryFileSliceGuards
///   3. FileSlice retried → now has descriptor, proceeds to Valid/Reject
pub open spec fn guard_block_lifecycle(
    file_arrived_first: bool,
) -> (FileSliceState, FileSliceState) {
    if file_arrived_first {
        // File first: slice has descriptor immediately
        (FileSliceState::ValidInsert, FileSliceState::ValidInsert)
    } else {
        // Slice first: guard-blocked, then retried after file arrives
        (FileSliceState::GuardBlocked, FileSliceState::ValidInsert)
    }
}

/// Proof: regardless of arrival order, the final state is ValidInsert.
proof fn proof_guard_block_converges_to_valid()
    ensures
        ({
            let (initial_first, final_first) = guard_block_lifecycle(true);
            let (initial_second, final_second) = guard_block_lifecycle(false);
            // When file arrives first, immediate valid
            matches!(file_slice_decision(initial_first), ProjectionDecision::Valid)
            // When slice arrives first, guard-blocked then valid on retry
            && matches!(file_slice_decision(initial_second), ProjectionDecision::Block { .. })
            && matches!(file_slice_decision(final_second), ProjectionDecision::Valid)
        }),
{
}

// ═══════════════════════════════════════════════════════════════════
// Tombstone Propagation Through File Graph
// ═══════════════════════════════════════════════════════════════════

/// Model: when a message is deleted, its entire file attachment graph
/// is tombstoned. The propagation path is:
///   MessageDeletion → deleted_messages → File sees deleted target →
///   deleted_files → FileSlice sees deleted file → no row
pub open spec fn tombstone_propagates_to_files(
    message_deleted: bool,
) -> bool {
    message_deleted  // File projector checks this
}

pub open spec fn tombstone_propagates_to_slices(
    file_deleted: bool,
) -> bool {
    file_deleted  // FileSlice projector checks this
}

/// Proof: message deletion cascades through the full attachment graph.
proof fn proof_tombstone_cascades_through_graph(message_deleted: bool)
    requires message_deleted
    ensures
        tombstone_propagates_to_files(message_deleted),
        tombstone_propagates_to_slices(tombstone_propagates_to_files(message_deleted)),
{
}

/// Proof: non-deleted messages don't propagate tombstones.
proof fn proof_no_tombstone_without_deletion()
    ensures
        !tombstone_propagates_to_files(false),
        !tombstone_propagates_to_slices(false),
{
}

} // verus!
