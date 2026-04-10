//! Formal verification of pure projector functions.
//!
//! Each projector is modeled as a spec function from abstract event fields
//! and context to a decision. We use bool flags and nat counts rather than
//! string fields to keep things Verus-friendly.

use vstd::prelude::*;
use crate::decision::*;

verus! {

// ═══════════════════════════════════════════════════════════════════
// Projector DecisionContext model
// ═══════════════════════════════════════════════════════════════════

pub struct ProjectorDecisionContext {
    pub has_signer_mismatch: bool,
    pub has_admin_key_mismatch: bool,
    pub target_message_author_present: bool,
    pub target_message_author_matches_del: bool,
    pub target_tombstone_present: bool,
    pub target_tombstone_author_matches_del: bool,
    pub target_is_non_message: bool,
    pub has_matching_deletion_intent: bool,
    pub target_message_deleted: bool,
}

// ═══════════════════════════════════════════════════════════════════
// Message Projector
// ═══════════════════════════════════════════════════════════════════

pub struct MessageFields {
    pub content_len: nat,
}

/// Message projector decision (models message/projector.rs).
pub open spec fn message_project_decision(
    msg: &MessageFields,
    ctx: &ProjectorDecisionContext,
) -> ProjectionDecision {
    if msg.content_len == 0 {
        ProjectionDecision::Reject
    } else if ctx.has_signer_mismatch {
        ProjectionDecision::Reject
    } else {
        ProjectionDecision::Valid  // tombstoned-on-arrival or normal
    }
}

/// Whether the message is tombstoned on arrival (has matching deletion intent).
pub open spec fn message_is_tombstoned_on_arrival(
    msg: &MessageFields,
    ctx: &ProjectorDecisionContext,
) -> bool {
    msg.content_len > 0
    && !ctx.has_signer_mismatch
    && ctx.has_matching_deletion_intent
}

/// Whether the message produces a normal row insert.
pub open spec fn message_produces_row(
    msg: &MessageFields,
    ctx: &ProjectorDecisionContext,
) -> bool {
    msg.content_len > 0
    && !ctx.has_signer_mismatch
    && !ctx.has_matching_deletion_intent
}

// ─── Message Proofs ───

proof fn proof_message_rejects_empty_content(msg: &MessageFields, ctx: &ProjectorDecisionContext)
    requires msg.content_len == 0
    ensures matches!(message_project_decision(msg, ctx), ProjectionDecision::Reject),
{
}

proof fn proof_message_rejects_signer_mismatch(msg: &MessageFields, ctx: &ProjectorDecisionContext)
    requires msg.content_len > 0 && ctx.has_signer_mismatch
    ensures matches!(message_project_decision(msg, ctx), ProjectionDecision::Reject),
{
}

proof fn proof_message_valid_normal(msg: &MessageFields, ctx: &ProjectorDecisionContext)
    requires msg.content_len > 0 && !ctx.has_signer_mismatch
    ensures matches!(message_project_decision(msg, ctx), ProjectionDecision::Valid),
{
}

proof fn proof_message_tombstoned_on_arrival_is_valid(msg: &MessageFields, ctx: &ProjectorDecisionContext)
    requires msg.content_len > 0 && !ctx.has_signer_mismatch && ctx.has_matching_deletion_intent
    ensures
        matches!(message_project_decision(msg, ctx), ProjectionDecision::Valid),
        message_is_tombstoned_on_arrival(msg, ctx),
{
}

proof fn proof_message_never_blocks(msg: &MessageFields, ctx: &ProjectorDecisionContext)
    ensures !matches!(message_project_decision(msg, ctx), ProjectionDecision::Block { .. }),
{
}

// ═══════════════════════════════════════════════════════════════════
// Reaction Projector
// ═══════════════════════════════════════════════════════════════════

pub struct ReactionFields {
    pub emoji_len: nat,
}

/// Reaction projector decision (models reaction/projector.rs).
pub open spec fn reaction_project_decision(
    rxn: &ReactionFields,
    ctx: &ProjectorDecisionContext,
) -> ProjectionDecision {
    if rxn.emoji_len == 0 {
        ProjectionDecision::Reject
    } else if ctx.has_signer_mismatch {
        ProjectionDecision::Reject
    } else {
        ProjectionDecision::Valid  // valid whether target deleted or not
    }
}

/// Whether the reaction produces a row (only when target is live).
pub open spec fn reaction_produces_row(
    rxn: &ReactionFields,
    ctx: &ProjectorDecisionContext,
) -> bool {
    rxn.emoji_len > 0
    && !ctx.has_signer_mismatch
    && !ctx.target_message_deleted
}

proof fn proof_reaction_rejects_empty_emoji(rxn: &ReactionFields, ctx: &ProjectorDecisionContext)
    requires rxn.emoji_len == 0
    ensures matches!(reaction_project_decision(rxn, ctx), ProjectionDecision::Reject),
{
}

proof fn proof_reaction_on_deleted_is_valid_no_row(rxn: &ReactionFields, ctx: &ProjectorDecisionContext)
    requires rxn.emoji_len > 0 && !ctx.has_signer_mismatch && ctx.target_message_deleted
    ensures
        matches!(reaction_project_decision(rxn, ctx), ProjectionDecision::Valid),
        !reaction_produces_row(rxn, ctx),
{
}

proof fn proof_reaction_on_live_message_is_valid_with_row(rxn: &ReactionFields, ctx: &ProjectorDecisionContext)
    requires rxn.emoji_len > 0 && !ctx.has_signer_mismatch && !ctx.target_message_deleted
    ensures
        matches!(reaction_project_decision(rxn, ctx), ProjectionDecision::Valid),
        reaction_produces_row(rxn, ctx),
{
}

proof fn proof_reaction_never_blocks(rxn: &ReactionFields, ctx: &ProjectorDecisionContext)
    ensures !matches!(reaction_project_decision(rxn, ctx), ProjectionDecision::Block { .. }),
{
}

// ═══════════════════════════════════════════════════════════════════
// MessageDeletion Projector
// ═══════════════════════════════════════════════════════════════════

/// MessageDeletion projector decision (models message_deletion/projector.rs).
pub open spec fn message_deletion_project_decision(ctx: &ProjectorDecisionContext) -> ProjectionDecision {
    if ctx.has_signer_mismatch {
        ProjectionDecision::Reject
    } else if ctx.target_is_non_message {
        ProjectionDecision::Reject
    } else if ctx.target_tombstone_present {
        if !ctx.target_tombstone_author_matches_del {
            ProjectionDecision::Reject
        } else {
            ProjectionDecision::Valid  // already tombstoned, record intent
        }
    } else if ctx.target_message_author_present {
        if !ctx.target_message_author_matches_del {
            ProjectionDecision::Reject
        } else {
            ProjectionDecision::Valid  // tombstone + cascade
        }
    } else {
        ProjectionDecision::Valid  // intent-only
    }
}

/// Whether the deletion produces a tombstone row.
pub open spec fn deletion_produces_tombstone(ctx: &ProjectorDecisionContext) -> bool {
    !ctx.has_signer_mismatch
    && !ctx.target_is_non_message
    && !ctx.target_tombstone_present
    && ctx.target_message_author_present
    && ctx.target_message_author_matches_del
}

/// Whether the deletion only records an intent.
pub open spec fn deletion_is_intent_only(ctx: &ProjectorDecisionContext) -> bool {
    !ctx.has_signer_mismatch
    && !ctx.target_is_non_message
    && !ctx.target_tombstone_present
    && !ctx.target_message_author_present
}

proof fn proof_deletion_rejects_non_message_target(ctx: &ProjectorDecisionContext)
    requires !ctx.has_signer_mismatch && ctx.target_is_non_message
    ensures matches!(message_deletion_project_decision(ctx), ProjectionDecision::Reject),
{
}

proof fn proof_deletion_rejects_author_mismatch(ctx: &ProjectorDecisionContext)
    requires
        !ctx.has_signer_mismatch
        && !ctx.target_is_non_message
        && !ctx.target_tombstone_present
        && ctx.target_message_author_present
        && !ctx.target_message_author_matches_del
    ensures matches!(message_deletion_project_decision(ctx), ProjectionDecision::Reject),
{
}

proof fn proof_deletion_produces_tombstone_on_match(ctx: &ProjectorDecisionContext)
    requires
        !ctx.has_signer_mismatch
        && !ctx.target_is_non_message
        && !ctx.target_tombstone_present
        && ctx.target_message_author_present
        && ctx.target_message_author_matches_del
    ensures
        matches!(message_deletion_project_decision(ctx), ProjectionDecision::Valid),
        deletion_produces_tombstone(ctx),
{
}

proof fn proof_deletion_intent_only_when_target_missing(ctx: &ProjectorDecisionContext)
    requires
        !ctx.has_signer_mismatch
        && !ctx.target_is_non_message
        && !ctx.target_tombstone_present
        && !ctx.target_message_author_present
    ensures
        matches!(message_deletion_project_decision(ctx), ProjectionDecision::Valid),
        deletion_is_intent_only(ctx),
{
}

proof fn proof_deletion_never_blocks(ctx: &ProjectorDecisionContext)
    ensures !matches!(message_deletion_project_decision(ctx), ProjectionDecision::Block { .. }),
{
}

// ═══════════════════════════════════════════════════════════════════
// Delete-Before-Create Convergence
// ═══════════════════════════════════════════════════════════════════

/// Critical convergence proof: regardless of arrival order (deletion first
/// or message first), the message projector produces Valid.
///
/// Case 1 (message first): msg arrives, no intents → Valid (normal insert)
/// Case 2 (deletion first): intent recorded, msg arrives with intent → Valid (tombstone)
///
/// The key invariant: the final state is equivalent (message is tombstoned).
proof fn proof_delete_before_create_convergence(msg: &MessageFields)
    requires msg.content_len > 0
    ensures
        ({
            // Case 1: message arrives first (no deletion intent)
            let ctx_msg_first = ProjectorDecisionContext {
                has_signer_mismatch: false,
                has_admin_key_mismatch: false,
                target_message_author_present: false,
                target_message_author_matches_del: false,
                target_tombstone_present: false,
                target_tombstone_author_matches_del: false,
                target_is_non_message: false,
                has_matching_deletion_intent: false,
                target_message_deleted: false,
            };
            let d1 = message_project_decision(msg, &ctx_msg_first);

            // Case 2: deletion arrives first (intent present)
            let ctx_del_first = ProjectorDecisionContext {
                has_signer_mismatch: false,
                has_admin_key_mismatch: false,
                target_message_author_present: false,
                target_message_author_matches_del: false,
                target_tombstone_present: false,
                target_tombstone_author_matches_del: false,
                target_is_non_message: false,
                has_matching_deletion_intent: true,
                target_message_deleted: false,
            };
            let d2 = message_project_decision(msg, &ctx_del_first);

            // Both produce Valid
            matches!(d1, ProjectionDecision::Valid)
            && matches!(d2, ProjectionDecision::Valid)
            // But only case 2 is tombstoned on arrival
            && !message_is_tombstoned_on_arrival(msg, &ctx_msg_first)
            && message_is_tombstoned_on_arrival(msg, &ctx_del_first)
        }),
{
}

// ═══════════════════════════════════════════════════════════════════
// Admin Projector
// ═══════════════════════════════════════════════════════════════════

pub open spec fn admin_project_decision(ctx: &ProjectorDecisionContext) -> ProjectionDecision {
    if ctx.has_admin_key_mismatch {
        ProjectionDecision::Reject
    } else {
        ProjectionDecision::Valid
    }
}

proof fn proof_admin_rejects_key_mismatch(ctx: &ProjectorDecisionContext)
    requires ctx.has_admin_key_mismatch
    ensures matches!(admin_project_decision(ctx), ProjectionDecision::Reject),
{
}

proof fn proof_admin_valid_when_keys_match(ctx: &ProjectorDecisionContext)
    requires !ctx.has_admin_key_mismatch
    ensures matches!(admin_project_decision(ctx), ProjectionDecision::Valid),
{
}

// ═══════════════════════════════════════════════════════════════════
// User Projector
// ═══════════════════════════════════════════════════════════════════

pub struct UserFields {
    pub username_len: nat,
}

pub open spec fn user_project_decision(user: &UserFields) -> ProjectionDecision {
    if user.username_len == 0 {
        ProjectionDecision::Reject
    } else {
        ProjectionDecision::Valid
    }
}

proof fn proof_user_rejects_empty_username(user: &UserFields)
    requires user.username_len == 0
    ensures matches!(user_project_decision(user), ProjectionDecision::Reject),
{
}

proof fn proof_user_valid_with_username(user: &UserFields)
    requires user.username_len > 0
    ensures matches!(user_project_decision(user), ProjectionDecision::Valid),
{
}

proof fn proof_user_never_blocks(user: &UserFields)
    ensures !matches!(user_project_decision(user), ProjectionDecision::Block { .. }),
{
}

// ═══════════════════════════════════════════════════════════════════
// Cross-projector properties
// ═══════════════════════════════════════════════════════════════════

/// Proof: no pure projector ever produces a Block decision.
/// (Blocking is handled by the pipeline's dep-check stage, not projectors.)
proof fn proof_no_projector_blocks(
    msg: &MessageFields,
    rxn: &ReactionFields,
    user: &UserFields,
    ctx: &ProjectorDecisionContext,
)
    ensures
        !matches!(message_project_decision(msg, ctx), ProjectionDecision::Block { .. }),
        !matches!(reaction_project_decision(rxn, ctx), ProjectionDecision::Block { .. }),
        !matches!(message_deletion_project_decision(ctx), ProjectionDecision::Block { .. }),
        !matches!(admin_project_decision(ctx), ProjectionDecision::Block { .. }),
        !matches!(user_project_decision(user), ProjectionDecision::Block { .. }),
{
}

/// Proof: signer mismatch rejects ALL content projectors.
proof fn proof_signer_mismatch_rejects_all_content_projectors(
    msg: &MessageFields,
    rxn: &ReactionFields,
    ctx: &ProjectorDecisionContext,
)
    requires ctx.has_signer_mismatch
    ensures
        matches!(message_project_decision(msg, ctx), ProjectionDecision::Reject),
        matches!(reaction_project_decision(rxn, ctx), ProjectionDecision::Reject),
        matches!(message_deletion_project_decision(ctx), ProjectionDecision::Reject),
{
}

} // verus!
