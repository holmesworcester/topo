//! Formal verification of dispatch and side-effect execution policy.

use vstd::prelude::*;
use crate::decision::*;
use crate::contract::*;

verus! {

/// Transport privacy requirements.
pub enum TransportPrivacy {
    RequireEncrypted,
    PlaintextOnly,
    Either,
}

/// Signer verification result.
pub enum SignerResolution {
    Found,
    NotFound,
    Invalid,
}

/// Transport privacy check.
pub open spec fn check_transport_privacy(
    privacy: &TransportPrivacy,
    is_encrypted: bool,
) -> bool {
    match privacy {
        TransportPrivacy::RequireEncrypted => is_encrypted,
        TransportPrivacy::PlaintextOnly => !is_encrypted,
        TransportPrivacy::Either => true,
    }
}

/// Full apply_projection pipeline model.
pub open spec fn apply_projection_model(
    type_known: bool,
    transport_privacy_ok: bool,
    signer_required: bool,
    signer_resolution: SignerResolution,
    signature_valid: bool,
    projector_decision: ProjectionDecision,
) -> ProjectionDecision {
    if !type_known {
        ProjectionDecision::Reject
    } else if !transport_privacy_ok {
        ProjectionDecision::Reject
    } else if signer_required {
        match signer_resolution {
            SignerResolution::NotFound => ProjectionDecision::Reject,
            SignerResolution::Invalid => ProjectionDecision::Reject,
            SignerResolution::Found => {
                if !signature_valid {
                    ProjectionDecision::Reject
                } else {
                    projector_decision
                }
            },
        }
    } else {
        projector_decision
    }
}

// ═══════════════════════════════════════════════════════════════════
// Dispatch Proofs
// ═══════════════════════════════════════════════════════════════════

proof fn proof_unknown_type_code_rejected()
    ensures matches!(
        apply_projection_model(false, true, false, SignerResolution::Found, true, ProjectionDecision::Valid),
        ProjectionDecision::Reject
    ),
{
}

proof fn proof_transport_privacy_violation_rejected()
    ensures matches!(
        apply_projection_model(true, false, false, SignerResolution::Found, true, ProjectionDecision::Valid),
        ProjectionDecision::Reject
    ),
{
}

proof fn proof_missing_signer_rejected()
    ensures matches!(
        apply_projection_model(true, true, true, SignerResolution::NotFound, true, ProjectionDecision::Valid),
        ProjectionDecision::Reject
    ),
{
}

proof fn proof_invalid_signer_rejected()
    ensures matches!(
        apply_projection_model(true, true, true, SignerResolution::Invalid, true, ProjectionDecision::Valid),
        ProjectionDecision::Reject
    ),
{
}

proof fn proof_invalid_signature_rejected()
    ensures matches!(
        apply_projection_model(true, true, true, SignerResolution::Found, false, ProjectionDecision::Valid),
        ProjectionDecision::Reject
    ),
{
}

/// When all checks pass (no signer required), the projector's decision is returned.
proof fn proof_valid_pipeline_returns_projector_decision(d: ProjectionDecision)
    ensures
        apply_projection_model(true, true, false, SignerResolution::Found, true, d) == d,
{
}

/// When all checks pass (with valid signer), the projector's decision is returned.
proof fn proof_valid_signed_pipeline_returns_projector_decision(d: ProjectionDecision)
    ensures
        apply_projection_model(true, true, true, SignerResolution::Found, true, d) == d,
{
}

/// Unknown type always rejects regardless of other parameters.
proof fn proof_unknown_type_always_rejects_concrete_cases()
    ensures
        matches!(apply_projection_model(false, true, true, SignerResolution::Found, true, ProjectionDecision::Valid), ProjectionDecision::Reject),
        matches!(apply_projection_model(false, false, false, SignerResolution::NotFound, false, ProjectionDecision::Valid), ProjectionDecision::Reject),
        matches!(apply_projection_model(false, true, false, SignerResolution::Found, true, ProjectionDecision::AlreadyProcessed), ProjectionDecision::Reject),
{
}

/// Transport privacy failure always rejects when type is known.
proof fn proof_privacy_failure_always_rejects_concrete_cases()
    ensures
        matches!(apply_projection_model(true, false, true, SignerResolution::Found, true, ProjectionDecision::Valid), ProjectionDecision::Reject),
        matches!(apply_projection_model(true, false, false, SignerResolution::NotFound, false, ProjectionDecision::Valid), ProjectionDecision::Reject),
{
}

// ═══════════════════════════════════════════════════════════════════
// Side-Effect Execution Policy
// ═══════════════════════════════════════════════════════════════════

/// Model of what the apply engine does: (writes_executed, commands_executed).
pub open spec fn apply_engine_executes(
    decision: &ProjectionDecision,
) -> (bool, bool) {
    match decision {
        ProjectionDecision::Valid => (true, true),
        ProjectionDecision::Block { .. } => (false, true),
        ProjectionDecision::Reject => (false, false),
        ProjectionDecision::AlreadyProcessed => (false, false),
    }
}

proof fn proof_no_spurious_writes(decision: &ProjectionDecision)
    requires !matches!(*decision, ProjectionDecision::Valid)
    ensures !apply_engine_executes(decision).0,
{
}

proof fn proof_inert_decisions_execute_nothing(decision: &ProjectionDecision)
    requires forbids_all_effects(decision)
    ensures
        ({
            let (w, c) = apply_engine_executes(decision);
            !w && !c
        }),
{
}

proof fn proof_valid_executes_both(decision: &ProjectionDecision)
    requires matches!(*decision, ProjectionDecision::Valid)
    ensures
        ({
            let (w, c) = apply_engine_executes(decision);
            w && c
        }),
{
}

proof fn proof_block_executes_only_commands(decision: &ProjectionDecision)
    requires matches!(*decision, ProjectionDecision::Block { .. })
    ensures
        ({
            let (w, c) = apply_engine_executes(decision);
            !w && c
        }),
{
}

// ═══════════════════════════════════════════════════════════════════
// Transport Privacy Proofs
// ═══════════════════════════════════════════════════════════════════

proof fn proof_require_encrypted_needs_encryption()
    ensures
        check_transport_privacy(&TransportPrivacy::RequireEncrypted, true),
        !check_transport_privacy(&TransportPrivacy::RequireEncrypted, false),
{
}

proof fn proof_plaintext_only_rejects_encryption()
    ensures
        check_transport_privacy(&TransportPrivacy::PlaintextOnly, false),
        !check_transport_privacy(&TransportPrivacy::PlaintextOnly, true),
{
}

proof fn proof_either_always_passes(is_encrypted: bool)
    ensures check_transport_privacy(&TransportPrivacy::Either, is_encrypted),
{
}

} // verus!
