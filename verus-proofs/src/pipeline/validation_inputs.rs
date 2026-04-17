//! **Abstract specification — not grounded in runtime code.**
//!
//! Per `docs/planning/FORMAL_SEAM_COVERAGE.md`, this file encodes system-level
//! invariants that no single runtime function body satisfies on its own. The
//! SMT solver accepts the proofs inside this file, but they are NOT proofs about
//! runtime code — the grounded verification lives in the per-seam `ensures`
//! clauses on executable `pub fn`s in sibling modules. Do not treat entries
//! here as "the runtime is proven to satisfy X"; treat them as "X is modeled
//! in Verus and consistent with itself".
//!
//! Formal verification of persist-phase ingress validation normalization.
//!
//! This models the runtime boundary in `state::pipeline::phases`: cheap
//! prefix/type validation becomes raw typed validation state, then a normalized
//! `DecisionContext`, then a bounded persist-phase plan. Full dependency and
//! signer authority validation remains in projection-context seams.

use vstd::prelude::*;

verus! {

pub enum ValidationSource {
    Command,
    Wire,
    Replay,
}

pub enum RawValidationInput {
    MissingCreatedAt { source: ValidationSource },
    MissingTypeCode { source: ValidationSource },
    UnknownType { source: ValidationSource },
    KnownType { source: ValidationSource },
}

pub enum ValidationDecisionContext {
    RejectMissingCreatedAt,
    RejectMissingTypeCode,
    RejectUnknownType,
    Ready,
}

pub enum ValidationPlan {
    Reject,
    ContinueToPersist,
}

pub open spec fn raw_validation_input(
    source: ValidationSource,
    has_created_at: bool,
    has_type_code: bool,
    known_type: bool,
) -> RawValidationInput {
    if !has_created_at {
        RawValidationInput::MissingCreatedAt { source }
    } else if !has_type_code {
        RawValidationInput::MissingTypeCode { source }
    } else if !known_type {
        RawValidationInput::UnknownType { source }
    } else {
        RawValidationInput::KnownType { source }
    }
}

pub open spec fn normalize_validation_input(
    input: RawValidationInput,
) -> ValidationDecisionContext {
    match input {
        RawValidationInput::MissingCreatedAt { source: _ } => {
            ValidationDecisionContext::RejectMissingCreatedAt
        }
        RawValidationInput::MissingTypeCode { source: _ } => {
            ValidationDecisionContext::RejectMissingTypeCode
        }
        RawValidationInput::UnknownType { source: _ } => {
            ValidationDecisionContext::RejectUnknownType
        }
        RawValidationInput::KnownType { source: _ } => ValidationDecisionContext::Ready,
    }
}

pub open spec fn decide_validation_plan(
    context: ValidationDecisionContext,
) -> ValidationPlan {
    match context {
        ValidationDecisionContext::Ready => ValidationPlan::ContinueToPersist,
        ValidationDecisionContext::RejectMissingCreatedAt
        | ValidationDecisionContext::RejectMissingTypeCode
        | ValidationDecisionContext::RejectUnknownType => ValidationPlan::Reject,
    }
}

proof fn missing_created_at_rejects(source: ValidationSource)
    ensures
        decide_validation_plan(normalize_validation_input(
            RawValidationInput::MissingCreatedAt { source },
        )) == ValidationPlan::Reject,
{
}

proof fn missing_type_code_rejects(source: ValidationSource)
    ensures
        decide_validation_plan(normalize_validation_input(
            RawValidationInput::MissingTypeCode { source },
        )) == ValidationPlan::Reject,
{
}

proof fn unknown_type_rejects(source: ValidationSource)
    ensures
        decide_validation_plan(normalize_validation_input(
            RawValidationInput::UnknownType { source },
        )) == ValidationPlan::Reject,
{
}

proof fn known_type_continues(source: ValidationSource)
    ensures
        decide_validation_plan(normalize_validation_input(
            RawValidationInput::KnownType { source },
        )) == ValidationPlan::ContinueToPersist,
{
}

proof fn validation_plan_is_source_noninterfering(
    has_created_at: bool,
    has_type_code: bool,
    known_type: bool,
)
    ensures
        decide_validation_plan(normalize_validation_input(raw_validation_input(
            ValidationSource::Command,
            has_created_at,
            has_type_code,
            known_type,
        ))) == decide_validation_plan(normalize_validation_input(raw_validation_input(
            ValidationSource::Wire,
            has_created_at,
            has_type_code,
            known_type,
        ))),
{
}

proof fn missing_created_at_rejects_regardless_of_later_fields(
    source: ValidationSource,
    has_type_code: bool,
    known_type: bool,
)
    ensures
        decide_validation_plan(normalize_validation_input(raw_validation_input(
            source,
            false,
            has_type_code,
            known_type,
        ))) == ValidationPlan::Reject,
{
}

proof fn missing_type_code_rejects_regardless_of_known_type(
    source: ValidationSource,
    known_type: bool,
)
    ensures
        decide_validation_plan(normalize_validation_input(raw_validation_input(
            source,
            true,
            false,
            known_type,
        ))) == ValidationPlan::Reject,
{
}

proof fn known_type_builder_continues(source: ValidationSource)
    ensures
        decide_validation_plan(normalize_validation_input(raw_validation_input(
            source,
            true,
            true,
            true,
        ))) == ValidationPlan::ContinueToPersist,
{
}

} // verus!
