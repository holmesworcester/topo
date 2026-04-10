//! Formal verification of command/wire validation input normalization.
//!
//! This models the first event-pipeline seam:
//! external command or wire input becomes raw typed validation state, then a
//! normalized `DecisionContext`, then a bounded pipeline plan.

use vstd::prelude::*;

verus! {

pub enum ValidationSource {
    Command,
    Wire,
    Replay,
}

pub enum RawValidationInput {
    MissingBlob,
    ParseFailed,
    Parsed {
        source: ValidationSource,
        known_type: bool,
        signer_required: bool,
        signer_present: bool,
        deps_well_formed: bool,
    },
}

pub enum ValidationDecisionContext {
    RejectMissingBlob,
    RejectParse,
    RejectUnknownType,
    RejectMissingSigner,
    RejectMalformedDeps,
    Ready {
        signer_required: bool,
        signer_present: bool,
    },
}

pub enum ValidationPlan {
    Reject,
    ContinueToProjection,
}

pub open spec fn normalize_validation_input(
    input: RawValidationInput,
) -> ValidationDecisionContext {
    match input {
        RawValidationInput::MissingBlob => ValidationDecisionContext::RejectMissingBlob,
        RawValidationInput::ParseFailed => ValidationDecisionContext::RejectParse,
        RawValidationInput::Parsed {
            source: _source,
            known_type,
            signer_required,
            signer_present,
            deps_well_formed,
        } => {
            if !known_type {
                ValidationDecisionContext::RejectUnknownType
            } else if signer_required && !signer_present {
                ValidationDecisionContext::RejectMissingSigner
            } else if !deps_well_formed {
                ValidationDecisionContext::RejectMalformedDeps
            } else {
                ValidationDecisionContext::Ready {
                    signer_required,
                    signer_present,
                }
            }
        }
    }
}

pub open spec fn decide_validation_plan(
    context: ValidationDecisionContext,
) -> ValidationPlan {
    match context {
        ValidationDecisionContext::Ready { .. } => ValidationPlan::ContinueToProjection,
        _ => ValidationPlan::Reject,
    }
}

proof fn missing_blob_rejects()
    ensures
        decide_validation_plan(normalize_validation_input(RawValidationInput::MissingBlob))
            == ValidationPlan::Reject,
{
}

proof fn parse_failure_rejects()
    ensures
        decide_validation_plan(normalize_validation_input(RawValidationInput::ParseFailed))
            == ValidationPlan::Reject,
{
}

proof fn unknown_type_rejects()
    ensures
        decide_validation_plan(normalize_validation_input(RawValidationInput::Parsed {
            source: ValidationSource::Wire,
            known_type: false,
            signer_required: false,
            signer_present: false,
            deps_well_formed: true,
        })) == ValidationPlan::Reject,
{
}

proof fn missing_required_signer_rejects()
    ensures
        decide_validation_plan(normalize_validation_input(RawValidationInput::Parsed {
            source: ValidationSource::Wire,
            known_type: true,
            signer_required: true,
            signer_present: false,
            deps_well_formed: true,
        })) == ValidationPlan::Reject,
{
}

proof fn malformed_deps_reject()
    ensures
        decide_validation_plan(normalize_validation_input(RawValidationInput::Parsed {
            source: ValidationSource::Wire,
            known_type: true,
            signer_required: false,
            signer_present: false,
            deps_well_formed: false,
        })) == ValidationPlan::Reject,
{
}

proof fn well_formed_known_input_continues(signer_required: bool, signer_present: bool)
    requires signer_required ==> signer_present
    ensures
        decide_validation_plan(normalize_validation_input(RawValidationInput::Parsed {
            source: ValidationSource::Command,
            known_type: true,
            signer_required,
            signer_present,
            deps_well_formed: true,
        })) == ValidationPlan::ContinueToProjection,
{
}

proof fn validation_plan_is_source_noninterfering(
    signer_required: bool,
    signer_present: bool,
    deps_well_formed: bool,
)
    ensures
        decide_validation_plan(normalize_validation_input(RawValidationInput::Parsed {
            source: ValidationSource::Command,
            known_type: true,
            signer_required,
            signer_present,
            deps_well_formed,
        })) == decide_validation_plan(normalize_validation_input(RawValidationInput::Parsed {
            source: ValidationSource::Wire,
            known_type: true,
            signer_required,
            signer_present,
            deps_well_formed,
        })),
{
}

} // verus!
