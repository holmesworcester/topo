//! Persist-phase ingress validation — verified on real bytes.
//!
//! Runtime `run_persist_phase` rejects blobs that lack a type byte or a created_at
//! prefix, and accepts only blobs whose type byte the event registry recognizes.
//! This file provides the verified primitives that implement that validation:
//! a byte-prefix extractor (`extract_event_type`) and the normalizer/planner pair
//! for `PersistValidation*`.
//!
//! The extractor's `ensures` clause ties the return value to the first blob byte
//! (`Some(blob[0])` when non-empty, `None` when empty). The planner's ensures
//! clause fixes the rejection policy per RawRows variant.

use vstd::prelude::*;

verus! {

/// Extract the event_type byte from the first position of a blob.
/// The verified ensures ties the return value directly to `blob[0]` so any drift
/// between the documented "first byte = event type" convention and the runtime
/// implementation fails SMT.
pub fn extract_event_type(blob: &[u8]) -> (out: Option<u8>)
    ensures
        blob.len() == 0 ==> out.is_none(),
        blob.len() > 0 ==> out == Some(blob[0]),
{
    if blob.len() == 0 {
        None
    } else {
        Some(blob[0])
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistValidationRawRows {
    MissingCreatedAt,
    MissingTypeCode,
    UnknownType { type_code: u8 },
    KnownType { created_at_ms: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistValidationDecisionContext {
    RejectMissingCreatedAt,
    RejectMissingTypeCode,
    RejectUnknownType,
    Ready { created_at_ms: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistValidationPlan {
    Skip,
    Continue { created_at_ms: u64 },
}

pub fn normalize_persist_validation(
    raw_rows: PersistValidationRawRows,
) -> (context: PersistValidationDecisionContext)
    ensures
        match raw_rows {
            PersistValidationRawRows::MissingCreatedAt =>
                context == PersistValidationDecisionContext::RejectMissingCreatedAt,
            PersistValidationRawRows::MissingTypeCode =>
                context == PersistValidationDecisionContext::RejectMissingTypeCode,
            PersistValidationRawRows::UnknownType { .. } =>
                context == PersistValidationDecisionContext::RejectUnknownType,
            PersistValidationRawRows::KnownType { created_at_ms } =>
                context == (PersistValidationDecisionContext::Ready { created_at_ms }),
        },
{
    match raw_rows {
        PersistValidationRawRows::MissingCreatedAt =>
            PersistValidationDecisionContext::RejectMissingCreatedAt,
        PersistValidationRawRows::MissingTypeCode =>
            PersistValidationDecisionContext::RejectMissingTypeCode,
        PersistValidationRawRows::UnknownType { .. } =>
            PersistValidationDecisionContext::RejectUnknownType,
        PersistValidationRawRows::KnownType { created_at_ms } =>
            PersistValidationDecisionContext::Ready { created_at_ms },
    }
}

pub fn decide_persist_validation_plan(
    context: &PersistValidationDecisionContext,
) -> (plan: PersistValidationPlan)
    ensures
        match context {
            PersistValidationDecisionContext::Ready { created_at_ms } =>
                plan == (PersistValidationPlan::Continue { created_at_ms: *created_at_ms }),
            PersistValidationDecisionContext::RejectMissingCreatedAt
            | PersistValidationDecisionContext::RejectMissingTypeCode
            | PersistValidationDecisionContext::RejectUnknownType =>
                plan == PersistValidationPlan::Skip,
        },
{
    match context {
        PersistValidationDecisionContext::Ready { created_at_ms } =>
            PersistValidationPlan::Continue { created_at_ms: *created_at_ms },
        PersistValidationDecisionContext::RejectMissingCreatedAt
        | PersistValidationDecisionContext::RejectMissingTypeCode
        | PersistValidationDecisionContext::RejectUnknownType =>
            PersistValidationPlan::Skip,
    }
}

} // verus!
