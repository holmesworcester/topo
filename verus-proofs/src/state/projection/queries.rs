//! Formal verification of projection query normalization seams.
//!
//! This models the boundary between raw typed SQL rows and the normalized
//! `DecisionContext` consumed by projector/context-load planners.

use vstd::prelude::*;

verus! {

pub enum WorkspaceAcceptedRows {
    Missing,
    Unique { workspace_matches_event: bool },
    Ambiguous,
    Malformed,
}

pub enum WorkspaceDecisionContext {
    MissingAcceptedWorkspace,
    UniqueAcceptedWorkspace { workspace_matches_event: bool },
    RejectAmbiguousAcceptedWorkspace,
    RejectMalformedAcceptedWorkspace,
}

pub enum WorkspaceContextPlan {
    BlockOnAcceptedWorkspace,
    Ready,
    Reject,
}

pub open spec fn normalize_workspace_acceptance(
    rows: WorkspaceAcceptedRows,
) -> WorkspaceDecisionContext {
    match rows {
        WorkspaceAcceptedRows::Missing => {
            WorkspaceDecisionContext::MissingAcceptedWorkspace
        }
        WorkspaceAcceptedRows::Unique { workspace_matches_event } => {
            WorkspaceDecisionContext::UniqueAcceptedWorkspace {
                workspace_matches_event,
            }
        }
        WorkspaceAcceptedRows::Ambiguous => {
            WorkspaceDecisionContext::RejectAmbiguousAcceptedWorkspace
        }
        WorkspaceAcceptedRows::Malformed => {
            WorkspaceDecisionContext::RejectMalformedAcceptedWorkspace
        }
    }
}

pub open spec fn decide_workspace_context_plan(
    context: WorkspaceDecisionContext,
) -> WorkspaceContextPlan {
    match context {
        WorkspaceDecisionContext::MissingAcceptedWorkspace => {
            WorkspaceContextPlan::BlockOnAcceptedWorkspace
        }
        WorkspaceDecisionContext::UniqueAcceptedWorkspace { workspace_matches_event } => {
            if workspace_matches_event {
                WorkspaceContextPlan::Ready
            } else {
                WorkspaceContextPlan::Reject
            }
        }
        WorkspaceDecisionContext::RejectAmbiguousAcceptedWorkspace
        | WorkspaceDecisionContext::RejectMalformedAcceptedWorkspace => {
            WorkspaceContextPlan::Reject
        }
    }
}

proof fn workspace_query_missing_blocks()
    ensures
        decide_workspace_context_plan(normalize_workspace_acceptance(
            WorkspaceAcceptedRows::Missing,
        )) == WorkspaceContextPlan::BlockOnAcceptedWorkspace,
{
}

proof fn workspace_query_unique_match_is_ready()
    ensures
        decide_workspace_context_plan(normalize_workspace_acceptance(
            WorkspaceAcceptedRows::Unique { workspace_matches_event: true },
        )) == WorkspaceContextPlan::Ready,
{
}

proof fn workspace_query_unique_mismatch_rejects()
    ensures
        decide_workspace_context_plan(normalize_workspace_acceptance(
            WorkspaceAcceptedRows::Unique { workspace_matches_event: false },
        )) == WorkspaceContextPlan::Reject,
{
}

proof fn workspace_query_ambiguity_fails_closed()
    ensures
        decide_workspace_context_plan(normalize_workspace_acceptance(
            WorkspaceAcceptedRows::Ambiguous,
        )) == WorkspaceContextPlan::Reject,
{
}

proof fn workspace_query_malformation_fails_closed()
    ensures
        decide_workspace_context_plan(normalize_workspace_acceptance(
            WorkspaceAcceptedRows::Malformed,
        )) == WorkspaceContextPlan::Reject,
{
}

pub enum SignerUserRows {
    NoAuthorCheckNeeded,
    MissingCurrentSigner,
    UnsupportedSignerType,
    Unique { signer_matches_author: bool },
    MissingSignerUser,
    AmbiguousSignerUser,
    Malformed,
}

pub enum ContentAuthorityDecisionContext {
    NoAuthorCheckNeeded,
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType,
    UniqueSignerUser { signer_matches_author: bool },
    RejectMissingSignerUser,
    RejectAmbiguousSignerUser,
    RejectMalformedSignerUser,
}

pub enum ContentAuthorityPlan {
    Ready,
    Reject,
}

pub open spec fn normalize_content_authority(
    rows: SignerUserRows,
) -> ContentAuthorityDecisionContext {
    match rows {
        SignerUserRows::NoAuthorCheckNeeded => {
            ContentAuthorityDecisionContext::NoAuthorCheckNeeded
        }
        SignerUserRows::MissingCurrentSigner => {
            ContentAuthorityDecisionContext::RejectMissingCurrentSigner
        }
        SignerUserRows::UnsupportedSignerType => {
            ContentAuthorityDecisionContext::RejectUnsupportedSignerType
        }
        SignerUserRows::Unique { signer_matches_author } => {
            ContentAuthorityDecisionContext::UniqueSignerUser {
                signer_matches_author,
            }
        }
        SignerUserRows::MissingSignerUser => {
            ContentAuthorityDecisionContext::RejectMissingSignerUser
        }
        SignerUserRows::AmbiguousSignerUser => {
            ContentAuthorityDecisionContext::RejectAmbiguousSignerUser
        }
        SignerUserRows::Malformed => {
            ContentAuthorityDecisionContext::RejectMalformedSignerUser
        }
    }
}

pub open spec fn decide_content_authority_plan(
    context: ContentAuthorityDecisionContext,
) -> ContentAuthorityPlan {
    match context {
        ContentAuthorityDecisionContext::NoAuthorCheckNeeded => ContentAuthorityPlan::Ready,
        ContentAuthorityDecisionContext::UniqueSignerUser { signer_matches_author } => {
            if signer_matches_author {
                ContentAuthorityPlan::Ready
            } else {
                ContentAuthorityPlan::Reject
            }
        }
        ContentAuthorityDecisionContext::RejectMissingCurrentSigner
        | ContentAuthorityDecisionContext::RejectUnsupportedSignerType
        | ContentAuthorityDecisionContext::RejectMissingSignerUser
        | ContentAuthorityDecisionContext::RejectAmbiguousSignerUser
        | ContentAuthorityDecisionContext::RejectMalformedSignerUser => {
            ContentAuthorityPlan::Reject
        }
    }
}

proof fn content_authority_missing_current_signer_rejects()
    ensures
        decide_content_authority_plan(normalize_content_authority(
            SignerUserRows::MissingCurrentSigner,
        )) == ContentAuthorityPlan::Reject,
{
}

proof fn content_authority_unsupported_signer_type_rejects()
    ensures
        decide_content_authority_plan(normalize_content_authority(
            SignerUserRows::UnsupportedSignerType,
        )) == ContentAuthorityPlan::Reject,
{
}

proof fn content_authority_unique_match_is_ready()
    ensures
        decide_content_authority_plan(normalize_content_authority(
            SignerUserRows::Unique { signer_matches_author: true },
        )) == ContentAuthorityPlan::Ready,
{
}

proof fn content_authority_unique_mismatch_rejects()
    ensures
        decide_content_authority_plan(normalize_content_authority(
            SignerUserRows::Unique { signer_matches_author: false },
        )) == ContentAuthorityPlan::Reject,
{
}

proof fn content_authority_ambiguity_fails_closed()
    ensures
        decide_content_authority_plan(normalize_content_authority(
            SignerUserRows::AmbiguousSignerUser,
        )) == ContentAuthorityPlan::Reject,
{
}

proof fn content_authority_malformation_fails_closed()
    ensures
        decide_content_authority_plan(normalize_content_authority(SignerUserRows::Malformed))
            == ContentAuthorityPlan::Reject,
{
}

pub enum SemanticTypeRows {
    Missing,
    UniqueKnown { code_in_range: bool, allowed_by_dep_field: bool },
    Ambiguous,
    Malformed,
}

pub enum SemanticTypeDecisionContext {
    Missing,
    UniqueAllowed,
    RejectWrongType,
    RejectOutOfRange,
    RejectAmbiguous,
    RejectMalformed,
}

pub enum SemanticTypePlan {
    DepMissing,
    DepReady,
    Reject,
}

pub open spec fn normalize_semantic_type(
    rows: SemanticTypeRows,
) -> SemanticTypeDecisionContext {
    match rows {
        SemanticTypeRows::Missing => SemanticTypeDecisionContext::Missing,
        SemanticTypeRows::UniqueKnown { code_in_range, allowed_by_dep_field } => {
            if !code_in_range {
                SemanticTypeDecisionContext::RejectOutOfRange
            } else if allowed_by_dep_field {
                SemanticTypeDecisionContext::UniqueAllowed
            } else {
                SemanticTypeDecisionContext::RejectWrongType
            }
        }
        SemanticTypeRows::Ambiguous => SemanticTypeDecisionContext::RejectAmbiguous,
        SemanticTypeRows::Malformed => SemanticTypeDecisionContext::RejectMalformed,
    }
}

pub open spec fn decide_semantic_type_plan(
    context: SemanticTypeDecisionContext,
) -> SemanticTypePlan {
    match context {
        SemanticTypeDecisionContext::Missing => SemanticTypePlan::DepMissing,
        SemanticTypeDecisionContext::UniqueAllowed => SemanticTypePlan::DepReady,
        SemanticTypeDecisionContext::RejectWrongType
        | SemanticTypeDecisionContext::RejectOutOfRange
        | SemanticTypeDecisionContext::RejectAmbiguous
        | SemanticTypeDecisionContext::RejectMalformed => SemanticTypePlan::Reject,
    }
}

proof fn semantic_type_allowed_is_ready()
    ensures
        decide_semantic_type_plan(normalize_semantic_type(SemanticTypeRows::UniqueKnown {
            code_in_range: true,
            allowed_by_dep_field: true,
        })) == SemanticTypePlan::DepReady,
{
}

proof fn semantic_type_wrong_type_rejects()
    ensures
        decide_semantic_type_plan(normalize_semantic_type(SemanticTypeRows::UniqueKnown {
            code_in_range: true,
            allowed_by_dep_field: false,
        })) == SemanticTypePlan::Reject,
{
}

proof fn semantic_type_out_of_range_rejects()
    ensures
        decide_semantic_type_plan(normalize_semantic_type(SemanticTypeRows::UniqueKnown {
            code_in_range: false,
            allowed_by_dep_field: true,
        })) == SemanticTypePlan::Reject,
{
}

proof fn semantic_type_malformed_rows_reject()
    ensures
        decide_semantic_type_plan(normalize_semantic_type(SemanticTypeRows::Malformed))
            == SemanticTypePlan::Reject,
{
}

} // verus!
