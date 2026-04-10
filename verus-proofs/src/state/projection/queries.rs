//! Formal verification of projection query normalization seams.
//!
//! This models the boundary between raw typed SQL rows and the normalized
//! `DecisionContext` consumed by projector/context-load planners.

use vstd::prelude::*;

verus! {

pub struct WorkspaceAcceptedRawRows {
    pub row_count: nat,
    pub all_workspace_ids_equal: bool,
    pub representative_workspace_matches_event: bool,
    pub malformed: bool,
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
    rows: WorkspaceAcceptedRawRows,
) -> WorkspaceDecisionContext {
    if rows.malformed {
        WorkspaceDecisionContext::RejectMalformedAcceptedWorkspace
    } else if rows.row_count == 0 {
        WorkspaceDecisionContext::MissingAcceptedWorkspace
    } else if rows.all_workspace_ids_equal {
        WorkspaceDecisionContext::UniqueAcceptedWorkspace {
            workspace_matches_event: rows.representative_workspace_matches_event,
        }
    } else {
        WorkspaceDecisionContext::RejectAmbiguousAcceptedWorkspace
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
            WorkspaceAcceptedRawRows {
                row_count: 0,
                all_workspace_ids_equal: true,
                representative_workspace_matches_event: false,
                malformed: false,
            },
        )) == WorkspaceContextPlan::BlockOnAcceptedWorkspace,
{
}

proof fn workspace_query_unique_match_is_ready()
    ensures
        decide_workspace_context_plan(normalize_workspace_acceptance(
            WorkspaceAcceptedRawRows {
                row_count: 1,
                all_workspace_ids_equal: true,
                representative_workspace_matches_event: true,
                malformed: false,
            },
        )) == WorkspaceContextPlan::Ready,
{
}

proof fn workspace_query_duplicate_same_workspace_rows_are_noninterfering(
    row_count_a: nat,
    row_count_b: nat,
    workspace_matches_event: bool,
)
    requires
        row_count_a > 0,
        row_count_b > 0,
    ensures
        decide_workspace_context_plan(normalize_workspace_acceptance(
            WorkspaceAcceptedRawRows {
                row_count: row_count_a,
                all_workspace_ids_equal: true,
                representative_workspace_matches_event: workspace_matches_event,
                malformed: false,
            },
        )) == decide_workspace_context_plan(normalize_workspace_acceptance(
            WorkspaceAcceptedRawRows {
                row_count: row_count_b,
                all_workspace_ids_equal: true,
                representative_workspace_matches_event: workspace_matches_event,
                malformed: false,
            },
        )),
{
}

proof fn workspace_query_unique_mismatch_rejects()
    ensures
        decide_workspace_context_plan(normalize_workspace_acceptance(
            WorkspaceAcceptedRawRows {
                row_count: 1,
                all_workspace_ids_equal: true,
                representative_workspace_matches_event: false,
                malformed: false,
            },
        )) == WorkspaceContextPlan::Reject,
{
}

proof fn workspace_query_ambiguity_fails_closed()
    ensures
        decide_workspace_context_plan(normalize_workspace_acceptance(
            WorkspaceAcceptedRawRows {
                row_count: 2,
                all_workspace_ids_equal: false,
                representative_workspace_matches_event: true,
                malformed: false,
            },
        )) == WorkspaceContextPlan::Reject,
{
}

proof fn workspace_query_malformation_fails_closed()
    ensures
        decide_workspace_context_plan(normalize_workspace_acceptance(
            WorkspaceAcceptedRawRows {
                row_count: 1,
                all_workspace_ids_equal: true,
                representative_workspace_matches_event: true,
                malformed: true,
            },
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

pub enum AdminAuthorityRows {
    MissingCurrentSigner,
    UnsupportedSignerType,
    UniqueUserKey { admin_key_matches_user_key: bool },
    MissingUser,
    AmbiguousUser,
    MalformedUserKey,
}

pub enum AdminAuthorityDecisionContext {
    UniqueUserKey { admin_key_matches_user_key: bool },
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType,
    RejectMissingUser,
    RejectAmbiguousUser,
    RejectMalformedUserKey,
}

pub enum AdminAuthorityPlan {
    Ready,
    Reject,
}

pub open spec fn normalize_admin_authority(
    rows: AdminAuthorityRows,
) -> AdminAuthorityDecisionContext {
    match rows {
        AdminAuthorityRows::MissingCurrentSigner => {
            AdminAuthorityDecisionContext::RejectMissingCurrentSigner
        }
        AdminAuthorityRows::UnsupportedSignerType => {
            AdminAuthorityDecisionContext::RejectUnsupportedSignerType
        }
        AdminAuthorityRows::UniqueUserKey { admin_key_matches_user_key } => {
            AdminAuthorityDecisionContext::UniqueUserKey {
                admin_key_matches_user_key,
            }
        }
        AdminAuthorityRows::MissingUser => AdminAuthorityDecisionContext::RejectMissingUser,
        AdminAuthorityRows::AmbiguousUser => {
            AdminAuthorityDecisionContext::RejectAmbiguousUser
        }
        AdminAuthorityRows::MalformedUserKey => {
            AdminAuthorityDecisionContext::RejectMalformedUserKey
        }
    }
}

pub open spec fn decide_admin_authority_plan(
    context: AdminAuthorityDecisionContext,
) -> AdminAuthorityPlan {
    match context {
        AdminAuthorityDecisionContext::UniqueUserKey { admin_key_matches_user_key } => {
            if admin_key_matches_user_key {
                AdminAuthorityPlan::Ready
            } else {
                AdminAuthorityPlan::Reject
            }
        }
        AdminAuthorityDecisionContext::RejectMissingCurrentSigner
        | AdminAuthorityDecisionContext::RejectUnsupportedSignerType
        | AdminAuthorityDecisionContext::RejectMissingUser
        | AdminAuthorityDecisionContext::RejectAmbiguousUser
        | AdminAuthorityDecisionContext::RejectMalformedUserKey => {
            AdminAuthorityPlan::Reject
        }
    }
}

proof fn admin_authority_matching_key_is_ready()
    ensures
        decide_admin_authority_plan(normalize_admin_authority(
            AdminAuthorityRows::UniqueUserKey { admin_key_matches_user_key: true },
        )) == AdminAuthorityPlan::Ready,
{
}

proof fn admin_authority_key_mismatch_rejects()
    ensures
        decide_admin_authority_plan(normalize_admin_authority(
            AdminAuthorityRows::UniqueUserKey { admin_key_matches_user_key: false },
        )) == AdminAuthorityPlan::Reject,
{
}

proof fn admin_authority_missing_current_signer_rejects()
    ensures
        decide_admin_authority_plan(normalize_admin_authority(
            AdminAuthorityRows::MissingCurrentSigner,
        )) == AdminAuthorityPlan::Reject,
{
}

proof fn admin_authority_unsupported_signer_type_rejects()
    ensures
        decide_admin_authority_plan(normalize_admin_authority(
            AdminAuthorityRows::UnsupportedSignerType,
        )) == AdminAuthorityPlan::Reject,
{
}

proof fn admin_authority_missing_user_rejects()
    ensures
        decide_admin_authority_plan(normalize_admin_authority(
            AdminAuthorityRows::MissingUser,
        )) == AdminAuthorityPlan::Reject,
{
}

proof fn admin_authority_ambiguous_user_rejects()
    ensures
        decide_admin_authority_plan(normalize_admin_authority(
            AdminAuthorityRows::AmbiguousUser,
        )) == AdminAuthorityPlan::Reject,
{
}

proof fn admin_authority_malformed_user_key_rejects()
    ensures
        decide_admin_authority_plan(normalize_admin_authority(
            AdminAuthorityRows::MalformedUserKey,
        )) == AdminAuthorityPlan::Reject,
{
}

pub enum PeerSharedAuthorityRows {
    MissingCurrentSigner,
    UnsupportedSignerType,
    MissingDeviceInviteBlob,
    MalformedDeviceInvite,
    UniqueAuthorizedUser { claimed_user_matches_authorized_user: bool },
}

pub enum PeerSharedAuthorityDecisionContext {
    UniqueAuthorizedUser { claimed_user_matches_authorized_user: bool },
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType,
    RejectMissingDeviceInviteBlob,
    RejectMalformedDeviceInvite,
}

pub enum PeerSharedAuthorityPlan {
    Ready,
    Reject,
}

pub open spec fn normalize_peer_shared_authority(
    rows: PeerSharedAuthorityRows,
) -> PeerSharedAuthorityDecisionContext {
    match rows {
        PeerSharedAuthorityRows::MissingCurrentSigner => {
            PeerSharedAuthorityDecisionContext::RejectMissingCurrentSigner
        }
        PeerSharedAuthorityRows::UnsupportedSignerType => {
            PeerSharedAuthorityDecisionContext::RejectUnsupportedSignerType
        }
        PeerSharedAuthorityRows::MissingDeviceInviteBlob => {
            PeerSharedAuthorityDecisionContext::RejectMissingDeviceInviteBlob
        }
        PeerSharedAuthorityRows::MalformedDeviceInvite => {
            PeerSharedAuthorityDecisionContext::RejectMalformedDeviceInvite
        }
        PeerSharedAuthorityRows::UniqueAuthorizedUser {
            claimed_user_matches_authorized_user,
        } => PeerSharedAuthorityDecisionContext::UniqueAuthorizedUser {
            claimed_user_matches_authorized_user,
        },
    }
}

pub open spec fn decide_peer_shared_authority_plan(
    context: PeerSharedAuthorityDecisionContext,
) -> PeerSharedAuthorityPlan {
    match context {
        PeerSharedAuthorityDecisionContext::UniqueAuthorizedUser {
            claimed_user_matches_authorized_user,
        } => {
            if claimed_user_matches_authorized_user {
                PeerSharedAuthorityPlan::Ready
            } else {
                PeerSharedAuthorityPlan::Reject
            }
        }
        PeerSharedAuthorityDecisionContext::RejectMissingCurrentSigner
        | PeerSharedAuthorityDecisionContext::RejectUnsupportedSignerType
        | PeerSharedAuthorityDecisionContext::RejectMissingDeviceInviteBlob
        | PeerSharedAuthorityDecisionContext::RejectMalformedDeviceInvite => {
            PeerSharedAuthorityPlan::Reject
        }
    }
}

proof fn peer_shared_authority_matching_user_is_ready()
    ensures
        decide_peer_shared_authority_plan(normalize_peer_shared_authority(
            PeerSharedAuthorityRows::UniqueAuthorizedUser {
                claimed_user_matches_authorized_user: true,
            },
        )) == PeerSharedAuthorityPlan::Ready,
{
}

proof fn peer_shared_authority_user_mismatch_rejects()
    ensures
        decide_peer_shared_authority_plan(normalize_peer_shared_authority(
            PeerSharedAuthorityRows::UniqueAuthorizedUser {
                claimed_user_matches_authorized_user: false,
            },
        )) == PeerSharedAuthorityPlan::Reject,
{
}

proof fn peer_shared_authority_missing_current_signer_rejects()
    ensures
        decide_peer_shared_authority_plan(normalize_peer_shared_authority(
            PeerSharedAuthorityRows::MissingCurrentSigner,
        )) == PeerSharedAuthorityPlan::Reject,
{
}

proof fn peer_shared_authority_unsupported_signer_type_rejects()
    ensures
        decide_peer_shared_authority_plan(normalize_peer_shared_authority(
            PeerSharedAuthorityRows::UnsupportedSignerType,
        )) == PeerSharedAuthorityPlan::Reject,
{
}

proof fn peer_shared_authority_missing_device_invite_rejects()
    ensures
        decide_peer_shared_authority_plan(normalize_peer_shared_authority(
            PeerSharedAuthorityRows::MissingDeviceInviteBlob,
        )) == PeerSharedAuthorityPlan::Reject,
{
}

proof fn peer_shared_authority_malformed_device_invite_rejects()
    ensures
        decide_peer_shared_authority_plan(normalize_peer_shared_authority(
            PeerSharedAuthorityRows::MalformedDeviceInvite,
        )) == PeerSharedAuthorityPlan::Reject,
{
}

pub enum DeletionSignerRows {
    MissingCurrentSigner,
    AdminSigner,
    UnsupportedSignerType,
    UniquePeerSharedSigner,
    MissingSignerUser,
    AmbiguousSignerUser,
    Malformed,
}

pub enum DeletionSignerDecisionContext {
    AdminSigner,
    UniquePeerSharedSignerUser,
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType,
    RejectMissingSignerUser,
    RejectAmbiguousSignerUser,
    RejectMalformedSignerUser,
}

pub enum DeletionSignerPlan {
    ReadyAdmin,
    ReadyPeerSharedUser,
    Reject,
}

pub open spec fn normalize_deletion_signer(
    rows: DeletionSignerRows,
) -> DeletionSignerDecisionContext {
    match rows {
        DeletionSignerRows::MissingCurrentSigner => {
            DeletionSignerDecisionContext::RejectMissingCurrentSigner
        }
        DeletionSignerRows::AdminSigner => DeletionSignerDecisionContext::AdminSigner,
        DeletionSignerRows::UnsupportedSignerType => {
            DeletionSignerDecisionContext::RejectUnsupportedSignerType
        }
        DeletionSignerRows::UniquePeerSharedSigner => {
            DeletionSignerDecisionContext::UniquePeerSharedSignerUser
        }
        DeletionSignerRows::MissingSignerUser => {
            DeletionSignerDecisionContext::RejectMissingSignerUser
        }
        DeletionSignerRows::AmbiguousSignerUser => {
            DeletionSignerDecisionContext::RejectAmbiguousSignerUser
        }
        DeletionSignerRows::Malformed => {
            DeletionSignerDecisionContext::RejectMalformedSignerUser
        }
    }
}

pub open spec fn decide_deletion_signer_plan(
    context: DeletionSignerDecisionContext,
) -> DeletionSignerPlan {
    match context {
        DeletionSignerDecisionContext::AdminSigner => DeletionSignerPlan::ReadyAdmin,
        DeletionSignerDecisionContext::UniquePeerSharedSignerUser => {
            DeletionSignerPlan::ReadyPeerSharedUser
        }
        DeletionSignerDecisionContext::RejectMissingCurrentSigner
        | DeletionSignerDecisionContext::RejectUnsupportedSignerType
        | DeletionSignerDecisionContext::RejectMissingSignerUser
        | DeletionSignerDecisionContext::RejectAmbiguousSignerUser
        | DeletionSignerDecisionContext::RejectMalformedSignerUser => {
            DeletionSignerPlan::Reject
        }
    }
}

proof fn deletion_signer_admin_is_ready()
    ensures
        decide_deletion_signer_plan(normalize_deletion_signer(
            DeletionSignerRows::AdminSigner,
        )) == DeletionSignerPlan::ReadyAdmin,
{
}

proof fn deletion_signer_peer_user_is_ready()
    ensures
        decide_deletion_signer_plan(normalize_deletion_signer(
            DeletionSignerRows::UniquePeerSharedSigner,
        )) == DeletionSignerPlan::ReadyPeerSharedUser,
{
}

proof fn deletion_signer_missing_current_signer_rejects()
    ensures
        decide_deletion_signer_plan(normalize_deletion_signer(
            DeletionSignerRows::MissingCurrentSigner,
        )) == DeletionSignerPlan::Reject,
{
}

proof fn deletion_signer_unsupported_type_rejects()
    ensures
        decide_deletion_signer_plan(normalize_deletion_signer(
            DeletionSignerRows::UnsupportedSignerType,
        )) == DeletionSignerPlan::Reject,
{
}

proof fn deletion_signer_missing_user_rejects()
    ensures
        decide_deletion_signer_plan(normalize_deletion_signer(
            DeletionSignerRows::MissingSignerUser,
        )) == DeletionSignerPlan::Reject,
{
}

proof fn deletion_signer_ambiguous_user_rejects()
    ensures
        decide_deletion_signer_plan(normalize_deletion_signer(
            DeletionSignerRows::AmbiguousSignerUser,
        )) == DeletionSignerPlan::Reject,
{
}

proof fn deletion_signer_malformed_user_rejects()
    ensures
        decide_deletion_signer_plan(normalize_deletion_signer(DeletionSignerRows::Malformed))
            == DeletionSignerPlan::Reject,
{
}

pub enum SemanticTypeRows {
    Missing,
    UniqueKnown {
        type_check_required: bool,
        code_present: bool,
        code_in_range: bool,
        allowed_by_dep_field: bool,
    },
    Ambiguous,
    Malformed,
}

pub enum SemanticTypeDecisionContext {
    Missing,
    UniqueReady,
    RejectMissingType,
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
        SemanticTypeRows::UniqueKnown {
            type_check_required,
            code_present,
            code_in_range,
            allowed_by_dep_field,
        } => {
            if !code_present && type_check_required {
                SemanticTypeDecisionContext::RejectMissingType
            } else if !code_present {
                SemanticTypeDecisionContext::UniqueReady
            } else if !code_in_range {
                SemanticTypeDecisionContext::RejectOutOfRange
            } else if !type_check_required || allowed_by_dep_field {
                SemanticTypeDecisionContext::UniqueReady
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
        SemanticTypeDecisionContext::UniqueReady => SemanticTypePlan::DepReady,
        SemanticTypeDecisionContext::RejectMissingType
        | SemanticTypeDecisionContext::RejectWrongType
        | SemanticTypeDecisionContext::RejectOutOfRange
        | SemanticTypeDecisionContext::RejectAmbiguous
        | SemanticTypeDecisionContext::RejectMalformed => SemanticTypePlan::Reject,
    }
}

proof fn semantic_type_allowed_is_ready()
    ensures
        decide_semantic_type_plan(normalize_semantic_type(SemanticTypeRows::UniqueKnown {
            type_check_required: true,
            code_present: true,
            code_in_range: true,
            allowed_by_dep_field: true,
        })) == SemanticTypePlan::DepReady,
{
}

proof fn semantic_type_untyped_missing_code_is_ready()
    ensures
        decide_semantic_type_plan(normalize_semantic_type(SemanticTypeRows::UniqueKnown {
            type_check_required: false,
            code_present: false,
            code_in_range: true,
            allowed_by_dep_field: false,
        })) == SemanticTypePlan::DepReady,
{
}

proof fn semantic_type_typed_missing_code_rejects()
    ensures
        decide_semantic_type_plan(normalize_semantic_type(SemanticTypeRows::UniqueKnown {
            type_check_required: true,
            code_present: false,
            code_in_range: true,
            allowed_by_dep_field: false,
        })) == SemanticTypePlan::Reject,
{
}

proof fn semantic_type_wrong_type_rejects()
    ensures
        decide_semantic_type_plan(normalize_semantic_type(SemanticTypeRows::UniqueKnown {
            type_check_required: true,
            code_present: true,
            code_in_range: true,
            allowed_by_dep_field: false,
        })) == SemanticTypePlan::Reject,
{
}

proof fn semantic_type_out_of_range_rejects()
    ensures
        decide_semantic_type_plan(normalize_semantic_type(SemanticTypeRows::UniqueKnown {
            type_check_required: true,
            code_present: true,
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
