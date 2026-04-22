//! Formal verification of projection query normalization seams.
//!
//! This models the boundary between raw typed SQL rows and the normalized
//! `DecisionContext` consumed by projector/context-load planners.
//!
//! Every `pub fn` below is an executable Rust core dispatcher consumed by
//! `src/state/projection/decision_context.rs`. Postconditions (`ensures`) are SMT-checked
//! against the function body by `cargo-verus verify`.
//!
//! Runtime carries rich payloads (String signer_event_ids, Vec<Option<String>>
//! user_id lists). This Verus core reduces each dispatch to primitive booleans
//! and counts — the runtime keeps the rich payloads locally and only delegates
//! the tag-level dispatch decision.
//!
//! That includes the newer key-delivery context loaders, which now supply direct
//! key-rotation and invite-history material into `ProjectorDecisionContext`.

use vstd::prelude::*;

verus! {

// ═══════════════════════════════════════════════════════════════════
// Workspace acceptance
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkspaceAcceptedRawRowsCore {
    pub row_count: u64,
    pub all_workspace_ids_equal: bool,
    pub representative_workspace_matches_event: bool,
    pub malformed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceDecisionContextCore {
    MissingAcceptedWorkspace,
    UniqueAcceptedWorkspace { workspace_matches_event: bool },
    RejectAmbiguousAcceptedWorkspace,
    RejectMalformedAcceptedWorkspace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceContextPlanCore {
    BlockOnAcceptedWorkspace,
    Ready,
    Reject,
}

pub fn normalize_workspace_acceptance_core(
    rows: WorkspaceAcceptedRawRowsCore,
) -> (context: WorkspaceDecisionContextCore)
    ensures
        rows.malformed ==> context == WorkspaceDecisionContextCore::RejectMalformedAcceptedWorkspace,
        (!rows.malformed && rows.row_count == 0)
            ==> context == WorkspaceDecisionContextCore::MissingAcceptedWorkspace,
        (!rows.malformed && rows.row_count > 0 && rows.all_workspace_ids_equal)
            ==> context == (WorkspaceDecisionContextCore::UniqueAcceptedWorkspace {
                workspace_matches_event: rows.representative_workspace_matches_event,
            }),
        (!rows.malformed && rows.row_count > 0 && !rows.all_workspace_ids_equal)
            ==> context == WorkspaceDecisionContextCore::RejectAmbiguousAcceptedWorkspace,
{
    if rows.malformed {
        WorkspaceDecisionContextCore::RejectMalformedAcceptedWorkspace
    } else if rows.row_count == 0 {
        WorkspaceDecisionContextCore::MissingAcceptedWorkspace
    } else if rows.all_workspace_ids_equal {
        WorkspaceDecisionContextCore::UniqueAcceptedWorkspace {
            workspace_matches_event: rows.representative_workspace_matches_event,
        }
    } else {
        WorkspaceDecisionContextCore::RejectAmbiguousAcceptedWorkspace
    }
}

pub fn decide_workspace_context_plan_core(
    context: WorkspaceDecisionContextCore,
) -> (plan: WorkspaceContextPlanCore)
    ensures
        context == WorkspaceDecisionContextCore::MissingAcceptedWorkspace
            ==> plan == WorkspaceContextPlanCore::BlockOnAcceptedWorkspace,
        context == (WorkspaceDecisionContextCore::UniqueAcceptedWorkspace {
            workspace_matches_event: true,
        }) ==> plan == WorkspaceContextPlanCore::Ready,
        context == (WorkspaceDecisionContextCore::UniqueAcceptedWorkspace {
            workspace_matches_event: false,
        }) ==> plan == WorkspaceContextPlanCore::Reject,
        context == WorkspaceDecisionContextCore::RejectAmbiguousAcceptedWorkspace
            ==> plan == WorkspaceContextPlanCore::Reject,
        context == WorkspaceDecisionContextCore::RejectMalformedAcceptedWorkspace
            ==> plan == WorkspaceContextPlanCore::Reject,
{
    match context {
        WorkspaceDecisionContextCore::MissingAcceptedWorkspace => {
            WorkspaceContextPlanCore::BlockOnAcceptedWorkspace
        }
        WorkspaceDecisionContextCore::UniqueAcceptedWorkspace { workspace_matches_event } => {
            if workspace_matches_event {
                WorkspaceContextPlanCore::Ready
            } else {
                WorkspaceContextPlanCore::Reject
            }
        }
        WorkspaceDecisionContextCore::RejectAmbiguousAcceptedWorkspace
        | WorkspaceDecisionContextCore::RejectMalformedAcceptedWorkspace => {
            WorkspaceContextPlanCore::Reject
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Content authority
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentAuthorityRowsCore {
    NoAuthorCheckNeeded,
    MissingCurrentSigner,
    UnsupportedSignerType,
    PeerSharedSigner {
        row_count: u64,
        all_signer_user_ids_equal: bool,
        representative_signer_matches_author: bool,
        malformed: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentAuthorityDecisionContextCore {
    NoAuthorCheckNeeded,
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType,
    UniqueSignerUser { signer_matches_author: bool },
    RejectMissingSignerUser,
    RejectAmbiguousSignerUser,
    RejectMalformedSignerUser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentAuthorityPlanCore {
    Ready,
    Reject,
}

pub fn normalize_content_authority_core(
    rows: ContentAuthorityRowsCore,
) -> (context: ContentAuthorityDecisionContextCore)
    ensures
        rows == ContentAuthorityRowsCore::NoAuthorCheckNeeded
            ==> context == ContentAuthorityDecisionContextCore::NoAuthorCheckNeeded,
        rows == ContentAuthorityRowsCore::MissingCurrentSigner
            ==> context == ContentAuthorityDecisionContextCore::RejectMissingCurrentSigner,
        rows == ContentAuthorityRowsCore::UnsupportedSignerType
            ==> context == ContentAuthorityDecisionContextCore::RejectUnsupportedSignerType,
{
    match rows {
        ContentAuthorityRowsCore::NoAuthorCheckNeeded => {
            ContentAuthorityDecisionContextCore::NoAuthorCheckNeeded
        }
        ContentAuthorityRowsCore::MissingCurrentSigner => {
            ContentAuthorityDecisionContextCore::RejectMissingCurrentSigner
        }
        ContentAuthorityRowsCore::UnsupportedSignerType => {
            ContentAuthorityDecisionContextCore::RejectUnsupportedSignerType
        }
        ContentAuthorityRowsCore::PeerSharedSigner {
            row_count,
            all_signer_user_ids_equal,
            representative_signer_matches_author,
            malformed,
        } => {
            if malformed {
                ContentAuthorityDecisionContextCore::RejectMalformedSignerUser
            } else if row_count == 0 {
                ContentAuthorityDecisionContextCore::RejectMissingSignerUser
            } else if all_signer_user_ids_equal {
                ContentAuthorityDecisionContextCore::UniqueSignerUser {
                    signer_matches_author: representative_signer_matches_author,
                }
            } else {
                ContentAuthorityDecisionContextCore::RejectAmbiguousSignerUser
            }
        }
    }
}

pub fn decide_content_authority_plan_core(
    context: ContentAuthorityDecisionContextCore,
) -> (plan: ContentAuthorityPlanCore)
    ensures
        context == ContentAuthorityDecisionContextCore::NoAuthorCheckNeeded
            ==> plan == ContentAuthorityPlanCore::Ready,
        context == (ContentAuthorityDecisionContextCore::UniqueSignerUser {
            signer_matches_author: true,
        }) ==> plan == ContentAuthorityPlanCore::Ready,
        context == (ContentAuthorityDecisionContextCore::UniqueSignerUser {
            signer_matches_author: false,
        }) ==> plan == ContentAuthorityPlanCore::Reject,
        context == ContentAuthorityDecisionContextCore::RejectMissingCurrentSigner
            ==> plan == ContentAuthorityPlanCore::Reject,
        context == ContentAuthorityDecisionContextCore::RejectUnsupportedSignerType
            ==> plan == ContentAuthorityPlanCore::Reject,
        context == ContentAuthorityDecisionContextCore::RejectMissingSignerUser
            ==> plan == ContentAuthorityPlanCore::Reject,
        context == ContentAuthorityDecisionContextCore::RejectAmbiguousSignerUser
            ==> plan == ContentAuthorityPlanCore::Reject,
        context == ContentAuthorityDecisionContextCore::RejectMalformedSignerUser
            ==> plan == ContentAuthorityPlanCore::Reject,
{
    match context {
        ContentAuthorityDecisionContextCore::NoAuthorCheckNeeded => ContentAuthorityPlanCore::Ready,
        ContentAuthorityDecisionContextCore::UniqueSignerUser { signer_matches_author } => {
            if signer_matches_author {
                ContentAuthorityPlanCore::Ready
            } else {
                ContentAuthorityPlanCore::Reject
            }
        }
        ContentAuthorityDecisionContextCore::RejectMissingCurrentSigner
        | ContentAuthorityDecisionContextCore::RejectUnsupportedSignerType
        | ContentAuthorityDecisionContextCore::RejectMissingSignerUser
        | ContentAuthorityDecisionContextCore::RejectAmbiguousSignerUser
        | ContentAuthorityDecisionContextCore::RejectMalformedSignerUser => {
            ContentAuthorityPlanCore::Reject
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Admin authority
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAuthorityRowsCore {
    MissingCurrentSigner,
    UnsupportedSignerType,
    WorkspaceSigner {
        authority_matches_signer: bool,
        row_count: u64,
        all_user_keys_equal: bool,
        representative_key_matches_admin_key: bool,
        malformed: bool,
    },
    PeerSharedSigner {
        authority_matches_signer: bool,
        row_count: u64,
        all_user_keys_equal: bool,
        representative_key_matches_admin_key: bool,
        malformed: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAuthorityDecisionContextCore {
    WorkspaceUserKey {
        authority_matches_signer: bool,
        admin_key_matches_user_key: bool,
    },
    PeerSharedUserKey {
        authority_matches_signer: bool,
        admin_key_matches_user_key: bool,
    },
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType,
    RejectMissingUser,
    RejectAmbiguousUser,
    RejectMalformedUserKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminAuthorityPlanCore {
    Ready,
    Reject,
}

pub fn normalize_admin_authority_core(
    rows: AdminAuthorityRowsCore,
) -> (context: AdminAuthorityDecisionContextCore)
    ensures
        rows == AdminAuthorityRowsCore::MissingCurrentSigner
            ==> context == AdminAuthorityDecisionContextCore::RejectMissingCurrentSigner,
        rows == AdminAuthorityRowsCore::UnsupportedSignerType
            ==> context == AdminAuthorityDecisionContextCore::RejectUnsupportedSignerType,
{
    match rows {
        AdminAuthorityRowsCore::MissingCurrentSigner => {
            AdminAuthorityDecisionContextCore::RejectMissingCurrentSigner
        }
        AdminAuthorityRowsCore::UnsupportedSignerType => {
            AdminAuthorityDecisionContextCore::RejectUnsupportedSignerType
        }
        AdminAuthorityRowsCore::WorkspaceSigner {
            authority_matches_signer,
            row_count,
            all_user_keys_equal,
            representative_key_matches_admin_key,
            malformed,
        } => {
            if malformed {
                AdminAuthorityDecisionContextCore::RejectMalformedUserKey
            } else if row_count == 0 {
                AdminAuthorityDecisionContextCore::RejectMissingUser
            } else if all_user_keys_equal {
                AdminAuthorityDecisionContextCore::WorkspaceUserKey {
                    authority_matches_signer,
                    admin_key_matches_user_key: representative_key_matches_admin_key,
                }
            } else {
                AdminAuthorityDecisionContextCore::RejectAmbiguousUser
            }
        }
        AdminAuthorityRowsCore::PeerSharedSigner {
            authority_matches_signer,
            row_count,
            all_user_keys_equal,
            representative_key_matches_admin_key,
            malformed,
        } => {
            if malformed {
                AdminAuthorityDecisionContextCore::RejectMalformedUserKey
            } else if row_count == 0 {
                AdminAuthorityDecisionContextCore::RejectMissingUser
            } else if all_user_keys_equal {
                AdminAuthorityDecisionContextCore::PeerSharedUserKey {
                    authority_matches_signer,
                    admin_key_matches_user_key: representative_key_matches_admin_key,
                }
            } else {
                AdminAuthorityDecisionContextCore::RejectAmbiguousUser
            }
        }
    }
}

pub fn decide_admin_authority_plan_core(
    context: AdminAuthorityDecisionContextCore,
) -> (plan: AdminAuthorityPlanCore)
    ensures
        context == (AdminAuthorityDecisionContextCore::WorkspaceUserKey {
            authority_matches_signer: true,
            admin_key_matches_user_key: true,
        }) ==> plan == AdminAuthorityPlanCore::Ready,
        context == (AdminAuthorityDecisionContextCore::PeerSharedUserKey {
            authority_matches_signer: true,
            admin_key_matches_user_key: true,
        }) ==> plan == AdminAuthorityPlanCore::Ready,
        context == (AdminAuthorityDecisionContextCore::WorkspaceUserKey {
            authority_matches_signer: false,
            admin_key_matches_user_key: true,
        }) ==> plan == AdminAuthorityPlanCore::Reject,
        context == (AdminAuthorityDecisionContextCore::PeerSharedUserKey {
            authority_matches_signer: false,
            admin_key_matches_user_key: true,
        }) ==> plan == AdminAuthorityPlanCore::Reject,
        context == (AdminAuthorityDecisionContextCore::WorkspaceUserKey {
            authority_matches_signer: true,
            admin_key_matches_user_key: false,
        }) ==> plan == AdminAuthorityPlanCore::Reject,
        context == (AdminAuthorityDecisionContextCore::PeerSharedUserKey {
            authority_matches_signer: true,
            admin_key_matches_user_key: false,
        }) ==> plan == AdminAuthorityPlanCore::Reject,
        context == AdminAuthorityDecisionContextCore::RejectMissingCurrentSigner
            ==> plan == AdminAuthorityPlanCore::Reject,
        context == AdminAuthorityDecisionContextCore::RejectUnsupportedSignerType
            ==> plan == AdminAuthorityPlanCore::Reject,
        context == AdminAuthorityDecisionContextCore::RejectMissingUser
            ==> plan == AdminAuthorityPlanCore::Reject,
        context == AdminAuthorityDecisionContextCore::RejectAmbiguousUser
            ==> plan == AdminAuthorityPlanCore::Reject,
        context == AdminAuthorityDecisionContextCore::RejectMalformedUserKey
            ==> plan == AdminAuthorityPlanCore::Reject,
{
    match context {
        AdminAuthorityDecisionContextCore::WorkspaceUserKey {
            authority_matches_signer,
            admin_key_matches_user_key,
        }
        | AdminAuthorityDecisionContextCore::PeerSharedUserKey {
            authority_matches_signer,
            admin_key_matches_user_key,
        } => {
            if authority_matches_signer && admin_key_matches_user_key {
                AdminAuthorityPlanCore::Ready
            } else {
                AdminAuthorityPlanCore::Reject
            }
        }
        AdminAuthorityDecisionContextCore::RejectMissingCurrentSigner
        | AdminAuthorityDecisionContextCore::RejectUnsupportedSignerType
        | AdminAuthorityDecisionContextCore::RejectMissingUser
        | AdminAuthorityDecisionContextCore::RejectAmbiguousUser
        | AdminAuthorityDecisionContextCore::RejectMalformedUserKey => {
            AdminAuthorityPlanCore::Reject
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Peer-shared authority
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSharedAuthorityRowsCore {
    MissingCurrentSigner,
    UnsupportedSignerType,
    MissingDeviceInviteBlob,
    MalformedDeviceInvite,
    UniqueAuthorizedUser { claimed_user_matches_authorized_user: bool },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSharedAuthorityDecisionContextCore {
    UniqueAuthorizedUser { claimed_user_matches_authorized_user: bool },
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType,
    RejectMissingDeviceInviteBlob,
    RejectMalformedDeviceInvite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSharedAuthorityPlanCore {
    Ready,
    Reject,
}

pub fn normalize_peer_shared_authority_core(
    rows: PeerSharedAuthorityRowsCore,
) -> (context: PeerSharedAuthorityDecisionContextCore)
    ensures
        rows == PeerSharedAuthorityRowsCore::MissingCurrentSigner
            ==> context == PeerSharedAuthorityDecisionContextCore::RejectMissingCurrentSigner,
        rows == PeerSharedAuthorityRowsCore::UnsupportedSignerType
            ==> context == PeerSharedAuthorityDecisionContextCore::RejectUnsupportedSignerType,
        rows == PeerSharedAuthorityRowsCore::MissingDeviceInviteBlob
            ==> context == PeerSharedAuthorityDecisionContextCore::RejectMissingDeviceInviteBlob,
        rows == PeerSharedAuthorityRowsCore::MalformedDeviceInvite
            ==> context == PeerSharedAuthorityDecisionContextCore::RejectMalformedDeviceInvite,
        rows == (PeerSharedAuthorityRowsCore::UniqueAuthorizedUser {
            claimed_user_matches_authorized_user: true,
        }) ==> context == (PeerSharedAuthorityDecisionContextCore::UniqueAuthorizedUser {
            claimed_user_matches_authorized_user: true,
        }),
        rows == (PeerSharedAuthorityRowsCore::UniqueAuthorizedUser {
            claimed_user_matches_authorized_user: false,
        }) ==> context == (PeerSharedAuthorityDecisionContextCore::UniqueAuthorizedUser {
            claimed_user_matches_authorized_user: false,
        }),
{
    match rows {
        PeerSharedAuthorityRowsCore::MissingCurrentSigner => {
            PeerSharedAuthorityDecisionContextCore::RejectMissingCurrentSigner
        }
        PeerSharedAuthorityRowsCore::UnsupportedSignerType => {
            PeerSharedAuthorityDecisionContextCore::RejectUnsupportedSignerType
        }
        PeerSharedAuthorityRowsCore::MissingDeviceInviteBlob => {
            PeerSharedAuthorityDecisionContextCore::RejectMissingDeviceInviteBlob
        }
        PeerSharedAuthorityRowsCore::MalformedDeviceInvite => {
            PeerSharedAuthorityDecisionContextCore::RejectMalformedDeviceInvite
        }
        PeerSharedAuthorityRowsCore::UniqueAuthorizedUser {
            claimed_user_matches_authorized_user,
        } => PeerSharedAuthorityDecisionContextCore::UniqueAuthorizedUser {
            claimed_user_matches_authorized_user,
        },
    }
}

pub fn decide_peer_shared_authority_plan_core(
    context: PeerSharedAuthorityDecisionContextCore,
) -> (plan: PeerSharedAuthorityPlanCore)
    ensures
        context == (PeerSharedAuthorityDecisionContextCore::UniqueAuthorizedUser {
            claimed_user_matches_authorized_user: true,
        }) ==> plan == PeerSharedAuthorityPlanCore::Ready,
        context == (PeerSharedAuthorityDecisionContextCore::UniqueAuthorizedUser {
            claimed_user_matches_authorized_user: false,
        }) ==> plan == PeerSharedAuthorityPlanCore::Reject,
        context == PeerSharedAuthorityDecisionContextCore::RejectMissingCurrentSigner
            ==> plan == PeerSharedAuthorityPlanCore::Reject,
        context == PeerSharedAuthorityDecisionContextCore::RejectUnsupportedSignerType
            ==> plan == PeerSharedAuthorityPlanCore::Reject,
        context == PeerSharedAuthorityDecisionContextCore::RejectMissingDeviceInviteBlob
            ==> plan == PeerSharedAuthorityPlanCore::Reject,
        context == PeerSharedAuthorityDecisionContextCore::RejectMalformedDeviceInvite
            ==> plan == PeerSharedAuthorityPlanCore::Reject,
{
    match context {
        PeerSharedAuthorityDecisionContextCore::UniqueAuthorizedUser {
            claimed_user_matches_authorized_user,
        } => {
            if claimed_user_matches_authorized_user {
                PeerSharedAuthorityPlanCore::Ready
            } else {
                PeerSharedAuthorityPlanCore::Reject
            }
        }
        PeerSharedAuthorityDecisionContextCore::RejectMissingCurrentSigner
        | PeerSharedAuthorityDecisionContextCore::RejectUnsupportedSignerType
        | PeerSharedAuthorityDecisionContextCore::RejectMissingDeviceInviteBlob
        | PeerSharedAuthorityDecisionContextCore::RejectMalformedDeviceInvite => {
            PeerSharedAuthorityPlanCore::Reject
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Deletion signer
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionSignerRowsCore {
    MissingCurrentSigner,
    AdminSigner,
    UnsupportedSignerType,
    PeerSharedSigner {
        row_count: u64,
        all_signer_user_ids_equal: bool,
        malformed: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionSignerDecisionContextCore {
    AdminSigner,
    UniquePeerSharedSignerUser,
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType,
    RejectMissingSignerUser,
    RejectAmbiguousSignerUser,
    RejectMalformedSignerUser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletionSignerPlanCore {
    ReadyAdmin,
    ReadyPeerSharedUser,
    Reject,
}

pub fn normalize_deletion_signer_core(
    rows: DeletionSignerRowsCore,
) -> (context: DeletionSignerDecisionContextCore)
    ensures
        rows == DeletionSignerRowsCore::MissingCurrentSigner
            ==> context == DeletionSignerDecisionContextCore::RejectMissingCurrentSigner,
        rows == DeletionSignerRowsCore::AdminSigner
            ==> context == DeletionSignerDecisionContextCore::AdminSigner,
        rows == DeletionSignerRowsCore::UnsupportedSignerType
            ==> context == DeletionSignerDecisionContextCore::RejectUnsupportedSignerType,
{
    match rows {
        DeletionSignerRowsCore::MissingCurrentSigner => {
            DeletionSignerDecisionContextCore::RejectMissingCurrentSigner
        }
        DeletionSignerRowsCore::AdminSigner => DeletionSignerDecisionContextCore::AdminSigner,
        DeletionSignerRowsCore::UnsupportedSignerType => {
            DeletionSignerDecisionContextCore::RejectUnsupportedSignerType
        }
        DeletionSignerRowsCore::PeerSharedSigner {
            row_count,
            all_signer_user_ids_equal,
            malformed,
        } => {
            if malformed {
                DeletionSignerDecisionContextCore::RejectMalformedSignerUser
            } else if row_count == 0 {
                DeletionSignerDecisionContextCore::RejectMissingSignerUser
            } else if all_signer_user_ids_equal {
                DeletionSignerDecisionContextCore::UniquePeerSharedSignerUser
            } else {
                DeletionSignerDecisionContextCore::RejectAmbiguousSignerUser
            }
        }
    }
}

pub fn decide_deletion_signer_plan_core(
    context: DeletionSignerDecisionContextCore,
) -> (plan: DeletionSignerPlanCore)
    ensures
        context == DeletionSignerDecisionContextCore::AdminSigner
            ==> plan == DeletionSignerPlanCore::ReadyAdmin,
        context == DeletionSignerDecisionContextCore::UniquePeerSharedSignerUser
            ==> plan == DeletionSignerPlanCore::ReadyPeerSharedUser,
        context == DeletionSignerDecisionContextCore::RejectMissingCurrentSigner
            ==> plan == DeletionSignerPlanCore::Reject,
        context == DeletionSignerDecisionContextCore::RejectUnsupportedSignerType
            ==> plan == DeletionSignerPlanCore::Reject,
        context == DeletionSignerDecisionContextCore::RejectMissingSignerUser
            ==> plan == DeletionSignerPlanCore::Reject,
        context == DeletionSignerDecisionContextCore::RejectAmbiguousSignerUser
            ==> plan == DeletionSignerPlanCore::Reject,
        context == DeletionSignerDecisionContextCore::RejectMalformedSignerUser
            ==> plan == DeletionSignerPlanCore::Reject,
{
    match context {
        DeletionSignerDecisionContextCore::AdminSigner => DeletionSignerPlanCore::ReadyAdmin,
        DeletionSignerDecisionContextCore::UniquePeerSharedSignerUser => {
            DeletionSignerPlanCore::ReadyPeerSharedUser
        }
        DeletionSignerDecisionContextCore::RejectMissingCurrentSigner
        | DeletionSignerDecisionContextCore::RejectUnsupportedSignerType
        | DeletionSignerDecisionContextCore::RejectMissingSignerUser
        | DeletionSignerDecisionContextCore::RejectAmbiguousSignerUser
        | DeletionSignerDecisionContextCore::RejectMalformedSignerUser => {
            DeletionSignerPlanCore::Reject
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Removal authority / target kind
//
// The former `RemovalSignerRowsCore` / `decide_removal_signer_plan_core`
// chain modelled an `is_admin: bool` rollup flag — a proof over an
// opaque predicate that said nothing about HOW the runtime knew
// admin-ness. With Removal's admin_authority_event_id now an explicit
// dep (see runtime `dep_facts::RemovalDepFacts`), that proof surface
// is obsolete: the positive-authority obligation is the structural
// equality `admin.user_event_id == signer_ps.user_event_id` over two
// parsed event types, which lifts to Verus directly once the
// `decide_removal` pure fn is mirrored into this crate. Target-kind
// triage (`RemovalTargetRowsCore` → `RemovalTargetPlanCore`) moved
// into the runtime's `RemovalGuardFacts` + pure decide; it will come
// back here as part of the DepFacts/GuardFacts mirror when signer-as
// -dep migration lands (see plan).
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
// Semantic type
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticTypeRowsCore {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticTypeDecisionContextCore {
    Missing,
    UniqueReady,
    RejectMissingType,
    RejectWrongType,
    RejectOutOfRange,
    RejectAmbiguous,
    RejectMalformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticTypePlanCore {
    DepMissing,
    DepReady,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepLoadDecisionContextCore {
    pub purge_sensitive_dep_is_tombstoned: bool,
    pub semantic_type_rows: SemanticTypeRowsCore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepLoadPlanCore {
    Purge,
    SemanticRowsReady,
    Missing,
}

pub fn normalize_semantic_type_core(
    rows: SemanticTypeRowsCore,
) -> (context: SemanticTypeDecisionContextCore)
    ensures
        rows == SemanticTypeRowsCore::Missing
            ==> context == SemanticTypeDecisionContextCore::Missing,
        rows == SemanticTypeRowsCore::Ambiguous
            ==> context == SemanticTypeDecisionContextCore::RejectAmbiguous,
        rows == SemanticTypeRowsCore::Malformed
            ==> context == SemanticTypeDecisionContextCore::RejectMalformed,
{
    match rows {
        SemanticTypeRowsCore::Missing => SemanticTypeDecisionContextCore::Missing,
        SemanticTypeRowsCore::UniqueKnown {
            type_check_required,
            code_present,
            code_in_range,
            allowed_by_dep_field,
        } => {
            if !code_present && type_check_required {
                SemanticTypeDecisionContextCore::RejectMissingType
            } else if !code_present {
                SemanticTypeDecisionContextCore::UniqueReady
            } else if !code_in_range {
                SemanticTypeDecisionContextCore::RejectOutOfRange
            } else if !type_check_required || allowed_by_dep_field {
                SemanticTypeDecisionContextCore::UniqueReady
            } else {
                SemanticTypeDecisionContextCore::RejectWrongType
            }
        }
        SemanticTypeRowsCore::Ambiguous => SemanticTypeDecisionContextCore::RejectAmbiguous,
        SemanticTypeRowsCore::Malformed => SemanticTypeDecisionContextCore::RejectMalformed,
    }
}

pub fn decide_semantic_type_plan_core(
    context: SemanticTypeDecisionContextCore,
) -> (plan: SemanticTypePlanCore)
    ensures
        context == SemanticTypeDecisionContextCore::Missing
            ==> plan == SemanticTypePlanCore::DepMissing,
        context == SemanticTypeDecisionContextCore::UniqueReady
            ==> plan == SemanticTypePlanCore::DepReady,
        context == SemanticTypeDecisionContextCore::RejectMissingType
            ==> plan == SemanticTypePlanCore::Reject,
        context == SemanticTypeDecisionContextCore::RejectWrongType
            ==> plan == SemanticTypePlanCore::Reject,
        context == SemanticTypeDecisionContextCore::RejectOutOfRange
            ==> plan == SemanticTypePlanCore::Reject,
        context == SemanticTypeDecisionContextCore::RejectAmbiguous
            ==> plan == SemanticTypePlanCore::Reject,
        context == SemanticTypeDecisionContextCore::RejectMalformed
            ==> plan == SemanticTypePlanCore::Reject,
{
    match context {
        SemanticTypeDecisionContextCore::Missing => SemanticTypePlanCore::DepMissing,
        SemanticTypeDecisionContextCore::UniqueReady => SemanticTypePlanCore::DepReady,
        SemanticTypeDecisionContextCore::RejectMissingType
        | SemanticTypeDecisionContextCore::RejectWrongType
        | SemanticTypeDecisionContextCore::RejectOutOfRange
        | SemanticTypeDecisionContextCore::RejectAmbiguous
        | SemanticTypeDecisionContextCore::RejectMalformed => SemanticTypePlanCore::Reject,
    }
}

pub fn decide_dep_load_plan_core(
    context: DepLoadDecisionContextCore,
) -> (plan: DepLoadPlanCore)
    ensures
        context.purge_sensitive_dep_is_tombstoned ==> plan == DepLoadPlanCore::Purge,
        (!context.purge_sensitive_dep_is_tombstoned
         && context.semantic_type_rows == SemanticTypeRowsCore::Missing)
            ==> plan == DepLoadPlanCore::Missing,
        (!context.purge_sensitive_dep_is_tombstoned
         && context.semantic_type_rows == SemanticTypeRowsCore::Ambiguous)
            ==> plan == DepLoadPlanCore::SemanticRowsReady,
        (!context.purge_sensitive_dep_is_tombstoned
         && context.semantic_type_rows == SemanticTypeRowsCore::Malformed)
            ==> plan == DepLoadPlanCore::SemanticRowsReady,
{
    if context.purge_sensitive_dep_is_tombstoned {
        DepLoadPlanCore::Purge
    } else {
        match context.semantic_type_rows {
            SemanticTypeRowsCore::Missing => DepLoadPlanCore::Missing,
            SemanticTypeRowsCore::UniqueKnown { .. }
            | SemanticTypeRowsCore::Ambiguous
            | SemanticTypeRowsCore::Malformed => DepLoadPlanCore::SemanticRowsReady,
        }
    }
}

} // verus!
