use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::event_modules::{
    endpoint_shared::load_endpoint_shared_by_event_id, parse_event, AdminEvent, DeviceInviteEvent,
    FileEvent, FileSliceEvent, InviteAcceptedEvent, KeyHistoryEvent, KeyRequestEvent,
    KeyRotationEvent, KeySharedEvent, MessageDeletionEvent, MessageEvent, ParsedEvent,
    RemovalEvent,
    PeerSharedEvent, ReactionEvent, UserInviteEvent, WorkspaceEvent, EVENT_TYPE_ADMIN,
    EVENT_TYPE_DEVICE_INVITE, EVENT_TYPE_PEER_SHARED, EVENT_TYPE_WORKSPACE,
};
use crate::projection::projector::{
    BootstrapDecisionContext, CurrentSignerInfo, DeletionIntentInfo, FileDescriptorInfo,
    HistoricalKeyMaterial, ProjectorDecisionContext, RemovalTargetKind, UnwrappedSecretMaterial,
};
use crate::projection::encrypted::unwrap_key_from_sender;
use crate::projection::signer::{resolve_signer_key, SignerResolution};
use crate::crypto::decrypt_bundle_from_sender;
use crate::state::db::transport_creds::{peer_has_creds_with_source, CRED_SOURCE_PEER_SHARED};
use crate::state::db::transport_trust::read_bootstrap_context;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension};

pub(crate) type ProjectionQueryResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone)]
pub enum ContextLoadResult {
    Ready(ProjectorDecisionContext),
    Block { missing: Vec<EventId> },
    Reject { reason: String },
    Purge { message_event_id: String },
}

impl ContextLoadResult {
    pub fn ready(ctx: ProjectorDecisionContext) -> Self {
        Self::Ready(ctx)
    }

    pub fn block(missing: Vec<EventId>) -> Self {
        Self::Block { missing }
    }

    pub fn block_guard() -> Self {
        Self::Block {
            missing: Vec::new(),
        }
    }

    pub fn reject(reason: impl Into<String>) -> Self {
        Self::Reject {
            reason: reason.into(),
        }
    }

    pub fn purge(message_event_id: impl Into<String>) -> Self {
        Self::Purge {
            message_event_id: message_event_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepLoadResult {
    Ready {
        semantic_type_rows: SemanticTypeRawRows,
    },
    Missing,
    Reject {
        reason: String,
    },
    Purge {
        message_event_id: String,
    },
}

impl DepLoadResult {
    pub fn ready(semantic_type_code: Option<u8>) -> Self {
        Self::Ready {
            semantic_type_rows: SemanticTypeRawRows::UniqueKnown {
                semantic_type_code: semantic_type_code.map(i64::from),
            },
        }
    }

    pub fn ready_raw(semantic_type_code: Option<i64>) -> Self {
        Self::Ready {
            semantic_type_rows: SemanticTypeRawRows::UniqueKnown { semantic_type_code },
        }
    }

    pub fn missing() -> Self {
        Self::Missing
    }

    pub fn reject(reason: impl Into<String>) -> Self {
        Self::Reject {
            reason: reason.into(),
        }
    }

    pub fn purge(message_event_id: impl Into<String>) -> Self {
        Self::Purge {
            message_event_id: message_event_id.into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProjectionFrameContext {
    pub current_transport_key_event_id: Option<String>,
    pub current_owner_event_id: Option<String>,
    pub current_signer: Option<CurrentSignerInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceAcceptedRawRows {
    pub workspace_ids: Vec<String>,
    pub malformed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceDecisionContext {
    MissingAcceptedWorkspace,
    UniqueAcceptedWorkspace { workspace_id: String },
    RejectAmbiguousAcceptedWorkspace,
    RejectMalformedAcceptedWorkspace,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkspaceContextPlan {
    BlockOnAcceptedWorkspace,
    Ready { accepted_workspace_id: String },
    Reject { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentAuthorityRawRows {
    NoAuthorCheckNeeded,
    MissingCurrentSigner,
    UnsupportedSignerType {
        semantic_type_code: u8,
    },
    PeerSharedSigner {
        signer_event_id: String,
        signer_user_ids: Vec<Option<String>>,
        malformed: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentAuthorityDecisionContext {
    NoAuthorCheckNeeded,
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType {
        semantic_type_code: u8,
    },
    UniqueSignerUser {
        signer_event_id: String,
        signer_user_id: String,
        author_id: String,
    },
    RejectMissingSignerUser {
        signer_event_id: String,
    },
    RejectAmbiguousSignerUser {
        signer_event_id: String,
    },
    RejectMalformedSignerUser {
        signer_event_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentAuthorityPlan {
    Ready,
    Reject { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminAuthorityRawRows {
    MissingCurrentSigner,
    UnsupportedSignerType {
        semantic_type_code: u8,
    },
    WorkspaceSigner {
        authority_matches_signer: bool,
        user_event_id: String,
        user_public_keys: Vec<Option<Vec<u8>>>,
        malformed: bool,
    },
    PeerSharedSigner {
        authority_matches_signer: bool,
        user_event_id: String,
        user_public_keys: Vec<Option<Vec<u8>>>,
        malformed: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminAuthorityDecisionContext {
    WorkspaceUserKey {
        authority_matches_signer: bool,
        user_event_id: String,
        user_public_key: Vec<u8>,
        admin_public_key: Vec<u8>,
    },
    PeerSharedUserKey {
        authority_matches_signer: bool,
        user_event_id: String,
        user_public_key: Vec<u8>,
        admin_public_key: Vec<u8>,
    },
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType {
        semantic_type_code: u8,
    },
    RejectMissingUser {
        user_event_id: String,
    },
    RejectAmbiguousUser {
        user_event_id: String,
    },
    RejectMalformedUserKey {
        user_event_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdminAuthorityPlan {
    Ready,
    Reject { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSharedAuthorityRawRows {
    MissingCurrentSigner,
    UnsupportedSignerType {
        semantic_type_code: u8,
    },
    MissingDeviceInviteBlob {
        signer_event_id: String,
    },
    MalformedDeviceInvite {
        signer_event_id: String,
        reason: String,
    },
    DeviceInviteSigner {
        signer_event_id: String,
        authorized_user_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSharedAuthorityDecisionContext {
    UniqueAuthorizedUser {
        signer_event_id: String,
        authorized_user_id: String,
        claimed_user_id: String,
    },
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType {
        semantic_type_code: u8,
    },
    RejectMissingDeviceInviteBlob {
        signer_event_id: String,
    },
    RejectMalformedDeviceInvite {
        signer_event_id: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerSharedAuthorityPlan {
    Ready,
    Reject { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletionSignerRawRows {
    MissingCurrentSigner,
    AdminSigner,
    UnsupportedSignerType {
        semantic_type_code: u8,
    },
    PeerSharedSigner {
        signer_event_id: String,
        signer_user_ids: Vec<Option<String>>,
        malformed: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletionSignerDecisionContext {
    AdminSigner,
    UniquePeerSharedSignerUser {
        signer_event_id: String,
        signer_user_id: String,
    },
    RejectMissingCurrentSigner,
    RejectUnsupportedSignerType {
        semantic_type_code: u8,
    },
    RejectMissingSignerUser {
        signer_event_id: String,
    },
    RejectAmbiguousSignerUser {
        signer_event_id: String,
    },
    RejectMalformedSignerUser {
        signer_event_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletionSignerPlan {
    ReadyAdmin,
    ReadyPeerSharedUser { signer_user_id: String },
    Reject { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticTypeRawRows {
    Missing,
    UniqueKnown { semantic_type_code: Option<i64> },
    Ambiguous,
    Malformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticTypeDecisionContext {
    Missing,
    UniqueReady { semantic_type_code: Option<u8> },
    RejectMissingType,
    RejectWrongType { actual: u8, allowed: Vec<u8> },
    RejectOutOfRange { semantic_type_code: i64 },
    RejectAmbiguous,
    RejectMalformed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticTypePlan {
    DepMissing,
    DepReady { semantic_type_code: Option<u8> },
    Reject { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepLoadDecisionContext {
    pub deleted_message_purge: Option<String>,
    pub semantic_type_rows: SemanticTypeRawRows,
}

pub fn normalize_workspace_acceptance(
    raw_rows: &WorkspaceAcceptedRawRows,
) -> WorkspaceDecisionContext {
    if raw_rows.malformed {
        return WorkspaceDecisionContext::RejectMalformedAcceptedWorkspace;
    }

    let mut workspace_ids = raw_rows.workspace_ids.clone();
    workspace_ids.sort();
    workspace_ids.dedup();
    if workspace_ids
        .iter()
        .any(|workspace_id| event_id_from_base64(workspace_id).is_none())
    {
        return WorkspaceDecisionContext::RejectMalformedAcceptedWorkspace;
    }

    match workspace_ids.as_slice() {
        [] => WorkspaceDecisionContext::MissingAcceptedWorkspace,
        [workspace_id] => WorkspaceDecisionContext::UniqueAcceptedWorkspace {
            workspace_id: workspace_id.clone(),
        },
        _ => WorkspaceDecisionContext::RejectAmbiguousAcceptedWorkspace,
    }
}

pub fn normalize_content_authority(
    raw_rows: &ContentAuthorityRawRows,
    author_id_b64: &str,
) -> ContentAuthorityDecisionContext {
    match raw_rows {
        ContentAuthorityRawRows::NoAuthorCheckNeeded => {
            ContentAuthorityDecisionContext::NoAuthorCheckNeeded
        }
        ContentAuthorityRawRows::MissingCurrentSigner => {
            ContentAuthorityDecisionContext::RejectMissingCurrentSigner
        }
        ContentAuthorityRawRows::UnsupportedSignerType { semantic_type_code } => {
            ContentAuthorityDecisionContext::RejectUnsupportedSignerType {
                semantic_type_code: *semantic_type_code,
            }
        }
        ContentAuthorityRawRows::PeerSharedSigner {
            signer_event_id,
            signer_user_ids,
            malformed,
        } => {
            if *malformed
                || event_id_from_base64(signer_event_id).is_none()
                || event_id_from_base64(author_id_b64).is_none()
            {
                return ContentAuthorityDecisionContext::RejectMalformedSignerUser {
                    signer_event_id: signer_event_id.clone(),
                };
            }

            let mut user_ids = Vec::with_capacity(signer_user_ids.len());
            for user_id in signer_user_ids {
                let Some(user_id) = user_id.as_ref() else {
                    return ContentAuthorityDecisionContext::RejectMalformedSignerUser {
                        signer_event_id: signer_event_id.clone(),
                    };
                };
                if user_id.is_empty() || event_id_from_base64(user_id).is_none() {
                    return ContentAuthorityDecisionContext::RejectMalformedSignerUser {
                        signer_event_id: signer_event_id.clone(),
                    };
                }
                user_ids.push(user_id.clone());
            }

            user_ids.sort();
            user_ids.dedup();
            match user_ids.as_slice() {
                [] => ContentAuthorityDecisionContext::RejectMissingSignerUser {
                    signer_event_id: signer_event_id.clone(),
                },
                [signer_user_id] => ContentAuthorityDecisionContext::UniqueSignerUser {
                    signer_event_id: signer_event_id.clone(),
                    signer_user_id: signer_user_id.clone(),
                    author_id: author_id_b64.to_string(),
                },
                _ => ContentAuthorityDecisionContext::RejectAmbiguousSignerUser {
                    signer_event_id: signer_event_id.clone(),
                },
            }
        }
    }
}

pub fn normalize_semantic_type(
    raw_rows: &SemanticTypeRawRows,
    allowed_type_codes: &[u8],
) -> SemanticTypeDecisionContext {
    match raw_rows {
        SemanticTypeRawRows::Missing => SemanticTypeDecisionContext::Missing,
        SemanticTypeRawRows::UniqueKnown { semantic_type_code } => {
            let Some(semantic_type_code) = semantic_type_code else {
                if allowed_type_codes.is_empty() {
                    return SemanticTypeDecisionContext::UniqueReady {
                        semantic_type_code: None,
                    };
                }
                return SemanticTypeDecisionContext::RejectMissingType;
            };
            let Ok(actual) = u8::try_from(*semantic_type_code) else {
                return SemanticTypeDecisionContext::RejectOutOfRange {
                    semantic_type_code: *semantic_type_code,
                };
            };
            if allowed_type_codes.is_empty() || allowed_type_codes.contains(&actual) {
                SemanticTypeDecisionContext::UniqueReady {
                    semantic_type_code: Some(actual),
                }
            } else {
                SemanticTypeDecisionContext::RejectWrongType {
                    actual,
                    allowed: allowed_type_codes.to_vec(),
                }
            }
        }
        SemanticTypeRawRows::Ambiguous => SemanticTypeDecisionContext::RejectAmbiguous,
        SemanticTypeRawRows::Malformed => SemanticTypeDecisionContext::RejectMalformed,
    }
}

pub fn normalize_admin_authority(
    raw_rows: &AdminAuthorityRawRows,
    admin_public_key: &[u8; 32],
) -> AdminAuthorityDecisionContext {
    match raw_rows {
        AdminAuthorityRawRows::MissingCurrentSigner => {
            AdminAuthorityDecisionContext::RejectMissingCurrentSigner
        }
        AdminAuthorityRawRows::UnsupportedSignerType { semantic_type_code } => {
            AdminAuthorityDecisionContext::RejectUnsupportedSignerType {
                semantic_type_code: *semantic_type_code,
            }
        }
        AdminAuthorityRawRows::WorkspaceSigner {
            authority_matches_signer,
            user_event_id,
            user_public_keys,
            malformed,
        }
        | AdminAuthorityRawRows::PeerSharedSigner {
            authority_matches_signer,
            user_event_id,
            user_public_keys,
            malformed,
        } => {
            if *malformed || event_id_from_base64(user_event_id).is_none() {
                return AdminAuthorityDecisionContext::RejectMalformedUserKey {
                    user_event_id: user_event_id.clone(),
                };
            }

            let mut keys = Vec::with_capacity(user_public_keys.len());
            for public_key in user_public_keys {
                let Some(public_key) = public_key.as_ref() else {
                    return AdminAuthorityDecisionContext::RejectMalformedUserKey {
                        user_event_id: user_event_id.clone(),
                    };
                };
                if public_key.len() != 32 {
                    return AdminAuthorityDecisionContext::RejectMalformedUserKey {
                        user_event_id: user_event_id.clone(),
                    };
                }
                keys.push(public_key.clone());
            }

            keys.sort();
            keys.dedup();
            match keys.as_slice() {
                [] => AdminAuthorityDecisionContext::RejectMissingUser {
                    user_event_id: user_event_id.clone(),
                },
                [user_public_key] => match raw_rows {
                    AdminAuthorityRawRows::WorkspaceSigner { .. } => {
                        AdminAuthorityDecisionContext::WorkspaceUserKey {
                            authority_matches_signer: *authority_matches_signer,
                            user_event_id: user_event_id.clone(),
                            user_public_key: user_public_key.clone(),
                            admin_public_key: admin_public_key.to_vec(),
                        }
                    }
                    AdminAuthorityRawRows::PeerSharedSigner { .. } => {
                        AdminAuthorityDecisionContext::PeerSharedUserKey {
                            authority_matches_signer: *authority_matches_signer,
                            user_event_id: user_event_id.clone(),
                            user_public_key: user_public_key.clone(),
                            admin_public_key: admin_public_key.to_vec(),
                        }
                    }
                    _ => unreachable!("matched only workspace/peer_shared signer rows"),
                },
                _ => AdminAuthorityDecisionContext::RejectAmbiguousUser {
                    user_event_id: user_event_id.clone(),
                },
            }
        }
    }
}

pub fn normalize_peer_shared_authority(
    raw_rows: &PeerSharedAuthorityRawRows,
    claimed_user_id: &str,
) -> PeerSharedAuthorityDecisionContext {
    match raw_rows {
        PeerSharedAuthorityRawRows::MissingCurrentSigner => {
            PeerSharedAuthorityDecisionContext::RejectMissingCurrentSigner
        }
        PeerSharedAuthorityRawRows::UnsupportedSignerType { semantic_type_code } => {
            PeerSharedAuthorityDecisionContext::RejectUnsupportedSignerType {
                semantic_type_code: *semantic_type_code,
            }
        }
        PeerSharedAuthorityRawRows::MissingDeviceInviteBlob { signer_event_id } => {
            PeerSharedAuthorityDecisionContext::RejectMissingDeviceInviteBlob {
                signer_event_id: signer_event_id.clone(),
            }
        }
        PeerSharedAuthorityRawRows::MalformedDeviceInvite {
            signer_event_id,
            reason,
        } => PeerSharedAuthorityDecisionContext::RejectMalformedDeviceInvite {
            signer_event_id: signer_event_id.clone(),
            reason: reason.clone(),
        },
        PeerSharedAuthorityRawRows::DeviceInviteSigner {
            signer_event_id,
            authorized_user_id,
        } => {
            if event_id_from_base64(signer_event_id).is_none()
                || event_id_from_base64(authorized_user_id).is_none()
                || event_id_from_base64(claimed_user_id).is_none()
            {
                return PeerSharedAuthorityDecisionContext::RejectMalformedDeviceInvite {
                    signer_event_id: signer_event_id.clone(),
                    reason: format!(
                        "malformed peer_shared device_invite authorization for signer {}",
                        signer_event_id
                    ),
                };
            }
            PeerSharedAuthorityDecisionContext::UniqueAuthorizedUser {
                signer_event_id: signer_event_id.clone(),
                authorized_user_id: authorized_user_id.clone(),
                claimed_user_id: claimed_user_id.to_string(),
            }
        }
    }
}

pub fn normalize_deletion_signer(
    raw_rows: &DeletionSignerRawRows,
) -> DeletionSignerDecisionContext {
    match raw_rows {
        DeletionSignerRawRows::MissingCurrentSigner => {
            DeletionSignerDecisionContext::RejectMissingCurrentSigner
        }
        DeletionSignerRawRows::AdminSigner => DeletionSignerDecisionContext::AdminSigner,
        DeletionSignerRawRows::UnsupportedSignerType { semantic_type_code } => {
            DeletionSignerDecisionContext::RejectUnsupportedSignerType {
                semantic_type_code: *semantic_type_code,
            }
        }
        DeletionSignerRawRows::PeerSharedSigner {
            signer_event_id,
            signer_user_ids,
            malformed,
        } => {
            if *malformed || event_id_from_base64(signer_event_id).is_none() {
                return DeletionSignerDecisionContext::RejectMalformedSignerUser {
                    signer_event_id: signer_event_id.clone(),
                };
            }

            let mut user_ids = Vec::with_capacity(signer_user_ids.len());
            for user_id in signer_user_ids {
                let Some(user_id) = user_id.as_ref() else {
                    return DeletionSignerDecisionContext::RejectMalformedSignerUser {
                        signer_event_id: signer_event_id.clone(),
                    };
                };
                if user_id.is_empty() || event_id_from_base64(user_id).is_none() {
                    return DeletionSignerDecisionContext::RejectMalformedSignerUser {
                        signer_event_id: signer_event_id.clone(),
                    };
                }
                user_ids.push(user_id.clone());
            }

            user_ids.sort();
            user_ids.dedup();
            match user_ids.as_slice() {
                [] => DeletionSignerDecisionContext::RejectMissingSignerUser {
                    signer_event_id: signer_event_id.clone(),
                },
                [signer_user_id] => DeletionSignerDecisionContext::UniquePeerSharedSignerUser {
                    signer_event_id: signer_event_id.clone(),
                    signer_user_id: signer_user_id.clone(),
                },
                _ => DeletionSignerDecisionContext::RejectAmbiguousSignerUser {
                    signer_event_id: signer_event_id.clone(),
                },
            }
        }
    }
}

pub fn build_workspace_projector_decision_context(
    context: &WorkspaceDecisionContext,
) -> ProjectorDecisionContext {
    match context {
        WorkspaceDecisionContext::UniqueAcceptedWorkspace { workspace_id } => {
            ProjectorDecisionContext {
                accepted_workspace_id: Some(workspace_id.clone()),
                ..ProjectorDecisionContext::default()
            }
        }
        WorkspaceDecisionContext::MissingAcceptedWorkspace
        | WorkspaceDecisionContext::RejectAmbiguousAcceptedWorkspace
        | WorkspaceDecisionContext::RejectMalformedAcceptedWorkspace => {
            ProjectorDecisionContext::default()
        }
    }
}

pub fn decide_workspace_context_plan(
    context: &WorkspaceDecisionContext,
    event_id_b64: &str,
) -> WorkspaceContextPlan {
    match context {
        WorkspaceDecisionContext::MissingAcceptedWorkspace => {
            WorkspaceContextPlan::BlockOnAcceptedWorkspace
        }
        WorkspaceDecisionContext::UniqueAcceptedWorkspace { workspace_id }
            if workspace_id == event_id_b64 =>
        {
            WorkspaceContextPlan::Ready {
                accepted_workspace_id: workspace_id.clone(),
            }
        }
        WorkspaceDecisionContext::UniqueAcceptedWorkspace { .. } => WorkspaceContextPlan::Reject {
            reason: "workspace_id does not match accepted invite binding".to_string(),
        },
        WorkspaceDecisionContext::RejectAmbiguousAcceptedWorkspace => {
            WorkspaceContextPlan::Reject {
                reason: "ambiguous accepted invite workspace binding".to_string(),
            }
        }
        WorkspaceDecisionContext::RejectMalformedAcceptedWorkspace => {
            WorkspaceContextPlan::Reject {
                reason: "malformed accepted invite workspace binding".to_string(),
            }
        }
    }
}

pub fn decide_semantic_type_plan(
    context: &SemanticTypeDecisionContext,
    field_name: &str,
) -> SemanticTypePlan {
    match context {
        SemanticTypeDecisionContext::Missing => SemanticTypePlan::DepMissing,
        SemanticTypeDecisionContext::UniqueReady { semantic_type_code } => {
            SemanticTypePlan::DepReady {
                semantic_type_code: *semantic_type_code,
            }
        }
        SemanticTypeDecisionContext::RejectMissingType => SemanticTypePlan::Reject {
            reason: format!(
                "dep {} missing tenant-scoped semantic type record",
                field_name
            ),
        },
        SemanticTypeDecisionContext::RejectWrongType { actual, allowed } => {
            SemanticTypePlan::Reject {
                reason: format!(
                    "dep {} has semantic type code {} but expected one of {:?}",
                    field_name, actual, allowed
                ),
            }
        }
        SemanticTypeDecisionContext::RejectOutOfRange { semantic_type_code } => {
            SemanticTypePlan::Reject {
                reason: format!(
                    "dep {} has out-of-range semantic type code {}",
                    field_name, semantic_type_code
                ),
            }
        }
        SemanticTypeDecisionContext::RejectAmbiguous => SemanticTypePlan::Reject {
            reason: format!("dep {} has ambiguous semantic type rows", field_name),
        },
        SemanticTypeDecisionContext::RejectMalformed => SemanticTypePlan::Reject {
            reason: format!(
                "dep {} has malformed tenant-scoped semantic type record",
                field_name
            ),
        },
    }
}

pub fn decide_dep_load_plan(context: &DepLoadDecisionContext) -> DepLoadResult {
    if let Some(message_event_id) = &context.deleted_message_purge {
        return DepLoadResult::purge(message_event_id.clone());
    }
    if context.semantic_type_rows != SemanticTypeRawRows::Missing {
        return DepLoadResult::Ready {
            semantic_type_rows: context.semantic_type_rows.clone(),
        };
    }
    DepLoadResult::missing()
}

pub fn decide_admin_authority_plan(context: &AdminAuthorityDecisionContext) -> AdminAuthorityPlan {
    match context {
        AdminAuthorityDecisionContext::WorkspaceUserKey {
            authority_matches_signer: false,
            user_event_id: _,
            user_public_key: _,
            admin_public_key: _,
        } => AdminAuthorityPlan::Reject {
            reason: "bootstrap admin must use workspace as signer and authority".to_string(),
        },
        AdminAuthorityDecisionContext::PeerSharedUserKey {
            authority_matches_signer: false,
            user_event_id: _,
            user_public_key: _,
            admin_public_key: _,
        } => AdminAuthorityPlan::Reject {
            reason: "peer-signed admin authority does not match signer admin identity".to_string(),
        },
        AdminAuthorityDecisionContext::WorkspaceUserKey {
            authority_matches_signer: true,
            user_event_id: _,
            user_public_key,
            admin_public_key,
        }
        | AdminAuthorityDecisionContext::PeerSharedUserKey {
            authority_matches_signer: true,
            user_event_id: _,
            user_public_key,
            admin_public_key,
        } if user_public_key == admin_public_key => AdminAuthorityPlan::Ready,
        AdminAuthorityDecisionContext::WorkspaceUserKey {
            authority_matches_signer: true,
            user_event_id,
            user_public_key: _,
            admin_public_key: _,
        }
        | AdminAuthorityDecisionContext::PeerSharedUserKey {
            authority_matches_signer: true,
            user_event_id,
            user_public_key: _,
            admin_public_key: _,
        } => AdminAuthorityPlan::Reject {
            reason: format!(
                "admin public_key does not match user public_key for {}",
                user_event_id
            ),
        },
        AdminAuthorityDecisionContext::RejectMissingCurrentSigner => AdminAuthorityPlan::Reject {
            reason: "admin event missing current signer envelope".to_string(),
        },
        AdminAuthorityDecisionContext::RejectUnsupportedSignerType { semantic_type_code } => {
            AdminAuthorityPlan::Reject {
                reason: format!(
                    "admin signer must be workspace or peer_shared, got semantic type {}",
                    semantic_type_code
                ),
            }
        }
        AdminAuthorityDecisionContext::RejectMissingUser { user_event_id } => {
            AdminAuthorityPlan::Reject {
                reason: format!("no users row for user_event_id {}", user_event_id),
            }
        }
        AdminAuthorityDecisionContext::RejectAmbiguousUser { user_event_id } => {
            AdminAuthorityPlan::Reject {
                reason: format!("ambiguous users rows for user_event_id {}", user_event_id),
            }
        }
        AdminAuthorityDecisionContext::RejectMalformedUserKey { user_event_id } => {
            AdminAuthorityPlan::Reject {
                reason: format!(
                    "user {} has invalid public_key length or type",
                    user_event_id
                ),
            }
        }
    }
}

pub fn admin_authority_plan_to_mismatch_reason(plan: AdminAuthorityPlan) -> Option<String> {
    match plan {
        AdminAuthorityPlan::Ready => None,
        AdminAuthorityPlan::Reject { reason } => Some(reason),
    }
}

pub fn decide_peer_shared_authority_plan(
    context: &PeerSharedAuthorityDecisionContext,
) -> PeerSharedAuthorityPlan {
    match context {
        PeerSharedAuthorityDecisionContext::UniqueAuthorizedUser {
            signer_event_id: _,
            authorized_user_id,
            claimed_user_id,
        } if authorized_user_id == claimed_user_id => PeerSharedAuthorityPlan::Ready,
        PeerSharedAuthorityDecisionContext::UniqueAuthorizedUser {
            signer_event_id: _,
            authorized_user_id,
            claimed_user_id,
        } => PeerSharedAuthorityPlan::Reject {
            reason: format!(
                "peer_shared signer authorizes user {} but event claims {}",
                authorized_user_id, claimed_user_id
            ),
        },
        PeerSharedAuthorityDecisionContext::RejectMissingCurrentSigner => {
            PeerSharedAuthorityPlan::Reject {
                reason: "peer_shared missing current signer envelope".to_string(),
            }
        }
        PeerSharedAuthorityDecisionContext::RejectUnsupportedSignerType { semantic_type_code } => {
            PeerSharedAuthorityPlan::Reject {
                reason: format!(
                    "peer_shared signer must be device_invite, got semantic type {}",
                    semantic_type_code
                ),
            }
        }
        PeerSharedAuthorityDecisionContext::RejectMissingDeviceInviteBlob { signer_event_id } => {
            PeerSharedAuthorityPlan::Reject {
                reason: format!("no valid device_invite blob for signer {}", signer_event_id),
            }
        }
        PeerSharedAuthorityDecisionContext::RejectMalformedDeviceInvite {
            signer_event_id: _,
            reason,
        } => PeerSharedAuthorityPlan::Reject {
            reason: reason.clone(),
        },
    }
}

pub fn peer_shared_authority_plan_to_mismatch_reason(
    plan: PeerSharedAuthorityPlan,
) -> Option<String> {
    match plan {
        PeerSharedAuthorityPlan::Ready => None,
        PeerSharedAuthorityPlan::Reject { reason } => Some(reason),
    }
}

pub fn decide_deletion_signer_plan(context: &DeletionSignerDecisionContext) -> DeletionSignerPlan {
    match context {
        DeletionSignerDecisionContext::AdminSigner => DeletionSignerPlan::ReadyAdmin,
        DeletionSignerDecisionContext::UniquePeerSharedSignerUser {
            signer_event_id: _,
            signer_user_id,
        } => DeletionSignerPlan::ReadyPeerSharedUser {
            signer_user_id: signer_user_id.clone(),
        },
        DeletionSignerDecisionContext::RejectMissingCurrentSigner => DeletionSignerPlan::Reject {
            reason: "missing current signer envelope".to_string(),
        },
        DeletionSignerDecisionContext::RejectUnsupportedSignerType { semantic_type_code } => {
            DeletionSignerPlan::Reject {
                reason: format!(
                    "message_deletion signer must be peer_shared or admin, got semantic type {}",
                    semantic_type_code
                ),
            }
        }
        DeletionSignerDecisionContext::RejectMissingSignerUser { signer_event_id } => {
            DeletionSignerPlan::Reject {
                reason: format!("no peers_shared entry for signer {}", signer_event_id),
            }
        }
        DeletionSignerDecisionContext::RejectAmbiguousSignerUser { signer_event_id } => {
            DeletionSignerPlan::Reject {
                reason: format!(
                    "ambiguous peers_shared user binding for message_deletion signer {}",
                    signer_event_id
                ),
            }
        }
        DeletionSignerDecisionContext::RejectMalformedSignerUser { signer_event_id } => {
            DeletionSignerPlan::Reject {
                reason: format!(
                    "malformed peers_shared user binding for message_deletion signer {}",
                    signer_event_id
                ),
            }
        }
    }
}

pub fn deletion_signer_plan_to_context_fields(
    plan: DeletionSignerPlan,
) -> (Option<String>, bool, Option<String>) {
    match plan {
        DeletionSignerPlan::ReadyAdmin => (None, true, None),
        DeletionSignerPlan::ReadyPeerSharedUser { signer_user_id } => {
            (Some(signer_user_id), false, None)
        }
        DeletionSignerPlan::Reject { reason } => (None, false, Some(reason)),
    }
}

pub fn decide_content_authority_plan(
    context: &ContentAuthorityDecisionContext,
) -> ContentAuthorityPlan {
    match context {
        ContentAuthorityDecisionContext::NoAuthorCheckNeeded => ContentAuthorityPlan::Ready,
        ContentAuthorityDecisionContext::RejectMissingCurrentSigner => {
            ContentAuthorityPlan::Reject {
                reason: "missing current signer envelope".to_string(),
            }
        }
        ContentAuthorityDecisionContext::RejectUnsupportedSignerType { semantic_type_code } => {
            ContentAuthorityPlan::Reject {
                reason: format!(
                    "content signer must be peer_shared, got semantic type {}",
                    semantic_type_code
                ),
            }
        }
        ContentAuthorityDecisionContext::UniqueSignerUser {
            signer_event_id: _,
            signer_user_id,
            author_id,
        } if signer_user_id == author_id => ContentAuthorityPlan::Ready,
        ContentAuthorityDecisionContext::UniqueSignerUser {
            signer_event_id,
            signer_user_id,
            author_id,
        } => ContentAuthorityPlan::Reject {
            reason: format!(
                "signer {} belongs to user {} but author_id claims {}",
                signer_event_id, signer_user_id, author_id
            ),
        },
        ContentAuthorityDecisionContext::RejectMissingSignerUser { signer_event_id } => {
            ContentAuthorityPlan::Reject {
                reason: format!("no peers_shared entry for signer {}", signer_event_id),
            }
        }
        ContentAuthorityDecisionContext::RejectAmbiguousSignerUser { signer_event_id } => {
            ContentAuthorityPlan::Reject {
                reason: format!(
                    "ambiguous peers_shared user binding for signer {}",
                    signer_event_id
                ),
            }
        }
        ContentAuthorityDecisionContext::RejectMalformedSignerUser { signer_event_id } => {
            ContentAuthorityPlan::Reject {
                reason: format!(
                    "malformed peers_shared user binding for signer {}",
                    signer_event_id
                ),
            }
        }
    }
}

pub fn content_authority_plan_to_signer_user_mismatch_reason(
    plan: ContentAuthorityPlan,
) -> Option<String> {
    match plan {
        ContentAuthorityPlan::Ready => None,
        ContentAuthorityPlan::Reject { reason } => Some(reason),
    }
}

pub fn workspace_context_plan_to_load_result(plan: WorkspaceContextPlan) -> ContextLoadResult {
    match plan {
        WorkspaceContextPlan::BlockOnAcceptedWorkspace => ContextLoadResult::block(vec![]),
        WorkspaceContextPlan::Ready {
            accepted_workspace_id,
        } => ContextLoadResult::ready(ProjectorDecisionContext {
            accepted_workspace_id: Some(accepted_workspace_id),
            ..ProjectorDecisionContext::default()
        }),
        WorkspaceContextPlan::Reject { reason } => ContextLoadResult::reject(reason),
    }
}

pub trait ProjectionQueries {
    fn load_dep_result(
        &self,
        recorded_by: &str,
        parsed: &ParsedEvent,
        field_name: &str,
        dep_id: &EventId,
    ) -> ProjectionQueryResult<DepLoadResult>;

    fn load_key_secret_bytes(
        &self,
        recorded_by: &str,
        key_event_id: &[u8; 32],
    ) -> ProjectionQueryResult<Option<[u8; 32]>>;

    fn load_workspace_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        workspace: &WorkspaceEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;

    fn load_workspace_decision_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        workspace: &WorkspaceEvent,
    ) -> ProjectionQueryResult<WorkspaceDecisionContext> {
        let ctx = self.load_workspace_context(frame, recorded_by, event_id_b64, workspace)?;
        Ok(normalize_workspace_acceptance(&WorkspaceAcceptedRawRows {
            workspace_ids: ctx.accepted_workspace_id.into_iter().collect(),
            malformed: false,
        }))
    }

    fn load_admin_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        admin: &AdminEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;

    fn load_peer_shared_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        peer_shared: &PeerSharedEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;

    fn load_user_invite_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        user_invite: &UserInviteEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;

    fn load_device_invite_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        device_invite: &DeviceInviteEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;

    fn load_message_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        message: &MessageEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;

    fn load_message_deletion_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        message_deletion: &MessageDeletionEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;

    fn load_reaction_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        reaction: &ReactionEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;

    fn load_file_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        file: &FileEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;

    fn load_file_slice_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        file_slice: &FileSliceEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;

    fn load_invite_accepted_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        invite_accepted: &InviteAcceptedEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;

    fn load_removal_context(
        &self,
        _frame: &ProjectionFrameContext,
        _recorded_by: &str,
        _event_id_b64: &str,
        _removal: &RemovalEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        Ok(ProjectorDecisionContext::default())
    }

    fn load_key_request_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        key_request: &KeyRequestEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;

    fn load_key_shared_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        key_shared: &KeySharedEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;

    fn load_key_rotation_context(
        &self,
        _frame: &ProjectionFrameContext,
        _recorded_by: &str,
        _event_id_b64: &str,
        _key_rotation: &KeyRotationEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        Ok(ProjectorDecisionContext::default())
    }

    fn load_key_history_context(
        &self,
        _frame: &ProjectionFrameContext,
        _recorded_by: &str,
        _event_id_b64: &str,
        _key_history: &KeyHistoryEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        Ok(ProjectorDecisionContext::default())
    }

    // Per-Message FS producer/consumer context loaders. Default impls
    // return an empty context so test doubles and simulation backends
    // don't need to implement them right away. The real Connection
    // impl below performs the actual tombstone + privkey queries.

    fn load_message_key_context(
        &self,
        _frame: &ProjectionFrameContext,
        _recorded_by: &str,
        _event_id_b64: &str,
        _message_key: &crate::event_modules::MessageKeyEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        Ok(ProjectorDecisionContext::default())
    }

    fn load_key_broadcast_context(
        &self,
        _frame: &ProjectionFrameContext,
        _recorded_by: &str,
        _event_id_b64: &str,
        _key_broadcast: &crate::event_modules::KeyBroadcastEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        Ok(ProjectorDecisionContext::default())
    }

    fn load_key_history_bundle_context(
        &self,
        _frame: &ProjectionFrameContext,
        _recorded_by: &str,
        _event_id_b64: &str,
        _key_history_bundle: &crate::event_modules::KeyHistoryBundleEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        Ok(ProjectorDecisionContext::default())
    }

    fn load_key_bundle_share_context(
        &self,
        _frame: &ProjectionFrameContext,
        _recorded_by: &str,
        _event_id_b64: &str,
        _key_bundle_share: &crate::event_modules::KeyBundleShareEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        Ok(ProjectorDecisionContext::default())
    }
}

/// Declare a projector-local context loader that downcasts ParsedEvent to the
/// expected variant and forwards to the matching ProjectionQueries method.
macro_rules! define_query_context_loader {
    ($fn_name:ident, $variant:ident, $query_method:ident, $label:literal) => {
        pub fn $fn_name(
            queries: &dyn $crate::projection::decision_context::ProjectionQueries,
            frame: &$crate::projection::decision_context::ProjectionFrameContext,
            recorded_by: &str,
            event_id_b64: &str,
            parsed: &$crate::event_modules::ParsedEvent,
        ) -> Result<$crate::projection::decision_context::ContextLoadResult, Box<dyn std::error::Error>> {
            let event = match parsed {
                $crate::event_modules::ParsedEvent::$variant(event) => event,
                _ => {
                    return Err(
                        concat!($label, " context loader called for non-", $label, " event").into(),
                    )
                }
            };

            Ok($crate::projection::decision_context::ContextLoadResult::ready(
                queries.$query_method(frame, recorded_by, event_id_b64, event)?,
            ))
        }
    };
}

pub(crate) use define_query_context_loader;

fn semantic_type_code_for_parsed(parsed: &ParsedEvent) -> u8 {
    match parsed {
        ParsedEvent::Encrypted(enc) => enc.inner_type_code,
        _ => parsed.event_type_code(),
    }
}

fn derive_semantic_type_code_from_blob(
    blob: &[u8],
) -> Result<Option<u8>, Box<dyn std::error::Error>> {
    let parsed = match parse_event(blob) {
        Ok(parsed) => parsed,
        Err(_) => return Ok(crate::event_modules::outer_semantic_type_code(blob)),
    };
    Ok(Some(semantic_type_code_for_parsed(&parsed)))
}

fn global_endpoint_shared_is_valid(
    conn: &Connection,
    dep_b64: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let present: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM endpoints_shared
             WHERE event_id = ?1
         )",
        rusqlite::params![dep_b64],
        |row| row.get(0),
    )?;
    Ok(present)
}

fn semantic_type_row_error_is_malformed(err: &rusqlite::Error) -> bool {
    matches!(
        err,
        rusqlite::Error::InvalidColumnType(..)
            | rusqlite::Error::FromSqlConversionFailure(..)
            | rusqlite::Error::IntegralValueOutOfRange(..)
    )
}

fn load_semantic_type_raw_rows(
    conn: &Connection,
    recorded_by: &str,
    dep_b64: &str,
) -> ProjectionQueryResult<SemanticTypeRawRows> {
    match conn.query_row(
        "SELECT semantic_type_code
         FROM valid_events
         WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, dep_b64],
        |row| row.get::<_, Option<i64>>(0),
    ) {
        Ok(Some(code)) => Ok(SemanticTypeRawRows::UniqueKnown {
            semantic_type_code: Some(code),
        }),
        Ok(None) => {
            let blob_result = conn
                .query_row(
                    "SELECT blob FROM events WHERE event_id = ?1",
                    rusqlite::params![dep_b64],
                    |row| crate::db::sql_types::get_blob(row, 0),
                )
                .optional();
            let blob = match blob_result {
                Ok(blob) => blob,
                Err(err) if semantic_type_row_error_is_malformed(&err) => {
                    return Ok(SemanticTypeRawRows::Malformed);
                }
                Err(err) => return Err(err.into()),
            };
            let Some(blob) = blob else {
                return Ok(SemanticTypeRawRows::UniqueKnown {
                    semantic_type_code: None,
                });
            };
            let Some(code) = derive_semantic_type_code_from_blob(&blob)? else {
                return Ok(SemanticTypeRawRows::UniqueKnown {
                    semantic_type_code: None,
                });
            };
            conn.execute(
                "UPDATE valid_events
                 SET semantic_type_code = ?3
                 WHERE peer_id = ?1 AND event_id = ?2 AND semantic_type_code IS NULL",
                rusqlite::params![recorded_by, dep_b64, i64::from(code)],
            )?;
            Ok(SemanticTypeRawRows::UniqueKnown {
                semantic_type_code: Some(i64::from(code)),
            })
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            if global_endpoint_shared_is_valid(conn, dep_b64)? {
                return Ok(SemanticTypeRawRows::UniqueKnown {
                    semantic_type_code: Some(i64::from(
                        crate::event_modules::EVENT_TYPE_ENDPOINT_SHARED,
                    )),
                });
            }
            Ok(SemanticTypeRawRows::Missing)
        }
        Err(err) if semantic_type_row_error_is_malformed(&err) => {
            Ok(SemanticTypeRawRows::Malformed)
        }
        Err(err) => Err(err.into()),
    }
}

fn deleted_message_purges_dep(
    conn: &Connection,
    recorded_by: &str,
    parsed: &ParsedEvent,
    field_name: &str,
    dep_b64: &str,
) -> Result<Option<String>, rusqlite::Error> {
    let is_deleted_message_target = matches!(
        (parsed, field_name),
        (ParsedEvent::Reaction(_), "target_event_id")
            | (ParsedEvent::File(_), "message_id")
            | (ParsedEvent::Encrypted(_), "owner_event_id")
    );
    if !is_deleted_message_target {
        return Ok(None);
    }
    let deleted: bool = conn.query_row(
        "SELECT COUNT(*) > 0
         FROM deleted_messages
         WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, dep_b64],
        |row| row.get(0),
    )?;
    Ok(deleted.then(|| dep_b64.to_string()))
}

fn load_bootstrap_decision_context(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id_b64: &str,
) -> ProjectionQueryResult<Option<BootstrapDecisionContext>> {
    Ok(
        read_bootstrap_context(conn, recorded_by, invite_event_id_b64)
            .map_err(|err| -> Box<dyn std::error::Error> { err })?
            .map(|bc| BootstrapDecisionContext {
                workspace_id: bc.workspace_id,
                bootstrap_addrs: bc.bootstrap_addrs,
                bootstrap_spki_fingerprint: bc.bootstrap_spki_fingerprint,
            }),
    )
}

fn signer_user_mismatch_reason(
    conn: &Connection,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    author_id: &[u8; 32],
) -> Result<Option<String>, rusqlite::Error> {
    let raw_rows = load_content_authority_raw_rows(conn, frame, recorded_by)?;
    let context = normalize_content_authority(&raw_rows, &event_id_to_base64(author_id));
    Ok(content_authority_plan_to_signer_user_mismatch_reason(
        decide_content_authority_plan(&context),
    ))
}

fn deletion_signer_context(
    conn: &Connection,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
) -> Result<(Option<String>, bool, Option<String>), rusqlite::Error> {
    let raw_rows = load_deletion_signer_raw_rows(conn, frame, recorded_by)?;
    let context = normalize_deletion_signer(&raw_rows);
    Ok(deletion_signer_plan_to_context_fields(
        decide_deletion_signer_plan(&context),
    ))
}

fn load_valid_event_blob(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
) -> Result<Option<Vec<u8>>, rusqlite::Error> {
    conn.query_row(
        "SELECT e.blob
         FROM events e
         INNER JOIN valid_events v ON v.event_id = e.event_id
         WHERE v.peer_id = ?1 AND e.event_id = ?2",
        rusqlite::params![recorded_by, event_id_b64],
        |row| row.get(0),
    )
    .optional()
}

fn load_peer_shared_authority_raw_rows(
    conn: &Connection,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
) -> Result<PeerSharedAuthorityRawRows, rusqlite::Error> {
    let Some(current_signer) = frame.current_signer.as_ref() else {
        return Ok(PeerSharedAuthorityRawRows::MissingCurrentSigner);
    };
    if current_signer.semantic_type_code != EVENT_TYPE_DEVICE_INVITE {
        return Ok(PeerSharedAuthorityRawRows::UnsupportedSignerType {
            semantic_type_code: current_signer.semantic_type_code,
        });
    }

    let signer_b64 = current_signer.event_id.clone();
    let Some(blob) = load_valid_event_blob(conn, recorded_by, &signer_b64)? else {
        return Ok(PeerSharedAuthorityRawRows::MissingDeviceInviteBlob {
            signer_event_id: signer_b64,
        });
    };

    let device_invite = match parse_event(&blob) {
        Ok(ParsedEvent::DeviceInvite(device_invite)) => device_invite,
        Ok(ParsedEvent::Signed(signed)) => match parse_event(&signed.payload) {
            Ok(ParsedEvent::DeviceInvite(device_invite)) => device_invite,
            Ok(other) => {
                return Ok(PeerSharedAuthorityRawRows::MalformedDeviceInvite {
                    signer_event_id: signer_b64.clone(),
                    reason: format!(
                        "peer_shared signer {} resolved to unexpected event type {}",
                        signer_b64,
                        other.event_type_code()
                    ),
                })
            }
            Err(err) => {
                return Ok(PeerSharedAuthorityRawRows::MalformedDeviceInvite {
                    signer_event_id: signer_b64.clone(),
                    reason: format!(
                        "failed to parse signed device_invite signer {}: {}",
                        signer_b64, err
                    ),
                })
            }
        },
        Ok(other) => {
            return Ok(PeerSharedAuthorityRawRows::MalformedDeviceInvite {
                signer_event_id: signer_b64.clone(),
                reason: format!(
                    "peer_shared signer {} resolved to unexpected event type {}",
                    signer_b64,
                    other.event_type_code()
                ),
            })
        }
        Err(err) => {
            return Ok(PeerSharedAuthorityRawRows::MalformedDeviceInvite {
                signer_event_id: signer_b64.clone(),
                reason: format!(
                    "failed to parse device_invite signer {}: {}",
                    signer_b64, err
                ),
            })
        }
    };

    Ok(PeerSharedAuthorityRawRows::DeviceInviteSigner {
        signer_event_id: signer_b64,
        authorized_user_id: event_id_to_base64(&device_invite.authority_event_id),
    })
}

fn bootstrap_spki_already_peer_shared(
    conn: &Connection,
    recorded_by: &str,
    spki_fingerprint: &[u8; 32],
) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM peers_shared p
            WHERE p.recorded_by = ?1
              AND p.transport_fingerprint = ?2
        )",
        rusqlite::params![recorded_by, spki_fingerprint.as_slice()],
        |row| row.get(0),
    )
}

fn load_workspace_accepted_raw_rows(
    conn: &Connection,
    recorded_by: &str,
) -> rusqlite::Result<WorkspaceAcceptedRawRows> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT workspace_id
         FROM invites_accepted
         WHERE recorded_by = ?1
         ORDER BY workspace_id
         LIMIT 2",
    )?;
    let workspace_ids = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            crate::db::sql_types::get_text(row, 0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(WorkspaceAcceptedRawRows {
        workspace_ids,
        malformed: false,
    })
}

fn load_content_authority_raw_rows(
    conn: &Connection,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
) -> rusqlite::Result<ContentAuthorityRawRows> {
    let Some(current_signer) = frame.current_signer.as_ref() else {
        return Ok(ContentAuthorityRawRows::MissingCurrentSigner);
    };
    if current_signer.semantic_type_code != EVENT_TYPE_PEER_SHARED {
        return Ok(ContentAuthorityRawRows::UnsupportedSignerType {
            semantic_type_code: current_signer.semantic_type_code,
        });
    }

    let mut stmt = conn.prepare(
        "SELECT DISTINCT user_event_id
         FROM peers_shared
         WHERE recorded_by = ?1 AND event_id = ?2
         ORDER BY user_event_id
         LIMIT 2",
    )?;
    let mut rows = stmt.query(rusqlite::params![recorded_by, &current_signer.event_id])?;
    let mut signer_user_ids = Vec::new();
    let mut malformed = false;
    while let Some(row) = rows.next()? {
        match crate::db::sql_types::get_opt_text(row, 0) {
            Ok(user_id) => signer_user_ids.push(user_id),
            Err(_) => malformed = true,
        }
    }

    Ok(ContentAuthorityRawRows::PeerSharedSigner {
        signer_event_id: current_signer.event_id.clone(),
        signer_user_ids,
        malformed,
    })
}

fn load_admin_authority_raw_rows(
    conn: &Connection,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    admin: &AdminEvent,
) -> rusqlite::Result<AdminAuthorityRawRows> {
    let Some(current_signer) = frame.current_signer.as_ref() else {
        return Ok(AdminAuthorityRawRows::MissingCurrentSigner);
    };
    let user_event_id = event_id_to_base64(&admin.user_event_id);
    let authority_event_id = event_id_to_base64(&admin.authority_event_id);
    let mut stmt = conn.prepare(
        "SELECT DISTINCT public_key
         FROM users
         WHERE recorded_by = ?1 AND event_id = ?2
         ORDER BY public_key
         LIMIT 2",
    )?;
    let mut rows = stmt.query(rusqlite::params![recorded_by, &user_event_id])?;
    let mut user_public_keys = Vec::new();
    let mut malformed = false;
    while let Some(row) = rows.next()? {
        match crate::db::sql_types::get_blob(row, 0) {
            Ok(public_key) => user_public_keys.push(Some(public_key)),
            Err(_) => malformed = true,
        }
    }

    match current_signer.semantic_type_code {
        EVENT_TYPE_WORKSPACE => Ok(AdminAuthorityRawRows::WorkspaceSigner {
            authority_matches_signer: current_signer.event_id == authority_event_id,
            user_event_id,
            user_public_keys,
            malformed,
        }),
        EVENT_TYPE_PEER_SHARED => {
            let authority_matches_signer: bool = conn.query_row(
                "SELECT EXISTS(
                     SELECT 1
                     FROM peers_shared ps
                     JOIN users u
                       ON u.recorded_by = ps.recorded_by
                      AND u.event_id = ps.user_event_id
                     JOIN admins a
                       ON a.recorded_by = u.recorded_by
                      AND a.public_key = u.public_key
                     WHERE ps.recorded_by = ?1
                       AND ps.event_id = ?2
                       AND a.event_id = ?3
                 )",
                rusqlite::params![recorded_by, &current_signer.event_id, &authority_event_id],
                |row| row.get(0),
            )?;
            Ok(AdminAuthorityRawRows::PeerSharedSigner {
                authority_matches_signer,
                user_event_id,
                user_public_keys,
                malformed,
            })
        }
        semantic_type_code => Ok(AdminAuthorityRawRows::UnsupportedSignerType {
            semantic_type_code,
        }),
    }
}

fn load_deletion_signer_raw_rows(
    conn: &Connection,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
) -> rusqlite::Result<DeletionSignerRawRows> {
    let Some(current_signer) = frame.current_signer.as_ref() else {
        return Ok(DeletionSignerRawRows::MissingCurrentSigner);
    };
    match current_signer.semantic_type_code {
        EVENT_TYPE_ADMIN => Ok(DeletionSignerRawRows::AdminSigner),
        EVENT_TYPE_PEER_SHARED => {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT user_event_id
                 FROM peers_shared
                 WHERE recorded_by = ?1 AND event_id = ?2
                 ORDER BY user_event_id
                 LIMIT 2",
            )?;
            let mut rows = stmt.query(rusqlite::params![recorded_by, &current_signer.event_id])?;
            let mut signer_user_ids = Vec::new();
            let mut malformed = false;
            while let Some(row) = rows.next()? {
                match crate::db::sql_types::get_opt_text(row, 0) {
                    Ok(user_id) => signer_user_ids.push(user_id),
                    Err(_) => malformed = true,
                }
            }

            Ok(DeletionSignerRawRows::PeerSharedSigner {
                signer_event_id: current_signer.event_id.clone(),
                signer_user_ids,
                malformed,
            })
        }
        semantic_type_code => {
            Ok(DeletionSignerRawRows::UnsupportedSignerType { semantic_type_code })
        }
    }
}

fn load_workspace_decision_context_from_db(
    conn: &Connection,
    recorded_by: &str,
) -> ProjectionQueryResult<WorkspaceDecisionContext> {
    let raw_rows = load_workspace_accepted_raw_rows(conn, recorded_by)?;
    Ok(normalize_workspace_acceptance(&raw_rows))
}

fn load_matching_invite_secret_signing_key(
    conn: &Connection,
    recorded_by: &str,
    recipient_public_key: &[u8; 32],
) -> ProjectionQueryResult<Option<SigningKey>> {
    let mut stmt = conn.prepare(
        "SELECT private_key
         FROM invite_secrets
         WHERE recorded_by = ?1
         ORDER BY created_at DESC, event_id DESC",
    )?;
    let rows = stmt.query_map(rusqlite::params![recorded_by], |row| {
        crate::db::sql_types::get_blob(row, 0)
    })?;
    for row in rows {
        let private_key_bytes = row?;
        if private_key_bytes.len() != 32 {
            continue;
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&private_key_bytes);
        let signing_key = SigningKey::from_bytes(&key_arr);
        if signing_key.verifying_key().to_bytes() == *recipient_public_key {
            return Ok(Some(signing_key));
        }
    }
    Ok(None)
}

impl ProjectionQueries for Connection {
    fn load_dep_result(
        &self,
        recorded_by: &str,
        parsed: &ParsedEvent,
        field_name: &str,
        dep_id: &EventId,
    ) -> ProjectionQueryResult<DepLoadResult> {
        let dep_b64 = event_id_to_base64(dep_id);
        let deleted_message_purge =
            deleted_message_purges_dep(self, recorded_by, parsed, field_name, &dep_b64)?;
        let semantic_type_rows = if deleted_message_purge.is_some() {
            SemanticTypeRawRows::Missing
        } else {
            load_semantic_type_raw_rows(self, recorded_by, &dep_b64)?
        };

        Ok(decide_dep_load_plan(&DepLoadDecisionContext {
            deleted_message_purge,
            semantic_type_rows,
        }))
    }

    fn load_key_secret_bytes(
        &self,
        recorded_by: &str,
        key_event_id: &[u8; 32],
    ) -> ProjectionQueryResult<Option<[u8; 32]>> {
        let key_b64 = event_id_to_base64(key_event_id);
        let key_bytes: Option<Vec<u8>> = self
            .query_row(
                "SELECT key_bytes FROM key_secrets WHERE recorded_by = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, key_b64],
                |row| crate::db::sql_types::get_blob(row, 0),
            )
            .optional()?;
        let Some(key_bytes) = key_bytes else {
            return Ok(None);
        };
        if key_bytes.len() != 32 {
            return Ok(None);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&key_bytes);
        Ok(Some(out))
    }

    fn load_workspace_context(
        &self,
        _frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        _workspace: &WorkspaceEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let context = load_workspace_decision_context_from_db(self, recorded_by)?;
        Ok(build_workspace_projector_decision_context(&context))
    }

    fn load_workspace_decision_context(
        &self,
        _frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        _workspace: &WorkspaceEvent,
    ) -> ProjectionQueryResult<WorkspaceDecisionContext> {
        load_workspace_decision_context_from_db(self, recorded_by)
    }

    fn load_admin_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        admin: &AdminEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let raw_rows = load_admin_authority_raw_rows(self, frame, recorded_by, admin)?;
        let context = normalize_admin_authority(&raw_rows, &admin.public_key);
        Ok(ProjectorDecisionContext {
            admin_user_key_mismatch_reason: admin_authority_plan_to_mismatch_reason(
                decide_admin_authority_plan(&context),
            ),
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_peer_shared_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        peer_shared: &PeerSharedEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let raw_rows = load_peer_shared_authority_raw_rows(self, frame, recorded_by)?;
        let claimed_user_id = event_id_to_base64(&peer_shared.user_event_id);
        let authority_context = normalize_peer_shared_authority(&raw_rows, &claimed_user_id);

        let endpoint_shared_event_id_b64 =
            event_id_to_base64(&peer_shared.endpoint_shared_event_id);
        let endpoint_shared_row =
            load_endpoint_shared_by_event_id(self, &endpoint_shared_event_id_b64)
                .map_err(|e| -> Box<dyn std::error::Error> { e })?;

        Ok(ProjectorDecisionContext {
            peer_shared_user_mismatch_reason: peer_shared_authority_plan_to_mismatch_reason(
                decide_peer_shared_authority_plan(&authority_context),
            ),
            peer_shared_endpoint_id: endpoint_shared_row
                .as_ref()
                .map(|row| row.endpoint_id.clone()),
            peer_shared_endpoint_binding_reason: match endpoint_shared_row {
                Some(_) => None,
                None => Some(format!(
                    "no projected endpoint_shared row for {}",
                    endpoint_shared_event_id_b64
                )),
            },
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_user_invite_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        _user_invite: &UserInviteEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let mut ctx = ProjectorDecisionContext::default();

        ctx.is_local_create = match self.query_row(
            "SELECT source FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
            |row| crate::db::sql_types::get_text(row, 0),
        ) {
            Ok(source) => source == "local" || source == "local_create",
            Err(_) => false,
        };

        if let Some(current_signer) = frame.current_signer.as_ref() {
            if current_signer.semantic_type_code == EVENT_TYPE_PEER_SHARED {
                let signer_b64 = current_signer.event_id.clone();
                let authority_b64 = event_id_to_base64(&_user_invite.authority_event_id);
                let authority_matches_signer: bool = self.query_row(
                    "SELECT EXISTS(
                         SELECT 1
                         FROM peers_shared ps
                         JOIN users u
                           ON u.recorded_by = ps.recorded_by
                          AND u.event_id = ps.user_event_id
                         JOIN admins a
                           ON a.recorded_by = u.recorded_by
                          AND a.public_key = u.public_key
                         WHERE ps.recorded_by = ?1
                           AND ps.event_id = ?2
                           AND a.event_id = ?3
                     )",
                    rusqlite::params![recorded_by, signer_b64, authority_b64],
                    |row| row.get(0),
                )?;
                ctx.invite_authority_matches_signer = Some(authority_matches_signer);
            }
        }

        ctx.bootstrap_context = load_bootstrap_decision_context(self, recorded_by, event_id_b64)?;
        Ok(ctx)
    }

    fn load_device_invite_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        device_invite: &DeviceInviteEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let mut ctx = ProjectorDecisionContext::default();

        ctx.is_local_create = match self.query_row(
            "SELECT source FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
            |row| crate::db::sql_types::get_text(row, 0),
        ) {
            Ok(source) => source == "local" || source == "local_create",
            Err(_) => false,
        };

        if let Some(current_signer) = frame.current_signer.as_ref() {
            if current_signer.semantic_type_code == EVENT_TYPE_PEER_SHARED {
                let signer_b64 = current_signer.event_id.clone();
                let authority_b64 = event_id_to_base64(&device_invite.authority_event_id);
                let authority_matches_signer: bool = self.query_row(
                    "SELECT EXISTS(
                         SELECT 1
                         FROM peers_shared
                         WHERE recorded_by = ?1
                           AND event_id = ?2
                           AND user_event_id = ?3
                     )",
                    rusqlite::params![recorded_by, signer_b64, authority_b64],
                    |row| row.get(0),
                )?;
                ctx.invite_authority_matches_signer = Some(authority_matches_signer);
            }
        }

        ctx.bootstrap_context = load_bootstrap_decision_context(self, recorded_by, event_id_b64)?;
        Ok(ctx)
    }

    fn load_message_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        message: &MessageEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let signer_user_mismatch_reason =
            signer_user_mismatch_reason(self, frame, recorded_by, &message.author_id)?;

        let mut stmt = self.prepare_cached(
            "SELECT deletion_event_id, author_id, authorized_by_admin, created_at
             FROM deletion_intents
             WHERE recorded_by = ?1
               AND target_id = ?2
             ORDER BY deletion_event_id",
        )?;
        let deletion_intents = stmt
            .query_map(rusqlite::params![recorded_by, event_id_b64], |row| {
                Ok(DeletionIntentInfo {
                    deletion_event_id: crate::db::sql_types::get_text(row, 0)?,
                    author_id: crate::db::sql_types::get_text(row, 1)?,
                    authorized_by_admin: row.get::<_, i64>(2)? != 0,
                    created_at: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ProjectorDecisionContext {
            signer_user_mismatch_reason,
            deletion_intents,
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_message_deletion_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        message_deletion: &MessageDeletionEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let mut ctx = ProjectorDecisionContext::default();
        let (deletion_signer_user_id, deletion_signer_is_admin, deletion_signer_reject_reason) =
            deletion_signer_context(self, frame, recorded_by)?;
        ctx.deletion_signer_user_id = deletion_signer_user_id;
        ctx.deletion_signer_is_admin = deletion_signer_is_admin;
        ctx.deletion_signer_reject_reason = deletion_signer_reject_reason;

        let target_b64 = event_id_to_base64(&message_deletion.target_event_id);
        ctx.target_tombstone_author = self
            .query_row(
                "SELECT author_id FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![recorded_by, &target_b64],
                |row| crate::db::sql_types::get_text(row, 0),
            )
            .optional()?;

        ctx.target_message_author = self
            .query_row(
                "SELECT author_id FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![recorded_by, &target_b64],
                |row| crate::db::sql_types::get_text(row, 0),
            )
            .optional()?;

        if ctx.target_message_author.is_none() && ctx.target_tombstone_author.is_none() {
            ctx.target_is_non_message = self.query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &target_b64],
                |row| row.get(0),
            )?;
        }

        Ok(ctx)
    }

    fn load_reaction_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        reaction: &ReactionEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let signer_user_mismatch_reason =
            signer_user_mismatch_reason(self, frame, recorded_by, &reaction.author_id)?;

        Ok(ProjectorDecisionContext {
            signer_user_mismatch_reason,
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_file_context(
        &self,
        _frame: &ProjectionFrameContext,
        _recorded_by: &str,
        _event_id_b64: &str,
        _file: &FileEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        Ok(ProjectorDecisionContext::default())
    }

    fn load_file_slice_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        file_slice: &FileSliceEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let mut ctx = ProjectorDecisionContext::default();
        let file_id_b64 = event_id_to_base64(&file_slice.file_id);

        if let Some(owner_event_id_b64) = frame.current_owner_event_id.as_deref() {
            let owner_deleted: bool = self.query_row(
                "SELECT COUNT(*) > 0
                 FROM deleted_messages
                 WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![recorded_by, owner_event_id_b64],
                |row| row.get(0),
            )?;
            if owner_deleted {
                ctx.purge_message_event_id = Some(owner_event_id_b64.to_string());
            }
        }

        let mut desc_stmt = self.prepare(
            "SELECT event_id, message_id, signer_event_id, key_event_id, root_hash, blob_bytes, slice_bytes
             FROM files
             WHERE recorded_by = ?1 AND file_id = ?2
             ORDER BY created_at ASC, event_id ASC",
        )?;
        ctx.file_descriptors = desc_stmt
            .query_map(rusqlite::params![recorded_by, &file_id_b64], |row| {
                let root_hash_blob = crate::db::sql_types::get_blob(row, 4)?;
                let mut root_hash = [0u8; 32];
                if root_hash_blob.len() == 32 {
                    root_hash.copy_from_slice(&root_hash_blob);
                }
                Ok(FileDescriptorInfo {
                    event_id: crate::db::sql_types::get_text(row, 0)?,
                    message_id: crate::db::sql_types::get_text(row, 1)?,
                    signer_event_id: crate::db::sql_types::get_text(row, 2)?,
                    key_event_id: crate::db::sql_types::get_text(row, 3)?,
                    root_hash,
                    blob_bytes: row.get::<_, i64>(5)? as u64,
                    slice_bytes: row.get::<_, i64>(6)? as u32,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        if ctx.purge_message_event_id.is_none() {
            for descriptor in &ctx.file_descriptors {
                let message_deleted: bool = self.query_row(
                    "SELECT COUNT(*) > 0
                     FROM deleted_messages
                     WHERE recorded_by = ?1 AND message_id = ?2",
                    rusqlite::params![recorded_by, &descriptor.message_id],
                    |row| row.get(0),
                )?;
                if message_deleted {
                    ctx.purge_message_event_id = Some(descriptor.message_id.clone());
                    break;
                }
            }
        }

        ctx.existing_file_slice = match self.query_row(
            "SELECT event_id, descriptor_event_id
             FROM file_slices
             WHERE recorded_by = ?1 AND file_id = ?2 AND slice_number = ?3",
            rusqlite::params![recorded_by, &file_id_b64, file_slice.slice_number as i64],
            |row| {
                Ok((
                    crate::db::sql_types::get_text(row, 0)?,
                    crate::db::sql_types::get_text(row, 1)?,
                ))
            },
        ) {
            Ok(v) => Some(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.into()),
        };

        Ok(ctx)
    }

    fn load_invite_accepted_context(
        &self,
        _frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        invite_accepted: &InviteAcceptedEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let mut ctx = ProjectorDecisionContext::default();
        let invite_event_id_b64 = event_id_to_base64(&invite_accepted.invite_event_id);
        let workspace_id_b64 = event_id_to_base64(&invite_accepted.workspace_id);

        ctx.has_local_invite_secret = self.query_row(
            "SELECT EXISTS(
                     SELECT 1
                     FROM invite_secrets
                     WHERE recorded_by = ?1
                       AND invite_event_id = ?2
                       AND length(private_key) = 32
                 )",
            rusqlite::params![recorded_by, &invite_event_id_b64],
            |row| row.get(0),
        )?;
        ctx.peer_shared_transport_identity_active =
            peer_has_creds_with_source(self, recorded_by, CRED_SOURCE_PEER_SHARED).unwrap_or(false);

        if let Some(bc) = load_bootstrap_decision_context(self, recorded_by, &invite_event_id_b64)?
        {
            if bc.workspace_id != workspace_id_b64 {
                ctx.invite_accepted_link_workspace_mismatch_reason = Some(
                    "invite_accepted workspace_id does not match locally recorded invite-link workspace"
                        .to_string(),
                );
            }
            ctx.bootstrap_spki_already_peer_shared = bootstrap_spki_already_peer_shared(
                self,
                recorded_by,
                &bc.bootstrap_spki_fingerprint,
            )?;
            ctx.bootstrap_context = Some(bc);
        } else if invite_accepted.invite_event_id != invite_accepted.workspace_id {
            ctx.invite_accepted_link_workspace_mismatch_reason = Some(
                "invite_accepted missing locally recorded invite-link workspace binding"
                    .to_string(),
            );
        }

        Ok(ctx)
    }

    fn load_removal_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        removal: &RemovalEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        use topo_verus_proofs::state::projection::decision_context::{
            decide_removal_signer_plan_core, decide_removal_target_plan_core,
            normalize_removal_signer_core, RemovalSignerPlanCore, RemovalSignerRowsCore,
            RemovalTargetPlanCore, RemovalTargetRowsCore,
        };

        let mut ctx = ProjectorDecisionContext::default();

        let signer_rows = match frame.current_signer.as_ref() {
            Some(current_signer) if current_signer.semantic_type_code == EVENT_TYPE_PEER_SHARED => {
                let signer_b64 = current_signer.event_id.clone();
                let is_admin: bool = self.query_row(
                    "SELECT EXISTS(
                         SELECT 1
                         FROM peers_shared ps
                         JOIN users u
                           ON u.recorded_by = ps.recorded_by
                          AND u.event_id = ps.user_event_id
                         JOIN admins a
                           ON a.recorded_by = u.recorded_by
                          AND a.public_key = u.public_key
                         WHERE ps.recorded_by = ?1
                           AND ps.event_id = ?2
                     )",
                    rusqlite::params![recorded_by, signer_b64],
                    |row| row.get(0),
                )?;
                RemovalSignerRowsCore::PeerSharedSigner { is_admin }
            }
            Some(_) => RemovalSignerRowsCore::UnsupportedSignerType,
            None => RemovalSignerRowsCore::MissingCurrentSigner,
        };
        ctx.removal_signer_reject_reason = match decide_removal_signer_plan_core(
            normalize_removal_signer_core(signer_rows),
        ) {
            RemovalSignerPlanCore::Ready => None,
            RemovalSignerPlanCore::RejectMissingCurrentSigner => {
                Some("removal missing current signer envelope".to_string())
            }
            RemovalSignerPlanCore::RejectUnsupportedSignerType => {
                Some("removal signer must be peer_shared".to_string())
            }
            RemovalSignerPlanCore::RejectNonAdminPeerShared => {
                Some("removal signer must be an admin peer_shared identity".to_string())
            }
        };

        let target_b64 = event_id_to_base64(&removal.removed_member_ref);
        let semantic_type_code: Option<i64> = self
            .query_row(
                "SELECT semantic_type_code
                 FROM valid_events
                 WHERE peer_id = ?1
                   AND event_id = ?2
                 LIMIT 1",
                rusqlite::params![recorded_by, &target_b64],
                |row| row.get(0),
            )
            .optional()?;
        let target_rows = match semantic_type_code {
            Some(code) if code == i64::from(crate::event_modules::EVENT_TYPE_USER) => {
                RemovalTargetRowsCore::User
            }
            Some(code) if code == i64::from(EVENT_TYPE_PEER_SHARED) => {
                RemovalTargetRowsCore::Peer
            }
            Some(_) => RemovalTargetRowsCore::Unsupported,
            None => RemovalTargetRowsCore::Missing,
        };
        ctx.removal_target_kind = match decide_removal_target_plan_core(target_rows) {
            RemovalTargetPlanCore::ReadyUser => Some(RemovalTargetKind::User),
            RemovalTargetPlanCore::ReadyPeer => Some(RemovalTargetKind::Peer),
            RemovalTargetPlanCore::Missing | RemovalTargetPlanCore::RejectUnsupported => None,
        };

        Ok(ctx)
    }

    fn load_key_request_context(
        &self,
        _frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        key_request: &KeyRequestEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let delivery_target_b64 = event_id_to_base64(&key_request.delivery_target_id);
        let key_request_suppress_sharing = self.query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM key_shared
                 WHERE recorded_by = ?1
                   AND delivery_target_id = ?2
             )",
            rusqlite::params![recorded_by, &delivery_target_b64],
            |row| row.get(0),
        )?;

        Ok(ProjectorDecisionContext {
            key_request_suppress_sharing,
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_key_shared_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        key_shared: &KeySharedEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let recipient_b64 = event_id_to_base64(&key_shared.recipient_event_id);
        let unwrap_key_b64 = event_id_to_base64(&key_shared.unwrap_key_event_id);

        let peer_secret_row: Option<Vec<u8>> = self
            .query_row(
                "SELECT private_key
                 FROM peer_secrets
                 WHERE recorded_by = ?1
                   AND event_id = ?2
                   AND signer_event_id = ?3
                 LIMIT 1",
                rusqlite::params![recorded_by, &unwrap_key_b64, &recipient_b64],
                |row| crate::db::sql_types::get_blob(row, 0),
            )
            .optional()?;

        let invite_secret_row: Option<Vec<u8>> = self
            .query_row(
                "SELECT private_key
                 FROM invite_secrets
                 WHERE recorded_by = ?1
                   AND event_id = ?2
                   AND invite_event_id = ?3
                 LIMIT 1",
                rusqlite::params![recorded_by, &unwrap_key_b64, &recipient_b64],
                |row| crate::db::sql_types::get_blob(row, 0),
            )
            .optional()?;

        let private_key_bytes = match peer_secret_row.or(invite_secret_row) {
            Some(private_key_bytes) => private_key_bytes,
            None => return Ok(ProjectorDecisionContext::default()),
        };
        if private_key_bytes.len() != 32 {
            return Ok(ProjectorDecisionContext::default());
        }

        let Some(current_signer) = frame.current_signer.as_ref() else {
            return Ok(ProjectorDecisionContext::default());
        };
        let Some(current_signer_event_id) = event_id_from_base64(&current_signer.event_id) else {
            return Ok(ProjectorDecisionContext::default());
        };

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&private_key_bytes);
        let local_signing_key = SigningKey::from_bytes(&key_arr);

        let sender_key = match resolve_signer_key(self, recorded_by, &current_signer_event_id)? {
            SignerResolution::Found(k) => k,
            _ => return Ok(ProjectorDecisionContext::default()),
        };
        let sender_pub = match VerifyingKey::from_bytes(&sender_key.public_key) {
            Ok(vk) => vk,
            Err(_) => return Ok(ProjectorDecisionContext::default()),
        };

        let plaintext_key =
            unwrap_key_from_sender(&local_signing_key, &sender_pub, &key_shared.wrapped_key);

        Ok(ProjectorDecisionContext {
            unwrapped_secret_material: Some(UnwrappedSecretMaterial {
                key_bytes: plaintext_key,
            }),
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_key_rotation_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        key_rotation: &KeyRotationEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let Some((local_recipient_event_id, local_signing_key)) = crate::event_modules::peer_shared::load_local_peer_signer(self, recorded_by)
            .map_err(|err| -> Box<dyn std::error::Error> { err.to_string().into() })?
        else {
            return Ok(ProjectorDecisionContext::default());
        };
        let Some(slot_index) = key_rotation
            .recipient_slots
            .iter()
            .position(|slot| *slot == local_recipient_event_id)
        else {
            return Ok(ProjectorDecisionContext::default());
        };
        let Some(current_signer) = frame.current_signer.as_ref() else {
            return Ok(ProjectorDecisionContext::default());
        };
        let Some(current_signer_event_id) = event_id_from_base64(&current_signer.event_id) else {
            return Ok(ProjectorDecisionContext::default());
        };

        let sender_key = match resolve_signer_key(self, recorded_by, &current_signer_event_id)? {
            SignerResolution::Found(k) => k,
            _ => return Ok(ProjectorDecisionContext::default()),
        };
        let sender_pub = match VerifyingKey::from_bytes(&sender_key.public_key) {
            Ok(vk) => vk,
            Err(_) => return Ok(ProjectorDecisionContext::default()),
        };

        let plaintext_key = unwrap_key_from_sender(
            &local_signing_key,
            &sender_pub,
            &key_rotation.wrapped_keys[slot_index],
        );

        Ok(ProjectorDecisionContext {
            unwrapped_secret_material: Some(UnwrappedSecretMaterial {
                key_bytes: plaintext_key,
            }),
            ..ProjectorDecisionContext::default()
        })
    }

    fn load_key_history_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        key_history: &KeyHistoryEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let Some(local_signing_key) =
            load_matching_invite_secret_signing_key(self, recorded_by, &key_history.recipient_public_key)?
        else {
            return Ok(ProjectorDecisionContext::default());
        };
        let Some(current_signer) = frame.current_signer.as_ref() else {
            return Ok(ProjectorDecisionContext::default());
        };
        let Some(current_signer_event_id) = event_id_from_base64(&current_signer.event_id) else {
            return Ok(ProjectorDecisionContext::default());
        };
        let sender_key = match resolve_signer_key(self, recorded_by, &current_signer_event_id)? {
            SignerResolution::Found(k) => k,
            _ => return Ok(ProjectorDecisionContext::default()),
        };
        let sender_pub = match VerifyingKey::from_bytes(&sender_key.public_key) {
            Ok(vk) => vk,
            Err(_) => return Ok(ProjectorDecisionContext::default()),
        };

        let plaintext = match decrypt_bundle_from_sender(
            &local_signing_key,
            &sender_pub,
            &key_history.nonce,
            &key_history.ciphertext,
            &key_history.auth_tag,
        ) {
            Ok(plaintext) => plaintext,
            Err(_) => return Ok(ProjectorDecisionContext::default()),
        };

        let entries = match crate::event_modules::key_history::decode_key_history_plaintext(&plaintext)
        {
            Ok(entries) => entries,
            Err(_) => return Ok(ProjectorDecisionContext::default()),
        };

        Ok(ProjectorDecisionContext {
            unwrapped_key_history_material: entries
                .into_iter()
                .map(|entry| HistoricalKeyMaterial {
                    key_event_id: entry.key_event_id,
                    key_bytes: entry.key_bytes,
                })
                .collect(),
            ..ProjectorDecisionContext::default()
        })
    }

    // ── Per-Message FS context loaders ────────────────────────────

    /// Pre-check for `message_key` projection: is the owning message
    /// durably tombstoned (`deleted_messages` row present)? If yes,
    /// the projector will self-drop without materializing K_m.
    ///
    /// Deliberately checks `deleted_messages` only, not
    /// `deletion_intents` — non-authorized intents are not terminal
    /// and would produce false-positive drops. (Authorization for
    /// admin-authored pre-create deletions is a follow-up enhancement
    /// that requires resolving the intent's signer authority here.)
    ///
    /// The K_m materialization path (query `key_secrets` for
    /// `k_bundle_local_event_id`, AEAD-decrypt `wrapped_k_m` under
    /// K_bundle) is intentionally deferred to the next pass — the
    /// crypto wiring requires surfacing AES-GCM decrypt against the
    /// event's nonce, which belongs alongside the producer-unwrap
    /// work below.
    fn load_message_key_context(
        &self,
        _frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        message_key: &crate::event_modules::MessageKeyEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let owning_b64 = event_id_to_base64(&message_key.owning_message_event_id);
        let tombstoned: bool = self
            .query_row(
                "SELECT COUNT(*) > 0 FROM deleted_messages
                 WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![recorded_by, owning_b64],
                |row| row.get(0),
            )
            .unwrap_or(false);

        // Look up the local deterministic KeySecret(K_bundle) row; if
        // present, surface K_bundle bytes so the projector can AEAD-
        // decrypt wrapped_k_m and emit KeySecret(K_m).
        let k_bundle = self
            .load_key_secret_bytes(recorded_by, &message_key.k_bundle_local_event_id)?;

        Ok(ProjectorDecisionContext {
            owning_message_tombstoned: Some(tombstoned),
            unwrapped_k_bundle: k_bundle,
            ..ProjectorDecisionContext::default()
        })
    }

    /// Pattern (b): scan `wrap_privkeys` for a row whose pubkey
    /// event id matches one of the broadcast's recipient slots.
    /// If found, surface the RAW local signing key + sender's
    /// verifying key + wrapped slot bytes to the projector. The
    /// projector runs `unwrap_key_from_sender` (deterministic, pure).
    fn load_key_broadcast_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        key_broadcast: &crate::event_modules::KeyBroadcastEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        resolve_raw_wrap_material(
            self,
            frame,
            recorded_by,
            &key_broadcast.recipient_pubkey_slots,
            &key_broadcast.wrapped_bundle_slots,
        )
    }

    /// Pattern (b): same shape as `load_key_broadcast_context`, but
    /// the bundle has a single recipient slot + N historical slots.
    /// Populates raw unwrap material for the anchor; the projector
    /// decrypts each historical slot AEAD-style under the recovered
    /// anchor K_bundle.
    fn load_key_history_bundle_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        key_history_bundle: &crate::event_modules::KeyHistoryBundleEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let recipient_slots = vec![key_history_bundle.recipient_wrappubkey_event_id];
        let wrapped_slots = vec![key_history_bundle.wrapped_anchor_bundle];
        let mut ctx = resolve_raw_wrap_material(
            self,
            frame,
            recorded_by,
            &recipient_slots,
            &wrapped_slots,
        )?;
        ctx.history_payload = Some(crate::projection::projector::HistoryBundlePayload {
            nonce: key_history_bundle.nonce.to_vec(),
            ciphertext: key_history_bundle.historical_slots.clone(),
            auth_tag: [0u8; 16], // AEAD tag is trailing 16 bytes of ciphertext
        });
        Ok(ctx)
    }

    /// Pattern (b): targeted 1×1 heal — one recipient slot, one
    /// wrapped K_bundle. Resolves raw wrap material; projector
    /// runs `unwrap_key_from_sender`.
    fn load_key_bundle_share_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        key_bundle_share: &crate::event_modules::KeyBundleShareEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let recipient_slots = vec![key_bundle_share.recipient_wrappubkey_event_id];
        let wrapped_slots = vec![key_bundle_share.wrapped_k_bundle];
        resolve_raw_wrap_material(
            self,
            frame,
            recorded_by,
            &recipient_slots,
            &wrapped_slots,
        )
    }
}

/// Pattern-(b) helper: given parallel arrays of recipient pubkey
/// event ids + wrapped-key slots, find the slot that targets a
/// locally-held privkey (`wrap_privkeys`), resolve the sender's
/// verifying key via `resolve_signer_key(frame.current_signer)`,
/// and return a `ProjectorDecisionContext` carrying the RAW bytes
/// for `unwrap_key_from_sender`. The projector does the crypto.
fn resolve_raw_wrap_material(
    conn: &Connection,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    recipient_pubkey_slots: &[[u8; 32]],
    wrapped_slots: &[[u8; 32]],
) -> ProjectionQueryResult<ProjectorDecisionContext> {
    if recipient_pubkey_slots.len() != wrapped_slots.len() {
        return Ok(ProjectorDecisionContext::default());
    }

    // Scan recipient slots against our locally-emitted WrapPubkeys.
    // `wrap_privkeys` is local-only; each row is
    // (pubkey_event_id, privkey, valid_until_ms, created_at_ms).
    let mut matched: Option<(Vec<u8>, [u8; 32])> = None;
    for (slot_idx, recipient_event_id) in recipient_pubkey_slots.iter().enumerate() {
        if *recipient_event_id == [0u8; 32] {
            continue;
        }
        let recipient_b64 = event_id_to_base64(recipient_event_id);
        let privkey: Option<Vec<u8>> = conn
            .query_row(
                "SELECT privkey FROM wrap_privkeys WHERE pubkey_event_id = ?1",
                rusqlite::params![recipient_b64],
                |row| crate::db::sql_types::get_blob(row, 0),
            )
            .optional()?;
        if let Some(privkey_bytes) = privkey {
            if privkey_bytes.len() == 32 {
                matched = Some((privkey_bytes, wrapped_slots[slot_idx]));
                break;
            }
        }
    }

    let (privkey_bytes, wrapped_slot) = match matched {
        Some(v) => v,
        None => return Ok(ProjectorDecisionContext::default()),
    };

    let mut local_sk = [0u8; 32];
    local_sk.copy_from_slice(&privkey_bytes);

    let Some(current_signer) = frame.current_signer.as_ref() else {
        return Ok(ProjectorDecisionContext::default());
    };
    let Some(current_signer_event_id) = event_id_from_base64(&current_signer.event_id) else {
        return Ok(ProjectorDecisionContext::default());
    };
    let sender_key = match resolve_signer_key(conn, recorded_by, &current_signer_event_id)? {
        SignerResolution::Found(k) => k,
        _ => return Ok(ProjectorDecisionContext::default()),
    };

    Ok(ProjectorDecisionContext {
        local_signing_key_bytes: Some(local_sk),
        sender_verifying_key_bytes: Some(sender_key.public_key),
        wrapped_key_bytes: Some(wrapped_slot),
        ..ProjectorDecisionContext::default()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::EVENT_TYPE_MESSAGE;

    fn workspace_id(byte: u8) -> String {
        event_id_to_base64(&[byte; 32])
    }

    fn event_id_b64(byte: u8) -> String {
        event_id_to_base64(&[byte; 32])
    }

    fn content_authority_raw(
        signer_event_id: String,
        signer_user_ids: Vec<Option<String>>,
    ) -> ContentAuthorityRawRows {
        ContentAuthorityRawRows::PeerSharedSigner {
            signer_event_id,
            signer_user_ids,
            malformed: false,
        }
    }

    fn admin_authority_raw(
        authority_matches_signer: bool,
        user_event_id: String,
        user_public_keys: Vec<Option<Vec<u8>>>,
    ) -> AdminAuthorityRawRows {
        AdminAuthorityRawRows::WorkspaceSigner {
            authority_matches_signer,
            user_event_id,
            user_public_keys,
            malformed: false,
        }
    }

    fn admin_authority_peer_raw(
        authority_matches_signer: bool,
        user_event_id: String,
        user_public_keys: Vec<Option<Vec<u8>>>,
    ) -> AdminAuthorityRawRows {
        AdminAuthorityRawRows::PeerSharedSigner {
            authority_matches_signer,
            user_event_id,
            user_public_keys,
            malformed: false,
        }
    }

    fn deletion_signer_raw(
        signer_event_id: String,
        signer_user_ids: Vec<Option<String>>,
    ) -> DeletionSignerRawRows {
        DeletionSignerRawRows::PeerSharedSigner {
            signer_event_id,
            signer_user_ids,
            malformed: false,
        }
    }

    #[test]
    fn workspace_acceptance_blocks_when_missing() {
        let context = normalize_workspace_acceptance(&WorkspaceAcceptedRawRows {
            workspace_ids: vec![],
            malformed: false,
        });

        assert_eq!(
            decide_workspace_context_plan(&context, &workspace_id(1)),
            WorkspaceContextPlan::BlockOnAcceptedWorkspace
        );
    }

    #[test]
    fn workspace_acceptance_allows_multiple_invites_for_same_workspace() {
        let workspace_id = workspace_id(1);
        let context = normalize_workspace_acceptance(&WorkspaceAcceptedRawRows {
            workspace_ids: vec![workspace_id.clone(), workspace_id.clone()],
            malformed: false,
        });

        assert_eq!(
            context,
            WorkspaceDecisionContext::UniqueAcceptedWorkspace {
                workspace_id: workspace_id.clone()
            }
        );
        assert_eq!(
            decide_workspace_context_plan(&context, &workspace_id),
            WorkspaceContextPlan::Ready {
                accepted_workspace_id: workspace_id
            }
        );
    }

    #[test]
    fn workspace_acceptance_rejects_distinct_workspace_bindings() {
        let context = normalize_workspace_acceptance(&WorkspaceAcceptedRawRows {
            workspace_ids: vec![workspace_id(1), workspace_id(2)],
            malformed: false,
        });

        assert_eq!(
            context,
            WorkspaceDecisionContext::RejectAmbiguousAcceptedWorkspace
        );
        assert!(matches!(
            decide_workspace_context_plan(&context, &workspace_id(1)),
            WorkspaceContextPlan::Reject { reason } if reason.contains("ambiguous")
        ));
    }

    #[test]
    fn workspace_acceptance_rejects_malformed_workspace_binding() {
        let context = normalize_workspace_acceptance(&WorkspaceAcceptedRawRows {
            workspace_ids: vec!["not-base64".to_string()],
            malformed: false,
        });

        assert_eq!(
            context,
            WorkspaceDecisionContext::RejectMalformedAcceptedWorkspace
        );
        assert!(matches!(
            decide_workspace_context_plan(&context, &workspace_id(1)),
            WorkspaceContextPlan::Reject { reason } if reason.contains("malformed")
        ));
    }

    #[test]
    fn workspace_context_plan_rejects_mismatched_workspace_event() {
        let context = WorkspaceDecisionContext::UniqueAcceptedWorkspace {
            workspace_id: workspace_id(1),
        };

        assert!(matches!(
            decide_workspace_context_plan(&context, &workspace_id(2)),
            WorkspaceContextPlan::Reject { reason } if reason.contains("does not match")
        ));
    }

    #[test]
    fn content_authority_allows_unique_matching_signer_user() {
        let signer_id = event_id_b64(1);
        let author_id = event_id_b64(2);
        let context = normalize_content_authority(
            &content_authority_raw(signer_id.clone(), vec![Some(author_id.clone())]),
            &author_id,
        );

        assert_eq!(
            context,
            ContentAuthorityDecisionContext::UniqueSignerUser {
                signer_event_id: signer_id,
                signer_user_id: author_id.clone(),
                author_id
            }
        );
        assert_eq!(
            decide_content_authority_plan(&context),
            ContentAuthorityPlan::Ready
        );
    }

    #[test]
    fn content_authority_allows_duplicate_matching_signer_user() {
        let signer_id = event_id_b64(1);
        let author_id = event_id_b64(2);
        let context = normalize_content_authority(
            &content_authority_raw(
                signer_id.clone(),
                vec![Some(author_id.clone()), Some(author_id.clone())],
            ),
            &author_id,
        );

        assert_eq!(
            context,
            ContentAuthorityDecisionContext::UniqueSignerUser {
                signer_event_id: signer_id,
                signer_user_id: author_id.clone(),
                author_id
            }
        );
        assert_eq!(
            decide_content_authority_plan(&context),
            ContentAuthorityPlan::Ready
        );
    }

    #[test]
    fn content_authority_rejects_mismatched_signer_user() {
        let signer_id = event_id_b64(1);
        let context = normalize_content_authority(
            &content_authority_raw(signer_id, vec![Some(event_id_b64(2))]),
            &event_id_b64(3),
        );

        assert!(matches!(
            decide_content_authority_plan(&context),
            ContentAuthorityPlan::Reject { reason } if reason.contains("author_id claims")
        ));
    }

    #[test]
    fn content_authority_rejects_missing_signer_user() {
        let signer_id = event_id_b64(1);
        let context = normalize_content_authority(
            &content_authority_raw(signer_id, Vec::new()),
            &event_id_b64(2),
        );

        assert!(matches!(
            decide_content_authority_plan(&context),
            ContentAuthorityPlan::Reject { reason } if reason.contains("no peers_shared entry")
        ));
    }

    #[test]
    fn content_authority_rejects_ambiguous_signer_user() {
        let signer_id = event_id_b64(1);
        let context = normalize_content_authority(
            &content_authority_raw(
                signer_id,
                vec![Some(event_id_b64(2)), Some(event_id_b64(3))],
            ),
            &event_id_b64(2),
        );

        assert!(matches!(
            decide_content_authority_plan(&context),
            ContentAuthorityPlan::Reject { reason } if reason.contains("ambiguous")
        ));
    }

    #[test]
    fn content_authority_rejects_malformed_signer_user() {
        let signer_id = event_id_b64(1);
        let context = normalize_content_authority(
            &content_authority_raw(signer_id, vec![Some("not-base64".to_string())]),
            &event_id_b64(2),
        );

        assert!(matches!(
            decide_content_authority_plan(&context),
            ContentAuthorityPlan::Reject { reason } if reason.contains("malformed")
        ));
    }

    #[test]
    fn content_authority_rejects_missing_current_signer() {
        let context = normalize_content_authority(
            &ContentAuthorityRawRows::MissingCurrentSigner,
            &event_id_b64(2),
        );

        assert!(matches!(
            decide_content_authority_plan(&context),
            ContentAuthorityPlan::Reject { reason } if reason.contains("missing current signer")
        ));
    }

    #[test]
    fn content_authority_rejects_unsupported_signer_type() {
        let context = normalize_content_authority(
            &ContentAuthorityRawRows::UnsupportedSignerType {
                semantic_type_code: EVENT_TYPE_WORKSPACE,
            },
            &event_id_b64(2),
        );

        assert!(matches!(
            decide_content_authority_plan(&context),
            ContentAuthorityPlan::Reject { reason } if reason.contains("must be peer_shared")
        ));
    }

    #[test]
    fn admin_authority_allows_matching_workspace_signed_user_key() {
        let user_id = event_id_b64(1);
        let admin_key = [2u8; 32];
        let context = normalize_admin_authority(
            &admin_authority_raw(true, user_id.clone(), vec![Some(admin_key.to_vec())]),
            &admin_key,
        );

        assert_eq!(
            context,
            AdminAuthorityDecisionContext::WorkspaceUserKey {
                authority_matches_signer: true,
                user_event_id: user_id,
                user_public_key: admin_key.to_vec(),
                admin_public_key: admin_key.to_vec()
            }
        );
        assert_eq!(
            decide_admin_authority_plan(&context),
            AdminAuthorityPlan::Ready
        );
    }

    #[test]
    fn admin_authority_allows_duplicate_matching_workspace_signed_user_key() {
        let user_id = event_id_b64(1);
        let admin_key = [2u8; 32];
        let context = normalize_admin_authority(
            &admin_authority_raw(
                true,
                user_id.clone(),
                vec![Some(admin_key.to_vec()), Some(admin_key.to_vec())],
            ),
            &admin_key,
        );

        assert_eq!(
            context,
            AdminAuthorityDecisionContext::WorkspaceUserKey {
                authority_matches_signer: true,
                user_event_id: user_id,
                user_public_key: admin_key.to_vec(),
                admin_public_key: admin_key.to_vec()
            }
        );
        assert_eq!(
            decide_admin_authority_plan(&context),
            AdminAuthorityPlan::Ready
        );
    }

    #[test]
    fn admin_authority_rejects_missing_current_signer() {
        let context =
            normalize_admin_authority(&AdminAuthorityRawRows::MissingCurrentSigner, &[2u8; 32]);

        assert!(matches!(
            decide_admin_authority_plan(&context),
            AdminAuthorityPlan::Reject { reason } if reason.contains("missing current signer")
        ));
    }

    #[test]
    fn admin_authority_rejects_unsupported_signer_type() {
        let context = normalize_admin_authority(
            &AdminAuthorityRawRows::UnsupportedSignerType {
                semantic_type_code: EVENT_TYPE_DEVICE_INVITE,
            },
            &[2u8; 32],
        );

        assert!(matches!(
            decide_admin_authority_plan(&context),
            AdminAuthorityPlan::Reject { reason } if reason.contains("workspace or peer_shared")
        ));
    }

    #[test]
    fn admin_authority_rejects_missing_user_key() {
        let context = normalize_admin_authority(
            &admin_authority_raw(true, event_id_b64(1), Vec::new()),
            &[2u8; 32],
        );

        assert!(matches!(
            decide_admin_authority_plan(&context),
            AdminAuthorityPlan::Reject { reason } if reason.contains("no users row")
        ));
    }

    #[test]
    fn admin_authority_rejects_mismatched_user_key() {
        let context = normalize_admin_authority(
            &admin_authority_raw(true, event_id_b64(1), vec![Some(vec![3u8; 32])]),
            &[2u8; 32],
        );

        assert!(matches!(
            decide_admin_authority_plan(&context),
            AdminAuthorityPlan::Reject { reason } if reason.contains("does not match user public_key")
        ));
    }

    #[test]
    fn admin_authority_rejects_ambiguous_user_keys() {
        let context = normalize_admin_authority(
            &admin_authority_raw(
                true,
                event_id_b64(1),
                vec![Some(vec![2u8; 32]), Some(vec![3u8; 32])],
            ),
            &[2u8; 32],
        );

        assert!(matches!(
            decide_admin_authority_plan(&context),
            AdminAuthorityPlan::Reject { reason } if reason.contains("ambiguous")
        ));
    }

    #[test]
    fn admin_authority_rejects_malformed_user_key() {
        let context = normalize_admin_authority(
            &admin_authority_raw(true, event_id_b64(1), vec![Some(vec![2u8; 31])]),
            &[2u8; 32],
        );

        assert!(matches!(
            decide_admin_authority_plan(&context),
            AdminAuthorityPlan::Reject { reason } if reason.contains("invalid public_key")
        ));
    }

    #[test]
    fn admin_authority_allows_matching_peer_signed_user_key() {
        let user_id = event_id_b64(1);
        let admin_key = [2u8; 32];
        let context = normalize_admin_authority(
            &admin_authority_peer_raw(true, user_id.clone(), vec![Some(admin_key.to_vec())]),
            &admin_key,
        );

        assert_eq!(
            context,
            AdminAuthorityDecisionContext::PeerSharedUserKey {
                authority_matches_signer: true,
                user_event_id: user_id,
                user_public_key: admin_key.to_vec(),
                admin_public_key: admin_key.to_vec()
            }
        );
        assert_eq!(
            decide_admin_authority_plan(&context),
            AdminAuthorityPlan::Ready
        );
    }

    #[test]
    fn admin_authority_rejects_workspace_authority_mismatch() {
        let context = normalize_admin_authority(
            &admin_authority_raw(false, event_id_b64(1), vec![Some(vec![2u8; 32])]),
            &[2u8; 32],
        );

        assert!(matches!(
            decide_admin_authority_plan(&context),
            AdminAuthorityPlan::Reject { reason }
                if reason.contains("workspace as signer and authority")
        ));
    }

    #[test]
    fn admin_authority_rejects_peer_signed_authority_mismatch() {
        let context = normalize_admin_authority(
            &admin_authority_peer_raw(false, event_id_b64(1), vec![Some(vec![2u8; 32])]),
            &[2u8; 32],
        );

        assert!(matches!(
            decide_admin_authority_plan(&context),
            AdminAuthorityPlan::Reject { reason }
                if reason.contains("peer-signed admin authority")
        ));
    }

    #[test]
    fn peer_shared_authority_allows_matching_device_invite_user() {
        let signer_id = event_id_b64(1);
        let user_id = event_id_b64(2);
        let context = normalize_peer_shared_authority(
            &PeerSharedAuthorityRawRows::DeviceInviteSigner {
                signer_event_id: signer_id.clone(),
                authorized_user_id: user_id.clone(),
            },
            &user_id,
        );

        assert_eq!(
            context,
            PeerSharedAuthorityDecisionContext::UniqueAuthorizedUser {
                signer_event_id: signer_id,
                authorized_user_id: user_id.clone(),
                claimed_user_id: user_id
            }
        );
        assert_eq!(
            decide_peer_shared_authority_plan(&context),
            PeerSharedAuthorityPlan::Ready
        );
    }

    #[test]
    fn peer_shared_authority_rejects_missing_current_signer() {
        let context = normalize_peer_shared_authority(
            &PeerSharedAuthorityRawRows::MissingCurrentSigner,
            &event_id_b64(2),
        );

        assert!(matches!(
            decide_peer_shared_authority_plan(&context),
            PeerSharedAuthorityPlan::Reject { reason } if reason.contains("missing current signer")
        ));
    }

    #[test]
    fn peer_shared_authority_rejects_unsupported_signer_type() {
        let context = normalize_peer_shared_authority(
            &PeerSharedAuthorityRawRows::UnsupportedSignerType {
                semantic_type_code: EVENT_TYPE_PEER_SHARED,
            },
            &event_id_b64(2),
        );

        assert!(matches!(
            decide_peer_shared_authority_plan(&context),
            PeerSharedAuthorityPlan::Reject { reason } if reason.contains("must be device_invite")
        ));
    }

    #[test]
    fn peer_shared_authority_rejects_missing_device_invite_blob() {
        let context = normalize_peer_shared_authority(
            &PeerSharedAuthorityRawRows::MissingDeviceInviteBlob {
                signer_event_id: event_id_b64(1),
            },
            &event_id_b64(2),
        );

        assert!(matches!(
            decide_peer_shared_authority_plan(&context),
            PeerSharedAuthorityPlan::Reject { reason } if reason.contains("no valid device_invite")
        ));
    }

    #[test]
    fn peer_shared_authority_rejects_malformed_device_invite() {
        let context = normalize_peer_shared_authority(
            &PeerSharedAuthorityRawRows::MalformedDeviceInvite {
                signer_event_id: event_id_b64(1),
                reason: "failed to parse device_invite signer".to_string(),
            },
            &event_id_b64(2),
        );

        assert!(matches!(
            decide_peer_shared_authority_plan(&context),
            PeerSharedAuthorityPlan::Reject { reason } if reason.contains("failed to parse")
        ));
    }

    #[test]
    fn peer_shared_authority_rejects_claimed_user_mismatch() {
        let context = normalize_peer_shared_authority(
            &PeerSharedAuthorityRawRows::DeviceInviteSigner {
                signer_event_id: event_id_b64(1),
                authorized_user_id: event_id_b64(2),
            },
            &event_id_b64(3),
        );

        assert!(matches!(
            decide_peer_shared_authority_plan(&context),
            PeerSharedAuthorityPlan::Reject { reason } if reason.contains("event claims")
        ));
    }

    #[test]
    fn deletion_signer_allows_admin_signer() {
        let context = normalize_deletion_signer(&DeletionSignerRawRows::AdminSigner);

        assert_eq!(
            decide_deletion_signer_plan(&context),
            DeletionSignerPlan::ReadyAdmin
        );
    }

    #[test]
    fn deletion_signer_allows_unique_peer_user() {
        let signer_id = event_id_b64(1);
        let user_id = event_id_b64(2);
        let context = normalize_deletion_signer(&deletion_signer_raw(
            signer_id.clone(),
            vec![Some(user_id.clone())],
        ));

        assert_eq!(
            context,
            DeletionSignerDecisionContext::UniquePeerSharedSignerUser {
                signer_event_id: signer_id,
                signer_user_id: user_id.clone()
            }
        );
        assert_eq!(
            decide_deletion_signer_plan(&context),
            DeletionSignerPlan::ReadyPeerSharedUser {
                signer_user_id: user_id
            }
        );
    }

    #[test]
    fn deletion_signer_allows_duplicate_peer_user() {
        let signer_id = event_id_b64(1);
        let user_id = event_id_b64(2);
        let context = normalize_deletion_signer(&deletion_signer_raw(
            signer_id.clone(),
            vec![Some(user_id.clone()), Some(user_id.clone())],
        ));

        assert_eq!(
            context,
            DeletionSignerDecisionContext::UniquePeerSharedSignerUser {
                signer_event_id: signer_id,
                signer_user_id: user_id.clone()
            }
        );
        assert_eq!(
            decide_deletion_signer_plan(&context),
            DeletionSignerPlan::ReadyPeerSharedUser {
                signer_user_id: user_id
            }
        );
    }

    #[test]
    fn deletion_signer_rejects_missing_current_signer() {
        let context = normalize_deletion_signer(&DeletionSignerRawRows::MissingCurrentSigner);

        assert!(matches!(
            decide_deletion_signer_plan(&context),
            DeletionSignerPlan::Reject { reason } if reason.contains("missing current signer")
        ));
    }

    #[test]
    fn deletion_signer_rejects_unsupported_signer_type() {
        let context = normalize_deletion_signer(&DeletionSignerRawRows::UnsupportedSignerType {
            semantic_type_code: EVENT_TYPE_WORKSPACE,
        });

        assert!(matches!(
            decide_deletion_signer_plan(&context),
            DeletionSignerPlan::Reject { reason } if reason.contains("peer_shared or admin")
        ));
    }

    #[test]
    fn deletion_signer_rejects_missing_peer_user() {
        let signer_id = event_id_b64(1);
        let context = normalize_deletion_signer(&deletion_signer_raw(signer_id, Vec::new()));

        assert!(matches!(
            decide_deletion_signer_plan(&context),
            DeletionSignerPlan::Reject { reason } if reason.contains("no peers_shared entry")
        ));
    }

    #[test]
    fn deletion_signer_rejects_ambiguous_peer_user() {
        let signer_id = event_id_b64(1);
        let context = normalize_deletion_signer(&deletion_signer_raw(
            signer_id,
            vec![Some(event_id_b64(2)), Some(event_id_b64(3))],
        ));

        assert!(matches!(
            decide_deletion_signer_plan(&context),
            DeletionSignerPlan::Reject { reason } if reason.contains("ambiguous")
        ));
    }

    #[test]
    fn deletion_signer_rejects_malformed_peer_user() {
        let signer_id = event_id_b64(1);
        let context = normalize_deletion_signer(&deletion_signer_raw(signer_id, vec![None]));

        assert!(matches!(
            decide_deletion_signer_plan(&context),
            DeletionSignerPlan::Reject { reason } if reason.contains("malformed")
        ));
    }

    #[test]
    fn semantic_type_allowed_is_ready() {
        let context = normalize_semantic_type(
            &SemanticTypeRawRows::UniqueKnown {
                semantic_type_code: Some(i64::from(EVENT_TYPE_WORKSPACE)),
            },
            &[EVENT_TYPE_WORKSPACE],
        );

        assert_eq!(
            decide_semantic_type_plan(&context, "workspace_id"),
            SemanticTypePlan::DepReady {
                semantic_type_code: Some(EVENT_TYPE_WORKSPACE)
            }
        );
    }

    #[test]
    fn semantic_type_no_allowed_list_accepts_missing_type_code() {
        let context = normalize_semantic_type(
            &SemanticTypeRawRows::UniqueKnown {
                semantic_type_code: None,
            },
            &[],
        );

        assert_eq!(
            decide_semantic_type_plan(&context, "parent_1"),
            SemanticTypePlan::DepReady {
                semantic_type_code: None
            }
        );
    }

    #[test]
    fn semantic_type_rejects_missing_type_code_when_typed() {
        let context = normalize_semantic_type(
            &SemanticTypeRawRows::UniqueKnown {
                semantic_type_code: None,
            },
            &[EVENT_TYPE_WORKSPACE],
        );

        assert!(matches!(
            decide_semantic_type_plan(&context, "workspace_id"),
            SemanticTypePlan::Reject { reason } if reason.contains("missing tenant-scoped")
        ));
    }

    #[test]
    fn semantic_type_wrong_type_rejects() {
        let context = normalize_semantic_type(
            &SemanticTypeRawRows::UniqueKnown {
                semantic_type_code: Some(i64::from(EVENT_TYPE_WORKSPACE)),
            },
            &[EVENT_TYPE_MESSAGE],
        );

        assert!(matches!(
            decide_semantic_type_plan(&context, "target_event_id"),
            SemanticTypePlan::Reject { reason }
                if reason.contains("semantic type code") && reason.contains("expected")
        ));
    }

    #[test]
    fn semantic_type_out_of_range_rejects() {
        let context = normalize_semantic_type(
            &SemanticTypeRawRows::UniqueKnown {
                semantic_type_code: Some(300),
            },
            &[EVENT_TYPE_MESSAGE],
        );

        assert!(matches!(
            decide_semantic_type_plan(&context, "target_event_id"),
            SemanticTypePlan::Reject { reason } if reason.contains("out-of-range")
        ));
    }

    #[test]
    fn semantic_type_malformed_rows_reject() {
        let context =
            normalize_semantic_type(&SemanticTypeRawRows::Malformed, &[EVENT_TYPE_MESSAGE]);

        assert!(matches!(
            decide_semantic_type_plan(&context, "target_event_id"),
            SemanticTypePlan::Reject { reason } if reason.contains("malformed")
        ));
    }

    #[test]
    fn dep_load_plan_tombstone_wins_over_all_semantic_rows() {
        let semantic_rows = [
            SemanticTypeRawRows::Missing,
            SemanticTypeRawRows::UniqueKnown {
                semantic_type_code: Some(i64::from(EVENT_TYPE_MESSAGE)),
            },
            SemanticTypeRawRows::UniqueKnown {
                semantic_type_code: None,
            },
            SemanticTypeRawRows::Ambiguous,
            SemanticTypeRawRows::Malformed,
        ];

        for semantic_type_rows in semantic_rows {
            assert_eq!(
                decide_dep_load_plan(&DepLoadDecisionContext {
                    deleted_message_purge: Some("deleted-message".to_string()),
                    semantic_type_rows,
                }),
                DepLoadResult::Purge {
                    message_event_id: "deleted-message".to_string()
                }
            );
        }
    }

    #[test]
    fn dep_load_plan_uses_semantic_rows_when_not_tombstoned() {
        let semantic_type_rows = SemanticTypeRawRows::UniqueKnown {
            semantic_type_code: Some(i64::from(EVENT_TYPE_MESSAGE)),
        };

        assert_eq!(
            decide_dep_load_plan(&DepLoadDecisionContext {
                deleted_message_purge: None,
                semantic_type_rows: semantic_type_rows.clone(),
            }),
            DepLoadResult::Ready { semantic_type_rows }
        );
    }

    #[test]
    fn dep_load_plan_missing_when_not_tombstoned_and_semantic_missing() {
        assert_eq!(
            decide_dep_load_plan(&DepLoadDecisionContext {
                deleted_message_purge: None,
                semantic_type_rows: SemanticTypeRawRows::Missing,
            }),
            DepLoadResult::Missing
        );
    }
}
