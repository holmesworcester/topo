use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::event_modules::{
    endpoint_shared::load_endpoint_shared_by_event_id, parse_event, AdminEvent, DeviceInviteEvent,
    FileEvent, FileSliceEvent, InviteAcceptedEvent, KeySharedEvent, MessageDeletionEvent,
    MessageEvent, ParsedEvent, PeerSharedEvent, ReactionEvent, UserInviteEvent, WorkspaceEvent,
    EVENT_TYPE_ADMIN, EVENT_TYPE_DEVICE_INVITE, EVENT_TYPE_PEER_SHARED, EVENT_TYPE_WORKSPACE,
};
use crate::projection::contract::{
    BootstrapDecisionContext, CurrentSignerInfo, DeletionIntentInfo, FileDescriptorInfo,
    ProjectorDecisionContext, UnwrappedSecretMaterial,
};
use crate::projection::encrypted::unwrap_key_from_sender;
use crate::projection::signer::{resolve_signer_key, SignerResolution};
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

    fn load_key_shared_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        key_shared: &KeySharedEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext>;
}

/// Declare a projector-local context loader that downcasts ParsedEvent to the
/// expected variant and forwards to the matching ProjectionQueries method.
macro_rules! define_query_context_loader {
    ($fn_name:ident, $variant:ident, $query_method:ident, $label:literal) => {
        pub fn $fn_name(
            queries: &dyn $crate::projection::queries::ProjectionQueries,
            frame: &$crate::projection::queries::ProjectionFrameContext,
            recorded_by: &str,
            event_id_b64: &str,
            parsed: &$crate::event_modules::ParsedEvent,
        ) -> Result<$crate::projection::queries::ContextLoadResult, Box<dyn std::error::Error>> {
            let event = match parsed {
                $crate::event_modules::ParsedEvent::$variant(event) => event,
                _ => {
                    return Err(
                        concat!($label, " context loader called for non-", $label, " event").into(),
                    )
                }
            };

            Ok($crate::projection::queries::ContextLoadResult::ready(
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
    let Some(current_signer) = frame.current_signer.as_ref() else {
        return Ok((
            None,
            false,
            Some("missing current signer envelope".to_string()),
        ));
    };

    match current_signer.semantic_type_code {
        EVENT_TYPE_ADMIN => Ok((None, true, None)),
        EVENT_TYPE_PEER_SHARED => {
            let signed_by_b64 = current_signer.event_id.clone();
            let peer_user_eid: String = match conn.query_row(
                "SELECT COALESCE(user_event_id, '') FROM peers_shared WHERE recorded_by = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &signed_by_b64],
                |row| crate::db::sql_types::get_text(row, 0),
            ) {
                Ok(v) => v,
                Err(rusqlite::Error::QueryReturnedNoRows) => {
                    return Ok((
                        None,
                        false,
                        Some(format!("no peers_shared entry for signer {}", signed_by_b64)),
                    ))
                }
                Err(e) => return Err(e),
            };

            if peer_user_eid.is_empty() {
                return Ok((
                    None,
                    false,
                    Some(format!(
                        "peers_shared entry for signer {} has no user_event_id (legacy row)",
                        signed_by_b64
                    )),
                ));
            }

            Ok((Some(peer_user_eid), false, None))
        }
        other => Ok((
            None,
            false,
            Some(format!(
                "message_deletion signer must be peer_shared or admin, got semantic type {}",
                other
            )),
        )),
    }
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

fn authorized_user_for_device_invite(
    conn: &Connection,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
) -> Result<Option<String>, rusqlite::Error> {
    let Some(current_signer) = frame.current_signer.as_ref() else {
        return Ok(Some(
            "__ERROR__:missing current signer envelope for device_invite".to_string(),
        ));
    };
    if current_signer.semantic_type_code != EVENT_TYPE_DEVICE_INVITE {
        return Ok(Some(format!(
            "__ERROR__:unsupported device_invite signer semantic type {} for peer_shared authorization",
            current_signer.semantic_type_code
        )));
    }

    let signer_b64 = current_signer.event_id.clone();
    let Some(blob) = load_valid_event_blob(conn, recorded_by, &signer_b64)? else {
        return Ok(Some(format!(
            "__ERROR__:no valid device_invite blob for signer {}",
            signer_b64
        )));
    };

    let device_invite = match parse_event(&blob) {
        Ok(ParsedEvent::DeviceInvite(device_invite)) => device_invite,
        Ok(ParsedEvent::Signed(signed)) => match parse_event(&signed.payload) {
            Ok(ParsedEvent::DeviceInvite(device_invite)) => device_invite,
            Ok(other) => {
                return Ok(Some(format!(
                    "__ERROR__:peer_shared signer {} resolved to unexpected event type {}",
                    signer_b64,
                    other.event_type_code()
                )))
            }
            Err(err) => {
                return Ok(Some(format!(
                    "__ERROR__:failed to parse signed device_invite signer {}: {}",
                    signer_b64, err
                )))
            }
        },
        Ok(other) => {
            return Ok(Some(format!(
                "__ERROR__:peer_shared signer {} resolved to unexpected event type {}",
                signer_b64,
                other.event_type_code()
            )))
        }
        Err(err) => {
            return Ok(Some(format!(
                "__ERROR__:failed to parse device_invite signer {}: {}",
                signer_b64, err
            )))
        }
    };

    Ok(Some(event_id_to_base64(&device_invite.authority_event_id)))
}

fn peer_shared_user_mismatch_reason(
    conn: &Connection,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    user_event_id: &[u8; 32],
) -> Result<Option<String>, rusqlite::Error> {
    let claimed_user_b64 = event_id_to_base64(user_event_id);
    let expected_user = authorized_user_for_device_invite(conn, frame, recorded_by)?;

    let Some(expected_user) = expected_user else {
        return Ok(None);
    };

    if let Some(detail) = expected_user.strip_prefix("__ERROR__:") {
        return Ok(Some(detail.to_string()));
    }

    if expected_user != claimed_user_b64 {
        return Ok(Some(format!(
            "peer_shared signer authorizes user {} but event claims {}",
            expected_user, claimed_user_b64
        )));
    }

    Ok(None)
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

fn load_workspace_decision_context_from_db(
    conn: &Connection,
    recorded_by: &str,
) -> ProjectionQueryResult<WorkspaceDecisionContext> {
    let raw_rows = load_workspace_accepted_raw_rows(conn, recorded_by)?;
    Ok(normalize_workspace_acceptance(&raw_rows))
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
        let semantic_type_rows = load_semantic_type_raw_rows(self, recorded_by, &dep_b64)?;
        if semantic_type_rows != SemanticTypeRawRows::Missing {
            return Ok(DepLoadResult::Ready { semantic_type_rows });
        }
        if let Some(message_event_id) =
            deleted_message_purges_dep(self, recorded_by, parsed, field_name, &dep_b64)?
        {
            return Ok(DepLoadResult::purge(message_event_id));
        }
        Ok(DepLoadResult::missing())
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
        let mut ctx = ProjectorDecisionContext::default();
        match frame.current_signer.as_ref() {
            Some(current_signer) if current_signer.semantic_type_code == EVENT_TYPE_WORKSPACE => {}
            Some(current_signer) => {
                return Ok(ProjectorDecisionContext {
                    admin_user_key_mismatch_reason: Some(format!(
                        "admin signer must be workspace, got semantic type {}",
                        current_signer.semantic_type_code
                    )),
                    ..ProjectorDecisionContext::default()
                });
            }
            None => {
                return Ok(ProjectorDecisionContext {
                    admin_user_key_mismatch_reason: Some(
                        "admin event missing current signer envelope".to_string(),
                    ),
                    ..ProjectorDecisionContext::default()
                });
            }
        }

        let user_event_id_b64 = event_id_to_base64(&admin.user_event_id);
        let user_public_key: Option<Vec<u8>> = self
            .query_row(
                "SELECT public_key FROM users WHERE recorded_by = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &user_event_id_b64],
                |row| crate::db::sql_types::get_blob(row, 0),
            )
            .optional()?;

        let admin_user_key_mismatch_reason = match user_public_key {
            None => Some(format!(
                "no users row for user_event_id {}",
                user_event_id_b64
            )),
            Some(user_public_key) if user_public_key.len() != 32 => Some(format!(
                "user {} has invalid public_key length {}",
                user_event_id_b64,
                user_public_key.len()
            )),
            Some(user_public_key) if user_public_key.as_slice() != admin.public_key => {
                Some(format!(
                    "admin public_key does not match user public_key for {}",
                    user_event_id_b64
                ))
            }
            Some(_) => None,
        };

        ctx.admin_user_key_mismatch_reason = admin_user_key_mismatch_reason;
        Ok(ctx)
    }

    fn load_peer_shared_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        peer_shared: &PeerSharedEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let Some(current_signer) = frame.current_signer.as_ref() else {
            return Ok(ProjectorDecisionContext {
                peer_shared_user_mismatch_reason: Some(
                    "peer_shared missing current signer envelope".to_string(),
                ),
                ..ProjectorDecisionContext::default()
            });
        };
        if current_signer.semantic_type_code != EVENT_TYPE_DEVICE_INVITE {
            return Ok(ProjectorDecisionContext {
                peer_shared_user_mismatch_reason: Some(format!(
                    "peer_shared signer must be device_invite, got semantic type {}",
                    current_signer.semantic_type_code
                )),
                ..ProjectorDecisionContext::default()
            });
        }

        let signed_by_b64 = current_signer.event_id.clone();
        let blob = load_valid_event_blob(self, recorded_by, &signed_by_b64)?;
        let Some(blob) = blob else {
            return Ok(ProjectorDecisionContext {
                peer_shared_user_mismatch_reason: Some(format!(
                    "no valid device_invite blob for signer {}",
                    signed_by_b64
                )),
                ..ProjectorDecisionContext::default()
            });
        };

        let _device_invite = match parse_event(&blob) {
            Ok(ParsedEvent::DeviceInvite(device_invite)) => device_invite,
            Ok(ParsedEvent::Signed(signed)) => match parse_event(&signed.payload) {
                Ok(ParsedEvent::DeviceInvite(device_invite)) => device_invite,
                Ok(other) => {
                    return Ok(ProjectorDecisionContext {
                        peer_shared_user_mismatch_reason: Some(format!(
                            "peer_shared signer {} resolved to unexpected event type {}",
                            signed_by_b64,
                            other.event_type_code()
                        )),
                        ..ProjectorDecisionContext::default()
                    })
                }
                Err(err) => {
                    return Ok(ProjectorDecisionContext {
                        peer_shared_user_mismatch_reason: Some(format!(
                            "failed to parse signed device_invite signer {}: {}",
                            signed_by_b64, err
                        )),
                        ..ProjectorDecisionContext::default()
                    })
                }
            },
            Ok(other) => {
                return Ok(ProjectorDecisionContext {
                    peer_shared_user_mismatch_reason: Some(format!(
                        "peer_shared signer {} resolved to unexpected event type {}",
                        signed_by_b64,
                        other.event_type_code()
                    )),
                    ..ProjectorDecisionContext::default()
                })
            }
            Err(err) => {
                return Ok(ProjectorDecisionContext {
                    peer_shared_user_mismatch_reason: Some(format!(
                        "failed to parse device_invite signer {}: {}",
                        signed_by_b64, err
                    )),
                    ..ProjectorDecisionContext::default()
                })
            }
        };

        let endpoint_shared_event_id_b64 =
            event_id_to_base64(&peer_shared.endpoint_shared_event_id);
        let endpoint_shared_row =
            load_endpoint_shared_by_event_id(self, &endpoint_shared_event_id_b64)
                .map_err(|e| -> Box<dyn std::error::Error> { e })?;

        Ok(ProjectorDecisionContext {
            peer_shared_user_mismatch_reason: peer_shared_user_mismatch_reason(
                self,
                frame,
                recorded_by,
                &peer_shared.user_event_id,
            )?,
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

    fn load_key_shared_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        key_shared: &KeySharedEvent,
    ) -> ProjectionQueryResult<ProjectorDecisionContext> {
        let recipient_b64 = event_id_to_base64(&key_shared.recipient_event_id);
        let unwrap_key_b64 = event_id_to_base64(&key_shared.unwrap_key_event_id);

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

        let Some(private_key_bytes) = invite_secret_row else {
            return Ok(ProjectorDecisionContext::default());
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
}
