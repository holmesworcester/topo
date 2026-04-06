use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::event_modules::{
    endpoint_shared::load_endpoint_shared_by_event_id, parse_event, AdminEvent, DeviceInviteEvent,
    FileEvent, FileSliceEvent, InviteAcceptedEvent, KeySharedEvent, MessageDeletionEvent,
    MessageEvent, ParsedEvent, PeerSharedEvent, ReactionEvent, UserInviteEvent, WorkspaceEvent,
    EVENT_TYPE_ADMIN, EVENT_TYPE_DEVICE_INVITE, EVENT_TYPE_PEER_SHARED, EVENT_TYPE_WORKSPACE,
};
use crate::projection::contract::{
    BootstrapContextSnapshot, ContextSnapshot, CurrentSignerInfo, DeletionIntentInfo,
    FileDescriptorInfo, UnwrappedSecretMaterial,
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
    Ready(ContextSnapshot),
    Block { missing: Vec<EventId> },
    Reject { reason: String },
    Purge { message_event_id: String },
}

impl ContextLoadResult {
    pub fn ready(ctx: ContextSnapshot) -> Self {
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
    Ready { semantic_type_code: Option<u8> },
    Missing,
    Purge { message_event_id: String },
}

impl DepLoadResult {
    pub fn ready(semantic_type_code: Option<u8>) -> Self {
        Self::Ready { semantic_type_code }
    }

    pub fn missing() -> Self {
        Self::Missing
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
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_admin_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        admin: &AdminEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_peer_shared_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        peer_shared: &PeerSharedEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_user_invite_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        user_invite: &UserInviteEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_device_invite_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        device_invite: &DeviceInviteEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_message_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        message: &MessageEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_message_deletion_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        message_deletion: &MessageDeletionEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_reaction_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        reaction: &ReactionEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_file_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        file: &FileEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_file_slice_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        file_slice: &FileSliceEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_invite_accepted_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        invite_accepted: &InviteAcceptedEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_key_shared_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        key_shared: &KeySharedEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;
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

fn load_valid_semantic_type_code(
    conn: &Connection,
    recorded_by: &str,
    dep_b64: &str,
) -> Result<Option<u8>, Box<dyn std::error::Error>> {
    let stored: Option<Option<i64>> = conn
        .query_row(
            "SELECT semantic_type_code
             FROM valid_events
             WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, dep_b64],
            |row| row.get(0),
        )
        .optional()?;

    match stored {
        Some(Some(code)) => {
            let code = u8::try_from(code).map_err(|_| {
                format!(
                    "semantic_type_code {} out of range for event {}",
                    code, dep_b64
                )
            })?;
            Ok(Some(code))
        }
        Some(None) => {
            let blob: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT blob FROM events WHERE event_id = ?1",
                    rusqlite::params![dep_b64],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(blob) = blob else {
                return Ok(None);
            };
            let Some(code) = derive_semantic_type_code_from_blob(&blob)? else {
                return Ok(None);
            };
            conn.execute(
                "UPDATE valid_events
                 SET semantic_type_code = ?3
                 WHERE peer_id = ?1 AND event_id = ?2 AND semantic_type_code IS NULL",
                rusqlite::params![recorded_by, dep_b64, i64::from(code)],
            )?;
            Ok(Some(code))
        }
        None => {
            if global_endpoint_shared_is_valid(conn, dep_b64)? {
                return Ok(Some(crate::event_modules::EVENT_TYPE_ENDPOINT_SHARED));
            }
            Ok(None)
        }
    }
}

fn dep_is_satisfied_for_scope(
    conn: &Connection,
    recorded_by: &str,
    dep_b64: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let dep_valid: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, dep_b64],
        |row| row.get(0),
    )?;
    if dep_valid {
        return Ok(true);
    }
    global_endpoint_shared_is_valid(conn, dep_b64)
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

fn load_bootstrap_context_snapshot(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id_b64: &str,
) -> ProjectionQueryResult<Option<BootstrapContextSnapshot>> {
    Ok(
        read_bootstrap_context(conn, recorded_by, invite_event_id_b64)
            .map_err(|err| -> Box<dyn std::error::Error> { err })?
            .map(|bc| BootstrapContextSnapshot {
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
    let Some(current_signer) = frame.current_signer.as_ref() else {
        return Ok(Some("missing current signer envelope".to_string()));
    };
    if current_signer.semantic_type_code != EVENT_TYPE_PEER_SHARED {
        return Ok(Some(format!(
            "content signer must be peer_shared, got semantic type {}",
            current_signer.semantic_type_code
        )));
    }
    let signed_by_b64 = current_signer.event_id.clone();
    let author_id_b64 = event_id_to_base64(author_id);

    let peer_user_eid: String = match conn.query_row(
        "SELECT COALESCE(user_event_id, '') FROM peers_shared WHERE recorded_by = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &signed_by_b64],
        |row| row.get::<_, String>(0),
    ) {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Ok(Some(format!(
                "no peers_shared entry for signer {}",
                signed_by_b64
            )));
        }
        Err(e) => return Err(e),
    };

    if peer_user_eid.is_empty() {
        return Ok(Some(format!(
            "peers_shared entry for signer {} has no user_event_id (legacy row)",
            signed_by_b64
        )));
    }

    if peer_user_eid != author_id_b64 {
        return Ok(Some(format!(
            "signer {} belongs to user {} but author_id claims {}",
            signed_by_b64, peer_user_eid, author_id_b64
        )));
    }

    Ok(None)
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
                |row| row.get::<_, String>(0),
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

impl ProjectionQueries for Connection {
    fn load_dep_result(
        &self,
        recorded_by: &str,
        parsed: &ParsedEvent,
        field_name: &str,
        dep_id: &EventId,
    ) -> ProjectionQueryResult<DepLoadResult> {
        let dep_b64 = event_id_to_base64(dep_id);
        if dep_is_satisfied_for_scope(self, recorded_by, &dep_b64)? {
            return Ok(DepLoadResult::ready(load_valid_semantic_type_code(
                self,
                recorded_by,
                &dep_b64,
            )?));
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
                |row| row.get(0),
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
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let accepted_workspace_id = match self.query_row(
            "SELECT workspace_id
             FROM invites_accepted
             WHERE recorded_by = ?1
             ORDER BY created_at ASC, event_id ASC
             LIMIT 1",
            rusqlite::params![recorded_by],
            |row| row.get::<_, String>(0),
        ) {
            Ok(v) => Some(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.into()),
        };

        Ok(ContextSnapshot {
            accepted_workspace_id,
            ..ContextSnapshot::default()
        })
    }

    fn load_admin_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        admin: &AdminEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let mut ctx = ContextSnapshot::default();
        match frame.current_signer.as_ref() {
            Some(current_signer) if current_signer.semantic_type_code == EVENT_TYPE_WORKSPACE => {}
            Some(current_signer) => {
                return Ok(ContextSnapshot {
                    admin_user_key_mismatch_reason: Some(format!(
                        "admin signer must be workspace, got semantic type {}",
                        current_signer.semantic_type_code
                    )),
                    ..ContextSnapshot::default()
                });
            }
            None => {
                return Ok(ContextSnapshot {
                    admin_user_key_mismatch_reason: Some(
                        "admin event missing current signer envelope".to_string(),
                    ),
                    ..ContextSnapshot::default()
                });
            }
        }

        let user_event_id_b64 = event_id_to_base64(&admin.user_event_id);
        let user_public_key: Option<Vec<u8>> = self
            .query_row(
                "SELECT public_key FROM users WHERE recorded_by = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &user_event_id_b64],
                |row| row.get(0),
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
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let Some(current_signer) = frame.current_signer.as_ref() else {
            return Ok(ContextSnapshot {
                peer_shared_user_mismatch_reason: Some(
                    "peer_shared missing current signer envelope".to_string(),
                ),
                ..ContextSnapshot::default()
            });
        };
        if current_signer.semantic_type_code != EVENT_TYPE_DEVICE_INVITE {
            return Ok(ContextSnapshot {
                peer_shared_user_mismatch_reason: Some(format!(
                    "peer_shared signer must be device_invite, got semantic type {}",
                    current_signer.semantic_type_code
                )),
                ..ContextSnapshot::default()
            });
        }

        let signed_by_b64 = current_signer.event_id.clone();
        let blob = load_valid_event_blob(self, recorded_by, &signed_by_b64)?;
        let Some(blob) = blob else {
            return Ok(ContextSnapshot {
                peer_shared_user_mismatch_reason: Some(format!(
                    "no valid device_invite blob for signer {}",
                    signed_by_b64
                )),
                ..ContextSnapshot::default()
            });
        };

        let _device_invite = match parse_event(&blob) {
            Ok(ParsedEvent::DeviceInvite(device_invite)) => device_invite,
            Ok(ParsedEvent::Signed(signed)) => match parse_event(&signed.payload) {
                Ok(ParsedEvent::DeviceInvite(device_invite)) => device_invite,
                Ok(other) => {
                    return Ok(ContextSnapshot {
                        peer_shared_user_mismatch_reason: Some(format!(
                            "peer_shared signer {} resolved to unexpected event type {}",
                            signed_by_b64,
                            other.event_type_code()
                        )),
                        ..ContextSnapshot::default()
                    })
                }
                Err(err) => {
                    return Ok(ContextSnapshot {
                        peer_shared_user_mismatch_reason: Some(format!(
                            "failed to parse signed device_invite signer {}: {}",
                            signed_by_b64, err
                        )),
                        ..ContextSnapshot::default()
                    })
                }
            },
            Ok(other) => {
                return Ok(ContextSnapshot {
                    peer_shared_user_mismatch_reason: Some(format!(
                        "peer_shared signer {} resolved to unexpected event type {}",
                        signed_by_b64,
                        other.event_type_code()
                    )),
                    ..ContextSnapshot::default()
                })
            }
            Err(err) => {
                return Ok(ContextSnapshot {
                    peer_shared_user_mismatch_reason: Some(format!(
                        "failed to parse device_invite signer {}: {}",
                        signed_by_b64, err
                    )),
                    ..ContextSnapshot::default()
                })
            }
        };

        let endpoint_shared_event_id_b64 =
            event_id_to_base64(&peer_shared.endpoint_shared_event_id);
        let endpoint_shared_row =
            load_endpoint_shared_by_event_id(self, &endpoint_shared_event_id_b64)
                .map_err(|e| -> Box<dyn std::error::Error> { e })?;

        Ok(ContextSnapshot {
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
            ..ContextSnapshot::default()
        })
    }

    fn load_user_invite_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        _user_invite: &UserInviteEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let mut ctx = ContextSnapshot::default();

        ctx.is_local_create = match self.query_row(
            "SELECT source FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get::<_, String>(0),
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

        ctx.bootstrap_context = load_bootstrap_context_snapshot(self, recorded_by, event_id_b64)?;
        Ok(ctx)
    }

    fn load_device_invite_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        device_invite: &DeviceInviteEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let mut ctx = ContextSnapshot::default();

        ctx.is_local_create = match self.query_row(
            "SELECT source FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
            |row| row.get::<_, String>(0),
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

        ctx.bootstrap_context = load_bootstrap_context_snapshot(self, recorded_by, event_id_b64)?;
        Ok(ctx)
    }

    fn load_message_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        event_id_b64: &str,
        message: &MessageEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
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
                    deletion_event_id: row.get(0)?,
                    author_id: row.get(1)?,
                    authorized_by_admin: row.get::<_, i64>(2)? != 0,
                    created_at: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ContextSnapshot {
            signer_user_mismatch_reason,
            deletion_intents,
            ..ContextSnapshot::default()
        })
    }

    fn load_message_deletion_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        message_deletion: &MessageDeletionEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let mut ctx = ContextSnapshot::default();
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
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        ctx.target_message_author = self
            .query_row(
                "SELECT author_id FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
                rusqlite::params![recorded_by, &target_b64],
                |row| row.get::<_, String>(0),
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
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let signer_user_mismatch_reason =
            signer_user_mismatch_reason(self, frame, recorded_by, &reaction.author_id)?;

        Ok(ContextSnapshot {
            signer_user_mismatch_reason,
            ..ContextSnapshot::default()
        })
    }

    fn load_file_context(
        &self,
        _frame: &ProjectionFrameContext,
        _recorded_by: &str,
        _event_id_b64: &str,
        _file: &FileEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        Ok(ContextSnapshot::default())
    }

    fn load_file_slice_context(
        &self,
        frame: &ProjectionFrameContext,
        recorded_by: &str,
        _event_id_b64: &str,
        file_slice: &FileSliceEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let mut ctx = ContextSnapshot::default();
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
                let root_hash_blob: Vec<u8> = row.get(4)?;
                let mut root_hash = [0u8; 32];
                if root_hash_blob.len() == 32 {
                    root_hash.copy_from_slice(&root_hash_blob);
                }
                Ok(FileDescriptorInfo {
                    event_id: row.get::<_, String>(0)?,
                    message_id: row.get::<_, String>(1)?,
                    signer_event_id: row.get::<_, String>(2)?,
                    key_event_id: row.get::<_, String>(3)?,
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
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
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
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let mut ctx = ContextSnapshot::default();
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

        if let Some(bc) = load_bootstrap_context_snapshot(self, recorded_by, &invite_event_id_b64)?
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
    ) -> ProjectionQueryResult<ContextSnapshot> {
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
                |row| row.get(0),
            )
            .optional()?;

        let Some(private_key_bytes) = invite_secret_row else {
            return Ok(ContextSnapshot::default());
        };
        if private_key_bytes.len() != 32 {
            return Ok(ContextSnapshot::default());
        }

        let Some(current_signer) = frame.current_signer.as_ref() else {
            return Ok(ContextSnapshot::default());
        };
        let Some(current_signer_event_id) = event_id_from_base64(&current_signer.event_id) else {
            return Ok(ContextSnapshot::default());
        };

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&private_key_bytes);
        let local_signing_key = SigningKey::from_bytes(&key_arr);

        let sender_key = match resolve_signer_key(self, recorded_by, &current_signer_event_id)? {
            SignerResolution::Found(k) => k,
            _ => return Ok(ContextSnapshot::default()),
        };
        let sender_pub = match VerifyingKey::from_bytes(&sender_key.public_key) {
            Ok(vk) => vk,
            Err(_) => return Ok(ContextSnapshot::default()),
        };

        let plaintext_key =
            unwrap_key_from_sender(&local_signing_key, &sender_pub, &key_shared.wrapped_key);

        Ok(ContextSnapshot {
            unwrapped_secret_material: Some(UnwrappedSecretMaterial {
                key_bytes: plaintext_key,
            }),
            ..ContextSnapshot::default()
        })
    }
}
