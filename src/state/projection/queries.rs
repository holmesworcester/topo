use crate::crypto::event_id_to_base64;
use crate::event_modules::{
    parse_event, AdminEvent, DeviceInviteEvent, FileEvent, FileSliceEvent, InviteAcceptedEvent,
    KeySharedEvent, MessageDeletionEvent, MessageEvent, ParsedEvent, PeerSharedEvent,
    ReactionEvent, UserInviteEvent, WorkspaceEvent,
};
use crate::projection::contract::{
    BootstrapContextSnapshot, ContextSnapshot, DeletionIntentInfo, FileDescriptorInfo,
    UnwrappedSecretMaterial,
};
use crate::projection::encrypted::unwrap_key_from_sender;
use crate::projection::signer::{resolve_signer_key, SignerResolution};
use crate::state::db::transport_creds::{peer_has_creds_with_source, CRED_SOURCE_PEER_SHARED};
use crate::state::db::transport_trust::read_bootstrap_context;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{Connection, OptionalExtension};

pub(crate) type ProjectionQueryResult<T> = Result<T, Box<dyn std::error::Error>>;

pub trait ProjectionQueries {
    fn load_workspace_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        workspace: &WorkspaceEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_admin_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        admin: &AdminEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_peer_shared_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        peer_shared: &PeerSharedEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_user_invite_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        user_invite: &UserInviteEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_device_invite_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        device_invite: &DeviceInviteEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_message_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        message: &MessageEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_message_deletion_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        message_deletion: &MessageDeletionEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_reaction_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        reaction: &ReactionEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_file_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        file: &FileEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_file_slice_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        file_slice: &FileSliceEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_invite_accepted_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        invite_accepted: &InviteAcceptedEvent,
    ) -> ProjectionQueryResult<ContextSnapshot>;

    fn load_key_shared_context(
        &self,
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
            recorded_by: &str,
            event_id_b64: &str,
            parsed: &$crate::event_modules::ParsedEvent,
        ) -> Result<$crate::projection::contract::ContextSnapshot, Box<dyn std::error::Error>> {
            let event = match parsed {
                $crate::event_modules::ParsedEvent::$variant(event) => event,
                _ => {
                    return Err(
                        concat!($label, " context loader called for non-", $label, " event").into(),
                    )
                }
            };

            queries.$query_method(recorded_by, event_id_b64, event)
        }
    };
}

pub(crate) use define_query_context_loader;

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
    recorded_by: &str,
    signed_by: &[u8; 32],
    author_id: &[u8; 32],
) -> Result<Option<String>, rusqlite::Error> {
    let signed_by_b64 = event_id_to_base64(signed_by);
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
    recorded_by: &str,
    device_invite: &DeviceInviteEvent,
) -> Result<Option<String>, rusqlite::Error> {
    match device_invite.signer_type {
        4 => Ok(Some(event_id_to_base64(&device_invite.authority_event_id))),
        5 => {
            let signer_b64 = event_id_to_base64(&device_invite.signed_by);
            let signer_user_event_id: Option<String> = conn
                .query_row(
                    "SELECT COALESCE(user_event_id, '')
                     FROM peers_shared
                     WHERE recorded_by = ?1 AND event_id = ?2",
                    rusqlite::params![recorded_by, &signer_b64],
                    |row| row.get(0),
                )
                .optional()?;

            let Some(signer_user_event_id) = signer_user_event_id else {
                return Ok(Some(format!(
                    "__ERROR__:no peers_shared row for device_invite signer {}",
                    signer_b64
                )));
            };
            if signer_user_event_id.is_empty() {
                return Ok(Some(format!(
                    "__ERROR__:device_invite signer {} has empty peers_shared.user_event_id",
                    signer_b64
                )));
            }
            Ok(Some(signer_user_event_id))
        }
        other => Ok(Some(format!(
            "__ERROR__:unsupported device_invite signer_type {} for peer_shared authorization",
            other
        ))),
    }
}

fn peer_shared_user_mismatch_reason(
    conn: &Connection,
    recorded_by: &str,
    device_invite: &DeviceInviteEvent,
    user_event_id: &[u8; 32],
) -> Result<Option<String>, rusqlite::Error> {
    let claimed_user_b64 = event_id_to_base64(user_event_id);
    let expected_user = authorized_user_for_device_invite(conn, recorded_by, device_invite)?;

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
    fn load_workspace_context(
        &self,
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
        recorded_by: &str,
        _event_id_b64: &str,
        admin: &AdminEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
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

        Ok(ContextSnapshot {
            admin_user_key_mismatch_reason,
            ..ContextSnapshot::default()
        })
    }

    fn load_peer_shared_context(
        &self,
        recorded_by: &str,
        _event_id_b64: &str,
        peer_shared: &PeerSharedEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let signed_by_b64 = event_id_to_base64(&peer_shared.signed_by);
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

        let device_invite = match parse_event(&blob) {
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
                        "failed to parse device_invite signer {}: {}",
                        signed_by_b64, err
                    )),
                    ..ContextSnapshot::default()
                })
            }
        };

        Ok(ContextSnapshot {
            peer_shared_user_mismatch_reason: peer_shared_user_mismatch_reason(
                self,
                recorded_by,
                &device_invite,
                &peer_shared.user_event_id,
            )?,
            ..ContextSnapshot::default()
        })
    }

    fn load_user_invite_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        user_invite: &UserInviteEvent,
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

        if user_invite.signer_type == 5 {
            let signer_b64 = event_id_to_base64(&user_invite.signed_by);
            let authority_b64 = event_id_to_base64(&user_invite.authority_event_id);
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

        ctx.bootstrap_context = load_bootstrap_context_snapshot(self, recorded_by, event_id_b64)?;
        Ok(ctx)
    }

    fn load_device_invite_context(
        &self,
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

        if device_invite.signer_type == 5 {
            let signer_b64 = event_id_to_base64(&device_invite.signed_by);
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

        ctx.bootstrap_context = load_bootstrap_context_snapshot(self, recorded_by, event_id_b64)?;
        Ok(ctx)
    }

    fn load_message_context(
        &self,
        recorded_by: &str,
        event_id_b64: &str,
        message: &MessageEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let signer_user_mismatch_reason =
            signer_user_mismatch_reason(self, recorded_by, &message.signed_by, &message.author_id)?;

        let mut stmt = self.prepare_cached(
            "SELECT deletion_event_id, author_id, created_at
             FROM deletion_intents
             WHERE recorded_by = ?1
               AND target_kind = 'message'
               AND target_id = ?2
             ORDER BY deletion_event_id",
        )?;
        let deletion_intents = stmt
            .query_map(rusqlite::params![recorded_by, event_id_b64], |row| {
                Ok(DeletionIntentInfo {
                    deletion_event_id: row.get(0)?,
                    author_id: row.get(1)?,
                    created_at: row.get(2)?,
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
        recorded_by: &str,
        _event_id_b64: &str,
        message_deletion: &MessageDeletionEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let mut ctx = ContextSnapshot::default();
        ctx.signer_user_mismatch_reason = signer_user_mismatch_reason(
            self,
            recorded_by,
            &message_deletion.signed_by,
            &message_deletion.author_id,
        )?;

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
        recorded_by: &str,
        _event_id_b64: &str,
        reaction: &ReactionEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let target_b64 = event_id_to_base64(&reaction.target_event_id);
        let target_message_deleted = self.query_row(
            "SELECT COUNT(*) > 0 FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &target_b64],
            |row| row.get(0),
        )?;
        let signer_user_mismatch_reason = signer_user_mismatch_reason(
            self,
            recorded_by,
            &reaction.signed_by,
            &reaction.author_id,
        )?;

        Ok(ContextSnapshot {
            signer_user_mismatch_reason,
            target_message_deleted,
            ..ContextSnapshot::default()
        })
    }

    fn load_file_context(
        &self,
        recorded_by: &str,
        _event_id_b64: &str,
        file: &FileEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let message_id_b64 = event_id_to_base64(&file.message_id);
        let target_message_deleted: bool = self.query_row(
            "SELECT COUNT(*) > 0
             FROM deleted_messages
             WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &message_id_b64],
            |row| row.get(0),
        )?;
        let deleted_file_message_id = self
            .query_row(
                "SELECT message_id
                 FROM deleted_files
                 WHERE recorded_by = ?1 AND file_id = ?2",
                rusqlite::params![recorded_by, event_id_to_base64(&file.file_id)],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        Ok(ContextSnapshot {
            target_message_deleted,
            deleted_file_message_id,
            ..ContextSnapshot::default()
        })
    }

    fn load_file_slice_context(
        &self,
        recorded_by: &str,
        _event_id_b64: &str,
        file_slice: &FileSliceEvent,
    ) -> ProjectionQueryResult<ContextSnapshot> {
        let mut ctx = ContextSnapshot::default();
        let file_id_b64 = event_id_to_base64(&file_slice.file_id);

        ctx.deleted_file_message_id = self
            .query_row(
                "SELECT message_id
                 FROM deleted_files
                 WHERE recorded_by = ?1 AND file_id = ?2",
                rusqlite::params![recorded_by, &file_id_b64],
                |row| row.get::<_, String>(0),
            )
            .optional()?;

        let mut desc_stmt = self.prepare(
            "SELECT event_id, signer_event_id, key_event_id
             FROM files
             WHERE recorded_by = ?1 AND file_id = ?2
             ORDER BY created_at ASC, event_id ASC",
        )?;
        ctx.file_descriptors = desc_stmt
            .query_map(rusqlite::params![recorded_by, &file_id_b64], |row| {
                Ok(FileDescriptorInfo {
                    event_id: row.get::<_, String>(0)?,
                    signer_event_id: row.get::<_, String>(1)?,
                    key_event_id: row.get::<_, String>(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

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

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&private_key_bytes);
        let local_signing_key = SigningKey::from_bytes(&key_arr);

        let sender_key = match resolve_signer_key(
            self,
            recorded_by,
            key_shared.signer_type,
            &key_shared.signed_by,
        )? {
            SignerResolution::Found(k) => k,
            _ => return Ok(ContextSnapshot::default()),
        };
        let sender_pub = match VerifyingKey::from_bytes(&sender_key) {
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
