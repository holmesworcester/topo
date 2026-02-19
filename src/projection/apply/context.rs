use super::super::result::ContextSnapshot;
use crate::crypto::event_id_to_base64;
use crate::event_modules::ParsedEvent;
use rusqlite::Connection;

/// Verify that the signer's peer_shared row maps to the claimed author_id.
///
/// Returns:
/// - `Ok(None)` when signer-user binding is valid
/// - `Ok(Some(reason))` for semantic mismatch/missing data (rejectable)
/// - `Err(_)` for transient DB failures (non-rejecting infrastructure errors)
pub(crate) fn signer_user_mismatch_reason(
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

/// Build a ContextSnapshot for the given event from the database.
///
/// This is the only place where projector-relevant state is read from the DB.
/// Pure projectors receive this snapshot and make all decisions from it.
pub(crate) fn build_context_snapshot(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let mut ctx = ContextSnapshot::default();

    // Trust anchor — needed by Workspace, InviteAccepted, and other identity events
    match parsed {
        ParsedEvent::Workspace(_) | ParsedEvent::InviteAccepted(_) => {
            ctx.trust_anchor_workspace_id = match conn.query_row(
                "SELECT workspace_id FROM trust_anchors WHERE peer_id = ?1",
                rusqlite::params![recorded_by],
                |row| row.get::<_, String>(0),
            ) {
                Ok(v) => Some(v),
                Err(rusqlite::Error::QueryReturnedNoRows) => None,
                Err(e) => return Err(e.into()),
            };
        }
        _ => {}
    }

    // MessageDeletion context — target message author and tombstone state
    if let ParsedEvent::MessageDeletion(del) = parsed {
        ctx.signer_user_mismatch_reason =
            signer_user_mismatch_reason(conn, recorded_by, &del.signed_by, &del.author_id)?;

        let target_b64 = event_id_to_base64(&del.target_event_id);

        // Check existing tombstone
        ctx.target_tombstone_author = match conn.query_row(
            "SELECT author_id FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &target_b64],
            |row| row.get::<_, String>(0),
        ) {
            Ok(a) => Some(a),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.into()),
        };

        // Check target message author
        ctx.target_message_author = match conn.query_row(
            "SELECT author_id FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &target_b64],
            |row| row.get::<_, String>(0),
        ) {
            Ok(a) => Some(a),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.into()),
        };

        // Type validation: if target is in valid_events but not in messages or
        // deleted_messages, it's a non-message event. MessageDeletion no longer
        // carries target_event_id as a dep (for intent-only path), so we must
        // validate the target type here when the target is already projected.
        if ctx.target_message_author.is_none() && ctx.target_tombstone_author.is_none() {
            let target_in_valid: bool = conn.query_row(
                "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                rusqlite::params![recorded_by, &target_b64],
                |row| row.get(0),
            )?;
            ctx.target_is_non_message = target_in_valid;
        }
    }

    // Message context — check for pre-existing deletion intents (may be multiple).
    // ORDER BY deletion_event_id ensures deterministic selection when the projector
    // picks the first matching-author intent for tombstone creation.
    if let ParsedEvent::Message(_) = parsed {
        if let ParsedEvent::Message(msg) = parsed {
            ctx.signer_user_mismatch_reason =
                signer_user_mismatch_reason(conn, recorded_by, &msg.signed_by, &msg.author_id)?;
        }

        let mut stmt = conn.prepare_cached(
            "SELECT deletion_event_id, author_id, created_at FROM deletion_intents WHERE recorded_by = ?1 AND target_kind = 'message' AND target_id = ?2 ORDER BY deletion_event_id",
        )?;
        ctx.deletion_intents = stmt
            .query_map(rusqlite::params![recorded_by, event_id_b64], |row| {
                Ok(super::super::result::DeletionIntentInfo {
                    deletion_event_id: row.get(0)?,
                    author_id: row.get(1)?,
                    created_at: row.get(2)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;
    }

    // Reaction context — check if target message is tombstoned (actual deleted_messages row).
    // Pending deletion_intents are NOT checked: an unverified intent does not prove the
    // message is deleted (author may not match), and if the message hasn't arrived yet the
    // reaction will be dep-blocked on target_event_id anyway.
    if let ParsedEvent::Reaction(rxn) = parsed {
        ctx.signer_user_mismatch_reason =
            signer_user_mismatch_reason(conn, recorded_by, &rxn.signed_by, &rxn.author_id)?;

        let target_b64 = event_id_to_base64(&rxn.target_event_id);
        ctx.target_message_deleted = conn.query_row(
            "SELECT COUNT(*) > 0 FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
            rusqlite::params![recorded_by, &target_b64],
            |row| row.get(0),
        )?;
    }

    // SecretShared context — check if recipient is removed
    if let ParsedEvent::SecretShared(ss) = parsed {
        let recipient_b64 = event_id_to_base64(&ss.recipient_event_id);
        ctx.recipient_removed = conn.query_row(
            "SELECT COUNT(*) > 0 FROM removed_entities WHERE recorded_by = ?1 AND target_event_id = ?2",
            rusqlite::params![recorded_by, &recipient_b64],
            |row| row.get(0),
        )?;
    }

    // FileSlice context — descriptors and existing slice
    if let ParsedEvent::FileSlice(fs) = parsed {
        let file_id_b64 = event_id_to_base64(&fs.file_id);
        let mut desc_stmt = conn.prepare(
            "SELECT event_id, signer_event_id
             FROM message_attachments
             WHERE recorded_by = ?1 AND file_id = ?2
             ORDER BY created_at ASC, event_id ASC",
        )?;
        ctx.file_descriptors = desc_stmt
            .query_map(rusqlite::params![recorded_by, &file_id_b64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?;

        // Check existing slice in same slot
        ctx.existing_file_slice = match conn.query_row(
            "SELECT event_id, descriptor_event_id
             FROM file_slices
             WHERE recorded_by = ?1 AND file_id = ?2 AND slice_number = ?3",
            rusqlite::params![recorded_by, &file_id_b64, fs.slice_number as i64],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ) {
            Ok(v) => Some(v),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.into()),
        };
    }

    // Encrypted context — secret key bytes
    if let ParsedEvent::Encrypted(enc) = parsed {
        let key_b64 = event_id_to_base64(&enc.key_event_id);
        ctx.secret_key_bytes = match conn.query_row(
            "SELECT key_bytes FROM secret_keys WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &key_b64],
            |row| row.get::<_, Vec<u8>>(0),
        ) {
            Ok(k) => Some(k),
            Err(rusqlite::Error::QueryReturnedNoRows) => None,
            Err(e) => return Err(e.into()),
        };
    }

    Ok(ctx)
}
