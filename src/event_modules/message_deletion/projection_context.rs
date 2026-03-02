use crate::crypto::event_id_to_base64;
use crate::event_modules::ParsedEvent;
use crate::projection::contract::ContextSnapshot;
use rusqlite::Connection;

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

/// Build projector-local context for MessageDeletion projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let del = match parsed {
        ParsedEvent::MessageDeletion(del) => del,
        _ => {
            return Err(
                "message_deletion context loader called for non-message_deletion event".into(),
            )
        }
    };

    let mut ctx = ContextSnapshot::default();
    ctx.signer_user_mismatch_reason =
        signer_user_mismatch_reason(conn, recorded_by, &del.signed_by, &del.author_id)?;

    let target_b64 = event_id_to_base64(&del.target_event_id);

    ctx.target_tombstone_author = match conn.query_row(
        "SELECT author_id FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, &target_b64],
        |row| row.get::<_, String>(0),
    ) {
        Ok(v) => Some(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };

    ctx.target_message_author = match conn.query_row(
        "SELECT author_id FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, &target_b64],
        |row| row.get::<_, String>(0),
    ) {
        Ok(v) => Some(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };

    if ctx.target_message_author.is_none() && ctx.target_tombstone_author.is_none() {
        ctx.target_is_non_message = conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &target_b64],
            |row| row.get(0),
        )?;
    }

    Ok(ctx)
}
