use crate::crypto::event_id_to_base64;
use crate::event_modules::ParsedEvent;
use crate::projection::contract::{ContextSnapshot, DeletionIntentInfo};
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

/// Build projector-local context for Message projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let msg = match parsed {
        ParsedEvent::Message(msg) => msg,
        _ => return Err("message context loader called for non-message event".into()),
    };

    let signer_user_mismatch_reason =
        signer_user_mismatch_reason(conn, recorded_by, &msg.signed_by, &msg.author_id)?;

    let mut stmt = conn.prepare_cached(
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
