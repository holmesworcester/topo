use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::ContextSnapshot;
use rusqlite::{Connection, OptionalExtension};

fn admin_user_key_mismatch_reason(
    conn: &Connection,
    recorded_by: &str,
    user_event_id: &[u8; 32],
    public_key: &[u8; 32],
) -> Result<Option<String>, rusqlite::Error> {
    let user_event_id_b64 = event_id_to_base64(user_event_id);
    let user_public_key: Option<Vec<u8>> = conn
        .query_row(
            "SELECT public_key FROM users WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &user_event_id_b64],
            |row| row.get(0),
        )
        .optional()?;

    let Some(user_public_key) = user_public_key else {
        return Ok(Some(format!(
            "no users row for user_event_id {}",
            user_event_id_b64
        )));
    };

    if user_public_key.len() != 32 {
        return Ok(Some(format!(
            "user {} has invalid public_key length {}",
            user_event_id_b64,
            user_public_key.len()
        )));
    }

    if user_public_key.as_slice() != public_key {
        return Ok(Some(format!(
            "admin public_key does not match user public_key for {}",
            user_event_id_b64
        )));
    }

    Ok(None)
}

/// Build projector-local context for Admin projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let admin = match parsed {
        ParsedEvent::Admin(admin) => admin,
        _ => return Err("admin context loader called for non-admin event".into()),
    };

    Ok(ContextSnapshot {
        admin_user_key_mismatch_reason: admin_user_key_mismatch_reason(
            conn,
            recorded_by,
            &admin.user_event_id,
            &admin.public_key,
        )?,
        ..ContextSnapshot::default()
    })
}
