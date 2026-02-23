use crate::crypto::EventId;
use crate::event_modules::user_removed::{UserRemovedEvent, CreateUserRemovedCmd};
use crate::projection::create::create_signed_event_sync;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use super::super::ParsedEvent;

pub fn create_user_removed(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateUserRemovedCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let ur = ParsedEvent::UserRemoved(UserRemovedEvent {
        created_at_ms,
        target_event_id: cmd.target_event_id,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = create_signed_event_sync(db, recorded_by, &ur, signing_key)?;
    Ok(eid)
}

/// High-level remove-user command: creates a UserRemoved event and returns target hex.
pub fn remove_user(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    target_event_id: EventId,
) -> Result<String, String> {
    create_user_removed(
        db, recorded_by, signer_eid, signing_key, created_at_ms,
        CreateUserRemovedCmd { target_event_id },
    ).map_err(|e| format!("{}", e))?;

    Ok(hex::encode(target_event_id))
}
