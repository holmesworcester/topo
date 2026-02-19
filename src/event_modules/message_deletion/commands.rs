use crate::crypto::EventId;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use super::create::{create, CreateMessageDeletionCmd};

/// High-level delete command: creates a message_deletion event and returns target hex.
pub fn delete_message(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    author_id: [u8; 32],
    target_event_id: [u8; 32],
) -> Result<String, String> {
    create(
        db, recorded_by, signer_eid, signing_key, created_at_ms,
        CreateMessageDeletionCmd {
            target_event_id,
            author_id,
        },
    ).map_err(|e| format!("{}", e))?;

    Ok(hex::encode(target_event_id))
}
