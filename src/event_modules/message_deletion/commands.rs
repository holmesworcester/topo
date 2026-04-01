use crate::crypto::EventId;
use crate::projection::create::create_encrypted_event_synchronous;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use super::super::ParsedEvent;
use super::wire::MessageDeletionEvent;

pub struct CreateMessageDeletionCmd {
    pub target_event_id: [u8; 32],
    pub author_id: [u8; 32],
}

pub fn create(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateMessageDeletionCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let del = ParsedEvent::MessageDeletion(MessageDeletionEvent {
        created_at_ms,
        target_event_id: cmd.target_event_id,
        author_id: cmd.author_id,
    });
    let key_event_id =
        super::super::workspace::identity_ops::ensure_content_key_for_peer(db, recorded_by)?;
    let eid = create_encrypted_event_synchronous(
        db,
        recorded_by,
        &key_event_id,
        &del,
        Some((signer_eid, signing_key)),
    )?;
    Ok(eid)
}

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
        db,
        recorded_by,
        signer_eid,
        signing_key,
        created_at_ms,
        CreateMessageDeletionCmd {
            target_event_id,
            author_id,
        },
    )
    .map_err(|e| format!("{}", e))?;

    Ok(hex::encode(target_event_id))
}
