use crate::crypto::EventId;
use crate::projection::create::create_signed_event_sync;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use super::super::ParsedEvent;
use super::wire::MessageEvent;

pub struct CreateMessageCmd {
    pub workspace_id: [u8; 32],
    pub author_id: [u8; 32],
    pub content: String,
}

pub fn create(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateMessageCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms,
        workspace_id: cmd.workspace_id,
        author_id: cmd.author_id,
        content: cmd.content,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = create_signed_event_sync(db, recorded_by, &msg, signing_key)?;
    Ok(eid)
}
