use crate::crypto::EventId;
use crate::projection::create::create_signed_event_sync;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use super::super::ParsedEvent;
use super::wire::ReactionEvent;

pub struct CreateReactionCmd {
    pub target_event_id: [u8; 32],
    pub author_id: [u8; 32],
    pub emoji: String,
}

pub fn create(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateReactionCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let rxn = ParsedEvent::Reaction(ReactionEvent {
        created_at_ms,
        target_event_id: cmd.target_event_id,
        author_id: cmd.author_id,
        emoji: cmd.emoji,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let eid = create_signed_event_sync(db, recorded_by, &rxn, signing_key)?;
    Ok(eid)
}
