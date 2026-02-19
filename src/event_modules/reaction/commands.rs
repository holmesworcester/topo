use crate::crypto::EventId;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use serde::{Deserialize, Serialize};

use super::create::{create, CreateReactionCmd};

#[derive(Debug, Serialize, Deserialize)]
pub struct ReactResponse {
    pub emoji: String,
    pub event_id: String,
}

/// High-level react command: creates a reaction event and returns a ReactResponse.
pub fn react(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    author_id: [u8; 32],
    target_event_id: [u8; 32],
    emoji: &str,
) -> Result<ReactResponse, String> {
    let eid = create(
        db, recorded_by, signer_eid, signing_key, created_at_ms,
        CreateReactionCmd {
            target_event_id,
            author_id,
            emoji: emoji.to_string(),
        },
    ).map_err(|e| format!("{}", e))?;

    Ok(ReactResponse {
        emoji: emoji.to_string(),
        event_id: hex::encode(eid),
    })
}
