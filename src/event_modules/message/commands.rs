use crate::crypto::EventId;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use super::create::{create, CreateMessageCmd};

/// High-level send command: creates a message event and returns a SendResponse.
pub fn send(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    workspace_id: [u8; 32],
    author_id: [u8; 32],
    content: &str,
) -> Result<super::SendResponse, String> {
    let eid = create(
        db, recorded_by, signer_eid, signing_key, created_at_ms,
        CreateMessageCmd {
            workspace_id,
            author_id,
            content: content.to_string(),
        },
    ).map_err(|e| format!("{}", e))?;

    Ok(super::SendResponse {
        content: content.to_string(),
        event_id: hex::encode(eid),
    })
}
