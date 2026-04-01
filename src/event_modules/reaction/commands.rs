use crate::crypto::EventId;
use crate::projection::create::create_encrypted_event_synchronous;
use crate::service::open_db_for_peer;
use crate::state::db::queue::current_timestamp_ms_u64;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use super::super::message;
use super::super::ParsedEvent;
use super::wire::ReactionEvent;

use serde::{Deserialize, Serialize};

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
    });
    let key_event_id =
        super::super::workspace::identity_ops::ensure_content_key_for_peer(db, recorded_by)?;
    let eid = create_encrypted_event_synchronous(
        db,
        recorded_by,
        &key_event_id,
        &rxn,
        Some((signer_eid, signing_key)),
    )?;
    Ok(eid)
}

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
        db,
        recorded_by,
        signer_eid,
        signing_key,
        created_at_ms,
        CreateReactionCmd {
            target_event_id,
            author_id,
            emoji: emoji.to_string(),
        },
    )
    .map_err(|e| format!("{}", e))?;

    Ok(ReactResponse {
        emoji: emoji.to_string(),
        event_id: hex::encode(eid),
    })
}

// ---------------------------------------------------------------------------
// Peer-level command wrapper (moved from service.rs)
// ---------------------------------------------------------------------------

/// React to a message as a specific peer.
pub fn react_for_peer(
    db_path: &str,
    peer_id: &str,
    target_hex: &str,
    emoji: &str,
) -> Result<ReactResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    let ctx = super::super::workspace::load_local_authoring_context(&db, &recorded_by)?;
    let target_event_id = message::resolve(&db, &recorded_by, target_hex)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    react(
        &db,
        &recorded_by,
        &ctx.signer_event_id,
        &ctx.signing_key,
        current_timestamp_ms_u64(),
        ctx.author_id,
        target_event_id,
        emoji,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })
}
