use crate::crypto::EventId;
use crate::projection::create::create_encrypted_event_synchronous_with_owner;
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
    let eid = create_encrypted_event_synchronous_with_owner(
        db,
        recorded_by,
        &key_event_id,
        Some(&cmd.target_event_id),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::event_id_to_base64;
    use crate::db::{open_in_memory, schema::create_tables};
    use crate::event_modules::message::commands::{create as create_message, CreateMessageCmd};
    use crate::event_modules::workspace;
    use crate::event_modules::workspace::commands::create_workspace;

    fn peer_id_for_signing_key(key: &SigningKey) -> String {
        hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
            &key.verifying_key().to_bytes(),
        ))
    }

    #[test]
    fn react_returns_response_for_created_message_target() {
        let conn = open_in_memory().expect("open in-memory db");
        create_tables(&conn).expect("create tables");

        let workspace =
            create_workspace(&conn, "bootstrap", "ws", "alice", "laptop").expect("create ws");
        let recorded_by = peer_id_for_signing_key(&workspace.peer_shared_key);
        let ctx =
            workspace::load_local_authoring_context(&conn, &recorded_by).expect("authoring ctx");
        let message_event_id = create_message(
            &conn,
            &recorded_by,
            &ctx.signer_event_id,
            &ctx.signing_key,
            1_000,
            CreateMessageCmd {
                workspace_id: ctx.workspace_id,
                author_id: ctx.author_id,
                content: "hello".to_string(),
            },
        )
        .expect("create message");

        let response = react(
            &conn,
            &recorded_by,
            &ctx.signer_event_id,
            &ctx.signing_key,
            2_000,
            ctx.author_id,
            message_event_id,
            "thumbsup",
        )
        .expect("react");

        assert_eq!(response.emoji, "thumbsup");
        assert_eq!(response.event_id.len(), 64);

        let (target_event_id, emoji): (String, String) = conn
            .query_row(
                "SELECT target_event_id, emoji
                 FROM reactions
                 WHERE recorded_by = ?1
                 ORDER BY created_at ASC, event_id ASC
                 LIMIT 1",
                rusqlite::params![&recorded_by],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("load projected reaction");
        assert_eq!(target_event_id, event_id_to_base64(&message_event_id));
        assert_eq!(emoji, "thumbsup");
    }
}
