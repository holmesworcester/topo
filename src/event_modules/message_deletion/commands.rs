use crate::crypto::EventId;
use crate::projection::create::create_encrypted_event;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use super::super::ParsedEvent;
use super::wire::MessageDeletionEvent;

pub struct CreateMessageDeletionCmd {
    pub target_event_id: [u8; 32],
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
    });
    let key_event_id =
        super::super::workspace::identity_ops::ensure_content_key_for_peer(db, recorded_by)?;
    let eid = create_encrypted_event(
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
    target_event_id: [u8; 32],
) -> Result<String, String> {
    create(
        db,
        recorded_by,
        signer_eid,
        signing_key,
        created_at_ms,
        CreateMessageDeletionCmd { target_event_id },
    )
    .map_err(|e| format!("{}", e))?;

    Ok(hex::encode(target_event_id))
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
    fn delete_message_returns_target_hex_for_created_message() {
        let conn = open_in_memory().expect("open in-memory db");
        create_tables(&conn).expect("create tables");
        crate::transport::materialize_daemon_identity(&conn).expect("materialize daemon identity");

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

        let target_hex = delete_message(
            &conn,
            &recorded_by,
            &ctx.signer_event_id,
            &ctx.signing_key,
            2_000,
            message_event_id,
        )
        .expect("delete message");

        assert_eq!(target_hex, hex::encode(message_event_id));

        let intent_count: i64 = conn
            .query_row(
                "SELECT COUNT(*)
                 FROM deletion_intents
                 WHERE recorded_by = ?1 AND target_id = ?2",
                rusqlite::params![&recorded_by, event_id_to_base64(&message_event_id)],
                |row| row.get(0),
            )
            .expect("load deletion intent");
        assert_eq!(intent_count, 1);
    }
}
