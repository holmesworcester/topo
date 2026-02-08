use rusqlite::Connection;

use crate::crypto::event_id_to_base64;
use crate::events::{MessageEvent, MessageDeletionEvent, PeerKeyEvent, ReactionEvent, SecretKeyEvent, SignedMemoEvent};
use super::decision::ProjectionDecision;

/// Project a Message event into the messages table. Returns Ok(true) if written.
pub fn project_message(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    msg: &MessageEvent,
) -> Result<bool, rusqlite::Error> {
    let channel_id_b64 = event_id_to_base64(&msg.channel_id);
    let author_id_b64 = event_id_to_base64(&msg.author_id);
    let rows = conn.execute(
        "INSERT OR IGNORE INTO messages (message_id, channel_id, author_id, content, created_at, recorded_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            event_id_b64,
            channel_id_b64,
            author_id_b64,
            &msg.content,
            msg.created_at_ms as i64,
            recorded_by
        ],
    )?;
    Ok(rows > 0)
}

/// Project a Reaction event into the reactions table. Returns Ok(true) if written.
/// If the target message has been deleted, the reaction is structurally valid but skipped.
pub fn project_reaction(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    rxn: &ReactionEvent,
) -> Result<bool, rusqlite::Error> {
    let target_id_b64 = event_id_to_base64(&rxn.target_event_id);

    // Check if target message has been deleted — skip projection if so
    let target_deleted: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, &target_id_b64],
        |row| row.get(0),
    )?;
    if target_deleted {
        return Ok(true); // structurally valid, but skip projection (message gone)
    }

    let author_id_b64 = event_id_to_base64(&rxn.author_id);
    let rows = conn.execute(
        "INSERT OR IGNORE INTO reactions (event_id, target_event_id, author_id, emoji, created_at, recorded_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            event_id_b64,
            target_id_b64,
            author_id_b64,
            &rxn.emoji,
            rxn.created_at_ms as i64,
            recorded_by
        ],
    )?;
    Ok(rows > 0)
}

/// Project a PeerKey event into the peer_keys table. Returns Ok(true) if written.
pub fn project_peer_key(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    pk: &PeerKeyEvent,
) -> Result<bool, rusqlite::Error> {
    let public_key_hex = hex::encode(pk.public_key);
    let rows = conn.execute(
        "INSERT OR IGNORE INTO peer_keys (event_id, public_key, created_at, recorded_by)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            event_id_b64,
            public_key_hex,
            pk.created_at_ms as i64,
            recorded_by
        ],
    )?;
    Ok(rows > 0)
}

/// Project a SecretKey event into the secret_keys table. Returns Ok(true) if written.
pub fn project_secret_key(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    sk: &SecretKeyEvent,
) -> Result<bool, rusqlite::Error> {
    let rows = conn.execute(
        "INSERT OR IGNORE INTO secret_keys (event_id, key_bytes, created_at, recorded_by)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![
            event_id_b64,
            sk.key_bytes.as_slice(),
            sk.created_at_ms as i64,
            recorded_by
        ],
    )?;
    Ok(rows > 0)
}

/// Project a SignedMemo event into the signed_memos table. Returns Ok(true) if written.
pub fn project_signed_memo(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    memo: &SignedMemoEvent,
) -> Result<bool, rusqlite::Error> {
    let signed_by_b64 = event_id_to_base64(&memo.signed_by);
    let rows = conn.execute(
        "INSERT OR IGNORE INTO signed_memos (event_id, signed_by, signer_type, content, created_at, recorded_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            event_id_b64,
            signed_by_b64,
            memo.signer_type as i64,
            &memo.content,
            memo.created_at_ms as i64,
            recorded_by
        ],
    )?;
    Ok(rows > 0)
}

/// Project a MessageDeletion event: verify author matches, tombstone, cascade-delete message + reactions.
/// Returns ProjectionDecision directly (can Reject on auth failure).
pub fn project_message_deletion(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    del: &MessageDeletionEvent,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    let target_b64 = event_id_to_base64(&del.target_event_id);
    let del_author_b64 = event_id_to_base64(&del.author_id);

    // Check if already tombstoned
    let already_deleted: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, &target_b64],
        |row| row.get(0),
    )?;
    if already_deleted {
        return Ok(ProjectionDecision::AlreadyProcessed);
    }

    // Look up target message
    let msg_author: Option<String> = match conn.query_row(
        "SELECT author_id FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, &target_b64],
        |row| row.get(0),
    ) {
        Ok(a) => Some(a),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };

    match msg_author {
        None => {
            return Ok(ProjectionDecision::Reject {
                reason: "target message not found".to_string(),
            });
        }
        Some(author_b64) => {
            // Authorization: deletion author must match message author
            if author_b64 != del_author_b64 {
                return Ok(ProjectionDecision::Reject {
                    reason: "deletion author does not match message author".to_string(),
                });
            }
        }
    }

    // Tombstone
    conn.execute(
        "INSERT OR IGNORE INTO deleted_messages (recorded_by, message_id, deletion_event_id, author_id, deleted_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            recorded_by,
            &target_b64,
            event_id_b64,
            &del_author_b64,
            del.created_at_ms as i64
        ],
    )?;

    // Cascade: remove message and its reactions
    conn.execute(
        "DELETE FROM messages WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, &target_b64],
    )?;
    conn.execute(
        "DELETE FROM reactions WHERE recorded_by = ?1 AND target_event_id = ?2",
        rusqlite::params![recorded_by, &target_b64],
    )?;

    Ok(ProjectionDecision::Valid)
}
