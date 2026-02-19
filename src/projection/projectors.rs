use rusqlite::Connection;

use super::decision::ProjectionDecision;
use crate::crypto::event_id_to_base64;
use crate::events::{
    FileSliceEvent, MessageAttachmentEvent, MessageDeletionEvent, MessageEvent,
    ReactionEvent, SecretKeyEvent, SignedMemoEvent,
};

/// Verify that signed_by peer's user_event_id matches the claimed author_id.
/// Returns Ok(()) on match, Err with reason on mismatch or missing data.
fn verify_signer_user_match(
    conn: &Connection,
    recorded_by: &str,
    signed_by: &[u8; 32],
    author_id: &[u8; 32],
) -> Result<(), String> {
    let signed_by_b64 = event_id_to_base64(signed_by);
    let author_id_b64 = event_id_to_base64(author_id);

    let peer_user_eid: String = conn
        .query_row(
            "SELECT user_event_id FROM peers_shared WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, &signed_by_b64],
            |row| row.get(0),
        )
        .map_err(|_| format!("no peers_shared entry for signer {}", signed_by_b64))?;

    if peer_user_eid != author_id_b64 {
        return Err(format!(
            "signer {} belongs to user {} but author_id claims {}",
            signed_by_b64, peer_user_eid, author_id_b64
        ));
    }
    Ok(())
}

/// Project a Message event into the messages table. Returns Ok(true) if written.
pub fn project_message(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    msg: &MessageEvent,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    // Verify signer-user match
    if let Err(reason) = verify_signer_user_match(conn, recorded_by, &msg.signed_by, &msg.author_id) {
        return Ok(ProjectionDecision::Reject { reason });
    }

    let workspace_id_b64 = event_id_to_base64(&msg.workspace_id);
    let author_id_b64 = event_id_to_base64(&msg.author_id);
    conn.execute(
        "INSERT OR IGNORE INTO messages (message_id, workspace_id, author_id, content, created_at, recorded_by)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            event_id_b64,
            workspace_id_b64,
            author_id_b64,
            &msg.content,
            msg.created_at_ms as i64,
            recorded_by
        ],
    )?;
    Ok(ProjectionDecision::Valid)
}

/// Project a Reaction event into the reactions table.
/// If the target message has been deleted, the reaction is structurally valid but skipped.
pub fn project_reaction(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    rxn: &ReactionEvent,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    // Verify signer-user match
    if let Err(reason) = verify_signer_user_match(conn, recorded_by, &rxn.signed_by, &rxn.author_id) {
        return Ok(ProjectionDecision::Reject { reason });
    }

    let target_id_b64 = event_id_to_base64(&rxn.target_event_id);

    // Check if target message has been deleted — skip projection if so
    let target_deleted: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, &target_id_b64],
        |row| row.get(0),
    )?;
    if target_deleted {
        return Ok(ProjectionDecision::Valid); // structurally valid, but skip projection (message gone)
    }

    let author_id_b64 = event_id_to_base64(&rxn.author_id);
    conn.execute(
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
    Ok(ProjectionDecision::Valid)
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
    // Verify signer-user match
    if let Err(reason) = verify_signer_user_match(conn, recorded_by, &del.signed_by, &del.author_id) {
        return Ok(ProjectionDecision::Reject { reason });
    }

    let target_b64 = event_id_to_base64(&del.target_event_id);
    let del_author_b64 = event_id_to_base64(&del.author_id);

    // Check if already tombstoned — if so, verify author against tombstone before accepting
    let tombstone_author: Option<String> = match conn.query_row(
        "SELECT author_id FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, &target_b64],
        |row| row.get::<_, String>(0),
    ) {
        Ok(a) => Some(a),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };

    if let Some(ref stored_author) = tombstone_author {
        // Tombstone exists — still enforce author match
        if stored_author != &del_author_b64 {
            return Ok(ProjectionDecision::Reject {
                reason: "deletion author does not match message author".to_string(),
            });
        }
        return Ok(ProjectionDecision::AlreadyProcessed);
    }

    // No tombstone — look up target message for authorization
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

pub fn project_message_attachment(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    att: &MessageAttachmentEvent,
) -> Result<bool, rusqlite::Error> {
    let message_id_b64 = event_id_to_base64(&att.message_id);
    let file_id_b64 = event_id_to_base64(&att.file_id);
    let key_event_id_b64 = event_id_to_base64(&att.key_event_id);
    let signer_event_id_b64 = event_id_to_base64(&att.signed_by);
    let rows = conn.execute(
        "INSERT OR IGNORE INTO message_attachments (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at, signer_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        rusqlite::params![
            recorded_by,
            event_id_b64,
            message_id_b64,
            file_id_b64,
            att.blob_bytes as i64,
            att.total_slices as i64,
            att.slice_bytes as i64,
            att.root_hash.as_slice(),
            key_event_id_b64,
            &att.filename,
            &att.mime_type,
            att.created_at_ms as i64,
            signer_event_id_b64,
        ],
    )?;
    Ok(rows > 0)
}

/// Project a FileSlice event into the file_slices table (index only, no ciphertext).
/// Authorization: if a MessageAttachment descriptor exists for this file_id,
/// the file_slice signer must match the descriptor's signer. If no descriptor
/// exists yet, the file_slice is guard-blocked (Block with empty missing).
/// Returns Ok(ProjectionDecision::Valid) on success or idempotent replay.
/// Returns Ok(ProjectionDecision::Reject) if signer mismatch or slot conflict.
pub fn project_file_slice(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    fs: &FileSliceEvent,
) -> Result<ProjectionDecision, rusqlite::Error> {
    let file_id_b64 = event_id_to_base64(&fs.file_id);
    let slice_signer_b64 = event_id_to_base64(&fs.signed_by);

    // Authorization: load descriptors for this file_id deterministically.
    let mut desc_stmt = conn.prepare(
        "SELECT event_id, signer_event_id
         FROM message_attachments
         WHERE recorded_by = ?1 AND file_id = ?2
         ORDER BY created_at ASC, event_id ASC",
    )?;
    let descriptors: Vec<(String, String)> = desc_stmt
        .query_map(rusqlite::params![recorded_by, &file_id_b64], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    drop(desc_stmt);

    if descriptors.is_empty() {
        // No descriptor yet — guard-block until MessageAttachment arrives.
        conn.execute(
            "INSERT OR IGNORE INTO file_slice_guard_blocks (peer_id, file_id, event_id)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![recorded_by, &file_id_b64, event_id_b64],
        )?;
        return Ok(ProjectionDecision::Block { missing: vec![] });
    }

    // Ensure file_id does not map to conflicting descriptor signers.
    let mut descriptor_signers = std::collections::BTreeSet::new();
    for (_, signer) in &descriptors {
        descriptor_signers.insert(signer.clone());
    }
    if descriptor_signers.len() > 1 {
        conn.execute(
            "DELETE FROM file_slice_guard_blocks WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
        )?;
        return Ok(ProjectionDecision::Reject {
            reason: format!(
                "file_id {} maps to multiple attachment signers ({}), cannot authorize file_slice",
                file_id_b64,
                descriptor_signers.len()
            ),
        });
    }

    let (descriptor_event_id, descriptor_signer) = descriptors[0].clone();
    if descriptor_signer != slice_signer_b64 {
        conn.execute(
            "DELETE FROM file_slice_guard_blocks WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
        )?;
        return Ok(ProjectionDecision::Reject {
            reason: format!(
                "file_slice signer {} does not match attachment descriptor signer {}",
                slice_signer_b64, descriptor_signer
            ),
        });
    }

    let rows = conn.execute(
        "INSERT OR IGNORE INTO file_slices (recorded_by, file_id, slice_number, event_id, created_at, descriptor_event_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![
            recorded_by,
            &file_id_b64,
            fs.slice_number as i64,
            event_id_b64,
            fs.created_at_ms as i64,
            &descriptor_event_id,
        ],
    )?;
    if rows > 0 {
        conn.execute(
            "DELETE FROM file_slice_guard_blocks WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
        )?;
        return Ok(ProjectionDecision::Valid);
    }

    // Row already exists — check if same event_id (idempotent replay) or conflict
    let (existing_event_id, existing_descriptor_event_id): (String, String) = conn.query_row(
        "SELECT event_id, descriptor_event_id
         FROM file_slices
         WHERE recorded_by = ?1 AND file_id = ?2 AND slice_number = ?3",
        rusqlite::params![recorded_by, &file_id_b64, fs.slice_number as i64],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;

    if existing_event_id == event_id_b64 {
        if existing_descriptor_event_id != descriptor_event_id {
            return Ok(ProjectionDecision::Reject {
                reason: format!(
                    "file_slice descriptor mismatch: existing {} vs authorized {}",
                    existing_descriptor_event_id, descriptor_event_id
                ),
            });
        }
        conn.execute(
            "DELETE FROM file_slice_guard_blocks WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
        )?;
        Ok(ProjectionDecision::Valid) // idempotent replay
    } else {
        conn.execute(
            "DELETE FROM file_slice_guard_blocks WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, event_id_b64],
        )?;
        Ok(ProjectionDecision::Reject {
            reason: format!(
                "duplicate file_slice: slot ({}, {}, {}) already claimed by event {}",
                recorded_by, file_id_b64, fs.slice_number, existing_event_id
            ),
        })
    }
}
