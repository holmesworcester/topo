use crate::crypto::event_id_to_base64;
use crate::event_modules::ParsedEvent;
use crate::projection::result::ContextSnapshot;
use rusqlite::Connection;

fn signer_user_mismatch_reason(
    conn: &Connection,
    recorded_by: &str,
    signed_by: &[u8; 32],
    author_id: &[u8; 32],
) -> Result<Option<String>, rusqlite::Error> {
    let signed_by_b64 = event_id_to_base64(signed_by);
    let author_id_b64 = event_id_to_base64(author_id);

    let peer_user_eid: String = match conn.query_row(
        "SELECT COALESCE(user_event_id, '') FROM peers_shared WHERE recorded_by = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &signed_by_b64],
        |row| row.get::<_, String>(0),
    ) {
        Ok(v) => v,
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            return Ok(Some(format!(
                "no peers_shared entry for signer {}",
                signed_by_b64
            )));
        }
        Err(e) => return Err(e),
    };

    if peer_user_eid.is_empty() {
        return Ok(Some(format!(
            "peers_shared entry for signer {} has no user_event_id (legacy row)",
            signed_by_b64
        )));
    }

    if peer_user_eid != author_id_b64 {
        return Ok(Some(format!(
            "signer {} belongs to user {} but author_id claims {}",
            signed_by_b64, peer_user_eid, author_id_b64
        )));
    }

    Ok(None)
}

/// Build projector-local context for Reaction projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let rxn = match parsed {
        ParsedEvent::Reaction(rxn) => rxn,
        _ => return Err("reaction context loader called for non-reaction event".into()),
    };

    let target_b64 = event_id_to_base64(&rxn.target_event_id);
    let target_message_deleted = conn.query_row(
        "SELECT COUNT(*) > 0 FROM deleted_messages WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, &target_b64],
        |row| row.get(0),
    )?;
    let signer_user_mismatch_reason =
        signer_user_mismatch_reason(conn, recorded_by, &rxn.signed_by, &rxn.author_id)?;

    Ok(ContextSnapshot {
        signer_user_mismatch_reason,
        target_message_deleted,
        ..ContextSnapshot::default()
    })
}

use serde::{Deserialize, Serialize};

pub struct ReactionRow {
    pub event_id: String,
    pub target_event_id: String,
    pub emoji: String,
}

pub fn list_rows(db: &Connection, recorded_by: &str) -> Result<Vec<ReactionRow>, rusqlite::Error> {
    let mut stmt = db
        .prepare("SELECT event_id, target_event_id, emoji FROM reactions WHERE recorded_by = ?1")?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(ReactionRow {
                event_id: row.get(0)?,
                target_event_id: row.get(1)?,
                emoji: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn list_for_message(
    db: &Connection,
    recorded_by: &str,
    target_event_id_b64: &str,
) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt =
        db.prepare("SELECT emoji FROM reactions WHERE recorded_by = ?1 AND target_event_id = ?2")?;
    let emojis = stmt
        .query_map(rusqlite::params![recorded_by, target_event_id_b64], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(emojis)
}

pub fn count(db: &Connection, recorded_by: &str) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM reactions WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReactionItem {
    pub event_id: String,
    pub target_event_id: String,
    pub emoji: String,
}

/// Assemble a list of ReactionItems from the database.
pub fn list(db: &Connection, recorded_by: &str) -> Result<Vec<ReactionItem>, rusqlite::Error> {
    let rows = list_rows(db, recorded_by)?;
    Ok(rows
        .into_iter()
        .map(|row| ReactionItem {
            event_id: row.event_id,
            target_event_id: row.target_event_id,
            emoji: row.emoji,
        })
        .collect())
}

pub struct ReactionWithAuthor {
    pub emoji: String,
    pub reactor_name: String,
}

/// List reactions for a specific message, including reactor username.
pub fn list_for_message_with_authors(
    db: &Connection,
    recorded_by: &str,
    target_event_id_b64: &str,
) -> Result<Vec<ReactionWithAuthor>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT r.emoji, COALESCE(u.username, '') as reactor_name
         FROM reactions r
         LEFT JOIN users u ON r.author_id = u.event_id AND r.recorded_by = u.recorded_by
         WHERE r.target_event_id = ?1 AND r.recorded_by = ?2",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![target_event_id_b64, recorded_by], |row| {
            Ok(ReactionWithAuthor {
                emoji: row.get(0)?,
                reactor_name: row.get(1)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}
