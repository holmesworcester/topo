use rusqlite::Connection;

use crate::crypto::event_id_to_base64;
use crate::events::{MessageEvent, ReactionEvent};

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
pub fn project_reaction(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    rxn: &ReactionEvent,
) -> Result<bool, rusqlite::Error> {
    let target_id_b64 = event_id_to_base64(&rxn.target_event_id);
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
