use crate::crypto::event_id_to_base64;
use crate::event_modules::ParsedEvent;
use crate::projection::contract::ContextSnapshot;
use rusqlite::{Connection, OptionalExtension};

/// Build projector-local context for File projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let file = match parsed {
        ParsedEvent::File(file) => file,
        _ => return Err("file context loader called for non-file event".into()),
    };

    let message_id_b64 = event_id_to_base64(&file.message_id);
    let target_message_deleted: bool = conn.query_row(
        "SELECT COUNT(*) > 0
         FROM deleted_messages
         WHERE recorded_by = ?1 AND message_id = ?2",
        rusqlite::params![recorded_by, &message_id_b64],
        |row| row.get(0),
    )?;
    let deleted_file_message_id = conn
        .query_row(
            "SELECT message_id
             FROM deleted_files
             WHERE recorded_by = ?1 AND file_id = ?2",
            rusqlite::params![recorded_by, event_id_to_base64(&file.file_id)],
            |row| row.get::<_, String>(0),
        )
        .optional()?;

    Ok(ContextSnapshot {
        target_message_deleted,
        deleted_file_message_id,
        ..ContextSnapshot::default()
    })
}
