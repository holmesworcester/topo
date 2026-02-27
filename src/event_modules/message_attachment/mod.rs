pub mod wire;
pub mod projector;

// Re-export stable public API so callers import from `event_modules::message_attachment`.
pub use wire::{
    MessageAttachmentEvent, MESSAGE_ATTACHMENT_WIRE_SIZE,
    attachment_offsets,
    parse_message_attachment, encode_message_attachment,
    MESSAGE_ATTACHMENT_META,
};
pub use projector::project_pure;

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS message_attachments (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            file_id TEXT NOT NULL,
            blob_bytes INTEGER NOT NULL,
            total_slices INTEGER NOT NULL,
            slice_bytes INTEGER NOT NULL,
            root_hash BLOB NOT NULL,
            key_event_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            signer_event_id TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_msg_att_message
            ON message_attachments(recorded_by, message_id);
        CREATE INDEX IF NOT EXISTS idx_msg_att_file
            ON message_attachments(recorded_by, file_id);
        ",
    )?;
    Ok(())
}
