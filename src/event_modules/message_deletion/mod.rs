pub mod wire;
pub mod projector;
pub mod commands;
pub mod queries;

// Re-export stable public API so callers import from `event_modules::message_deletion`.
pub use wire::{
    MessageDeletionEvent,
    parse_message_deletion,
    encode_message_deletion,
    MESSAGE_DELETION_WIRE_SIZE,
    MESSAGE_DELETION_META,
};
pub use commands::{CreateMessageDeletionCmd, create, delete_message};
pub use queries::list_deleted_ids;
pub use projector::project_pure;

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS deleted_messages (
            recorded_by TEXT NOT NULL,
            message_id TEXT NOT NULL,
            deletion_event_id TEXT NOT NULL,
            author_id TEXT NOT NULL,
            deleted_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, message_id)
        );

        CREATE TABLE IF NOT EXISTS deletion_intents (
            recorded_by TEXT NOT NULL,
            target_kind TEXT NOT NULL,
            target_id TEXT NOT NULL,
            deletion_event_id TEXT NOT NULL,
            author_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, target_kind, target_id, deletion_event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_deletion_intents_target
            ON deletion_intents(recorded_by, target_id);
        ",
    )?;
    Ok(())
}
