pub mod commands;
mod projection_context;
pub mod projector;
pub mod queries;
pub mod wire;

// Re-export stable public API so callers import from `event_modules::reaction`.
pub use commands::{create, react, react_for_peer, CreateReactionCmd, ReactResponse};
pub use projector::project_pure;
pub use queries::{
    count, list, list_for_message, list_for_message_with_authors, list_rows, ReactionItem,
    ReactionRow, ReactionWithAuthor,
};
pub use wire::{
    encode_reaction, offsets, parse_reaction, ReactionEvent, REACTION_TYPE_META, REACTION_WIRE_SIZE,
};

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS reactions (
            event_id TEXT NOT NULL,
            target_event_id TEXT NOT NULL,
            author_id TEXT NOT NULL,
            emoji TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            recorded_by TEXT NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_reactions_target
            ON reactions(recorded_by, target_event_id);
        ",
    )?;
    Ok(())
}
