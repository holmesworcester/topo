pub mod wire;
pub mod projector;
pub mod commands;
pub mod queries;

// Re-export stable public API so callers import from `event_modules::reaction`.
pub use wire::{
    ReactionEvent,
    parse_reaction,
    encode_reaction,
    offsets,
    REACTION_WIRE_SIZE,
    REACTION_TYPE_META,
};
pub use commands::{CreateReactionCmd, create, react, ReactResponse, react_for_peer};
pub use queries::{ReactionRow, list_rows, list_for_message, count, ReactionItem, list, ReactionWithAuthor, list_for_message_with_authors};
pub use projector::project_pure;

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
