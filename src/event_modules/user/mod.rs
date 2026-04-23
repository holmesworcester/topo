//! `user` event (type 14): publishes a user's Ed25519 signing key and display name. This
//! is the author identity referenced by `author_id` on content events (messages, reactions).
//! The actual signer event for content writes is typically the author's `peer_shared`
//! device binding, not the user event itself.

pub mod projector;
pub mod queries;
pub mod wire;

pub use projector::{build_projector_context, project_pure};
pub use queries::{
    count, first_event_id, list, list_items, resolve, resolve_number, UserItem, UserRow,
};
pub use wire::{encode_user, parse_user, UserEvent, USER_META, USER_WIRE_SIZE};

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS users (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            username TEXT,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}
