pub mod commands;
pub mod projector;
pub mod queries;
pub mod wire;

// Re-export stable public API so callers import from `event_modules::user`.
pub use commands::{ban_for_peer, create_user_removed, remove_user, BanResponse};
pub use projector::project_pure;
pub use queries::{count, first_event_id, list, list_items, UserItem, UserRow};
pub use wire::{
    encode_user_boot, encode_user_ongoing, parse_user_boot, parse_user_ongoing, UserBootEvent,
    UserOngoingEvent, USER_BOOT_META, USER_ONGOING_META, USER_WIRE_SIZE,
};

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
