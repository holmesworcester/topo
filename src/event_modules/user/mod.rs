pub mod wire;
pub mod projector;
pub mod queries;
pub mod commands;

// Re-export stable public API so callers import from `event_modules::user`.
pub use wire::{
    UserBootEvent, UserOngoingEvent,
    parse_user_boot, encode_user_boot,
    parse_user_ongoing, encode_user_ongoing,
    USER_WIRE_SIZE,
    USER_BOOT_META, USER_ONGOING_META,
};
pub use queries::{UserRow, UserItem, list, list_items, count, first_event_id};
pub use commands::{create_user_removed, remove_user, BanResponse, ban_for_peer};
pub use projector::project_pure;

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

pub fn identity_rebind_recorded_by_tables() -> &'static [&'static str] {
    &["users"]
}
