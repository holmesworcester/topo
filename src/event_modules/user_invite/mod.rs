mod projection_context;
pub mod projector;
pub mod wire;

// Re-export stable public API so callers import from `event_modules::user_invite`.
pub use projector::project_pure;
pub use wire::{
    encode_user_invite_boot, encode_user_invite_ongoing, parse_user_invite_boot,
    parse_user_invite_ongoing, UserInviteBootEvent, UserInviteOngoingEvent, USER_INVITE_BOOT_META,
    USER_INVITE_BOOT_WIRE_SIZE, USER_INVITE_ONGOING_META, USER_INVITE_ONGOING_WIRE_SIZE,
};

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS user_invites (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}
