//! `user_invite` event (type 10): an invite that authorizes a new user to join a workspace
//! (bootstrap and ongoing invites). Wire `type_name` remains the historical
//! `user_invite_shared` for durable on-the-wire compatibility.

pub mod projector;
pub mod wire;

pub use projector::project_pure;
pub use wire::{
    encode_user_invite, parse_user_invite, UserInviteEvent, USER_INVITE_META, USER_INVITE_WIRE_SIZE,
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
