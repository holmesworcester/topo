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

fn column_exists(conn: &Connection, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare("PRAGMA table_info(user_invites)")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        if crate::db::sql_types::get_text(row, 1)? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

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
    if !column_exists(conn, "key_history_event_id")? {
        conn.execute(
            "ALTER TABLE user_invites ADD COLUMN key_history_event_id TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    Ok(())
}
