//! `device_invite` event (type 12): an invite that binds a new device/peer to an existing
//! user on the workspace. The wire `type_name` remains the historical `peer_invite_shared`
//! for durable on-the-wire compatibility; see the canonical-naming note in DESIGN.md.

pub mod projector;
pub mod wire;

pub use projector::project_pure;
pub use wire::{
    encode_device_invite, parse_device_invite, DeviceInviteEvent, DEVICE_INVITE_META,
    DEVICE_INVITE_WIRE_SIZE,
};

use rusqlite::Connection;

fn column_exists(conn: &Connection, column: &str) -> rusqlite::Result<bool> {
    let mut stmt = conn.prepare("PRAGMA table_info(device_invites)")?;
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
        CREATE TABLE IF NOT EXISTS device_invites (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    if !column_exists(conn, "key_history_event_id")? {
        conn.execute(
            "ALTER TABLE device_invites ADD COLUMN key_history_event_id TEXT NOT NULL DEFAULT ''",
            [],
        )?;
    }
    Ok(())
}
