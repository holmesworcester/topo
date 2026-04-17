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
    Ok(())
}
