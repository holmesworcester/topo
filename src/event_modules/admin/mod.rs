//! `admin` event (type 18): promotes a user (`user_event_id`) to admin, binding the
//! admin's public_key to that user. Bootstrap grants depend on and are signed by the
//! workspace; ongoing grants depend on a prior `admin` event and are signed by an
//! admin `peer_shared` identity. Referenced by invite creation, removal authorization,
//! and message-deletion authorization.

pub mod projector;
pub mod queries;
pub mod wire;

pub use projector::project_pure;
pub use queries::{count, list_event_ids};
pub use wire::{encode_admin, parse_admin, AdminEvent, ADMIN_META, ADMIN_WIRE_SIZE};

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS admins (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}
