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
