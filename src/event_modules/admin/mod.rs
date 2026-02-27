pub mod projector;
pub mod queries;
pub mod wire;

// Re-export stable public API so callers import from `event_modules::admin`.
pub use projector::project_pure;
pub use queries::{count, list_event_ids};
pub use wire::{
    encode_admin_boot, encode_admin_ongoing, parse_admin_boot, parse_admin_ongoing, AdminBootEvent,
    AdminOngoingEvent, ADMIN_BOOT_META, ADMIN_BOOT_WIRE_SIZE, ADMIN_ONGOING_META,
    ADMIN_ONGOING_WIRE_SIZE,
};

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
