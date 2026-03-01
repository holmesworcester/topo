mod projection_context;
pub mod projector;
pub mod wire;

// Re-export stable public API so callers import from `event_modules::file_slice`.
pub use projector::project_pure;
pub use wire::{
    encode_file_slice, parse_file_slice, FileSliceEvent, FILE_SLICE_CIPHERTEXT_BYTES,
    FILE_SLICE_MAX_BYTES, FILE_SLICE_META, FILE_SLICE_WIRE_SIZE,
};

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS file_slices (
            recorded_by TEXT NOT NULL,
            file_id TEXT NOT NULL,
            slice_number INTEGER NOT NULL,
            event_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            descriptor_event_id TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (recorded_by, file_id, slice_number)
        );
        CREATE INDEX IF NOT EXISTS idx_file_slices_event
            ON file_slices(recorded_by, event_id);
        CREATE INDEX IF NOT EXISTS idx_file_slices_descriptor
            ON file_slices(recorded_by, descriptor_event_id);

        CREATE TABLE IF NOT EXISTS file_slice_guard_blocks (
            peer_id TEXT NOT NULL,
            file_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            PRIMARY KEY (peer_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_file_slice_guard_blocks_file
            ON file_slice_guard_blocks(peer_id, file_id);
        ",
    )?;
    Ok(())
}
