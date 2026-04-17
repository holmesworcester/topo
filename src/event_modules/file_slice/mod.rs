//! `file_slice` event (type 25): one BAO-verified ciphertext chunk of a larger file. Many
//! slices per `file` event; this is the bulk-IO event type that dominates large-payload sync
//! throughput and low-memory budgets.

pub mod projector;
mod stats;
pub mod wire;

// Re-export stable public API so callers import from `event_modules::file_slice`.
pub use projector::{build_projector_context, project_pure};
pub use stats::{file_slice_event_count, file_slice_event_counts_by_source};
pub use wire::{
    encode_file_slice, parse_file_slice, BaoPayloadTooLarge, FileSliceEvent,
    BAO_PLAINTEXT_CAPACITY, FILE_SLICE_CIPHERTEXT_BYTES, FILE_SLICE_DATA_BYTES,
    FILE_SLICE_MAX_BYTES, FILE_SLICE_META, FILE_SLICE_WIRE_SIZE, MAX_FILE_BYTES,
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
        ",
    )?;
    Ok(())
}
