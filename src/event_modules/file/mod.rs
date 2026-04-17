//! `file` event (type 24): metadata record for a file attachment on a message — filename,
//! mime type, total size, slice count, BAO root hash, and the content-key event id. The
//! actual ciphertext lives in `file_slice` events; file and slices are linked by a shared
//! random `file_id` carried by both.

pub mod projector;
pub mod queries;
pub mod wire;

// Re-export stable public API so callers import from `event_modules::file`.
pub use projector::project_pure;
pub use wire::{encode_file, file_offsets, parse_file, FileEvent, FILE_META, FILE_WIRE_SIZE};

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS files (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            file_id TEXT NOT NULL,
            blob_bytes INTEGER NOT NULL,
            total_slices INTEGER NOT NULL,
            slice_bytes INTEGER NOT NULL,
            root_hash BLOB NOT NULL,
            key_event_id TEXT NOT NULL,
            filename TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            signer_event_id TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_files_message
            ON files(recorded_by, message_id);
        CREATE INDEX IF NOT EXISTS idx_files_file_id
            ON files(recorded_by, file_id);
        ",
    )?;
    Ok(())
}
