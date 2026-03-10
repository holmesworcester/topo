use std::collections::HashMap;

use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, FileDescriptorInfo};
use rusqlite::Connection;

fn is_file_slice_transport_blob(blob: &[u8]) -> bool {
    crate::event_modules::outer_semantic_type_code(blob)
        == Some(crate::event_modules::EVENT_TYPE_FILE_SLICE)
}

/// Build projector-local context for FileSlice projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let fs = match parsed {
        ParsedEvent::FileSlice(fs) => fs,
        _ => return Err("file_slice context loader called for non-file_slice event".into()),
    };

    let mut ctx = ContextSnapshot::default();
    let file_id_b64 = event_id_to_base64(&fs.file_id);

    let mut desc_stmt = conn.prepare(
        "SELECT event_id, signer_event_id, key_event_id
         FROM files
         WHERE recorded_by = ?1 AND file_id = ?2
         ORDER BY created_at ASC, event_id ASC",
    )?;
    ctx.file_descriptors = desc_stmt
        .query_map(rusqlite::params![recorded_by, &file_id_b64], |row| {
            Ok(FileDescriptorInfo {
                event_id: row.get::<_, String>(0)?,
                signer_event_id: row.get::<_, String>(1)?,
                key_event_id: row.get::<_, String>(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    ctx.existing_file_slice = match conn.query_row(
        "SELECT event_id, descriptor_event_id
         FROM file_slices
         WHERE recorded_by = ?1 AND file_id = ?2 AND slice_number = ?3",
        rusqlite::params![recorded_by, &file_id_b64, fs.slice_number as i64],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    ) {
        Ok(v) => Some(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };

    Ok(ctx)
}

/// Query file-slice event counts grouped by ingest source.
///
/// Joins `events` (filtered to file_slice type) with `recorded_events` to
/// attribute each received slice event back to the remote peer that sent it.
/// This works without projection (no trust anchor required at the sink).
/// Returns a map of source_peer → event_count.
pub fn file_slice_event_counts_by_source(
    conn: &Connection,
    recorded_by: &str,
) -> HashMap<String, i64> {
    let mut stmt = conn
        .prepare(
            "SELECT re.source, e.blob
             FROM events e
             JOIN recorded_events re
               ON e.event_id = re.event_id AND re.peer_id = ?1
             ORDER BY re.rowid ASC",
        )
        .expect("failed to prepare file_slice_event_counts_by_source");
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .expect("failed to query file_slice_event_counts_by_source");

    let mut counts = HashMap::new();
    for row in rows {
        let (source, blob) = row.unwrap();
        if is_file_slice_transport_blob(&blob) {
            *counts.entry(source).or_insert(0) += 1;
        }
    }
    counts
}

/// Count total file_slice events received by a peer (no projection required).
pub fn file_slice_event_count(conn: &Connection, recorded_by: &str) -> i64 {
    let mut stmt = conn
        .prepare(
            "SELECT e.blob
             FROM events e
             JOIN recorded_events re ON e.event_id = re.event_id AND re.peer_id = ?1",
        )
        .expect("failed to prepare file_slice_event_count");
    stmt.query_map(rusqlite::params![recorded_by], |row| {
        row.get::<_, Vec<u8>>(0)
    })
    .expect("failed to query file_slice_event_count")
    .filter_map(Result::ok)
    .filter(|blob| is_file_slice_transport_blob(blob))
    .count() as i64
}
