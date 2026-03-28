use std::collections::HashMap;

use rusqlite::Connection;

fn is_file_slice_transport_blob(blob: &[u8]) -> bool {
    crate::event_modules::outer_semantic_type_code(blob)
        == Some(crate::event_modules::EVENT_TYPE_FILE_SLICE)
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
        .query_map(rusqlite::params![recorded_by], |row: &rusqlite::Row<'_>| {
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
    stmt.query_map(rusqlite::params![recorded_by], |row: &rusqlite::Row<'_>| {
        row.get::<_, Vec<u8>>(0)
    })
    .expect("failed to query file_slice_event_count")
    .filter_map(Result::ok)
    .filter(|blob| is_file_slice_transport_blob(blob))
    .count() as i64
}
