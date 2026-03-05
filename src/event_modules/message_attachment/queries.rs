use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct AttachmentSummary {
    pub filename: String,
    pub mime_type: String,
    pub blob_bytes: i64,
    pub total_slices: i64,
    pub slices_received: i64,
}

pub fn list_for_message(
    db: &Connection,
    recorded_by: &str,
    message_id_b64: &str,
) -> Result<Vec<AttachmentSummary>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT a.filename, a.mime_type, a.blob_bytes, a.total_slices,
                (SELECT COUNT(*) FROM file_slices fs
                 WHERE fs.recorded_by = a.recorded_by AND fs.file_id = a.file_id) as slices_received
         FROM message_attachments a
         WHERE a.recorded_by = ?1 AND a.message_id = ?2",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by, message_id_b64], |row| {
            Ok(AttachmentSummary {
                filename: row.get(0)?,
                mime_type: row.get(1)?,
                blob_bytes: row.get(2)?,
                total_slices: row.get(3)?,
                slices_received: row.get(4)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        crate::event_modules::message_attachment::ensure_schema(&db).unwrap();
        crate::event_modules::file_slice::ensure_schema(&db).unwrap();
        db
    }

    #[test]
    fn test_list_for_message_empty() {
        let db = setup_db();
        let result = list_for_message(&db, "peer1", "msg1").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_list_for_message_returns_attachments() {
        let db = setup_db();
        db.execute(
            "INSERT INTO message_attachments
             (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params!["peer1", "evt1", "msg1", "file1", 1234, 1, 1234, &[0u8; 32] as &[u8], "key1", "photo.jpg", "image/jpeg", 1000],
        ).unwrap();
        db.execute(
            "INSERT INTO message_attachments
             (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params!["peer1", "evt2", "msg1", "file2", 5678, 1, 5678, &[0u8; 32] as &[u8], "key1", "doc.pdf", "application/pdf", 1001],
        ).unwrap();
        // Different message — should not appear
        db.execute(
            "INSERT INTO message_attachments
             (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params!["peer1", "evt3", "msg2", "file3", 999, 1, 999, &[0u8; 32] as &[u8], "key1", "other.txt", "text/plain", 1002],
        ).unwrap();

        let result = list_for_message(&db, "peer1", "msg1").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].filename, "photo.jpg");
        assert_eq!(result[0].mime_type, "image/jpeg");
        assert_eq!(result[0].blob_bytes, 1234);
        assert_eq!(result[0].total_slices, 1);
        assert_eq!(result[0].slices_received, 0); // no file_slices inserted
        assert_eq!(result[1].filename, "doc.pdf");
        assert_eq!(result[1].blob_bytes, 5678);
    }

    #[test]
    fn test_slices_received_counts_correctly() {
        let db = setup_db();
        db.execute(
            "INSERT INTO message_attachments
             (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params!["peer1", "evt1", "msg1", "file1", 524288, 2, 262144, &[0u8; 32] as &[u8], "key1", "big.bin", "application/octet-stream", 1000],
        ).unwrap();
        // Insert 1 of 2 slices
        db.execute(
            "INSERT INTO file_slices (recorded_by, file_id, slice_number, event_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["peer1", "file1", 0, "slice_evt1", 1001],
        )
        .unwrap();

        let result = list_for_message(&db, "peer1", "msg1").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].total_slices, 2);
        assert_eq!(result[0].slices_received, 1);

        // Insert second slice
        db.execute(
            "INSERT INTO file_slices (recorded_by, file_id, slice_number, event_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["peer1", "file1", 1, "slice_evt2", 1002],
        )
        .unwrap();

        let result = list_for_message(&db, "peer1", "msg1").unwrap();
        assert_eq!(result[0].slices_received, 2);
    }
}
