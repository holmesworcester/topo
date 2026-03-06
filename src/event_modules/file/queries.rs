use crate::crypto::{b64_to_hex, decrypt_event_blob, event_id_from_hex, event_id_to_base64};
use crate::event_modules::{parse_event, ParsedEvent};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct FileSummary {
    pub filename: String,
    pub mime_type: String,
    pub blob_bytes: i64,
    pub total_slices: i64,
    pub slices_received: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileItem {
    pub file_event_id: String,
    pub message_id: String,
    pub file_id: String,
    pub filename: String,
    pub mime_type: String,
    pub blob_bytes: i64,
    pub total_slices: i64,
    pub slices_received: i64,
    pub complete: bool,
    pub created_at: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FilesResponse {
    pub files: Vec<FileItem>,
    pub total: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveFileResponse {
    pub file_event_id: String,
    pub filename: String,
    pub output_path: String,
    pub bytes_written: u64,
    pub total_slices: i64,
}

pub fn list_for_message(
    db: &Connection,
    recorded_by: &str,
    message_id_b64: &str,
) -> Result<Vec<FileSummary>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT a.filename, a.mime_type, a.blob_bytes, a.total_slices,
                (SELECT COUNT(*) FROM file_slices fs
                 WHERE fs.recorded_by = a.recorded_by AND fs.file_id = a.file_id) as slices_received
         FROM files a
         WHERE a.recorded_by = ?1 AND a.message_id = ?2",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by, message_id_b64], |row| {
            Ok(FileSummary {
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

pub fn list_files(
    db: &Connection,
    recorded_by: &str,
    limit: usize,
) -> Result<FilesResponse, Box<dyn std::error::Error + Send + Sync>> {
    let limit_clause = if limit > 0 {
        format!("LIMIT {}", limit)
    } else {
        String::new()
    };

    let query = format!(
        "SELECT a.event_id, a.message_id, a.file_id, a.filename, a.mime_type,
                a.blob_bytes, a.total_slices, a.created_at,
                (SELECT COUNT(*) FROM file_slices fs
                 WHERE fs.recorded_by = a.recorded_by AND fs.file_id = a.file_id) AS slices_received
         FROM files a
         WHERE a.recorded_by = ?1
         ORDER BY a.created_at ASC, a.event_id ASC
         {}",
        limit_clause
    );

    let mut stmt = db.prepare(&query)?;
    let files = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            let file_event_id_b64: String = row.get(0)?;
            let message_id_b64: String = row.get(1)?;
            let file_id_b64: String = row.get(2)?;
            let total_slices: i64 = row.get(6)?;
            let slices_received: i64 = row.get(8)?;
            Ok(FileItem {
                file_event_id: b64_to_hex(&file_event_id_b64),
                message_id: b64_to_hex(&message_id_b64),
                file_id: b64_to_hex(&file_id_b64),
                filename: row.get(3)?,
                mime_type: row.get(4)?,
                blob_bytes: row.get(5)?,
                total_slices,
                slices_received,
                complete: total_slices > 0 && slices_received >= total_slices,
                created_at: row.get(7)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let total: i64 = db.query_row(
        "SELECT COUNT(*) FROM files WHERE recorded_by = ?1",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )?;

    Ok(FilesResponse { files, total })
}

fn resolve_file_selector_to_b64(
    db: &Connection,
    recorded_by: &str,
    selector: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let stripped = selector.strip_prefix('#').unwrap_or(selector);
    if let Ok(num) = stripped.parse::<usize>() {
        if num == 0 {
            return Err("file number must be >= 1".into());
        }
        let file_event_id_b64: Option<String> = db
            .query_row(
                "SELECT event_id
                 FROM files
                 WHERE recorded_by = ?1
                 ORDER BY created_at ASC, event_id ASC
                 LIMIT 1 OFFSET ?2",
                rusqlite::params![recorded_by, num - 1],
                |row| row.get(0),
            )
            .ok();
        return match file_event_id_b64 {
            Some(v) => Ok(v),
            None => {
                let total: i64 = db.query_row(
                    "SELECT COUNT(*) FROM files WHERE recorded_by = ?1",
                    rusqlite::params![recorded_by],
                    |row| row.get(0),
                )?;
                Err(format!("invalid file number {}; available: 1-{}", num, total).into())
            }
        };
    }

    let file_event_id = event_id_from_hex(selector)
        .ok_or_else(|| format!("invalid file selector: {}", selector))?;
    let file_event_id_b64 = event_id_to_base64(&file_event_id);
    let exists: bool = db.query_row(
        "SELECT COUNT(*) > 0
         FROM files
         WHERE recorded_by = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, &file_event_id_b64],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(format!("file not found for selector {}", selector).into());
    }
    Ok(file_event_id_b64)
}

fn load_file_slice_payload(
    db: &Connection,
    recorded_by: &str,
    slice_event_id_b64: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let blob: Vec<u8> = db.query_row(
        "SELECT blob FROM events WHERE event_id = ?1",
        rusqlite::params![slice_event_id_b64],
        |row| row.get(0),
    )?;

    let parsed =
        parse_event(&blob).map_err(|e| format!("parse event {}: {}", slice_event_id_b64, e))?;
    match parsed {
        ParsedEvent::FileSlice(fs) => Ok(fs.ciphertext),
        ParsedEvent::Encrypted(enc) => {
            let key_event_id_b64 = event_id_to_base64(&enc.key_event_id);
            let key_bytes: Vec<u8> = db.query_row(
                "SELECT key_bytes
                 FROM key_secrets
                 WHERE recorded_by = ?1 AND event_id = ?2
                 LIMIT 1",
                rusqlite::params![recorded_by, &key_event_id_b64],
                |row| row.get(0),
            )?;
            if key_bytes.len() != 32 {
                return Err(format!(
                    "invalid key length {} for key_secret {}",
                    key_bytes.len(),
                    key_event_id_b64
                )
                .into());
            }
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&key_bytes);

            let plaintext =
                decrypt_event_blob(&key_arr, &enc.nonce, &enc.ciphertext, &enc.auth_tag).map_err(
                    |e| format!("decrypt encrypted slice {}: {}", slice_event_id_b64, e),
                )?;
            match parse_event(&plaintext) {
                Ok(ParsedEvent::FileSlice(fs)) => Ok(fs.ciphertext),
                Ok(other) => Err(format!(
                    "slice event {} decrypted to unexpected type {}",
                    slice_event_id_b64,
                    crate::event_modules::registry()
                        .lookup(other.event_type_code())
                        .map(|m| m.type_name)
                        .unwrap_or("unknown")
                )
                .into()),
                Err(e) => {
                    Err(format!("parse decrypted slice {}: {}", slice_event_id_b64, e).into())
                }
            }
        }
        other => Err(format!(
            "slice event {} is not file_slice (got {})",
            slice_event_id_b64,
            crate::event_modules::registry()
                .lookup(other.event_type_code())
                .map(|m| m.type_name)
                .unwrap_or("unknown")
        )
        .into()),
    }
}

pub fn save_file_by_selector(
    db: &Connection,
    recorded_by: &str,
    selector: &str,
    output_path: &str,
) -> Result<SaveFileResponse, Box<dyn std::error::Error + Send + Sync>> {
    let file_event_id_b64 = resolve_file_selector_to_b64(db, recorded_by, selector)?;
    let file_event_id_hex = b64_to_hex(&file_event_id_b64);

    let (file_id_b64, blob_bytes, total_slices, slice_bytes, filename): (
        String,
        i64,
        i64,
        i64,
        String,
    ) = db.query_row(
        "SELECT file_id, blob_bytes, total_slices, slice_bytes, filename
         FROM files
         WHERE recorded_by = ?1 AND event_id = ?2
         LIMIT 1",
        rusqlite::params![recorded_by, &file_event_id_b64],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;

    let mut stmt = db.prepare(
        "SELECT slice_number, event_id
         FROM file_slices
         WHERE recorded_by = ?1 AND file_id = ?2
         ORDER BY slice_number ASC, created_at ASC, event_id ASC",
    )?;
    let slices = stmt
        .query_map(rusqlite::params![recorded_by, &file_id_b64], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    if slices.len() as i64 != total_slices {
        return Err(format!(
            "file incomplete: have {}/{} slices",
            slices.len(),
            total_slices
        )
        .into());
    }

    let mut data =
        Vec::with_capacity((total_slices.max(0) as usize) * (slice_bytes.max(0) as usize));
    for (idx, (slice_number, slice_event_id_b64)) in slices.iter().enumerate() {
        if *slice_number != idx as i64 {
            return Err(format!(
                "file has missing/out-of-order slices: expected {}, got {}",
                idx, slice_number
            )
            .into());
        }
        let payload = load_file_slice_payload(db, recorded_by, slice_event_id_b64)?;
        data.extend_from_slice(&payload);
    }

    let expected_len = blob_bytes.max(0) as usize;
    if data.len() < expected_len {
        return Err(format!(
            "file data shorter than expected: {} < {}",
            data.len(),
            expected_len
        )
        .into());
    }
    data.truncate(expected_len);

    let out_path = Path::new(output_path);
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(out_path, &data)?;

    Ok(SaveFileResponse {
        file_event_id: file_event_id_hex,
        filename,
        output_path: out_path.to_string_lossy().to_string(),
        bytes_written: data.len() as u64,
        total_slices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        crate::event_modules::file::ensure_schema(&db).unwrap();
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
    fn test_list_for_message_returns_files() {
        let db = setup_db();
        db.execute(
            "INSERT INTO files
             (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params!["peer1", "evt1", "msg1", "file1", 1234, 1, 1234, &[0u8; 32] as &[u8], "key1", "photo.jpg", "image/jpeg", 1000],
        ).unwrap();
        db.execute(
            "INSERT INTO files
             (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params!["peer1", "evt2", "msg1", "file2", 5678, 1, 5678, &[0u8; 32] as &[u8], "key1", "doc.pdf", "application/pdf", 1001],
        ).unwrap();
        // Different message — should not appear
        db.execute(
            "INSERT INTO files
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
            "INSERT INTO files
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

    #[test]
    fn test_list_files_empty() {
        let db = setup_db();
        let result = list_files(&db, "peer1", 50).unwrap();
        assert_eq!(result.total, 0);
        assert!(result.files.is_empty());
    }
}
