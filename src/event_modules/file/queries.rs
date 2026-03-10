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
    pub downloaded_bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_rate_mib_s: Option<f64>,
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
    pub downloaded_bytes: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download_rate_mib_s: Option<f64>,
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
    pub elapsed_ms: u64,
}

fn calculate_download_rate_mib_s(
    downloaded_bytes: i64,
    earliest_sync_start_ms: Option<i64>,
    last_slice_recorded_at_ms: Option<i64>,
) -> Option<f64> {
    if downloaded_bytes <= 0 {
        return None;
    }
    let start_ms = earliest_sync_start_ms?;
    let end_ms = last_slice_recorded_at_ms?;
    let elapsed_ms = end_ms.saturating_sub(start_ms).max(1) as f64;
    Some((downloaded_bytes as f64 / (1024.0 * 1024.0)) / (elapsed_ms / 1000.0))
}

pub fn list_for_message(
    db: &Connection,
    recorded_by: &str,
    message_id_b64: &str,
) -> Result<Vec<FileSummary>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT a.filename, a.mime_type, a.blob_bytes, a.total_slices,
                (SELECT COUNT(*) FROM file_slices fs
                 WHERE fs.recorded_by = a.recorded_by AND fs.file_id = a.file_id) AS slices_received,
                COALESCE(
                    (SELECT SUM(
                        CASE
                            WHEN fs.slice_number = a.total_slices - 1
                                THEN a.blob_bytes - (a.slice_bytes * (a.total_slices - 1))
                            ELSE a.slice_bytes
                        END
                    )
                     FROM file_slices fs
                     WHERE fs.recorded_by = a.recorded_by AND fs.file_id = a.file_id),
                    0
                ) AS downloaded_bytes,
                (SELECT MIN(sr.started_at_ms)
                 FROM file_slices fs
                 JOIN sync_run_rx_events sre ON sre.event_id = fs.event_id
                 JOIN sync_runs sr
                   ON sr.run_id = sre.run_id AND sr.tenant_id = fs.recorded_by
                 WHERE fs.recorded_by = a.recorded_by AND fs.file_id = a.file_id) AS earliest_sync_start_ms,
                (SELECT MAX(re.recorded_at)
                 FROM file_slices fs
                 JOIN recorded_events re
                   ON re.peer_id = fs.recorded_by AND re.event_id = fs.event_id
                 WHERE fs.recorded_by = a.recorded_by AND fs.file_id = a.file_id) AS last_slice_recorded_at_ms
         FROM files a
         WHERE a.recorded_by = ?1 AND a.message_id = ?2",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by, message_id_b64], |row| {
            let downloaded_bytes: i64 = row.get(5)?;
            let earliest_sync_start_ms: Option<i64> = row.get(6)?;
            let last_slice_recorded_at_ms: Option<i64> = row.get(7)?;
            Ok(FileSummary {
                filename: row.get(0)?,
                mime_type: row.get(1)?,
                blob_bytes: row.get(2)?,
                total_slices: row.get(3)?,
                slices_received: row.get(4)?,
                downloaded_bytes,
                download_rate_mib_s: calculate_download_rate_mib_s(
                    downloaded_bytes,
                    earliest_sync_start_ms,
                    last_slice_recorded_at_ms,
                ),
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
                 WHERE fs.recorded_by = a.recorded_by AND fs.file_id = a.file_id) AS slices_received,
                COALESCE(
                    (SELECT SUM(
                        CASE
                            WHEN fs.slice_number = a.total_slices - 1
                                THEN a.blob_bytes - (a.slice_bytes * (a.total_slices - 1))
                            ELSE a.slice_bytes
                        END
                    )
                     FROM file_slices fs
                     WHERE fs.recorded_by = a.recorded_by AND fs.file_id = a.file_id),
                    0
                ) AS downloaded_bytes,
                (SELECT MIN(sr.started_at_ms)
                 FROM file_slices fs
                 JOIN sync_run_rx_events sre ON sre.event_id = fs.event_id
                 JOIN sync_runs sr
                   ON sr.run_id = sre.run_id AND sr.tenant_id = fs.recorded_by
                 WHERE fs.recorded_by = a.recorded_by AND fs.file_id = a.file_id) AS earliest_sync_start_ms,
                (SELECT MAX(re.recorded_at)
                 FROM file_slices fs
                 JOIN recorded_events re
                   ON re.peer_id = fs.recorded_by AND re.event_id = fs.event_id
                 WHERE fs.recorded_by = a.recorded_by AND fs.file_id = a.file_id) AS last_slice_recorded_at_ms
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
            let downloaded_bytes: i64 = row.get(9)?;
            let earliest_sync_start_ms: Option<i64> = row.get(10)?;
            let last_slice_recorded_at_ms: Option<i64> = row.get(11)?;
            Ok(FileItem {
                file_event_id: b64_to_hex(&file_event_id_b64),
                message_id: b64_to_hex(&message_id_b64),
                file_id: b64_to_hex(&file_id_b64),
                filename: row.get(3)?,
                mime_type: row.get(4)?,
                blob_bytes: row.get(5)?,
                total_slices,
                slices_received,
                downloaded_bytes,
                download_rate_mib_s: calculate_download_rate_mib_s(
                    downloaded_bytes,
                    earliest_sync_start_ms,
                    last_slice_recorded_at_ms,
                ),
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
    expected_key_event_id_b64: &str,
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
            if key_event_id_b64 != expected_key_event_id_b64 {
                return Err(format!(
                    "slice {} key mismatch: wrapper uses {} but file descriptor expects {}",
                    slice_event_id_b64, key_event_id_b64, expected_key_event_id_b64
                )
                .into());
            }
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
    use std::io::Write;
    use std::time::Instant;

    let start = Instant::now();
    let file_event_id_b64 = resolve_file_selector_to_b64(db, recorded_by, selector)?;
    let file_event_id_hex = b64_to_hex(&file_event_id_b64);

    let (file_id_b64, blob_bytes, total_slices, _slice_bytes, filename, key_event_id_b64): (
        String,
        i64,
        i64,
        i64,
        String,
        String,
    ) = db.query_row(
        "SELECT file_id, blob_bytes, total_slices, slice_bytes, filename, key_event_id
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
                row.get(5)?,
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

    let out_path = Path::new(output_path);
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Write to a temp file in the same directory, then rename on success.
    // This preserves all-or-nothing semantics: a failure mid-decrypt will
    // not clobber an existing file at output_path.
    let parent_dir = out_path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_path = parent_dir.join(format!(
        ".topo-save-{}-{}.tmp",
        std::process::id(),
        rand::random::<u32>()
    ));
    let write_result = (|| -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let mut file = std::fs::File::create(&tmp_path)?;
        let mut bytes_written: u64 = 0;
        for (idx, (slice_number, slice_event_id_b64)) in slices.iter().enumerate() {
            if *slice_number != idx as i64 {
                return Err(format!(
                    "file has missing/out-of-order slices: expected {}, got {}",
                    idx, slice_number
                )
                .into());
            }
            let payload = load_file_slice_payload(db, recorded_by, slice_event_id_b64, &key_event_id_b64)?;
            file.write_all(&payload)?;
            bytes_written += payload.len() as u64;
        }
        file.flush()?;
        let expected_len = blob_bytes.max(0) as u64;
        if bytes_written < expected_len {
            return Err(format!(
                "file data shorter than expected: {} < {}",
                bytes_written, expected_len
            )
            .into());
        }
        file.set_len(expected_len)?;
        Ok(expected_len)
    })();

    let expected_len = match write_result {
        Ok(len) => len,
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            return Err(e);
        }
    };
    // Atomic replace: on Unix, rename atomically replaces the destination.
    std::fs::rename(&tmp_path, out_path)?;

    let elapsed_ms = start.elapsed().as_millis() as u64;

    Ok(SaveFileResponse {
        file_event_id: file_event_id_hex,
        filename,
        output_path: out_path.to_string_lossy().to_string(),
        bytes_written: expected_len,
        total_slices,
        elapsed_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::create_tables;

    fn approx_eq(left: f64, right: f64) {
        let delta = (left - right).abs();
        assert!(
            delta < 0.000_001,
            "expected {left} ~= {right} (delta={delta})"
        );
    }

    fn setup_db() -> Connection {
        let db = Connection::open_in_memory().unwrap();
        create_tables(&db).unwrap();
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
        assert_eq!(result[0].downloaded_bytes, 0);
        assert_eq!(result[0].download_rate_mib_s, None);
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
        assert_eq!(result[0].downloaded_bytes, 262144);
        assert_eq!(result[0].download_rate_mib_s, None);

        // Insert second slice
        db.execute(
            "INSERT INTO file_slices (recorded_by, file_id, slice_number, event_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["peer1", "file1", 1, "slice_evt2", 1002],
        )
        .unwrap();

        let result = list_for_message(&db, "peer1", "msg1").unwrap();
        assert_eq!(result[0].slices_received, 2);
        assert_eq!(result[0].downloaded_bytes, 524288);
        assert_eq!(result[0].download_rate_mib_s, None);
    }

    #[test]
    fn test_download_rate_uses_earliest_contributing_sync_start() {
        let db = setup_db();
        db.execute(
            "INSERT INTO files
             (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                "peer1",
                "evt1",
                "msg1",
                "file1",
                524288i64,
                2i64,
                262144i64,
                &[0u8; 32] as &[u8],
                "key1",
                "big.bin",
                "application/octet-stream",
                1000i64
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO file_slices (recorded_by, file_id, slice_number, event_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["peer1", "file1", 0i64, "slice_evt1", 3000i64],
        )
        .unwrap();
        db.execute(
            "INSERT INTO file_slices (recorded_by, file_id, slice_number, event_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["peer1", "file1", 1i64, "slice_evt2", 4000i64],
        )
        .unwrap();
        db.execute(
            "INSERT INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["peer1", "slice_evt1", 3000i64, "quic_recv:alice"],
        )
        .unwrap();
        db.execute(
            "INSERT INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["peer1", "slice_evt2", 4000i64, "quic_recv:bob"],
        )
        .unwrap();
        db.execute(
            "INSERT INTO sync_runs
             (run_id, started_at_ms, ended_at_ms, session_id, tenant_id, peer_id, direction, remote_addr, role,
              rounds, events_sent, events_received, bytes_sent, bytes_received, changed, outcome, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            rusqlite::params![
                11i64,
                1000i64,
                4500i64,
                11i64,
                "peer1",
                "remote-a",
                "inbound",
                "127.0.0.1:4444",
                "responder",
                2i64,
                0i64,
                1i64,
                0i64,
                262144i64,
                1i64,
                "ok",
                Option::<String>::None
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO sync_runs
             (run_id, started_at_ms, ended_at_ms, session_id, tenant_id, peer_id, direction, remote_addr, role,
              rounds, events_sent, events_received, bytes_sent, bytes_received, changed, outcome, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            rusqlite::params![
                12i64,
                2500i64,
                4200i64,
                12i64,
                "peer1",
                "remote-b",
                "inbound",
                "127.0.0.1:5555",
                "responder",
                2i64,
                0i64,
                1i64,
                0i64,
                262144i64,
                1i64,
                "ok",
                Option::<String>::None
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO sync_run_rx_events (run_id, event_id) VALUES (?1, ?2)",
            rusqlite::params![11i64, "slice_evt1"],
        )
        .unwrap();
        db.execute(
            "INSERT INTO sync_run_rx_events (run_id, event_id) VALUES (?1, ?2)",
            rusqlite::params![12i64, "slice_evt2"],
        )
        .unwrap();

        let by_message = list_for_message(&db, "peer1", "msg1").unwrap();
        assert_eq!(by_message.len(), 1);
        assert_eq!(by_message[0].downloaded_bytes, 524288);
        approx_eq(by_message[0].download_rate_mib_s.unwrap(), 1.0 / 6.0);

        let files = list_files(&db, "peer1", 10).unwrap();
        assert_eq!(files.total, 1);
        assert_eq!(files.files[0].downloaded_bytes, 524288);
        approx_eq(files.files[0].download_rate_mib_s.unwrap(), 1.0 / 6.0);
    }

    #[test]
    fn test_downloaded_bytes_uses_actual_last_slice_size() {
        let db = setup_db();
        db.execute(
            "INSERT INTO files
             (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                "peer1",
                "evt1",
                "msg1",
                "file1",
                300000i64,
                2i64,
                262144i64,
                &[0u8; 32] as &[u8],
                "key1",
                "odd.bin",
                "application/octet-stream",
                1000i64
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO file_slices (recorded_by, file_id, slice_number, event_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["peer1", "file1", 0i64, "slice_evt1", 1001i64],
        )
        .unwrap();
        db.execute(
            "INSERT INTO file_slices (recorded_by, file_id, slice_number, event_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["peer1", "file1", 1i64, "slice_evt2", 1002i64],
        )
        .unwrap();

        let by_message = list_for_message(&db, "peer1", "msg1").unwrap();
        assert_eq!(by_message.len(), 1);
        assert_eq!(by_message[0].downloaded_bytes, 300000);
        assert_eq!(by_message[0].download_rate_mib_s, None);

        let files = list_files(&db, "peer1", 10).unwrap();
        assert_eq!(files.total, 1);
        assert_eq!(files.files[0].downloaded_bytes, 300000);
        assert!(files.files[0].complete);
    }

    #[test]
    fn test_list_files_empty() {
        let db = setup_db();
        let result = list_files(&db, "peer1", 50).unwrap();
        assert_eq!(result.total, 0);
        assert!(result.files.is_empty());
    }
}
