use crate::crypto::{b64_to_hex, decrypt_event_blob, event_id_from_hex, event_id_to_base64};
use crate::event_modules::{parse_event, ParsedEvent};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::io::{BufWriter, Write};
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

#[derive(Debug)]
struct FileDescriptorRow {
    event_id: String,
    message_id: String,
    file_id: String,
    filename: String,
    mime_type: String,
    blob_bytes: i64,
    total_slices: i64,
    slice_bytes: i64,
    key_event_id: String,
    created_at: i64,
}

#[derive(Debug, Default)]
struct VerifiedFileProgress {
    slices_received: i64,
    downloaded_bytes: i64,
    earliest_sync_start_ms: Option<i64>,
    last_slice_recorded_at_ms: Option<i64>,
}

fn logical_slice_bytes(
    slice_number: i64,
    total_slices: i64,
    blob_bytes: i64,
    slice_bytes: i64,
) -> i64 {
    if total_slices <= 0 || slice_bytes <= 0 {
        return 0;
    }
    if slice_number == total_slices - 1 {
        blob_bytes
            .saturating_sub(slice_bytes.saturating_mul(total_slices.saturating_sub(1)))
            .max(0)
    } else {
        slice_bytes.max(0)
    }
}

fn collect_verified_file_progress(
    db: &Connection,
    recorded_by: &str,
    file_id_b64: &str,
    descriptor_event_id_b64: Option<&str>,
    expected_key_event_id_b64: &str,
    total_slices: i64,
    blob_bytes: i64,
    slice_bytes: i64,
) -> Result<VerifiedFileProgress, Box<dyn std::error::Error + Send + Sync>> {
    let sql = if descriptor_event_id_b64.is_some() {
        "SELECT fs.slice_number,
                fs.event_id,
                (SELECT MIN(sr.started_at_ms)
                 FROM sync_run_rx_events sre
                 JOIN sync_runs sr ON sr.run_id = sre.run_id AND sr.tenant_id = fs.recorded_by
                 WHERE sre.event_id = fs.event_id) AS earliest_sync_start_ms,
                (SELECT MAX(re.recorded_at)
                 FROM recorded_events re
                 WHERE re.peer_id = fs.recorded_by AND re.event_id = fs.event_id) AS last_slice_recorded_at_ms
         FROM file_slices fs
         WHERE fs.recorded_by = ?1 AND fs.file_id = ?2 AND fs.descriptor_event_id = ?3
         ORDER BY fs.slice_number ASC, fs.created_at ASC, fs.event_id ASC"
    } else {
        "SELECT fs.slice_number,
                fs.event_id,
                (SELECT MIN(sr.started_at_ms)
                 FROM sync_run_rx_events sre
                 JOIN sync_runs sr ON sr.run_id = sre.run_id AND sr.tenant_id = fs.recorded_by
                 WHERE sre.event_id = fs.event_id) AS earliest_sync_start_ms,
                (SELECT MAX(re.recorded_at)
                 FROM recorded_events re
                 WHERE re.peer_id = fs.recorded_by AND re.event_id = fs.event_id) AS last_slice_recorded_at_ms
         FROM file_slices fs
         WHERE fs.recorded_by = ?1 AND fs.file_id = ?2 AND fs.descriptor_event_id = ''
         ORDER BY fs.slice_number ASC, fs.created_at ASC, fs.event_id ASC"
    };

    let mut stmt = db.prepare(sql)?;
    let mut rows = if let Some(descriptor_event_id_b64) = descriptor_event_id_b64 {
        stmt.query(rusqlite::params![
            recorded_by,
            file_id_b64,
            descriptor_event_id_b64
        ])?
    } else {
        stmt.query(rusqlite::params![recorded_by, file_id_b64])?
    };

    let mut seen_slices = std::collections::BTreeSet::<i64>::new();
    let mut progress = VerifiedFileProgress::default();
    while let Some(row) = rows.next()? {
        let slice_number: i64 = row.get(0)?;
        let slice_event_id_b64: String = row.get(1)?;
        let earliest_sync_start_ms: Option<i64> = row.get(2)?;
        let last_slice_recorded_at_ms: Option<i64> = row.get(3)?;
        if slice_number < 0 || slice_number >= total_slices {
            continue;
        }
        if seen_slices.contains(&slice_number) {
            continue;
        }
        if load_file_slice_payload(
            db,
            recorded_by,
            &slice_event_id_b64,
            expected_key_event_id_b64,
        )
        .is_err()
        {
            continue;
        }
        seen_slices.insert(slice_number);

        progress.slices_received += 1;
        progress.downloaded_bytes +=
            logical_slice_bytes(slice_number, total_slices, blob_bytes, slice_bytes);
        progress.earliest_sync_start_ms =
            match (progress.earliest_sync_start_ms, earliest_sync_start_ms) {
                (Some(current), Some(candidate)) => Some(current.min(candidate)),
                (None, candidate) => candidate,
                (current, None) => current,
            };
        progress.last_slice_recorded_at_ms = match (
            progress.last_slice_recorded_at_ms,
            last_slice_recorded_at_ms,
        ) {
            (Some(current), Some(candidate)) => Some(current.max(candidate)),
            (None, candidate) => candidate,
            (current, None) => current,
        };
    }

    Ok(progress)
}

pub fn list_for_message(
    db: &Connection,
    recorded_by: &str,
    message_id_b64: &str,
) -> Result<Vec<FileSummary>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT a.event_id, a.file_id, a.filename, a.mime_type, a.blob_bytes,
                a.total_slices, a.slice_bytes, a.key_event_id
         FROM files a
         WHERE a.recorded_by = ?1 AND a.message_id = ?2",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by, message_id_b64], |row| {
            Ok(FileDescriptorRow {
                event_id: row.get(0)?,
                message_id: message_id_b64.to_string(),
                file_id: row.get(1)?,
                filename: row.get(2)?,
                mime_type: row.get(3)?,
                blob_bytes: row.get(4)?,
                total_slices: row.get(5)?,
                slice_bytes: row.get(6)?,
                key_event_id: row.get(7)?,
                created_at: 0,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    rows.into_iter()
        .map(|row| {
            let progress = collect_verified_file_progress(
                db,
                recorded_by,
                &row.file_id,
                Some(&row.event_id),
                &row.key_event_id,
                row.total_slices,
                row.blob_bytes,
                row.slice_bytes,
            )
            .map_err(|err| rusqlite::Error::ToSqlConversionFailure(err))?;
            Ok(FileSummary {
                filename: row.filename,
                mime_type: row.mime_type,
                blob_bytes: row.blob_bytes,
                total_slices: row.total_slices,
                slices_received: progress.slices_received,
                downloaded_bytes: progress.downloaded_bytes,
                download_rate_mib_s: calculate_download_rate_mib_s(
                    progress.downloaded_bytes,
                    progress.earliest_sync_start_ms,
                    progress.last_slice_recorded_at_ms,
                ),
            })
        })
        .collect::<Result<Vec<_>, _>>()
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
                a.blob_bytes, a.total_slices, a.slice_bytes, a.key_event_id, a.created_at
         FROM files a
         WHERE a.recorded_by = ?1
         ORDER BY a.created_at ASC, a.event_id ASC
         {}",
        limit_clause
    );

    let mut stmt = db.prepare(&query)?;
    let rows = stmt
        .query_map(rusqlite::params![recorded_by], |row| {
            Ok(FileDescriptorRow {
                event_id: row.get(0)?,
                message_id: row.get(1)?,
                file_id: row.get(2)?,
                filename: row.get(3)?,
                mime_type: row.get(4)?,
                blob_bytes: row.get(5)?,
                total_slices: row.get(6)?,
                slice_bytes: row.get(7)?,
                key_event_id: row.get(8)?,
                created_at: row.get(9)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let files = rows
        .into_iter()
        .map(|row| {
            let progress = collect_verified_file_progress(
                db,
                recorded_by,
                &row.file_id,
                Some(&row.event_id),
                &row.key_event_id,
                row.total_slices,
                row.blob_bytes,
                row.slice_bytes,
            )?;
            Ok(FileItem {
                file_event_id: b64_to_hex(&row.event_id),
                message_id: b64_to_hex(&row.message_id),
                file_id: b64_to_hex(&row.file_id),
                filename: row.filename,
                mime_type: row.mime_type,
                blob_bytes: row.blob_bytes,
                total_slices: row.total_slices,
                slices_received: progress.slices_received,
                downloaded_bytes: progress.downloaded_bytes,
                download_rate_mib_s: calculate_download_rate_mib_s(
                    progress.downloaded_bytes,
                    progress.earliest_sync_start_ms,
                    progress.last_slice_recorded_at_ms,
                ),
                complete: row.total_slices > 0 && progress.slices_received >= row.total_slices,
                created_at: row.created_at,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error + Send + Sync>>>()?;

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
    fn load_from_parsed(
        db: &Connection,
        recorded_by: &str,
        slice_event_id_b64: &str,
        expected_key_event_id_b64: &str,
        parsed: ParsedEvent,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        match parsed {
            ParsedEvent::FileSlice(fs) => Ok(fs.ciphertext),
            ParsedEvent::Signed(signed) => {
                let inner = parse_event(&signed.payload).map_err(|e| {
                    format!(
                        "parse signed payload for slice {}: {}",
                        slice_event_id_b64, e
                    )
                })?;
                if inner.event_type_code() != signed.inner_type_code {
                    return Err(format!(
                        "slice event {} inner type mismatch: signed wrapper declares {} but payload is {}",
                        slice_event_id_b64,
                        signed.inner_type_code,
                        inner.event_type_code()
                    )
                    .into());
                }
                load_from_parsed(
                    db,
                    recorded_by,
                    slice_event_id_b64,
                    expected_key_event_id_b64,
                    inner,
                )
            }
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
                    decrypt_event_blob(&key_arr, &enc.nonce, &enc.ciphertext, &enc.auth_tag)
                        .map_err(|e| {
                            format!("decrypt encrypted slice {}: {}", slice_event_id_b64, e)
                        })?;
                let inner = parse_event(&plaintext)
                    .map_err(|e| format!("parse decrypted slice {}: {}", slice_event_id_b64, e))?;
                if inner.event_type_code() != enc.inner_type_code {
                    return Err(format!(
                        "slice event {} inner type mismatch: encrypted wrapper declares {} but payload is {}",
                        slice_event_id_b64,
                        enc.inner_type_code,
                        inner.event_type_code()
                    )
                    .into());
                }
                load_from_parsed(
                    db,
                    recorded_by,
                    slice_event_id_b64,
                    expected_key_event_id_b64,
                    inner,
                )
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

    let blob: Vec<u8> = db.query_row(
        "SELECT blob FROM events WHERE event_id = ?1",
        rusqlite::params![slice_event_id_b64],
        |row| row.get(0),
    )?;
    let parsed =
        parse_event(&blob).map_err(|e| format!("parse event {}: {}", slice_event_id_b64, e))?;
    load_from_parsed(
        db,
        recorded_by,
        slice_event_id_b64,
        expected_key_event_id_b64,
        parsed,
    )
}

fn write_matching_file_slices<W: Write>(
    db: &Connection,
    recorded_by: &str,
    file_id_b64: &str,
    descriptor_event_id_b64: Option<&str>,
    expected_key_event_id_b64: &str,
    root_hash_arr: &[u8; 32],
    blob_bytes: i64,
    slice_bytes: i64,
    total_slices: i64,
    writer: &mut W,
) -> Result<(i64, u64), Box<dyn std::error::Error + Send + Sync>> {
    let sql = if descriptor_event_id_b64.is_some() {
        "SELECT slice_number, event_id
         FROM file_slices
         WHERE recorded_by = ?1 AND file_id = ?2 AND descriptor_event_id = ?3
         ORDER BY slice_number ASC, created_at ASC, event_id ASC"
    } else {
        "SELECT slice_number, event_id
         FROM file_slices
         WHERE recorded_by = ?1 AND file_id = ?2 AND descriptor_event_id = ''
         ORDER BY slice_number ASC, created_at ASC, event_id ASC"
    };

    let mut stmt = db.prepare(sql)?;
    let mut rows = if let Some(descriptor_event_id_b64) = descriptor_event_id_b64 {
        stmt.query(rusqlite::params![
            recorded_by,
            file_id_b64,
            descriptor_event_id_b64
        ])?
    } else {
        stmt.query(rusqlite::params![recorded_by, file_id_b64])?
    };

    let mut slices_seen = 0i64;
    let mut seen_slice_numbers = std::collections::BTreeSet::<i64>::new();
    let mut bytes_written = 0u64;
    while let Some(row) = rows.next()? {
        let slice_number: i64 = row.get(0)?;
        let slice_event_id_b64: String = row.get(1)?;
        if slice_number < 0 || slice_number >= total_slices {
            continue;
        }
        if !seen_slice_numbers.insert(slice_number) {
            continue;
        }
        let raw_payload = load_file_slice_payload(
            db,
            recorded_by,
            &slice_event_id_b64,
            expected_key_event_id_b64,
        )?;
        if slice_number != slices_seen {
            return Err(format!(
                "file has missing/out-of-order slices: expected {}, got {}",
                slices_seen, slice_number
            )
            .into());
        }
        let (bao_encoding, raw_data) =
            crate::event_modules::file_slice::wire::unpack_bao_payload(&raw_payload);
        if !bao_encoding.is_empty() {
            let slice_start = slices_seen as u64 * slice_bytes as u64;
            let remaining = blob_bytes.saturating_sub(slice_start as i64) as u64;
            let slice_len = remaining.min(slice_bytes as u64);
            let plaintext = crate::crypto::bao_verify::verify_slice(
                root_hash_arr,
                &bao_encoding,
                slice_start,
                slice_len,
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("bao decode slice {}: {}", slices_seen, e).into()
            })?;
            writer.write_all(&plaintext)?;
            bytes_written += plaintext.len() as u64;
        } else {
            writer.write_all(&raw_data)?;
            bytes_written += raw_data.len() as u64;
        }
        slices_seen += 1;
    }

    Ok((slices_seen, bytes_written))
}

pub fn save_file_by_selector(
    db: &Connection,
    recorded_by: &str,
    selector: &str,
    output_path: &str,
) -> Result<SaveFileResponse, Box<dyn std::error::Error + Send + Sync>> {
    let file_event_id_b64 = resolve_file_selector_to_b64(db, recorded_by, selector)?;
    let file_event_id_hex = b64_to_hex(&file_event_id_b64);

    let (
        file_id_b64,
        blob_bytes,
        total_slices,
        filename,
        key_event_id_b64,
        root_hash_blob,
        slice_bytes,
    ): (String, i64, i64, String, String, Vec<u8>, i64) = db.query_row(
        "SELECT file_id, blob_bytes, total_slices, filename, key_event_id, root_hash, slice_bytes
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
                row.get(6)?,
            ))
        },
    )?;

    let mut root_hash_arr = [0u8; 32];
    if root_hash_blob.len() == 32 {
        root_hash_arr.copy_from_slice(&root_hash_blob);
    }

    let out_path = Path::new(output_path);
    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let parent_dir = out_path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp_file = tempfile::Builder::new()
        .prefix(".topo-save-")
        .suffix(".tmp")
        .tempfile_in(parent_dir)?;

    let (slices_written, bytes_written) = {
        let mut writer = BufWriter::new(temp_file.as_file_mut());
        let (mut slices_written, mut bytes_written) = write_matching_file_slices(
            db,
            recorded_by,
            &file_id_b64,
            Some(&file_event_id_b64),
            &key_event_id_b64,
            &root_hash_arr,
            blob_bytes,
            slice_bytes,
            total_slices,
            &mut writer,
        )?;
        if slices_written == 0 {
            (slices_written, bytes_written) = write_matching_file_slices(
                db,
                recorded_by,
                &file_id_b64,
                None,
                &key_event_id_b64,
                &root_hash_arr,
                blob_bytes,
                slice_bytes,
                total_slices,
                &mut writer,
            )?;
        }
        writer.flush()?;
        (slices_written, bytes_written)
    };
    if slices_written != total_slices {
        return Err(format!(
            "file incomplete: have {}/{} slices",
            slices_written, total_slices
        )
        .into());
    }

    let expected_len = blob_bytes.max(0) as u64;
    if bytes_written < expected_len {
        return Err(format!(
            "file data shorter than expected: {} < {}",
            bytes_written, expected_len
        )
        .into());
    }
    temp_file.as_file_mut().set_len(expected_len)?;
    temp_file.as_file_mut().sync_all()?;

    // Per-slice bao verification happens at projection time (file_slice
    // projector), so the save path is pure reassembly — no re-verification
    // needed here.

    temp_file
        .persist(out_path)
        .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> { err.error.into() })?;

    Ok(SaveFileResponse {
        file_event_id: file_event_id_hex,
        filename,
        output_path: out_path.to_string_lossy().to_string(),
        bytes_written: expected_len,
        total_slices,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{hash_event, EventId};
    use crate::db::schema::create_tables;
    use crate::event_modules::file_slice::{FILE_SLICE_CIPHERTEXT_BYTES, FILE_SLICE_DATA_BYTES};
    use crate::event_modules::{encode_event, EncryptedEvent, FileSliceEvent, ParsedEvent};

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

    fn insert_key_secret_row(
        db: &Connection,
        recorded_by: &str,
        key_event_id: EventId,
        key_bytes: [u8; 32],
    ) -> String {
        let key_event_id_b64 = event_id_to_base64(&key_event_id);
        db.execute(
            "INSERT INTO key_secrets (event_id, key_bytes, created_at, recorded_by)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![&key_event_id_b64, key_bytes.to_vec(), 1000i64, recorded_by],
        )
        .unwrap();
        key_event_id_b64
    }

    fn insert_encrypted_slice_event(
        db: &Connection,
        wrapper_key_event_id: EventId,
        key_bytes: [u8; 32],
        file_id: EventId,
        slice_number: i64,
        created_at_ms: i64,
        payload: &[u8],
    ) -> String {
        let mut ciphertext = vec![0u8; FILE_SLICE_CIPHERTEXT_BYTES];
        let copy_len = payload.len().min(FILE_SLICE_DATA_BYTES);
        ciphertext[4..4 + copy_len].copy_from_slice(&payload[..copy_len]);
        let inner = ParsedEvent::FileSlice(FileSliceEvent {
            created_at_ms: created_at_ms as u64,
            file_id,
            slice_number: slice_number as u32,
            ciphertext,
        });
        let inner_blob = encode_event(&inner).unwrap();
        let (nonce, ciphertext, auth_tag) =
            crate::crypto::encrypt_event_blob(&key_bytes, &inner_blob).unwrap();
        let outer = ParsedEvent::Encrypted(EncryptedEvent {
            created_at_ms: created_at_ms as u64,
            key_event_id: wrapper_key_event_id,
            owner_event_id: crate::event_modules::encrypted::NO_OWNER_EVENT_ID,
            inner_type_code: crate::event_modules::EVENT_TYPE_FILE_SLICE,
            nonce,
            ciphertext,
            auth_tag,
        });
        let blob = encode_event(&outer).unwrap();
        let event_id_b64 = event_id_to_base64(&hash_event(&blob));
        db.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                &event_id_b64,
                "encrypted",
                blob,
                "shared",
                created_at_ms,
                created_at_ms
            ],
        )
        .unwrap();
        event_id_b64
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
        let recorded_by = "peer1";
        let file_id = [1u8; 32];
        let file_id_b64 = event_id_to_base64(&file_id);
        let key_event_id = [2u8; 32];
        let key_bytes = [3u8; 32];
        let key_event_id_b64 = insert_key_secret_row(&db, recorded_by, key_event_id, key_bytes);
        db.execute(
            "INSERT INTO files
             (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                recorded_by,
                "evt1",
                "msg1",
                &file_id_b64,
                524288,
                2,
                FILE_SLICE_DATA_BYTES as i64,
                &[0u8; 32] as &[u8],
                &key_event_id_b64,
                "big.bin",
                "application/octet-stream",
                1000
            ],
        ).unwrap();
        let slice_evt1 = insert_encrypted_slice_event(
            &db,
            key_event_id,
            key_bytes,
            file_id,
            0,
            1001,
            &[11u8; FILE_SLICE_DATA_BYTES],
        );
        db.execute(
            "INSERT INTO file_slices
             (recorded_by, file_id, slice_number, event_id, created_at, descriptor_event_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![recorded_by, &file_id_b64, 0, &slice_evt1, 1001, "evt1"],
        )
        .unwrap();

        let result = list_for_message(&db, recorded_by, "msg1").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].total_slices, 2);
        assert_eq!(result[0].slices_received, 1);
        assert_eq!(result[0].downloaded_bytes, FILE_SLICE_DATA_BYTES as i64);
        assert_eq!(result[0].download_rate_mib_s, None);

        let slice_evt2 = insert_encrypted_slice_event(
            &db,
            key_event_id,
            key_bytes,
            file_id,
            1,
            1002,
            &[12u8; FILE_SLICE_DATA_BYTES],
        );
        db.execute(
            "INSERT INTO file_slices
             (recorded_by, file_id, slice_number, event_id, created_at, descriptor_event_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![recorded_by, &file_id_b64, 1, &slice_evt2, 1002, "evt1"],
        )
        .unwrap();

        let result = list_for_message(&db, recorded_by, "msg1").unwrap();
        assert_eq!(result[0].slices_received, 2);
        assert_eq!(result[0].downloaded_bytes, 524288);
        assert_eq!(result[0].download_rate_mib_s, None);
    }

    #[test]
    fn test_download_rate_uses_earliest_contributing_sync_start() {
        use crate::db::sync_log::{
            finalize_run, insert_run_received_event, insert_run_start, load_config, NewSyncRun,
        };

        let db = setup_db();
        let recorded_by = "peer1";
        let file_id = [4u8; 32];
        let file_id_b64 = event_id_to_base64(&file_id);
        let key_event_id = [5u8; 32];
        let key_bytes = [6u8; 32];
        let key_event_id_b64 = insert_key_secret_row(&db, recorded_by, key_event_id, key_bytes);

        // Use a recent base timestamp so prune_locked (max_age_days) doesn't
        // discard the runs — the old hardcoded-1970 timestamps were silently
        // pruned, masking the bug where finalize_run deletes rx_events for
        // unchanged runs.
        let base: i64 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
            - 10_000;

        db.execute(
            "INSERT INTO files
             (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                "peer1",
                "evt1",
                "msg1",
                &file_id_b64,
                524288i64,
                2i64,
                FILE_SLICE_DATA_BYTES as i64,
                &[0u8; 32] as &[u8],
                &key_event_id_b64,
                "big.bin",
                "application/octet-stream",
                base
            ],
        )
        .unwrap();
        let slice_evt1 = insert_encrypted_slice_event(
            &db,
            key_event_id,
            key_bytes,
            file_id,
            0,
            base + 2000,
            &[21u8; FILE_SLICE_DATA_BYTES],
        );
        db.execute(
            "INSERT INTO file_slices
             (recorded_by, file_id, slice_number, event_id, created_at, descriptor_event_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                &file_id_b64,
                0i64,
                &slice_evt1,
                base + 2000,
                "evt1"
            ],
        )
        .unwrap();
        let slice_evt2 = insert_encrypted_slice_event(
            &db,
            key_event_id,
            key_bytes,
            file_id,
            1,
            base + 3000,
            &[22u8; FILE_SLICE_DATA_BYTES],
        );
        db.execute(
            "INSERT INTO file_slices
             (recorded_by, file_id, slice_number, event_id, created_at, descriptor_event_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                &file_id_b64,
                1i64,
                &slice_evt2,
                base + 3000,
                "evt1"
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![recorded_by, &slice_evt1, base + 2000, "quic_recv:alice"],
        )
        .unwrap();
        db.execute(
            "INSERT INTO recorded_events (peer_id, event_id, recorded_at, source)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![recorded_by, &slice_evt2, base + 3000, "quic_recv:bob"],
        )
        .unwrap();

        let cfg = load_config(&db).unwrap();

        // First sync run (started_at = base, i.e. offset 0)
        let run1 = NewSyncRun {
            started_at_ms: base,
            ended_at_ms: base + 3500,
            session_id: 11,
            tenant_id: recorded_by.to_string(),
            peer_id: "remote-a".to_string(),
            direction: "inbound".to_string(),
            remote_addr: "127.0.0.1:4444".to_string(),
            role: "responder".to_string(),
            rounds: 2,
            events_sent: 0,
            events_received: 1,
            bytes_sent: 0,
            bytes_received: FILE_SLICE_DATA_BYTES as u64,
            changed: true,
            outcome: "in_progress".to_string(),
            error: None,
        };
        let run_id_1 = insert_run_start(&db, &run1).unwrap();
        insert_run_received_event(&db, run_id_1, &slice_evt1).unwrap();

        let final_run1 = NewSyncRun {
            outcome: "ok".to_string(),
            ..run1.clone()
        };
        let kept1 = finalize_run(&db, run_id_1, &final_run1, &cfg).unwrap();
        assert!(kept1.is_some(), "changed run should be preserved");

        // Second sync run (started_at = base+1500)
        let run2 = NewSyncRun {
            started_at_ms: base + 1500,
            ended_at_ms: base + 3200,
            session_id: 12,
            tenant_id: recorded_by.to_string(),
            peer_id: "remote-b".to_string(),
            direction: "inbound".to_string(),
            remote_addr: "127.0.0.1:5555".to_string(),
            role: "responder".to_string(),
            rounds: 2,
            events_sent: 0,
            events_received: 1,
            bytes_sent: 0,
            bytes_received: FILE_SLICE_DATA_BYTES as u64,
            changed: true,
            outcome: "in_progress".to_string(),
            error: None,
        };
        let run_id_2 = insert_run_start(&db, &run2).unwrap();
        insert_run_received_event(&db, run_id_2, &slice_evt2).unwrap();

        let final_run2 = NewSyncRun {
            outcome: "ok".to_string(),
            ..run2.clone()
        };
        let kept2 = finalize_run(&db, run_id_2, &final_run2, &cfg).unwrap();
        assert!(kept2.is_some(), "changed run should be preserved");

        // earliest_sync_start_ms = base (from run1)
        // last_slice_recorded_at_ms = base+3000 (from recorded_events)
        // elapsed = 3000ms, downloaded = 524288 bytes = 0.5 MiB
        // rate = 0.5 / 3.0 = 1/6 MiB/s
        let by_message = list_for_message(&db, recorded_by, "msg1").unwrap();
        assert_eq!(by_message.len(), 1);
        assert_eq!(by_message[0].downloaded_bytes, 524288);
        approx_eq(by_message[0].download_rate_mib_s.unwrap(), 1.0 / 6.0);

        let files = list_files(&db, recorded_by, 10).unwrap();
        assert_eq!(files.total, 1);
        assert_eq!(files.files[0].downloaded_bytes, 524288);
        approx_eq(files.files[0].download_rate_mib_s.unwrap(), 1.0 / 6.0);
    }

    #[test]
    fn test_downloaded_bytes_uses_actual_last_slice_size() {
        let db = setup_db();
        let recorded_by = "peer1";
        let file_id = [7u8; 32];
        let file_id_b64 = event_id_to_base64(&file_id);
        let key_event_id = [8u8; 32];
        let key_bytes = [9u8; 32];
        let key_event_id_b64 = insert_key_secret_row(&db, recorded_by, key_event_id, key_bytes);
        db.execute(
            "INSERT INTO files
             (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                recorded_by,
                "evt1",
                "msg1",
                &file_id_b64,
                300000i64,
                2i64,
                FILE_SLICE_DATA_BYTES as i64,
                &[0u8; 32] as &[u8],
                &key_event_id_b64,
                "odd.bin",
                "application/octet-stream",
                1000i64
            ],
        )
        .unwrap();
        let slice_evt1 = insert_encrypted_slice_event(
            &db,
            key_event_id,
            key_bytes,
            file_id,
            0,
            1001,
            &[31u8; FILE_SLICE_DATA_BYTES],
        );
        db.execute(
            "INSERT INTO file_slices
             (recorded_by, file_id, slice_number, event_id, created_at, descriptor_event_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                &file_id_b64,
                0i64,
                &slice_evt1,
                1001i64,
                "evt1"
            ],
        )
        .unwrap();
        let slice_evt2 = insert_encrypted_slice_event(
            &db,
            key_event_id,
            key_bytes,
            file_id,
            1,
            1002,
            &[32u8; 37_856],
        );
        db.execute(
            "INSERT INTO file_slices
             (recorded_by, file_id, slice_number, event_id, created_at, descriptor_event_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                &file_id_b64,
                1i64,
                &slice_evt2,
                1002i64,
                "evt1"
            ],
        )
        .unwrap();

        let by_message = list_for_message(&db, recorded_by, "msg1").unwrap();
        assert_eq!(by_message.len(), 1);
        assert_eq!(by_message[0].downloaded_bytes, 300000);
        assert_eq!(by_message[0].download_rate_mib_s, None);

        let files = list_files(&db, recorded_by, 10).unwrap();
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

    #[test]
    fn test_save_file_by_selector_writes_encrypted_slices_exact_bytes() {
        let db = setup_db();
        let recorded_by = "peer1";
        let file_event_id = [1u8; 32];
        let file_event_id_b64 = event_id_to_base64(&file_event_id);
        let file_id = [2u8; 32];
        let file_id_b64 = event_id_to_base64(&file_id);
        let key_event_id = [3u8; 32];
        let key_bytes = [9u8; 32];
        let key_event_id_b64 = insert_key_secret_row(&db, recorded_by, key_event_id, key_bytes);
        let payload = b"hello encrypted world";
        let slice_event_id_b64 =
            insert_encrypted_slice_event(&db, key_event_id, key_bytes, file_id, 0, 1001, payload);

        db.execute(
            "INSERT INTO files
             (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                recorded_by,
                &file_event_id_b64,
                "msg1",
                &file_id_b64,
                payload.len() as i64,
                1i64,
                FILE_SLICE_DATA_BYTES as i64,
                &[0u8; 32] as &[u8],
                &key_event_id_b64,
                "payload.bin",
                "application/octet-stream",
                1000i64
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO file_slices
             (recorded_by, file_id, slice_number, event_id, created_at, descriptor_event_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                &file_id_b64,
                0i64,
                &slice_event_id_b64,
                1001i64,
                &file_event_id_b64
            ],
        )
        .unwrap();

        let tmpdir = tempfile::tempdir().unwrap();
        let output_path = tmpdir.path().join("payload.bin");
        let response = save_file_by_selector(
            &db,
            recorded_by,
            &hex::encode(file_event_id),
            output_path.to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(response.bytes_written, payload.len() as u64);
        assert_eq!(std::fs::read(&output_path).unwrap(), payload);
    }

    #[test]
    fn test_save_file_by_selector_rejects_wrapper_key_mismatch() {
        let db = setup_db();
        let recorded_by = "peer1";
        let file_event_id = [4u8; 32];
        let file_event_id_b64 = event_id_to_base64(&file_event_id);
        let file_id = [5u8; 32];
        let file_id_b64 = event_id_to_base64(&file_id);
        let descriptor_key_event_id = [6u8; 32];
        let descriptor_key_bytes = [7u8; 32];
        let wrapper_key_event_id = [8u8; 32];
        let wrapper_key_bytes = [10u8; 32];
        let descriptor_key_event_id_b64 = insert_key_secret_row(
            &db,
            recorded_by,
            descriptor_key_event_id,
            descriptor_key_bytes,
        );
        insert_key_secret_row(&db, recorded_by, wrapper_key_event_id, wrapper_key_bytes);
        let slice_event_id_b64 = insert_encrypted_slice_event(
            &db,
            wrapper_key_event_id,
            wrapper_key_bytes,
            file_id,
            0,
            1001,
            b"mismatch",
        );

        db.execute(
            "INSERT INTO files
             (recorded_by, event_id, message_id, file_id, blob_bytes, total_slices, slice_bytes, root_hash, key_event_id, filename, mime_type, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            rusqlite::params![
                recorded_by,
                &file_event_id_b64,
                "msg1",
                &file_id_b64,
                8i64,
                1i64,
                FILE_SLICE_DATA_BYTES as i64,
                &[0u8; 32] as &[u8],
                &descriptor_key_event_id_b64,
                "payload.bin",
                "application/octet-stream",
                1000i64
            ],
        )
        .unwrap();
        db.execute(
            "INSERT INTO file_slices
             (recorded_by, file_id, slice_number, event_id, created_at, descriptor_event_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![
                recorded_by,
                &file_id_b64,
                0i64,
                &slice_event_id_b64,
                1001i64,
                &file_event_id_b64
            ],
        )
        .unwrap();

        let tmpdir = tempfile::tempdir().unwrap();
        let output_path = tmpdir.path().join("payload.bin");
        let err = save_file_by_selector(
            &db,
            recorded_by,
            &hex::encode(file_event_id),
            output_path.to_str().unwrap(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("key mismatch"),
            "expected key mismatch error, got {}",
            msg
        );
        assert!(
            !output_path.exists(),
            "failed save should not leave output behind"
        );
    }
}
