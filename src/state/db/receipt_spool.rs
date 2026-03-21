use std::cell::Cell;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rusqlite::{Connection, Result as SqliteResult};

use crate::contracts::event_pipeline_contract::IngestItem;

const SEGMENT_MAGIC: &[u8; 8] = b"RCPTSEG1";
const RECORD_HEADER_LEN: usize = 8 + 8 + 2 + 2 + 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptSpoolRow {
    pub spool_id: i64,
    pub item: IngestItem,
    pub durable_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiptSpoolStats {
    pub count: i64,
    pub first_durable_at_ms: Option<i64>,
    pub last_durable_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyncMode {
    None,
    Data,
    Full,
}

pub fn ensure_schema(_conn: &Connection) -> SqliteResult<()> {
    Ok(())
}

pub fn spool_path_for_db_path<P: AsRef<Path>>(db_path: P) -> PathBuf {
    let path = db_path.as_ref();
    let mut os = path.as_os_str().to_owned();
    os.push(".receipt-burst.d");
    PathBuf::from(os)
}

fn stats_path_for_db_path<P: AsRef<Path>>(db_path: P) -> PathBuf {
    let path = db_path.as_ref();
    let mut os = path.as_os_str().to_owned();
    os.push(".receipt-burst.stats");
    PathBuf::from(os)
}

fn sync_mode() -> SyncMode {
    match std::env::var("TOPO_RECEIPT_SPOOL_SYNC")
        .unwrap_or_else(|_| "data".to_string())
        .to_ascii_lowercase()
        .as_str()
    {
        "none" | "off" => SyncMode::None,
        "full" => SyncMode::Full,
        _ => SyncMode::Data,
    }
}

fn segment_ready_path(dir: &Path, segment_id: u64) -> PathBuf {
    dir.join(format!("{segment_id:020}.ready"))
}

fn segment_tmp_path(dir: &Path, segment_id: u64) -> PathBuf {
    dir.join(format!("{segment_id:020}.tmp"))
}

fn parse_segment_id(path: &Path) -> Option<u64> {
    let ext = path.extension()?.to_str()?;
    if ext != "ready" {
        return None;
    }
    path.file_stem()?.to_str()?.parse::<u64>().ok()
}

fn list_ready_segments(dir: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let mut segments = Vec::new();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(segments),
        Err(err) => return Err(err),
    };
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if let Some(segment_id) = parse_segment_id(&path) {
            segments.push((segment_id, path));
        }
    }
    segments.sort_by_key(|(segment_id, _)| *segment_id);
    Ok(segments)
}

fn encode_batch(batch: &[IngestItem], durable_at_ms: i64) -> Vec<u8> {
    let mut encoded_len = SEGMENT_MAGIC.len();
    for (_, blob, recorded_by, source_tag, _) in batch {
        encoded_len = encoded_len
            .saturating_add(4)
            .saturating_add(RECORD_HEADER_LEN)
            .saturating_add(recorded_by.len())
            .saturating_add(source_tag.len())
            .saturating_add(blob.len());
    }
    let mut encoded = Vec::with_capacity(encoded_len);
    encoded.extend_from_slice(SEGMENT_MAGIC);
    for (_, blob, recorded_by, source_tag, received_at_ms) in batch {
        let payload_len = RECORD_HEADER_LEN + recorded_by.len() + source_tag.len() + blob.len();
        encoded.extend_from_slice(&(payload_len as u32).to_le_bytes());
        encoded.extend_from_slice(&durable_at_ms.to_le_bytes());
        encoded.extend_from_slice(&received_at_ms.to_le_bytes());
        encoded.extend_from_slice(&(recorded_by.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&(source_tag.len() as u16).to_le_bytes());
        encoded.extend_from_slice(&(blob.len() as u32).to_le_bytes());
        encoded.extend_from_slice(recorded_by.as_bytes());
        encoded.extend_from_slice(source_tag.as_bytes());
        encoded.extend_from_slice(blob);
    }
    encoded
}

fn read_u16_le(src: &[u8], offset: &mut usize) -> io::Result<u16> {
    if *offset + 2 > src.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short u16 field in receipt segment",
        ));
    }
    let value = u16::from_le_bytes([src[*offset], src[*offset + 1]]);
    *offset += 2;
    Ok(value)
}

fn read_u32_le(src: &[u8], offset: &mut usize) -> io::Result<u32> {
    if *offset + 4 > src.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short u32 field in receipt segment",
        ));
    }
    let value = u32::from_le_bytes([
        src[*offset],
        src[*offset + 1],
        src[*offset + 2],
        src[*offset + 3],
    ]);
    *offset += 4;
    Ok(value)
}

fn read_i64_le(src: &[u8], offset: &mut usize) -> io::Result<i64> {
    if *offset + 8 > src.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short i64 field in receipt segment",
        ));
    }
    let value = i64::from_le_bytes([
        src[*offset],
        src[*offset + 1],
        src[*offset + 2],
        src[*offset + 3],
        src[*offset + 4],
        src[*offset + 5],
        src[*offset + 6],
        src[*offset + 7],
    ]);
    *offset += 8;
    Ok(value)
}

fn decode_record(payload: &[u8]) -> io::Result<(IngestItem, i64)> {
    let mut offset = 0usize;
    let durable_at_ms = read_i64_le(payload, &mut offset)?;
    let received_at_ms = read_i64_le(payload, &mut offset)?;
    let recorded_by_len = read_u16_le(payload, &mut offset)? as usize;
    let source_tag_len = read_u16_le(payload, &mut offset)? as usize;
    let blob_len = read_u32_le(payload, &mut offset)? as usize;
    let trailing = recorded_by_len
        .checked_add(source_tag_len)
        .and_then(|v| v.checked_add(blob_len))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "receipt segment overflow"))?;
    if offset + trailing != payload.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "receipt segment record length mismatch",
        ));
    }
    let recorded_by = String::from_utf8(payload[offset..offset + recorded_by_len].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid recorded_by utf8"))?;
    offset += recorded_by_len;
    let source_tag = String::from_utf8(payload[offset..offset + source_tag_len].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid source_tag utf8"))?;
    offset += source_tag_len;
    let blob = payload[offset..offset + blob_len].to_vec();
    Ok((
        ([0u8; 32], blob, recorded_by, source_tag, received_at_ms),
        durable_at_ms,
    ))
}

fn read_segment_rows(path: &Path, segment_id: u64) -> io::Result<Vec<ReceiptSpoolRow>> {
    let raw = fs::read(path)?;
    if raw.len() < SEGMENT_MAGIC.len() || &raw[..SEGMENT_MAGIC.len()] != SEGMENT_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid receipt segment magic",
        ));
    }
    let mut offset = SEGMENT_MAGIC.len();
    let mut rows = Vec::new();
    while offset < raw.len() {
        let payload_len = read_u32_le(&raw, &mut offset)? as usize;
        if offset + payload_len > raw.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated receipt segment payload",
            ));
        }
        let (item, durable_at_ms) = decode_record(&raw[offset..offset + payload_len])?;
        offset += payload_len;
        rows.push(ReceiptSpoolRow {
            spool_id: segment_id as i64,
            item,
            durable_at_ms,
        });
    }
    Ok(rows)
}

fn read_stats_file(path: &Path) -> io::Result<Option<ReceiptSpoolStats>> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err),
    };
    let mut parts = raw.split_whitespace();
    let count = match parts.next() {
        Some(value) => value.parse::<i64>().ok(),
        None => None,
    };
    let first = match parts.next() {
        Some("-") | None => None,
        Some(value) => value.parse::<i64>().ok(),
    };
    let last = match parts.next() {
        Some("-") | None => None,
        Some(value) => value.parse::<i64>().ok(),
    };
    Ok(count.map(|count| ReceiptSpoolStats {
        count,
        first_durable_at_ms: first,
        last_durable_at_ms: last,
    }))
}

pub fn stats_for_db_path<P: AsRef<Path>>(
    db_path: P,
    skip_count: usize,
) -> io::Result<ReceiptSpoolStats> {
    let stats_path = stats_path_for_db_path(&db_path);
    let stats = read_stats_file(&stats_path)?.unwrap_or(ReceiptSpoolStats {
        count: 0,
        first_durable_at_ms: None,
        last_durable_at_ms: None,
    });
    if skip_count == 0 {
        return Ok(stats);
    }
    let remaining = stats.count.saturating_sub(skip_count as i64);
    Ok(ReceiptSpoolStats {
        count: remaining,
        first_durable_at_ms: if remaining > 0 {
            stats.first_durable_at_ms
        } else {
            None
        },
        last_durable_at_ms: if remaining > 0 {
            stats.last_durable_at_ms
        } else {
            None
        },
    })
}

pub fn reset_for_db_path<P: AsRef<Path>>(db_path: P) -> io::Result<()> {
    let spool_dir = spool_path_for_db_path(&db_path);
    match fs::remove_dir_all(&spool_dir) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    match fs::remove_file(stats_path_for_db_path(db_path)) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    Ok(())
}

pub struct ReceiptSpool {
    dir: PathBuf,
    stats_path: PathBuf,
    next_segment_id: Cell<u64>,
    stats_count: Cell<u64>,
    first_durable_at_ms: Cell<i64>,
    last_durable_at_ms: Cell<i64>,
}

impl ReceiptSpool {
    pub fn new(conn: &Connection) -> Self {
        let db_path = conn.path().unwrap_or(":memory:");
        Self::new_for_db_path(db_path)
    }

    pub fn new_for_db_path<P: AsRef<Path>>(db_path: P) -> Self {
        let dir = spool_path_for_db_path(&db_path);
        let stats_path = stats_path_for_db_path(&db_path);
        let stats = read_stats_file(&stats_path).ok().flatten();
        let next_segment_id = list_ready_segments(&dir)
            .ok()
            .and_then(|segments| segments.last().map(|(segment_id, _)| segment_id + 1))
            .unwrap_or(1);
        Self {
            dir,
            stats_path,
            next_segment_id: Cell::new(next_segment_id),
            stats_count: Cell::new(stats.map(|s| s.count.max(0) as u64).unwrap_or(0)),
            first_durable_at_ms: Cell::new(stats.and_then(|s| s.first_durable_at_ms).unwrap_or(0)),
            last_durable_at_ms: Cell::new(stats.and_then(|s| s.last_durable_at_ms).unwrap_or(0)),
        }
    }

    fn write_stats(&self) -> io::Result<()> {
        let first = self.first_durable_at_ms.get();
        let last = self.last_durable_at_ms.get();
        let payload = if first > 0 || last > 0 {
            let first = if first > 0 {
                first.to_string()
            } else {
                "-".to_string()
            };
            let last = if last > 0 {
                last.to_string()
            } else {
                "-".to_string()
            };
            format!("{} {} {}\n", self.stats_count.get(), first, last)
        } else {
            format!("{} - -\n", self.stats_count.get())
        };
        let tmp_path = self.stats_path.with_extension("stats.tmp");
        fs::write(&tmp_path, payload)?;
        fs::rename(tmp_path, &self.stats_path)?;
        Ok(())
    }

    pub fn append_batch(&self, batch: &[IngestItem], durable_at_ms: i64) -> io::Result<usize> {
        if batch.is_empty() {
            return Ok(0);
        }
        fs::create_dir_all(&self.dir)?;
        let segment_id = self.next_segment_id.get();
        self.next_segment_id.set(segment_id.saturating_add(1));
        let tmp_path = segment_tmp_path(&self.dir, segment_id);
        let ready_path = segment_ready_path(&self.dir, segment_id);
        let encoded = encode_batch(batch, durable_at_ms);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)?;
        file.write_all(&encoded)?;
        match sync_mode() {
            SyncMode::None => {}
            SyncMode::Data => file.sync_data()?,
            SyncMode::Full => file.sync_all()?,
        }
        drop(file);
        fs::rename(&tmp_path, &ready_path)?;
        if self.first_durable_at_ms.get() == 0 {
            self.first_durable_at_ms.set(durable_at_ms);
        }
        self.last_durable_at_ms.set(durable_at_ms);
        self.stats_count
            .set(self.stats_count.get().saturating_add(batch.len() as u64));
        self.write_stats()?;
        Ok(batch.len())
    }

    pub fn load_pending_batch(&self, limit: usize) -> io::Result<Vec<ReceiptSpoolRow>> {
        let Some((segment_id, path)) = list_ready_segments(&self.dir)?.into_iter().next() else {
            return Ok(Vec::new());
        };
        let rows = read_segment_rows(&path, segment_id)?;
        if rows.len() > limit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "receipt segment exceeded importer batch limit",
            ));
        }
        Ok(rows)
    }

    pub fn mark_materialized(&self, spool_ids: &[i64], _materialized_at_ms: i64) -> io::Result<()> {
        if spool_ids.is_empty() {
            return Ok(());
        }
        let unique_ids: BTreeSet<u64> = spool_ids.iter().map(|id| *id as u64).collect();
        for segment_id in unique_ids {
            match fs::remove_file(segment_ready_path(&self.dir, segment_id)) {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::NotFound => {}
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }

    pub fn prune_consumed_file(&self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_spool_round_trips_pending_rows() {
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("test.db");
        let spool = ReceiptSpool::new_for_db_path(&db_path);
        let batch = vec![(
            [7u8; 32],
            vec![1u8, 2, 3],
            "peer-a".to_string(),
            "sync".to_string(),
            123,
        )];

        spool.append_batch(&batch, 456).unwrap();
        let pending = spool.load_pending_batch(8).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].item.0, [0u8; 32]);
        assert_eq!(pending[0].item.1, batch[0].1);
        assert_eq!(pending[0].item.2, batch[0].2);
        assert_eq!(pending[0].item.3, batch[0].3);
        assert_eq!(pending[0].item.4, batch[0].4);
        assert_eq!(pending[0].durable_at_ms, 456);

        spool
            .mark_materialized(&[pending[0].spool_id], 789)
            .unwrap();
        spool.prune_consumed_file().unwrap();
        assert!(spool.load_pending_batch(8).unwrap().is_empty());
        assert!(list_ready_segments(&spool_path_for_db_path(&db_path))
            .unwrap()
            .is_empty());
    }
}
