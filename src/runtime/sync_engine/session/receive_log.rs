use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{event_id_to_base64, hash_event};
use crate::db::{open_connection, timeline::EventTimeline};
use crate::protocol::{encode_frame, parse_frame, Frame, ParseError};
use crate::state::pipeline::ingest_now;

const RECEIVE_LOG_PREFIX: &str = "recvlog";
const RECEIVE_LOG_DATA_SUFFIX: &str = "bin";
const RECEIVE_LOG_META_SUFFIX: &str = "meta";
const RECEIVE_LOG_INGEST_BATCH_CAP: usize = 256;
const RECEIVE_LOG_HEADER_MAGIC: &[u8; 4] = b"P7RL";
const RECEIVE_LOG_HEADER_VERSION: u8 = 1;
const RECEIVE_LOG_HEADER_PREFIX_LEN: usize = 9;
const RECEIVE_LOG_HEADER_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveLogHeader {
    pub recorded_by: String,
    pub session_id: u64,
    pub source_tag: String,
}

pub struct ReceiveLogWriter {
    path: PathBuf,
    file: File,
    timeline_db: rusqlite::Connection,
    bytes_written: u64,
}

impl ReceiveLogWriter {
    pub fn open(
        db_path: &str,
        recorded_by: &str,
        session_id: u64,
        source_tag: &str,
    ) -> Result<Self, String> {
        let dir = receive_log_dir(db_path);
        fs::create_dir_all(&dir)
            .map_err(|e| format!("create receive log dir {}: {e}", dir.display()))?;
        let stem = receive_log_stem(session_id);
        let path = dir.join(format!("{stem}.{RECEIVE_LOG_DATA_SUFFIX}"));
        let header = ReceiveLogHeader {
            recorded_by: recorded_by.to_string(),
            session_id,
            source_tag: source_tag.to_string(),
        };
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .map_err(|e| format!("open receive log {}: {e}", path.display()))?;
        write_receive_log_header(&mut file, &header)?;
        let timeline_db = open_connection(db_path)
            .map_err(|e| format!("open timeline db for receive log {}: {e}", path.display()))?;
        Ok(Self {
            path,
            file,
            timeline_db,
            bytes_written: 0,
        })
    }

    pub fn append_blob(&mut self, blob: &[u8]) -> Result<(), String> {
        let event_id_b64 = event_id_to_base64(&hash_event(blob));
        let received_at = current_timestamp_ms();
        let timeline = EventTimeline::new(&self.timeline_db);
        let _ = timeline.mark_response_received_b64(&event_id_b64, received_at);
        let frame = encode_frame(&Frame::Event {
            blob: blob.to_vec(),
        });
        self.file
            .write_all(&frame)
            .map_err(|e| format!("append receive log {}: {e}", self.path.display()))?;
        self.bytes_written = self.bytes_written.saturating_add(frame.len() as u64);
        let _ = timeline.mark_persisted_b64(&event_id_b64, current_timestamp_ms());
        Ok(())
    }

    pub fn finish(mut self) -> Result<Option<PathBuf>, String> {
        self.file
            .flush()
            .map_err(|e| format!("flush receive log {}: {e}", self.path.display()))?;
        self.file
            .sync_all()
            .map_err(|e| format!("sync receive log {}: {e}", self.path.display()))?;
        if self.bytes_written == 0 {
            fs::remove_file(&self.path)
                .map_err(|e| format!("delete empty receive log {}: {e}", self.path.display()))?;
            return Ok(None);
        }
        Ok(Some(self.path))
    }
}

pub fn receive_log_dir(db_path: &str) -> PathBuf {
    Path::new(db_path).with_extension("receive-logs")
}

pub fn ingest_receive_log(db_path: &str, path: &Path) -> Result<usize, String> {
    let (mut file, header) = open_receive_log(path)?;
    let mut ingested = 0usize;
    let mut batch = Vec::<IngestItem>::with_capacity(RECEIVE_LOG_INGEST_BATCH_CAP);

    stream_receive_log(&mut file, path, |blob| {
        let event_id = hash_event(&blob);
        batch.push((
            event_id,
            blob,
            header.recorded_by.clone(),
            header.source_tag.clone(),
            current_timestamp_ms(),
        ));
        if batch.len() >= RECEIVE_LOG_INGEST_BATCH_CAP {
            ingested += ingest_now(db_path, std::mem::take(&mut batch))?;
        }
        Ok(())
    })?;
    if !batch.is_empty() {
        ingested += ingest_now(db_path, batch)?;
    }

    fs::remove_file(path).map_err(|e| format!("delete receive log {}: {e}", path.display()))?;
    let _ = fs::remove_file(legacy_receive_log_meta_path(path));
    Ok(ingested)
}

pub fn recover_receive_logs(db_path: &str) -> Result<usize, String> {
    let dir = receive_log_dir(db_path);
    if !dir.exists() {
        return Ok(0);
    }

    let mut paths = Vec::new();
    for entry in
        fs::read_dir(&dir).map_err(|e| format!("read receive log dir {}: {e}", dir.display()))?
    {
        let entry = entry.map_err(|e| format!("read receive log entry: {e}"))?;
        let path = entry.path();
        if path.is_file()
            && path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext == RECEIVE_LOG_DATA_SUFFIX)
                .unwrap_or(false)
        {
            paths.push(path);
        }
    }
    paths.sort();

    let mut ingested = 0usize;
    for path in paths {
        ingested += ingest_receive_log(db_path, &path)?;
    }
    Ok(ingested)
}

fn receive_log_stem(session_id: u64) -> String {
    format!(
        "{RECEIVE_LOG_PREFIX}.{session_id}.{}",
        current_timestamp_ms()
    )
}

fn write_receive_log_header(file: &mut File, header: &ReceiveLogHeader) -> Result<(), String> {
    let payload =
        serde_json::to_vec(header).map_err(|e| format!("encode receive log header: {e}"))?;
    if payload.len() > RECEIVE_LOG_HEADER_MAX_BYTES {
        return Err(format!(
            "receive log header too large: {} bytes",
            payload.len()
        ));
    }
    file.write_all(RECEIVE_LOG_HEADER_MAGIC)
        .map_err(|e| format!("write receive log header magic: {e}"))?;
    file.write_all(&[RECEIVE_LOG_HEADER_VERSION])
        .map_err(|e| format!("write receive log header version: {e}"))?;
    file.write_all(&(payload.len() as u32).to_le_bytes())
        .map_err(|e| format!("write receive log header length: {e}"))?;
    file.write_all(&payload)
        .map_err(|e| format!("write receive log header payload: {e}"))?;
    Ok(())
}

fn open_receive_log(path: &Path) -> Result<(File, ReceiveLogHeader), String> {
    let mut file =
        File::open(path).map_err(|e| format!("open receive log {}: {e}", path.display()))?;
    let header = match try_read_embedded_receive_log_header(&mut file, path)? {
        Some(header) => header,
        None => parse_legacy_receive_log_meta(path)?,
    };
    Ok((file, header))
}

fn try_read_embedded_receive_log_header(
    file: &mut File,
    path: &Path,
) -> Result<Option<ReceiveLogHeader>, String> {
    let mut prefix = [0u8; RECEIVE_LOG_HEADER_PREFIX_LEN];
    match file.read_exact(&mut prefix) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            file.seek(SeekFrom::Start(0))
                .map_err(|seek_err| format!("rewind receive log {}: {seek_err}", path.display()))?;
            return Ok(None);
        }
        Err(e) => return Err(format!("read receive log header {}: {e}", path.display())),
    }

    if &prefix[..4] != RECEIVE_LOG_HEADER_MAGIC {
        file.seek(SeekFrom::Start(0))
            .map_err(|e| format!("rewind receive log {}: {e}", path.display()))?;
        return Ok(None);
    }
    if prefix[4] != RECEIVE_LOG_HEADER_VERSION {
        return Err(format!(
            "unsupported receive log header version {} for {}",
            prefix[4],
            path.display()
        ));
    }
    let len = u32::from_le_bytes(prefix[5..9].try_into().unwrap()) as usize;
    if len > RECEIVE_LOG_HEADER_MAX_BYTES {
        return Err(format!(
            "receive log header too large in {}: {} bytes",
            path.display(),
            len
        ));
    }
    let mut payload = vec![0u8; len];
    file.read_exact(&mut payload)
        .map_err(|e| format!("read receive log header payload {}: {e}", path.display()))?;
    let header: ReceiveLogHeader = serde_json::from_slice(&payload)
        .map_err(|e| format!("decode receive log header {}: {e}", path.display()))?;
    Ok(Some(header))
}

fn parse_legacy_receive_log_meta(path: &Path) -> Result<ReceiveLogHeader, String> {
    let meta_path = legacy_receive_log_meta_path(path);
    let bytes = fs::read(&meta_path)
        .map_err(|e| format!("read receive log meta {}: {e}", meta_path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("decode receive log meta {}: {e}", meta_path.display()))
}

fn legacy_receive_log_meta_path(path: &Path) -> PathBuf {
    path.with_extension(RECEIVE_LOG_META_SUFFIX)
}

fn stream_receive_log<F>(file: &mut File, path: &Path, mut on_blob: F) -> Result<usize, String>
where
    F: FnMut(Vec<u8>) -> Result<(), String>,
{
    let mut buffer = Vec::<u8>::with_capacity(64 * 1024);
    let mut read_buf = [0u8; 64 * 1024];
    let mut offset = 0usize;
    let mut sent = 0usize;

    loop {
        match parse_next_frame(&buffer, &mut offset)? {
            Some(Frame::Event { blob }) => {
                on_blob(blob)?;
                sent += 1;
            }
            Some(_) => {}
            None => {
                if offset > 0 {
                    buffer.drain(..offset);
                    offset = 0;
                }
                let read = file
                    .read(&mut read_buf)
                    .map_err(|e| format!("read receive log {}: {e}", path.display()))?;
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&read_buf[..read]);
            }
        }
    }

    Ok(sent)
}

fn parse_next_frame(buffer: &[u8], offset: &mut usize) -> Result<Option<Frame>, String> {
    if *offset >= buffer.len() {
        return Ok(None);
    }

    match parse_frame(&buffer[*offset..]) {
        Ok((frame, consumed)) => {
            *offset += consumed;
            Ok(Some(frame))
        }
        Err(ParseError::InsufficientData) => Ok(None),
        Err(_) => {
            *offset = buffer.len();
            Ok(None)
        }
    }
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::event_id_to_base64;
    use crate::db::{open_connection, schema::create_tables, timeline::EventTimeline};

    #[test]
    fn receive_log_round_trips_and_ignores_truncated_tail() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();
        let mut writer = ReceiveLogWriter::open(
            db_path.to_str().unwrap(),
            "tenant-a",
            7,
            "quic_recv:peer-x@127.0.0.1:7777",
        )
        .unwrap();
        writer.append_blob(b"one").unwrap();
        writer.append_blob(b"two").unwrap();
        let path = writer.finish().unwrap().unwrap();

        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&[0x03, 0x08, 0x00]).unwrap();
        }

        let mut blobs = Vec::new();
        let (mut file, _header) = open_receive_log(&path).unwrap();
        let parsed = stream_receive_log(&mut file, &path, |blob| {
            blobs.push(blob);
            Ok(())
        })
        .unwrap();
        assert_eq!(parsed, 2);
        assert_eq!(blobs, vec![b"one".to_vec(), b"two".to_vec()]);

        let (_file, header) = open_receive_log(&path).unwrap();
        assert_eq!(header.recorded_by, "tenant-a");
        assert_eq!(header.session_id, 7);
        assert_eq!(header.source_tag, "quic_recv:peer-x@127.0.0.1:7777");
    }

    #[test]
    fn receive_log_append_marks_first_store_time() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let blob = b"hello world".to_vec();
        let event_id_b64 = event_id_to_base64(&hash_event(&blob));
        let mut writer =
            ReceiveLogWriter::open(db_path.to_str().unwrap(), "tenant-a", 8, "peer-x").unwrap();
        writer.append_blob(&blob).unwrap();
        writer.finish().unwrap();

        let timeline = EventTimeline::new(&conn);
        let row = timeline.load(&event_id_b64).unwrap().unwrap();
        assert!(row.response_received_at.is_some());
        assert!(row.persisted_at.is_some());
        assert!(row.response_received_at.unwrap() <= row.persisted_at.unwrap());
    }
}
