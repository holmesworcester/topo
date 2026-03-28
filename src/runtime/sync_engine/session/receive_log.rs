use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::hash_event;
use crate::db::queue::current_timestamp_ms;
use crate::protocol::{parse_frame, Frame, ParseError};
use crate::state::pipeline::ingest_now;

const RECEIVE_LOG_PREFIX: &str = "recvlog";
const RECEIVE_LOG_DATA_SUFFIX: &str = "bin";
const RECEIVE_LOG_META_SUFFIX: &str = "meta";
const RECEIVE_LOG_INGEST_BATCH_CAP: usize = 256;
const RECEIVE_LOG_INGEST_BATCH_MAX_BYTES: usize = 8 * 1024 * 1024;
const RECEIVE_LOG_HEADER_MAGIC: &[u8; 4] = b"P7RL";
const RECEIVE_LOG_HEADER_VERSION: u8 = 2;
const RECEIVE_LOG_HEADER_PREFIX_LEN: usize = 9;
const RECEIVE_LOG_HEADER_MAX_BYTES: usize = 64 * 1024;
const RECEIVE_LOG_RECORD_PREFIX_LEN: usize = 12;
const RECEIVE_LOG_RECORD_SUFFIX_LEN: usize = 8;

#[derive(Default)]
struct ReceiveLogIngestInner {
    pending: VecDeque<PathBuf>,
    active_hot_receives: usize,
    worker_running: bool,
}

#[derive(Default)]
struct ReceiveLogIngestState {
    inner: Mutex<ReceiveLogIngestInner>,
    wake: Condvar,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiveLogHeader {
    pub recorded_by: String,
    pub session_id: u64,
    pub source_tag: String,
}

pub struct ReceiveLogWriter {
    path: PathBuf,
    file: File,
    bytes_written: u64,
}

fn ingest_state_map() -> &'static Mutex<HashMap<String, Arc<ReceiveLogIngestState>>> {
    static STATES: OnceLock<Mutex<HashMap<String, Arc<ReceiveLogIngestState>>>> = OnceLock::new();
    STATES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn ingest_state(db_path: &str) -> Arc<ReceiveLogIngestState> {
    let mut states = ingest_state_map()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    states
        .entry(db_path.to_string())
        .or_insert_with(|| Arc::new(ReceiveLogIngestState::default()))
        .clone()
}

pub fn note_hot_receive_started(db_path: &str) {
    let state = ingest_state(db_path);
    let mut inner = state
        .inner
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    inner.active_hot_receives = inner.active_hot_receives.saturating_add(1);
}

pub fn note_hot_receive_finished(db_path: &str) {
    let state = ingest_state(db_path);
    {
        let mut inner = state
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.active_hot_receives = inner.active_hot_receives.saturating_sub(1);
    }
    state.wake.notify_all();
}

pub fn enqueue_receive_log_ingest(db_path: &str, path: PathBuf) {
    let state = ingest_state(db_path);
    let mut spawn_worker = false;
    {
        let mut inner = state
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.pending.push_back(path);
        if !inner.worker_running {
            inner.worker_running = true;
            spawn_worker = true;
        }
    }
    state.wake.notify_all();

    if spawn_worker {
        let db_path = db_path.to_string();
        let state = state.clone();
        if let Err(e) = std::thread::Builder::new()
            .name(format!("recvlog-ingest-{}", current_timestamp_ms()))
            .spawn(move || receive_log_ingest_worker(db_path, state))
        {
            tracing::warn!("spawn receive log ingest worker: {}", e);
        }
    }
}

fn receive_log_ingest_worker(db_path: String, state: Arc<ReceiveLogIngestState>) {
    loop {
        let next_path = {
            let mut inner = state
                .inner
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            loop {
                if inner.pending.is_empty() {
                    inner.worker_running = false;
                    return;
                }
                if inner.active_hot_receives == 0 {
                    break inner.pending.pop_front();
                }
                inner = state
                    .wake
                    .wait(inner)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        };

        let Some(path) = next_path else {
            continue;
        };
        if let Err(e) = ingest_receive_log(&db_path, &path) {
            tracing::warn!("background receive log ingest {}: {}", path.display(), e);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiveLogRecord {
    blob: Vec<u8>,
    received_at_ms: i64,
    first_stored_at_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReceiveLogVersion {
    V1Frames,
    V2Records,
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
        let _ = db_path;
        Ok(Self {
            path,
            file,
            bytes_written: 0,
        })
    }

    pub fn append_blob(&mut self, blob: &[u8]) -> Result<(), String> {
        let received_at = current_timestamp_ms();
        let blob_len = u32::try_from(blob.len())
            .map_err(|_| format!("receive log blob too large: {} bytes", blob.len()))?;
        self.file
            .write_all(&received_at.to_le_bytes())
            .map_err(|e| format!("append receive log {}: {e}", self.path.display()))?;
        self.file
            .write_all(&blob_len.to_le_bytes())
            .map_err(|e| format!("append receive log {}: {e}", self.path.display()))?;
        self.file
            .write_all(blob)
            .map_err(|e| format!("append receive log {}: {e}", self.path.display()))?;
        let first_stored_at_ms = current_timestamp_ms();
        self.file
            .write_all(&first_stored_at_ms.to_le_bytes())
            .map_err(|e| format!("append receive log {}: {e}", self.path.display()))?;
        self.bytes_written = self.bytes_written.saturating_add(
            (RECEIVE_LOG_RECORD_PREFIX_LEN + blob.len() + RECEIVE_LOG_RECORD_SUFFIX_LEN) as u64,
        );
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
            match fs::remove_file(&self.path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(format!(
                        "delete empty receive log {}: {e}",
                        self.path.display()
                    ))
                }
            }
            return Ok(None);
        }
        Ok(Some(self.path))
    }

    pub fn abort(self) {
        let path = self.path;
        drop(self.file);
        let _ = fs::remove_file(path);
    }
}

pub fn receive_log_dir(db_path: &str) -> PathBuf {
    Path::new(db_path).with_extension("receive-logs")
}

pub fn ingest_receive_log(db_path: &str, path: &Path) -> Result<usize, String> {
    let (mut file, header, version) = open_receive_log(path)?;
    let mut ingested = 0usize;
    let mut batch = Vec::<IngestItem>::with_capacity(RECEIVE_LOG_INGEST_BATCH_CAP);
    let mut batch_bytes = 0usize;

    stream_receive_log(&mut file, path, version, |record| {
        let event_id = hash_event(&record.blob);
        batch_bytes = batch_bytes.saturating_add(record.blob.len());
        batch.push((
            event_id,
            record.blob,
            header.recorded_by.clone(),
            header.source_tag.clone(),
            record.received_at_ms,
            record.first_stored_at_ms,
        ));
        if batch.len() >= RECEIVE_LOG_INGEST_BATCH_CAP
            || batch_bytes >= RECEIVE_LOG_INGEST_BATCH_MAX_BYTES
        {
            ingested += ingest_now(db_path, std::mem::take(&mut batch))?;
            batch_bytes = 0;
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
    static NEXT_RECEIVE_LOG_NONCE: AtomicU64 = AtomicU64::new(1);
    format!(
        "{RECEIVE_LOG_PREFIX}.{session_id}.{}.{}",
        current_timestamp_ms(),
        NEXT_RECEIVE_LOG_NONCE.fetch_add(1, Ordering::Relaxed)
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

fn open_receive_log(path: &Path) -> Result<(File, ReceiveLogHeader, ReceiveLogVersion), String> {
    let mut file =
        File::open(path).map_err(|e| format!("open receive log {}: {e}", path.display()))?;
    let (header, version) = match try_read_embedded_receive_log_header(&mut file, path)? {
        Some(result) => result,
        None => (
            parse_legacy_receive_log_meta(path)?,
            ReceiveLogVersion::V1Frames,
        ),
    };
    Ok((file, header, version))
}

fn try_read_embedded_receive_log_header(
    file: &mut File,
    path: &Path,
) -> Result<Option<(ReceiveLogHeader, ReceiveLogVersion)>, String> {
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
    let version = match prefix[4] {
        1 => ReceiveLogVersion::V1Frames,
        2 => ReceiveLogVersion::V2Records,
        other => {
            return Err(format!(
                "unsupported receive log header version {} for {}",
                other,
                path.display()
            ))
        }
    };
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
    Ok(Some((header, version)))
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

fn stream_receive_log<F>(
    file: &mut File,
    path: &Path,
    version: ReceiveLogVersion,
    on_record: F,
) -> Result<usize, String>
where
    F: FnMut(ReceiveLogRecord) -> Result<(), String>,
{
    match version {
        ReceiveLogVersion::V1Frames => stream_legacy_receive_log(file, path, on_record),
        ReceiveLogVersion::V2Records => stream_record_receive_log(file, path, on_record),
    }
}

fn stream_legacy_receive_log<F>(
    file: &mut File,
    path: &Path,
    mut on_record: F,
) -> Result<usize, String>
where
    F: FnMut(ReceiveLogRecord) -> Result<(), String>,
{
    let mut buffer = Vec::<u8>::with_capacity(64 * 1024);
    let mut read_buf = [0u8; 64 * 1024];
    let mut offset = 0usize;
    let mut sent = 0usize;

    loop {
        match parse_next_frame(&buffer, &mut offset)? {
            Some(Frame::Event { blob }) => {
                let now_ms = current_timestamp_ms();
                on_record(ReceiveLogRecord {
                    blob,
                    received_at_ms: now_ms,
                    first_stored_at_ms: now_ms,
                })?;
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

fn stream_record_receive_log<F>(
    file: &mut File,
    path: &Path,
    mut on_record: F,
) -> Result<usize, String>
where
    F: FnMut(ReceiveLogRecord) -> Result<(), String>,
{
    let mut buffer = Vec::<u8>::with_capacity(64 * 1024);
    let mut read_buf = [0u8; 64 * 1024];
    let mut offset = 0usize;
    let mut sent = 0usize;

    loop {
        match parse_next_record(&buffer, &mut offset)? {
            Some(record) => {
                on_record(record)?;
                sent += 1;
            }
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

fn parse_next_record(
    buffer: &[u8],
    offset: &mut usize,
) -> Result<Option<ReceiveLogRecord>, String> {
    if *offset >= buffer.len() {
        return Ok(None);
    }
    if buffer.len() - *offset < RECEIVE_LOG_RECORD_PREFIX_LEN {
        return Ok(None);
    }

    let received_at_ms = i64::from_le_bytes(
        buffer[*offset..*offset + 8]
            .try_into()
            .map_err(|_| "receive log record received_at truncated".to_string())?,
    );
    let blob_len = u32::from_le_bytes(
        buffer[*offset + 8..*offset + 12]
            .try_into()
            .map_err(|_| "receive log record blob length truncated".to_string())?,
    ) as usize;
    let record_len = RECEIVE_LOG_RECORD_PREFIX_LEN
        .saturating_add(blob_len)
        .saturating_add(RECEIVE_LOG_RECORD_SUFFIX_LEN);
    if buffer.len() - *offset < record_len {
        return Ok(None);
    }

    let blob_start = *offset + RECEIVE_LOG_RECORD_PREFIX_LEN;
    let blob_end = blob_start + blob_len;
    let first_stored_at_ms = i64::from_le_bytes(
        buffer[blob_end..blob_end + RECEIVE_LOG_RECORD_SUFFIX_LEN]
            .try_into()
            .map_err(|_| "receive log record stored_at truncated".to_string())?,
    );
    let blob = buffer[blob_start..blob_end].to_vec();
    *offset += record_len;
    Ok(Some(ReceiveLogRecord {
        blob,
        received_at_ms,
        first_stored_at_ms,
    }))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;
    use crate::crypto::{event_id_to_base64, hash_event};
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
        let (mut file, _header, version) = open_receive_log(&path).unwrap();
        let parsed = stream_receive_log(&mut file, &path, version, |record| {
            blobs.push(record.blob);
            Ok(())
        })
        .unwrap();
        assert_eq!(parsed, 2);
        assert_eq!(blobs, vec![b"one".to_vec(), b"two".to_vec()]);

        let (_file, header, version) = open_receive_log(&path).unwrap();
        assert_eq!(header.recorded_by, "tenant-a");
        assert_eq!(header.session_id, 7);
        assert_eq!(header.source_tag, "quic_recv:peer-x@127.0.0.1:7777");
        assert_eq!(version, ReceiveLogVersion::V2Records);
    }

    #[test]
    fn receive_log_ingest_replays_first_store_time() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let blob = b"hello world".to_vec();
        let event_id_b64 = event_id_to_base64(&hash_event(&blob));
        let mut writer =
            ReceiveLogWriter::open(db_path.to_str().unwrap(), "tenant-a", 8, "peer-x").unwrap();
        writer.append_blob(&blob).unwrap();
        let path = writer.finish().unwrap().unwrap();

        ingest_receive_log(db_path.to_str().unwrap(), &path).unwrap();

        let timeline = EventTimeline::new(&conn);
        let row = timeline.load(&event_id_b64).unwrap().unwrap();
        assert!(row.first_received_at.is_some());
        assert!(row.first_stored_at.is_some());
        assert!(row.first_received_at.unwrap() <= row.first_stored_at.unwrap());
    }

    #[test]
    fn receive_log_stems_are_unique_with_same_session_and_timestamp() {
        let first = receive_log_stem(42);
        let second = receive_log_stem(42);
        assert_ne!(first, second);
        assert!(first.starts_with("recvlog.42."));
        assert!(second.starts_with("recvlog.42."));
    }

    #[test]
    fn background_ingest_waits_for_active_hot_receives() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let blob = b"queued while downloading".to_vec();
        let event_id_b64 = event_id_to_base64(&hash_event(&blob));
        let mut writer =
            ReceiveLogWriter::open(db_path.to_str().unwrap(), "tenant-a", 9, "peer-x").unwrap();
        writer.append_blob(&blob).unwrap();
        let path = writer.finish().unwrap().unwrap();

        note_hot_receive_started(db_path.to_str().unwrap());
        enqueue_receive_log_ingest(db_path.to_str().unwrap(), path.clone());
        std::thread::sleep(Duration::from_millis(150));

        let timeline = EventTimeline::new(&conn);
        assert!(path.exists(), "queued receive log should remain on disk");
        assert!(
            timeline.load(&event_id_b64).unwrap().is_none(),
            "background ingest should stay paused while a hot range receive is active"
        );

        note_hot_receive_finished(db_path.to_str().unwrap());

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if timeline.load(&event_id_b64).unwrap().is_some() && !path.exists() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "background ingest did not resume after receives went idle"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}
