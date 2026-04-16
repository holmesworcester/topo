use std::cmp::Reverse;
use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, OwnedSemaphorePermit, Semaphore};
use tracing::debug;

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::EventId;
use crate::db::queue::current_timestamp_ms;
use crate::state::pipeline::ingest_now;
use crate::sync::session::windowing::SyncWindowKind;

const RECEIVE_LOG_PREFIX: &str = "recvlog";
const RECEIVE_LOG_DATA_SUFFIX: &str = "bin";
const RECEIVE_LOG_INGEST_BATCH_CAP: usize = 256;
const RECEIVE_LOG_INGEST_BATCH_MAX_BYTES: usize = 8 * 1024 * 1024;
const RECEIVE_LOG_HEADER_MAGIC: &[u8; 4] = b"P7RL";
const RECEIVE_LOG_HEADER_VERSION: u8 = 2;
const RECEIVE_LOG_HEADER_PREFIX_LEN: usize = 9;
const RECEIVE_LOG_HEADER_MAX_BYTES: usize = 64 * 1024;
const RECEIVE_LOG_RECORD_PREFIX_LEN: usize = 12;
const RECEIVE_LOG_RECORD_SUFFIX_LEN: usize = 8;
const RECEIVE_LOG_RECORD_EVENT_ID_LEN: usize = 32;
const RECEIVE_LOG_RECORD_WITH_EVENT_ID_PREFIX_LEN: usize =
    RECEIVE_LOG_RECORD_PREFIX_LEN + RECEIVE_LOG_RECORD_EVENT_ID_LEN;

#[derive(Default)]
struct ReceiveLogIngestInner {
    pending: VecDeque<ReceiveLogIngestJob>,
    active_hot_receives: usize,
    worker_running: bool,
}

#[derive(Default)]
struct ReceiveLogIngestState {
    inner: Mutex<ReceiveLogIngestInner>,
    wake: Condvar,
}

#[derive(Debug)]
struct ReceiveLogIngestJob {
    path: PathBuf,
    priority: bool,
    priority_segment_ordinal: Option<u64>,
    enqueue_seq: u64,
    pending_overlay: Option<PendingReceiveOverlaySession>,
    completion: Option<oneshot::Sender<Result<usize, String>>>,
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

pub type ReceiveLogIngestWaiter = oneshot::Receiver<Result<usize, String>>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PendingReceiveOverlayKey {
    db_path: String,
    workspace_id: String,
    window_kind: SyncWindowKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PendingReceiveOverlaySession {
    key: PendingReceiveOverlayKey,
    session_id: u64,
}

pub struct PendingReceiveOverlayGuard {
    session: Option<PendingReceiveOverlaySession>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingReceiveOverlayEntry {
    pub created_at_ms: i64,
    pub event_id: EventId,
}

fn pending_receive_overlay(
) -> &'static Mutex<HashMap<PendingReceiveOverlayKey, HashMap<u64, Vec<PendingReceiveOverlayEntry>>>>
{
    static OVERLAY: OnceLock<
        Mutex<HashMap<PendingReceiveOverlayKey, HashMap<u64, Vec<PendingReceiveOverlayEntry>>>>,
    > = OnceLock::new();
    OVERLAY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn open_pending_receive_overlay_session(
    db_path: &str,
    workspace_id: &str,
    window_kind: SyncWindowKind,
    session_id: u64,
) -> PendingReceiveOverlayGuard {
    let session = PendingReceiveOverlaySession {
        key: PendingReceiveOverlayKey {
            db_path: db_path.to_string(),
            workspace_id: workspace_id.to_string(),
            window_kind,
        },
        session_id,
    };
    pending_receive_overlay()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(session.key.clone())
        .or_default()
        .entry(session.session_id)
        .or_default();
    PendingReceiveOverlayGuard {
        session: Some(session),
    }
}

impl PendingReceiveOverlayGuard {
    pub fn session(&self) -> &PendingReceiveOverlaySession {
        self.session
            .as_ref()
            .expect("pending receive overlay guard already disarmed")
    }

    pub fn into_session(mut self) -> PendingReceiveOverlaySession {
        self.session
            .take()
            .expect("pending receive overlay guard already disarmed")
    }
}

impl Drop for PendingReceiveOverlayGuard {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            clear_pending_receive_overlay_session(&session);
        }
    }
}

pub fn record_pending_receive_overlay_entry(
    session: &PendingReceiveOverlaySession,
    created_at_ms: i64,
    event_id: EventId,
) {
    record_pending_receive_overlay_entries(
        session,
        std::iter::once(PendingReceiveOverlayEntry {
            created_at_ms,
            event_id,
        }),
    );
}

pub fn record_pending_receive_overlay_entries(
    session: &PendingReceiveOverlaySession,
    entries: impl IntoIterator<Item = PendingReceiveOverlayEntry>,
) {
    pending_receive_overlay()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(session.key.clone())
        .or_default()
        .entry(session.session_id)
        .or_default()
        .extend(entries);
}

pub fn load_pending_receive_overlay_entries(
    db_path: &str,
    workspace_id: &str,
    _window_kind: SyncWindowKind,
) -> Vec<PendingReceiveOverlayEntry> {
    pending_receive_overlay()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .iter()
        .filter(|(key, _)| key.db_path == db_path && key.workspace_id == workspace_id)
        .flat_map(|(_, sessions)| sessions.values())
        .flat_map(|entries| entries.iter().copied())
        .collect()
}

pub fn clear_pending_receive_overlay_session(session: &PendingReceiveOverlaySession) {
    let mut overlay = pending_receive_overlay()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(sessions) = overlay.get_mut(&session.key) {
        sessions.remove(&session.session_id);
        if sessions.is_empty() {
            overlay.remove(&session.key);
        }
    }
}

fn ingest_state_map() -> &'static Mutex<HashMap<String, Arc<ReceiveLogIngestState>>> {
    static STATES: OnceLock<Mutex<HashMap<String, Arc<ReceiveLogIngestState>>>> = OnceLock::new();
    STATES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn peer_session_ingest_gate_map() -> &'static Mutex<HashMap<String, Arc<Semaphore>>> {
    static GATES: OnceLock<Mutex<HashMap<String, Arc<Semaphore>>>> = OnceLock::new();
    GATES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn peer_session_ingest_gate(db_path: &str, peer_id: &str) -> Arc<Semaphore> {
    let mut gates = peer_session_ingest_gate_map()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    gates
        .entry(format!("{db_path}|{peer_id}"))
        .or_insert_with(|| Arc::new(Semaphore::new(1)))
        .clone()
}

pub async fn acquire_peer_session_ingest_guard(
    db_path: &str,
    peer_id: &str,
) -> Result<OwnedSemaphorePermit, String> {
    peer_session_ingest_gate(db_path, peer_id)
        .acquire_owned()
        .await
        .map_err(|_| format!("peer session ingest gate closed for {peer_id}"))
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
    debug!(
        target: "topo::sync_operation",
        db_path,
        active_hot_receives = inner.active_hot_receives,
        "hot receive started"
    );
}

pub fn note_hot_receive_finished(db_path: &str) {
    let state = ingest_state(db_path);
    {
        let mut inner = state
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.active_hot_receives = inner.active_hot_receives.saturating_sub(1);
        debug!(
            target: "topo::sync_operation",
            db_path,
            active_hot_receives = inner.active_hot_receives,
            "hot receive finished"
        );
    }
    state.wake.notify_all();
}

fn spawn_receive_log_ingest_worker(
    db_path: &str,
    state: &Arc<ReceiveLogIngestState>,
) -> Result<(), String> {
    let db_path = db_path.to_string();
    let state = state.clone();
    std::thread::Builder::new()
        .name(format!("recvlog-ingest-{}", current_timestamp_ms()))
        .spawn(move || receive_log_ingest_worker(db_path, state))
        .map(|_| ())
        .map_err(|e| format!("spawn receive log ingest worker: {e}"))
}

fn next_receive_log_ingest_enqueue_seq() -> u64 {
    static NEXT_RECEIVE_LOG_INGEST_ENQUEUE_SEQ: AtomicU64 = AtomicU64::new(1);
    NEXT_RECEIVE_LOG_INGEST_ENQUEUE_SEQ.fetch_add(1, Ordering::Relaxed)
}

fn enqueue_receive_log_ingest_job(
    db_path: &str,
    path: PathBuf,
    priority: bool,
    priority_segment_ordinal: Option<u64>,
    pending_overlay: Option<PendingReceiveOverlaySession>,
    completion: Option<oneshot::Sender<Result<usize, String>>>,
) -> Result<(), String> {
    let state = ingest_state(db_path);
    let mut spawn_worker = false;
    {
        let mut inner = state
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        inner.pending.push_back(ReceiveLogIngestJob {
            path,
            priority,
            priority_segment_ordinal,
            enqueue_seq: next_receive_log_ingest_enqueue_seq(),
            pending_overlay,
            completion,
        });
        debug!(
            target: "topo::sync_operation",
            db_path,
            pending_receive_logs = inner.pending.len(),
            active_hot_receives = inner.active_hot_receives,
            priority,
            "receive log ingest enqueued"
        );
        if !inner.worker_running {
            inner.worker_running = true;
            spawn_worker = true;
        }
    }
    state.wake.notify_all();

    if spawn_worker {
        spawn_receive_log_ingest_worker(db_path, &state)?;
    }
    Ok(())
}

pub fn enqueue_receive_log_ingest(db_path: &str, path: PathBuf, priority: bool) {
    if let Err(e) =
        enqueue_receive_log_ingest_job(db_path, path, priority, priority.then_some(0), None, None)
    {
        tracing::warn!("{e}");
    }
}

pub fn enqueue_receive_log_ingest_with_pending_overlay(
    db_path: &str,
    path: PathBuf,
    priority: bool,
    pending_overlay: PendingReceiveOverlaySession,
) {
    if let Err(e) = enqueue_receive_log_ingest_job(
        db_path,
        path,
        priority,
        priority.then_some(0),
        Some(pending_overlay),
        None,
    ) {
        tracing::warn!("{e}");
    }
}

pub fn enqueue_receive_log_ingest_waiter(
    db_path: &str,
    path: PathBuf,
    priority: bool,
) -> Result<ReceiveLogIngestWaiter, String> {
    enqueue_receive_log_ingest_waiter_with_priority_segment(
        db_path,
        path,
        priority,
        priority.then_some(0),
    )
}

pub fn enqueue_receive_log_ingest_waiter_with_priority_segment(
    db_path: &str,
    path: PathBuf,
    priority: bool,
    priority_segment_ordinal: Option<u64>,
) -> Result<ReceiveLogIngestWaiter, String> {
    let (completion_tx, completion_rx) = oneshot::channel();
    enqueue_receive_log_ingest_job(
        db_path,
        path,
        priority,
        priority_segment_ordinal,
        None,
        Some(completion_tx),
    )?;
    Ok(completion_rx)
}

pub fn enqueue_receive_log_ingest_with_pending_overlay_waiter(
    db_path: &str,
    path: PathBuf,
    priority: bool,
    pending_overlay: PendingReceiveOverlaySession,
) -> Result<ReceiveLogIngestWaiter, String> {
    enqueue_receive_log_ingest_with_pending_overlay_waiter_with_priority_segment(
        db_path,
        path,
        priority,
        priority.then_some(0),
        pending_overlay,
    )
}

pub fn enqueue_receive_log_ingest_with_pending_overlay_waiter_with_priority_segment(
    db_path: &str,
    path: PathBuf,
    priority: bool,
    priority_segment_ordinal: Option<u64>,
    pending_overlay: PendingReceiveOverlaySession,
) -> Result<ReceiveLogIngestWaiter, String> {
    let (completion_tx, completion_rx) = oneshot::channel();
    enqueue_receive_log_ingest_job(
        db_path,
        path,
        priority,
        priority_segment_ordinal,
        Some(pending_overlay),
        Some(completion_tx),
    )?;
    Ok(completion_rx)
}

pub fn enqueue_receive_log_ingest_and_wait(
    db_path: &str,
    path: PathBuf,
    priority: bool,
) -> Result<usize, String> {
    let completion_rx = enqueue_receive_log_ingest_waiter(db_path, path, priority)?;
    completion_rx
        .blocking_recv()
        .map_err(|e| format!("receive log ingest waiter dropped: {e}"))?
}

pub async fn wait_for_receive_log_ingests(
    waiters: Vec<ReceiveLogIngestWaiter>,
) -> Result<usize, String> {
    let mut ingested = 0usize;
    for waiter in waiters {
        let result = tokio::task::spawn_blocking(move || waiter.blocking_recv())
            .await
            .map_err(|e| format!("join receive log ingest waiter: {e}"))?
            .map_err(|e| format!("receive log ingest waiter dropped: {e}"))?;
        ingested = ingested.saturating_add(result?);
    }
    Ok(ingested)
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
                if let Some((priority_idx, _)) = inner
                    .pending
                    .iter()
                    .enumerate()
                    .filter(|(_, job)| job.priority)
                    .min_by_key(|(_, job)| {
                        (
                            job.priority_segment_ordinal.unwrap_or(u64::MAX),
                            Reverse(job.enqueue_seq),
                        )
                    })
                {
                    break inner.pending.remove(priority_idx);
                }
                if inner.active_hot_receives == 0 {
                    break inner.pending.pop_front();
                }
                debug!(
                    target: "topo::sync_operation",
                    db_path = %db_path,
                    pending_receive_logs = inner.pending.len(),
                    active_hot_receives = inner.active_hot_receives,
                    "receive log ingest waiting for active hot receives"
                );
                inner = state
                    .wake
                    .wait(inner)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
        };

        let Some(path) = next_path else {
            continue;
        };
        debug!(
            target: "topo::sync_operation",
            db_path = %db_path,
            path = %path.path.display(),
            priority = path.priority,
            "receive log ingest starting"
        );
        let result = ingest_receive_log(&db_path, &path.path);
        if let Some(pending_overlay) = &path.pending_overlay {
            clear_pending_receive_overlay_session(pending_overlay);
        }
        if let Some(completion) = path.completion {
            let _ = completion.send(result);
            continue;
        }
        match result {
            Err(e) => {
                tracing::warn!(
                    "background receive log ingest {}: {}",
                    path.path.display(),
                    e
                );
            }
            Ok(ingested) => {
                debug!(
                    target: "topo::sync_operation",
                    db_path = %db_path,
                    path = %path.path.display(),
                    priority = path.priority,
                    ingested,
                    "receive log ingest finished"
                );
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiveLogRecord {
    event_id: EventId,
    blob: Vec<u8>,
    received_at_ms: i64,
    first_stored_at_ms: i64,
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

    pub fn append_blob(&mut self, event_id: &EventId, blob: &[u8]) -> Result<(), String> {
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
            .write_all(event_id)
            .map_err(|e| format!("append receive log {}: {e}", self.path.display()))?;
        self.file
            .write_all(blob)
            .map_err(|e| format!("append receive log {}: {e}", self.path.display()))?;
        let first_stored_at_ms = current_timestamp_ms();
        self.file
            .write_all(&first_stored_at_ms.to_le_bytes())
            .map_err(|e| format!("append receive log {}: {e}", self.path.display()))?;
        self.bytes_written = self.bytes_written.saturating_add(
            (RECEIVE_LOG_RECORD_WITH_EVENT_ID_PREFIX_LEN
                + blob.len()
                + RECEIVE_LOG_RECORD_SUFFIX_LEN) as u64,
        );
        Ok(())
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
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
    let (mut file, header) = open_receive_log(path)?;
    let mut ingested = 0usize;
    let mut batch = Vec::<IngestItem>::with_capacity(RECEIVE_LOG_INGEST_BATCH_CAP);
    let mut batch_bytes = 0usize;

    stream_receive_log(&mut file, path, |record| {
        batch_bytes = batch_bytes.saturating_add(record.blob.len());
        batch.push((
            record.event_id,
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

pub fn next_pending_receive_overlay_session_id() -> u64 {
    static NEXT_PENDING_OVERLAY_NONCE: AtomicU64 = AtomicU64::new(1);
    NEXT_PENDING_OVERLAY_NONCE.fetch_add(1, Ordering::Relaxed)
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
    let header = read_receive_log_header(&mut file, path)?;
    Ok((file, header))
}

fn read_receive_log_header(file: &mut File, path: &Path) -> Result<ReceiveLogHeader, String> {
    let mut prefix = [0u8; RECEIVE_LOG_HEADER_PREFIX_LEN];
    file.read_exact(&mut prefix)
        .map_err(|e| format!("read receive log header {}: {e}", path.display()))?;

    if &prefix[..4] != RECEIVE_LOG_HEADER_MAGIC {
        return Err(format!(
            "receive log {} has unsupported header magic",
            path.display()
        ));
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
    Ok(header)
}

fn stream_receive_log<F>(file: &mut File, path: &Path, mut on_record: F) -> Result<usize, String>
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

fn parse_next_record(
    buffer: &[u8],
    offset: &mut usize,
) -> Result<Option<ReceiveLogRecord>, String> {
    if *offset >= buffer.len() {
        return Ok(None);
    }
    if buffer.len() - *offset < RECEIVE_LOG_RECORD_WITH_EVENT_ID_PREFIX_LEN {
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
    let event_id_start = *offset + RECEIVE_LOG_RECORD_PREFIX_LEN;
    let event_id_end = event_id_start + RECEIVE_LOG_RECORD_EVENT_ID_LEN;
    let record_len = RECEIVE_LOG_RECORD_WITH_EVENT_ID_PREFIX_LEN
        .saturating_add(blob_len)
        .saturating_add(RECEIVE_LOG_RECORD_SUFFIX_LEN);
    if buffer.len() - *offset < record_len {
        return Ok(None);
    }

    let blob_start = *offset + RECEIVE_LOG_RECORD_WITH_EVENT_ID_PREFIX_LEN;
    let blob_end = blob_start + blob_len;
    let first_stored_at_ms = i64::from_le_bytes(
        buffer[blob_end..blob_end + RECEIVE_LOG_RECORD_SUFFIX_LEN]
            .try_into()
            .map_err(|_| "receive log record stored_at truncated".to_string())?,
    );
    let mut event_id = [0u8; RECEIVE_LOG_RECORD_EVENT_ID_LEN];
    event_id.copy_from_slice(&buffer[event_id_start..event_id_end]);
    let blob = buffer[blob_start..blob_end].to_vec();
    *offset += record_len;
    Ok(Some(ReceiveLogRecord {
        event_id,
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

    fn write_record(
        file: &mut File,
        event_id: &EventId,
        blob: &[u8],
        received_at_ms: i64,
        first_stored_at_ms: i64,
    ) {
        let blob_len = u32::try_from(blob.len()).unwrap();
        file.write_all(&received_at_ms.to_le_bytes()).unwrap();
        file.write_all(&blob_len.to_le_bytes()).unwrap();
        file.write_all(event_id).unwrap();
        file.write_all(blob).unwrap();
        file.write_all(&first_stored_at_ms.to_le_bytes()).unwrap();
    }

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
        let first_id = hash_event(b"one");
        let second_id = hash_event(b"two");
        writer.append_blob(&first_id, b"one").unwrap();
        writer.append_blob(&second_id, b"two").unwrap();
        let path = writer.finish().unwrap().unwrap();

        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&[0x03, 0x08, 0x00]).unwrap();
        }

        let mut blobs = Vec::new();
        let mut event_ids = Vec::new();
        let (mut file, _header) = open_receive_log(&path).unwrap();
        let parsed = stream_receive_log(&mut file, &path, |record| {
            event_ids.push(record.event_id);
            blobs.push(record.blob);
            Ok(())
        })
        .unwrap();
        assert_eq!(parsed, 2);
        assert_eq!(blobs, vec![b"one".to_vec(), b"two".to_vec()]);
        assert_eq!(event_ids, vec![first_id, second_id]);

        let (_file, header) = open_receive_log(&path).unwrap();
        assert_eq!(header.recorded_by, "tenant-a");
        assert_eq!(header.session_id, 7);
        assert_eq!(header.source_tag, "quic_recv:peer-x@127.0.0.1:7777");
    }

    #[test]
    fn receive_log_rejects_unsupported_header_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unsupported-version.bin");
        let header = ReceiveLogHeader {
            recorded_by: "tenant-a".to_string(),
            session_id: 17,
            source_tag: "peer-x".to_string(),
        };

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .unwrap();
        let payload = serde_json::to_vec(&header).unwrap();
        file.write_all(RECEIVE_LOG_HEADER_MAGIC).unwrap();
        file.write_all(&[1]).unwrap();
        file.write_all(&(payload.len() as u32).to_le_bytes())
            .unwrap();
        file.write_all(&payload).unwrap();
        drop(file);

        let error = open_receive_log(&path).unwrap_err();
        assert!(
            error.contains("unsupported receive log header version 1"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn receive_log_ingest_uses_stored_event_id_from_headered_records() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let log_dir = receive_log_dir(db_path.to_str().unwrap());
        std::fs::create_dir_all(&log_dir).unwrap();
        let path = log_dir.join("manual-v2.bin");
        let header = ReceiveLogHeader {
            recorded_by: "tenant-a".to_string(),
            session_id: 27,
            source_tag: "peer-x".to_string(),
        };
        let blob = b"stored-id-is-authoritative".to_vec();
        let hashed_id = hash_event(&blob);
        let stored_id = [0x5Au8; 32];

        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&path)
            .unwrap();
        write_receive_log_header(&mut file, &header).unwrap();
        write_record(&mut file, &stored_id, &blob, 31, 32);
        drop(file);

        ingest_receive_log(db_path.to_str().unwrap(), &path).unwrap();

        let timeline = EventTimeline::new(&conn);
        assert!(
            timeline
                .load(&event_id_to_base64(&stored_id))
                .unwrap()
                .is_some(),
            "ingest should trust stored event ids from receive logs"
        );
        assert!(
            timeline
                .load(&event_id_to_base64(&hashed_id))
                .unwrap()
                .is_none(),
            "ingest should not re-hash blobs when replaying receive logs"
        );
    }

    #[test]
    fn receive_log_ingest_replays_first_store_time() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let blob = b"hello world".to_vec();
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let mut writer =
            ReceiveLogWriter::open(db_path.to_str().unwrap(), "tenant-a", 8, "peer-x").unwrap();
        writer.append_blob(&event_id, &blob).unwrap();
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
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let mut writer =
            ReceiveLogWriter::open(db_path.to_str().unwrap(), "tenant-a", 9, "peer-x").unwrap();
        writer.append_blob(&event_id, &blob).unwrap();
        let path = writer.finish().unwrap().unwrap();

        note_hot_receive_started(db_path.to_str().unwrap());
        enqueue_receive_log_ingest(db_path.to_str().unwrap(), path.clone(), false);
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

    #[test]
    fn background_ingest_processes_priority_logs_during_active_hot_receives() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let blob = b"hot receive should not starve".to_vec();
        let event_id = hash_event(&blob);
        let event_id_b64 = event_id_to_base64(&event_id);
        let mut writer =
            ReceiveLogWriter::open(db_path.to_str().unwrap(), "tenant-a", 10, "peer-x").unwrap();
        writer.append_blob(&event_id, &blob).unwrap();
        let path = writer.finish().unwrap().unwrap();

        note_hot_receive_started(db_path.to_str().unwrap());
        enqueue_receive_log_ingest(db_path.to_str().unwrap(), path.clone(), true);

        let timeline = EventTimeline::new(&conn);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if timeline.load(&event_id_b64).unwrap().is_some() && !path.exists() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "priority receive log did not ingest while hot receives stayed active"
            );
            std::thread::sleep(Duration::from_millis(25));
        }

        note_hot_receive_finished(db_path.to_str().unwrap());
    }

    #[test]
    fn background_ingest_prefers_newest_priority_logs_during_active_hot_receives() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let older_blob = vec![0x41; 8 * 1024];
        let mut older_writer =
            ReceiveLogWriter::open(db_path.to_str().unwrap(), "tenant-a", 11, "peer-x").unwrap();
        for idx in 0..2048u32 {
            let mut blob = older_blob.clone();
            blob[..4].copy_from_slice(&idx.to_le_bytes());
            let event_id = hash_event(&blob);
            older_writer.append_blob(&event_id, &blob).unwrap();
        }
        let older_path = older_writer.finish().unwrap().unwrap();

        let newer_blob = b"newer-priority-log".to_vec();
        let newer_event_id = hash_event(&newer_blob);
        let newer_event_id_b64 = event_id_to_base64(&newer_event_id);
        let mut newer_writer =
            ReceiveLogWriter::open(db_path.to_str().unwrap(), "tenant-a", 12, "peer-x").unwrap();
        newer_writer
            .append_blob(&newer_event_id, &newer_blob)
            .unwrap();
        let newer_path = newer_writer.finish().unwrap().unwrap();

        note_hot_receive_started(db_path.to_str().unwrap());
        enqueue_receive_log_ingest(db_path.to_str().unwrap(), older_path.clone(), true);
        enqueue_receive_log_ingest(db_path.to_str().unwrap(), newer_path.clone(), true);

        let timeline = EventTimeline::new(&conn);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if timeline.load(&newer_event_id_b64).unwrap().is_some() && !newer_path.exists() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "newest priority receive log did not ingest first"
            );
            std::thread::sleep(Duration::from_millis(25));
        }

        assert!(
            older_path.exists(),
            "older priority receive log should still be waiting while a hot receive is active"
        );

        note_hot_receive_finished(db_path.to_str().unwrap());

        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if !older_path.exists() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "older priority receive log did not ingest after hot receives finished"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn peer_session_ingest_guard_serializes_same_peer() {
        let first = acquire_peer_session_ingest_guard("/tmp/peer-gate-a", "peer-a")
            .await
            .unwrap();

        let other_peer = tokio::time::timeout(
            Duration::from_millis(100),
            acquire_peer_session_ingest_guard("/tmp/peer-gate-a", "peer-b"),
        )
        .await
        .expect("different peer should not block")
        .unwrap();
        drop(other_peer);

        let waiting = tokio::spawn(async {
            acquire_peer_session_ingest_guard("/tmp/peer-gate-a", "peer-a").await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !waiting.is_finished(),
            "same peer should stay blocked until the previous session releases its ingest guard"
        );

        drop(first);

        let second = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("same peer should unblock after release")
            .expect("join waiting peer ingest guard task")
            .expect("acquire same peer ingest guard");
        drop(second);
    }
}
