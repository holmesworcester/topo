use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use negentropy::{Id, NegentropyStorageVector};
use rusqlite::Connection;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::store::{Store, SHARED_PRIORITY_LANE_AUTH, SHARED_PRIORITY_LANE_KEY};
use crate::protocol::{neg_id_to_event_id, Frame};
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::receive_log::ReceiveLogWriter;
use crate::sync::session::windowing::{SyncWindow, SyncWindowKind};
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};
use crate::tuning::{
    live_suppression_event_id_cap, live_suppression_mode, live_suppression_send_batch_size,
    low_mem_mode,
};

const RANGE_DATA_RECORD_PREFIX_LEN: usize = 4;
const LIVE_SUPPRESSION_PREFETCH_IDS: usize = 32;
const LOW_MEM_LIVE_SUPPRESSION_PREFETCH_IDS: usize = 8;

pub struct RangeReceiveResult {
    pub events_received: u64,
    pub bytes_received: u64,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LiveSuppressionCohortKey {
    db_path: String,
    recorded_by: String,
    window_kind: SyncWindowKind,
}

struct LiveSuppressionRegistration {
    key: LiveSuppressionCohortKey,
    session_id: u64,
}

pub struct LiveSuppressionSession {
    _registration: LiveSuppressionRegistration,
    outbound_suppression_rx: UnboundedReceiver<EventId>,
    inbound_suppression_rx: UnboundedReceiver<Vec<EventId>>,
    remote_done_rx: UnboundedReceiver<()>,
}

pub struct LiveSuppressionReceiveState {
    key: LiveSuppressionCohortKey,
    session_id: u64,
    inbound_suppression_tx: UnboundedSender<Vec<EventId>>,
    remote_done_tx: UnboundedSender<()>,
    remote_done_notified: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharedIndexLoadPlan {
    PriorityLane(&'static str),
    TimeWindow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharedSendOrderPolicy {
    PreserveInput,
    OldestFirst,
    NewestFirst,
}

fn decide_shared_index_load_plan(kind: SyncWindowKind) -> SharedIndexLoadPlan {
    match kind {
        SyncWindowKind::AuthGraph => SharedIndexLoadPlan::PriorityLane(SHARED_PRIORITY_LANE_AUTH),
        SyncWindowKind::KeyGraph => SharedIndexLoadPlan::PriorityLane(SHARED_PRIORITY_LANE_KEY),
        SyncWindowKind::Full
        | SyncWindowKind::LastDay
        | SyncWindowKind::LastWeek
        | SyncWindowKind::LastTwelveWeeks => SharedIndexLoadPlan::TimeWindow,
    }
}

fn decide_shared_send_order_policy(kind: SyncWindowKind) -> SharedSendOrderPolicy {
    match kind {
        SyncWindowKind::AuthGraph => SharedSendOrderPolicy::OldestFirst,
        SyncWindowKind::KeyGraph | SyncWindowKind::LastDay => SharedSendOrderPolicy::NewestFirst,
        SyncWindowKind::Full | SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks => {
            SharedSendOrderPolicy::PreserveInput
        }
    }
}

fn load_shared_index_entries(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<Vec<(i64, EventId)>, String> {
    let mut entries = Vec::new();

    match decide_shared_index_load_plan(range.kind) {
        SharedIndexLoadPlan::PriorityLane(lane) => {
            let mut stmt = conn
                .prepare(
                    "SELECT ts, id
                     FROM shared_priority_event_index
                     WHERE workspace_id = ?1
                       AND lane = ?2
                     ORDER BY ts, id",
                )
                .map_err(|e| format!("prepare shared priority index query: {e}"))?;
            let mut rows = stmt
                .query(rusqlite::params![workspace_id, lane])
                .map_err(|e| format!("query shared priority index rows: {e}"))?;
            while let Some(row) = rows
                .next()
                .map_err(|e| format!("iterate shared priority index rows: {e}"))?
            {
                let ts: i64 = row
                    .get(0)
                    .map_err(|e| format!("read shared priority index ts: {e}"))?;
                let id_blob: Vec<u8> = row
                    .get(1)
                    .map_err(|e| format!("read shared priority index id: {e}"))?;
                if id_blob.len() != 32 {
                    continue;
                }
                let mut event_id = [0u8; 32];
                event_id.copy_from_slice(&id_blob);
                entries.push((ts, event_id));
            }
        }
        SharedIndexLoadPlan::TimeWindow => {
            let mut stmt = conn
                .prepare(
                    "SELECT ts, id
                     FROM shared_event_index
                     WHERE workspace_id = ?1
                       AND (?2 IS NULL OR ts >= ?2)
                       AND (?3 IS NULL OR ts < ?3)
                     ORDER BY ts, id",
                )
                .map_err(|e| format!("prepare shared index query: {e}"))?;
            let mut rows = stmt
                .query(rusqlite::params![
                    workspace_id,
                    range.ts_min(),
                    range.ts_max_exclusive()
                ])
                .map_err(|e| format!("query shared index rows: {e}"))?;
            while let Some(row) = rows
                .next()
                .map_err(|e| format!("iterate shared index rows: {e}"))?
            {
                let ts: i64 = row
                    .get(0)
                    .map_err(|e| format!("read shared index ts: {e}"))?;
                let id_blob: Vec<u8> = row
                    .get(1)
                    .map_err(|e| format!("read shared index id: {e}"))?;
                if id_blob.len() != 32 {
                    continue;
                }
                let mut event_id = [0u8; 32];
                event_id.copy_from_slice(&id_blob);
                entries.push((ts, event_id));
            }
        }
    }
    Ok(entries)
}

pub fn load_shared_event_index_slice(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<NegentropyStorageVector, String> {
    let mut storage = NegentropyStorageVector::new();
    for (ts, event_id) in load_shared_index_entries(conn, workspace_id, range)? {
        storage
            .insert(ts.max(0) as u64, Id::from_byte_array(event_id))
            .map_err(|e| format!("insert negentropy vector item: {e}"))?;
    }
    storage
        .seal()
        .map_err(|e| format!("seal negentropy vector storage: {e}"))?;
    Ok(storage)
}

pub fn load_shared_send_batch(
    store: &Store<'_>,
    ids: &[EventId],
) -> Result<Vec<(EventId, Vec<u8>)>, String> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }

    let base_blobs = store
        .get_shared_batch(ids)
        .map_err(|e| format!("load shared batch: {e}"))?;
    let mut ordered = Vec::with_capacity(ids.len());

    for event_id in ids {
        let Some(blob) = base_blobs.get(event_id) else {
            continue;
        };
        ordered.push((*event_id, blob.clone()));
    }

    Ok(ordered)
}

fn prioritize_send_order(
    store: &Store<'_>,
    range: SyncWindow,
    ids: &[EventId],
) -> Result<Vec<EventId>, String> {
    let order_policy = decide_shared_send_order_policy(range.kind);
    if matches!(order_policy, SharedSendOrderPolicy::PreserveInput) {
        return Ok(ids.to_vec());
    }

    let created_at_by_id = store
        .get_shared_created_at_batch(ids)
        .map_err(|e| format!("load shared created_at batch: {e}"))?;
    let mut ordered: Vec<EventId> = ids
        .iter()
        .filter(|event_id| created_at_by_id.contains_key(*event_id))
        .copied()
        .collect();
    ordered.sort_by(|left, right| {
        let left_ts = created_at_by_id.get(left).copied().unwrap_or_default();
        let right_ts = created_at_by_id.get(right).copied().unwrap_or_default();
        match order_policy {
            SharedSendOrderPolicy::OldestFirst => {
                left_ts.cmp(&right_ts).then_with(|| left.cmp(right))
            }
            SharedSendOrderPolicy::NewestFirst => {
                right_ts.cmp(&left_ts).then_with(|| right.cmp(left))
            }
            SharedSendOrderPolicy::PreserveInput => left.cmp(right),
        }
    });
    Ok(ordered)
}

fn live_suppression_registry(
) -> &'static Mutex<HashMap<LiveSuppressionCohortKey, HashMap<u64, UnboundedSender<EventId>>>> {
    static REGISTRY: OnceLock<
        Mutex<HashMap<LiveSuppressionCohortKey, HashMap<u64, UnboundedSender<EventId>>>>,
    > = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn live_suppression_key(
    db_path: &str,
    recorded_by: &str,
    range: SyncWindow,
) -> LiveSuppressionCohortKey {
    LiveSuppressionCohortKey {
        db_path: db_path.to_string(),
        recorded_by: recorded_by.to_string(),
        window_kind: range.kind,
    }
}

impl Drop for LiveSuppressionRegistration {
    fn drop(&mut self) {
        let mut registry = live_suppression_registry()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(sessions) = registry.get_mut(&self.key) {
            sessions.remove(&self.session_id);
            if sessions.is_empty() {
                registry.remove(&self.key);
            }
        }
    }
}

pub fn open_live_suppression_session(
    db_path: &str,
    recorded_by: &str,
    range: SyncWindow,
    session_id: u64,
) -> Option<(LiveSuppressionSession, LiveSuppressionReceiveState)> {
    if !live_suppression_mode() {
        return None;
    }

    let key = live_suppression_key(db_path, recorded_by, range);
    let (outbound_suppression_tx, outbound_suppression_rx) = mpsc::unbounded_channel();
    live_suppression_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry(key.clone())
        .or_default()
        .insert(session_id, outbound_suppression_tx);

    let (inbound_suppression_tx, inbound_suppression_rx) = mpsc::unbounded_channel();
    let (remote_done_tx, remote_done_rx) = mpsc::unbounded_channel();
    Some((
        LiveSuppressionSession {
            _registration: LiveSuppressionRegistration {
                key: key.clone(),
                session_id,
            },
            outbound_suppression_rx,
            inbound_suppression_rx,
            remote_done_rx,
        },
        LiveSuppressionReceiveState {
            key,
            session_id,
            inbound_suppression_tx,
            remote_done_tx,
            remote_done_notified: false,
        },
    ))
}

fn publish_live_suppression_event(
    key: &LiveSuppressionCohortKey,
    origin_session_id: u64,
    event_id: EventId,
) {
    let mut registry = live_suppression_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut stale_sessions = Vec::new();
    if let Some(sessions) = registry.get_mut(key) {
        for (session_id, tx) in sessions.iter() {
            if *session_id == origin_session_id {
                continue;
            }
            if tx.send(event_id).is_err() {
                stale_sessions.push(*session_id);
            }
        }
        for session_id in stale_sessions {
            sessions.remove(&session_id);
        }
        if sessions.is_empty() {
            registry.remove(key);
        }
    }
}

fn live_suppression_prefetch_ids() -> usize {
    if low_mem_mode() {
        LOW_MEM_LIVE_SUPPRESSION_PREFETCH_IDS
    } else {
        LIVE_SUPPRESSION_PREFETCH_IDS
    }
}

fn enqueue_remote_suppressions(ids: &[EventId], suppressed_ids: &mut HashSet<EventId>, cap: usize) {
    for event_id in ids {
        if suppressed_ids.len() >= cap && !suppressed_ids.contains(event_id) {
            break;
        }
        suppressed_ids.insert(*event_id);
    }
}

fn drain_remote_suppression_rx(
    rx: &mut UnboundedReceiver<Vec<EventId>>,
    suppressed_ids: &mut HashSet<EventId>,
    cap: usize,
) {
    while let Ok(ids) = rx.try_recv() {
        enqueue_remote_suppressions(&ids, suppressed_ids, cap);
    }
}

fn enqueue_outbound_suppression(
    event_id: EventId,
    outbound_pending: &mut VecDeque<EventId>,
    outbound_known: &mut HashSet<EventId>,
    cap: usize,
) {
    if outbound_known.len() >= cap && !outbound_known.contains(&event_id) {
        return;
    }
    if outbound_known.insert(event_id) {
        outbound_pending.push_back(event_id);
    }
}

fn drain_outbound_suppression_rx(
    rx: &mut UnboundedReceiver<EventId>,
    outbound_pending: &mut VecDeque<EventId>,
    outbound_known: &mut HashSet<EventId>,
    cap: usize,
) {
    while let Ok(event_id) = rx.try_recv() {
        enqueue_outbound_suppression(event_id, outbound_pending, outbound_known, cap);
    }
}

fn maybe_note_remote_done(state: &mut Option<LiveSuppressionReceiveState>) {
    let Some(state) = state.as_mut() else {
        return;
    };
    if state.remote_done_notified {
        return;
    }
    let _ = state.remote_done_tx.send(());
    state.remote_done_notified = true;
}

fn refill_live_send_queue(
    store: &Store<'_>,
    ordered_ids: &[EventId],
    next_idx: &mut usize,
    suppressed_ids: &HashSet<EventId>,
    send_queue: &mut VecDeque<(EventId, Vec<u8>)>,
) -> Result<(), String> {
    let prefetch = live_suppression_prefetch_ids();
    while send_queue.len() < prefetch && *next_idx < ordered_ids.len() {
        let remaining = prefetch.saturating_sub(send_queue.len()).max(1);
        let mut refill_ids = Vec::with_capacity(remaining);
        while refill_ids.len() < remaining && *next_idx < ordered_ids.len() {
            let event_id = ordered_ids[*next_idx];
            *next_idx += 1;
            if suppressed_ids.contains(&event_id) {
                continue;
            }
            refill_ids.push(event_id);
        }
        if refill_ids.is_empty() {
            break;
        }
        for (event_id, blob) in load_shared_send_batch(store, &refill_ids)? {
            if !suppressed_ids.contains(&event_id) {
                send_queue.push_back((event_id, blob));
            }
        }
    }
    Ok(())
}

async fn send_have_events_live<S>(
    store: &Store<'_>,
    data_send: &mut S,
    have_ids: &[Id],
    range: SyncWindow,
    live_suppression: &mut LiveSuppressionSession,
) -> Result<(u64, u64), String>
where
    S: StreamSend,
{
    let cap = live_suppression_event_id_cap();
    let suppression_batch_size = live_suppression_send_batch_size();
    let mut events_sent = 0u64;
    let mut bytes_sent = 0u64;
    let event_ids: Vec<EventId> = have_ids.iter().map(neg_id_to_event_id).collect();
    let ordered_ids = prioritize_send_order(store, range, &event_ids)?;
    let mut next_idx = 0usize;
    let mut send_queue = VecDeque::<(EventId, Vec<u8>)>::new();
    let mut suppressed_ids = HashSet::<EventId>::new();
    let mut outbound_known = HashSet::<EventId>::new();
    let mut outbound_pending = VecDeque::<EventId>::new();
    let mut local_done_sent = false;
    let mut remote_done = false;

    loop {
        drain_outbound_suppression_rx(
            &mut live_suppression.outbound_suppression_rx,
            &mut outbound_pending,
            &mut outbound_known,
            cap,
        );
        drain_remote_suppression_rx(
            &mut live_suppression.inbound_suppression_rx,
            &mut suppressed_ids,
            cap,
        );
        while live_suppression.remote_done_rx.try_recv().is_ok() {
            remote_done = true;
        }
        while matches!(
            send_queue.front(),
            Some((event_id, _)) if suppressed_ids.contains(event_id)
        ) {
            send_queue.pop_front();
        }
        refill_live_send_queue(
            store,
            &ordered_ids,
            &mut next_idx,
            &suppressed_ids,
            &mut send_queue,
        )?;
        while matches!(
            send_queue.front(),
            Some((event_id, _)) if suppressed_ids.contains(event_id)
        ) {
            send_queue.pop_front();
        }

        if !outbound_pending.is_empty() {
            let mut ids = Vec::with_capacity(suppression_batch_size);
            while ids.len() < suppression_batch_size {
                let Some(event_id) = outbound_pending.pop_front() else {
                    break;
                };
                ids.push(event_id);
            }
            if !ids.is_empty() {
                data_send
                    .send(&Frame::SuppressIds { ids })
                    .await
                    .map_err(|e| format!("send suppression frame: {e}"))?;
                continue;
            }
        }

        if let Some((event_id, blob)) = send_queue.pop_front() {
            if suppressed_ids.contains(&event_id) {
                continue;
            }
            bytes_sent += blob.len() as u64;
            events_sent += 1;
            data_send
                .send(&Frame::Event { blob })
                .await
                .map_err(|e| format!("send range event frame: {e}"))?;
            continue;
        }

        if !local_done_sent {
            data_send
                .send(&Frame::RangeDataDone)
                .await
                .map_err(|e| format!("send range data done: {e}"))?;
            local_done_sent = true;
            if remote_done {
                break;
            }
            continue;
        }

        if remote_done {
            break;
        }

        tokio::select! {
            maybe_event_id = live_suppression.outbound_suppression_rx.recv() => {
                if let Some(event_id) = maybe_event_id {
                    enqueue_outbound_suppression(event_id, &mut outbound_pending, &mut outbound_known, cap);
                }
            }
            maybe_ids = live_suppression.inbound_suppression_rx.recv() => {
                if let Some(ids) = maybe_ids {
                    enqueue_remote_suppressions(&ids, &mut suppressed_ids, cap);
                }
            }
            maybe_done = live_suppression.remote_done_rx.recv() => {
                if maybe_done.is_some() {
                    remote_done = true;
                }
            }
        }
    }

    data_send
        .flush()
        .await
        .map_err(|e| format!("flush range data stream: {e}"))?;
    Ok((events_sent, bytes_sent))
}

pub async fn send_have_events<S>(
    store: &Store<'_>,
    data_send: &mut S,
    have_ids: &[Id],
    range: SyncWindow,
    live_suppression: Option<&mut LiveSuppressionSession>,
) -> Result<(u64, u64), String>
where
    S: StreamSend,
{
    if let Some(live_suppression) = live_suppression {
        return send_have_events_live(store, data_send, have_ids, range, live_suppression).await;
    }

    if have_ids.is_empty() {
        return Ok((0, 0));
    }

    let mut events_sent = 0u64;
    let mut bytes_sent = 0u64;
    let event_ids: Vec<EventId> = have_ids.iter().map(neg_id_to_event_id).collect();
    let event_ids = prioritize_send_order(store, range, &event_ids)?;
    for chunk in event_ids.chunks(64) {
        let ordered = load_shared_send_batch(store, chunk)?;
        let mut payload = Vec::new();
        for (_event_id, blob) in ordered {
            let blob_len = u32::try_from(blob.len())
                .map_err(|_| format!("range event too large: {} bytes", blob.len()))?;
            payload.extend_from_slice(&blob_len.to_le_bytes());
            payload.extend_from_slice(&blob);
            events_sent += 1;
            bytes_sent += blob.len() as u64;
        }
        if payload.is_empty() {
            continue;
        }
        data_send
            .send_bytes(&payload)
            .await
            .map_err(|e| format!("send range data chunk: {e}"))?;
    }
    data_send
        .flush()
        .await
        .map_err(|e| format!("flush range data stream: {e}"))?;
    Ok((events_sent, bytes_sent))
}

fn parse_next_blob_record(buffer: &[u8], offset: &mut usize) -> Result<Option<Vec<u8>>, String> {
    if *offset >= buffer.len() {
        return Ok(None);
    }
    if buffer.len() - *offset < RANGE_DATA_RECORD_PREFIX_LEN {
        return Ok(None);
    }
    let blob_len = u32::from_le_bytes(
        buffer[*offset..*offset + RANGE_DATA_RECORD_PREFIX_LEN]
            .try_into()
            .map_err(|_| "range data record length truncated".to_string())?,
    ) as usize;
    let record_len = RANGE_DATA_RECORD_PREFIX_LEN.saturating_add(blob_len);
    if buffer.len() - *offset < record_len {
        return Ok(None);
    }
    let blob_start = *offset + RANGE_DATA_RECORD_PREFIX_LEN;
    let blob_end = blob_start + blob_len;
    let blob = buffer[blob_start..blob_end].to_vec();
    *offset += record_len;
    Ok(Some(blob))
}

pub fn spawn_receive_log_task<R>(
    data_recv: R,
    db_path: String,
    recorded_by: String,
    session_id: u64,
    source_tag: String,
    idle_timeout: Duration,
    rx_capture: Option<SyncRunRxCapture>,
    live_suppression: Option<LiveSuppressionReceiveState>,
) -> tokio::task::JoinHandle<Result<RangeReceiveResult, String>>
where
    R: StreamRecv + Send + 'static,
{
    tokio::spawn(async move {
        let mut data_recv = data_recv;
        let mut writer = ReceiveLogWriter::open(&db_path, &recorded_by, session_id, &source_tag)?;
        let mut events_received = 0u64;
        let mut bytes_received = 0u64;
        let mut live_suppression = live_suppression;

        if live_suppression.is_some() {
            loop {
                let next = tokio::time::timeout(idle_timeout, data_recv.recv()).await;
                match next {
                    Ok(Ok(Frame::Event { blob })) => {
                        let event_id = hash_event(&blob);
                        if let Some(capture) = &rx_capture {
                            capture.record_event_id_b64(event_id_to_base64(&event_id));
                        }
                        if let Some(state) = &live_suppression {
                            publish_live_suppression_event(&state.key, state.session_id, event_id);
                        }
                        bytes_received += blob.len() as u64;
                        events_received += 1;
                        writer.append_blob(&blob)?;
                    }
                    Ok(Ok(Frame::SuppressIds { ids })) => {
                        if let Some(state) = &live_suppression {
                            let _ = state.inbound_suppression_tx.send(ids);
                        }
                    }
                    Ok(Ok(Frame::RangeDataDone)) => {
                        maybe_note_remote_done(&mut live_suppression);
                    }
                    Ok(Ok(_)) => {}
                    Ok(Err(ConnectionError::Closed)) | Ok(Err(_)) | Err(_) => {
                        maybe_note_remote_done(&mut live_suppression);
                        break;
                    }
                }
            }
        } else {
            let mut buffer = Vec::<u8>::with_capacity(64 * 1024);
            loop {
                let next = tokio::time::timeout(idle_timeout, data_recv.recv_chunk()).await;
                match next {
                    Ok(Ok(chunk)) => {
                        buffer.extend_from_slice(&chunk);
                        let mut offset = 0usize;
                        while let Some(blob) = parse_next_blob_record(&buffer, &mut offset)? {
                            if let Some(capture) = &rx_capture {
                                capture.record_event_id_b64(event_id_to_base64(&hash_event(&blob)));
                            }
                            bytes_received += blob.len() as u64;
                            events_received += 1;
                            writer.append_blob(&blob)?;
                        }
                        if offset > 0 {
                            buffer.drain(..offset);
                        }
                    }
                    Ok(Err(ConnectionError::Closed)) => break,
                    Ok(Err(_)) => break,
                    Err(_) => break,
                }
            }
        }

        Ok(RangeReceiveResult {
            events_received,
            bytes_received,
            path: writer.finish()?,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use crate::crypto::hash_event;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::db::store::{insert_event, insert_shared_event_index_entry_if_shared};
    use crate::event_modules::{
        encode_event, endpoint_shared, registry::ShareScope, removal::frontier_hash_from_refs,
        KeyRotationEvent, MessageEvent, ParsedEvent, PeerSharedEvent, RemovalEvent,
    };
    use crate::transport::connection::ConnectionError;
    use async_trait::async_trait;

    struct EnvGuard {
        prev_live_suppression: Option<String>,
    }

    impl EnvGuard {
        fn enable_live_suppression() -> Self {
            let prev_live_suppression = std::env::var("TOPO_ENABLE_LIVE_SUPPRESSION").ok();
            std::env::set_var("TOPO_ENABLE_LIVE_SUPPRESSION", "1");
            Self {
                prev_live_suppression,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev_live_suppression {
                Some(v) => std::env::set_var("TOPO_ENABLE_LIVE_SUPPRESSION", v),
                None => std::env::remove_var("TOPO_ENABLE_LIVE_SUPPRESSION"),
            }
        }
    }

    #[derive(Default, Debug)]
    struct MockSendState {
        frames: Vec<Frame>,
        raw_bytes: Vec<Vec<u8>>,
        flushes: usize,
    }

    #[derive(Clone)]
    struct MockDataSend {
        state: Arc<Mutex<MockSendState>>,
    }

    impl MockDataSend {
        fn new() -> (Self, Arc<Mutex<MockSendState>>) {
            let state = Arc::new(Mutex::new(MockSendState::default()));
            (
                Self {
                    state: state.clone(),
                },
                state,
            )
        }
    }

    #[async_trait]
    impl StreamSend for MockDataSend {
        async fn send(&mut self, msg: &Frame) -> Result<(), ConnectionError> {
            self.state
                .lock()
                .expect("mock send lock")
                .frames
                .push(msg.clone());
            Ok(())
        }

        async fn send_bytes(&mut self, bytes: &[u8]) -> Result<(), ConnectionError> {
            self.state
                .lock()
                .expect("mock send lock")
                .raw_bytes
                .push(bytes.to_vec());
            Ok(())
        }

        async fn flush(&mut self) -> Result<(), ConnectionError> {
            self.state.lock().expect("mock send lock").flushes += 1;
            Ok(())
        }
    }

    struct MockDataRecv {
        frames: VecDeque<Result<Frame, ConnectionError>>,
    }

    impl MockDataRecv {
        fn with_frames(frames: Vec<Result<Frame, ConnectionError>>) -> Self {
            Self {
                frames: frames.into(),
            }
        }
    }

    #[async_trait]
    impl StreamRecv for MockDataRecv {
        async fn recv(&mut self) -> Result<Frame, ConnectionError> {
            self.frames
                .pop_front()
                .unwrap_or(Err(ConnectionError::Closed))
        }

        async fn recv_chunk(&mut self) -> Result<Vec<u8>, ConnectionError> {
            Err(ConnectionError::Closed)
        }
    }

    fn insert_shared_message(
        conn: &Connection,
        workspace_id: &[u8; 32],
        author_id: &[u8; 32],
        created_at_ms: i64,
        content: &str,
    ) -> (EventId, Vec<u8>) {
        let event = ParsedEvent::Message(MessageEvent {
            created_at_ms: created_at_ms as u64,
            workspace_id: *workspace_id,
            author_id: *author_id,
            content: content.to_string(),
        });
        let blob = encode_event(&event).unwrap();
        let event_id = hash_event(&blob);
        insert_event(
            conn,
            &event_id,
            "message",
            &blob,
            ShareScope::Shared,
            created_at_ms,
            created_at_ms,
        )
        .unwrap();
        (event_id, blob)
    }

    #[test]
    fn shared_send_batch_returns_requested_events_only() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let endpoint_event = endpoint_shared::deterministic_endpoint_shared_event([0x11; 32]);
        let endpoint_blob = encode_event(&endpoint_event).unwrap();
        let endpoint_event_id = hash_event(&endpoint_blob);
        insert_event(
            &conn,
            &endpoint_event_id,
            "endpoint_shared",
            &endpoint_blob,
            ShareScope::Shared,
            1,
            1,
        )
        .unwrap();

        let peer_shared_event = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: 2,
            public_key: [0x22; 32],
            user_event_id: [0x33; 32],
            endpoint_shared_event_id: endpoint_event_id,
            device_name: "device".to_string(),
        });
        let peer_shared_blob = encode_event(&peer_shared_event).unwrap();
        let peer_shared_event_id = hash_event(&peer_shared_blob);
        insert_event(
            &conn,
            &peer_shared_event_id,
            "peer_shared",
            &peer_shared_blob,
            ShareScope::Shared,
            2,
            2,
        )
        .unwrap();

        let store = Store::new(&conn);
        let ordered = load_shared_send_batch(&store, &[peer_shared_event_id]).unwrap();

        assert_eq!(ordered.len(), 1);
        assert_eq!(ordered[0].0, peer_shared_event_id);
    }

    #[test]
    fn shared_send_batch_preserves_requested_order_without_extra_deps() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let endpoint_event = endpoint_shared::deterministic_endpoint_shared_event([0x55; 32]);
        let endpoint_blob = encode_event(&endpoint_event).unwrap();
        let endpoint_event_id = hash_event(&endpoint_blob);
        insert_event(
            &conn,
            &endpoint_event_id,
            "endpoint_shared",
            &endpoint_blob,
            ShareScope::Shared,
            1,
            1,
        )
        .unwrap();

        let peer_shared_event = ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: 2,
            public_key: [0x66; 32],
            user_event_id: [0x77; 32],
            endpoint_shared_event_id: endpoint_event_id,
            device_name: "device".to_string(),
        });
        let peer_shared_blob = encode_event(&peer_shared_event).unwrap();
        let peer_shared_event_id = hash_event(&peer_shared_blob);
        insert_event(
            &conn,
            &peer_shared_event_id,
            "peer_shared",
            &peer_shared_blob,
            ShareScope::Shared,
            2,
            2,
        )
        .unwrap();

        let store = Store::new(&conn);
        let ordered =
            load_shared_send_batch(&store, &[endpoint_event_id, peer_shared_event_id]).unwrap();

        assert_eq!(ordered.len(), 2);
        assert_eq!(ordered[0].0, endpoint_event_id);
        assert_eq!(ordered[1].0, peer_shared_event_id);
    }

    #[test]
    fn priority_index_entries_split_auth_and_key_preflight_lanes() {
        assert_eq!(
            decide_shared_index_load_plan(SyncWindowKind::AuthGraph),
            SharedIndexLoadPlan::PriorityLane(SHARED_PRIORITY_LANE_AUTH)
        );
        assert_eq!(
            decide_shared_index_load_plan(SyncWindowKind::KeyGraph),
            SharedIndexLoadPlan::PriorityLane(SHARED_PRIORITY_LANE_KEY)
        );

        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "workspace-auth-key";

        let endpoint_event = endpoint_shared::deterministic_endpoint_shared_event([0x10; 32]);
        let endpoint_blob = encode_event(&endpoint_event).unwrap();
        let endpoint_event_id = hash_event(&endpoint_blob);
        insert_event(
            &conn,
            &endpoint_event_id,
            "endpoint_shared",
            &endpoint_blob,
            ShareScope::Shared,
            10,
            10,
        )
        .unwrap();
        insert_shared_event_index_entry_if_shared(
            &conn,
            ShareScope::Shared,
            10,
            &endpoint_event_id,
            workspace_id,
            &endpoint_blob,
        )
        .unwrap();

        let removal_event = ParsedEvent::Removal(RemovalEvent {
            created_at_ms: 15,
            removed_member_ref: [0x15; 32],
            parent_count: 0,
            parent_1: [0; 32],
            parent_2: [0; 32],
            parent_3: [0; 32],
            parent_4: [0; 32],
            frontier_hash: frontier_hash_from_refs(&[]),
            removed_by: [0x16; 32],
        });
        let removal_blob = encode_event(&removal_event).unwrap();
        let removal_event_id = hash_event(&removal_blob);
        insert_event(
            &conn,
            &removal_event_id,
            "removal",
            &removal_blob,
            ShareScope::Shared,
            15,
            15,
        )
        .unwrap();
        insert_shared_event_index_entry_if_shared(
            &conn,
            ShareScope::Shared,
            15,
            &removal_event_id,
            workspace_id,
            &removal_blob,
        )
        .unwrap();

        let key_rotation_event = ParsedEvent::KeyRotation(KeyRotationEvent {
            created_at_ms: 20,
            key_event_id: [0x20; 32],
            frontier_count: 0,
            frontier_ref_1: [0; 32],
            frontier_ref_2: [0; 32],
            frontier_ref_3: [0; 32],
            frontier_ref_4: [0; 32],
            frontier_hash: [0; 32],
            rotated_by: [0x21; 32],
        });
        let key_rotation_blob = encode_event(&key_rotation_event).unwrap();
        let key_rotation_event_id = hash_event(&key_rotation_blob);
        insert_event(
            &conn,
            &key_rotation_event_id,
            "key_rotation",
            &key_rotation_blob,
            ShareScope::Shared,
            20,
            20,
        )
        .unwrap();
        insert_shared_event_index_entry_if_shared(
            &conn,
            ShareScope::Shared,
            20,
            &key_rotation_event_id,
            workspace_id,
            &key_rotation_blob,
        )
        .unwrap();

        let message_event = ParsedEvent::Message(MessageEvent {
            created_at_ms: 30,
            workspace_id: [0x30; 32],
            author_id: [0x31; 32],
            content: "hello".to_string(),
        });
        let message_blob = encode_event(&message_event).unwrap();
        let message_event_id = hash_event(&message_blob);
        insert_event(
            &conn,
            &message_event_id,
            "message",
            &message_blob,
            ShareScope::Shared,
            30,
            30,
        )
        .unwrap();
        insert_shared_event_index_entry_if_shared(
            &conn,
            ShareScope::Shared,
            30,
            &message_event_id,
            workspace_id,
            &message_blob,
        )
        .unwrap();

        let auth_entries = load_shared_index_entries(
            &conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::AuthGraph,
                ts_min_inclusive_ms: None,
                ts_max_exclusive_ms: None,
            },
        )
        .unwrap();
        let key_entries = load_shared_index_entries(
            &conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::KeyGraph,
                ts_min_inclusive_ms: None,
                ts_max_exclusive_ms: None,
            },
        )
        .unwrap();

        assert_eq!(
            auth_entries,
            vec![(10, endpoint_event_id), (15, removal_event_id)]
        );
        assert_eq!(key_entries, vec![(20, key_rotation_event_id)]);
    }

    #[test]
    fn prioritize_send_order_matches_lane_policy() {
        assert_eq!(
            decide_shared_send_order_policy(SyncWindowKind::AuthGraph),
            SharedSendOrderPolicy::OldestFirst
        );
        assert_eq!(
            decide_shared_send_order_policy(SyncWindowKind::KeyGraph),
            SharedSendOrderPolicy::NewestFirst
        );
        assert_eq!(
            decide_shared_send_order_policy(SyncWindowKind::Full),
            SharedSendOrderPolicy::PreserveInput
        );

        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let first = ParsedEvent::Message(MessageEvent {
            created_at_ms: 10,
            workspace_id: [0x41; 32],
            author_id: [0x42; 32],
            content: "first".to_string(),
        });
        let second = ParsedEvent::Message(MessageEvent {
            created_at_ms: 20,
            workspace_id: [0x41; 32],
            author_id: [0x42; 32],
            content: "second".to_string(),
        });
        let first_blob = encode_event(&first).unwrap();
        let second_blob = encode_event(&second).unwrap();
        let first_id = hash_event(&first_blob);
        let second_id = hash_event(&second_blob);
        insert_event(
            &conn,
            &first_id,
            "message",
            &first_blob,
            ShareScope::Shared,
            10,
            10,
        )
        .unwrap();
        insert_event(
            &conn,
            &second_id,
            "message",
            &second_blob,
            ShareScope::Shared,
            20,
            20,
        )
        .unwrap();

        let store = Store::new(&conn);
        let auth_order = prioritize_send_order(
            &store,
            SyncWindow {
                kind: SyncWindowKind::AuthGraph,
                ts_min_inclusive_ms: None,
                ts_max_exclusive_ms: None,
            },
            &[second_id, first_id],
        )
        .unwrap();
        let key_order = prioritize_send_order(
            &store,
            SyncWindow {
                kind: SyncWindowKind::KeyGraph,
                ts_min_inclusive_ms: None,
                ts_max_exclusive_ms: None,
            },
            &[first_id, second_id],
        )
        .unwrap();
        let hot_order = prioritize_send_order(
            &store,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(0),
                ts_max_exclusive_ms: None,
            },
            &[first_id, second_id],
        )
        .unwrap();

        assert_eq!(auth_order, vec![first_id, second_id]);
        assert_eq!(key_order, vec![second_id, first_id]);
        assert_eq!(hot_order, vec![second_id, first_id]);
    }

    #[test]
    fn live_suppression_registry_drops_state_between_sessions() {
        let _env = EnvGuard::enable_live_suppression();
        let range = SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(10),
            ts_max_exclusive_ms: None,
        };
        let key = live_suppression_key("/tmp/live-suppress.db", "tenant-a", range);
        let (_session_a, _) =
            open_live_suppression_session("/tmp/live-suppress.db", "tenant-a", range, 1)
                .expect("open first suppression session");
        let (mut session_b, _) =
            open_live_suppression_session("/tmp/live-suppress.db", "tenant-a", range, 2)
                .expect("open second suppression session");

        publish_live_suppression_event(&key, 1, [0x44; 32]);
        assert_eq!(
            session_b
                .outbound_suppression_rx
                .try_recv()
                .expect("deliver live suppression"),
            [0x44; 32]
        );

        drop(session_b);
        drop(_session_a);

        let (mut session_c, _) =
            open_live_suppression_session("/tmp/live-suppress.db", "tenant-a", range, 3)
                .expect("open fresh suppression session");
        assert!(
            session_c.outbound_suppression_rx.try_recv().is_err(),
            "new session should not inherit stale suppressions"
        );
    }

    #[tokio::test]
    async fn live_suppression_sender_skips_unsent_ids_and_emits_suppressions() {
        let _env = EnvGuard::enable_live_suppression();
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = [0x51; 32];
        let author_id = [0x61; 32];
        let (first_id, first_blob) =
            insert_shared_message(&conn, &workspace_id, &author_id, 10, "first");
        let (second_id, _second_blob) =
            insert_shared_message(&conn, &workspace_id, &author_id, 20, "second");
        let (third_id, third_blob) =
            insert_shared_message(&conn, &workspace_id, &author_id, 30, "third");
        let store = Store::new(&conn);
        let range = SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(0),
            ts_max_exclusive_ms: None,
        };
        let have_ids = vec![
            Id::from_byte_array(first_id),
            Id::from_byte_array(second_id),
            Id::from_byte_array(third_id),
        ];
        let (mut live_suppression, receive_state) =
            open_live_suppression_session("/tmp/live-sender.db", "tenant-a", range, 11)
                .expect("open live suppression sender state");
        publish_live_suppression_event(&receive_state.key, 999, [0x88; 32]);
        receive_state
            .inbound_suppression_tx
            .send(vec![second_id])
            .expect("queue inbound remote suppression");
        receive_state
            .remote_done_tx
            .send(())
            .expect("queue remote done marker");

        let (mut data_send, send_state) = MockDataSend::new();
        let (events_sent, bytes_sent) = send_have_events(
            &store,
            &mut data_send,
            &have_ids,
            range,
            Some(&mut live_suppression),
        )
        .await
        .expect("send live suppression range");

        assert_eq!(events_sent, 2);
        assert_eq!(bytes_sent, (first_blob.len() + third_blob.len()) as u64);
        let send_state = send_state.lock().expect("mock send state");
        assert_eq!(send_state.raw_bytes.len(), 0);
        assert_eq!(send_state.flushes, 1);
        assert_eq!(
            send_state.frames,
            vec![
                Frame::SuppressIds {
                    ids: vec![[0x88; 32]]
                },
                Frame::Event { blob: third_blob },
                Frame::Event { blob: first_blob },
                Frame::RangeDataDone,
            ]
        );
    }

    #[tokio::test]
    async fn live_receive_task_publishes_events_and_forwards_remote_suppressions() {
        let _env = EnvGuard::enable_live_suppression();
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("node.db");
        std::fs::File::create(&db_path).unwrap();
        let range = SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(0),
            ts_max_exclusive_ms: None,
        };
        let (mut sibling_session, _sibling_receive_state) =
            open_live_suppression_session(db_path.to_str().unwrap(), "tenant-a", range, 21)
                .expect("open sibling suppression session");
        let (mut primary_session, primary_receive_state) =
            open_live_suppression_session(db_path.to_str().unwrap(), "tenant-a", range, 22)
                .expect("open primary suppression session");
        let event = ParsedEvent::Message(MessageEvent {
            created_at_ms: 40,
            workspace_id: [0x71; 32],
            author_id: [0x72; 32],
            content: "rx".to_string(),
        });
        let blob = encode_event(&event).unwrap();
        let event_id = hash_event(&blob);
        let remote_suppressed = [0x99; 32];
        let receive_task = spawn_receive_log_task(
            MockDataRecv::with_frames(vec![
                Ok(Frame::Event { blob: blob.clone() }),
                Ok(Frame::SuppressIds {
                    ids: vec![remote_suppressed],
                }),
                Ok(Frame::RangeDataDone),
                Err(ConnectionError::Closed),
            ]),
            db_path.to_str().unwrap().to_string(),
            "tenant-a".to_string(),
            22,
            "quic_recv:peer@example".to_string(),
            Duration::from_secs(1),
            None,
            Some(primary_receive_state),
        );

        let result = receive_task.await.unwrap().unwrap();
        assert_eq!(result.events_received, 1);
        assert_eq!(result.bytes_received, blob.len() as u64);
        assert!(result.path.is_some());
        assert_eq!(
            sibling_session
                .outbound_suppression_rx
                .try_recv()
                .expect("sibling suppression delivery"),
            event_id
        );
        assert_eq!(
            primary_session
                .inbound_suppression_rx
                .try_recv()
                .expect("forwarded remote suppression")[0],
            remote_suppressed
        );
        assert!(
            primary_session.remote_done_rx.try_recv().is_ok(),
            "receive task should notify remote done once the peer finishes"
        );
    }
}
