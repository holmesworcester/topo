use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tracing::debug;

use crate::crypto::EventId;
use crate::db::store::Store;
use crate::protocol::Frame;
use crate::sync::session::range_session::{
    append_event_frame_bytes, load_shared_send_batch, trace_dep_send_ids_enabled,
    trace_event_id_list,
};
use crate::sync::session::windowing::SyncWindow;
use crate::transport::StreamSend;
use crate::tuning::{
    live_suppression_batch_settle_ms, live_suppression_event_id_cap, live_suppression_mode,
    live_suppression_prefetch_ids, live_suppression_send_batch_size, response_send_quantum_bytes,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct LiveSuppressionCohortKey {
    db_path: String,
    recorded_by: String,
    workspace_id: String,
}

struct LiveSuppressionRegistrySession {
    remote_peer_id: String,
    tx: UnboundedSender<EventId>,
}

#[derive(Default)]
struct LiveSuppressionCohort {
    sessions: HashMap<u64, LiveSuppressionRegistrySession>,
    recent_order: VecDeque<EventId>,
    recent_known: HashSet<EventId>,
}

struct LiveSuppressionRegistration {
    key: LiveSuppressionCohortKey,
    session_id: u64,
    remote_peer_id: String,
}

pub struct LiveSuppressionSession {
    _registration: LiveSuppressionRegistration,
    settle_between_batches: bool,
    pub(crate) outbound_suppression_rx: UnboundedReceiver<EventId>,
    pub(crate) inbound_suppression_rx: UnboundedReceiver<Vec<EventId>>,
    pub(crate) remote_done_rx: UnboundedReceiver<()>,
}

pub struct LiveSuppressionReceiveState {
    pub(crate) key: LiveSuppressionCohortKey,
    pub(crate) session_id: u64,
    pub(crate) inbound_suppression_tx: UnboundedSender<Vec<EventId>>,
    pub(crate) remote_done_tx: UnboundedSender<()>,
    pub(crate) remote_done_notified: bool,
}

fn live_suppression_registry(
) -> &'static Mutex<HashMap<LiveSuppressionCohortKey, LiveSuppressionCohort>> {
    static REGISTRY: OnceLock<Mutex<HashMap<LiveSuppressionCohortKey, LiveSuppressionCohort>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(crate) fn live_suppression_key(
    db_path: &str,
    recorded_by: &str,
    workspace_id: &str,
) -> LiveSuppressionCohortKey {
    LiveSuppressionCohortKey {
        db_path: db_path.to_string(),
        recorded_by: recorded_by.to_string(),
        workspace_id: workspace_id.to_string(),
    }
}

impl Drop for LiveSuppressionRegistration {
    fn drop(&mut self) {
        let mut registry = live_suppression_registry()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(cohort) = registry.get_mut(&self.key) {
            cohort.sessions.remove(&self.session_id);
        }
    }
}

pub fn open_live_suppression_session(
    db_path: &str,
    recorded_by: &str,
    workspace_id: &str,
    remote_peer_id: &str,
    settle_between_batches: bool,
    session_id: u64,
) -> Option<(LiveSuppressionSession, LiveSuppressionReceiveState)> {
    if !live_suppression_mode() {
        return None;
    }

    let key = live_suppression_key(db_path, recorded_by, workspace_id);
    let (outbound_suppression_tx, outbound_suppression_rx) = mpsc::unbounded_channel();
    {
        let mut registry = live_suppression_registry()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let cohort = registry.entry(key.clone()).or_default();
        for event_id in &cohort.recent_order {
            let _ = outbound_suppression_tx.send(*event_id);
        }
        cohort.sessions.insert(
            session_id,
            LiveSuppressionRegistrySession {
                remote_peer_id: remote_peer_id.to_string(),
                tx: outbound_suppression_tx,
            },
        );
    }

    let (inbound_suppression_tx, inbound_suppression_rx) = mpsc::unbounded_channel();
    let (remote_done_tx, remote_done_rx) = mpsc::unbounded_channel();
    Some((
        LiveSuppressionSession {
            _registration: LiveSuppressionRegistration {
                key: key.clone(),
                session_id,
                remote_peer_id: remote_peer_id.to_string(),
            },
            settle_between_batches,
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

impl LiveSuppressionSession {
    pub(crate) fn should_settle_between_batches(&self) -> bool {
        self.settle_between_batches
            || live_suppression_has_distinct_remote_peer(&self._registration)
    }
}

fn live_suppression_has_distinct_remote_peer(registration: &LiveSuppressionRegistration) -> bool {
    let registry = live_suppression_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    registry
        .get(&registration.key)
        .map(|cohort| {
            cohort.sessions.iter().any(|(session_id, session)| {
                *session_id != registration.session_id
                    && session.remote_peer_id != registration.remote_peer_id
            })
        })
        .unwrap_or(false)
}

pub(crate) fn publish_live_suppression_event(
    key: &LiveSuppressionCohortKey,
    origin_session_id: u64,
    event_id: EventId,
    _created_at_ms: i64,
) {
    let mut registry = live_suppression_registry()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut stale_sessions = Vec::new();
    let cap = live_suppression_event_id_cap();
    if let Some(cohort) = registry.get_mut(key) {
        if cohort.recent_known.insert(event_id) {
            cohort.recent_order.push_back(event_id);
            while cohort.recent_order.len() > cap {
                if let Some(evicted) = cohort.recent_order.pop_front() {
                    cohort.recent_known.remove(&evicted);
                }
            }
        }
        for (session_id, session) in cohort.sessions.iter() {
            if *session_id == origin_session_id {
                continue;
            }
            if session.tx.send(event_id).is_err() {
                stale_sessions.push(*session_id);
            }
        }
        for session_id in stale_sessions {
            cohort.sessions.remove(&session_id);
        }
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

async fn wait_for_live_suppression_signal(
    live_suppression: &mut LiveSuppressionSession,
    outbound_pending: &mut VecDeque<EventId>,
    outbound_known: &mut HashSet<EventId>,
    suppressed_ids: &mut HashSet<EventId>,
    remote_done: &mut bool,
    cap: usize,
) {
    let settle_ms = live_suppression_batch_settle_ms();
    if settle_ms == 0 || !live_suppression.should_settle_between_batches() {
        return;
    }

    tokio::select! {
        _ = tokio::time::sleep(Duration::from_millis(settle_ms)) => {}
        maybe_event_id = live_suppression.outbound_suppression_rx.recv() => {
            if let Some(event_id) = maybe_event_id {
                enqueue_outbound_suppression(event_id, outbound_pending, outbound_known, cap);
            }
        }
        maybe_ids = live_suppression.inbound_suppression_rx.recv() => {
            if let Some(ids) = maybe_ids {
                enqueue_remote_suppressions(&ids, suppressed_ids, cap);
            }
        }
        maybe_done = live_suppression.remote_done_rx.recv() => {
            if maybe_done.is_some() {
                *remote_done = true;
            }
        }
    }
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
        let loaded = load_shared_send_batch(store, &refill_ids)?;
        if trace_dep_send_ids_enabled() {
            let loaded_ids = loaded
                .iter()
                .map(|(event_id, _)| *event_id)
                .collect::<Vec<_>>();
            debug!(
                target: "topo::sync_operation",
                refill_requested_ids = ?trace_event_id_list(&refill_ids),
                refill_loaded_ids = ?trace_event_id_list(&loaded_ids),
                "live send queue refill"
            );
        }
        for (event_id, blob) in loaded {
            if !suppressed_ids.contains(&event_id) {
                send_queue.push_back((event_id, blob));
            }
        }
    }
    Ok(())
}

pub async fn send_have_events_live<S>(
    store: &Store<'_>,
    data_send: &mut S,
    ordered_ids: &[EventId],
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
    debug!(
        target: "topo::sync_operation",
        range = ?range.kind,
        requested_count = ordered_ids.len(),
        ordered_count = ordered_ids.len(),
        suppression_cap = cap,
        suppression_batch_size,
        "live suppression sender starting"
    );
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
            ordered_ids,
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
                data_send
                    .flush()
                    .await
                    .map_err(|e| format!("flush suppression frame: {e}"))?;
                continue;
            }
        }

        if let Some((event_id, blob)) = send_queue.pop_front() {
            let mut payload = Vec::new();
            let batch_cap = live_suppression_prefetch_ids();
            let byte_cap = response_send_quantum_bytes();
            let mut batch_events = 0usize;
            let mut next_item = Some((event_id, blob));
            while let Some((event_id, blob)) = next_item.take() {
                if suppressed_ids.contains(&event_id) {
                    next_item = send_queue.pop_front();
                    continue;
                }
                let frame_len = 1usize.saturating_add(4).saturating_add(blob.len());
                if !payload.is_empty()
                    && (batch_events >= batch_cap
                        || payload.len().saturating_add(frame_len) > byte_cap)
                {
                    send_queue.push_front((event_id, blob));
                    break;
                }
                append_event_frame_bytes(&mut payload, &blob)?;
                bytes_sent += blob.len() as u64;
                events_sent += 1;
                batch_events += 1;
                if batch_events >= batch_cap {
                    break;
                }
                next_item = send_queue.pop_front();
            }
            if !payload.is_empty() {
                data_send
                    .send_bytes(&payload)
                    .await
                    .map_err(|e| format!("send live suppression event batch: {e}"))?;
                data_send
                    .flush()
                    .await
                    .map_err(|e| format!("flush live suppression event batch: {e}"))?;
                wait_for_live_suppression_signal(
                    live_suppression,
                    &mut outbound_pending,
                    &mut outbound_known,
                    &mut suppressed_ids,
                    &mut remote_done,
                    cap,
                )
                .await;
            }
            continue;
        }

        if !local_done_sent {
            data_send
                .send(&Frame::RangeDataDone)
                .await
                .map_err(|e| format!("send range data done: {e}"))?;
            data_send
                .flush()
                .await
                .map_err(|e| format!("flush range data done: {e}"))?;
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
    debug!(
        target: "topo::sync_operation",
        range = ?range.kind,
        events_sent,
        bytes_sent,
        remote_suppressed_count = suppressed_ids.len(),
        local_suppressed_count = outbound_known.len(),
        "live suppression sender complete"
    );
    Ok((events_sent, bytes_sent))
}
