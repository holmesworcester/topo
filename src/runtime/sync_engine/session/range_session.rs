use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use negentropy::{Id, NegentropyStorageVector};
use rusqlite::Connection;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tracing::debug;

use crate::crypto::{event_id_to_base64, hash_event, EventId};
use crate::db::hot_week_deps::{
    list_hot_week_dep_entries, should_include_week_deps, week_starts_for_window,
};
use crate::db::store::Store;
use crate::protocol::{neg_id_to_event_id, Frame, MSG_TYPE_EVENT};
use crate::sync::session::logging::SyncRunRxCapture;
use crate::sync::session::receive_log::{
    load_pending_receive_overlay_entries, open_pending_receive_overlay_session,
    record_pending_receive_overlay_entries, PendingReceiveOverlayEntry,
    PendingReceiveOverlaySession, ReceiveLogWriter,
};
use crate::sync::session::windowing::{SyncWindow, SyncWindowKind};
use crate::transport::connection::ConnectionError;
use crate::transport::{StreamRecv, StreamSend};
use crate::tuning::{
    live_suppression_batch_settle_ms, live_suppression_event_id_cap, live_suppression_mode,
    live_suppression_send_batch_size, low_mem_mode, response_send_quantum_bytes,
};

const RANGE_DATA_RECORD_PREFIX_LEN: usize = 4;
const LIVE_SUPPRESSION_PREFETCH_IDS: usize = 32;
const LOW_MEM_LIVE_SUPPRESSION_PREFETCH_IDS: usize = 8;

pub struct RangeReceiveResult {
    pub events_received: u64,
    pub bytes_received: u64,
    pub path: Option<PathBuf>,
    pub pending_overlay: Option<PendingReceiveOverlaySession>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct LiveSuppressionCohortKey {
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
enum SharedSendOrderPolicy {
    PreserveInput,
    NewestFirst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedSyncEntryDecisionContext {
    window_kind: SyncWindowKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedSyncEntryRawRows {
    window_kind: SyncWindowKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedSyncEntryPlan {
    include_hot_week_deps: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedSendEligibilityRawRows {
    requested_by_reconciliation: bool,
    present_in_workspace_index: bool,
    shared_blob_available: bool,
    used_bootstrap_auth: bool,
    used_peer_shared_auth: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SharedSendEligibilityDecisionContext {
    requested_by_reconciliation: bool,
    present_in_workspace_index: bool,
    shared_blob_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharedSendEligibilityPlan {
    SendRoot,
    SkipRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelectedDepOrderRawRows {
    dep_is_selected: bool,
    dep_already_emitted: bool,
    dep_currently_visiting: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelectedDepOrderDecisionContext {
    dep_is_selected: bool,
    dep_already_emitted: bool,
    dep_currently_visiting: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectedDepOrderPlan {
    EmitDepBeforeRoot,
    SkipDepEdge,
}

fn decide_shared_send_order_policy(kind: SyncWindowKind) -> SharedSendOrderPolicy {
    match kind {
        SyncWindowKind::LastDay => SharedSendOrderPolicy::NewestFirst,
        SyncWindowKind::Full | SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks => {
            SharedSendOrderPolicy::PreserveInput
        }
    }
}

fn normalize_shared_sync_entry_context(
    raw_rows: SharedSyncEntryRawRows,
) -> SharedSyncEntryDecisionContext {
    SharedSyncEntryDecisionContext {
        window_kind: raw_rows.window_kind,
    }
}

fn decide_shared_sync_entry_plan(context: &SharedSyncEntryDecisionContext) -> SharedSyncEntryPlan {
    SharedSyncEntryPlan {
        include_hot_week_deps: should_include_week_deps(context.window_kind),
    }
}

fn normalize_shared_send_eligibility_context(
    raw_rows: SharedSendEligibilityRawRows,
) -> SharedSendEligibilityDecisionContext {
    let _ = (raw_rows.used_bootstrap_auth, raw_rows.used_peer_shared_auth);
    SharedSendEligibilityDecisionContext {
        requested_by_reconciliation: raw_rows.requested_by_reconciliation,
        present_in_workspace_index: raw_rows.present_in_workspace_index,
        shared_blob_available: raw_rows.shared_blob_available,
    }
}

fn decide_shared_send_eligibility_plan(
    context: &SharedSendEligibilityDecisionContext,
) -> SharedSendEligibilityPlan {
    if context.requested_by_reconciliation
        && context.present_in_workspace_index
        && context.shared_blob_available
    {
        SharedSendEligibilityPlan::SendRoot
    } else {
        SharedSendEligibilityPlan::SkipRoot
    }
}

fn normalize_selected_dep_order_context(
    raw_rows: SelectedDepOrderRawRows,
) -> SelectedDepOrderDecisionContext {
    SelectedDepOrderDecisionContext {
        dep_is_selected: raw_rows.dep_is_selected,
        dep_already_emitted: raw_rows.dep_already_emitted,
        dep_currently_visiting: raw_rows.dep_currently_visiting,
    }
}

fn decide_selected_dep_order_plan(
    context: &SelectedDepOrderDecisionContext,
) -> SelectedDepOrderPlan {
    if context.dep_is_selected && !context.dep_already_emitted && !context.dep_currently_visiting {
        SelectedDepOrderPlan::EmitDepBeforeRoot
    } else {
        SelectedDepOrderPlan::SkipDepEdge
    }
}

fn load_shared_index_entries(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<Vec<(i64, EventId)>, String> {
    let mut entries = Vec::new();

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
    Ok(entries)
}

fn load_shared_sync_entries(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<Vec<(i64, EventId)>, String> {
    let mut seen = HashSet::new();
    let mut entries = Vec::new();

    for (created_at_ms, event_id) in load_shared_index_entries(conn, workspace_id, range)? {
        if seen.insert(event_id) {
            entries.push((created_at_ms, event_id));
        }
    }

    let sync_entry_plan = decide_shared_sync_entry_plan(&normalize_shared_sync_entry_context(
        SharedSyncEntryRawRows {
            window_kind: range.kind,
        },
    ));
    if sync_entry_plan.include_hot_week_deps {
        let now_ms = range
            .ts_max_exclusive()
            .unwrap_or_else(crate::db::queue::current_timestamp_ms);
        let week_starts = week_starts_for_window(range, now_ms);
        for (created_at_ms, event_id) in list_hot_week_dep_entries(conn, workspace_id, &week_starts)
            .map_err(|e| format!("load hot week dep entries: {e}"))?
        {
            if seen.insert(event_id) {
                entries.push((created_at_ms, event_id));
            }
        }
    }

    entries.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(entries)
}

fn sync_window_contains_ts(range: SyncWindow, created_at_ms: i64) -> bool {
    if range
        .ts_min()
        .map(|ts_min| created_at_ms < ts_min)
        .unwrap_or(false)
    {
        return false;
    }
    if range
        .ts_max_exclusive()
        .map(|ts_max| created_at_ms >= ts_max)
        .unwrap_or(false)
    {
        return false;
    }
    true
}

fn load_shared_sync_entries_with_pending(
    conn: &Connection,
    db_path: &str,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<Vec<(i64, EventId)>, String> {
    let mut entries = load_shared_sync_entries(conn, workspace_id, range)?;
    let mut seen = entries
        .iter()
        .map(|(_, event_id)| *event_id)
        .collect::<HashSet<_>>();

    for pending in load_pending_receive_overlay_entries(db_path, workspace_id, range.kind) {
        if sync_window_contains_ts(range, pending.created_at_ms) && seen.insert(pending.event_id) {
            entries.push((pending.created_at_ms, pending.event_id));
        }
    }

    entries.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(entries)
}

pub fn load_shared_event_index_slice(
    conn: &Connection,
    db_path: &str,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<NegentropyStorageVector, String> {
    let mut storage = NegentropyStorageVector::new();
    for (ts, event_id) in load_shared_sync_entries_with_pending(conn, db_path, workspace_id, range)?
    {
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

fn append_blob_record_bytes(payload: &mut Vec<u8>, blob: &[u8]) -> Result<(), String> {
    let blob_len = u32::try_from(blob.len())
        .map_err(|_| format!("range event too large: {} bytes", blob.len()))?;
    payload.extend_from_slice(&blob_len.to_le_bytes());
    payload.extend_from_slice(blob);
    Ok(())
}

pub fn build_shared_snapshot_bytes(
    conn: &Connection,
    db_path: &str,
    store: &Store<'_>,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<(Vec<u8>, u64), String> {
    let requested_ids = load_shared_sync_entries_with_pending(conn, db_path, workspace_id, range)?
        .into_iter()
        .map(|(_, event_id)| event_id)
        .collect::<Vec<_>>();
    build_shared_snapshot_bytes_for_roots(conn, store, workspace_id, range, &requested_ids)
}

pub fn build_shared_snapshot_bytes_for_roots(
    conn: &Connection,
    store: &Store<'_>,
    workspace_id: &str,
    range: SyncWindow,
    requested_ids: &[EventId],
) -> Result<(Vec<u8>, u64), String> {
    let ordered_ids =
        order_snapshot_ids_for_send(conn, store, workspace_id, range, requested_ids, None)?;
    let mut payload = Vec::new();
    let mut events = 0u64;
    for chunk in ordered_ids.chunks(64) {
        let ordered = load_shared_send_batch(store, chunk)?;
        for (_event_id, blob) in ordered {
            append_blob_record_bytes(&mut payload, &blob)?;
            events += 1;
        }
    }
    Ok((payload, events))
}

fn load_workspace_index_membership(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
    ids: &[EventId],
) -> Result<HashSet<EventId>, String> {
    let mut members = HashSet::new();
    if ids.is_empty() {
        return Ok(members);
    }

    for chunk in ids.chunks(64) {
        let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let mut sql = format!(
            "SELECT id
             FROM shared_event_index
             WHERE workspace_id = ?
               AND id IN ({placeholders})",
        );
        let mut params = Vec::<rusqlite::types::Value>::with_capacity(chunk.len() + 3);
        params.push(rusqlite::types::Value::Text(workspace_id.to_string()));
        for event_id in chunk {
            params.push(rusqlite::types::Value::Blob(event_id.to_vec()));
        }
        if let Some(ts_min) = range.ts_min() {
            sql.push_str(" AND ts >= ?");
            params.push(rusqlite::types::Value::Integer(ts_min));
        }
        if let Some(ts_max) = range.ts_max_exclusive() {
            sql.push_str(" AND ts < ?");
            params.push(rusqlite::types::Value::Integer(ts_max));
        }

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| format!("prepare shared send eligibility query: {e}"))?;
        let mut rows = stmt
            .query(rusqlite::params_from_iter(params.iter()))
            .map_err(|e| format!("query shared send eligibility rows: {e}"))?;
        while let Some(row) = rows
            .next()
            .map_err(|e| format!("iterate shared send eligibility rows: {e}"))?
        {
            let id_blob: Vec<u8> = row
                .get(0)
                .map_err(|e| format!("read shared send eligibility id: {e}"))?;
            if id_blob.len() != 32 {
                continue;
            }
            let mut event_id = [0u8; 32];
            event_id.copy_from_slice(&id_blob);
            members.insert(event_id);
        }
    }

    if should_include_week_deps(range.kind) {
        let now_ms = range
            .ts_max_exclusive()
            .unwrap_or_else(crate::db::queue::current_timestamp_ms);
        let week_starts = week_starts_for_window(range, now_ms);
        if !week_starts.is_empty() {
            let week_placeholders = week_starts
                .iter()
                .map(|_| "?")
                .collect::<Vec<_>>()
                .join(",");
            for chunk in ids.chunks(64) {
                let id_placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
                let sql = format!(
                    "SELECT event_id
                     FROM hot_week_dep_index
                     WHERE workspace_id = ?
                       AND event_id IN ({id_placeholders})
                       AND week_start_ms IN ({week_placeholders})",
                );
                let mut params = Vec::<rusqlite::types::Value>::with_capacity(
                    1 + chunk.len() + week_starts.len(),
                );
                params.push(rusqlite::types::Value::Text(workspace_id.to_string()));
                for event_id in chunk {
                    params.push(rusqlite::types::Value::Text(event_id_to_base64(event_id)));
                }
                for week_start in &week_starts {
                    params.push(rusqlite::types::Value::Integer(*week_start));
                }

                let mut stmt = conn
                    .prepare(&sql)
                    .map_err(|e| format!("prepare hot dep send eligibility query: {e}"))?;
                let mut rows = stmt
                    .query(rusqlite::params_from_iter(params.iter()))
                    .map_err(|e| format!("query hot dep send eligibility rows: {e}"))?;
                while let Some(row) = rows
                    .next()
                    .map_err(|e| format!("iterate hot dep send eligibility rows: {e}"))?
                {
                    let event_id_b64: String = row
                        .get(0)
                        .map_err(|e| format!("read hot dep send eligibility id: {e}"))?;
                    if let Some(event_id) = crate::crypto::event_id_from_base64(&event_id_b64) {
                        members.insert(event_id);
                    }
                }
            }
        }
    }

    Ok(members)
}

fn eligible_shared_send_root_ids(
    conn: &Connection,
    store: &Store<'_>,
    workspace_id: &str,
    range: SyncWindow,
    requested_ids: &[EventId],
) -> Result<(Vec<EventId>, HashMap<EventId, i64>), String> {
    let workspace_index_members =
        load_workspace_index_membership(conn, workspace_id, range, requested_ids)?;
    let created_at_by_id = store
        .get_shared_created_at_batch(requested_ids)
        .map_err(|e| format!("load selected created_at batch: {e}"))?;
    let mut eligible = Vec::with_capacity(requested_ids.len());
    for event_id in requested_ids {
        let plan = decide_shared_send_eligibility_plan(&normalize_shared_send_eligibility_context(
            SharedSendEligibilityRawRows {
                requested_by_reconciliation: true,
                present_in_workspace_index: workspace_index_members.contains(event_id),
                shared_blob_available: created_at_by_id.contains_key(event_id),
                used_bootstrap_auth: false,
                used_peer_shared_auth: false,
            },
        ));
        if matches!(plan, SharedSendEligibilityPlan::SendRoot) {
            eligible.push(*event_id);
        }
    }

    Ok((eligible, created_at_by_id))
}

fn live_suppression_order_rank(seed: &str, event_id: &EventId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(seed.as_bytes());
    hasher.update(event_id);
    *hasher.finalize().as_bytes()
}

fn prioritize_send_order_with_created_at(
    range: SyncWindow,
    ids: &[EventId],
    live_suppression_seed: Option<&str>,
    created_at_by_id: &HashMap<EventId, i64>,
) -> Vec<EventId> {
    if let Some(seed) = live_suppression_seed {
        let mut ranked = ids
            .iter()
            .map(|event_id| (*event_id, live_suppression_order_rank(seed, event_id)))
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
        return ranked.into_iter().map(|(event_id, _)| event_id).collect();
    }

    let order_policy = decide_shared_send_order_policy(range.kind);
    if matches!(order_policy, SharedSendOrderPolicy::PreserveInput) {
        return ids.to_vec();
    }

    let mut ordered = ids.to_vec();
    ordered.sort_by(|left, right| {
        let left_ts = created_at_by_id.get(left).copied().unwrap_or_default();
        let right_ts = created_at_by_id.get(right).copied().unwrap_or_default();
        match order_policy {
            SharedSendOrderPolicy::NewestFirst => {
                right_ts.cmp(&left_ts).then_with(|| right.cmp(left))
            }
            SharedSendOrderPolicy::PreserveInput => left.cmp(right),
        }
    });
    ordered
}

#[cfg(test)]
fn prioritize_send_order(
    store: &Store<'_>,
    range: SyncWindow,
    ids: &[EventId],
    live_suppression_seed: Option<&str>,
) -> Result<Vec<EventId>, String> {
    if let Some(seed) = live_suppression_seed {
        let mut ranked = ids
            .iter()
            .map(|event_id| (*event_id, live_suppression_order_rank(seed, event_id)))
            .collect::<Vec<_>>();
        ranked.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
        return Ok(ranked.into_iter().map(|(event_id, _)| event_id).collect());
    }

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
            SharedSendOrderPolicy::NewestFirst => {
                right_ts.cmp(&left_ts).then_with(|| right.cmp(left))
            }
            SharedSendOrderPolicy::PreserveInput => left.cmp(right),
        }
    });
    Ok(ordered)
}

fn live_suppression_registry(
) -> &'static Mutex<HashMap<LiveSuppressionCohortKey, LiveSuppressionCohort>> {
    static REGISTRY: OnceLock<Mutex<HashMap<LiveSuppressionCohortKey, LiveSuppressionCohort>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn live_suppression_key(
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
    _range: SyncWindow,
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
    fn should_settle_between_batches(&self) -> bool {
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

fn publish_live_suppression_event(
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

async fn wait_for_live_suppression_signal(
    live_suppression: &mut LiveSuppressionSession,
    outbound_pending: &mut VecDeque<EventId>,
    outbound_known: &mut HashSet<EventId>,
    suppressed_ids: &mut HashSet<EventId>,
    remote_done: &mut bool,
    cap: usize,
) {
    let settle_ms = live_suppression_batch_settle_ms();
    if settle_ms == 0 {
        return;
    }
    if !live_suppression.should_settle_between_batches() {
        // The settle delay exists to give other source peers time to receive
        // suppression. In a 1:1 cohort it only throttles the sole sender.
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

fn load_selected_direct_deps(
    conn: &Connection,
    workspace_id: &str,
    event_id: &EventId,
    selected_ids: &HashSet<EventId>,
    created_at_by_id: &HashMap<EventId, i64>,
    dep_cache: &mut HashMap<EventId, Vec<EventId>>,
) -> Result<Vec<EventId>, String> {
    if let Some(dep_ids) = dep_cache.get(event_id) {
        return Ok(dep_ids.clone());
    }

    let mut dep_ids = crate::db::dep_index::list_shared_event_deps(conn, workspace_id, event_id)
        .map_err(|e| format!("load shared event deps: {e}"))?
        .into_iter()
        .filter(|dep_id| selected_ids.contains(dep_id))
        .collect::<Vec<_>>();
    dep_ids.sort_by(|left, right| {
        let left_ts = created_at_by_id.get(left).copied().unwrap_or_default();
        let right_ts = created_at_by_id.get(right).copied().unwrap_or_default();
        left_ts.cmp(&right_ts).then_with(|| left.cmp(right))
    });
    dep_cache.insert(*event_id, dep_ids.clone());
    Ok(dep_ids)
}

fn visit_selected_send_order(
    conn: &Connection,
    workspace_id: &str,
    event_id: EventId,
    selected_ids: &HashSet<EventId>,
    created_at_by_id: &HashMap<EventId, i64>,
    dep_cache: &mut HashMap<EventId, Vec<EventId>>,
    emitted: &mut HashSet<EventId>,
    visiting: &mut HashSet<EventId>,
    ordered: &mut Vec<EventId>,
) -> Result<(), String> {
    if emitted.contains(&event_id) {
        return Ok(());
    }
    if !visiting.insert(event_id) {
        return Ok(());
    }

    for dep_id in load_selected_direct_deps(
        conn,
        workspace_id,
        &event_id,
        selected_ids,
        created_at_by_id,
        dep_cache,
    )? {
        let dep_plan = decide_selected_dep_order_plan(&normalize_selected_dep_order_context(
            SelectedDepOrderRawRows {
                dep_is_selected: selected_ids.contains(&dep_id),
                dep_already_emitted: emitted.contains(&dep_id),
                dep_currently_visiting: visiting.contains(&dep_id),
            },
        ));
        match dep_plan {
            SelectedDepOrderPlan::EmitDepBeforeRoot => {
                visit_selected_send_order(
                    conn,
                    workspace_id,
                    dep_id,
                    selected_ids,
                    created_at_by_id,
                    dep_cache,
                    emitted,
                    visiting,
                    ordered,
                )?;
            }
            SelectedDepOrderPlan::SkipDepEdge => continue,
        }
    }

    visiting.remove(&event_id);
    emitted.insert(event_id);
    ordered.push(event_id);
    Ok(())
}

fn order_requested_ids_for_send(
    conn: &Connection,
    store: &Store<'_>,
    workspace_id: &str,
    range: SyncWindow,
    requested_ids: &[EventId],
    live_suppression_seed: Option<&str>,
) -> Result<Vec<EventId>, String> {
    if requested_ids.is_empty() {
        return Ok(Vec::new());
    }

    let (eligible_roots, created_at_by_id) =
        eligible_shared_send_root_ids(conn, store, workspace_id, range, requested_ids)?;
    let ordered_roots = prioritize_send_order_with_created_at(
        range,
        &eligible_roots,
        live_suppression_seed,
        &created_at_by_id,
    );
    let selected_ids: HashSet<EventId> = eligible_roots.iter().copied().collect();

    let mut ordered = Vec::new();
    let mut emitted = HashSet::new();
    let mut visiting = HashSet::new();
    let mut dep_cache = HashMap::new();

    for event_id in ordered_roots {
        visit_selected_send_order(
            conn,
            workspace_id,
            event_id,
            &selected_ids,
            &created_at_by_id,
            &mut dep_cache,
            &mut emitted,
            &mut visiting,
            &mut ordered,
        )?;
    }

    Ok(ordered)
}

fn load_snapshot_direct_deps(
    conn: &Connection,
    store: &Store<'_>,
    workspace_id: &str,
    event_id: &EventId,
    created_at_by_id: &mut HashMap<EventId, i64>,
    dep_cache: &mut HashMap<EventId, Vec<EventId>>,
) -> Result<Vec<EventId>, String> {
    if let Some(dep_ids) = dep_cache.get(event_id) {
        return Ok(dep_ids.clone());
    }

    let mut dep_ids = crate::db::dep_index::list_shared_event_deps(conn, workspace_id, event_id)
        .map_err(|e| format!("load snapshot event deps: {e}"))?;
    if dep_ids.is_empty() {
        dep_cache.insert(*event_id, Vec::new());
        return Ok(Vec::new());
    }

    let dep_created_at = store
        .get_shared_created_at_batch(&dep_ids)
        .map_err(|e| format!("load snapshot dep created_at batch: {e}"))?;
    dep_ids.retain(|dep_id| dep_created_at.contains_key(dep_id));
    for (dep_id, created_at_ms) in dep_created_at {
        created_at_by_id.entry(dep_id).or_insert(created_at_ms);
    }
    dep_ids.sort_by(|left, right| {
        let left_ts = created_at_by_id.get(left).copied().unwrap_or_default();
        let right_ts = created_at_by_id.get(right).copied().unwrap_or_default();
        left_ts.cmp(&right_ts).then_with(|| left.cmp(right))
    });
    dep_cache.insert(*event_id, dep_ids.clone());
    Ok(dep_ids)
}

fn visit_snapshot_send_order(
    conn: &Connection,
    store: &Store<'_>,
    workspace_id: &str,
    event_id: EventId,
    created_at_by_id: &mut HashMap<EventId, i64>,
    dep_cache: &mut HashMap<EventId, Vec<EventId>>,
    emitted: &mut HashSet<EventId>,
    visiting: &mut HashSet<EventId>,
    ordered: &mut Vec<EventId>,
) -> Result<(), String> {
    if emitted.contains(&event_id) {
        return Ok(());
    }
    if !visiting.insert(event_id) {
        return Ok(());
    }

    for dep_id in load_snapshot_direct_deps(
        conn,
        store,
        workspace_id,
        &event_id,
        created_at_by_id,
        dep_cache,
    )? {
        visit_snapshot_send_order(
            conn,
            store,
            workspace_id,
            dep_id,
            created_at_by_id,
            dep_cache,
            emitted,
            visiting,
            ordered,
        )?;
    }

    visiting.remove(&event_id);
    emitted.insert(event_id);
    ordered.push(event_id);
    Ok(())
}

fn order_snapshot_ids_for_send(
    conn: &Connection,
    store: &Store<'_>,
    workspace_id: &str,
    range: SyncWindow,
    requested_ids: &[EventId],
    live_suppression_seed: Option<&str>,
) -> Result<Vec<EventId>, String> {
    if requested_ids.is_empty() {
        return Ok(Vec::new());
    }

    let (eligible_roots, mut created_at_by_id) =
        eligible_shared_send_root_ids(conn, store, workspace_id, range, requested_ids)?;
    let ordered_roots = prioritize_send_order_with_created_at(
        range,
        &eligible_roots,
        live_suppression_seed,
        &created_at_by_id,
    );

    let mut ordered = Vec::new();
    let mut emitted = HashSet::new();
    let mut visiting = HashSet::new();
    let mut dep_cache = HashMap::new();

    for event_id in ordered_roots {
        visit_snapshot_send_order(
            conn,
            store,
            workspace_id,
            event_id,
            &mut created_at_by_id,
            &mut dep_cache,
            &mut emitted,
            &mut visiting,
            &mut ordered,
        )?;
    }

    Ok(ordered)
}

async fn send_have_events_live<S>(
    conn: &Connection,
    store: &Store<'_>,
    data_send: &mut S,
    have_ids: &[Id],
    recorded_by: &str,
    workspace_id: &str,
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
    let ordered_ids = order_requested_ids_for_send(
        conn,
        store,
        workspace_id,
        range,
        &event_ids,
        Some(recorded_by),
    )?;
    debug!(
        target: "topo::sync_operation",
        range = ?range.kind,
        requested_count = have_ids.len(),
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

pub async fn send_have_events<S>(
    conn: &Connection,
    store: &Store<'_>,
    data_send: &mut S,
    have_ids: &[Id],
    _recorded_by: &str,
    workspace_id: &str,
    range: SyncWindow,
    live_suppression: Option<&mut LiveSuppressionSession>,
) -> Result<(u64, u64), String>
where
    S: StreamSend,
{
    if let Some(live_suppression) = live_suppression {
        return send_have_events_live(
            conn,
            store,
            data_send,
            have_ids,
            _recorded_by,
            workspace_id,
            range,
            live_suppression,
        )
        .await;
    }

    if have_ids.is_empty() {
        return Ok((0, 0));
    }

    let mut events_sent = 0u64;
    let mut bytes_sent = 0u64;
    let event_ids: Vec<EventId> = have_ids.iter().map(neg_id_to_event_id).collect();
    let event_ids =
        order_requested_ids_for_send(conn, store, workspace_id, range, &event_ids, None)?;
    for chunk in event_ids.chunks(64) {
        let ordered = load_shared_send_batch(store, chunk)?;
        let mut payload = Vec::new();
        for (_event_id, blob) in ordered {
            append_blob_record_bytes(&mut payload, &blob)?;
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

fn event_created_at_ms(blob: &[u8]) -> Option<i64> {
    crate::event_modules::extract_created_at_ms(blob)
        .and_then(|created_at_ms| i64::try_from(created_at_ms).ok())
}

fn pending_receive_overlay_entry_for_created_at(
    range: SyncWindow,
    created_at_ms: i64,
    event_id: EventId,
) -> Option<PendingReceiveOverlayEntry> {
    if sync_window_contains_ts(range, created_at_ms) {
        Some(PendingReceiveOverlayEntry {
            created_at_ms,
            event_id,
        })
    } else {
        None
    }
}

fn append_event_frame_bytes(payload: &mut Vec<u8>, blob: &[u8]) -> Result<(), String> {
    let blob_len = u32::try_from(blob.len())
        .map_err(|_| format!("range event too large: {} bytes", blob.len()))?;
    payload.push(MSG_TYPE_EVENT);
    payload.extend_from_slice(&blob_len.to_le_bytes());
    payload.extend_from_slice(blob);
    Ok(())
}

pub fn spawn_receive_log_task<R>(
    data_recv: R,
    db_path: String,
    recorded_by: String,
    workspace_id: String,
    range: SyncWindow,
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
        let pending_overlay =
            open_pending_receive_overlay_session(&db_path, &workspace_id, range.kind, session_id);
        let mut pending_overlay_entries = Vec::new();
        let mut events_received = 0u64;
        let mut bytes_received = 0u64;
        let mut live_suppression = live_suppression;

        if live_suppression.is_some() {
            debug!(
                target: "topo::sync_operation",
                session_id,
                source = %source_tag,
                "live suppression receive task starting"
            );
            loop {
                let next = tokio::time::timeout(idle_timeout, data_recv.recv()).await;
                match next {
                    Ok(Ok(Frame::Event { blob })) => {
                        let event_id = hash_event(&blob);
                        let created_at_ms = event_created_at_ms(&blob);
                        if let Some(capture) = &rx_capture {
                            capture.record_event_id_b64(event_id_to_base64(&event_id));
                        }
                        if let (Some(state), Some(created_at_ms)) =
                            (&live_suppression, created_at_ms)
                        {
                            publish_live_suppression_event(
                                &state.key,
                                state.session_id,
                                event_id,
                                created_at_ms,
                            );
                        }
                        if let Some(entry) = created_at_ms.and_then(|created_at_ms| {
                            pending_receive_overlay_entry_for_created_at(
                                range,
                                created_at_ms,
                                event_id,
                            )
                        }) {
                            pending_overlay_entries.push(entry);
                        }
                        bytes_received += blob.len() as u64;
                        events_received += 1;
                        writer.append_blob(&event_id, &blob)?;
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
            debug!(
                target: "topo::sync_operation",
                session_id,
                source = %source_tag,
                events_received,
                bytes_received,
                "live suppression receive task complete"
            );
        } else {
            let mut buffer = Vec::<u8>::with_capacity(64 * 1024);
            loop {
                let next = tokio::time::timeout(idle_timeout, data_recv.recv_chunk()).await;
                match next {
                    Ok(Ok(chunk)) => {
                        buffer.extend_from_slice(&chunk);
                        let mut offset = 0usize;
                        while let Some(blob) = parse_next_blob_record(&buffer, &mut offset)? {
                            let event_id = hash_event(&blob);
                            let created_at_ms = event_created_at_ms(&blob);
                            if let Some(capture) = &rx_capture {
                                capture.record_event_id_b64(event_id_to_base64(&event_id));
                            }
                            if let Some(entry) = created_at_ms.and_then(|created_at_ms| {
                                pending_receive_overlay_entry_for_created_at(
                                    range,
                                    created_at_ms,
                                    event_id,
                                )
                            }) {
                                pending_overlay_entries.push(entry);
                            }
                            bytes_received += blob.len() as u64;
                            events_received += 1;
                            writer.append_blob(&event_id, &blob)?;
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

        let path = writer.finish()?;
        let pending_overlay = if path.is_some() {
            record_pending_receive_overlay_entries(
                pending_overlay.session(),
                pending_overlay_entries,
            );
            Some(pending_overlay.into_session())
        } else {
            None
        };
        Ok(RangeReceiveResult {
            events_received,
            bytes_received,
            path,
            pending_overlay,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use crate::contracts::event_pipeline_contract::IngestItem;
    use crate::crypto::hash_event;
    use crate::db::dep_index::replace_shared_event_deps;
    use crate::db::queue::current_timestamp_ms;
    use crate::db::schema::create_tables;
    use crate::db::store::{insert_event, insert_shared_event_index_entry_if_shared};
    use crate::db::{open_connection, open_in_memory};
    use crate::event_modules::{
        encode_event, endpoint_shared, registry::ShareScope, BenchDepEvent, MessageEvent,
        ParsedEvent, PeerSharedEvent,
    };
    use crate::state::pipeline::ingest_now;
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

    fn insert_shared_bench_dep(
        conn: &Connection,
        workspace_id: &str,
        created_at_ms: i64,
        dep_ids: Vec<EventId>,
        marker: u8,
    ) -> EventId {
        let blob = encode_event(&ParsedEvent::BenchDep(BenchDepEvent {
            created_at_ms: created_at_ms as u64,
            dep_ids,
            payload: [marker; 16],
        }))
        .unwrap();
        let event_id = hash_event(&blob);
        insert_event(
            conn,
            &event_id,
            "bench_dep_perf_testing",
            &blob,
            ShareScope::Shared,
            created_at_ms,
            created_at_ms,
        )
        .unwrap();
        insert_shared_event_index_entry_if_shared(
            conn,
            ShareScope::Shared,
            created_at_ms,
            &event_id,
            workspace_id,
            &blob,
        )
        .unwrap();
        event_id
    }

    fn make_ingest_batch(
        recorded_by: &str,
        source_tag: &str,
        ordered: &[(EventId, Vec<u8>)],
    ) -> Vec<IngestItem> {
        ordered
            .iter()
            .enumerate()
            .map(|(idx, (event_id, blob))| {
                (
                    *event_id,
                    blob.clone(),
                    recorded_by.to_string(),
                    source_tag.to_string(),
                    idx as i64,
                    idx as i64,
                )
            })
            .collect()
    }

    fn valid_event_count(conn: &Connection, recorded_by: &str) -> i64 {
        conn.query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn is_valid(conn: &Connection, recorded_by: &str, event_id: &EventId) -> bool {
        conn.query_row(
            "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, crate::crypto::event_id_to_base64(event_id)],
            |row| row.get(0),
        )
        .unwrap()
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
    fn prioritize_send_order_matches_lane_policy() {
        assert_eq!(
            decide_shared_send_order_policy(SyncWindowKind::LastDay),
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
        let hot_order = prioritize_send_order(
            &store,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(0),
                ts_max_exclusive_ms: None,
            },
            &[first_id, second_id],
            None,
        )
        .unwrap();

        assert_eq!(hot_order, vec![second_id, first_id]);
    }

    #[test]
    fn shared_sync_entry_plan_matches_hot_week_dep_policy() {
        assert_eq!(
            decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
                window_kind: SyncWindowKind::Full,
            }),
            SharedSyncEntryPlan {
                include_hot_week_deps: false,
            }
        );
        assert_eq!(
            decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
                window_kind: SyncWindowKind::LastDay,
            }),
            SharedSyncEntryPlan {
                include_hot_week_deps: true,
            }
        );
        assert_eq!(
            decide_shared_sync_entry_plan(&SharedSyncEntryDecisionContext {
                window_kind: SyncWindowKind::LastWeek,
            }),
            SharedSyncEntryPlan {
                include_hot_week_deps: true,
            }
        );
    }

    #[test]
    fn shared_sync_entry_normalizer_preserves_raw_rows_for_planner() {
        let raw = SharedSyncEntryRawRows {
            window_kind: SyncWindowKind::LastDay,
        };
        let context = normalize_shared_sync_entry_context(raw);
        assert_eq!(
            context,
            SharedSyncEntryDecisionContext {
                window_kind: SyncWindowKind::LastDay,
            }
        );
        assert_eq!(
            decide_shared_sync_entry_plan(&context),
            SharedSyncEntryPlan {
                include_hot_week_deps: true,
            }
        );
    }

    #[test]
    fn shared_send_eligibility_plan_ignores_session_auth_path() {
        let bootstrap_context =
            normalize_shared_send_eligibility_context(SharedSendEligibilityRawRows {
                requested_by_reconciliation: true,
                present_in_workspace_index: true,
                shared_blob_available: true,
                used_bootstrap_auth: true,
                used_peer_shared_auth: false,
            });
        let peer_shared_context =
            normalize_shared_send_eligibility_context(SharedSendEligibilityRawRows {
                requested_by_reconciliation: true,
                present_in_workspace_index: true,
                shared_blob_available: true,
                used_bootstrap_auth: false,
                used_peer_shared_auth: true,
            });

        assert_eq!(bootstrap_context, peer_shared_context);
        assert_eq!(
            decide_shared_send_eligibility_plan(&bootstrap_context),
            SharedSendEligibilityPlan::SendRoot
        );
        assert_eq!(
            decide_shared_send_eligibility_plan(&peer_shared_context),
            SharedSendEligibilityPlan::SendRoot
        );
    }

    #[test]
    fn order_requested_ids_for_send_filters_local_only_rows_even_if_indexed() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "workspace-a";
        let blob = b"local secret blob";
        let event_id = hash_event(blob);
        insert_event(
            &conn,
            &event_id,
            "key_secret",
            blob,
            ShareScope::Local,
            1,
            1,
        )
        .unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO shared_event_index (workspace_id, ts, id)
             VALUES (?1, ?2, ?3)",
            rusqlite::params![workspace_id, 1i64, event_id.as_slice()],
        )
        .unwrap();

        let store = Store::new(&conn);
        let ordered = order_requested_ids_for_send(
            &conn,
            &store,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::Full,
                ts_min_inclusive_ms: None,
                ts_max_exclusive_ms: None,
            },
            &[event_id],
            None,
        )
        .unwrap();

        assert!(ordered.is_empty());
    }

    #[test]
    fn order_requested_ids_for_send_filters_wrong_workspace_rows() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let blob = b"shared workspace-b blob";
        let event_id = hash_event(blob);
        insert_event(&conn, &event_id, "message", blob, ShareScope::Shared, 1, 1).unwrap();
        insert_shared_event_index_entry_if_shared(
            &conn,
            ShareScope::Shared,
            1,
            &event_id,
            "workspace-b",
            blob,
        )
        .unwrap();

        let store = Store::new(&conn);
        let range = SyncWindow {
            kind: SyncWindowKind::Full,
            ts_min_inclusive_ms: None,
            ts_max_exclusive_ms: None,
        };
        let wrong_workspace_order =
            order_requested_ids_for_send(&conn, &store, "workspace-a", range, &[event_id], None)
                .unwrap();
        let matching_workspace_order =
            order_requested_ids_for_send(&conn, &store, "workspace-b", range, &[event_id], None)
                .unwrap();

        assert!(wrong_workspace_order.is_empty());
        assert_eq!(matching_workspace_order, vec![event_id]);
    }

    #[test]
    fn selected_dep_order_plan_emits_only_selected_unvisited_deps() {
        assert_eq!(
            decide_selected_dep_order_plan(&SelectedDepOrderDecisionContext {
                dep_is_selected: true,
                dep_already_emitted: false,
                dep_currently_visiting: false,
            }),
            SelectedDepOrderPlan::EmitDepBeforeRoot
        );
        assert_eq!(
            decide_selected_dep_order_plan(&SelectedDepOrderDecisionContext {
                dep_is_selected: false,
                dep_already_emitted: false,
                dep_currently_visiting: false,
            }),
            SelectedDepOrderPlan::SkipDepEdge
        );
        assert_eq!(
            decide_selected_dep_order_plan(&SelectedDepOrderDecisionContext {
                dep_is_selected: true,
                dep_already_emitted: true,
                dep_currently_visiting: false,
            }),
            SelectedDepOrderPlan::SkipDepEdge
        );
        assert_eq!(
            decide_selected_dep_order_plan(&SelectedDepOrderDecisionContext {
                dep_is_selected: true,
                dep_already_emitted: false,
                dep_currently_visiting: true,
            }),
            SelectedDepOrderPlan::SkipDepEdge
        );
    }

    #[test]
    fn selected_dep_order_plan_matches_all_boolean_cases() {
        for dep_is_selected in [false, true] {
            for dep_already_emitted in [false, true] {
                for dep_currently_visiting in [false, true] {
                    let context = SelectedDepOrderDecisionContext {
                        dep_is_selected,
                        dep_already_emitted,
                        dep_currently_visiting,
                    };
                    let expected =
                        if dep_is_selected && !dep_already_emitted && !dep_currently_visiting {
                            SelectedDepOrderPlan::EmitDepBeforeRoot
                        } else {
                            SelectedDepOrderPlan::SkipDepEdge
                        };
                    assert_eq!(decide_selected_dep_order_plan(&context), expected);
                }
            }
        }
    }

    #[test]
    fn selected_dep_order_normalizer_preserves_raw_rows_for_planner() {
        let raw = SelectedDepOrderRawRows {
            dep_is_selected: true,
            dep_already_emitted: false,
            dep_currently_visiting: false,
        };
        let context = normalize_selected_dep_order_context(raw);
        assert_eq!(
            context,
            SelectedDepOrderDecisionContext {
                dep_is_selected: true,
                dep_already_emitted: false,
                dep_currently_visiting: false,
            }
        );
        assert_eq!(
            decide_selected_dep_order_plan(&context),
            SelectedDepOrderPlan::EmitDepBeforeRoot
        );
    }

    #[test]
    fn live_suppression_send_order_uses_peer_seed_to_scatter_roots() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let store = Store::new(&conn);
        let range = SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(0),
            ts_max_exclusive_ms: None,
        };
        let ids = (0u8..16)
            .map(|idx| {
                let mut event_id = [0u8; 32];
                event_id[31] = idx;
                event_id
            })
            .collect::<Vec<_>>();

        let tenant_a_order = prioritize_send_order(&store, range, &ids, Some("tenant-a")).unwrap();
        let tenant_b_order = prioritize_send_order(&store, range, &ids, Some("tenant-b")).unwrap();
        let mut expected_a = ids
            .iter()
            .map(|event_id| (*event_id, live_suppression_order_rank("tenant-a", event_id)))
            .collect::<Vec<_>>();
        expected_a.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
        let expected_a = expected_a
            .into_iter()
            .map(|(event_id, _)| event_id)
            .collect::<Vec<_>>();

        assert_eq!(tenant_a_order, expected_a);
        assert_ne!(
            tenant_a_order, tenant_b_order,
            "different local peers should not all send replicated roots in the same order"
        );
    }

    #[test]
    fn load_shared_sync_entries_includes_hot_week_deps_for_last_day() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "workspace-bench-chain";
        let now_ms = current_timestamp_ms();
        let hot_created_at_ms = now_ms - 1_000;

        let root = insert_shared_bench_dep(&conn, workspace_id, 1, vec![], 1);
        let mid = insert_shared_bench_dep(&conn, workspace_id, 2, vec![root], 2);
        let leaf = insert_shared_bench_dep(&conn, workspace_id, hot_created_at_ms, vec![mid], 3);
        replace_shared_event_deps(&conn, workspace_id, &mid, &[root]).unwrap();
        replace_shared_event_deps(&conn, workspace_id, &leaf, &[mid]).unwrap();
        crate::db::hot_week_deps::track_valid_shared_event_deps(
            &conn,
            workspace_id,
            &leaf,
            hot_created_at_ms,
            now_ms,
        )
        .unwrap();

        let entries = load_shared_sync_entries(
            &conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(now_ms - (24 * 60 * 60 * 1000)),
                ts_max_exclusive_ms: Some(now_ms),
            },
        )
        .unwrap();
        let selected_ids = entries
            .into_iter()
            .map(|(_, event_id)| event_id)
            .collect::<Vec<_>>();
        assert_eq!(selected_ids, vec![root, mid, leaf]);

        let store = Store::new(&conn);
        let ordered = order_requested_ids_for_send(
            &conn,
            &store,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(now_ms - (24 * 60 * 60 * 1000)),
                ts_max_exclusive_ms: Some(now_ms),
            },
            &selected_ids,
            None,
        )
        .unwrap();

        assert_eq!(ordered, vec![root, mid, leaf]);
    }

    #[test]
    fn load_shared_sync_entries_includes_pending_receive_overlay() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("node.db");
        let db_path = db_path.to_str().unwrap();
        let workspace_id = "workspace-pending-receive";
        let range = SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(10),
            ts_max_exclusive_ms: Some(100),
        };
        let durable_id = insert_shared_bench_dep(&conn, workspace_id, 20, vec![], 1);
        let pending_id = [0x33; 32];
        let out_of_range_pending_id = [0x44; 32];

        let overlay = crate::sync::session::receive_log::open_pending_receive_overlay_session(
            db_path,
            workspace_id,
            range.kind,
            77,
        );
        crate::sync::session::receive_log::record_pending_receive_overlay_entry(
            overlay.session(),
            30,
            pending_id,
        );
        crate::sync::session::receive_log::record_pending_receive_overlay_entry(
            overlay.session(),
            30,
            durable_id,
        );
        crate::sync::session::receive_log::record_pending_receive_overlay_entry(
            overlay.session(),
            5,
            out_of_range_pending_id,
        );

        let entries =
            load_shared_sync_entries_with_pending(&conn, db_path, workspace_id, range).unwrap();
        let selected_ids = entries
            .into_iter()
            .map(|(_, event_id)| event_id)
            .collect::<Vec<_>>();

        assert_eq!(selected_ids, vec![durable_id, pending_id]);
        let broader_range = SyncWindow {
            kind: SyncWindowKind::LastWeek,
            ts_min_inclusive_ms: Some(0),
            ts_max_exclusive_ms: Some(100),
        };
        let entries =
            load_shared_sync_entries_with_pending(&conn, db_path, workspace_id, broader_range)
                .unwrap();
        let selected_ids = entries
            .into_iter()
            .map(|(_, event_id)| event_id)
            .collect::<Vec<_>>();
        assert_eq!(
            selected_ids,
            vec![out_of_range_pending_id, durable_id, pending_id],
            "pending receives from a narrower active window must suppress/overlay broader follow-up windows"
        );
        drop(overlay);

        let entries =
            load_shared_sync_entries_with_pending(&conn, db_path, workspace_id, range).unwrap();
        let selected_ids = entries
            .into_iter()
            .map(|(_, event_id)| event_id)
            .collect::<Vec<_>>();
        assert_eq!(selected_ids, vec![durable_id]);
    }

    #[test]
    fn full_window_sync_entries_do_not_include_week_deps() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "workspace-full-no-deps";
        let now_ms = current_timestamp_ms();

        let root = insert_shared_bench_dep(&conn, workspace_id, 1, vec![], 1);
        let leaf = insert_shared_bench_dep(&conn, workspace_id, now_ms - 1_000, vec![root], 2);
        replace_shared_event_deps(&conn, workspace_id, &leaf, &[root]).unwrap();
        crate::db::hot_week_deps::track_valid_shared_event_deps(
            &conn,
            workspace_id,
            &leaf,
            now_ms - 1_000,
            now_ms,
        )
        .unwrap();

        let entries = load_shared_sync_entries(
            &conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::Full,
                ts_min_inclusive_ms: Some(0),
                ts_max_exclusive_ms: Some(now_ms - (12 * 7 * 24 * 60 * 60 * 1000)),
            },
        )
        .unwrap();

        let selected_ids = entries
            .into_iter()
            .map(|(_, event_id)| event_id)
            .collect::<Vec<_>>();
        assert_eq!(selected_ids, vec![root]);
    }

    #[test]
    fn order_requested_ids_sends_week_deps_before_root() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "workspace-bench-order";
        let now_ms = current_timestamp_ms();
        let hot_created_at_ms = now_ms - 1_000;

        let root = insert_shared_bench_dep(&conn, workspace_id, 1, vec![], 1);
        let mid = insert_shared_bench_dep(&conn, workspace_id, 2, vec![root], 2);
        let leaf = insert_shared_bench_dep(&conn, workspace_id, hot_created_at_ms, vec![mid], 3);
        replace_shared_event_deps(&conn, workspace_id, &mid, &[root]).unwrap();
        replace_shared_event_deps(&conn, workspace_id, &leaf, &[mid]).unwrap();
        crate::db::hot_week_deps::track_valid_shared_event_deps(
            &conn,
            workspace_id,
            &leaf,
            hot_created_at_ms,
            now_ms,
        )
        .unwrap();

        let selected_ids = load_shared_sync_entries(
            &conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(now_ms - (24 * 60 * 60 * 1000)),
                ts_max_exclusive_ms: Some(now_ms),
            },
        )
        .unwrap()
        .into_iter()
        .map(|(_, event_id)| event_id)
        .collect::<Vec<_>>();
        let store = Store::new(&conn);
        let ordered = order_requested_ids_for_send(
            &conn,
            &store,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(now_ms - (24 * 60 * 60 * 1000)),
                ts_max_exclusive_ms: Some(now_ms),
            },
            &selected_ids,
            None,
        )
        .unwrap();

        assert_eq!(ordered, vec![root, mid, leaf]);
    }

    #[test]
    fn week_dep_sync_entries_project_full_chain_in_one_round() {
        let dir = tempfile::tempdir().unwrap();
        let source_db_path = dir.path().join("source.db");
        let dest_db_path = dir.path().join("dest.db");

        let source_conn = open_connection(&source_db_path).unwrap();
        let dest_conn = open_connection(&dest_db_path).unwrap();
        create_tables(&source_conn).unwrap();
        create_tables(&dest_conn).unwrap();

        let workspace_id = "workspace-one-round";
        let now_ms = current_timestamp_ms();
        let mut all_ids = Vec::new();
        let mut prior = None;
        for idx in 0..128i64 {
            let dep_ids = prior.into_iter().collect::<Vec<_>>();
            let created_at_ms = if idx == 127 { now_ms - 1_000 } else { idx + 1 };
            let event_id = insert_shared_bench_dep(
                &source_conn,
                workspace_id,
                created_at_ms,
                dep_ids.clone(),
                (idx % 251) as u8,
            );
            if let Some(dep_id) = dep_ids.first() {
                replace_shared_event_deps(&source_conn, workspace_id, &event_id, &[*dep_id])
                    .unwrap();
            }
            all_ids.push(event_id);
            prior = Some(event_id);
        }
        let leaf = *all_ids.last().unwrap();
        crate::db::hot_week_deps::track_valid_shared_event_deps(
            &source_conn,
            workspace_id,
            &leaf,
            now_ms - 1_000,
            now_ms,
        )
        .unwrap();

        let selected_ids = load_shared_sync_entries(
            &source_conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(now_ms - (24 * 60 * 60 * 1000)),
                ts_max_exclusive_ms: Some(now_ms),
            },
        )
        .unwrap()
        .into_iter()
        .map(|(_, event_id)| event_id)
        .collect::<Vec<_>>();
        let store = Store::new(&source_conn);
        let ordered_ids = order_requested_ids_for_send(
            &source_conn,
            &store,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(now_ms - (24 * 60 * 60 * 1000)),
                ts_max_exclusive_ms: Some(now_ms),
            },
            &selected_ids,
            None,
        )
        .unwrap();
        assert_eq!(ordered_ids.len(), all_ids.len());

        let ordered = load_shared_send_batch(&store, &ordered_ids).unwrap();
        let dest_path = dest_db_path.to_string_lossy().to_string();
        let persisted = ingest_now(
            &dest_path,
            make_ingest_batch("tenant-a", "quic_recv:peer-z@test", &ordered),
        )
        .unwrap();

        assert_eq!(persisted, all_ids.len());
        assert_eq!(
            valid_event_count(&dest_conn, "tenant-a"),
            all_ids.len() as i64
        );
        assert!(is_valid(&dest_conn, "tenant-a", &leaf));
    }

    #[test]
    fn live_suppression_registry_replays_recent_state_between_sessions() {
        let _env = EnvGuard::enable_live_suppression();
        let range = SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(10),
            ts_max_exclusive_ms: None,
        };
        let key = live_suppression_key("/tmp/live-suppress.db", "tenant-a", "workspace-a");
        let (_session_a, _) = open_live_suppression_session(
            "/tmp/live-suppress.db",
            "tenant-a",
            "workspace-a",
            "remote-a",
            false,
            range,
            1,
        )
        .expect("open first suppression session");
        let (mut session_b, _) = open_live_suppression_session(
            "/tmp/live-suppress.db",
            "tenant-a",
            "workspace-a",
            "remote-b",
            false,
            range,
            2,
        )
        .expect("open second suppression session");

        publish_live_suppression_event(&key, 1, [0x44; 32], 20);
        assert_eq!(
            session_b
                .outbound_suppression_rx
                .try_recv()
                .expect("deliver live suppression"),
            [0x44; 32]
        );

        drop(session_b);
        drop(_session_a);

        let (mut session_c, _) = open_live_suppression_session(
            "/tmp/live-suppress.db",
            "tenant-a",
            "workspace-a",
            "remote-c",
            false,
            range,
            3,
        )
        .expect("open fresh suppression session");
        assert_eq!(
            session_c
                .outbound_suppression_rx
                .try_recv()
                .expect("fresh session should inherit recent suppressions"),
            [0x44; 32]
        );
    }

    #[test]
    fn live_suppression_settle_requires_distinct_remote_peer() {
        let _env = EnvGuard::enable_live_suppression();
        let range = SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(10),
            ts_max_exclusive_ms: None,
        };
        let (session_a, _) = open_live_suppression_session(
            "/tmp/live-settle.db",
            "tenant-a",
            "workspace-a",
            "remote-a",
            false,
            range,
            1,
        )
        .expect("open first suppression session");
        assert!(
            !session_a.should_settle_between_batches(),
            "one remote peer cannot benefit from suppression settle"
        );

        let (session_a_duplicate, _) = open_live_suppression_session(
            "/tmp/live-settle.db",
            "tenant-a",
            "workspace-a",
            "remote-a",
            false,
            range,
            2,
        )
        .expect("open duplicate-peer suppression session");
        assert!(
            !session_a.should_settle_between_batches(),
            "duplicate sessions for the same remote peer are not multi-source"
        );
        assert!(!session_a_duplicate.should_settle_between_batches());

        let (session_b, _) = open_live_suppression_session(
            "/tmp/live-settle.db",
            "tenant-a",
            "workspace-a",
            "remote-b",
            false,
            range,
            3,
        )
        .expect("open distinct-peer suppression session");
        assert!(session_a.should_settle_between_batches());
        assert!(session_b.should_settle_between_batches());
    }

    #[test]
    fn live_suppression_event_notifies_same_workspace_regardless_of_range() {
        let _env = EnvGuard::enable_live_suppression();
        let hot_range = SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(10),
            ts_max_exclusive_ms: Some(100),
        };
        let cold_range = SyncWindow {
            kind: SyncWindowKind::LastWeek,
            ts_min_inclusive_ms: Some(100),
            ts_max_exclusive_ms: Some(200),
        };
        let key = live_suppression_key("/tmp/live-overlap.db", "tenant-a", "workspace-a");
        let (_origin_session, _) = open_live_suppression_session(
            "/tmp/live-overlap.db",
            "tenant-a",
            "workspace-a",
            "remote-a",
            false,
            hot_range,
            1,
        )
        .expect("open origin suppression session");
        let (mut overlapping_session, _) = open_live_suppression_session(
            "/tmp/live-overlap.db",
            "tenant-a",
            "workspace-a",
            "remote-b",
            false,
            hot_range,
            2,
        )
        .expect("open overlapping suppression session");
        let (mut non_overlapping_session, _) = open_live_suppression_session(
            "/tmp/live-overlap.db",
            "tenant-a",
            "workspace-a",
            "remote-c",
            false,
            cold_range,
            3,
        )
        .expect("open non-overlapping suppression session");
        let (mut other_workspace_session, _) = open_live_suppression_session(
            "/tmp/live-overlap.db",
            "tenant-a",
            "workspace-b",
            "remote-d",
            false,
            hot_range,
            4,
        )
        .expect("open other workspace suppression session");

        publish_live_suppression_event(&key, 1, [0x55; 32], 50);
        assert_eq!(
            overlapping_session
                .outbound_suppression_rx
                .try_recv()
                .unwrap(),
            [0x55; 32]
        );
        assert_eq!(
            non_overlapping_session
                .outbound_suppression_rx
                .try_recv()
                .unwrap(),
            [0x55; 32]
        );
        assert!(other_workspace_session
            .outbound_suppression_rx
            .try_recv()
            .is_err());
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
        for (created_at_ms, event_id, blob) in [
            (10, first_id, first_blob.as_slice()),
            (20, second_id, _second_blob.as_slice()),
            (30, third_id, third_blob.as_slice()),
        ] {
            insert_shared_event_index_entry_if_shared(
                &conn,
                ShareScope::Shared,
                created_at_ms,
                &event_id,
                "workspace-live-sender",
                blob,
            )
            .unwrap();
        }
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
        let (mut live_suppression, receive_state) = open_live_suppression_session(
            "/tmp/live-sender.db",
            "tenant-a",
            "workspace-live-sender",
            "remote-a",
            false,
            range,
            11,
        )
        .expect("open live suppression sender state");
        publish_live_suppression_event(&receive_state.key, 999, [0x88; 32], 20);
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
            &conn,
            &store,
            &mut data_send,
            &have_ids,
            "tenant-a",
            "workspace-live-sender",
            range,
            Some(&mut live_suppression),
        )
        .await
        .expect("send live suppression range");

        assert_eq!(events_sent, 2);
        assert_eq!(bytes_sent, (first_blob.len() + third_blob.len()) as u64);
        let send_state = send_state.lock().expect("mock send state");
        assert_eq!(send_state.raw_bytes.len(), 1);
        let mut raw_frames = Vec::new();
        for raw in &send_state.raw_bytes {
            let mut offset = 0usize;
            while offset < raw.len() {
                let (frame, consumed) = crate::protocol::parse_frame(&raw[offset..])
                    .expect("parse batched live suppression event frame");
                raw_frames.push(frame);
                offset += consumed;
            }
        }
        let expected_event_blobs = order_requested_ids_for_send(
            &conn,
            &store,
            "workspace-live-sender",
            range,
            &[first_id, second_id, third_id],
            Some("tenant-a"),
        )
        .unwrap()
        .into_iter()
        .filter_map(|event_id| {
            if event_id == first_id {
                Some(first_blob.clone())
            } else if event_id == third_id {
                Some(third_blob.clone())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
        let actual_event_blobs = raw_frames
            .into_iter()
            .map(|frame| match frame {
                Frame::Event { blob } => blob,
                other => panic!("expected batched event frame, got {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(actual_event_blobs, expected_event_blobs);
        assert!(
            send_state.flushes >= 2,
            "suppression and done frames should flush promptly"
        );
        assert_eq!(
            send_state.frames,
            vec![
                Frame::SuppressIds {
                    ids: vec![[0x88; 32]]
                },
                Frame::RangeDataDone,
            ]
        );
    }

    #[tokio::test]
    async fn live_receive_task_publishes_events_and_forwards_remote_suppressions() {
        let _env = EnvGuard::enable_live_suppression();
        let tmpdir = tempfile::tempdir().unwrap();
        let db_path = tmpdir.path().join("node.db");
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = crate::crypto::event_id_to_base64(&[0x71; 32]);
        let range = SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(0),
            ts_max_exclusive_ms: None,
        };
        let (mut sibling_session, _sibling_receive_state) = open_live_suppression_session(
            db_path.to_str().unwrap(),
            "tenant-a",
            &workspace_id,
            "remote-a",
            false,
            range,
            21,
        )
        .expect("open sibling suppression session");
        let (mut primary_session, primary_receive_state) = open_live_suppression_session(
            db_path.to_str().unwrap(),
            "tenant-a",
            &workspace_id,
            "remote-b",
            false,
            range,
            22,
        )
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
            workspace_id.clone(),
            range,
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
        assert!(result.pending_overlay.is_some());
        assert_eq!(
            load_shared_sync_entries_with_pending(
                &conn,
                db_path.to_str().unwrap(),
                &workspace_id,
                range
            )
            .unwrap(),
            vec![(40, event_id)]
        );
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
        crate::sync::session::receive_log::clear_pending_receive_overlay_session(
            result.pending_overlay.as_ref().unwrap(),
        );
    }
}
