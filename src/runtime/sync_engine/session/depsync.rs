use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};

use negentropy::{
    Bound, DepReconcileRangeStorage, Fingerprint, Id, Item, NegentropyStorageBase,
    NegentropyStorageVector,
};
use rusqlite::Connection;

use crate::crypto::{event_id_to_base64, EventId};
use crate::db::dep_index::list_shared_event_deps;
use crate::db::negentropy_cache::{sum_day_epochs, sum_week_epochs, workspace_dep_epoch};
use crate::db::store::Store;
use crate::sync::session::windowing::{SyncWindow, SyncWindowKind};

const CONTROL_PHASE1: u8 = 1;
const CONTROL_PHASE1_DONE: u8 = 2;
const CONTROL_DEP_CANDIDATE_CHUNK: u8 = 3;
const CONTROL_DEP_CANDIDATE_DONE: u8 = 4;
const CONTROL_PHASE2: u8 = 5;
const CONTROL_PHASE2_DONE: u8 = 6;
pub(crate) const DEP_CANDIDATE_CHUNK_SIZE: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DepSyncControlPayload {
    Phase1(Vec<u8>),
    Phase1Done,
    DepCandidateChunk(Vec<EventId>),
    DepCandidateDone,
    Phase2(Vec<u8>),
    Phase2Done,
}

#[derive(Debug)]
pub(crate) struct RangeDepStorage {
    roots: Vec<Item>,
    dep_search_enabled: bool,
    dep_candidate_closure_by_root: Arc<HashMap<EventId, Arc<Vec<EventId>>>>,
    present_dep_closure_by_root: Arc<HashMap<EventId, Arc<Vec<EventId>>>>,
    dep_candidate_slice_cache: Mutex<HashMap<(usize, usize), Arc<Vec<EventId>>>>,
    present_dep_slice_cache: Mutex<HashMap<(usize, usize), Arc<Vec<EventId>>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DepRangeStorageCacheKey {
    db_path: String,
    workspace_id: String,
    window_kind: SyncWindowKind,
}

#[derive(Debug, Clone)]
struct DepRangeStorageCacheEntry {
    epoch: u64,
    ts_min_inclusive_ms: Option<i64>,
    ts_max_exclusive_ms: Option<i64>,
    storage: Arc<RangeDepStorage>,
}

impl RangeDepStorage {
    #[allow(dead_code)]
    pub(crate) fn dep_ids(&self, begin: usize, end: usize) -> Result<Vec<Id>, negentropy::Error> {
        Ok(self
            .candidate_dep_ids_for_slice(begin, end)
            .iter()
            .map(|event_id| Id::from_byte_array(*event_id))
            .collect())
    }

    pub(crate) fn dep_candidate_ids_for_roots(&self, root_ids: &[EventId]) -> Vec<EventId> {
        if !self.dep_search_enabled {
            return Vec::new();
        }
        let selected_roots = root_ids.iter().copied().collect::<HashSet<_>>();
        let mut dep_ids = BTreeSet::new();
        for root_id in root_ids {
            if let Some(closure) = self.dep_candidate_closure_by_root.get(root_id) {
                for dep_id in closure.iter().copied() {
                    if !selected_roots.contains(&dep_id) {
                        dep_ids.insert(dep_id);
                    }
                }
            }
        }
        dep_ids.into_iter().collect()
    }

    fn combined_fingerprint_for_slice(
        &self,
        begin: usize,
        end: usize,
    ) -> Result<Fingerprint, negentropy::Error> {
        let root_ids = self.roots[begin..end].iter().map(|item| item.id);
        if !self.dep_search_enabled {
            return fingerprint_ids(root_ids);
        }
        let dep_ids_for_slice = self.present_dep_ids_for_slice(begin, end);
        let dep_ids = dep_ids_for_slice.iter().copied().map(Id::from_byte_array);
        fingerprint_ids(root_ids.chain(dep_ids))
    }

    fn candidate_dep_ids_for_slice(&self, begin: usize, end: usize) -> Arc<Vec<EventId>> {
        {
            let cache = self
                .dep_candidate_slice_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cached) = cache.get(&(begin, end)) {
                return cached.clone();
            }
        }

        let root_ids = self.roots[begin..end]
            .iter()
            .map(|item| item.id.to_bytes())
            .collect::<HashSet<_>>();
        let mut dep_ids = BTreeSet::new();
        for root in &self.roots[begin..end] {
            if let Some(closure) = self.dep_candidate_closure_by_root.get(&root.id.to_bytes()) {
                for dep_id in closure.iter().copied() {
                    if !root_ids.contains(&dep_id) {
                        dep_ids.insert(dep_id);
                    }
                }
            }
        }

        let dep_ids = Arc::new(dep_ids.into_iter().collect::<Vec<_>>());
        let mut cache = self
            .dep_candidate_slice_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.insert((begin, end), dep_ids.clone());
        dep_ids
    }

    fn present_dep_ids_for_slice(&self, begin: usize, end: usize) -> Arc<Vec<EventId>> {
        {
            let cache = self
                .present_dep_slice_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(cached) = cache.get(&(begin, end)) {
                return cached.clone();
            }
        }

        let root_ids = self.roots[begin..end]
            .iter()
            .map(|item| item.id.to_bytes())
            .collect::<HashSet<_>>();
        let mut dep_ids = BTreeSet::new();
        for root in &self.roots[begin..end] {
            if let Some(closure) = self.present_dep_closure_by_root.get(&root.id.to_bytes()) {
                for dep_id in closure.iter().copied() {
                    if !root_ids.contains(&dep_id) {
                        dep_ids.insert(dep_id);
                    }
                }
            }
        }

        let dep_ids = Arc::new(dep_ids.into_iter().collect::<Vec<_>>());
        let mut cache = self
            .present_dep_slice_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.insert((begin, end), dep_ids.clone());
        dep_ids
    }
}

impl DepReconcileRangeStorage for RangeDepStorage {
    fn root_size(&self) -> Result<usize, negentropy::Error> {
        Ok(self.roots.len())
    }

    fn get_root_item(&self, i: usize) -> Result<Option<Item>, negentropy::Error> {
        Ok(self.roots.get(i).copied())
    }

    fn find_lower_bound(&self, mut first: usize, last: usize, value: &Bound) -> usize {
        let mut count = last.saturating_sub(first);
        while count > 0 {
            let mut it = first;
            let step = count / 2;
            it += step;

            if self.roots[it] < value.item {
                it += 1;
                first = it;
                count -= step + 1;
            } else {
                count = step;
            }
        }

        first
    }

    fn combined_fingerprint(
        &self,
        begin: usize,
        end: usize,
    ) -> Result<Fingerprint, negentropy::Error> {
        self.combined_fingerprint_for_slice(begin, end)
    }

    fn root_ids(&self, begin: usize, end: usize) -> Result<Vec<Id>, negentropy::Error> {
        Ok(self.roots[begin..end].iter().map(|item| item.id).collect())
    }
}

pub(crate) fn build_range_dep_storage(
    conn: &Connection,
    _db_path: &str,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<Arc<RangeDepStorage>, String> {
    load_cached_range_dep_storage(conn, _db_path, workspace_id, range)
}

fn build_durable_range_dep_storage(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<RangeDepStorage, String> {
    let entries = load_shared_index_entries(conn, workspace_id, range)?;
    let dep_search_enabled = !matches!(range.kind, SyncWindowKind::Old);
    let mut direct_dep_cache = HashMap::<EventId, Vec<EventId>>::new();
    let mut candidate_closure_cache = HashMap::<EventId, Arc<Vec<EventId>>>::new();
    let mut present_closure_cache = HashMap::<EventId, Arc<Vec<EventId>>>::new();
    let mut shared_presence_cache = HashMap::<EventId, bool>::new();
    if dep_search_enabled {
        for (_, event_id) in &entries {
            let mut visiting = HashSet::new();
            let _ = compute_transitive_dep_closure(
                conn,
                workspace_id,
                *event_id,
                &mut direct_dep_cache,
                &mut candidate_closure_cache,
                &mut visiting,
            )?;
            let mut visiting = HashSet::new();
            let _ = compute_present_transitive_dep_closure(
                conn,
                workspace_id,
                *event_id,
                &mut direct_dep_cache,
                &mut present_closure_cache,
                &mut shared_presence_cache,
                &mut visiting,
            )?;
        }
    }

    let roots = entries
        .iter()
        .map(|(created_at_ms, event_id)| {
            Item::with_timestamp_and_id(
                (*created_at_ms).max(0) as u64,
                Id::from_byte_array(*event_id),
            )
        })
        .collect::<Vec<_>>();

    Ok(RangeDepStorage {
        roots,
        dep_search_enabled,
        dep_candidate_closure_by_root: Arc::new(candidate_closure_cache),
        present_dep_closure_by_root: Arc::new(present_closure_cache),
        dep_candidate_slice_cache: Mutex::new(HashMap::new()),
        present_dep_slice_cache: Mutex::new(HashMap::new()),
    })
}

pub(crate) fn build_candidate_storage(
    store: &Store<'_>,
    candidate_universe: &[EventId],
) -> Result<NegentropyStorageVector, String> {
    let created_at_by_id = store
        .get_shared_created_at_batch(candidate_universe)
        .map_err(|e| format!("load dep candidate created_at batch: {e}"))?;
    let mut entries = created_at_by_id.into_iter().collect::<Vec<_>>();
    entries.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));

    let mut storage = NegentropyStorageVector::with_capacity(entries.len());
    for (event_id, created_at_ms) in entries {
        storage
            .insert(created_at_ms.max(0) as u64, Id::from_byte_array(event_id))
            .map_err(|e| format!("insert phase2 dep candidate item: {e}"))?;
    }
    storage
        .seal()
        .map_err(|e| format!("seal phase2 dep candidate storage: {e}"))?;
    Ok(storage)
}

pub(crate) fn encode_dep_sync_control(payload: &DepSyncControlPayload) -> Vec<u8> {
    match payload {
        DepSyncControlPayload::Phase1(msg) => encode_control_bytes(CONTROL_PHASE1, msg),
        DepSyncControlPayload::Phase1Done => vec![CONTROL_PHASE1_DONE],
        DepSyncControlPayload::DepCandidateChunk(ids) => {
            let mut out = Vec::with_capacity(1 + 4 + (ids.len() * 32));
            out.push(CONTROL_DEP_CANDIDATE_CHUNK);
            out.extend((ids.len() as u32).to_le_bytes());
            for event_id in ids {
                out.extend(event_id);
            }
            out
        }
        DepSyncControlPayload::DepCandidateDone => vec![CONTROL_DEP_CANDIDATE_DONE],
        DepSyncControlPayload::Phase2(msg) => encode_control_bytes(CONTROL_PHASE2, msg),
        DepSyncControlPayload::Phase2Done => vec![CONTROL_PHASE2_DONE],
    }
}

pub(crate) fn decode_dep_sync_control(msg: &[u8]) -> Result<DepSyncControlPayload, String> {
    let Some(tag) = msg.first().copied() else {
        return Err("empty dep-sync control payload".to_string());
    };
    match tag {
        CONTROL_PHASE1 => Ok(DepSyncControlPayload::Phase1(msg[1..].to_vec())),
        CONTROL_PHASE1_DONE => Ok(DepSyncControlPayload::Phase1Done),
        CONTROL_DEP_CANDIDATE_CHUNK => {
            if msg.len() < 5 {
                return Err("dep candidate chunk truncated".to_string());
            }
            let count = u32::from_le_bytes(
                msg[1..5]
                    .try_into()
                    .map_err(|_| "dep candidate count truncated".to_string())?,
            ) as usize;
            let expected_len = 5 + (count * 32);
            if msg.len() != expected_len {
                return Err(format!(
                    "dep candidate chunk length mismatch: expected {} bytes, got {}",
                    expected_len,
                    msg.len()
                ));
            }
            let mut ids = Vec::with_capacity(count);
            for chunk in msg[5..].chunks(32) {
                let mut event_id = [0u8; 32];
                event_id.copy_from_slice(chunk);
                ids.push(event_id);
            }
            Ok(DepSyncControlPayload::DepCandidateChunk(ids))
        }
        CONTROL_DEP_CANDIDATE_DONE => Ok(DepSyncControlPayload::DepCandidateDone),
        CONTROL_PHASE2 => Ok(DepSyncControlPayload::Phase2(msg[1..].to_vec())),
        CONTROL_PHASE2_DONE => Ok(DepSyncControlPayload::Phase2Done),
        other => Err(format!("unsupported dep-sync control tag {}", other)),
    }
}

pub(crate) fn chunk_event_ids(ids: &[EventId], chunk_size: usize) -> Vec<Vec<EventId>> {
    ids.chunks(chunk_size).map(|chunk| chunk.to_vec()).collect()
}

fn encode_control_bytes(tag: u8, msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + msg.len());
    out.push(tag);
    out.extend_from_slice(msg);
    out
}

fn fingerprint_ids(ids: impl Iterator<Item = Id>) -> Result<Fingerprint, negentropy::Error> {
    let ids = ids.collect::<Vec<_>>();
    let mut storage = NegentropyStorageVector::with_capacity(ids.len());
    for (idx, id) in ids.iter().enumerate() {
        storage.insert(idx as u64, *id)?;
    }
    storage.seal()?;
    storage.fingerprint(0, storage.size()?)
}

fn compute_transitive_dep_closure(
    conn: &Connection,
    workspace_id: &str,
    event_id: EventId,
    direct_dep_cache: &mut HashMap<EventId, Vec<EventId>>,
    closure_cache: &mut HashMap<EventId, Arc<Vec<EventId>>>,
    visiting: &mut HashSet<EventId>,
) -> Result<Arc<Vec<EventId>>, String> {
    if let Some(cached) = closure_cache.get(&event_id) {
        return Ok(cached.clone());
    }
    if !visiting.insert(event_id) {
        return Ok(Arc::new(Vec::new()));
    }

    let direct_deps = if let Some(cached) = direct_dep_cache.get(&event_id) {
        cached.clone()
    } else {
        let deps = list_shared_event_deps(conn, workspace_id, &event_id)
            .map_err(|e| format!("load shared deps for {}: {e}", hex::encode(event_id)))?;
        direct_dep_cache.insert(event_id, deps.clone());
        deps
    };

    let mut closure = BTreeSet::new();
    for dep_id in direct_deps {
        closure.insert(dep_id);
        let nested = compute_transitive_dep_closure(
            conn,
            workspace_id,
            dep_id,
            direct_dep_cache,
            closure_cache,
            visiting,
        )?;
        for nested_dep in nested.iter().copied() {
            closure.insert(nested_dep);
        }
    }

    visiting.remove(&event_id);
    let closure = Arc::new(closure.into_iter().collect::<Vec<_>>());
    closure_cache.insert(event_id, closure.clone());
    Ok(closure)
}

fn compute_present_transitive_dep_closure(
    conn: &Connection,
    workspace_id: &str,
    event_id: EventId,
    direct_dep_cache: &mut HashMap<EventId, Vec<EventId>>,
    closure_cache: &mut HashMap<EventId, Arc<Vec<EventId>>>,
    shared_presence_cache: &mut HashMap<EventId, bool>,
    visiting: &mut HashSet<EventId>,
) -> Result<Arc<Vec<EventId>>, String> {
    if let Some(cached) = closure_cache.get(&event_id) {
        return Ok(cached.clone());
    }
    if !visiting.insert(event_id) {
        return Ok(Arc::new(Vec::new()));
    }

    let direct_deps = if let Some(cached) = direct_dep_cache.get(&event_id) {
        cached.clone()
    } else {
        let deps = list_shared_event_deps(conn, workspace_id, &event_id)
            .map_err(|e| format!("load shared deps for {}: {e}", hex::encode(event_id)))?;
        direct_dep_cache.insert(event_id, deps.clone());
        deps
    };

    let mut closure = BTreeSet::new();
    for dep_id in direct_deps {
        if !shared_event_present_locally(conn, dep_id, shared_presence_cache)? {
            continue;
        }
        closure.insert(dep_id);
        let nested = compute_present_transitive_dep_closure(
            conn,
            workspace_id,
            dep_id,
            direct_dep_cache,
            closure_cache,
            shared_presence_cache,
            visiting,
        )?;
        for nested_dep in nested.iter().copied() {
            closure.insert(nested_dep);
        }
    }

    visiting.remove(&event_id);
    let closure = Arc::new(closure.into_iter().collect::<Vec<_>>());
    closure_cache.insert(event_id, closure.clone());
    Ok(closure)
}

fn shared_event_present_locally(
    conn: &Connection,
    event_id: EventId,
    shared_presence_cache: &mut HashMap<EventId, bool>,
) -> Result<bool, String> {
    if let Some(cached) = shared_presence_cache.get(&event_id) {
        return Ok(*cached);
    }
    let present: bool = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM events
                 WHERE event_id = ?1
                   AND share_scope = 'shared'
             )",
            rusqlite::params![event_id_to_base64(&event_id)],
            |row| row.get(0),
        )
        .map_err(|e| {
            format!(
                "load shared event presence for {}: {e}",
                hex::encode(event_id)
            )
        })?;
    shared_presence_cache.insert(event_id, present);
    Ok(present)
}

fn dep_range_storage_cache(
) -> &'static Mutex<HashMap<DepRangeStorageCacheKey, DepRangeStorageCacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<DepRangeStorageCacheKey, DepRangeStorageCacheEntry>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn dep_range_storage_cache_key(
    db_path: &str,
    workspace_id: &str,
    range: SyncWindow,
) -> DepRangeStorageCacheKey {
    DepRangeStorageCacheKey {
        db_path: db_path.to_string(),
        workspace_id: workspace_id.to_string(),
        window_kind: range.kind,
    }
}

fn current_range_epoch(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<u64, String> {
    let dep_epoch = workspace_dep_epoch(conn, workspace_id)
        .map_err(|e| format!("load dep-sync dep epoch: {e}"))?;
    let Some(ts_max_exclusive_ms) = range.ts_max_exclusive() else {
        return Ok(dep_epoch);
    };
    let base_epoch = match range.kind {
        SyncWindowKind::LastDay | SyncWindowKind::LastWeek => {
            let Some(ts_min_inclusive_ms) = range.ts_min() else {
                return Ok(dep_epoch);
            };
            sum_day_epochs(conn, workspace_id, ts_min_inclusive_ms, ts_max_exclusive_ms)
                .map_err(|e| format!("load dep-sync day epochs: {e}"))
        }
        SyncWindowKind::LastTwelveWeeks => {
            sum_week_epochs(conn, workspace_id, range.ts_min(), ts_max_exclusive_ms)
                .map_err(|e| format!("load dep-sync twelve-week epochs: {e}"))
        }
        SyncWindowKind::Old => sum_week_epochs(conn, workspace_id, None, ts_max_exclusive_ms)
            .map_err(|e| format!("load dep-sync old epochs: {e}")),
    }?;
    Ok(base_epoch.saturating_add(dep_epoch))
}

fn cached_dep_storage_matches(
    entry: &DepRangeStorageCacheEntry,
    range: SyncWindow,
    epoch: u64,
) -> bool {
    entry.epoch == epoch
        && entry.ts_min_inclusive_ms == range.ts_min()
        && entry.ts_max_exclusive_ms == range.ts_max_exclusive()
}

fn load_cached_range_dep_storage(
    conn: &Connection,
    db_path: &str,
    workspace_id: &str,
    range: SyncWindow,
) -> Result<Arc<RangeDepStorage>, String> {
    let epoch = current_range_epoch(conn, workspace_id, range)?;
    let key = dep_range_storage_cache_key(db_path, workspace_id, range);
    {
        let cache = dep_range_storage_cache()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(entry) = cache.get(&key) {
            if cached_dep_storage_matches(entry, range, epoch) {
                return Ok(entry.storage.clone());
            }
        }
    }

    let storage = Arc::new(build_durable_range_dep_storage(conn, workspace_id, range)?);
    let mut cache = dep_range_storage_cache()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(entry) = cache.get(&key) {
        if cached_dep_storage_matches(entry, range, epoch) {
            return Ok(entry.storage.clone());
        }
    }
    cache.insert(
        key,
        DepRangeStorageCacheEntry {
            epoch,
            ts_min_inclusive_ms: range.ts_min(),
            ts_max_exclusive_ms: range.ts_max_exclusive(),
            storage: storage.clone(),
        },
    );
    Ok(storage)
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
        .map_err(|e| format!("prepare dep-sync shared index query: {e}"))?;
    let mut rows = stmt
        .query(rusqlite::params![
            workspace_id,
            range.ts_min(),
            range.ts_max_exclusive()
        ])
        .map_err(|e| format!("query dep-sync shared index rows: {e}"))?;

    while let Some(row) = rows
        .next()
        .map_err(|e| format!("iterate dep-sync shared index rows: {e}"))?
    {
        let created_at_ms: i64 = row
            .get(0)
            .map_err(|e| format!("read dep-sync shared index ts: {e}"))?;
        let id_blob: Vec<u8> = row
            .get(1)
            .map_err(|e| format!("read dep-sync shared index id: {e}"))?;
        if id_blob.len() != 32 {
            continue;
        }
        let mut event_id = [0u8; 32];
        event_id.copy_from_slice(&id_blob);
        entries.push((created_at_ms, event_id));
    }

    Ok(entries)
}
