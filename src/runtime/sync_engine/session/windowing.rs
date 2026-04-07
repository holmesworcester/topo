use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::tuning::low_mem_mode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncWindowKind {
    Full = 0,
    LastDay = 1,
    LastWeek = 2,
    LastTwelveWeeks = 3,
}

pub fn encode_sync_window_kind(kind: SyncWindowKind) -> u8 {
    kind as u8
}

pub fn decode_sync_window_kind(kind: u8) -> Result<SyncWindowKind, String> {
    match kind {
        0 => Ok(SyncWindowKind::Full),
        1 => Ok(SyncWindowKind::LastDay),
        2 => Ok(SyncWindowKind::LastWeek),
        3 => Ok(SyncWindowKind::LastTwelveWeeks),
        other => Err(format!("unsupported sync window kind {}", other)),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncWindow {
    pub kind: SyncWindowKind,
    pub ts_min_inclusive_ms: Option<i64>,
    pub ts_max_exclusive_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncTask {
    pub window: SyncWindow,
    pub shard_min_inclusive: u16,
    pub shard_max_exclusive: u16,
}

impl SyncTask {
    pub const fn full_window(window: SyncWindow) -> Self {
        Self {
            window,
            shard_min_inclusive: 0,
            shard_max_exclusive: VIRTUAL_SHARD_COUNT,
        }
    }

    pub fn shard_span(self) -> u16 {
        self.shard_max_exclusive
            .saturating_sub(self.shard_min_inclusive)
    }
}

const WINDOW_MAGIC: &[u8; 4] = b"P7SW";
const WINDOW_VERSION_LEGACY: u8 = 3;
const WINDOW_VERSION: u8 = 4;
const NONE_TS_SENTINEL: i64 = i64::MIN;
const ALL_START_MS: i64 = 0;
const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const WEEK_MS: i64 = 7 * DAY_MS;
const TWELVE_WEEK_MS: i64 = 12 * WEEK_MS;
pub const VIRTUAL_SHARD_COUNT: u16 = 256;
const LAST_DAY_SHARD_SPAN: u16 = VIRTUAL_SHARD_COUNT;
const LAST_WEEK_SHARD_SPAN: u16 = 8;
const COLD_SHARD_SPAN: u16 = 4;
const LAST_DAY_TAKEOVER_BASE_MS: i64 = 2_000;
const LAST_WEEK_TAKEOVER_BASE_MS: i64 = 30_000;
const LAST_TWELVE_WEEKS_TAKEOVER_BASE_MS: i64 = 120_000;
const FULL_TAKEOVER_BASE_MS: i64 = 300_000;
const DEFAULT_WINDOW_ORDER: [SyncWindowKind; 4] = [
    SyncWindowKind::LastDay,
    SyncWindowKind::LastWeek,
    SyncWindowKind::LastTwelveWeeks,
    SyncWindowKind::Full,
];
const LOW_MEM_WINDOW_ORDER: [SyncWindowKind; 2] =
    [SyncWindowKind::LastDay, SyncWindowKind::LastWeek];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlannerState {
    next_hot_idx: usize,
    next_cold_idx: usize,
    prefer_hot_next: bool,
    cycle_anchor_now_ms: Option<i64>,
    restrict_to_low_mem_windows: bool,
}

fn planner_state() -> &'static Mutex<HashMap<String, PlannerState>> {
    static STATE: OnceLock<Mutex<HashMap<String, PlannerState>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn planner_key(db_path: &str, recorded_by: &str, peer_id: &str) -> String {
    format!("{db_path}|{recorded_by}|{peer_id}")
}

fn state_for<'a>(
    state: &'a mut HashMap<String, PlannerState>,
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
) -> &'a mut PlannerState {
    state
        .entry(planner_key(db_path, recorded_by, peer_id))
        .or_insert(PlannerState {
            next_hot_idx: 0,
            next_cold_idx: 0,
            prefer_hot_next: true,
            cycle_anchor_now_ms: None,
            restrict_to_low_mem_windows: false,
        })
}

fn planner_order(planner: &PlannerState) -> &'static [SyncWindowKind] {
    if low_mem_mode() || planner.restrict_to_low_mem_windows {
        &LOW_MEM_WINDOW_ORDER
    } else {
        &DEFAULT_WINDOW_ORDER
    }
}

fn shard_group_span(kind: SyncWindowKind) -> u16 {
    match kind {
        SyncWindowKind::LastDay => LAST_DAY_SHARD_SPAN,
        SyncWindowKind::LastWeek => LAST_WEEK_SHARD_SPAN,
        SyncWindowKind::LastTwelveWeeks | SyncWindowKind::Full => COLD_SHARD_SPAN,
    }
}

fn task_count_for_kind(kind: SyncWindowKind) -> usize {
    (VIRTUAL_SHARD_COUNT / shard_group_span(kind)) as usize
}

fn hot_task_offset_for_pair(local_peer_id: &str, remote_peer_id: &str, anchor_now_ms: i64) -> usize {
    let hot_task_count = task_count_for_kind(SyncWindowKind::LastDay).max(1);
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"poc7-hot-task-offset-v2");
    hasher.update(local_peer_id.as_bytes());
    hasher.update(b":");
    hasher.update(remote_peer_id.as_bytes());
    hasher.update(b":");
    hasher.update(&anchor_now_ms.to_le_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    (u64::from_le_bytes(bytes) % hot_task_count as u64) as usize
}

fn takeover_base_delay_ms(kind: SyncWindowKind) -> i64 {
    match kind {
        SyncWindowKind::LastDay => LAST_DAY_TAKEOVER_BASE_MS,
        SyncWindowKind::LastWeek => LAST_WEEK_TAKEOVER_BASE_MS,
        SyncWindowKind::LastTwelveWeeks => LAST_TWELVE_WEEKS_TAKEOVER_BASE_MS,
        SyncWindowKind::Full => FULL_TAKEOVER_BASE_MS,
    }
}

fn tasks_for_window(window: SyncWindow) -> Vec<SyncTask> {
    let span = shard_group_span(window.kind);
    (0..VIRTUAL_SHARD_COUNT)
        .step_by(span as usize)
        .map(|shard_min| SyncTask {
            window,
            shard_min_inclusive: shard_min,
            shard_max_exclusive: shard_min + span,
        })
        .collect()
}

fn planned_hot_tasks(now_ms: i64, local_peer_id: &str, remote_peer_id: &str) -> Vec<SyncTask> {
    let mut tasks = tasks_for_window(window_for_kind(SyncWindowKind::LastDay, now_ms));
    if tasks.len() > 1 {
        tasks.rotate_left(hot_task_offset_for_pair(local_peer_id, remote_peer_id, now_ms));
    }
    tasks
}

fn planned_cold_tasks(planner: &PlannerState, now_ms: i64) -> Vec<SyncTask> {
    planner_order(planner)
        .iter()
        .filter(|kind| !is_hot_window(**kind))
        .flat_map(|kind| tasks_for_window(window_for_kind(*kind, now_ms)))
        .collect()
}

fn task_identity_bytes(task: SyncTask) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 8 + 8 + 2 + 2);
    out.push(task.window.kind as u8);
    out.extend_from_slice(
        &task
            .window
            .ts_min_inclusive_ms
            .unwrap_or(NONE_TS_SENTINEL)
            .to_le_bytes(),
    );
    out.extend_from_slice(
        &task
            .window
            .ts_max_exclusive_ms
            .unwrap_or(NONE_TS_SENTINEL)
            .to_le_bytes(),
    );
    out.extend_from_slice(&task.shard_min_inclusive.to_le_bytes());
    out.extend_from_slice(&task.shard_max_exclusive.to_le_bytes());
    out
}

fn task_owner_score(task: SyncTask, peer_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&task_identity_bytes(task));
    hasher.update(peer_id.as_bytes());
    *hasher.finalize().as_bytes()
}

fn normalized_live_peers(peer_id: &str, live_peer_ids: &[String]) -> Vec<String> {
    let mut peers = live_peer_ids.to_vec();
    if !peers.iter().any(|candidate| candidate == peer_id) {
        peers.push(peer_id.to_string());
    }
    peers.sort();
    peers.dedup();
    peers
}

fn task_owner_rank(task: SyncTask, peer_id: &str, live_peer_ids: &[String]) -> Option<usize> {
    let peers = normalized_live_peers(peer_id, live_peer_ids);
    let mut ranked: Vec<([u8; 32], &str)> = peers
        .iter()
        .map(|candidate| (task_owner_score(task, candidate), candidate.as_str()))
        .collect();
    ranked.sort_by(|(left_score, left_peer), (right_score, right_peer)| {
        right_score
            .cmp(left_score)
            .then_with(|| left_peer.cmp(right_peer))
    });
    ranked
        .iter()
        .position(|(_, candidate)| *candidate == peer_id)
}

fn task_takeover_delay_ms(task: SyncTask, rank: usize) -> i64 {
    takeover_base_delay_ms(task.window.kind).saturating_mul(rank as i64)
}

fn task_is_eligible_for_peer(
    task: SyncTask,
    peer_id: &str,
    live_peer_ids: &[String],
    elapsed_ms: i64,
) -> bool {
    if is_hot_window(task.window.kind) {
        return true;
    }
    let Some(rank) = task_owner_rank(task, peer_id, live_peer_ids) else {
        return false;
    };
    elapsed_ms >= task_takeover_delay_ms(task, rank)
}

pub fn reset_outbound_window_state(db_path: &str, recorded_by: &str, peer_id: &str) {
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.remove(&planner_key(db_path, recorded_by, peer_id));
}

pub fn prime_outbound_window_kind(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    kind: SyncWindowKind,
) {
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let planner = state_for(&mut state, db_path, recorded_by, peer_id);
    planner.cycle_anchor_now_ms = None;
    planner.next_hot_idx = 0;
    planner.next_cold_idx = 0;
    planner.prefer_hot_next = is_hot_window(kind);
    if !is_hot_window(kind) {
        let cold_tasks = planned_cold_tasks(planner, 0);
        planner.next_cold_idx = cold_tasks
            .iter()
            .position(|task| task.window.kind == kind)
            .unwrap_or(0);
    }
}

pub fn select_outbound_task(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    live_peer_ids: &[String],
    now_ms: i64,
) -> SyncTask {
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let planner = state_for(&mut state, db_path, recorded_by, peer_id);
    let anchor_now_ms = *planner.cycle_anchor_now_ms.get_or_insert(now_ms);
    let hot_tasks = planned_hot_tasks(anchor_now_ms, recorded_by, peer_id);
    let cold_tasks = planned_cold_tasks(planner, anchor_now_ms);
    let elapsed_ms = now_ms.saturating_sub(anchor_now_ms);
    let hot_task = hot_tasks
        .get(planner.next_hot_idx % hot_tasks.len().max(1))
        .copied();
    let cold_task = (0..cold_tasks.len())
        .find_map(|offset| {
            let idx = (planner.next_cold_idx + offset) % cold_tasks.len();
            let task = cold_tasks[idx];
            task_is_eligible_for_peer(task, peer_id, live_peer_ids, elapsed_ms).then_some(task)
        });

    let selected = if planner.prefer_hot_next {
        hot_task.or(cold_task)
    } else {
        cold_task.or(hot_task)
    }
    .unwrap_or_else(|| panic!("planner produced no outbound sync tasks"));

    planner.prefer_hot_next = !is_hot_window(selected.window.kind);
    selected
}

pub fn mark_outbound_task_completed(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    task: SyncTask,
) {
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let planner = state_for(&mut state, db_path, recorded_by, peer_id);
    let anchor_now_ms = planner
        .cycle_anchor_now_ms
        .unwrap_or_else(|| task.window.ts_max_exclusive_ms.unwrap_or(0));
    let hot_tasks = planned_hot_tasks(anchor_now_ms, recorded_by, peer_id);
    let cold_tasks = planned_cold_tasks(planner, anchor_now_ms);

    if let Some(idx) = hot_tasks.iter().position(|candidate| *candidate == task) {
        planner.next_hot_idx = (idx + 1) % hot_tasks.len().max(1);
        if planner.next_hot_idx == 0 && cold_tasks.is_empty() {
            planner.cycle_anchor_now_ms = None;
        }
        return;
    }

    if let Some(idx) = cold_tasks.iter().position(|candidate| *candidate == task) {
        planner.next_cold_idx = (idx + 1) % cold_tasks.len().max(1);
        if planner.next_cold_idx == 0 {
            planner.cycle_anchor_now_ms = None;
        }
        return;
    }

    planner.prefer_hot_next = true;
    planner.cycle_anchor_now_ms = None;
}

pub fn restrict_outbound_windows_to_last_week(db_path: &str, recorded_by: &str, peer_id: &str) {
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let planner = state_for(&mut state, db_path, recorded_by, peer_id);
    planner.restrict_to_low_mem_windows = true;
    planner.next_hot_idx = 0;
    planner.next_cold_idx = 0;
    planner.prefer_hot_next = true;
    planner.cycle_anchor_now_ms = None;
}

fn window_for_kind(kind: SyncWindowKind, now_ms: i64) -> SyncWindow {
    match kind {
        SyncWindowKind::Full => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(ALL_START_MS),
            ts_max_exclusive_ms: Some(now_ms - TWELVE_WEEK_MS),
        },
        SyncWindowKind::LastDay => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(now_ms - DAY_MS),
            ts_max_exclusive_ms: None,
        },
        SyncWindowKind::LastWeek => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(now_ms - WEEK_MS),
            ts_max_exclusive_ms: Some(now_ms - DAY_MS),
        },
        SyncWindowKind::LastTwelveWeeks => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(now_ms - TWELVE_WEEK_MS),
            ts_max_exclusive_ms: Some(now_ms - WEEK_MS),
        },
    }
}

pub fn is_hot_window(kind: SyncWindowKind) -> bool {
    matches!(kind, SyncWindowKind::LastDay)
}

pub fn is_priority_ingest_window(kind: SyncWindowKind) -> bool {
    is_hot_window(kind)
}

pub fn is_low_mem_allowed_window(kind: SyncWindowKind) -> bool {
    matches!(kind, SyncWindowKind::LastDay | SyncWindowKind::LastWeek)
}

impl SyncWindow {
    pub fn ts_min(self) -> Option<i64> {
        self.ts_min_inclusive_ms
    }

    pub fn ts_max_exclusive(self) -> Option<i64> {
        self.ts_max_exclusive_ms
    }
}

pub fn encode_initial_neg_open(window: SyncWindow, inner: Vec<u8>) -> Vec<u8> {
    encode_initial_neg_open_task(SyncTask::full_window(window), inner)
}

pub fn encode_initial_neg_open_task(task: SyncTask, inner: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 1 + 8 + 8 + 2 + 2 + inner.len());
    out.extend_from_slice(WINDOW_MAGIC);
    out.push(WINDOW_VERSION);
    out.push(task.window.kind as u8);
    out.extend_from_slice(
        &task
            .window
            .ts_min_inclusive_ms
            .unwrap_or(NONE_TS_SENTINEL)
            .to_le_bytes(),
    );
    out.extend_from_slice(
        &task
            .window
            .ts_max_exclusive_ms
            .unwrap_or(NONE_TS_SENTINEL)
            .to_le_bytes(),
    );
    out.extend_from_slice(&task.shard_min_inclusive.to_le_bytes());
    out.extend_from_slice(&task.shard_max_exclusive.to_le_bytes());
    out.extend_from_slice(&inner);
    out
}

pub fn decode_initial_neg_open(msg: &[u8]) -> Result<(SyncTask, &[u8]), String> {
    if msg.len() < 22 || &msg[..4] != WINDOW_MAGIC {
        return Ok((
            SyncTask::full_window(SyncWindow {
                kind: SyncWindowKind::Full,
                ts_min_inclusive_ms: None,
                ts_max_exclusive_ms: None,
            }),
            msg,
        ));
    }

    let version = msg[4];
    if version != WINDOW_VERSION && version != WINDOW_VERSION_LEGACY {
        return Err(format!("unsupported sync window version {}", version));
    }
    let kind = decode_sync_window_kind(msg[5])?;
    let ts_min = i64::from_le_bytes(
        msg[6..14]
            .try_into()
            .map_err(|_| "sync window min header truncated".to_string())?,
    );
    let ts_max = i64::from_le_bytes(
        msg[14..22]
            .try_into()
            .map_err(|_| "sync window max header truncated".to_string())?,
    );
    let window = SyncWindow {
        kind,
        ts_min_inclusive_ms: (ts_min != NONE_TS_SENTINEL).then_some(ts_min),
        ts_max_exclusive_ms: (ts_max != NONE_TS_SENTINEL).then_some(ts_max),
    };
    if version == WINDOW_VERSION_LEGACY {
        return Ok((SyncTask::full_window(window), &msg[22..]));
    }
    if msg.len() < 26 {
        return Err("sync task shard header truncated".to_string());
    }
    let shard_min_inclusive = u16::from_le_bytes(
        msg[22..24]
            .try_into()
            .map_err(|_| "sync task shard min header truncated".to_string())?,
    );
    let shard_max_exclusive = u16::from_le_bytes(
        msg[24..26]
            .try_into()
            .map_err(|_| "sync task shard max header truncated".to_string())?,
    );
    if shard_min_inclusive >= shard_max_exclusive || shard_max_exclusive > VIRTUAL_SHARD_COUNT {
        return Err(format!(
            "invalid sync task shard range {}..{}",
            shard_min_inclusive, shard_max_exclusive
        ));
    }
    Ok((
        SyncTask {
            window,
            shard_min_inclusive,
            shard_max_exclusive,
        },
        &msg[26..],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EnvGuard {
        prev_low_mem_ios: Option<String>,
    }

    impl EnvGuard {
        fn enable_low_mem_ios() -> Self {
            let prev_low_mem_ios = std::env::var("LOW_MEM_IOS").ok();
            std::env::set_var("LOW_MEM_IOS", "1");
            Self { prev_low_mem_ios }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev_low_mem_ios {
                Some(v) => std::env::set_var("LOW_MEM_IOS", v),
                None => std::env::remove_var("LOW_MEM_IOS"),
            }
        }
    }

    #[test]
    fn task_scheduler_drains_all_last_day_shard_groups_before_older_ranges() {
        let db_path = "/tmp/window-round-robin";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);

        let hot_task_count = task_count_for_kind(SyncWindowKind::LastDay);
        let tasks: Vec<SyncTask> = (0..(hot_task_count + 2))
            .map(|_| {
                let task =
                    select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
                mark_outbound_task_completed(db_path, recorded_by, peer_id, task);
                task
            })
            .collect();

        assert!(tasks[..hot_task_count].iter().all(|task| {
            task.window.kind == SyncWindowKind::LastDay && task.shard_span() == LAST_DAY_SHARD_SPAN
        }));
        let hot_groups: std::collections::BTreeSet<u16> = tasks[..hot_task_count]
            .iter()
            .map(|task| task.shard_min_inclusive)
            .collect();
        let expected_hot_groups: std::collections::BTreeSet<u16> =
            (0..VIRTUAL_SHARD_COUNT).step_by(LAST_DAY_SHARD_SPAN as usize).collect();
        assert_eq!(hot_groups, expected_hot_groups);
        assert_eq!(tasks[hot_task_count].window.kind, SyncWindowKind::LastWeek);
        assert_eq!(tasks[hot_task_count].shard_span(), LAST_WEEK_SHARD_SPAN);
    }

    #[test]
    fn task_scheduler_revisits_hot_after_each_cold_step() {
        let db_path = "/tmp/window-hot-revisit";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);

        for _ in 0..task_count_for_kind(SyncWindowKind::LastDay) {
            let hot = select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
            assert_eq!(hot.window.kind, SyncWindowKind::LastDay);
            mark_outbound_task_completed(db_path, recorded_by, peer_id, hot);
        }

        let cold = select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
        assert_ne!(cold.window.kind, SyncWindowKind::LastDay);
        mark_outbound_task_completed(db_path, recorded_by, peer_id, cold);

        let hot_again =
            select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
        assert_eq!(hot_again.window.kind, SyncWindowKind::LastDay);
    }

    #[test]
    fn task_scheduler_revisits_hot_even_without_cold_completion() {
        let db_path = "/tmp/window-hot-no-cold-complete";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);

        let hot = select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
        assert_eq!(hot.window.kind, SyncWindowKind::LastDay);
        mark_outbound_task_completed(db_path, recorded_by, peer_id, hot);

        let cold = select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
        assert_ne!(cold.window.kind, SyncWindowKind::LastDay);

        let hot_again =
            select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
        assert_eq!(hot_again.window.kind, SyncWindowKind::LastDay);
    }

    #[test]
    fn lowmem_task_scheduler_emits_only_day_and_week_groups() {
        let _env = EnvGuard::enable_low_mem_ios();
        let db_path = "/tmp/window-round-robin-lowmem";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);

        let tasks: Vec<SyncTask> = (0..20)
            .map(|_| {
                let task = select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
                mark_outbound_task_completed(db_path, recorded_by, peer_id, task);
                task
            })
            .collect();

        assert!(tasks.iter().all(|task| {
            matches!(task.window.kind, SyncWindowKind::LastDay | SyncWindowKind::LastWeek)
        }));
    }

    #[test]
    fn peer_restricted_to_lowmem_windows_emits_only_day_and_week_groups() {
        let db_path = "/tmp/window-round-robin-remote-lowmem";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);
        restrict_outbound_windows_to_last_week(db_path, recorded_by, peer_id);

        let tasks: Vec<SyncTask> = (0..20)
            .map(|_| {
                let task = select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
                mark_outbound_task_completed(db_path, recorded_by, peer_id, task);
                task
            })
            .collect();

        assert!(tasks.iter().all(|task| {
            matches!(task.window.kind, SyncWindowKind::LastDay | SyncWindowKind::LastWeek)
        }));
    }

    #[test]
    fn scheduler_uses_adjacent_non_full_windows() {
        let day = window_for_kind(SyncWindowKind::LastDay, 1_000_000);
        let week = window_for_kind(SyncWindowKind::LastWeek, 1_000_000);
        let twelve_weeks = window_for_kind(SyncWindowKind::LastTwelveWeeks, 1_000_000);
        let full = window_for_kind(SyncWindowKind::Full, 1_000_000);

        assert_eq!(day.ts_min(), Some(1_000_000 - DAY_MS));
        assert_eq!(day.ts_max_exclusive(), None);

        assert_eq!(week.ts_min(), Some(1_000_000 - WEEK_MS));
        assert_eq!(week.ts_max_exclusive(), Some(1_000_000 - DAY_MS));

        assert_eq!(twelve_weeks.ts_min(), Some(1_000_000 - TWELVE_WEEK_MS));
        assert_eq!(twelve_weeks.ts_max_exclusive(), Some(1_000_000 - WEEK_MS));

        assert_eq!(full.ts_min(), Some(ALL_START_MS));
        assert_eq!(full.ts_max_exclusive(), Some(1_000_000 - TWELVE_WEEK_MS));
    }

    #[test]
    fn lowmem_allows_only_day_and_week_windows() {
        assert!(is_low_mem_allowed_window(SyncWindowKind::LastDay));
        assert!(is_low_mem_allowed_window(SyncWindowKind::LastWeek));
        assert!(!is_low_mem_allowed_window(SyncWindowKind::LastTwelveWeeks));
        assert!(!is_low_mem_allowed_window(SyncWindowKind::Full));
    }

    #[test]
    fn different_local_peers_to_same_hub_start_on_different_hot_shard_groups() {
        let db_path = "/tmp/window-partition";
        let hub = "hub";
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        let live_peers = vec![hub.to_string()];
        reset_outbound_window_state(db_path, peer_a, hub);
        reset_outbound_window_state(db_path, peer_b, hub);

        let hot_a = select_outbound_task(db_path, peer_a, hub, &live_peers, 1_000_000);
        let hot_b = select_outbound_task(db_path, peer_b, hub, &live_peers, 1_000_000);
        assert_eq!(hot_a.window.kind, SyncWindowKind::LastDay);
        assert_eq!(hot_b.window.kind, SyncWindowKind::LastDay);
        if task_count_for_kind(SyncWindowKind::LastDay) > 1 {
            assert_ne!(hot_a, hot_b);
        } else {
            assert_eq!(hot_a, hot_b);
        }
    }

    #[test]
    fn hot_shard_offset_changes_when_cycle_anchor_changes() {
        let db_path = "/tmp/window-hot-cycle";
        let recorded_by = "tenant-a";
        let peer_id = "peer-b";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);

        let first = select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
        reset_outbound_window_state(db_path, recorded_by, peer_id);
        let second = select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 2_000_000);

        assert_eq!(first.window.kind, SyncWindowKind::LastDay);
        assert_eq!(second.window.kind, SyncWindowKind::LastDay);
        if task_count_for_kind(SyncWindowKind::LastDay) > 1 {
            assert_ne!(first, second);
        } else {
            assert_eq!(first.window.kind, second.window.kind);
            assert_eq!(first.shard_min_inclusive, second.shard_min_inclusive);
            assert_eq!(first.shard_max_exclusive, second.shard_max_exclusive);
        }
    }

    #[test]
    fn rank_one_takeover_unlocks_after_cold_delay() {
        let task = SyncTask {
            window: window_for_kind(SyncWindowKind::LastWeek, 1_000_000),
            shard_min_inclusive: 0,
            shard_max_exclusive: LAST_WEEK_SHARD_SPAN,
        };
        let live_peers = vec!["peer-a".to_string(), "peer-b".to_string()];
        let rank_b = task_owner_rank(task, "peer-b", &live_peers).unwrap();
        if rank_b == 0 {
            return;
        }
        let delay = task_takeover_delay_ms(task, rank_b);
        assert!(!task_is_eligible_for_peer(task, "peer-b", &live_peers, delay - 1));
        assert!(task_is_eligible_for_peer(task, "peer-b", &live_peers, delay));
    }

    #[test]
    fn task_scheduler_uses_stable_cycle_anchor_across_hot_and_cold_steps() {
        let db_path = "/tmp/window-cycle-anchor";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);

        let first_day =
            select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
        assert_eq!(first_day.window.kind, SyncWindowKind::LastDay);
        assert_eq!(first_day.window.ts_min(), Some(1_000_000 - DAY_MS));
        mark_outbound_task_completed(db_path, recorded_by, peer_id, first_day);

        for _ in 0..(task_count_for_kind(SyncWindowKind::LastDay) - 1) {
            let day_task =
                select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 2_000_000);
            assert_eq!(day_task.window.kind, SyncWindowKind::LastDay);
            assert_eq!(day_task.window.ts_min(), Some(1_000_000 - DAY_MS));
            mark_outbound_task_completed(db_path, recorded_by, peer_id, day_task);
        }

        let week = select_outbound_task(db_path, recorded_by, peer_id, &live_peers, 2_000_000);
        assert_eq!(week.window.kind, SyncWindowKind::LastWeek);
        assert_eq!(week.window.ts_min(), Some(1_000_000 - WEEK_MS));
    }

    #[test]
    fn initial_neg_open_roundtrips_task_header() {
        let task = SyncTask {
            window: SyncWindow {
                kind: SyncWindowKind::LastWeek,
                ts_min_inclusive_ms: Some(123),
                ts_max_exclusive_ms: Some(456),
            },
            shard_min_inclusive: 32,
            shard_max_exclusive: 40,
        };
        let payload = vec![1u8, 2, 3, 4];
        let encoded = encode_initial_neg_open_task(task, payload.clone());
        let (decoded_task, inner) = decode_initial_neg_open(&encoded).unwrap();
        assert_eq!(decoded_task, task);
        assert_eq!(inner, payload.as_slice());
    }

    #[test]
    fn legacy_window_header_decodes_to_full_shard_task() {
        let window = SyncWindow {
            kind: SyncWindowKind::LastWeek,
            ts_min_inclusive_ms: Some(123),
            ts_max_exclusive_ms: Some(456),
        };
        let payload = vec![1u8, 2, 3, 4];
        let encoded = encode_initial_neg_open(window, payload.clone());
        let (decoded_task, inner) = decode_initial_neg_open(&encoded).unwrap();
        assert_eq!(decoded_task, SyncTask::full_window(window));
        assert_eq!(inner, payload.as_slice());
    }
}
