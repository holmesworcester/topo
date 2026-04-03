use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::tuning::{low_mem_mode, sync_dep_claim_shard_cap, sync_last_day_only};

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
pub enum SyncNegPhase {
    ClaimsDayShard { shard_start_ms: i64 },
    ObjectsRange { window: SyncWindow },
}

const WINDOW_MAGIC: &[u8; 4] = b"P7SN";
const WINDOW_VERSION: u8 = 3;
const NEG_PHASE_CLAIMS_DAY_SHARD: u8 = 1;
const NEG_PHASE_OBJECTS_RANGE: u8 = 2;
const NONE_TS_SENTINEL: i64 = i64::MIN;
const ALL_START_MS: i64 = 0;
const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const WEEK_MS: i64 = 7 * DAY_MS;
const TWELVE_WEEK_MS: i64 = 12 * WEEK_MS;
const DEFAULT_TIER_ORDER: [SyncWindowKind; 4] = [
    SyncWindowKind::LastDay,
    SyncWindowKind::LastWeek,
    SyncWindowKind::LastTwelveWeeks,
    SyncWindowKind::Full,
];
const LOW_MEM_TIER_ORDER: [SyncWindowKind; 2] = [SyncWindowKind::LastDay, SyncWindowKind::LastWeek];
const LAST_DAY_ONLY_TIER_ORDER: [SyncWindowKind; 1] = [SyncWindowKind::LastDay];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlannerState {
    next_idx: usize,
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
            next_idx: 0,
            cycle_anchor_now_ms: None,
            restrict_to_low_mem_windows: false,
        })
}

fn planner_tier_order(planner: &PlannerState) -> &'static [SyncWindowKind] {
    if sync_last_day_only() {
        &LAST_DAY_ONLY_TIER_ORDER
    } else if low_mem_mode() || planner.restrict_to_low_mem_windows {
        &LOW_MEM_TIER_ORDER
    } else {
        &DEFAULT_TIER_ORDER
    }
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
    let tier_order = planner_tier_order(planner);
    let idx = tier_order
        .iter()
        .position(|candidate| *candidate == kind)
        .unwrap_or(0);
    planner.next_idx = idx;
    planner.cycle_anchor_now_ms = None;
}

pub fn select_outbound_window(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    live_peer_ids: &[String],
    now_ms: i64,
) -> SyncWindow {
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let planner = state_for(&mut state, db_path, recorded_by, peer_id);
    let tier_order = planner_tier_order(planner);
    let anchor_now_ms = *planner.cycle_anchor_now_ms.get_or_insert(now_ms);
    let idx = planner.next_idx % tier_order.len();
    let kind = tier_order[idx];
    assign_window(
        window_for_kind(kind, anchor_now_ms),
        kind,
        peer_id,
        live_peer_ids,
        anchor_now_ms,
    )
}

pub fn mark_outbound_window_completed(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    _window: SyncWindow,
) {
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let planner = state_for(&mut state, db_path, recorded_by, peer_id);
    let tier_order = planner_tier_order(planner);
    planner.next_idx = (planner.next_idx + 1) % tier_order.len();
    if planner.next_idx == 0 {
        planner.cycle_anchor_now_ms = None;
    }
}

pub fn restrict_outbound_windows_to_last_week(db_path: &str, recorded_by: &str, peer_id: &str) {
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let planner = state_for(&mut state, db_path, recorded_by, peer_id);
    planner.restrict_to_low_mem_windows = true;
    planner.next_idx %= LOW_MEM_TIER_ORDER.len();
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

pub fn is_low_mem_allowed_window(kind: SyncWindowKind) -> bool {
    matches!(kind, SyncWindowKind::LastDay | SyncWindowKind::LastWeek)
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

fn partition_window_bounds(window: SyncWindow, now_ms: i64) -> Option<(i64, i64)> {
    let start = window.ts_min()?;
    let end = window.ts_max_exclusive().unwrap_or(now_ms);
    (start < end).then_some((start, end))
}

fn partition_window(
    window: SyncWindow,
    peer_rank: usize,
    peer_count: usize,
    now_ms: i64,
) -> SyncWindow {
    if peer_count <= 1 {
        return window;
    }
    let Some((start, end)) = partition_window_bounds(window, now_ms) else {
        return window;
    };
    let width = end.saturating_sub(start);
    if width <= 1 {
        return window;
    }

    let oldest_slot = peer_count.saturating_sub(peer_rank + 1);
    let slice_start = start + (width * oldest_slot as i64) / peer_count as i64;
    let slice_end = start + (width * (oldest_slot + 1) as i64) / peer_count as i64;
    SyncWindow {
        kind: window.kind,
        ts_min_inclusive_ms: Some(slice_start),
        ts_max_exclusive_ms: Some(slice_end.max(slice_start)),
    }
}

fn assign_window(
    window: SyncWindow,
    kind: SyncWindowKind,
    peer_id: &str,
    live_peer_ids: &[String],
    now_ms: i64,
) -> SyncWindow {
    if is_hot_window(kind) {
        return window;
    }
    let peers = normalized_live_peers(peer_id, live_peer_ids);
    let Some(peer_rank) = peers.iter().position(|candidate| candidate == peer_id) else {
        return window;
    };
    partition_window(window, peer_rank, peers.len(), now_ms)
}

impl SyncWindow {
    pub fn ts_min(self) -> Option<i64> {
        self.ts_min_inclusive_ms
    }

    pub fn ts_max_exclusive(self) -> Option<i64> {
        self.ts_max_exclusive_ms
    }
}

pub fn claim_shard_starts_for_window(window: SyncWindow, now_ms: i64) -> Vec<i64> {
    let Some((start, end)) = partition_window_bounds(window, now_ms) else {
        return Vec::new();
    };
    if start >= end {
        return Vec::new();
    }

    let first_shard = crate::db::dep_claims::utc_day_start_ms(start);
    let last_shard = crate::db::dep_claims::utc_day_start_ms(end.saturating_sub(1));
    let shard_cap = sync_dep_claim_shard_cap();
    let mut shards = Vec::new();
    let mut shard = first_shard;
    loop {
        shards.push(shard);
        if shards.len() > shard_cap {
            return Vec::new();
        }
        if shard == last_shard {
            return shards;
        }
        shard = shard.saturating_add(DAY_MS);
    }
}

pub fn encode_initial_neg_open(phase: SyncNegPhase, inner: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 1 + 1 + 8 + 8 + inner.len());
    out.extend_from_slice(WINDOW_MAGIC);
    out.push(WINDOW_VERSION);
    match phase {
        SyncNegPhase::ClaimsDayShard { shard_start_ms } => {
            out.push(NEG_PHASE_CLAIMS_DAY_SHARD);
            out.extend_from_slice(&shard_start_ms.to_le_bytes());
        }
        SyncNegPhase::ObjectsRange { window } => {
            out.push(NEG_PHASE_OBJECTS_RANGE);
            out.push(window.kind as u8);
            out.extend_from_slice(
                &window
                    .ts_min_inclusive_ms
                    .unwrap_or(NONE_TS_SENTINEL)
                    .to_le_bytes(),
            );
            out.extend_from_slice(
                &window
                    .ts_max_exclusive_ms
                    .unwrap_or(NONE_TS_SENTINEL)
                    .to_le_bytes(),
            );
        }
    }
    out.extend_from_slice(&inner);
    out
}

pub fn decode_initial_neg_open(msg: &[u8]) -> Result<(SyncNegPhase, &[u8]), String> {
    if msg.len() < 6 || &msg[..4] != WINDOW_MAGIC {
        return Ok((
            SyncNegPhase::ObjectsRange {
                window: SyncWindow {
                    kind: SyncWindowKind::Full,
                    ts_min_inclusive_ms: None,
                    ts_max_exclusive_ms: None,
                },
            },
            msg,
        ));
    }

    let version = msg[4];
    if version != WINDOW_VERSION {
        return Err(format!("unsupported sync window version {}", version));
    }
    match msg[5] {
        NEG_PHASE_CLAIMS_DAY_SHARD => {
            if msg.len() < 14 {
                return Err("sync claim shard header truncated".to_string());
            }
            let shard_start_ms = i64::from_le_bytes(
                msg[6..14]
                    .try_into()
                    .map_err(|_| "sync claim shard header truncated".to_string())?,
            );
            Ok((SyncNegPhase::ClaimsDayShard { shard_start_ms }, &msg[14..]))
        }
        NEG_PHASE_OBJECTS_RANGE => {
            if msg.len() < 23 {
                return Err("sync window header truncated".to_string());
            }
            let kind = decode_sync_window_kind(msg[6])?;
            let ts_min = i64::from_le_bytes(
                msg[7..15]
                    .try_into()
                    .map_err(|_| "sync window min header truncated".to_string())?,
            );
            let ts_max = i64::from_le_bytes(
                msg[15..23]
                    .try_into()
                    .map_err(|_| "sync window max header truncated".to_string())?,
            );
            Ok((
                SyncNegPhase::ObjectsRange {
                    window: SyncWindow {
                        kind,
                        ts_min_inclusive_ms: (ts_min != NONE_TS_SENTINEL).then_some(ts_min),
                        ts_max_exclusive_ms: (ts_max != NONE_TS_SENTINEL).then_some(ts_max),
                    },
                },
                &msg[23..],
            ))
        }
        other => Err(format!("unsupported sync phase {}", other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EnvGuard {
        prev_low_mem_ios: Option<String>,
        prev_sync_last_day_only: Option<String>,
    }

    impl EnvGuard {
        fn enable_low_mem_ios() -> Self {
            let prev_low_mem_ios = std::env::var("LOW_MEM_IOS").ok();
            std::env::set_var("LOW_MEM_IOS", "1");
            Self {
                prev_low_mem_ios,
                prev_sync_last_day_only: std::env::var("TOPO_SYNC_LAST_DAY_ONLY").ok(),
            }
        }

        fn enable_last_day_only() -> Self {
            let prev_sync_last_day_only = std::env::var("TOPO_SYNC_LAST_DAY_ONLY").ok();
            std::env::set_var("TOPO_SYNC_LAST_DAY_ONLY", "1");
            Self {
                prev_low_mem_ios: std::env::var("LOW_MEM_IOS").ok(),
                prev_sync_last_day_only,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev_low_mem_ios {
                Some(v) => std::env::set_var("LOW_MEM_IOS", v),
                None => std::env::remove_var("LOW_MEM_IOS"),
            }
            match &self.prev_sync_last_day_only {
                Some(v) => std::env::set_var("TOPO_SYNC_LAST_DAY_ONLY", v),
                None => std::env::remove_var("TOPO_SYNC_LAST_DAY_ONLY"),
            }
        }
    }

    #[test]
    fn range_scheduler_round_robins_windows() {
        let db_path = "/tmp/window-round-robin";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);

        let kinds: Vec<SyncWindowKind> = (0..8)
            .map(|_| {
                let window =
                    select_outbound_window(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
                let kind = window.kind;
                mark_outbound_window_completed(db_path, recorded_by, peer_id, window);
                kind
            })
            .collect();

        assert_eq!(
            kinds,
            vec![
                SyncWindowKind::LastDay,
                SyncWindowKind::LastWeek,
                SyncWindowKind::LastTwelveWeeks,
                SyncWindowKind::Full,
                SyncWindowKind::LastDay,
                SyncWindowKind::LastWeek,
                SyncWindowKind::LastTwelveWeeks,
                SyncWindowKind::Full,
            ]
        );
    }

    #[test]
    fn last_day_only_scheduler_repeats_hot_window() {
        let _env = EnvGuard::enable_last_day_only();
        let db_path = "/tmp/window-round-robin-last-day-only";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);

        let kinds: Vec<SyncWindowKind> = (0..4)
            .map(|_| {
                let window =
                    select_outbound_window(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
                let kind = window.kind;
                mark_outbound_window_completed(db_path, recorded_by, peer_id, window);
                kind
            })
            .collect();

        assert_eq!(
            kinds,
            vec![
                SyncWindowKind::LastDay,
                SyncWindowKind::LastDay,
                SyncWindowKind::LastDay,
                SyncWindowKind::LastDay,
            ]
        );
    }

    #[test]
    fn lowmem_range_scheduler_round_robins_day_and_week_only() {
        let _env = EnvGuard::enable_low_mem_ios();
        let db_path = "/tmp/window-round-robin-lowmem";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);

        let kinds: Vec<SyncWindowKind> = (0..6)
            .map(|_| {
                let window =
                    select_outbound_window(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
                let kind = window.kind;
                mark_outbound_window_completed(db_path, recorded_by, peer_id, window);
                kind
            })
            .collect();

        assert_eq!(
            kinds,
            vec![
                SyncWindowKind::LastDay,
                SyncWindowKind::LastWeek,
                SyncWindowKind::LastDay,
                SyncWindowKind::LastWeek,
                SyncWindowKind::LastDay,
                SyncWindowKind::LastWeek,
            ]
        );
    }

    #[test]
    fn peer_restricted_to_lowmem_windows_round_robins_day_and_week_only() {
        let db_path = "/tmp/window-round-robin-remote-lowmem";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);
        restrict_outbound_windows_to_last_week(db_path, recorded_by, peer_id);

        let kinds: Vec<SyncWindowKind> = (0..6)
            .map(|_| {
                let window =
                    select_outbound_window(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
                let kind = window.kind;
                mark_outbound_window_completed(db_path, recorded_by, peer_id, window);
                kind
            })
            .collect();

        assert_eq!(
            kinds,
            vec![
                SyncWindowKind::LastDay,
                SyncWindowKind::LastWeek,
                SyncWindowKind::LastDay,
                SyncWindowKind::LastWeek,
                SyncWindowKind::LastDay,
                SyncWindowKind::LastWeek,
            ]
        );
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
    fn hot_windows_are_duplicated_across_live_peers() {
        let db_path = "/tmp/window-hot-dup";
        let recorded_by = "tenant-a";
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        let live_peers = vec![peer_a.to_string(), peer_b.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_a);
        reset_outbound_window_state(db_path, recorded_by, peer_b);

        let day_a = select_outbound_window(db_path, recorded_by, peer_a, &live_peers, 1_000_000);
        let day_b = select_outbound_window(db_path, recorded_by, peer_b, &live_peers, 1_000_000);
        assert_eq!(day_a, day_b);
    }

    #[test]
    fn range_scheduler_uses_stable_cycle_anchor_across_window_steps() {
        let db_path = "/tmp/window-cycle-anchor";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);

        let day = select_outbound_window(db_path, recorded_by, peer_id, &live_peers, 1_000_000);
        mark_outbound_window_completed(db_path, recorded_by, peer_id, day);
        let week = select_outbound_window(db_path, recorded_by, peer_id, &live_peers, 2_000_000);

        assert_eq!(day.kind, SyncWindowKind::LastDay);
        assert_eq!(week.kind, SyncWindowKind::LastWeek);
        assert_eq!(week.ts_min(), Some(1_000_000 - WEEK_MS));
    }

    #[test]
    fn cold_windows_partition_by_live_peer_rank() {
        let db_path = "/tmp/window-partition";
        let recorded_by = "tenant-a";
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        let live_peers = vec![peer_a.to_string(), peer_b.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_a);
        reset_outbound_window_state(db_path, recorded_by, peer_b);

        for _ in 0..1 {
            let a = select_outbound_window(db_path, recorded_by, peer_a, &live_peers, 1_000_000);
            let b = select_outbound_window(db_path, recorded_by, peer_b, &live_peers, 1_000_000);
            mark_outbound_window_completed(db_path, recorded_by, peer_a, a);
            mark_outbound_window_completed(db_path, recorded_by, peer_b, b);
        }

        let week_a = select_outbound_window(db_path, recorded_by, peer_a, &live_peers, 1_000_000);
        let week_b = select_outbound_window(db_path, recorded_by, peer_b, &live_peers, 1_000_000);

        assert_eq!(week_a.kind, SyncWindowKind::LastWeek);
        assert_eq!(week_b.kind, SyncWindowKind::LastWeek);
        assert_eq!(week_a.ts_min(), week_b.ts_max_exclusive());
        assert_eq!(week_a.ts_min(), Some(1_000_000 - (4 * DAY_MS)));
        assert_eq!(week_a.ts_max_exclusive(), Some(1_000_000 - DAY_MS));
        assert_eq!(week_b.ts_min(), Some(1_000_000 - WEEK_MS));
        assert_eq!(week_b.ts_max_exclusive(), Some(1_000_000 - (4 * DAY_MS)));
    }

    #[test]
    fn cold_windows_expand_when_live_peer_set_shrinks() {
        let db_path = "/tmp/window-peer-loss";
        let recorded_by = "tenant-a";
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        reset_outbound_window_state(db_path, recorded_by, peer_a);
        reset_outbound_window_state(db_path, recorded_by, peer_b);

        for _ in 0..1 {
            let a = select_outbound_window(
                db_path,
                recorded_by,
                peer_a,
                &[peer_a.to_string(), peer_b.to_string()],
                1_000_000,
            );
            mark_outbound_window_completed(db_path, recorded_by, peer_a, a);
        }
        let split_week = select_outbound_window(
            db_path,
            recorded_by,
            peer_a,
            &[peer_a.to_string(), peer_b.to_string()],
            1_000_000,
        );
        let single_week = select_outbound_window(
            db_path,
            recorded_by,
            peer_a,
            &[peer_a.to_string()],
            1_000_000,
        );

        assert_eq!(split_week.kind, SyncWindowKind::LastWeek);
        assert_eq!(split_week.ts_min(), Some(1_000_000 - (4 * DAY_MS)));
        assert_eq!(split_week.ts_max_exclusive(), Some(1_000_000 - DAY_MS));
        assert_eq!(single_week.ts_min(), Some(1_000_000 - WEEK_MS));
        assert_eq!(single_week.ts_max_exclusive(), Some(1_000_000 - DAY_MS));
    }

    #[test]
    fn full_range_partitions_cover_without_overlap() {
        let db_path = "/tmp/window-full-cover";
        let recorded_by = "tenant-a";
        let peers = vec![
            "peer-a".to_string(),
            "peer-b".to_string(),
            "peer-c".to_string(),
            "peer-d".to_string(),
        ];
        let now_ms = 4 * TWELVE_WEEK_MS;
        for peer in &peers {
            reset_outbound_window_state(db_path, recorded_by, peer);
        }

        for peer in &peers {
            for _ in 0..3 {
                let window = select_outbound_window(db_path, recorded_by, peer, &peers, now_ms);
                mark_outbound_window_completed(db_path, recorded_by, peer, window);
            }
        }

        let mut full_windows: Vec<SyncWindow> = peers
            .iter()
            .map(|peer| select_outbound_window(db_path, recorded_by, peer, &peers, now_ms))
            .collect();
        full_windows.sort_by_key(|window| window.ts_min());

        assert_eq!(full_windows.len(), 4);
        assert_eq!(full_windows[0].ts_min(), Some(ALL_START_MS));
        assert_eq!(
            full_windows[3].ts_max_exclusive(),
            Some(now_ms - TWELVE_WEEK_MS)
        );
        for pair in full_windows.windows(2) {
            assert_eq!(pair[0].ts_max_exclusive(), pair[1].ts_min());
        }
    }

    #[test]
    fn claim_shards_cover_small_window_in_utc_days() {
        let window = SyncWindow {
            kind: SyncWindowKind::LastWeek,
            ts_min_inclusive_ms: Some(DAY_MS - 1),
            ts_max_exclusive_ms: Some((3 * DAY_MS) + 1),
        };
        assert_eq!(
            claim_shard_starts_for_window(window, 10 * DAY_MS),
            vec![0, DAY_MS, 2 * DAY_MS, 3 * DAY_MS]
        );
    }

    #[test]
    fn claim_shards_skip_windows_over_configured_cap() {
        let prev = std::env::var("TOPO_SYNC_DEP_CLAIM_SHARD_CAP").ok();
        std::env::set_var("TOPO_SYNC_DEP_CLAIM_SHARD_CAP", "2");
        let window = SyncWindow {
            kind: SyncWindowKind::LastWeek,
            ts_min_inclusive_ms: Some(0),
            ts_max_exclusive_ms: Some(3 * DAY_MS),
        };
        assert!(claim_shard_starts_for_window(window, 10 * DAY_MS).is_empty());
        match prev {
            Some(v) => std::env::set_var("TOPO_SYNC_DEP_CLAIM_SHARD_CAP", v),
            None => std::env::remove_var("TOPO_SYNC_DEP_CLAIM_SHARD_CAP"),
        }
    }

    #[test]
    fn initial_neg_open_roundtrips_window_header() {
        let window = SyncWindow {
            kind: SyncWindowKind::LastWeek,
            ts_min_inclusive_ms: Some(123_456),
            ts_max_exclusive_ms: Some(456_789),
        };
        let payload = vec![1, 2, 3, 4];
        let encoded =
            encode_initial_neg_open(SyncNegPhase::ObjectsRange { window }, payload.clone());
        let (decoded_phase, inner) = decode_initial_neg_open(&encoded).unwrap();

        assert_eq!(decoded_phase, SyncNegPhase::ObjectsRange { window });
        assert_eq!(inner, payload.as_slice());
    }

    #[test]
    fn initial_neg_open_roundtrips_claim_shard_header() {
        let payload = vec![5, 6, 7];
        let encoded = encode_initial_neg_open(
            SyncNegPhase::ClaimsDayShard {
                shard_start_ms: 42 * DAY_MS,
            },
            payload.clone(),
        );
        let (decoded_phase, inner) = decode_initial_neg_open(&encoded).unwrap();

        assert_eq!(
            decoded_phase,
            SyncNegPhase::ClaimsDayShard {
                shard_start_ms: 42 * DAY_MS,
            }
        );
        assert_eq!(inner, payload.as_slice());
    }
}
