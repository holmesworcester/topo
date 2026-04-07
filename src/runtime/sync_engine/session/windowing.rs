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

const WINDOW_MAGIC: &[u8; 4] = b"P7SW";
const WINDOW_VERSION: u8 = 3;
const NONE_TS_SENTINEL: i64 = i64::MIN;
const ALL_START_MS: i64 = 0;
const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const WEEK_MS: i64 = 7 * DAY_MS;
const TWELVE_WEEK_MS: i64 = 12 * WEEK_MS;
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

fn planner_order(planner: &PlannerState) -> &'static [SyncWindowKind] {
    if low_mem_mode() || planner.restrict_to_low_mem_windows {
        &LOW_MEM_WINDOW_ORDER
    } else {
        &DEFAULT_WINDOW_ORDER
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
    planner.cycle_anchor_now_ms = None;
    let order = planner_order(planner);
    planner.next_idx = order.iter().position(|candidate| *candidate == kind).unwrap_or(0);
}

pub fn select_outbound_window(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    live_peer_ids: &[String],
    now_ms: i64,
) -> SyncWindow {
    let (kind, anchor_now_ms) = {
        let mut state = planner_state()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let planner = state_for(&mut state, db_path, recorded_by, peer_id);
        let anchor_now_ms = *planner.cycle_anchor_now_ms.get_or_insert(now_ms);
        let order = planner_order(planner);
        (order[planner.next_idx % order.len()], anchor_now_ms)
    };

    let window = window_for_kind(kind, anchor_now_ms);
    assign_window(window, peer_id, live_peer_ids, anchor_now_ms)
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
    let order_len = planner_order(planner).len();
    planner.next_idx = (planner.next_idx + 1) % order_len;
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
    planner.next_idx %= LOW_MEM_WINDOW_ORDER.len();
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
    if peer_count <= 1 || is_hot_window(window.kind) {
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
    peer_id: &str,
    live_peer_ids: &[String],
    now_ms: i64,
) -> SyncWindow {
    if is_hot_window(window.kind) {
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

pub fn encode_initial_neg_open(window: SyncWindow, inner: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 1 + 1 + 8 + 8 + inner.len());
    out.extend_from_slice(WINDOW_MAGIC);
    out.push(WINDOW_VERSION);
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
    out.extend_from_slice(&inner);
    out
}

pub fn decode_initial_neg_open(msg: &[u8]) -> Result<(SyncWindow, &[u8]), String> {
    if msg.len() < 22 || &msg[..4] != WINDOW_MAGIC {
        return Ok((
            SyncWindow {
                kind: SyncWindowKind::Full,
                ts_min_inclusive_ms: None,
                ts_max_exclusive_ms: None,
            },
            msg,
        ));
    }

    let version = msg[4];
    if version != WINDOW_VERSION {
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
    Ok((
        SyncWindow {
            kind,
            ts_min_inclusive_ms: (ts_min != NONE_TS_SENTINEL).then_some(ts_min),
            ts_max_exclusive_ms: (ts_max != NONE_TS_SENTINEL).then_some(ts_max),
        },
        &msg[22..],
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
    fn hot_window_is_not_partitioned_but_cold_windows_are() {
        let db_path = "/tmp/window-partition";
        let recorded_by = "tenant-a";
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        let live_peers = vec![peer_a.to_string(), peer_b.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_a);
        reset_outbound_window_state(db_path, recorded_by, peer_b);

        let hot_a = select_outbound_window(db_path, recorded_by, peer_a, &live_peers, 1_000_000);
        let hot_b = select_outbound_window(db_path, recorded_by, peer_b, &live_peers, 1_000_000);
        assert_eq!(hot_a.kind, SyncWindowKind::LastDay);
        assert_eq!(hot_b.kind, SyncWindowKind::LastDay);
        assert_eq!(hot_a, hot_b);

        mark_outbound_window_completed(db_path, recorded_by, peer_a, hot_a);
        mark_outbound_window_completed(db_path, recorded_by, peer_b, hot_b);
        let cold_a = select_outbound_window(db_path, recorded_by, peer_a, &live_peers, 1_000_000);
        let cold_b = select_outbound_window(db_path, recorded_by, peer_b, &live_peers, 1_000_000);
        assert_eq!(cold_a.kind, SyncWindowKind::LastWeek);
        assert_eq!(cold_b.kind, SyncWindowKind::LastWeek);
        assert_ne!(cold_a, cold_b);
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
        mark_outbound_window_completed(db_path, recorded_by, peer_id, week);
        let twelve_weeks =
            select_outbound_window(db_path, recorded_by, peer_id, &live_peers, 2_000_000);

        assert_eq!(day.kind, SyncWindowKind::LastDay);
        assert_eq!(week.kind, SyncWindowKind::LastWeek);
        assert_eq!(twelve_weeks.kind, SyncWindowKind::LastTwelveWeeks);
        assert_eq!(day.ts_min(), Some(1_000_000 - DAY_MS));
        assert_eq!(week.ts_min(), Some(1_000_000 - WEEK_MS));
        assert_eq!(twelve_weeks.ts_min(), Some(1_000_000 - TWELVE_WEEK_MS));
    }

    #[test]
    fn initial_neg_open_roundtrips_window_header() {
        let window = SyncWindow {
            kind: SyncWindowKind::LastWeek,
            ts_min_inclusive_ms: Some(123),
            ts_max_exclusive_ms: Some(456),
        };
        let payload = vec![1u8, 2, 3, 4];
        let encoded = encode_initial_neg_open(window, payload.clone());
        let (decoded_window, inner) = decode_initial_neg_open(&encoded).unwrap();
        assert_eq!(decoded_window, window);
        assert_eq!(inner, payload.as_slice());
    }
}
