use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use tracing::debug;

use crate::tuning::{low_mem_mode, sync_last_day_only_mode};

pub use topo_verus_proofs::runtime::sync_engine::session::windowing::{
    decide_cold_tier_plan, decide_select_outbound_window_plan, normalize_cold_tier_context,
    normalize_select_outbound_window_context, ColdTierDecisionContext, ColdTierPlan,
    ColdTierRawRows, SelectOutboundWindowDecisionContext, SelectOutboundWindowPlan,
    SelectOutboundWindowRawRows,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncWindowKind {
    Old = 0,
    LastDay = 1,
    LastWeek = 2,
    LastTwelveWeeks = 3,
}

pub fn encode_sync_window_kind(kind: SyncWindowKind) -> u8 {
    kind as u8
}

pub fn decode_sync_window_kind(kind: u8) -> Result<SyncWindowKind, String> {
    match kind {
        0 => Ok(SyncWindowKind::Old),
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
const WINDOW_VERSION: u8 = 2;
const NONE_TS_SENTINEL: i64 = i64::MIN;
const ALL_START_MS: i64 = 0;
const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const WEEK_MS: i64 = 7 * DAY_MS;
const DEFAULT_COLD_TIER_ORDER: [SyncWindowKind; 3] = [
    SyncWindowKind::LastWeek,
    SyncWindowKind::LastTwelveWeeks,
    SyncWindowKind::Old,
];
const LOW_MEM_COLD_TIER_ORDER: [SyncWindowKind; 1] = [SyncWindowKind::LastWeek];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SinglePeerPhase {
    LastDay,
    Cold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlannerState {
    cold_next_idx: usize,
    restrict_to_low_mem_windows: bool,
    single_peer_phase: SinglePeerPhase,
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
            cold_next_idx: 0,
            restrict_to_low_mem_windows: false,
            single_peer_phase: SinglePeerPhase::LastDay,
        })
}

fn cold_tier_order(planner: &PlannerState) -> &'static [SyncWindowKind] {
    let context = normalize_cold_tier_context(ColdTierRawRows {
        global_low_mem_mode: low_mem_mode(),
        restrict_to_low_mem_windows: planner.restrict_to_low_mem_windows,
    });
    cold_tier_order_for_plan(decide_cold_tier_plan(&context))
}

fn cold_tier_order_for_plan(plan: ColdTierPlan) -> &'static [SyncWindowKind] {
    match plan {
        ColdTierPlan::Default => &DEFAULT_COLD_TIER_ORDER,
        ColdTierPlan::LowMemOnly => &LOW_MEM_COLD_TIER_ORDER,
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
    match kind {
        SyncWindowKind::LastDay => {
            planner.single_peer_phase = SinglePeerPhase::LastDay;
        }
        SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks | SyncWindowKind::Old => {
            let tier_order = cold_tier_order(planner);
            let idx = tier_order
                .iter()
                .position(|candidate| *candidate == kind)
                .unwrap_or(0);
            planner.cold_next_idx = idx;
            planner.single_peer_phase = SinglePeerPhase::Cold;
        }
    }
}

fn select_single_peer_window(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    now_ms: i64,
) -> SyncWindow {
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let planner = state_for(&mut state, db_path, recorded_by, peer_id);
    let kind = match planner.single_peer_phase {
        SinglePeerPhase::LastDay => SyncWindowKind::LastDay,
        SinglePeerPhase::Cold => {
            let tier_order = cold_tier_order(planner);
            let idx = planner.cold_next_idx % tier_order.len();
            tier_order[idx]
        }
    };
    window_for_kind(kind, now_ms)
}

fn normalized_live_peer_count(peer_id: &str, live_peer_ids: &[String]) -> usize {
    let mut peers = live_peer_ids.to_vec();
    if !peers.iter().any(|candidate| candidate == peer_id) {
        peers.push(peer_id.to_string());
    }
    peers.sort();
    peers.dedup();
    peers.len()
}

pub fn select_outbound_window(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    live_peer_ids: &[String],
    now_ms: i64,
) -> SyncWindow {
    let peer_short = &peer_id[..peer_id.len().min(16)];
    let live_peer_count = normalized_live_peer_count(peer_id, live_peer_ids);
    let plan = decide_select_outbound_window_plan(&normalize_select_outbound_window_context(
        SelectOutboundWindowRawRows {
            last_day_only_mode: sync_last_day_only_mode(),
            normalized_live_peer_count: u32::try_from(live_peer_count).unwrap_or(u32::MAX),
            peer_is_priority_owner: false,
        },
    ));
    if matches!(plan, SelectOutboundWindowPlan::LastDayOnly) {
        let window = window_for_kind(SyncWindowKind::LastDay, now_ms);
        debug!(
            target: "topo::sync_window_planner",
            db_path,
            recorded_by,
            peer = peer_short,
            normalized_live_peer_count = live_peer_count,
            kind = ?window.kind,
            "selected outbound sync window in last-day-only mode"
        );
        return window;
    }
    let window = select_single_peer_window(db_path, recorded_by, peer_id, now_ms);
    debug!(
        target: "topo::sync_window_planner",
        db_path,
        recorded_by,
        peer = peer_short,
        normalized_live_peer_count = live_peer_count,
        kind = ?window.kind,
        "selected outbound sync window in per-peer cadence"
    );
    window
}

pub fn mark_outbound_window_completed(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    window: SyncWindow,
) {
    if sync_last_day_only_mode() {
        return;
    }
    {
        let mut state = planner_state()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let planner = state_for(&mut state, db_path, recorded_by, peer_id);
        match window.kind {
            SyncWindowKind::LastDay => {
                planner.single_peer_phase = SinglePeerPhase::Cold;
            }
            SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks | SyncWindowKind::Old => {
                let tier_order = cold_tier_order(planner);
                planner.cold_next_idx = (planner.cold_next_idx + 1) % tier_order.len();
                planner.single_peer_phase = SinglePeerPhase::LastDay;
            }
        }
    }
}

pub fn restrict_outbound_windows_to_last_week(db_path: &str, recorded_by: &str, peer_id: &str) {
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let planner = state_for(&mut state, db_path, recorded_by, peer_id);
    planner.restrict_to_low_mem_windows = true;
    planner.cold_next_idx %= LOW_MEM_COLD_TIER_ORDER.len();
}

fn utc_day_start_ms(ts_ms: i64) -> i64 {
    ts_ms.div_euclid(DAY_MS) * DAY_MS
}

fn utc_week_start_ms(ts_ms: i64) -> i64 {
    let day_start_ms = utc_day_start_ms(ts_ms);
    let days_since_epoch = day_start_ms.div_euclid(DAY_MS);
    let weekday_monday_zero = (days_since_epoch + 3).rem_euclid(7);
    day_start_ms - (weekday_monday_zero * DAY_MS)
}

fn window_for_kind(kind: SyncWindowKind, now_ms: i64) -> SyncWindow {
    let today_start_ms = utc_day_start_ms(now_ms);
    let yesterday_start_ms = today_start_ms - DAY_MS;
    let tomorrow_start_ms = today_start_ms + DAY_MS;
    let this_week_start_ms = utc_week_start_ms(now_ms);
    let old_start_ms = this_week_start_ms - (13 * WEEK_MS);
    match kind {
        SyncWindowKind::Old => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(ALL_START_MS),
            ts_max_exclusive_ms: Some(old_start_ms),
        },
        SyncWindowKind::LastDay => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(yesterday_start_ms),
            ts_max_exclusive_ms: Some(tomorrow_start_ms),
        },
        SyncWindowKind::LastWeek => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(this_week_start_ms - WEEK_MS),
            ts_max_exclusive_ms: Some(yesterday_start_ms),
        },
        SyncWindowKind::LastTwelveWeeks => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(old_start_ms),
            ts_max_exclusive_ms: Some(this_week_start_ms - WEEK_MS),
        },
    }
}

pub fn is_priority_ingest_window(kind: SyncWindowKind) -> bool {
    matches!(kind, SyncWindowKind::LastDay)
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
                kind: SyncWindowKind::Old,
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
        prev_last_day_only: Option<String>,
    }

    impl EnvGuard {
        fn enable_low_mem_ios() -> Self {
            let prev_low_mem_ios = std::env::var("LOW_MEM_IOS").ok();
            let prev_last_day_only = std::env::var("TOPO_SYNC_LAST_DAY_ONLY").ok();
            std::env::set_var("LOW_MEM_IOS", "1");
            Self {
                prev_low_mem_ios,
                prev_last_day_only,
            }
        }

        fn enable_last_day_only_sync() -> Self {
            let prev_low_mem_ios = std::env::var("LOW_MEM_IOS").ok();
            let prev_last_day_only = std::env::var("TOPO_SYNC_LAST_DAY_ONLY").ok();
            std::env::set_var("TOPO_SYNC_LAST_DAY_ONLY", "1");
            Self {
                prev_low_mem_ios,
                prev_last_day_only,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.prev_low_mem_ios {
                Some(v) => std::env::set_var("LOW_MEM_IOS", v),
                None => std::env::remove_var("LOW_MEM_IOS"),
            }
            match &self.prev_last_day_only {
                Some(v) => std::env::set_var("TOPO_SYNC_LAST_DAY_ONLY", v),
                None => std::env::remove_var("TOPO_SYNC_LAST_DAY_ONLY"),
            }
        }
    }

    #[test]
    fn cold_tier_decision_context_selects_lowmem_tier_for_global_or_peer_restriction() {
        assert_eq!(
            decide_cold_tier_plan(&ColdTierDecisionContext {
                global_low_mem_mode: true,
                restrict_to_low_mem_windows: false,
            }),
            ColdTierPlan::LowMemOnly
        );
        assert_eq!(
            decide_cold_tier_plan(&ColdTierDecisionContext {
                global_low_mem_mode: false,
                restrict_to_low_mem_windows: true,
            }),
            ColdTierPlan::LowMemOnly
        );
        assert_eq!(
            decide_cold_tier_plan(&ColdTierDecisionContext {
                global_low_mem_mode: false,
                restrict_to_low_mem_windows: false,
            }),
            ColdTierPlan::Default
        );
    }

    #[test]
    fn cold_tier_normalizer_preserves_raw_rows_for_planner() {
        let raw_rows = [
            ColdTierRawRows {
                global_low_mem_mode: false,
                restrict_to_low_mem_windows: false,
            },
            ColdTierRawRows {
                global_low_mem_mode: true,
                restrict_to_low_mem_windows: false,
            },
            ColdTierRawRows {
                global_low_mem_mode: false,
                restrict_to_low_mem_windows: true,
            },
        ];

        for raw in raw_rows {
            let context = normalize_cold_tier_context(raw);
            assert_eq!(
                context,
                ColdTierDecisionContext {
                    global_low_mem_mode: raw.global_low_mem_mode,
                    restrict_to_low_mem_windows: raw.restrict_to_low_mem_windows,
                }
            );
            assert_eq!(
                decide_cold_tier_plan(&context),
                if raw.global_low_mem_mode || raw.restrict_to_low_mem_windows {
                    ColdTierPlan::LowMemOnly
                } else {
                    ColdTierPlan::Default
                }
            );
        }
    }

    #[test]
    fn select_outbound_window_decision_context_uses_per_peer_cadence_without_partition_owner() {
        assert_eq!(
            decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
                last_day_only_mode: true,
                normalized_live_peer_count: 3,
                peer_is_priority_owner: false,
            }),
            SelectOutboundWindowPlan::LastDayOnly
        );
        assert_eq!(
            decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
                last_day_only_mode: false,
                normalized_live_peer_count: 1,
                peer_is_priority_owner: false,
            }),
            SelectOutboundWindowPlan::PerPeerCadence
        );
        assert_eq!(
            decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
                last_day_only_mode: false,
                normalized_live_peer_count: 3,
                peer_is_priority_owner: true,
            }),
            SelectOutboundWindowPlan::PerPeerCadence
        );
        assert_eq!(
            decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
                last_day_only_mode: false,
                normalized_live_peer_count: 3,
                peer_is_priority_owner: false,
            }),
            SelectOutboundWindowPlan::PerPeerCadence
        );
    }

    #[test]
    fn select_outbound_window_last_day_only_ignores_peer_count_and_owner() {
        for normalized_live_peer_count in [0, 1, 2, 10] {
            for peer_is_priority_owner in [false, true] {
                let context = SelectOutboundWindowDecisionContext {
                    last_day_only_mode: true,
                    normalized_live_peer_count,
                    peer_is_priority_owner,
                };
                assert_eq!(
                    decide_select_outbound_window_plan(&context),
                    SelectOutboundWindowPlan::LastDayOnly
                );
            }
        }
    }

    #[test]
    fn select_outbound_window_non_last_day_mode_ignores_peer_count_and_owner() {
        for normalized_live_peer_count in [0, 1, 2, 10] {
            for peer_is_priority_owner in [false, true] {
                let context = SelectOutboundWindowDecisionContext {
                    last_day_only_mode: false,
                    normalized_live_peer_count,
                    peer_is_priority_owner,
                };
                assert_eq!(
                    decide_select_outbound_window_plan(&context),
                    SelectOutboundWindowPlan::PerPeerCadence
                );
            }
        }
    }

    #[test]
    fn select_outbound_window_normalizer_preserves_raw_rows_for_planner() {
        let raw_rows = [
            (
                SelectOutboundWindowRawRows {
                    last_day_only_mode: true,
                    normalized_live_peer_count: 3,
                    peer_is_priority_owner: false,
                },
                SelectOutboundWindowPlan::LastDayOnly,
            ),
            (
                SelectOutboundWindowRawRows {
                    last_day_only_mode: false,
                    normalized_live_peer_count: 1,
                    peer_is_priority_owner: false,
                },
                SelectOutboundWindowPlan::PerPeerCadence,
            ),
            (
                SelectOutboundWindowRawRows {
                    last_day_only_mode: false,
                    normalized_live_peer_count: 3,
                    peer_is_priority_owner: true,
                },
                SelectOutboundWindowPlan::PerPeerCadence,
            ),
            (
                SelectOutboundWindowRawRows {
                    last_day_only_mode: false,
                    normalized_live_peer_count: 3,
                    peer_is_priority_owner: false,
                },
                SelectOutboundWindowPlan::PerPeerCadence,
            ),
        ];

        for (raw, expected_plan) in raw_rows {
            let context = normalize_select_outbound_window_context(raw);
            assert_eq!(
                context,
                SelectOutboundWindowDecisionContext {
                    last_day_only_mode: raw.last_day_only_mode,
                    normalized_live_peer_count: raw.normalized_live_peer_count,
                    peer_is_priority_owner: raw.peer_is_priority_owner,
                }
            );
            assert_eq!(decide_select_outbound_window_plan(&context), expected_plan);
        }
    }

    #[test]
    fn last_day_only_mode_sticks_to_hot_window() {
        let _env = EnvGuard::enable_last_day_only_sync();
        let db_path = "/tmp/window-last-day-only";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string(), "peer-b".to_string()];
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

        assert_eq!(kinds, vec![SyncWindowKind::LastDay; 4]);
    }

    #[test]
    fn range_scheduler_round_robins_windows() {
        let db_path = "/tmp/window-round-robin";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);

        let kinds: Vec<SyncWindowKind> = (0..12)
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
                SyncWindowKind::LastTwelveWeeks,
                SyncWindowKind::LastDay,
                SyncWindowKind::Old,
                SyncWindowKind::LastDay,
                SyncWindowKind::LastWeek,
                SyncWindowKind::LastDay,
                SyncWindowKind::LastTwelveWeeks,
                SyncWindowKind::LastDay,
                SyncWindowKind::Old,
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
    fn lowmem_week_window_uses_fixed_utc_bounds() {
        let _env = EnvGuard::enable_low_mem_ios();
        let db_path = "/tmp/window-lowmem-fixed-week";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        let now_ms = (100 * DAY_MS) + (6 * HOUR_MS);
        let today_start_ms = utc_day_start_ms(now_ms);
        let this_week_start_ms = utc_week_start_ms(now_ms);

        reset_outbound_window_state(db_path, recorded_by, peer_id);
        let day = select_outbound_window(db_path, recorded_by, peer_id, &live_peers, now_ms);
        assert_eq!(day.kind, SyncWindowKind::LastDay);
        mark_outbound_window_completed(db_path, recorded_by, peer_id, day);

        let week = select_outbound_window(db_path, recorded_by, peer_id, &live_peers, now_ms);
        assert_eq!(week.kind, SyncWindowKind::LastWeek);
        assert_eq!(week.ts_min(), Some(this_week_start_ms - WEEK_MS));
        assert_eq!(week.ts_max_exclusive(), Some(today_start_ms - DAY_MS));
    }

    #[test]
    fn peer_restricted_to_lowmem_windows_round_robins_day_and_week_only() {
        let db_path = "/tmp/window-round-robin-remote-lowmem";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);
        restrict_outbound_windows_to_last_week(db_path, recorded_by, peer_id);

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
    fn scheduler_uses_fixed_utc_bucket_windows() {
        let now_ms = (100 * DAY_MS) + (6 * HOUR_MS);
        let today_start_ms = utc_day_start_ms(now_ms);
        let this_week_start_ms = utc_week_start_ms(now_ms);
        let day = window_for_kind(SyncWindowKind::LastDay, now_ms);
        let week = window_for_kind(SyncWindowKind::LastWeek, now_ms);
        let twelve_weeks = window_for_kind(SyncWindowKind::LastTwelveWeeks, now_ms);
        let old = window_for_kind(SyncWindowKind::Old, now_ms);

        assert_eq!(day.ts_min(), Some(today_start_ms - DAY_MS));
        assert_eq!(day.ts_max_exclusive(), Some(today_start_ms + DAY_MS));

        assert_eq!(week.ts_min(), Some(this_week_start_ms - WEEK_MS));
        assert_eq!(week.ts_max_exclusive(), Some(today_start_ms - DAY_MS));

        assert_eq!(
            twelve_weeks.ts_min(),
            Some(this_week_start_ms - (13 * WEEK_MS))
        );
        assert_eq!(
            twelve_weeks.ts_max_exclusive(),
            Some(this_week_start_ms - WEEK_MS)
        );

        assert_eq!(old.ts_min(), Some(ALL_START_MS));
        assert_eq!(
            old.ts_max_exclusive(),
            Some(this_week_start_ms - (13 * WEEK_MS))
        );
    }

    #[test]
    fn lowmem_allows_only_day_and_week_windows() {
        assert!(is_low_mem_allowed_window(SyncWindowKind::LastDay));
        assert!(is_low_mem_allowed_window(SyncWindowKind::LastWeek));
        assert!(!is_low_mem_allowed_window(SyncWindowKind::LastTwelveWeeks));
        assert!(!is_low_mem_allowed_window(SyncWindowKind::Old));
    }

    #[test]
    fn range_scheduler_recomputes_windows_from_current_utc_bucket() {
        let db_path = "/tmp/window-fixed-utc";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);

        let first_now_ms = (100 * DAY_MS) + (6 * HOUR_MS);
        let second_now_ms = first_now_ms + (14 * DAY_MS);
        let day = select_outbound_window(db_path, recorded_by, peer_id, &live_peers, first_now_ms);
        mark_outbound_window_completed(db_path, recorded_by, peer_id, day);
        let week =
            select_outbound_window(db_path, recorded_by, peer_id, &live_peers, second_now_ms);

        assert_eq!(day.kind, SyncWindowKind::LastDay);
        assert_eq!(week.kind, SyncWindowKind::LastWeek);
        assert_eq!(day.ts_min(), Some(utc_day_start_ms(first_now_ms) - DAY_MS));
        assert_eq!(
            week.ts_min(),
            Some(utc_week_start_ms(second_now_ms) - WEEK_MS)
        );
    }

    #[test]
    fn multi_peer_scheduler_uses_independent_per_peer_cadence() {
        let db_path = "/tmp/window-independent-peers";
        let recorded_by = "tenant-a";
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        let live_peers = vec![peer_a.to_string(), peer_b.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_a);
        reset_outbound_window_state(db_path, recorded_by, peer_b);

        let day_a = select_outbound_window(db_path, recorded_by, peer_a, &live_peers, 1_000_000);
        let day_b = select_outbound_window(db_path, recorded_by, peer_b, &live_peers, 1_000_000);
        assert_eq!(day_a.kind, SyncWindowKind::LastDay);
        assert_eq!(day_b.kind, SyncWindowKind::LastDay);

        mark_outbound_window_completed(db_path, recorded_by, peer_a, day_a);
        let week_a = select_outbound_window(db_path, recorded_by, peer_a, &live_peers, 1_000_000);
        let still_day_b =
            select_outbound_window(db_path, recorded_by, peer_b, &live_peers, 1_000_000);
        assert_eq!(week_a.kind, SyncWindowKind::LastWeek);
        assert_eq!(
            week_a.ts_min(),
            Some(utc_week_start_ms(1_000_000) - WEEK_MS)
        );
        assert_eq!(
            week_a.ts_max_exclusive(),
            Some(utc_day_start_ms(1_000_000) - DAY_MS)
        );
        assert_eq!(still_day_b.kind, SyncWindowKind::LastDay);
    }

    #[test]
    fn initial_neg_open_roundtrips_window_header() {
        let window = SyncWindow {
            kind: SyncWindowKind::LastWeek,
            ts_min_inclusive_ms: Some(123_456),
            ts_max_exclusive_ms: Some(456_789),
        };
        let payload = vec![1, 2, 3, 4];
        let encoded = encode_initial_neg_open(window, payload.clone());
        let (decoded_window, inner) = decode_initial_neg_open(&encoded).unwrap();

        assert_eq!(decoded_window, window);
        assert_eq!(inner, payload.as_slice());
    }
}
