use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use crate::tuning::{low_mem_mode, sync_last_day_only_mode};

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
const WINDOW_VERSION: u8 = 2;
const NONE_TS_SENTINEL: i64 = i64::MIN;
const ALL_START_MS: i64 = 0;
const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const WEEK_MS: i64 = 7 * DAY_MS;
const TWELVE_WEEK_MS: i64 = 12 * WEEK_MS;
const DEFAULT_COLD_TIER_ORDER: [SyncWindowKind; 3] = [
    SyncWindowKind::LastWeek,
    SyncWindowKind::LastTwelveWeeks,
    SyncWindowKind::Full,
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
    cycle_anchor_now_ms: Option<i64>,
    restrict_to_low_mem_windows: bool,
    single_peer_phase: SinglePeerPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ColdTierDecisionContext {
    global_low_mem_mode: bool,
    restrict_to_low_mem_windows: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColdTierPlan {
    Default,
    LowMemOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SelectOutboundWindowDecisionContext {
    last_day_only_mode: bool,
    normalized_live_peer_count: usize,
    peer_is_priority_owner: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectOutboundWindowPlan {
    LastDayOnly,
    SinglePeer,
    MultiPeerPriorityOwner,
    MultiPeerCold,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TenantPriorityState {
    owner_idx: usize,
    cycle_anchor_now_ms: Option<i64>,
}

fn planner_state() -> &'static Mutex<HashMap<String, PlannerState>> {
    static STATE: OnceLock<Mutex<HashMap<String, PlannerState>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn tenant_priority_state() -> &'static Mutex<HashMap<String, TenantPriorityState>> {
    static STATE: OnceLock<Mutex<HashMap<String, TenantPriorityState>>> = OnceLock::new();
    STATE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn planner_key(db_path: &str, recorded_by: &str, peer_id: &str) -> String {
    format!("{db_path}|{recorded_by}|{peer_id}")
}

fn planner_tenant_prefix(db_path: &str, recorded_by: &str) -> String {
    format!("{db_path}|{recorded_by}|")
}

fn tenant_priority_key(db_path: &str, recorded_by: &str) -> String {
    format!("{db_path}|{recorded_by}")
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
            cycle_anchor_now_ms: None,
            restrict_to_low_mem_windows: false,
            single_peer_phase: SinglePeerPhase::LastDay,
        })
}

fn tenant_state_for<'a>(
    state: &'a mut HashMap<String, TenantPriorityState>,
    db_path: &str,
    recorded_by: &str,
) -> &'a mut TenantPriorityState {
    state
        .entry(tenant_priority_key(db_path, recorded_by))
        .or_insert(TenantPriorityState {
            owner_idx: 0,
            cycle_anchor_now_ms: None,
        })
}

fn cold_tier_order(planner: &PlannerState) -> &'static [SyncWindowKind] {
    cold_tier_order_for_plan(decide_cold_tier_plan(&ColdTierDecisionContext {
        global_low_mem_mode: low_mem_mode(),
        restrict_to_low_mem_windows: planner.restrict_to_low_mem_windows,
    }))
}

fn decide_cold_tier_plan(context: &ColdTierDecisionContext) -> ColdTierPlan {
    if context.global_low_mem_mode || context.restrict_to_low_mem_windows {
        ColdTierPlan::LowMemOnly
    } else {
        ColdTierPlan::Default
    }
}

fn cold_tier_order_for_plan(plan: ColdTierPlan) -> &'static [SyncWindowKind] {
    match plan {
        ColdTierPlan::Default => &DEFAULT_COLD_TIER_ORDER,
        ColdTierPlan::LowMemOnly => &LOW_MEM_COLD_TIER_ORDER,
    }
}

fn decide_select_outbound_window_plan(
    context: &SelectOutboundWindowDecisionContext,
) -> SelectOutboundWindowPlan {
    if context.last_day_only_mode {
        SelectOutboundWindowPlan::LastDayOnly
    } else if context.normalized_live_peer_count <= 1 {
        SelectOutboundWindowPlan::SinglePeer
    } else if context.peer_is_priority_owner {
        SelectOutboundWindowPlan::MultiPeerPriorityOwner
    } else {
        SelectOutboundWindowPlan::MultiPeerCold
    }
}

pub fn reset_outbound_window_state(db_path: &str, recorded_by: &str, peer_id: &str) {
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.remove(&planner_key(db_path, recorded_by, peer_id));
    let tenant_prefix = planner_tenant_prefix(db_path, recorded_by);
    let should_remove_tenant_state = !state
        .keys()
        .any(|candidate| candidate.starts_with(&tenant_prefix));
    drop(state);
    if should_remove_tenant_state {
        tenant_priority_state()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&tenant_priority_key(db_path, recorded_by));
    }
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
    match kind {
        SyncWindowKind::LastDay => {
            planner.single_peer_phase = SinglePeerPhase::LastDay;
        }
        SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks | SyncWindowKind::Full => {
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
    let anchor_now_ms = *planner.cycle_anchor_now_ms.get_or_insert(now_ms);
    let kind = match planner.single_peer_phase {
        SinglePeerPhase::LastDay => SyncWindowKind::LastDay,
        SinglePeerPhase::Cold => {
            let tier_order = cold_tier_order(planner);
            let idx = planner.cold_next_idx % tier_order.len();
            tier_order[idx]
        }
    };
    window_for_kind(kind, anchor_now_ms)
}

fn select_cold_window(
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
    let tier_order = cold_tier_order(planner);
    let anchor_now_ms = *planner.cycle_anchor_now_ms.get_or_insert(now_ms);
    let idx = planner.cold_next_idx % tier_order.len();
    let kind = tier_order[idx];
    assign_window(
        window_for_kind(kind, anchor_now_ms),
        kind,
        peer_id,
        live_peer_ids,
        anchor_now_ms,
    )
}

pub fn select_outbound_window(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    live_peer_ids: &[String],
    now_ms: i64,
) -> SyncWindow {
    let last_day_only_mode = sync_last_day_only_mode();
    if matches!(
        decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
            last_day_only_mode,
            normalized_live_peer_count: 0,
            peer_is_priority_owner: false,
        }),
        SelectOutboundWindowPlan::LastDayOnly
    ) {
        return window_for_kind(SyncWindowKind::LastDay, now_ms);
    }
    let live_peers = normalized_live_peers(peer_id, live_peer_ids);
    if matches!(
        decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
            last_day_only_mode,
            normalized_live_peer_count: live_peers.len(),
            peer_is_priority_owner: false,
        }),
        SelectOutboundWindowPlan::SinglePeer
    ) {
        return select_single_peer_window(db_path, recorded_by, peer_id, now_ms);
    }

    let (owner_peer_id, owner_kind) = {
        let mut state = tenant_priority_state()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tenant_state = tenant_state_for(&mut state, db_path, recorded_by);
        let owner_idx = tenant_state.owner_idx % live_peers.len();
        let owner_peer_id = live_peers.get(owner_idx).cloned().unwrap_or_default();
        let owner_kind = if owner_peer_id == peer_id {
            let _ = tenant_state.cycle_anchor_now_ms.get_or_insert(now_ms);
            Some(SyncWindowKind::LastDay)
        } else {
            None
        };
        (owner_peer_id, owner_kind)
    };

    if matches!(
        decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
            last_day_only_mode,
            normalized_live_peer_count: live_peers.len(),
            peer_is_priority_owner: owner_kind.is_some(),
        }),
        SelectOutboundWindowPlan::MultiPeerPriorityOwner
    ) {
        let kind = owner_kind.expect("priority-owner plan requires owner window kind");
        let mut state = tenant_priority_state()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tenant_state = tenant_state_for(&mut state, db_path, recorded_by);
        let anchor_now_ms = *tenant_state.cycle_anchor_now_ms.get_or_insert(now_ms);
        return window_for_kind(kind, anchor_now_ms);
    }

    let cold_peers: Vec<String> = live_peers
        .into_iter()
        .filter(|candidate| candidate != &owner_peer_id)
        .collect();
    select_cold_window(db_path, recorded_by, peer_id, &cold_peers, now_ms)
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
            SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks | SyncWindowKind::Full => {
                let tier_order = cold_tier_order(planner);
                let was_single_peer_cold = planner.single_peer_phase == SinglePeerPhase::Cold;
                planner.cold_next_idx = (planner.cold_next_idx + 1) % tier_order.len();
                if was_single_peer_cold {
                    planner.single_peer_phase = SinglePeerPhase::LastDay;
                    planner.cycle_anchor_now_ms = None;
                } else if planner.cold_next_idx == 0 {
                    planner.cycle_anchor_now_ms = None;
                }
            }
        }
    }

    if window.kind == SyncWindowKind::LastDay {
        let mut state = tenant_priority_state()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let tenant_state = tenant_state_for(&mut state, db_path, recorded_by);
        tenant_state.owner_idx = tenant_state.owner_idx.saturating_add(1);
        tenant_state.cycle_anchor_now_ms = None;
    }
}

pub fn restrict_outbound_windows_to_last_week(db_path: &str, recorded_by: &str, peer_id: &str) {
    let mut state = planner_state()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let planner = state_for(&mut state, db_path, recorded_by, peer_id);
    planner.restrict_to_low_mem_windows = true;
    planner.cold_next_idx %= LOW_MEM_COLD_TIER_ORDER.len();
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
            ts_max_exclusive_ms: Some(now_ms),
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
    fn select_outbound_window_decision_context_prioritizes_hot_window_owner() {
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
            SelectOutboundWindowPlan::SinglePeer
        );
        assert_eq!(
            decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
                last_day_only_mode: false,
                normalized_live_peer_count: 3,
                peer_is_priority_owner: true,
            }),
            SelectOutboundWindowPlan::MultiPeerPriorityOwner
        );
        assert_eq!(
            decide_select_outbound_window_plan(&SelectOutboundWindowDecisionContext {
                last_day_only_mode: false,
                normalized_live_peer_count: 3,
                peer_is_priority_owner: false,
            }),
            SelectOutboundWindowPlan::MultiPeerCold
        );
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
                SyncWindowKind::Full,
                SyncWindowKind::LastDay,
                SyncWindowKind::LastWeek,
                SyncWindowKind::LastDay,
                SyncWindowKind::LastTwelveWeeks,
                SyncWindowKind::LastDay,
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
    fn scheduler_uses_adjacent_non_full_windows() {
        let day = window_for_kind(SyncWindowKind::LastDay, 1_000_000);
        let week = window_for_kind(SyncWindowKind::LastWeek, 1_000_000);
        let twelve_weeks = window_for_kind(SyncWindowKind::LastTwelveWeeks, 1_000_000);
        let full = window_for_kind(SyncWindowKind::Full, 1_000_000);

        assert_eq!(day.ts_min(), Some(1_000_000 - DAY_MS));
        assert_eq!(day.ts_max_exclusive(), Some(1_000_000));

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
    fn last_day_window_uses_single_owner_and_rotates_across_live_peers() {
        let db_path = "/tmp/window-priority-owner";
        let recorded_by = "tenant-a";
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        let peer_c = "peer-c";
        let live_peers = vec![peer_a.to_string(), peer_b.to_string(), peer_c.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_a);
        reset_outbound_window_state(db_path, recorded_by, peer_b);
        reset_outbound_window_state(db_path, recorded_by, peer_c);

        let day_a = select_outbound_window(db_path, recorded_by, peer_a, &live_peers, 1_000_000);
        let cold_b = select_outbound_window(db_path, recorded_by, peer_b, &live_peers, 1_000_000);
        assert_eq!(day_a.kind, SyncWindowKind::LastDay);
        assert_eq!(cold_b.kind, SyncWindowKind::LastWeek);

        mark_outbound_window_completed(db_path, recorded_by, peer_a, day_a);
        let day_b = select_outbound_window(db_path, recorded_by, peer_b, &live_peers, 1_000_000);
        let cold_a = select_outbound_window(db_path, recorded_by, peer_a, &live_peers, 1_000_000);
        assert_eq!(day_b.kind, SyncWindowKind::LastDay);
        assert_eq!(cold_a.kind, SyncWindowKind::LastWeek);
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
        assert_eq!(day.ts_min(), Some(1_000_000 - DAY_MS));
        assert_eq!(week.ts_min(), Some(1_000_000 - WEEK_MS));
    }

    #[test]
    fn cold_windows_partition_by_live_peer_rank() {
        let db_path = "/tmp/window-partition";
        let recorded_by = "tenant-a";
        let peer_b = "peer-b";
        let peer_c = "peer-c";
        let live_peers = vec!["peer-a".to_string(), peer_b.to_string(), peer_c.to_string()];
        reset_outbound_window_state(db_path, recorded_by, "peer-a");
        reset_outbound_window_state(db_path, recorded_by, peer_b);
        reset_outbound_window_state(db_path, recorded_by, peer_c);

        let week_b = select_outbound_window(db_path, recorded_by, peer_b, &live_peers, 1_000_000);
        let week_c = select_outbound_window(db_path, recorded_by, peer_c, &live_peers, 1_000_000);

        assert_eq!(week_b.kind, SyncWindowKind::LastWeek);
        assert_eq!(week_c.kind, SyncWindowKind::LastWeek);
        assert_eq!(week_b.ts_min(), week_c.ts_max_exclusive());
        assert_eq!(week_b.ts_min(), Some(1_000_000 - (4 * DAY_MS)));
        assert_eq!(week_b.ts_max_exclusive(), Some(1_000_000 - DAY_MS));
        assert_eq!(week_c.ts_min(), Some(1_000_000 - WEEK_MS));
        assert_eq!(week_c.ts_max_exclusive(), Some(1_000_000 - (4 * DAY_MS)));
    }

    #[test]
    fn cold_windows_expand_when_live_peer_set_shrinks() {
        let db_path = "/tmp/window-peer-loss";
        let recorded_by = "tenant-a";
        let peer_b = "peer-b";
        reset_outbound_window_state(db_path, recorded_by, "peer-a");
        reset_outbound_window_state(db_path, recorded_by, peer_b);
        reset_outbound_window_state(db_path, recorded_by, "peer-c");
        let split_week = select_outbound_window(
            db_path,
            recorded_by,
            peer_b,
            &[
                "peer-a".to_string(),
                peer_b.to_string(),
                "peer-c".to_string(),
            ],
            1_000_000,
        );
        let single_week = select_outbound_window(
            db_path,
            recorded_by,
            peer_b,
            &["peer-a".to_string(), peer_b.to_string()],
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

        for peer in peers.iter().skip(1) {
            for _ in 0..2 {
                let window = select_outbound_window(db_path, recorded_by, peer, &peers, now_ms);
                mark_outbound_window_completed(db_path, recorded_by, peer, window);
            }
        }

        let mut full_windows: Vec<SyncWindow> = peers
            .iter()
            .skip(1)
            .map(|peer| select_outbound_window(db_path, recorded_by, peer, &peers, now_ms))
            .collect();
        full_windows.sort_by_key(|window| window.ts_min());

        assert_eq!(full_windows.len(), 3);
        assert_eq!(full_windows[0].ts_min(), Some(ALL_START_MS));
        assert_eq!(
            full_windows[2].ts_max_exclusive(),
            Some(now_ms - TWELVE_WEEK_MS)
        );
        for pair in full_windows.windows(2) {
            assert_eq!(pair[0].ts_max_exclusive(), pair[1].ts_min());
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
        let encoded = encode_initial_neg_open(window, payload.clone());
        let (decoded_window, inner) = decode_initial_neg_open(&encoded).unwrap();

        assert_eq!(decoded_window, window);
        assert_eq!(inner, payload.as_slice());
    }
}
