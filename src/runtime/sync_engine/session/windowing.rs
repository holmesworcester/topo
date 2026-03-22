use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncWindowKind {
    Full = 0,
    LastHour = 1,
    LastDay = 2,
    LastWeek = 3,
    LastMonth = 4,
    LastYear = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncWindow {
    pub kind: SyncWindowKind,
    pub ts_min_inclusive_ms: Option<i64>,
    pub ts_max_exclusive_ms: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncWindowShape {
    Nested,
    Disjoint,
}

const WINDOW_MAGIC: &[u8; 4] = b"P7SW";
const WINDOW_VERSION: u8 = 2;
const NONE_TS_SENTINEL: i64 = i64::MIN;
const ALL_START_MS: i64 = 0;
const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const WEEK_MS: i64 = 7 * DAY_MS;
const MONTH_MS: i64 = 30 * DAY_MS;
const YEAR_MS: i64 = 365 * DAY_MS;
const TIER_ORDER: [SyncWindowKind; 6] = [
    SyncWindowKind::LastHour,
    SyncWindowKind::LastDay,
    SyncWindowKind::LastWeek,
    SyncWindowKind::LastMonth,
    SyncWindowKind::LastYear,
    SyncWindowKind::Full,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PlannerState {
    next_idx: usize,
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
        .or_insert(PlannerState { next_idx: 0 })
}

pub fn sync_window_shape() -> SyncWindowShape {
    match std::env::var("TOPO_SYNC_WINDOW_SHAPE")
        .ok()
        .unwrap_or_else(|| "nested".to_string())
        .to_lowercase()
        .as_str()
    {
        "disjoint" => SyncWindowShape::Disjoint,
        _ => SyncWindowShape::Nested,
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
    let idx = TIER_ORDER
        .iter()
        .position(|candidate| *candidate == kind)
        .unwrap_or(0);
    planner.next_idx = idx;
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
    let idx = planner.next_idx % TIER_ORDER.len();
    let kind = TIER_ORDER[idx];
    assign_window(window_for_kind(kind, now_ms), kind, peer_id, live_peer_ids, now_ms)
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
    planner.next_idx = (planner.next_idx + 1) % TIER_ORDER.len();
}

fn window_for_kind(kind: SyncWindowKind, now_ms: i64) -> SyncWindow {
    match (sync_window_shape(), kind) {
        (SyncWindowShape::Nested, SyncWindowKind::Full) => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(ALL_START_MS),
            ts_max_exclusive_ms: Some(now_ms),
        },
        (SyncWindowShape::Disjoint, SyncWindowKind::Full) => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(ALL_START_MS),
            ts_max_exclusive_ms: Some(now_ms - YEAR_MS),
        },
        (SyncWindowShape::Nested, SyncWindowKind::LastHour) => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(now_ms - HOUR_MS),
            ts_max_exclusive_ms: None,
        },
        (SyncWindowShape::Nested, SyncWindowKind::LastDay) => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(now_ms - DAY_MS),
            ts_max_exclusive_ms: None,
        },
        (SyncWindowShape::Nested, SyncWindowKind::LastWeek) => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(now_ms - WEEK_MS),
            ts_max_exclusive_ms: None,
        },
        (SyncWindowShape::Nested, SyncWindowKind::LastMonth) => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(now_ms - MONTH_MS),
            ts_max_exclusive_ms: None,
        },
        (SyncWindowShape::Nested, SyncWindowKind::LastYear) => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(now_ms - YEAR_MS),
            ts_max_exclusive_ms: None,
        },
        (SyncWindowShape::Disjoint, SyncWindowKind::LastHour) => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(now_ms - HOUR_MS),
            ts_max_exclusive_ms: None,
        },
        (SyncWindowShape::Disjoint, SyncWindowKind::LastDay) => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(now_ms - DAY_MS),
            ts_max_exclusive_ms: Some(now_ms - HOUR_MS),
        },
        (SyncWindowShape::Disjoint, SyncWindowKind::LastWeek) => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(now_ms - WEEK_MS),
            ts_max_exclusive_ms: Some(now_ms - DAY_MS),
        },
        (SyncWindowShape::Disjoint, SyncWindowKind::LastMonth) => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(now_ms - MONTH_MS),
            ts_max_exclusive_ms: Some(now_ms - WEEK_MS),
        },
        (SyncWindowShape::Disjoint, SyncWindowKind::LastYear) => SyncWindow {
            kind,
            ts_min_inclusive_ms: Some(now_ms - YEAR_MS),
            ts_max_exclusive_ms: Some(now_ms - MONTH_MS),
        },
    }
}

fn is_hot_window(kind: SyncWindowKind) -> bool {
    matches!(kind, SyncWindowKind::LastHour | SyncWindowKind::LastDay)
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

fn partition_window(window: SyncWindow, peer_rank: usize, peer_count: usize, now_ms: i64) -> SyncWindow {
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
    let kind = match msg[5] {
        0 => SyncWindowKind::Full,
        1 => SyncWindowKind::LastHour,
        2 => SyncWindowKind::LastDay,
        3 => SyncWindowKind::LastWeek,
        4 => SyncWindowKind::LastMonth,
        5 => SyncWindowKind::LastYear,
        other => return Err(format!("unsupported sync window kind {}", other)),
    };
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

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn range_scheduler_round_robins_windows() {
        let _guard = env_guard();
        std::env::remove_var("TOPO_SYNC_WINDOW_SHAPE");
        let db_path = "/tmp/window-round-robin";
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_id);

        let kinds: Vec<SyncWindowKind> = (0..8)
            .map(|_| {
                let window = select_outbound_window(
                    db_path,
                    recorded_by,
                    peer_id,
                    &live_peers,
                    1_000_000,
                );
                let kind = window.kind;
                mark_outbound_window_completed(db_path, recorded_by, peer_id, window);
                kind
            })
            .collect();

        assert_eq!(
            kinds,
            vec![
                SyncWindowKind::LastHour,
                SyncWindowKind::LastDay,
                SyncWindowKind::LastWeek,
                SyncWindowKind::LastMonth,
                SyncWindowKind::LastYear,
                SyncWindowKind::Full,
                SyncWindowKind::LastHour,
                SyncWindowKind::LastDay
            ]
        );
        std::env::remove_var("TOPO_SYNC_WINDOW_SHAPE");
    }

    #[test]
    fn disjoint_shape_uses_adjacent_non_full_windows() {
        let _guard = env_guard();
        std::env::set_var("TOPO_SYNC_WINDOW_SHAPE", "disjoint");

        let hour = window_for_kind(SyncWindowKind::LastHour, 1_000_000);
        let day = window_for_kind(SyncWindowKind::LastDay, 1_000_000);
        let week = window_for_kind(SyncWindowKind::LastWeek, 1_000_000);
        let month = window_for_kind(SyncWindowKind::LastMonth, 1_000_000);
        let year = window_for_kind(SyncWindowKind::LastYear, 1_000_000);
        let full = window_for_kind(SyncWindowKind::Full, 1_000_000);

        assert_eq!(hour.ts_min(), Some(1_000_000 - HOUR_MS));
        assert_eq!(hour.ts_max_exclusive(), None);

        assert_eq!(day.ts_min(), Some(1_000_000 - DAY_MS));
        assert_eq!(day.ts_max_exclusive(), Some(1_000_000 - HOUR_MS));

        assert_eq!(week.ts_min(), Some(1_000_000 - WEEK_MS));
        assert_eq!(week.ts_max_exclusive(), Some(1_000_000 - DAY_MS));

        assert_eq!(month.ts_min(), Some(1_000_000 - MONTH_MS));
        assert_eq!(month.ts_max_exclusive(), Some(1_000_000 - WEEK_MS));

        assert_eq!(year.ts_min(), Some(1_000_000 - YEAR_MS));
        assert_eq!(year.ts_max_exclusive(), Some(1_000_000 - MONTH_MS));

        assert_eq!(full.ts_min(), Some(ALL_START_MS));
        assert_eq!(full.ts_max_exclusive(), Some(1_000_000 - YEAR_MS));

        std::env::remove_var("TOPO_SYNC_WINDOW_SHAPE");
    }

    #[test]
    fn hot_windows_are_duplicated_across_live_peers() {
        let _guard = env_guard();
        std::env::remove_var("TOPO_SYNC_WINDOW_SHAPE");
        let db_path = "/tmp/window-hot-dup";
        let recorded_by = "tenant-a";
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        let live_peers = vec![peer_a.to_string(), peer_b.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_a);
        reset_outbound_window_state(db_path, recorded_by, peer_b);

        let hour_a = select_outbound_window(
            db_path,
            recorded_by,
            peer_a,
            &live_peers,
            1_000_000,
        );
        let hour_b = select_outbound_window(
            db_path,
            recorded_by,
            peer_b,
            &live_peers,
            1_000_000,
        );
        assert_eq!(hour_a, hour_b);

        mark_outbound_window_completed(db_path, recorded_by, peer_a, hour_a);
        mark_outbound_window_completed(db_path, recorded_by, peer_b, hour_b);

        let day_a = select_outbound_window(
            db_path,
            recorded_by,
            peer_a,
            &live_peers,
            1_000_000,
        );
        let day_b = select_outbound_window(
            db_path,
            recorded_by,
            peer_b,
            &live_peers,
            1_000_000,
        );
        assert_eq!(day_a, day_b);
    }

    #[test]
    fn cold_windows_partition_by_live_peer_rank() {
        let _guard = env_guard();
        std::env::set_var("TOPO_SYNC_WINDOW_SHAPE", "disjoint");
        let db_path = "/tmp/window-partition";
        let recorded_by = "tenant-a";
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        let live_peers = vec![peer_a.to_string(), peer_b.to_string()];
        reset_outbound_window_state(db_path, recorded_by, peer_a);
        reset_outbound_window_state(db_path, recorded_by, peer_b);

        for _ in 0..2 {
            let a = select_outbound_window(
                db_path,
                recorded_by,
                peer_a,
                &live_peers,
                1_000_000,
            );
            let b = select_outbound_window(
                db_path,
                recorded_by,
                peer_b,
                &live_peers,
                1_000_000,
            );
            mark_outbound_window_completed(db_path, recorded_by, peer_a, a);
            mark_outbound_window_completed(db_path, recorded_by, peer_b, b);
        }

        let week_a = select_outbound_window(
            db_path,
            recorded_by,
            peer_a,
            &live_peers,
            1_000_000,
        );
        let week_b = select_outbound_window(
            db_path,
            recorded_by,
            peer_b,
            &live_peers,
            1_000_000,
        );

        assert_eq!(week_a.kind, SyncWindowKind::LastWeek);
        assert_eq!(week_b.kind, SyncWindowKind::LastWeek);
        assert_eq!(week_a.ts_min(), week_b.ts_max_exclusive());
        assert_eq!(week_a.ts_min(), Some(1_000_000 - (4 * DAY_MS)));
        assert_eq!(week_a.ts_max_exclusive(), Some(1_000_000 - DAY_MS));
        assert_eq!(week_b.ts_min(), Some(1_000_000 - WEEK_MS));
        assert_eq!(week_b.ts_max_exclusive(), Some(1_000_000 - (4 * DAY_MS)));

        std::env::remove_var("TOPO_SYNC_WINDOW_SHAPE");
    }

    #[test]
    fn cold_windows_expand_when_live_peer_set_shrinks() {
        let _guard = env_guard();
        std::env::set_var("TOPO_SYNC_WINDOW_SHAPE", "disjoint");
        let db_path = "/tmp/window-peer-loss";
        let recorded_by = "tenant-a";
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        reset_outbound_window_state(db_path, recorded_by, peer_a);
        reset_outbound_window_state(db_path, recorded_by, peer_b);

        for _ in 0..2 {
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

        std::env::remove_var("TOPO_SYNC_WINDOW_SHAPE");
    }

    #[test]
    fn full_range_partitions_cover_without_overlap() {
        let _guard = env_guard();
        std::env::set_var("TOPO_SYNC_WINDOW_SHAPE", "disjoint");
        let db_path = "/tmp/window-full-cover";
        let recorded_by = "tenant-a";
        let peers = vec![
            "peer-a".to_string(),
            "peer-b".to_string(),
            "peer-c".to_string(),
            "peer-d".to_string(),
        ];
        let now_ms = 4 * YEAR_MS;
        for peer in &peers {
            reset_outbound_window_state(db_path, recorded_by, peer);
        }

        for peer in &peers {
            for _ in 0..5 {
                let window =
                    select_outbound_window(db_path, recorded_by, peer, &peers, now_ms);
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
        assert_eq!(full_windows[3].ts_max_exclusive(), Some(3 * YEAR_MS));
        for pair in full_windows.windows(2) {
            assert_eq!(pair[0].ts_max_exclusive(), pair[1].ts_min());
        }

        std::env::remove_var("TOPO_SYNC_WINDOW_SHAPE");
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
