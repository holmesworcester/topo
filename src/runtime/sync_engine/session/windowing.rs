use crate::db::open_connection;
use crate::event_modules::operational::sync_window_selected::{
    self as sync_window_selected, PlannerStateRow,
};

// Re-export types from the event family module — they are the source of truth.
pub use crate::event_modules::operational::sync_window_selected::{
    is_hot_window, SyncWindow, SyncWindowKind,
};

const WINDOW_MAGIC: &[u8; 4] = b"P7SW";
const WINDOW_VERSION: u8 = 2;
const NONE_TS_SENTINEL: i64 = i64::MIN;
const COLD_PARTITION_MAX_LOCAL_MESSAGES: i64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedOutboundWindow {
    pub window: SyncWindow,
    pub planner_next_idx_before: usize,
    pub planner_cycle_anchor_now_ms: Option<i64>,
}

pub fn reset_outbound_window_state(db_path: &str, recorded_by: &str, peer_id: &str) {
    if let Ok(db) = open_connection(db_path) {
        let _ = sync_window_selected::delete(&db, recorded_by, peer_id);
    }
}

pub fn prime_outbound_window_kind(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    kind: SyncWindowKind,
) {
    use crate::event_modules::operational::sync_window_selected::TIER_ORDER;
    let idx = TIER_ORDER
        .iter()
        .position(|candidate| *candidate == kind)
        .unwrap_or(0);
    if let Ok(db) = open_connection(db_path) {
        let _ = sync_window_selected::store(
            &db,
            recorded_by,
            peer_id,
            PlannerStateRow {
                next_idx: idx,
                cycle_anchor_now_ms: None,
            },
        );
    }
}

pub fn select_outbound_window(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    live_peer_ids: &[String],
    now_ms: i64,
) -> SyncWindow {
    select_outbound_window_with_planner(db_path, recorded_by, peer_id, live_peer_ids, now_ms).window
}

pub fn select_outbound_window_with_planner(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    live_peer_ids: &[String],
    now_ms: i64,
) -> SelectedOutboundWindow {
    let mut planner = load_planner_state(db_path, recorded_by, peer_id);
    if planner.cycle_anchor_now_ms.is_none() {
        planner.cycle_anchor_now_ms = Some(now_ms);
        store_planner_state(db_path, recorded_by, peer_id, planner);
    }
    let partition_cold = should_partition_cold_windows(db_path);
    let (window, _kind) =
        sync_window_selected::select_next_window(&planner, peer_id, live_peer_ids, now_ms, partition_cold);
    SelectedOutboundWindow {
        window,
        planner_next_idx_before: planner.next_idx,
        planner_cycle_anchor_now_ms: planner.cycle_anchor_now_ms,
    }
}

pub fn mark_outbound_window_completed(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    _window: SyncWindow,
) {
    let planner = load_planner_state(db_path, recorded_by, peer_id);
    let advanced = sync_window_selected::advance_planner(&planner);
    store_planner_state(db_path, recorded_by, peer_id, advanced);
}

fn load_planner_state(db_path: &str, recorded_by: &str, peer_id: &str) -> PlannerStateRow {
    let db = open_connection(db_path).ok();
    db.and_then(|db| sync_window_selected::load(&db, recorded_by, peer_id).ok())
        .unwrap_or_default()
}

fn store_planner_state(db_path: &str, recorded_by: &str, peer_id: &str, state: PlannerStateRow) {
    if let Ok(db) = open_connection(db_path) {
        let _ = sync_window_selected::store(&db, recorded_by, peer_id, state);
    }
}

fn should_partition_cold_windows(db_path: &str) -> bool {
    let Ok(db) = open_connection(db_path) else {
        return true;
    };
    let message_count: i64 = db
        .query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
        .unwrap_or(0);
    message_count <= COLD_PARTITION_MAX_LOCAL_MESSAGES
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
        1 => SyncWindowKind::LastDay,
        2 => SyncWindowKind::LastWeek,
        3 => SyncWindowKind::LastTwelveWeeks,
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
    use crate::db::{open_connection, schema::create_tables};
    // Import policy functions from the event family for test assertions
    use crate::event_modules::operational::sync_window_selected::{
        select_next_window, advance_planner, window_for_kind, TIER_ORDER,
    };

    const DAY_MS: i64 = 24 * 60 * 60 * 1000;
    const WEEK_MS: i64 = 7 * DAY_MS;
    const TWELVE_WEEK_MS: i64 = 12 * WEEK_MS;
    const ALL_START_MS: i64 = 0;

    fn temp_db_path(label: &str) -> (tempfile::TempDir, String) {
        let dir = tempfile::Builder::new().prefix(label).tempdir().unwrap();
        let path = dir.path().join("sync-window.sqlite");
        let path_str = path.to_string_lossy().to_string();
        let conn = open_connection(&path_str).unwrap();
        create_tables(&conn).unwrap();
        drop(conn);
        (dir, path_str)
    }

    #[test]
    fn range_scheduler_round_robins_windows() {
        let (_dir, db_path) = temp_db_path("window-round-robin");
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(&db_path, recorded_by, peer_id);

        let kinds: Vec<SyncWindowKind> = (0..8)
            .map(|_| {
                let window =
                    select_outbound_window(&db_path, recorded_by, peer_id, &live_peers, 1_000_000);
                let kind = window.kind;
                mark_outbound_window_completed(&db_path, recorded_by, peer_id, window);
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
    fn hot_windows_are_duplicated_across_live_peers() {
        let (_dir, db_path) = temp_db_path("window-hot-dup");
        let recorded_by = "tenant-a";
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        let live_peers = vec![peer_a.to_string(), peer_b.to_string()];
        reset_outbound_window_state(&db_path, recorded_by, peer_a);
        reset_outbound_window_state(&db_path, recorded_by, peer_b);

        let day_a = select_outbound_window(&db_path, recorded_by, peer_a, &live_peers, 1_000_000);
        let day_b = select_outbound_window(&db_path, recorded_by, peer_b, &live_peers, 1_000_000);
        assert_eq!(day_a, day_b);
    }

    #[test]
    fn range_scheduler_uses_stable_cycle_anchor_across_window_steps() {
        let (_dir, db_path) = temp_db_path("window-cycle-anchor");
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];
        reset_outbound_window_state(&db_path, recorded_by, peer_id);

        let day = select_outbound_window(&db_path, recorded_by, peer_id, &live_peers, 1_000_000);
        mark_outbound_window_completed(&db_path, recorded_by, peer_id, day);
        let week = select_outbound_window(&db_path, recorded_by, peer_id, &live_peers, 2_000_000);

        assert_eq!(day.kind, SyncWindowKind::LastDay);
        assert_eq!(week.kind, SyncWindowKind::LastWeek);
        assert_eq!(week.ts_min(), Some(1_000_000 - WEEK_MS));
    }

    #[test]
    fn cold_windows_partition_by_live_peer_rank() {
        let (_dir, db_path) = temp_db_path("window-partition");
        let recorded_by = "tenant-a";
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        let live_peers = vec![peer_a.to_string(), peer_b.to_string()];
        reset_outbound_window_state(&db_path, recorded_by, peer_a);
        reset_outbound_window_state(&db_path, recorded_by, peer_b);

        for _ in 0..1 {
            let a = select_outbound_window(&db_path, recorded_by, peer_a, &live_peers, 1_000_000);
            let b = select_outbound_window(&db_path, recorded_by, peer_b, &live_peers, 1_000_000);
            mark_outbound_window_completed(&db_path, recorded_by, peer_a, a);
            mark_outbound_window_completed(&db_path, recorded_by, peer_b, b);
        }

        let week_a = select_outbound_window(&db_path, recorded_by, peer_a, &live_peers, 1_000_000);
        let week_b = select_outbound_window(&db_path, recorded_by, peer_b, &live_peers, 1_000_000);

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
        let (_dir, db_path) = temp_db_path("window-peer-loss");
        let recorded_by = "tenant-a";
        let peer_a = "peer-a";
        let peer_b = "peer-b";
        reset_outbound_window_state(&db_path, recorded_by, peer_a);
        reset_outbound_window_state(&db_path, recorded_by, peer_b);

        for _ in 0..1 {
            let a = select_outbound_window(
                &db_path,
                recorded_by,
                peer_a,
                &[peer_a.to_string(), peer_b.to_string()],
                1_000_000,
            );
            mark_outbound_window_completed(&db_path, recorded_by, peer_a, a);
        }
        let split_week = select_outbound_window(
            &db_path,
            recorded_by,
            peer_a,
            &[peer_a.to_string(), peer_b.to_string()],
            1_000_000,
        );
        let single_week = select_outbound_window(
            &db_path,
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
        let (_dir, db_path) = temp_db_path("window-full-cover");
        let recorded_by = "tenant-a";
        let peers = vec![
            "peer-a".to_string(),
            "peer-b".to_string(),
            "peer-c".to_string(),
            "peer-d".to_string(),
        ];
        let now_ms = 4 * TWELVE_WEEK_MS;
        for peer in &peers {
            reset_outbound_window_state(&db_path, recorded_by, peer);
        }

        for peer in &peers {
            for _ in 0..3 {
                let window = select_outbound_window(&db_path, recorded_by, peer, &peers, now_ms);
                mark_outbound_window_completed(&db_path, recorded_by, peer, window);
            }
        }

        let mut full_windows: Vec<SyncWindow> = peers
            .iter()
            .map(|peer| select_outbound_window(&db_path, recorded_by, peer, &peers, now_ms))
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

    #[test]
    fn planner_state_is_persisted_in_sqlite() {
        let (_dir, db_path) = temp_db_path("window-state-sqlite");
        let recorded_by = "tenant-a";
        let peer_id = "peer-a";
        let live_peers = vec![peer_id.to_string()];

        let first = select_outbound_window(&db_path, recorded_by, peer_id, &live_peers, 1_000_000);
        assert_eq!(first.kind, SyncWindowKind::LastDay);

        let db = open_connection(&db_path).unwrap();
        let anchored = sync_window_selected::load(&db, recorded_by, peer_id).unwrap();
        assert_eq!(anchored.next_idx, 0);
        assert_eq!(anchored.cycle_anchor_now_ms, Some(1_000_000));
        drop(db);

        mark_outbound_window_completed(&db_path, recorded_by, peer_id, first);

        let db = open_connection(&db_path).unwrap();
        let completed = sync_window_selected::load(&db, recorded_by, peer_id).unwrap();
        assert_eq!(completed.next_idx, 1);
        assert_eq!(completed.cycle_anchor_now_ms, Some(1_000_000));
    }
}
