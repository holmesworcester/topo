use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use crate::db::queue::with_sqlite_busy_retry;
use crate::projection::contract::{SqlVal, WriteOp};

// ---------------------------------------------------------------------------
// Sync window types and selection policy (event-family-owned)
// ---------------------------------------------------------------------------

const HOUR_MS: i64 = 60 * 60 * 1000;
const DAY_MS: i64 = 24 * HOUR_MS;
const WEEK_MS: i64 = 7 * DAY_MS;
const TWELVE_WEEK_MS: i64 = 12 * WEEK_MS;
const ALL_START_MS: i64 = 0;

pub const TIER_ORDER: [SyncWindowKind; 4] = [
    SyncWindowKind::LastDay,
    SyncWindowKind::LastWeek,
    SyncWindowKind::LastTwelveWeeks,
    SyncWindowKind::Full,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncWindowKind {
    Full = 0,
    LastDay = 1,
    LastWeek = 2,
    LastTwelveWeeks = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncWindow {
    pub kind: SyncWindowKind,
    pub ts_min_inclusive_ms: Option<i64>,
    pub ts_max_exclusive_ms: Option<i64>,
}

impl SyncWindow {
    pub fn ts_min(self) -> Option<i64> {
        self.ts_min_inclusive_ms
    }
    pub fn ts_max_exclusive(self) -> Option<i64> {
        self.ts_max_exclusive_ms
    }
}

pub fn is_hot_window(kind: SyncWindowKind) -> bool {
    matches!(kind, SyncWindowKind::LastDay)
}

/// Pure selection: given planner state + context, deterministically select
/// the next sync window. No I/O. This is the event-family-owned policy.
pub fn select_next_window(
    planner: &PlannerStateRow,
    peer_id: &str,
    live_peer_ids: &[String],
    now_ms: i64,
    partition_cold: bool,
) -> (SyncWindow, SyncWindowKind) {
    let anchor_now_ms = planner.cycle_anchor_now_ms.unwrap_or(now_ms);
    let idx = planner.next_idx % TIER_ORDER.len();
    let kind = TIER_ORDER[idx];
    let base = window_for_kind(kind, anchor_now_ms);
    let window = assign_window(base, kind, peer_id, live_peer_ids, anchor_now_ms, partition_cold);
    (window, kind)
}

/// Advance planner state after a round completes.
pub fn advance_planner(planner: &PlannerStateRow) -> PlannerStateRow {
    let next_idx = (planner.next_idx + 1) % TIER_ORDER.len();
    PlannerStateRow {
        next_idx,
        cycle_anchor_now_ms: if next_idx == 0 {
            None
        } else {
            planner.cycle_anchor_now_ms
        },
    }
}

pub fn window_for_kind(kind: SyncWindowKind, now_ms: i64) -> SyncWindow {
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

fn normalized_live_peers(peer_id: &str, live_peer_ids: &[String]) -> Vec<String> {
    let mut peers = live_peer_ids.to_vec();
    if !peers.iter().any(|candidate| candidate == peer_id) {
        peers.push(peer_id.to_string());
    }
    peers.sort();
    peers.dedup();
    peers
}

fn assign_window(
    window: SyncWindow,
    kind: SyncWindowKind,
    peer_id: &str,
    live_peer_ids: &[String],
    now_ms: i64,
    partition_cold: bool,
) -> SyncWindow {
    if is_hot_window(kind) {
        return window;
    }
    if !partition_cold {
        return window;
    }
    let peers = normalized_live_peers(peer_id, live_peer_ids);
    let Some(peer_rank) = peers.iter().position(|candidate| candidate == peer_id) else {
        return window;
    };
    partition_window(window, peer_rank, peers.len(), now_ms)
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
    let start = window.ts_min().unwrap_or(0);
    let end = window.ts_max_exclusive().unwrap_or(now_ms);
    if start >= end {
        return window;
    }
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

/// Durable planner state owned by the future local `sync_window_selected`
/// operational event family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlannerStateRow {
    pub next_idx: usize,
    pub cycle_anchor_now_ms: Option<i64>,
}

impl Default for PlannerStateRow {
    fn default() -> Self {
        Self {
            next_idx: 0,
            cycle_anchor_now_ms: None,
        }
    }
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS sync_window_state_history (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            peer_id TEXT NOT NULL,
            next_idx INTEGER NOT NULL DEFAULT 0,
            cycle_anchor_now_ms INTEGER,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_sync_window_state_history_latest
            ON sync_window_state_history(recorded_by, peer_id, created_at DESC, event_id DESC);
        ",
    )?;
    Ok(())
}

pub fn load(conn: &Connection, recorded_by: &str, peer_id: &str) -> SqliteResult<PlannerStateRow> {
    with_sqlite_busy_retry(|| {
        conn.query_row(
            "SELECT next_idx, cycle_anchor_now_ms
             FROM sync_window_state_history
             WHERE recorded_by = ?1 AND peer_id = ?2
             ORDER BY created_at DESC, rowid DESC
             LIMIT 1",
            params![recorded_by, peer_id],
            |row| {
                Ok(PlannerStateRow {
                    next_idx: row.get::<_, i64>(0)?.max(0) as usize,
                    cycle_anchor_now_ms: row.get(1)?,
                })
            },
        )
        .optional()
        .map(|row| row.unwrap_or_default())
    })
}

pub fn planner_state_write_op(
    recorded_by: &str,
    event_id_b64: &str,
    peer_id: &str,
    state: PlannerStateRow,
    created_at_ms: i64,
) -> WriteOp {
    WriteOp::InsertOrIgnore {
        table: "sync_window_state_history",
        columns: vec![
            "recorded_by",
            "event_id",
            "peer_id",
            "next_idx",
            "cycle_anchor_now_ms",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(peer_id.to_string()),
            SqlVal::Int(state.next_idx as i64),
            state
                .cycle_anchor_now_ms
                .map(SqlVal::Int)
                .unwrap_or(SqlVal::Null),
            SqlVal::Int(created_at_ms),
        ],
    }
}

pub fn store(
    conn: &Connection,
    recorded_by: &str,
    peer_id: &str,
    state: PlannerStateRow,
) -> SqliteResult<()> {
    with_sqlite_busy_retry(|| {
        conn.execute(
            "INSERT INTO sync_window_state_history
                 (recorded_by, event_id, peer_id, next_idx, cycle_anchor_now_ms, created_at)
             VALUES (?1, hex(randomblob(32)), ?2, ?3, ?4, ?5)",
            params![
                recorded_by,
                peer_id,
                state.next_idx as i64,
                state.cycle_anchor_now_ms,
                crate::db::queue::current_timestamp_ms(),
            ],
        )?;
        Ok(())
    })
}

pub fn delete(conn: &Connection, recorded_by: &str, peer_id: &str) -> SqliteResult<()> {
    store(conn, recorded_by, peer_id, PlannerStateRow::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn load_defaults_when_no_state_exists() {
        let conn = setup();
        let state = load(&conn, "tenant-a", "peer-a").unwrap();
        assert_eq!(state, PlannerStateRow::default());
    }

    #[test]
    fn store_and_load_round_trip() {
        let conn = setup();
        let state = PlannerStateRow {
            next_idx: 2,
            cycle_anchor_now_ms: Some(123_456),
        };

        store(&conn, "tenant-a", "peer-a", state).unwrap();

        assert_eq!(load(&conn, "tenant-a", "peer-a").unwrap(), state);
    }

    #[test]
    fn delete_removes_row() {
        let conn = setup();
        store(
            &conn,
            "tenant-a",
            "peer-a",
            PlannerStateRow {
                next_idx: 1,
                cycle_anchor_now_ms: Some(42),
            },
        )
        .unwrap();

        delete(&conn, "tenant-a", "peer-a").unwrap();

        assert_eq!(
            load(&conn, "tenant-a", "peer-a").unwrap(),
            PlannerStateRow::default()
        );
    }
}
