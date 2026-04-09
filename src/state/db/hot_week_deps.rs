use std::collections::HashSet;

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::db::dep_index::list_shared_event_deps;
use crate::sync::session::windowing::{SyncWindow, SyncWindowKind};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const WEEK_MS: i64 = 7 * DAY_MS;
const HOT_WEEK_DEP_RETAIN_WEEKS: i64 = 13;

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS hot_week_dep_index (
            workspace_id TEXT NOT NULL,
            week_start_ms INTEGER NOT NULL,
            dep_created_at_ms INTEGER NOT NULL,
            event_id TEXT NOT NULL,
            PRIMARY KEY (workspace_id, week_start_ms, event_id)
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS idx_hot_week_dep_index_lookup
            ON hot_week_dep_index(workspace_id, week_start_ms, dep_created_at_ms, event_id);
        CREATE INDEX IF NOT EXISTS idx_hot_week_dep_index_prune
            ON hot_week_dep_index(week_start_ms);
        ",
    )?;
    Ok(())
}

fn utc_day_start_ms(ts_ms: i64) -> i64 {
    ts_ms.div_euclid(DAY_MS) * DAY_MS
}

pub fn utc_week_start_ms(ts_ms: i64) -> i64 {
    let day_start_ms = utc_day_start_ms(ts_ms);
    let days_since_epoch = day_start_ms.div_euclid(DAY_MS);
    let weekday_monday_zero = (days_since_epoch + 3).rem_euclid(7);
    day_start_ms - (weekday_monday_zero * DAY_MS)
}

fn oldest_retained_week_start_ms(now_ms: i64) -> i64 {
    utc_week_start_ms(now_ms) - ((HOT_WEEK_DEP_RETAIN_WEEKS - 1) * WEEK_MS)
}

fn prune_expired_hot_week_rows(conn: &Connection, now_ms: i64) -> SqliteResult<()> {
    conn.execute(
        "DELETE FROM hot_week_dep_index
         WHERE week_start_ms < ?1",
        params![oldest_retained_week_start_ms(now_ms)],
    )?;
    Ok(())
}

fn load_shared_created_at_ms(conn: &Connection, event_id: &EventId) -> SqliteResult<Option<i64>> {
    conn.query_row(
        "SELECT created_at
         FROM events
         WHERE event_id = ?1
           AND share_scope = 'shared'",
        params![event_id_to_base64(event_id)],
        |row| row.get(0),
    )
    .optional()
}

pub fn track_valid_shared_event_deps(
    conn: &Connection,
    workspace_id: &str,
    root_event_id: &EventId,
    root_created_at_ms: i64,
    now_ms: i64,
) -> SqliteResult<()> {
    prune_expired_hot_week_rows(conn, now_ms)?;

    let week_start_ms = utc_week_start_ms(root_created_at_ms);
    if week_start_ms < oldest_retained_week_start_ms(now_ms) {
        return Ok(());
    }

    let mut seen = HashSet::new();
    let mut pending = list_shared_event_deps(conn, workspace_id, root_event_id)?;

    while let Some(event_id) = pending.pop() {
        if !seen.insert(event_id) {
            continue;
        }
        let Some(dep_created_at_ms) = load_shared_created_at_ms(conn, &event_id)? else {
            continue;
        };
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO hot_week_dep_index
             (workspace_id, week_start_ms, dep_created_at_ms, event_id)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                workspace_id,
                week_start_ms,
                dep_created_at_ms,
                event_id_to_base64(&event_id)
            ],
        )?;
        if inserted == 0 {
            continue;
        }
        pending.extend(list_shared_event_deps(conn, workspace_id, &event_id)?);
    }

    Ok(())
}

pub fn week_starts_for_window(window: SyncWindow, now_ms: i64) -> Vec<i64> {
    let Some(start_ms) = window.ts_min() else {
        return Vec::new();
    };
    let end_exclusive_ms = window.ts_max_exclusive().unwrap_or(now_ms);
    if end_exclusive_ms <= start_ms {
        return Vec::new();
    }

    let mut week_starts = Vec::new();
    let mut week_start = utc_week_start_ms(start_ms);
    let last_week_start = utc_week_start_ms(end_exclusive_ms - 1);
    while week_start <= last_week_start {
        week_starts.push(week_start);
        week_start += WEEK_MS;
    }
    week_starts
}

pub fn should_include_week_deps(kind: SyncWindowKind) -> bool {
    matches!(
        kind,
        SyncWindowKind::LastDay | SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks
    )
}

pub fn list_hot_week_dep_entries(
    conn: &Connection,
    workspace_id: &str,
    week_starts_ms: &[i64],
) -> SqliteResult<Vec<(i64, EventId)>> {
    if week_starts_ms.is_empty() {
        return Ok(Vec::new());
    }

    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT dep_created_at_ms, event_id
         FROM hot_week_dep_index
         WHERE workspace_id = ?1
           AND week_start_ms = ?2
         ORDER BY dep_created_at_ms, event_id",
    )?;

    for week_start_ms in week_starts_ms {
        let rows = stmt.query_map(params![workspace_id, week_start_ms], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (created_at_ms, event_id_b64) = row?;
            let Some(event_id) = event_id_from_base64(&event_id_b64) else {
                continue;
            };
            if seen.insert(event_id) {
                entries.push((created_at_ms, event_id));
            }
        }
    }

    entries.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::dep_index::replace_shared_event_deps;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::db::store::{insert_event, insert_shared_event_index_entry_if_shared};
    use crate::event_modules::{encode_event, registry::ShareScope, BenchDepEvent, ParsedEvent};

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
        let event_id = crate::crypto::hash_event(&blob);
        insert_event(
            conn,
            &event_id,
            "bench_dep",
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

    #[test]
    fn track_valid_shared_event_deps_populates_transitive_week_closure_once() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "ws";
        let now_ms = 30 * WEEK_MS;
        let hot_created_at_ms = now_ms - 1_000;

        let root = insert_shared_bench_dep(&conn, workspace_id, 1, vec![], 1);
        let mid = insert_shared_bench_dep(&conn, workspace_id, 2, vec![root], 2);
        let leaf = insert_shared_bench_dep(&conn, workspace_id, hot_created_at_ms, vec![mid], 3);
        replace_shared_event_deps(&conn, workspace_id, &mid, &[root]).unwrap();
        replace_shared_event_deps(&conn, workspace_id, &leaf, &[mid]).unwrap();

        track_valid_shared_event_deps(&conn, workspace_id, &leaf, hot_created_at_ms, now_ms)
            .unwrap();
        track_valid_shared_event_deps(&conn, workspace_id, &leaf, hot_created_at_ms, now_ms)
            .unwrap();

        let dep_entries =
            list_hot_week_dep_entries(&conn, workspace_id, &[utc_week_start_ms(hot_created_at_ms)])
                .unwrap();
        assert_eq!(
            dep_entries
                .into_iter()
                .map(|(_, event_id)| event_id)
                .collect::<Vec<_>>(),
            vec![root, mid]
        );
    }

    #[test]
    fn track_valid_shared_event_deps_prunes_weeks_older_than_thirteen() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "ws";
        let now_ms = 30 * WEEK_MS;
        let very_old_week = utc_week_start_ms(now_ms) - (13 * WEEK_MS);
        let hot_created_at_ms = now_ms - 1_000;
        let hot_week = utc_week_start_ms(hot_created_at_ms);

        conn.execute(
            "INSERT INTO hot_week_dep_index
             (workspace_id, week_start_ms, dep_created_at_ms, event_id)
             VALUES (?1, ?2, 1, ?3)",
            params![workspace_id, very_old_week, event_id_to_base64(&[0x11; 32])],
        )
        .unwrap();

        let root = insert_shared_bench_dep(&conn, workspace_id, 1, vec![], 1);
        let leaf = insert_shared_bench_dep(&conn, workspace_id, hot_created_at_ms, vec![root], 2);
        replace_shared_event_deps(&conn, workspace_id, &leaf, &[root]).unwrap();
        track_valid_shared_event_deps(&conn, workspace_id, &leaf, hot_created_at_ms, now_ms)
            .unwrap();

        let old_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM hot_week_dep_index WHERE week_start_ms = ?1",
                params![very_old_week],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_count, 0);

        let hot_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM hot_week_dep_index WHERE week_start_ms = ?1",
                params![hot_week],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(hot_count, 1);
    }

    #[test]
    fn week_starts_for_window_covers_hot_window_boundaries() {
        let now_ms = 10 * DAY_MS + (6 * 60 * 60 * 1000);
        let last_day = SyncWindow {
            kind: SyncWindowKind::LastDay,
            ts_min_inclusive_ms: Some(now_ms - DAY_MS),
            ts_max_exclusive_ms: Some(now_ms),
        };
        let last_week = SyncWindow {
            kind: SyncWindowKind::LastWeek,
            ts_min_inclusive_ms: Some(now_ms - (7 * DAY_MS)),
            ts_max_exclusive_ms: Some(now_ms - DAY_MS),
        };
        let last_twelve_weeks = SyncWindow {
            kind: SyncWindowKind::LastTwelveWeeks,
            ts_min_inclusive_ms: Some(now_ms - (12 * WEEK_MS)),
            ts_max_exclusive_ms: Some(now_ms - WEEK_MS),
        };

        let last_day_weeks = week_starts_for_window(last_day, now_ms);
        assert_eq!(last_day_weeks.len(), 2);

        let last_week_weeks = week_starts_for_window(last_week, now_ms);
        assert_eq!(last_week_weeks.len(), 2);

        let last_twelve_week_weeks = week_starts_for_window(last_twelve_weeks, now_ms);
        assert_eq!(last_twelve_week_weeks.len(), 12);
    }
}
