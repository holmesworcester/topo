use std::collections::HashSet;

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::db::dep_index::list_shared_event_deps;
use crate::sync::session::windowing::{SyncWindow, SyncWindowKind};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const WEEK_MS: i64 = 7 * DAY_MS;
const RANGE_DEP_RETAIN_WEEKS: i64 = 13;

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS hot_week_dep_index (
            workspace_id TEXT NOT NULL,
            root_created_at_ms INTEGER NOT NULL,
            dep_created_at_ms INTEGER NOT NULL,
            event_id TEXT NOT NULL,
            PRIMARY KEY (workspace_id, root_created_at_ms, event_id)
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS idx_hot_week_dep_index_lookup
            ON hot_week_dep_index(workspace_id, root_created_at_ms, dep_created_at_ms, event_id);
        CREATE INDEX IF NOT EXISTS idx_hot_week_dep_index_workspace_event_root
            ON hot_week_dep_index(workspace_id, event_id, root_created_at_ms);
        CREATE INDEX IF NOT EXISTS idx_hot_week_dep_index_prune
            ON hot_week_dep_index(root_created_at_ms);
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

fn oldest_retained_root_created_at_ms(now_ms: i64) -> i64 {
    utc_week_start_ms(now_ms) - (RANGE_DEP_RETAIN_WEEKS * WEEK_MS)
}

fn prune_expired_hot_week_rows(conn: &Connection, now_ms: i64) -> SqliteResult<()> {
    conn.execute(
        "DELETE FROM hot_week_dep_index
         WHERE root_created_at_ms < ?1",
        params![oldest_retained_root_created_at_ms(now_ms)],
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

    if root_created_at_ms < oldest_retained_root_created_at_ms(now_ms) {
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
             (workspace_id, root_created_at_ms, dep_created_at_ms, event_id)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                workspace_id,
                root_created_at_ms,
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

pub fn should_include_week_deps(kind: SyncWindowKind) -> bool {
    matches!(
        kind,
        SyncWindowKind::LastDay | SyncWindowKind::LastWeek | SyncWindowKind::LastTwelveWeeks
    )
}

pub fn list_hot_week_dep_entries(
    conn: &Connection,
    workspace_id: &str,
    range: SyncWindow,
) -> SqliteResult<Vec<(i64, EventId)>> {
    let Some(ts_min_inclusive_ms) = range.ts_min() else {
        return Ok(Vec::new());
    };
    let Some(ts_max_exclusive_ms) = range.ts_max_exclusive() else {
        return Ok(Vec::new());
    };
    if ts_max_exclusive_ms <= ts_min_inclusive_ms {
        return Ok(Vec::new());
    }

    let mut seen = HashSet::new();
    let mut entries = Vec::new();
    let mut stmt = conn.prepare(
        "SELECT dep_created_at_ms, event_id
         FROM hot_week_dep_index
         WHERE workspace_id = ?1
           AND root_created_at_ms >= ?2
           AND root_created_at_ms < ?3
         ORDER BY dep_created_at_ms, event_id",
    )?;

    let rows = stmt.query_map(
        params![workspace_id, ts_min_inclusive_ms, ts_max_exclusive_ms],
        |row| {
            Ok((
                row.get::<_, i64>(0)?,
                crate::db::sql_types::get_text(row, 1)?,
            ))
        },
    )?;
    for row in rows {
        let (created_at_ms, event_id_b64) = row?;
        let Some(event_id) = event_id_from_base64(&event_id_b64) else {
            continue;
        };
        if seen.insert(event_id) {
            entries.push((created_at_ms, event_id));
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

        let dep_entries = list_hot_week_dep_entries(
            &conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(hot_created_at_ms - 1_000),
                ts_max_exclusive_ms: Some(hot_created_at_ms + 1_000),
            },
        )
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
        let very_old_root_created_at_ms = oldest_retained_root_created_at_ms(now_ms) - 1;
        let hot_created_at_ms = now_ms - 1_000;

        conn.execute(
            "INSERT INTO hot_week_dep_index
             (workspace_id, root_created_at_ms, dep_created_at_ms, event_id)
             VALUES (?1, ?2, 1, ?3)",
            params![
                workspace_id,
                very_old_root_created_at_ms,
                event_id_to_base64(&[0x11; 32])
            ],
        )
        .unwrap();

        let root = insert_shared_bench_dep(&conn, workspace_id, 1, vec![], 1);
        let leaf = insert_shared_bench_dep(&conn, workspace_id, hot_created_at_ms, vec![root], 2);
        replace_shared_event_deps(&conn, workspace_id, &leaf, &[root]).unwrap();
        track_valid_shared_event_deps(&conn, workspace_id, &leaf, hot_created_at_ms, now_ms)
            .unwrap();

        let old_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM hot_week_dep_index WHERE root_created_at_ms = ?1",
                params![very_old_root_created_at_ms],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(old_count, 0);

        let retained_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM hot_week_dep_index WHERE root_created_at_ms = ?1",
                params![hot_created_at_ms],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(retained_count, 1);
    }

    #[test]
    fn list_hot_week_dep_entries_filters_by_root_created_at_range() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "ws";
        let early_dep = event_id_to_base64(&[0x31; 32]);
        let late_dep = event_id_to_base64(&[0x32; 32]);

        conn.execute(
            "INSERT INTO hot_week_dep_index
             (workspace_id, root_created_at_ms, dep_created_at_ms, event_id)
             VALUES (?1, 10, 1, ?2), (?1, 30, 2, ?3)",
            params![workspace_id, early_dep, late_dep],
        )
        .unwrap();

        let early_only = list_hot_week_dep_entries(
            &conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(0),
                ts_max_exclusive_ms: Some(20),
            },
        )
        .unwrap();
        assert_eq!(early_only.len(), 1);

        let late_only = list_hot_week_dep_entries(
            &conn,
            workspace_id,
            SyncWindow {
                kind: SyncWindowKind::LastDay,
                ts_min_inclusive_ms: Some(20),
                ts_max_exclusive_ms: Some(40),
            },
        )
        .unwrap();
        assert_eq!(late_only.len(), 1);
    }
}
