use std::sync::OnceLock;

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use super::queue::with_sqlite_busy_retry;

#[derive(Clone, Copy)]
enum TimelineGroup {
    Receive,
    Store,
    Projection,
    Blocking,
}

impl TimelineGroup {
    const fn bit(self) -> u8 {
        match self {
            TimelineGroup::Receive => 1 << 0,
            TimelineGroup::Store => 1 << 1,
            TimelineGroup::Projection => 1 << 2,
            TimelineGroup::Blocking => 1 << 3,
        }
    }
}

const ALL_TIMELINE_GROUPS: u8 = TimelineGroup::Receive.bit()
    | TimelineGroup::Store.bit()
    | TimelineGroup::Projection.bit()
    | TimelineGroup::Blocking.bit();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventTimelineRow {
    pub event_id: String,
    pub first_received_at: Option<i64>,
    // First store time. For range sync this is the append-only receive-log
    // write; for direct ingest fallback paths this is the canonical insert.
    pub first_stored_at: Option<i64>,
    pub blocked_at: Option<i64>,
    pub unblocked_at: Option<i64>,
    pub unblocked_by_event_id: Option<String>,
    pub projected_at: Option<i64>,
}

pub struct EventTimeline<'a> {
    conn: &'a Connection,
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS event_timeline (
            event_id TEXT PRIMARY KEY,
            first_received_at INTEGER,
            first_stored_at INTEGER,
            blocked_at INTEGER,
            unblocked_at INTEGER,
            unblocked_by_event_id TEXT,
            projected_at INTEGER
        );
        ",
    )?;
    rename_or_copy_column(conn, "response_received_at", "first_received_at")?;
    rename_or_copy_column(conn, "persisted_at", "first_stored_at")?;
    if !column_exists(conn, "unblocked_by_event_id")? {
        conn.execute(
            "ALTER TABLE event_timeline ADD COLUMN unblocked_by_event_id TEXT",
            [],
        )?;
    }
    Ok(())
}

/// Whether event timeline recording is enabled. Controlled by the
/// `TOPO_EVENT_TIMELINE` env var:
///   "0" / "false" / "no" -> disabled (even in debug builds)
///   "1" / "true" / "yes" -> enabled
///   unset -> enabled in debug builds, disabled in release builds
pub fn recording_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(
        || match std::env::var("TOPO_EVENT_TIMELINE").ok().as_deref() {
            Some("0") | Some("false") | Some("FALSE") | Some("no") | Some("NO") => false,
            Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES") => true,
            _ => cfg!(debug_assertions),
        },
    )
}

fn enabled_groups_mask() -> u8 {
    static GROUPS: OnceLock<u8> = OnceLock::new();
    *GROUPS.get_or_init(|| {
        parse_groups_mask(std::env::var("TOPO_EVENT_TIMELINE_GROUPS").ok().as_deref())
    })
}

fn group_enabled(group: TimelineGroup) -> bool {
    recording_enabled() && (enabled_groups_mask() & group.bit()) != 0
}

fn parse_groups_mask(raw: Option<&str>) -> u8 {
    let Some(raw) = raw else {
        return ALL_TIMELINE_GROUPS;
    };
    let mut mask = 0u8;
    for part in raw.split(',').map(|s| s.trim().to_ascii_lowercase()) {
        match part.as_str() {
            "" => {}
            "all" => return ALL_TIMELINE_GROUPS,
            "receive" | "transfer" => mask |= TimelineGroup::Receive.bit(),
            "store" | "persist" => mask |= TimelineGroup::Store.bit(),
            "projection" => mask |= TimelineGroup::Projection.bit(),
            "blocking" => mask |= TimelineGroup::Blocking.bit(),
            _ => {}
        }
    }
    if mask == 0 {
        ALL_TIMELINE_GROUPS
    } else {
        mask
    }
}

impl<'a> EventTimeline<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    pub fn mark_first_received_b64(&self, event_id_b64: &str, ts: i64) -> SqliteResult<()> {
        if !group_enabled(TimelineGroup::Receive) {
            return Ok(());
        }
        self.mark_b64(event_id_b64, "first_received_at", ts)
    }

    pub fn mark_first_stored_b64(&self, event_id_b64: &str, ts: i64) -> SqliteResult<()> {
        if !group_enabled(TimelineGroup::Store) {
            return Ok(());
        }
        self.mark_b64(event_id_b64, "first_stored_at", ts)
    }

    pub fn mark_received_and_stored_b64(
        &self,
        event_id_b64: &str,
        first_received_at: i64,
        first_stored_at: i64,
    ) -> SqliteResult<()> {
        if !recording_enabled() {
            return Ok(());
        }
        let write_receive = group_enabled(TimelineGroup::Receive);
        let write_store = group_enabled(TimelineGroup::Store);
        if !write_receive && !write_store {
            return Ok(());
        }
        with_sqlite_busy_retry(|| {
            self.conn.execute(
                "INSERT INTO event_timeline (event_id, first_received_at, first_stored_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(event_id) DO UPDATE SET
                     first_received_at = CASE
                         WHEN event_timeline.first_received_at IS NULL AND ?4 != 0 THEN excluded.first_received_at
                         ELSE event_timeline.first_received_at
                     END,
                     first_stored_at = CASE
                         WHEN event_timeline.first_stored_at IS NULL AND ?5 != 0 THEN excluded.first_stored_at
                         ELSE event_timeline.first_stored_at
                     END",
                params![
                    event_id_b64,
                    write_receive.then_some(first_received_at),
                    write_store.then_some(first_stored_at),
                    if write_receive { 1 } else { 0 },
                    if write_store { 1 } else { 0 },
                ],
            )?;
            Ok(())
        })
    }

    pub fn mark_blocked_b64(&self, event_id_b64: &str, ts: i64) -> SqliteResult<()> {
        if !group_enabled(TimelineGroup::Blocking) {
            return Ok(());
        }
        self.mark_b64(event_id_b64, "blocked_at", ts)
    }

    pub fn mark_unblocked_b64(&self, event_id_b64: &str, ts: i64) -> SqliteResult<()> {
        self.mark_unblocked_with_dependency_b64(event_id_b64, ts, None)
    }

    pub fn mark_unblocked_with_dependency_b64(
        &self,
        event_id_b64: &str,
        ts: i64,
        blocker_event_id_b64: Option<&str>,
    ) -> SqliteResult<()> {
        if !group_enabled(TimelineGroup::Blocking) {
            return Ok(());
        }
        with_sqlite_busy_retry(|| {
            self.conn.execute(
                "INSERT INTO event_timeline (event_id, unblocked_at, unblocked_by_event_id)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(event_id) DO UPDATE SET
                     unblocked_at = COALESCE(event_timeline.unblocked_at, excluded.unblocked_at),
                     unblocked_by_event_id = COALESCE(event_timeline.unblocked_by_event_id, excluded.unblocked_by_event_id)",
                params![event_id_b64, ts, blocker_event_id_b64],
            )?;
            Ok(())
        })
    }

    pub fn mark_projected_b64(&self, event_id_b64: &str, ts: i64) -> SqliteResult<()> {
        if !group_enabled(TimelineGroup::Projection) {
            return Ok(());
        }
        self.mark_b64(event_id_b64, "projected_at", ts)
    }

    pub fn load(&self, event_id_b64: &str) -> SqliteResult<Option<EventTimelineRow>> {
        with_sqlite_busy_retry(|| {
            self.conn
                .query_row(
                    "SELECT
                         event_id,
                         first_received_at,
                         first_stored_at,
                         blocked_at,
                         unblocked_at,
                         unblocked_by_event_id,
                         projected_at
                     FROM event_timeline
                     WHERE event_id = ?1",
                    params![event_id_b64],
                    |row| {
                        Ok(EventTimelineRow {
                            event_id: row.get(0)?,
                            first_received_at: row.get(1)?,
                            first_stored_at: row.get(2)?,
                            blocked_at: row.get(3)?,
                            unblocked_at: row.get(4)?,
                            unblocked_by_event_id: row.get(5)?,
                            projected_at: row.get(6)?,
                        })
                    },
                )
                .optional()
        })
    }

    pub fn summary(&self, event_id_b64: &str) -> SqliteResult<Option<String>> {
        let Some(row) = self.load(event_id_b64)? else {
            return Ok(None);
        };
        let spans = [
            span_label(
                "receive_to_store_ms",
                row.first_received_at,
                row.first_stored_at,
            ),
            span_label("store_to_project_ms", row.first_stored_at, row.projected_at),
            span_label("blocked_duration_ms", row.blocked_at, row.unblocked_at),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
        let stages = format!(
            "received={}; stored={}; blocked={}; unblocked={}; unblocked_by={}; projected={}",
            fmt_opt(row.first_received_at),
            fmt_opt(row.first_stored_at),
            fmt_opt(row.blocked_at),
            fmt_opt(row.unblocked_at),
            row.unblocked_by_event_id
                .clone()
                .unwrap_or_else(|| "-".to_string()),
            fmt_opt(row.projected_at),
        );
        let spans = if spans.is_empty() {
            "spans=(none)".to_string()
        } else {
            format!("spans={spans}")
        };
        Ok(Some(format!(
            "event_timeline {}: {}; {}",
            row.event_id, stages, spans
        )))
    }

    fn mark_b64(&self, event_id_b64: &str, column: &str, ts: i64) -> SqliteResult<()> {
        if !recording_enabled() {
            return Ok(());
        }
        with_sqlite_busy_retry(|| {
            let sql = format!(
                "INSERT INTO event_timeline (event_id, {column}) VALUES (?1, ?2)
                 ON CONFLICT(event_id) DO UPDATE SET
                     {column} = COALESCE(event_timeline.{column}, excluded.{column})"
            );
            self.conn.execute(&sql, params![event_id_b64, ts])?;
            Ok(())
        })
    }
}

fn fmt_opt(value: Option<i64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn column_exists(conn: &Connection, column: &str) -> SqliteResult<bool> {
    let mut stmt = conn.prepare("PRAGMA table_info(event_timeline)")?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(1))?;
    for row in rows {
        if row? == column {
            return Ok(true);
        }
    }
    Ok(false)
}

fn rename_or_copy_column(
    conn: &Connection,
    old_column: &str,
    new_column: &str,
) -> SqliteResult<()> {
    if column_exists(conn, new_column)? || !column_exists(conn, old_column)? {
        return Ok(());
    }

    let rename_sql =
        format!("ALTER TABLE event_timeline RENAME COLUMN {old_column} TO {new_column}");
    match conn.execute(&rename_sql, []) {
        Ok(_) => Ok(()),
        Err(_) => {
            let add_sql = format!("ALTER TABLE event_timeline ADD COLUMN {new_column} INTEGER");
            conn.execute(&add_sql, [])?;
            let copy_sql = format!(
                "UPDATE event_timeline SET {new_column} = {old_column} WHERE {new_column} IS NULL"
            );
            conn.execute(&copy_sql, [])?;
            Ok(())
        }
    }
}

fn span_label(label: &str, start: Option<i64>, end: Option<i64>) -> Option<String> {
    Some(format!("{label}={}", end?.saturating_sub(start?)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{event_id_to_base64, EventId};
    use crate::db::{open_in_memory, schema::create_tables};

    fn event_id(byte: u8) -> EventId {
        let mut event_id = [0u8; 32];
        event_id[0] = byte;
        event_id
    }

    #[test]
    fn timeline_stage_timestamps_are_first_write_wins() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let timeline = EventTimeline::new(&conn);
        let event_id = event_id(7);
        let event_id_b64 = event_id_to_base64(&event_id);

        timeline.mark_first_received_b64(&event_id_b64, 50).unwrap();
        timeline.mark_first_stored_b64(&event_id_b64, 60).unwrap();
        timeline.mark_first_stored_b64(&event_id_b64, 70).unwrap();
        timeline.mark_blocked_b64(&event_id_b64, 65).unwrap();
        timeline
            .mark_unblocked_with_dependency_b64(&event_id_b64, 80, Some("dep-1"))
            .unwrap();
        timeline.mark_projected_b64(&event_id_b64, 90).unwrap();

        let row = timeline.load(&event_id_b64).unwrap().unwrap();
        assert_eq!(row.first_received_at, Some(50));
        assert_eq!(row.first_stored_at, Some(60));
        assert_eq!(row.blocked_at, Some(65));
        assert_eq!(row.unblocked_at, Some(80));
        assert_eq!(row.unblocked_by_event_id.as_deref(), Some("dep-1"));
        assert_eq!(row.projected_at, Some(90));

        let summary = timeline.summary(&event_id_b64).unwrap().unwrap();
        assert!(summary.contains("store_to_project_ms=30"));
        assert!(summary.contains("unblocked_by=dep-1"));
    }

    #[test]
    fn parse_groups_mask_accepts_named_subsets() {
        let mask = parse_groups_mask(Some("transfer,persist,blocking"));
        assert_ne!(mask & TimelineGroup::Receive.bit(), 0);
        assert_ne!(mask & TimelineGroup::Store.bit(), 0);
        assert_ne!(mask & TimelineGroup::Blocking.bit(), 0);
        assert_eq!(mask & TimelineGroup::Projection.bit(), 0);
    }
}
