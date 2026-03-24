use std::sync::OnceLock;

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use super::queue::with_sqlite_busy_retry;

#[derive(Clone, Copy)]
enum TimelineGroup {
    Transfer,
    Persist,
    Projection,
    Blocking,
}

impl TimelineGroup {
    const fn bit(self) -> u8 {
        match self {
            TimelineGroup::Transfer => 1 << 0,
            TimelineGroup::Persist => 1 << 1,
            TimelineGroup::Projection => 1 << 2,
            TimelineGroup::Blocking => 1 << 3,
        }
    }
}

const ALL_TIMELINE_GROUPS: u8 = TimelineGroup::Transfer.bit()
    | TimelineGroup::Persist.bit()
    | TimelineGroup::Projection.bit()
    | TimelineGroup::Blocking.bit();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventTimelineRow {
    pub event_id: String,
    pub response_received_at: Option<i64>,
    // First durable store time. For range sync this is the append-only receive
    // log write; for direct ingest fallback paths this is the canonical insert.
    pub persisted_at: Option<i64>,
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
            response_received_at INTEGER,
            persisted_at INTEGER,
            blocked_at INTEGER,
            unblocked_at INTEGER,
            unblocked_by_event_id TEXT,
            projected_at INTEGER
        );
        ",
    )?;
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
            "transfer" => mask |= TimelineGroup::Transfer.bit(),
            "persist" => mask |= TimelineGroup::Persist.bit(),
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

    pub fn mark_response_received_b64(&self, event_id_b64: &str, ts: i64) -> SqliteResult<()> {
        if !group_enabled(TimelineGroup::Transfer) {
            return Ok(());
        }
        self.mark_b64(event_id_b64, "response_received_at", ts)
    }

    pub fn mark_persisted_b64(&self, event_id_b64: &str, ts: i64) -> SqliteResult<()> {
        if !group_enabled(TimelineGroup::Persist) {
            return Ok(());
        }
        self.mark_b64(event_id_b64, "persisted_at", ts)
    }

    pub fn mark_received_and_persisted_b64(
        &self,
        event_id_b64: &str,
        response_received_at: i64,
        persisted_at: i64,
    ) -> SqliteResult<()> {
        if !recording_enabled() {
            return Ok(());
        }
        let write_transfer = group_enabled(TimelineGroup::Transfer);
        let write_persist = group_enabled(TimelineGroup::Persist);
        if !write_transfer && !write_persist {
            return Ok(());
        }
        with_sqlite_busy_retry(|| {
            self.conn.execute(
                "INSERT INTO event_timeline (event_id, response_received_at, persisted_at)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(event_id) DO UPDATE SET
                     response_received_at = CASE
                         WHEN event_timeline.response_received_at IS NULL AND ?4 != 0 THEN excluded.response_received_at
                         ELSE event_timeline.response_received_at
                     END,
                     persisted_at = CASE
                         WHEN event_timeline.persisted_at IS NULL AND ?5 != 0 THEN excluded.persisted_at
                         ELSE event_timeline.persisted_at
                     END",
                params![
                    event_id_b64,
                    write_transfer.then_some(response_received_at),
                    write_persist.then_some(persisted_at),
                    if write_transfer { 1 } else { 0 },
                    if write_persist { 1 } else { 0 },
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
                         response_received_at,
                         persisted_at,
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
                            response_received_at: row.get(1)?,
                            persisted_at: row.get(2)?,
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
                row.response_received_at,
                row.persisted_at,
            ),
            span_label("store_to_project_ms", row.persisted_at, row.projected_at),
            span_label("blocked_duration_ms", row.blocked_at, row.unblocked_at),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
        let stages = format!(
            "resp_recv={}; stored={}; blocked={}; unblocked={}; unblocked_by={}; projected={}",
            fmt_opt(row.response_received_at),
            fmt_opt(row.persisted_at),
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

        timeline
            .mark_response_received_b64(&event_id_b64, 50)
            .unwrap();
        timeline.mark_persisted_b64(&event_id_b64, 60).unwrap();
        timeline.mark_persisted_b64(&event_id_b64, 70).unwrap();
        timeline.mark_blocked_b64(&event_id_b64, 65).unwrap();
        timeline
            .mark_unblocked_with_dependency_b64(&event_id_b64, 80, Some("dep-1"))
            .unwrap();
        timeline.mark_projected_b64(&event_id_b64, 90).unwrap();

        let row = timeline.load(&event_id_b64).unwrap().unwrap();
        assert_eq!(row.response_received_at, Some(50));
        assert_eq!(row.persisted_at, Some(60));
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
        assert_ne!(mask & TimelineGroup::Transfer.bit(), 0);
        assert_ne!(mask & TimelineGroup::Persist.bit(), 0);
        assert_ne!(mask & TimelineGroup::Blocking.bit(), 0);
        assert_eq!(mask & TimelineGroup::Projection.bit(), 0);
    }
}
