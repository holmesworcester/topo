use std::sync::OnceLock;

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use super::queue::{with_immediate_tx, with_sqlite_busy_retry};
use crate::crypto::{event_id_to_base64, EventId};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventTimelineRow {
    pub event_id: String,
    pub discovery_round_started_at: Option<i64>,
    pub wanted_discovered_at: Option<i64>,
    pub request_sent_at: Option<i64>,
    pub request_received_at: Option<i64>,
    pub response_sent_at: Option<i64>,
    pub response_received_at: Option<i64>,
    pub persisted_at: Option<i64>,
    pub blocked_at: Option<i64>,
    pub unblocked_at: Option<i64>,
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
            discovery_round_started_at INTEGER,
            wanted_discovered_at INTEGER,
            request_sent_at INTEGER,
            request_received_at INTEGER,
            response_sent_at INTEGER,
            response_received_at INTEGER,
            persisted_at INTEGER,
            blocked_at INTEGER,
            unblocked_at INTEGER,
            projected_at INTEGER
        );
        ",
    )?;
    Ok(())
}

pub fn recording_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        cfg!(debug_assertions)
            || std::env::var("TOPO_EVENT_TIMELINE")
                .ok()
                .is_some_and(|v| matches!(v.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
    })
}

impl<'a> EventTimeline<'a> {
    pub fn new(conn: &'a Connection) -> Self {
        Self { conn }
    }

    pub fn mark_discovered_many_with_round_start(
        &self,
        ids: &[EventId],
        round_started_at: i64,
        discovered_at: i64,
    ) -> SqliteResult<usize> {
        if !recording_enabled() || ids.is_empty() {
            return Ok(0);
        }
        with_immediate_tx(self.conn, || {
            let mut stmt = self.conn.prepare(
                "INSERT INTO event_timeline (
                     event_id, discovery_round_started_at, wanted_discovered_at
                 ) VALUES (?1, ?2, ?3)
                 ON CONFLICT(event_id) DO UPDATE SET
                     discovery_round_started_at = COALESCE(event_timeline.discovery_round_started_at, excluded.discovery_round_started_at),
                     wanted_discovered_at = COALESCE(event_timeline.wanted_discovered_at, excluded.wanted_discovered_at)",
            )?;
            let mut changed = 0usize;
            for event_id in ids {
                changed += stmt.execute(params![
                    event_id_to_base64(event_id),
                    round_started_at,
                    discovered_at
                ])?;
            }
            Ok(changed)
        })
    }

    pub fn mark_request_sent_many(&self, ids: &[EventId], ts: i64) -> SqliteResult<usize> {
        self.mark_many(ids, "request_sent_at", ts)
    }

    pub fn mark_request_received_many(&self, ids: &[EventId], ts: i64) -> SqliteResult<usize> {
        self.mark_many(ids, "request_received_at", ts)
    }

    pub fn mark_response_sent(&self, event_id: &EventId, ts: i64) -> SqliteResult<()> {
        self.mark_b64(&event_id_to_base64(event_id), "response_sent_at", ts)
    }

    pub fn mark_response_received_b64(&self, event_id_b64: &str, ts: i64) -> SqliteResult<()> {
        self.mark_b64(event_id_b64, "response_received_at", ts)
    }

    pub fn mark_persisted_b64(&self, event_id_b64: &str, ts: i64) -> SqliteResult<()> {
        self.mark_b64(event_id_b64, "persisted_at", ts)
    }

    pub fn mark_blocked_b64(&self, event_id_b64: &str, ts: i64) -> SqliteResult<()> {
        self.mark_b64(event_id_b64, "blocked_at", ts)
    }

    pub fn mark_unblocked_b64(&self, event_id_b64: &str, ts: i64) -> SqliteResult<()> {
        self.mark_b64(event_id_b64, "unblocked_at", ts)
    }

    pub fn mark_projected_b64(&self, event_id_b64: &str, ts: i64) -> SqliteResult<()> {
        self.mark_b64(event_id_b64, "projected_at", ts)
    }

    pub fn load(&self, event_id_b64: &str) -> SqliteResult<Option<EventTimelineRow>> {
        with_sqlite_busy_retry(|| {
            self.conn
                .query_row(
                    "SELECT
                         event_id,
                         discovery_round_started_at,
                         wanted_discovered_at,
                         request_sent_at,
                         request_received_at,
                         response_sent_at,
                         response_received_at,
                         persisted_at,
                         blocked_at,
                         unblocked_at,
                         projected_at
                     FROM event_timeline
                     WHERE event_id = ?1",
                    params![event_id_b64],
                    |row| {
                        Ok(EventTimelineRow {
                            event_id: row.get(0)?,
                            discovery_round_started_at: row.get(1)?,
                            wanted_discovered_at: row.get(2)?,
                            request_sent_at: row.get(3)?,
                            request_received_at: row.get(4)?,
                            response_sent_at: row.get(5)?,
                            response_received_at: row.get(6)?,
                            persisted_at: row.get(7)?,
                            blocked_at: row.get(8)?,
                            unblocked_at: row.get(9)?,
                            projected_at: row.get(10)?,
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
                "discover_to_request_ms",
                row.wanted_discovered_at,
                row.request_sent_at,
            ),
            span_label(
                "request_transit_ms",
                row.request_sent_at,
                row.request_received_at,
            ),
            span_label(
                "source_queue_ms",
                row.request_received_at,
                row.response_sent_at,
            ),
            span_label(
                "response_transit_ms",
                row.response_sent_at,
                row.response_received_at,
            ),
            span_label(
                "receive_to_persist_ms",
                row.response_received_at,
                row.persisted_at,
            ),
            span_label("persist_to_project_ms", row.persisted_at, row.projected_at),
            span_label("blocked_duration_ms", row.blocked_at, row.unblocked_at),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>()
        .join(", ");
        let stages = format!(
            "discover_start={}; wanted={}; req_sent={}; req_recv={}; resp_sent={}; resp_recv={}; persisted={}; blocked={}; unblocked={}; projected={}",
            fmt_opt(row.discovery_round_started_at),
            fmt_opt(row.wanted_discovered_at),
            fmt_opt(row.request_sent_at),
            fmt_opt(row.request_received_at),
            fmt_opt(row.response_sent_at),
            fmt_opt(row.response_received_at),
            fmt_opt(row.persisted_at),
            fmt_opt(row.blocked_at),
            fmt_opt(row.unblocked_at),
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

    fn mark_many(&self, ids: &[EventId], column: &str, ts: i64) -> SqliteResult<usize> {
        if !recording_enabled() || ids.is_empty() {
            return Ok(0);
        }
        with_immediate_tx(self.conn, || {
            let sql = format!(
                "INSERT INTO event_timeline (event_id, {column}) VALUES (?1, ?2)
                 ON CONFLICT(event_id) DO UPDATE SET
                     {column} = COALESCE(event_timeline.{column}, excluded.{column})"
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let mut changed = 0usize;
            for event_id in ids {
                changed += stmt.execute(params![event_id_to_base64(event_id), ts])?;
            }
            Ok(changed)
        })
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

fn span_label(label: &str, start: Option<i64>, end: Option<i64>) -> Option<String> {
    Some(format!("{label}={}", end?.saturating_sub(start?)))
}

#[cfg(test)]
mod tests {
    use super::*;
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
            .mark_discovered_many_with_round_start(&[event_id], 10, 20)
            .unwrap();
        timeline.mark_request_sent_many(&[event_id], 30).unwrap();
        timeline.mark_request_sent_many(&[event_id], 40).unwrap();
        timeline
            .mark_response_received_b64(&event_id_b64, 50)
            .unwrap();
        timeline.mark_persisted_b64(&event_id_b64, 60).unwrap();
        timeline.mark_projected_b64(&event_id_b64, 80).unwrap();

        let row = timeline.load(&event_id_b64).unwrap().unwrap();
        assert_eq!(row.discovery_round_started_at, Some(10));
        assert_eq!(row.wanted_discovered_at, Some(20));
        assert_eq!(row.request_sent_at, Some(30));
        assert_eq!(row.response_received_at, Some(50));
        assert_eq!(row.persisted_at, Some(60));
        assert_eq!(row.projected_at, Some(80));

        let summary = timeline.summary(&event_id_b64).unwrap().unwrap();
        assert!(summary.contains("persist_to_project_ms=20"));
    }
}
