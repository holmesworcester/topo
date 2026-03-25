//! Durable job registry: typed recurring-work definitions with SQLite-backed
//! due-work state. The clock bridge polls `due_jobs` and emits wake events
//! without owning policy. Job semantics live in event families/projected state.

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use crate::db::queue::{current_timestamp_ms, with_sqlite_busy_retry};
use crate::event_modules::ParsedEvent;
use crate::projection::create::create_event_synchronous;

use super::job_due::JobDueEvent;

// ---------------------------------------------------------------------------
// Job kind registry
// ---------------------------------------------------------------------------

/// Typed job kinds. Each variant represents a class of recurring work whose
/// cadence, activation, and suppression are event-owned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurableJobKind {
    /// Re-evaluate connection plans and dispatch due targets.
    ConnectionPlanRefresh,
    /// Re-scan bootstrap invite targets for new endpoints.
    BootstrapRefresh,
    /// Re-scan observed peer endpoints for address changes.
    ObservedEndpointRefresh,
    /// Sync cadence heartbeat — triggers next outbound sync evaluation.
    SyncCadence,
}

impl DurableJobKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ConnectionPlanRefresh => "connection_plan_refresh",
            Self::BootstrapRefresh => "bootstrap_refresh",
            Self::ObservedEndpointRefresh => "observed_endpoint_refresh",
            Self::SyncCadence => "sync_cadence",
        }
    }

    pub fn from_str(raw: &str) -> Option<Self> {
        match raw {
            "connection_plan_refresh" => Some(Self::ConnectionPlanRefresh),
            "bootstrap_refresh" => Some(Self::BootstrapRefresh),
            "observed_endpoint_refresh" => Some(Self::ObservedEndpointRefresh),
            "sync_cadence" => Some(Self::SyncCadence),
            _ => None,
        }
    }

    /// Default interval in milliseconds between activations.
    pub fn default_interval_ms(self) -> i64 {
        match self {
            Self::ConnectionPlanRefresh => 1_000,
            Self::BootstrapRefresh => 1_000,
            Self::ObservedEndpointRefresh => 1_000,
            Self::SyncCadence => 5_000,
        }
    }
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS durable_jobs (
            client_id TEXT NOT NULL,
            job_kind TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            interval_ms INTEGER NOT NULL,
            next_due_at_ms INTEGER NOT NULL,
            last_completed_at_ms INTEGER,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (client_id, job_kind)
        );
        CREATE INDEX IF NOT EXISTS idx_durable_jobs_due
            ON durable_jobs(enabled, next_due_at_ms);
        ",
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Job instance management
// ---------------------------------------------------------------------------

/// Enable a durable job for the given client. If the job already exists and
/// is enabled, this is a no-op. If it doesn't exist, it is created with
/// `next_due_at_ms = now`.
pub fn enable_job(
    conn: &Connection,
    client_id: &str,
    kind: DurableJobKind,
) -> SqliteResult<()> {
    let now = current_timestamp_ms();
    with_sqlite_busy_retry(|| {
        conn.execute(
            "INSERT INTO durable_jobs (client_id, job_kind, enabled, interval_ms, next_due_at_ms, created_at)
             VALUES (?1, ?2, 1, ?3, ?4, ?4)
             ON CONFLICT(client_id, job_kind) DO UPDATE SET enabled = 1",
            params![client_id, kind.as_str(), kind.default_interval_ms(), now],
        )?;
        Ok(())
    })
}

/// Disable all durable jobs for the given client (e.g., on client_stopped).
pub fn disable_all_jobs(conn: &Connection, client_id: &str) -> SqliteResult<()> {
    with_sqlite_busy_retry(|| {
        conn.execute(
            "UPDATE durable_jobs SET enabled = 0 WHERE client_id = ?1",
            params![client_id],
        )?;
        Ok(())
    })
}

/// Enable default jobs for a newly started client.
pub fn enable_default_jobs(conn: &Connection, client_id: &str) -> SqliteResult<()> {
    let kinds = [
        DurableJobKind::ConnectionPlanRefresh,
        DurableJobKind::BootstrapRefresh,
        DurableJobKind::ObservedEndpointRefresh,
        DurableJobKind::SyncCadence,
    ];
    for kind in &kinds {
        enable_job(conn, client_id, *kind)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Due-work queries (clock bridge)
// ---------------------------------------------------------------------------

/// A job that is due for execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DueJob {
    pub client_id: String,
    pub kind: DurableJobKind,
    pub next_due_at_ms: i64,
}

/// Return up to `limit` jobs that are enabled and due now.
pub fn poll_due_jobs(conn: &Connection, limit: usize) -> SqliteResult<Vec<DueJob>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let now = current_timestamp_ms();
    with_sqlite_busy_retry(|| {
        let mut stmt = conn.prepare(
            "SELECT client_id, job_kind, next_due_at_ms
             FROM durable_jobs
             WHERE enabled = 1 AND next_due_at_ms <= ?1
             ORDER BY next_due_at_ms ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now, limit as i64], |row| {
            let kind_str: String = row.get(1)?;
            Ok(DueJob {
                client_id: row.get(0)?,
                kind: DurableJobKind::from_str(&kind_str)
                    .unwrap_or(DurableJobKind::ConnectionPlanRefresh),
                next_due_at_ms: row.get(2)?,
            })
        })?;
        rows.collect()
    })
}

/// Mark a job as completed and advance its next_due_at_ms by the interval.
/// Also authors a `job_due` event to record the completion in the event log.
pub fn complete_job(
    conn: &Connection,
    client_id: &str,
    kind: DurableJobKind,
) -> SqliteResult<()> {
    let now = current_timestamp_ms();
    with_sqlite_busy_retry(|| {
        conn.execute(
            "UPDATE durable_jobs
             SET next_due_at_ms = ?1 + interval_ms,
                 last_completed_at_ms = ?1
             WHERE client_id = ?2 AND job_kind = ?3",
            params![now, client_id, kind.as_str()],
        )?;
        Ok(())
    })?;
    // Best-effort: record the job_due event. If this fails, the job still
    // completed — the event is observational, not authoritative.
    let _ = record_job_due(conn, client_id, kind);
    Ok(())
}

/// Record a job_due event for the given client and job kind. Returns the
/// event id on success.
pub fn record_job_due(
    conn: &Connection,
    client_id: &str,
    kind: DurableJobKind,
) -> Result<[u8; 32], String> {
    let event = ParsedEvent::JobDue(JobDueEvent {
        created_at_ms: current_timestamp_ms() as u64,
        job_kind: kind.as_str().to_string(),
        client_id: client_id.to_string(),
    });
    create_event_synchronous(conn, client_id, &event).map_err(|e| e.to_string())
}

/// Return the earliest due time of any enabled job, or None if no jobs are
/// enabled. The clock bridge uses this to sleep until the next due time.
pub fn next_due_at(conn: &Connection) -> SqliteResult<Option<i64>> {
    with_sqlite_busy_retry(|| {
        conn.query_row(
            "SELECT MIN(next_due_at_ms)
             FROM durable_jobs
             WHERE enabled = 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map(|opt| opt.flatten())
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        conn
    }

    #[test]
    fn enable_creates_due_job() {
        let conn = setup();
        enable_job(&conn, "client-a", DurableJobKind::BootstrapRefresh).unwrap();

        let due = poll_due_jobs(&conn, 10).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].kind, DurableJobKind::BootstrapRefresh);
    }

    #[test]
    fn disable_all_hides_jobs_from_polling() {
        let conn = setup();
        enable_default_jobs(&conn, "client-a").unwrap();
        assert!(!poll_due_jobs(&conn, 10).unwrap().is_empty());

        disable_all_jobs(&conn, "client-a").unwrap();
        assert!(poll_due_jobs(&conn, 10).unwrap().is_empty());
    }

    #[test]
    fn complete_advances_due_time() {
        let conn = setup();
        enable_job(&conn, "client-a", DurableJobKind::SyncCadence).unwrap();

        let before = poll_due_jobs(&conn, 10).unwrap();
        assert_eq!(before.len(), 1);

        complete_job(&conn, "client-a", DurableJobKind::SyncCadence).unwrap();

        // After completion, the job should no longer be immediately due
        let after = poll_due_jobs(&conn, 10).unwrap();
        assert!(after.is_empty(), "job should not be due immediately after completion");
    }

    #[test]
    fn next_due_at_returns_earliest() {
        let conn = setup();
        assert_eq!(next_due_at(&conn).unwrap(), None);

        enable_job(&conn, "client-a", DurableJobKind::SyncCadence).unwrap();
        let due = next_due_at(&conn).unwrap();
        assert!(due.is_some());
    }

    #[test]
    fn enable_default_jobs_creates_all_kinds() {
        let conn = setup();
        enable_default_jobs(&conn, "client-a").unwrap();

        let due = poll_due_jobs(&conn, 20).unwrap();
        assert_eq!(due.len(), 4);
    }

    #[test]
    fn enable_idempotent_when_already_enabled() {
        let conn = setup();
        enable_job(&conn, "client-a", DurableJobKind::BootstrapRefresh).unwrap();
        enable_job(&conn, "client-a", DurableJobKind::BootstrapRefresh).unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM durable_jobs WHERE client_id = ?1",
                params!["client-a"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn disable_does_not_delete_preserves_state() {
        let conn = setup();
        enable_job(&conn, "client-a", DurableJobKind::BootstrapRefresh).unwrap();
        complete_job(&conn, "client-a", DurableJobKind::BootstrapRefresh).unwrap();
        disable_all_jobs(&conn, "client-a").unwrap();

        // Re-enable should preserve the job row
        enable_job(&conn, "client-a", DurableJobKind::BootstrapRefresh).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM durable_jobs WHERE client_id = ?1",
                params!["client-a"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}
