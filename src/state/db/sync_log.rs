use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncLogConfig {
    pub enabled: bool,
    pub changed_only: bool,
    pub capture_full_ids: bool,
    pub max_runs: i64,
    pub max_age_days: i64,
}

impl Default for SyncLogConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            changed_only: true,
            capture_full_ids: false,
            max_runs: 500,
            max_age_days: 7,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncLogConfigPatch {
    pub enabled: Option<bool>,
    pub changed_only: Option<bool>,
    pub capture_full_ids: Option<bool>,
    pub max_runs: Option<i64>,
    pub max_age_days: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct NewSyncRun {
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub session_id: u64,
    pub tenant_id: String,
    pub peer_id: String,
    pub direction: String,
    pub remote_addr: String,
    pub role: String,
    pub rounds: u64,
    pub events_sent: u64,
    pub events_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub changed: bool,
    pub outcome: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewSyncRunEvent {
    pub seq: u64,
    pub ts_ms: i64,
    pub lane: String,
    pub direction: String,
    pub frame_type: String,
    pub msg_len: usize,
    pub detail_json: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SyncRunRow {
    pub run_id: i64,
    pub started_at_ms: i64,
    pub ended_at_ms: i64,
    pub session_id: u64,
    pub tenant_id: String,
    pub peer_id: String,
    pub direction: String,
    pub remote_addr: String,
    pub role: String,
    pub rounds: u64,
    pub events_sent: u64,
    pub events_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub changed: bool,
    pub outcome: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SyncRunEventRow {
    pub run_id: i64,
    pub seq: u64,
    pub ts_ms: i64,
    pub lane: String,
    pub direction: String,
    pub frame_type: String,
    pub msg_len: usize,
    pub detail_json: Option<String>,
}

fn bool_to_i64(v: bool) -> i64 {
    if v {
        1
    } else {
        0
    }
}

fn i64_to_bool(v: i64) -> bool {
    v != 0
}

fn u64_to_i64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn usize_to_i64(v: usize) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn i64_to_u64(v: i64) -> u64 {
    if v <= 0 {
        0
    } else {
        v as u64
    }
}

fn i64_to_usize(v: i64) -> usize {
    if v <= 0 {
        0
    } else {
        v as usize
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

fn sanitize_config(mut cfg: SyncLogConfig) -> SyncLogConfig {
    if cfg.max_runs < 1 {
        cfg.max_runs = 1;
    }
    if cfg.max_age_days < 1 {
        cfg.max_age_days = 1;
    }
    cfg
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS sync_log_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            enabled INTEGER NOT NULL DEFAULT 0,
            changed_only INTEGER NOT NULL DEFAULT 1,
            capture_full_ids INTEGER NOT NULL DEFAULT 0,
            max_runs INTEGER NOT NULL DEFAULT 500,
            max_age_days INTEGER NOT NULL DEFAULT 7,
            updated_at_ms INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sync_runs (
            run_id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at_ms INTEGER NOT NULL,
            ended_at_ms INTEGER NOT NULL,
            session_id INTEGER NOT NULL,
            tenant_id TEXT NOT NULL,
            peer_id TEXT NOT NULL,
            direction TEXT NOT NULL,
            remote_addr TEXT NOT NULL,
            role TEXT NOT NULL,
            rounds INTEGER NOT NULL DEFAULT 0,
            events_sent INTEGER NOT NULL DEFAULT 0,
            events_received INTEGER NOT NULL DEFAULT 0,
            bytes_sent INTEGER NOT NULL DEFAULT 0,
            bytes_received INTEGER NOT NULL DEFAULT 0,
            changed INTEGER NOT NULL DEFAULT 0,
            outcome TEXT NOT NULL,
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_sync_runs_ended_at
            ON sync_runs(ended_at_ms DESC, run_id DESC);
        CREATE INDEX IF NOT EXISTS idx_sync_runs_peer
            ON sync_runs(peer_id, ended_at_ms DESC, run_id DESC);
        CREATE INDEX IF NOT EXISTS idx_sync_runs_tenant
            ON sync_runs(tenant_id, ended_at_ms DESC, run_id DESC);
        CREATE INDEX IF NOT EXISTS idx_sync_runs_changed
            ON sync_runs(changed, ended_at_ms DESC, run_id DESC);

        CREATE TABLE IF NOT EXISTS sync_run_events (
            run_id INTEGER NOT NULL,
            seq INTEGER NOT NULL,
            ts_ms INTEGER NOT NULL,
            lane TEXT NOT NULL,
            direction TEXT NOT NULL,
            frame_type TEXT NOT NULL,
            msg_len INTEGER NOT NULL,
            detail_json TEXT,
            PRIMARY KEY (run_id, seq)
        );
        CREATE INDEX IF NOT EXISTS idx_sync_run_events_run
            ON sync_run_events(run_id, seq);
        ",
    )?;

    let defaults = SyncLogConfig::default();
    conn.execute(
        "INSERT OR IGNORE INTO sync_log_config
         (id, enabled, changed_only, capture_full_ids, max_runs, max_age_days, updated_at_ms)
         VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            bool_to_i64(defaults.enabled),
            bool_to_i64(defaults.changed_only),
            bool_to_i64(defaults.capture_full_ids),
            defaults.max_runs,
            defaults.max_age_days,
            now_ms(),
        ],
    )?;
    Ok(())
}

pub fn load_config(conn: &Connection) -> SqliteResult<SyncLogConfig> {
    let row = conn
        .query_row(
            "SELECT enabled, changed_only, capture_full_ids, max_runs, max_age_days
             FROM sync_log_config WHERE id = 1",
            [],
            |r| {
                Ok(SyncLogConfig {
                    enabled: i64_to_bool(r.get::<_, i64>(0)?),
                    changed_only: i64_to_bool(r.get::<_, i64>(1)?),
                    capture_full_ids: i64_to_bool(r.get::<_, i64>(2)?),
                    max_runs: r.get(3)?,
                    max_age_days: r.get(4)?,
                })
            },
        )
        .optional()?;

    if let Some(cfg) = row {
        Ok(sanitize_config(cfg))
    } else {
        ensure_schema(conn)?;
        Ok(SyncLogConfig::default())
    }
}

pub fn update_config(conn: &Connection, patch: SyncLogConfigPatch) -> SqliteResult<SyncLogConfig> {
    let mut cfg = load_config(conn)?;
    if let Some(v) = patch.enabled {
        cfg.enabled = v;
    }
    if let Some(v) = patch.changed_only {
        cfg.changed_only = v;
    }
    if let Some(v) = patch.capture_full_ids {
        cfg.capture_full_ids = v;
    }
    if let Some(v) = patch.max_runs {
        cfg.max_runs = v;
    }
    if let Some(v) = patch.max_age_days {
        cfg.max_age_days = v;
    }
    cfg = sanitize_config(cfg);

    conn.execute(
        "UPDATE sync_log_config
         SET enabled = ?1,
             changed_only = ?2,
             capture_full_ids = ?3,
             max_runs = ?4,
             max_age_days = ?5,
             updated_at_ms = ?6
         WHERE id = 1",
        params![
            bool_to_i64(cfg.enabled),
            bool_to_i64(cfg.changed_only),
            bool_to_i64(cfg.capture_full_ids),
            cfg.max_runs,
            cfg.max_age_days,
            now_ms(),
        ],
    )?;

    Ok(cfg)
}

pub fn append_run_with_events(
    conn: &Connection,
    run: &NewSyncRun,
    events: &[NewSyncRunEvent],
    cfg: &SyncLogConfig,
) -> SqliteResult<i64> {
    conn.execute("BEGIN IMMEDIATE", [])?;

    let run_id = (|| -> SqliteResult<i64> {
        conn.execute(
            "INSERT INTO sync_runs
             (started_at_ms, ended_at_ms, session_id, tenant_id, peer_id, direction, remote_addr, role,
              rounds, events_sent, events_received, bytes_sent, bytes_received, changed, outcome, error)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
            params![
                run.started_at_ms,
                run.ended_at_ms,
                u64_to_i64(run.session_id),
                &run.tenant_id,
                &run.peer_id,
                &run.direction,
                &run.remote_addr,
                &run.role,
                u64_to_i64(run.rounds),
                u64_to_i64(run.events_sent),
                u64_to_i64(run.events_received),
                u64_to_i64(run.bytes_sent),
                u64_to_i64(run.bytes_received),
                bool_to_i64(run.changed),
                &run.outcome,
                run.error.as_deref(),
            ],
        )?;
        let run_id = conn.last_insert_rowid();

        if !events.is_empty() {
            let mut stmt = conn.prepare(
                "INSERT INTO sync_run_events
                 (run_id, seq, ts_ms, lane, direction, frame_type, msg_len, detail_json)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            )?;
            for ev in events {
                stmt.execute(params![
                    run_id,
                    u64_to_i64(ev.seq),
                    ev.ts_ms,
                    &ev.lane,
                    &ev.direction,
                    &ev.frame_type,
                    usize_to_i64(ev.msg_len),
                    ev.detail_json.as_deref(),
                ])?;
            }
        }

        prune_locked(conn, cfg)?;
        Ok(run_id)
    })();

    match run_id {
        Ok(id) => {
            conn.execute("COMMIT", [])?;
            Ok(id)
        }
        Err(e) => {
            let _ = conn.execute("ROLLBACK", []);
            Err(e)
        }
    }
}

fn prune_locked(conn: &Connection, cfg: &SyncLogConfig) -> SqliteResult<()> {
    let cutoff = now_ms().saturating_sub(cfg.max_age_days.saturating_mul(DAY_MS));
    conn.execute(
        "DELETE FROM sync_run_events
         WHERE run_id IN (SELECT run_id FROM sync_runs WHERE ended_at_ms < ?1)",
        params![cutoff],
    )?;
    conn.execute(
        "DELETE FROM sync_runs WHERE ended_at_ms < ?1",
        params![cutoff],
    )?;

    conn.execute(
        "DELETE FROM sync_run_events
         WHERE run_id IN (
            SELECT run_id FROM sync_runs
            ORDER BY ended_at_ms DESC, run_id DESC
            LIMIT -1 OFFSET ?1
         )",
        params![cfg.max_runs],
    )?;
    conn.execute(
        "DELETE FROM sync_runs
         WHERE run_id IN (
            SELECT run_id FROM sync_runs
            ORDER BY ended_at_ms DESC, run_id DESC
            LIMIT -1 OFFSET ?1
         )",
        params![cfg.max_runs],
    )?;
    Ok(())
}

pub fn list_runs(
    conn: &Connection,
    limit: usize,
    include_matches: bool,
    run_id: Option<i64>,
    peer_prefix: Option<&str>,
) -> SqliteResult<Vec<SyncRunRow>> {
    let mut out = Vec::new();

    match (run_id, peer_prefix) {
        (Some(id), _) => {
            let sql = if include_matches {
                "SELECT run_id, started_at_ms, ended_at_ms, session_id, tenant_id, peer_id, direction,
                        remote_addr, role, rounds, events_sent, events_received, bytes_sent, bytes_received,
                        changed, outcome, error
                 FROM sync_runs
                 WHERE run_id = ?1
                 ORDER BY ended_at_ms DESC, run_id DESC"
            } else {
                "SELECT run_id, started_at_ms, ended_at_ms, session_id, tenant_id, peer_id, direction,
                        remote_addr, role, rounds, events_sent, events_received, bytes_sent, bytes_received,
                        changed, outcome, error
                 FROM sync_runs
                 WHERE changed = 1 AND run_id = ?1
                 ORDER BY ended_at_ms DESC, run_id DESC"
            };
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map(params![id], row_to_run)?;
            for row in rows {
                out.push(row?);
            }
        }
        (None, Some(prefix)) => {
            let like = format!("{prefix}%");
            let sql = if include_matches {
                "SELECT run_id, started_at_ms, ended_at_ms, session_id, tenant_id, peer_id, direction,
                        remote_addr, role, rounds, events_sent, events_received, bytes_sent, bytes_received,
                        changed, outcome, error
                 FROM sync_runs
                 WHERE peer_id LIKE ?1
                 ORDER BY ended_at_ms DESC, run_id DESC
                 LIMIT ?2"
            } else {
                "SELECT run_id, started_at_ms, ended_at_ms, session_id, tenant_id, peer_id, direction,
                        remote_addr, role, rounds, events_sent, events_received, bytes_sent, bytes_received,
                        changed, outcome, error
                 FROM sync_runs
                 WHERE changed = 1 AND peer_id LIKE ?1
                 ORDER BY ended_at_ms DESC, run_id DESC
                 LIMIT ?2"
            };
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map(params![like, usize_to_i64(limit)], row_to_run)?;
            for row in rows {
                out.push(row?);
            }
        }
        (None, None) => {
            let sql = if include_matches {
                "SELECT run_id, started_at_ms, ended_at_ms, session_id, tenant_id, peer_id, direction,
                        remote_addr, role, rounds, events_sent, events_received, bytes_sent, bytes_received,
                        changed, outcome, error
                 FROM sync_runs
                 ORDER BY ended_at_ms DESC, run_id DESC
                 LIMIT ?1"
            } else {
                "SELECT run_id, started_at_ms, ended_at_ms, session_id, tenant_id, peer_id, direction,
                        remote_addr, role, rounds, events_sent, events_received, bytes_sent, bytes_received,
                        changed, outcome, error
                 FROM sync_runs
                 WHERE changed = 1
                 ORDER BY ended_at_ms DESC, run_id DESC
                 LIMIT ?1"
            };
            let mut stmt = conn.prepare(sql)?;
            let rows = stmt.query_map(params![usize_to_i64(limit)], row_to_run)?;
            for row in rows {
                out.push(row?);
            }
        }
    }

    Ok(out)
}

pub fn list_run_events(conn: &Connection, run_id: i64) -> SqliteResult<Vec<SyncRunEventRow>> {
    let mut stmt = conn.prepare(
        "SELECT run_id, seq, ts_ms, lane, direction, frame_type, msg_len, detail_json
         FROM sync_run_events
         WHERE run_id = ?1
         ORDER BY seq ASC",
    )?;

    let rows = stmt.query_map(params![run_id], |r| {
        Ok(SyncRunEventRow {
            run_id: r.get(0)?,
            seq: i64_to_u64(r.get::<_, i64>(1)?),
            ts_ms: r.get(2)?,
            lane: r.get(3)?,
            direction: r.get(4)?,
            frame_type: r.get(5)?,
            msg_len: i64_to_usize(r.get::<_, i64>(6)?),
            detail_json: r.get(7)?,
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn row_to_run(row: &rusqlite::Row<'_>) -> SqliteResult<SyncRunRow> {
    Ok(SyncRunRow {
        run_id: row.get(0)?,
        started_at_ms: row.get(1)?,
        ended_at_ms: row.get(2)?,
        session_id: i64_to_u64(row.get::<_, i64>(3)?),
        tenant_id: row.get(4)?,
        peer_id: row.get(5)?,
        direction: row.get(6)?,
        remote_addr: row.get(7)?,
        role: row.get(8)?,
        rounds: i64_to_u64(row.get::<_, i64>(9)?),
        events_sent: i64_to_u64(row.get::<_, i64>(10)?),
        events_received: i64_to_u64(row.get::<_, i64>(11)?),
        bytes_sent: i64_to_u64(row.get::<_, i64>(12)?),
        bytes_received: i64_to_u64(row.get::<_, i64>(13)?),
        changed: i64_to_bool(row.get::<_, i64>(14)?),
        outcome: row.get(15)?,
        error: row.get(16)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::schema::create_tables;

    #[test]
    fn sync_log_defaults_disabled() {
        let conn = crate::db::open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let cfg = load_config(&conn).unwrap();
        assert!(!cfg.enabled);
        assert!(cfg.changed_only);
    }

    #[test]
    fn sync_log_insert_and_query_roundtrip() {
        let conn = crate::db::open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let cfg = update_config(
            &conn,
            SyncLogConfigPatch {
                enabled: Some(true),
                ..Default::default()
            },
        )
        .unwrap();

        let run = NewSyncRun {
            started_at_ms: now_ms() - 1_000,
            ended_at_ms: now_ms(),
            session_id: 42,
            tenant_id: "tenant-a".to_string(),
            peer_id: "peer-a".to_string(),
            direction: "outbound".to_string(),
            remote_addr: "127.0.0.1:4433".to_string(),
            role: "initiator".to_string(),
            rounds: 3,
            events_sent: 2,
            events_received: 1,
            bytes_sent: 120,
            bytes_received: 60,
            changed: true,
            outcome: "ok".to_string(),
            error: None,
        };
        let events = vec![NewSyncRunEvent {
            seq: 1,
            ts_ms: 110,
            lane: "control".to_string(),
            direction: "tx".to_string(),
            frame_type: "NegOpen".to_string(),
            msg_len: 64,
            detail_json: Some("{\"entries\":1}".to_string()),
        }];

        let run_id = append_run_with_events(&conn, &run, &events, &cfg).unwrap();
        let runs = list_runs(&conn, 10, false, Some(run_id), None).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].session_id, 42);

        let evs = list_run_events(&conn, run_id).unwrap();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].frame_type, "NegOpen");
    }

    #[test]
    fn sync_log_prunes_by_count() {
        let conn = crate::db::open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let cfg = update_config(
            &conn,
            SyncLogConfigPatch {
                enabled: Some(true),
                max_runs: Some(2),
                ..Default::default()
            },
        )
        .unwrap();

        for i in 0..5 {
            let end = now_ms() + i * 10;
            let run = NewSyncRun {
                started_at_ms: end - 5,
                ended_at_ms: end,
                session_id: i as u64,
                tenant_id: "tenant-a".to_string(),
                peer_id: "peer-a".to_string(),
                direction: "outbound".to_string(),
                remote_addr: "127.0.0.1:4433".to_string(),
                role: "initiator".to_string(),
                rounds: 1,
                events_sent: 0,
                events_received: 0,
                bytes_sent: 0,
                bytes_received: 0,
                changed: false,
                outcome: "ok".to_string(),
                error: None,
            };
            append_run_with_events(&conn, &run, &[], &cfg).unwrap();
        }

        let rows = list_runs(&conn, 10, true, None, None).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].session_id, 4);
        assert_eq!(rows[1].session_id, 3);
    }
}
