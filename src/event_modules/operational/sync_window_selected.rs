use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use crate::db::queue::with_sqlite_busy_retry;
use crate::projection::contract::{SqlVal, WriteOp};

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
