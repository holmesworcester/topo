use rusqlite::{params, Connection, Result as SqliteResult};

const DAY_MS: i64 = 24 * 60 * 60 * 1000;
const WEEK_MS: i64 = 7 * DAY_MS;

fn utc_day_start_ms(ts_ms: i64) -> i64 {
    ts_ms.div_euclid(DAY_MS) * DAY_MS
}

fn utc_week_start_ms(ts_ms: i64) -> i64 {
    let day_start_ms = utc_day_start_ms(ts_ms);
    let days_since_epoch = day_start_ms.div_euclid(DAY_MS);
    let weekday_monday_zero = (days_since_epoch + 3).rem_euclid(7);
    day_start_ms - (weekday_monday_zero * DAY_MS)
}

fn covered_day_epoch_bounds(
    ts_min_inclusive_ms: i64,
    ts_max_exclusive_ms: i64,
) -> Option<(i64, i64)> {
    if ts_max_exclusive_ms <= ts_min_inclusive_ms {
        return None;
    }
    Some((
        utc_day_start_ms(ts_min_inclusive_ms),
        utc_day_start_ms(ts_max_exclusive_ms.saturating_sub(1)) + DAY_MS,
    ))
}

fn covered_week_epoch_bounds(
    ts_min_inclusive_ms: Option<i64>,
    ts_max_exclusive_ms: i64,
) -> Option<(Option<i64>, i64)> {
    if matches!(ts_min_inclusive_ms, Some(ts_min) if ts_max_exclusive_ms <= ts_min) {
        return None;
    }
    Some((
        ts_min_inclusive_ms.map(utc_week_start_ms),
        utc_week_start_ms(ts_max_exclusive_ms.saturating_sub(1)) + WEEK_MS,
    ))
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    let sql = format!(
        "
        CREATE TABLE IF NOT EXISTS negentropy_day_epoch (
            workspace_id TEXT NOT NULL,
            day_start_ms INTEGER NOT NULL,
            epoch INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (workspace_id, day_start_ms)
        ) WITHOUT ROWID;

        CREATE TABLE IF NOT EXISTS negentropy_week_epoch (
            workspace_id TEXT NOT NULL,
            week_start_ms INTEGER NOT NULL,
            epoch INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (workspace_id, week_start_ms)
        ) WITHOUT ROWID;

        CREATE TRIGGER IF NOT EXISTS trg_negentropy_epoch_shared_insert
        AFTER INSERT ON shared_event_index
        BEGIN
            INSERT INTO negentropy_day_epoch (workspace_id, day_start_ms, epoch)
            VALUES (NEW.workspace_id, ((NEW.ts / {day_ms}) * {day_ms}), 1)
            ON CONFLICT(workspace_id, day_start_ms) DO UPDATE SET
                epoch = epoch + 1;
            INSERT INTO negentropy_week_epoch (workspace_id, week_start_ms, epoch)
            VALUES (
                NEW.workspace_id,
                (((NEW.ts / {day_ms}) * {day_ms}) - ((((NEW.ts / {day_ms}) + 3) % 7) * {day_ms})),
                1
            )
            ON CONFLICT(workspace_id, week_start_ms) DO UPDATE SET
                epoch = epoch + 1;
        END;

        CREATE TRIGGER IF NOT EXISTS trg_negentropy_epoch_shared_delete
        AFTER DELETE ON shared_event_index
        BEGIN
            INSERT INTO negentropy_day_epoch (workspace_id, day_start_ms, epoch)
            VALUES (OLD.workspace_id, ((OLD.ts / {day_ms}) * {day_ms}), 1)
            ON CONFLICT(workspace_id, day_start_ms) DO UPDATE SET
                epoch = epoch + 1;
            INSERT INTO negentropy_week_epoch (workspace_id, week_start_ms, epoch)
            VALUES (
                OLD.workspace_id,
                (((OLD.ts / {day_ms}) * {day_ms}) - ((((OLD.ts / {day_ms}) + 3) % 7) * {day_ms})),
                1
            )
            ON CONFLICT(workspace_id, week_start_ms) DO UPDATE SET
                epoch = epoch + 1;
        END;
        ",
        day_ms = DAY_MS,
    );
    conn.execute_batch(&sql)?;
    Ok(())
}

pub fn sum_day_epochs(
    conn: &Connection,
    workspace_id: &str,
    ts_min_inclusive_ms: i64,
    ts_max_exclusive_ms: i64,
) -> SqliteResult<u64> {
    let Some((day_min_inclusive_ms, day_max_exclusive_ms)) =
        covered_day_epoch_bounds(ts_min_inclusive_ms, ts_max_exclusive_ms)
    else {
        return Ok(0);
    };
    let sum: i64 = conn.query_row(
        "SELECT COALESCE(SUM(epoch), 0)
         FROM negentropy_day_epoch
         WHERE workspace_id = ?1
           AND day_start_ms >= ?2
           AND day_start_ms < ?3",
        params![workspace_id, day_min_inclusive_ms, day_max_exclusive_ms],
        |row| row.get(0),
    )?;
    Ok(sum.max(0) as u64)
}

pub fn sum_week_epochs(
    conn: &Connection,
    workspace_id: &str,
    ts_min_inclusive_ms: Option<i64>,
    ts_max_exclusive_ms: i64,
) -> SqliteResult<u64> {
    let Some((week_min_inclusive_ms, week_max_exclusive_ms)) =
        covered_week_epoch_bounds(ts_min_inclusive_ms, ts_max_exclusive_ms)
    else {
        return Ok(0);
    };
    let sum: i64 = conn.query_row(
        "SELECT COALESCE(SUM(epoch), 0)
         FROM negentropy_week_epoch
         WHERE workspace_id = ?1
           AND (?2 IS NULL OR week_start_ms >= ?2)
           AND week_start_ms < ?3",
        params![workspace_id, week_min_inclusive_ms, week_max_exclusive_ms],
        |row| row.get(0),
    )?;
    Ok(sum.max(0) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;

    #[test]
    fn epochs_track_range_locality_for_shared_rows() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "ws";
        let event_id = [0x11u8; 32];
        let day_start_ms = 2 * DAY_MS;
        let tomorrow_start_ms = day_start_ms + DAY_MS;
        let old_week_start_ms = 0;
        let next_week_start_ms = 7 * DAY_MS;

        assert_eq!(
            sum_day_epochs(&conn, workspace_id, day_start_ms, tomorrow_start_ms).unwrap(),
            0
        );
        assert_eq!(
            sum_week_epochs(
                &conn,
                workspace_id,
                Some(old_week_start_ms),
                next_week_start_ms
            )
            .unwrap(),
            0
        );

        conn.execute(
            "INSERT INTO shared_event_index (workspace_id, ts, id)
             VALUES (?1, ?2, ?3)",
            params![workspace_id, day_start_ms + 1, event_id.as_slice()],
        )
        .unwrap();
        assert_eq!(
            sum_day_epochs(&conn, workspace_id, day_start_ms, tomorrow_start_ms).unwrap(),
            1
        );
        assert_eq!(
            sum_week_epochs(
                &conn,
                workspace_id,
                Some(old_week_start_ms),
                next_week_start_ms
            )
            .unwrap(),
            1
        );

        conn.execute(
            "DELETE FROM shared_event_index
             WHERE workspace_id = ?1 AND id = ?2",
            params![workspace_id, event_id.as_slice()],
        )
        .unwrap();
        assert_eq!(
            sum_day_epochs(&conn, workspace_id, day_start_ms, tomorrow_start_ms).unwrap(),
            2
        );
    }
}
