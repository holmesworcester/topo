use rusqlite::{params, Connection, Result as SqliteResult};

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};

const CLAIM_STRENGTH_SOFT: i64 = 1;
const CLAIM_STRENGTH_HARD: i64 = 2;
const UTC_DAY_MS: i64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimStrength {
    Soft,
    Hard,
}

impl ClaimStrength {
    fn as_i64(self) -> i64 {
        match self {
            Self::Soft => CLAIM_STRENGTH_SOFT,
            Self::Hard => CLAIM_STRENGTH_HARD,
        }
    }
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS dep_claims (
            workspace_id TEXT NOT NULL,
            shard_start_ms INTEGER NOT NULL,
            event_id TEXT NOT NULL,
            strength INTEGER NOT NULL,
            expires_at_ms INTEGER,
            updated_at_ms INTEGER NOT NULL,
            according_to_peer_id TEXT,
            PRIMARY KEY (workspace_id, shard_start_ms, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_dep_claims_event_lookup
            ON dep_claims(workspace_id, event_id, strength, shard_start_ms);
        CREATE INDEX IF NOT EXISTS idx_dep_claims_live_scan
            ON dep_claims(workspace_id, shard_start_ms, strength, expires_at_ms, event_id);
        ",
    )?;
    Ok(())
}

pub fn utc_day_start_ms(ts_ms: i64) -> i64 {
    ts_ms - ts_ms.rem_euclid(UTC_DAY_MS)
}

pub fn upsert_hard_claims(
    conn: &Connection,
    workspace_id: &str,
    shard_start_ms: i64,
    ids: &[EventId],
    updated_at_ms: i64,
) -> SqliteResult<usize> {
    upsert_claims(
        conn,
        workspace_id,
        shard_start_ms,
        ids,
        ClaimStrength::Hard,
        None,
        None,
        updated_at_ms,
    )
}

pub fn upsert_soft_claims(
    conn: &Connection,
    workspace_id: &str,
    shard_start_ms: i64,
    ids: &[EventId],
    according_to_peer_id: Option<&str>,
    updated_at_ms: i64,
    expires_at_ms: i64,
) -> SqliteResult<usize> {
    upsert_claims(
        conn,
        workspace_id,
        shard_start_ms,
        ids,
        ClaimStrength::Soft,
        Some(expires_at_ms),
        according_to_peer_id,
        updated_at_ms,
    )
}

fn upsert_claims(
    conn: &Connection,
    workspace_id: &str,
    shard_start_ms: i64,
    ids: &[EventId],
    strength: ClaimStrength,
    expires_at_ms: Option<i64>,
    according_to_peer_id: Option<&str>,
    updated_at_ms: i64,
) -> SqliteResult<usize> {
    if ids.is_empty() {
        return Ok(0);
    }

    let sql = match strength {
        ClaimStrength::Hard => {
            "INSERT INTO dep_claims
                 (workspace_id, shard_start_ms, event_id, strength, expires_at_ms, updated_at_ms, according_to_peer_id)
             VALUES (?1, ?2, ?3, ?4, NULL, ?5, NULL)
             ON CONFLICT(workspace_id, shard_start_ms, event_id) DO UPDATE SET
                 strength = 2,
                 expires_at_ms = NULL,
                 updated_at_ms = excluded.updated_at_ms"
        }
        ClaimStrength::Soft => {
            "INSERT INTO dep_claims
                 (workspace_id, shard_start_ms, event_id, strength, expires_at_ms, updated_at_ms, according_to_peer_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(workspace_id, shard_start_ms, event_id) DO UPDATE SET
                 strength = CASE
                     WHEN dep_claims.strength >= 2 THEN dep_claims.strength
                     ELSE excluded.strength
                 END,
                 expires_at_ms = CASE
                     WHEN dep_claims.strength >= 2 THEN NULL
                     ELSE excluded.expires_at_ms
                 END,
                 updated_at_ms = excluded.updated_at_ms,
                 according_to_peer_id = COALESCE(excluded.according_to_peer_id, dep_claims.according_to_peer_id)"
        }
    };
    let mut stmt = conn.prepare(sql)?;
    let mut changed = 0usize;
    for event_id in ids {
        let event_id_b64 = event_id_to_base64(event_id);
        changed += match strength {
            ClaimStrength::Hard => stmt.execute(params![
                workspace_id,
                shard_start_ms,
                event_id_b64,
                strength.as_i64(),
                updated_at_ms
            ])?,
            ClaimStrength::Soft => stmt.execute(params![
                workspace_id,
                shard_start_ms,
                event_id_b64,
                strength.as_i64(),
                expires_at_ms,
                updated_at_ms,
                according_to_peer_id
            ])?,
        };
    }
    Ok(changed)
}

pub fn list_live_claim_ids(
    conn: &Connection,
    workspace_id: &str,
    shard_start_ms: i64,
    now_ms: i64,
) -> SqliteResult<Vec<EventId>> {
    let mut stmt = conn.prepare(
        "SELECT event_id
         FROM dep_claims
         WHERE workspace_id = ?1
           AND shard_start_ms = ?2
           AND (strength >= 2 OR expires_at_ms IS NULL OR expires_at_ms > ?3)
         ORDER BY event_id",
    )?;
    let rows = stmt.query_map(params![workspace_id, shard_start_ms, now_ms], |row| {
        row.get::<_, String>(0)
    })?;
    let mut ids = Vec::new();
    for row in rows {
        let event_id_b64 = row?;
        if let Some(event_id) = event_id_from_base64(&event_id_b64) {
            ids.push(event_id);
        }
    }
    Ok(ids)
}

pub fn list_hard_claim_shards_for_event(
    conn: &Connection,
    workspace_id: &str,
    event_id: &EventId,
) -> SqliteResult<Vec<i64>> {
    let event_id_b64 = event_id_to_base64(event_id);
    let mut stmt = conn.prepare(
        "SELECT shard_start_ms
         FROM dep_claims
         WHERE workspace_id = ?1
           AND event_id = ?2
           AND strength >= 2
         ORDER BY shard_start_ms",
    )?;
    let rows = stmt.query_map(params![workspace_id, event_id_b64], |row| {
        row.get::<_, i64>(0)
    })?;
    rows.collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn utc_day_start_is_stable_at_boundaries() {
        assert_eq!(utc_day_start_ms(0), 0);
        assert_eq!(utc_day_start_ms(1), 0);
        assert_eq!(utc_day_start_ms(86_399_999), 0);
        assert_eq!(utc_day_start_ms(86_400_000), 86_400_000);
        assert_eq!(utc_day_start_ms(-1), -86_400_000);
    }

    #[test]
    fn soft_claims_expire_but_hard_claims_remain_live() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "ws";
        let shard_start_ms = utc_day_start_ms(123_456_789);
        let soft = [1u8; 32];
        let hard = [2u8; 32];

        upsert_soft_claims(
            &conn,
            workspace_id,
            shard_start_ms,
            &[soft],
            Some("peer-a"),
            100,
            200,
        )
        .unwrap();
        upsert_hard_claims(&conn, workspace_id, shard_start_ms, &[hard], 100).unwrap();

        assert_eq!(
            list_live_claim_ids(&conn, workspace_id, shard_start_ms, 150).unwrap(),
            vec![soft, hard]
        );
        assert_eq!(
            list_live_claim_ids(&conn, workspace_id, shard_start_ms, 250).unwrap(),
            vec![hard]
        );
    }

    #[test]
    fn soft_upsert_does_not_downgrade_existing_hard_claim() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "ws";
        let shard_start_ms = utc_day_start_ms(555_000);
        let event_id = [9u8; 32];

        upsert_hard_claims(&conn, workspace_id, shard_start_ms, &[event_id], 100).unwrap();
        upsert_soft_claims(
            &conn,
            workspace_id,
            shard_start_ms,
            &[event_id],
            Some("peer-b"),
            200,
            250,
        )
        .unwrap();

        let row: (i64, Option<i64>) = conn
            .query_row(
                "SELECT strength, expires_at_ms
                 FROM dep_claims
                 WHERE workspace_id = ?1 AND shard_start_ms = ?2 AND event_id = ?3",
                params![workspace_id, shard_start_ms, event_id_to_base64(&event_id)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(row.0, CLAIM_STRENGTH_HARD);
        assert_eq!(row.1, None);
    }

    #[test]
    fn hard_claim_lookup_returns_all_matching_shards() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        let workspace_id = "ws";
        let event_id = [4u8; 32];
        let shard_a = utc_day_start_ms(100);
        let shard_b = utc_day_start_ms(86_400_100);

        upsert_hard_claims(&conn, workspace_id, shard_a, &[event_id], 100).unwrap();
        upsert_soft_claims(
            &conn,
            workspace_id,
            shard_b,
            &[event_id],
            Some("peer-c"),
            100,
            1_000,
        )
        .unwrap();
        upsert_hard_claims(&conn, workspace_id, shard_b, &[event_id], 200).unwrap();

        assert_eq!(
            list_hard_claim_shards_for_event(&conn, workspace_id, &event_id).unwrap(),
            vec![shard_a, shard_b]
        );
    }
}
