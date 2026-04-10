use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestSourceCount {
    pub source_peer_id: Option<String>,
    pub source: String,
    pub event_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestEventObservation {
    pub event_id: String,
    pub observed: bool,
    pub observation_id: Option<i64>,
    pub source: Option<String>,
    pub source_peer_id: Option<String>,
    pub semantic_type_code: Option<i64>,
    pub received_at_ms: Option<i64>,
    pub first_stored_at_ms: Option<i64>,
    pub recorded_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestObservability {
    pub recorded_by: String,
    pub file_slice_count: i64,
    pub last_file_slice_observation_id: Option<i64>,
    pub quic_received_unique_event_count: i64,
    pub sources: Vec<IngestSourceCount>,
    pub events: Vec<IngestEventObservation>,
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS event_ingest_observations (
            id INTEGER PRIMARY KEY,
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            source TEXT NOT NULL,
            source_peer_id TEXT,
            semantic_type_code INTEGER,
            received_at_ms INTEGER NOT NULL,
            first_stored_at_ms INTEGER NOT NULL,
            recorded_at_ms INTEGER NOT NULL,
            UNIQUE(recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_event_ingest_observations_peer_order
            ON event_ingest_observations(recorded_by, id);
        CREATE INDEX IF NOT EXISTS idx_event_ingest_observations_source
            ON event_ingest_observations(recorded_by, source_peer_id, id);
        CREATE INDEX IF NOT EXISTS idx_event_ingest_observations_type
            ON event_ingest_observations(recorded_by, semantic_type_code, id);
        ",
    )?;
    Ok(())
}

pub fn source_peer_id_from_tag(source: &str) -> Option<String> {
    let rest = source.strip_prefix("quic_recv:")?;
    let (peer_id, _) = rest.split_once('@')?;
    if peer_id.is_empty() {
        None
    } else {
        Some(peer_id.to_string())
    }
}

pub fn insert_event_ingest_observation(
    conn: &Connection,
    recorded_by: &str,
    event_id: &str,
    source: &str,
    semantic_type_code: Option<i64>,
    received_at_ms: i64,
    first_stored_at_ms: i64,
    recorded_at_ms: i64,
) -> SqliteResult<usize> {
    let source_peer_id = source_peer_id_from_tag(source);
    conn.execute(
        "INSERT OR IGNORE INTO event_ingest_observations
         (recorded_by, event_id, source, source_peer_id, semantic_type_code,
          received_at_ms, first_stored_at_ms, recorded_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            recorded_by,
            event_id,
            source,
            source_peer_id.as_deref(),
            semantic_type_code,
            received_at_ms,
            first_stored_at_ms,
            recorded_at_ms,
        ],
    )
}

fn file_slice_count(conn: &Connection, recorded_by: &str) -> SqliteResult<i64> {
    conn.query_row(
        "SELECT COUNT(*)
         FROM event_ingest_observations
         WHERE recorded_by = ?1
           AND semantic_type_code = ?2",
        params![
            recorded_by,
            i64::from(crate::event_modules::EVENT_TYPE_FILE_SLICE)
        ],
        |row| row.get(0),
    )
}

fn last_file_slice_observation_id(
    conn: &Connection,
    recorded_by: &str,
) -> SqliteResult<Option<i64>> {
    conn.query_row(
        "SELECT MAX(id)
         FROM event_ingest_observations
         WHERE recorded_by = ?1
           AND semantic_type_code = ?2",
        params![
            recorded_by,
            i64::from(crate::event_modules::EVENT_TYPE_FILE_SLICE)
        ],
        |row| row.get(0),
    )
}

fn quic_received_unique_event_count(conn: &Connection, recorded_by: &str) -> SqliteResult<i64> {
    conn.query_row(
        "SELECT COUNT(*)
         FROM event_ingest_observations
         WHERE recorded_by = ?1
           AND source LIKE 'quic_recv:%'",
        params![recorded_by],
        |row| row.get(0),
    )
}

fn source_counts(conn: &Connection, recorded_by: &str) -> SqliteResult<Vec<IngestSourceCount>> {
    let mut stmt = conn.prepare(
        "SELECT source_peer_id, source, COUNT(*)
         FROM event_ingest_observations
         WHERE recorded_by = ?1
           AND source LIKE 'quic_recv:%'
         GROUP BY source_peer_id, source
         ORDER BY source_peer_id, source",
    )?;
    let rows = stmt.query_map(params![recorded_by], |row| {
        Ok(IngestSourceCount {
            source_peer_id: crate::db::sql_types::get_opt_text(row, 0)?,
            source: crate::db::sql_types::get_text(row, 1)?,
            event_count: row.get(2)?,
        })
    })?;
    rows.collect()
}

fn event_observation(
    conn: &Connection,
    recorded_by: &str,
    event_id: &str,
) -> SqliteResult<IngestEventObservation> {
    let row = conn
        .query_row(
            "SELECT id, source, source_peer_id, semantic_type_code,
                    received_at_ms, first_stored_at_ms, recorded_at_ms
             FROM event_ingest_observations
             WHERE recorded_by = ?1
               AND event_id = ?2",
            params![recorded_by, event_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    crate::db::sql_types::get_text(row, 1)?,
                    crate::db::sql_types::get_opt_text(row, 2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?;

    Ok(match row {
        Some((
            observation_id,
            source,
            source_peer_id,
            semantic_type_code,
            received_at_ms,
            first_stored_at_ms,
            recorded_at_ms,
        )) => IngestEventObservation {
            event_id: event_id.to_string(),
            observed: true,
            observation_id: Some(observation_id),
            source: Some(source),
            source_peer_id,
            semantic_type_code,
            received_at_ms: Some(received_at_ms),
            first_stored_at_ms: Some(first_stored_at_ms),
            recorded_at_ms: Some(recorded_at_ms),
        },
        None => IngestEventObservation {
            event_id: event_id.to_string(),
            observed: false,
            observation_id: None,
            source: None,
            source_peer_id: None,
            semantic_type_code: None,
            received_at_ms: None,
            first_stored_at_ms: None,
            recorded_at_ms: None,
        },
    })
}

pub fn ingest_observability(
    conn: &Connection,
    recorded_by: &str,
    event_ids: &[String],
) -> SqliteResult<IngestObservability> {
    let events = event_ids
        .iter()
        .map(|event_id| event_observation(conn, recorded_by, event_id))
        .collect::<SqliteResult<Vec<_>>>()?;
    Ok(IngestObservability {
        recorded_by: recorded_by.to_string(),
        file_slice_count: file_slice_count(conn, recorded_by)?,
        last_file_slice_observation_id: last_file_slice_observation_id(conn, recorded_by)?,
        quic_received_unique_event_count: quic_received_unique_event_count(conn, recorded_by)?,
        sources: source_counts(conn, recorded_by)?,
        events,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{open_in_memory, schema::create_tables};

    #[test]
    fn ingest_observability_counts_sources_and_file_slices() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        insert_event_ingest_observation(
            &conn,
            "peer-a",
            "event-a",
            "quic_recv:source-a@127.0.0.1:1",
            Some(i64::from(crate::event_modules::EVENT_TYPE_FILE_SLICE)),
            10,
            11,
            12,
        )
        .unwrap();
        insert_event_ingest_observation(
            &conn,
            "peer-a",
            "event-b",
            "local",
            Some(i64::from(crate::event_modules::EVENT_TYPE_MESSAGE)),
            20,
            21,
            22,
        )
        .unwrap();

        let data = ingest_observability(&conn, "peer-a", &["event-a".to_string()]).unwrap();
        assert_eq!(data.file_slice_count, 1);
        assert_eq!(data.quic_received_unique_event_count, 1);
        assert_eq!(data.last_file_slice_observation_id, Some(1));
        assert_eq!(
            data.sources,
            vec![IngestSourceCount {
                source_peer_id: Some("source-a".to_string()),
                source: "quic_recv:source-a@127.0.0.1:1".to_string(),
                event_count: 1,
            }]
        );
        assert_eq!(data.events[0].observation_id, Some(1));
    }
}
