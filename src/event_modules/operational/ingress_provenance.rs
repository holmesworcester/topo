//! Ingress provenance: durable record tying canonical event ingestion to the
//! transport/runtime episode that delivered it.
//!
//! Each row answers: "How did this event enter this client?"

use rusqlite::{params, Connection, Result as SqliteResult};

use crate::db::queue::{current_timestamp_ms, with_sqlite_busy_retry};

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS ingress_provenance (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            connection_id TEXT,
            sync_round_id TEXT,
            peer_id TEXT NOT NULL,
            source_tag TEXT NOT NULL,
            ingested_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_ingress_provenance_round
            ON ingress_provenance(recorded_by, sync_round_id);
        CREATE INDEX IF NOT EXISTS idx_ingress_provenance_peer
            ON ingress_provenance(recorded_by, peer_id);
        ",
    )?;
    Ok(())
}

/// Record provenance for a batch of ingested canonical events.
pub fn record_ingress_batch(
    conn: &Connection,
    recorded_by: &str,
    event_ids_b64: &[String],
    connection_id: Option<&str>,
    sync_round_id: Option<&str>,
    peer_id: &str,
    source_tag: &str,
) -> SqliteResult<usize> {
    if event_ids_b64.is_empty() {
        return Ok(0);
    }
    let now = current_timestamp_ms();
    with_sqlite_busy_retry(|| {
        let mut count = 0usize;
        let mut stmt = conn.prepare_cached(
            "INSERT OR IGNORE INTO ingress_provenance
                 (recorded_by, event_id, connection_id, sync_round_id, peer_id, source_tag, ingested_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        )?;
        for event_id in event_ids_b64 {
            count += stmt.execute(params![
                recorded_by,
                event_id,
                connection_id,
                sync_round_id,
                peer_id,
                source_tag,
                now
            ])? as usize;
        }
        Ok(count)
    })
}

/// Query provenance for a specific canonical event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvenanceRow {
    pub event_id: String,
    pub connection_id: Option<String>,
    pub sync_round_id: Option<String>,
    pub peer_id: String,
    pub source_tag: String,
    pub ingested_at: i64,
}

pub fn query_provenance(
    conn: &Connection,
    recorded_by: &str,
    event_id: &str,
) -> SqliteResult<Option<ProvenanceRow>> {
    with_sqlite_busy_retry(|| {
        conn.query_row(
            "SELECT event_id, connection_id, sync_round_id, peer_id, source_tag, ingested_at
             FROM ingress_provenance
             WHERE recorded_by = ?1 AND event_id = ?2",
            params![recorded_by, event_id],
            |row| {
                Ok(ProvenanceRow {
                    event_id: row.get(0)?,
                    connection_id: row.get(1)?,
                    sync_round_id: row.get(2)?,
                    peer_id: row.get(3)?,
                    source_tag: row.get(4)?,
                    ingested_at: row.get(5)?,
                })
            },
        )
        .optional()
    })
}

/// Count events ingested in a specific sync round.
pub fn count_events_in_round(
    conn: &Connection,
    recorded_by: &str,
    sync_round_id: &str,
) -> SqliteResult<usize> {
    with_sqlite_busy_retry(|| {
        conn.query_row(
            "SELECT COUNT(*) FROM ingress_provenance
             WHERE recorded_by = ?1 AND sync_round_id = ?2",
            params![recorded_by, sync_round_id],
            |row| row.get::<_, i64>(0).map(|n| n as usize),
        )
    })
}

use rusqlite::OptionalExtension;

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
    fn record_and_query_provenance() {
        let conn = setup();
        let ids = vec!["event-a".to_string(), "event-b".to_string()];
        let count = record_ingress_batch(
            &conn,
            "tenant-a",
            &ids,
            Some("conn-1"),
            Some("round-1"),
            "peer-x",
            "sync_responder",
        )
        .unwrap();
        assert_eq!(count, 2);

        let row = query_provenance(&conn, "tenant-a", "event-a").unwrap().unwrap();
        assert_eq!(row.peer_id, "peer-x");
        assert_eq!(row.connection_id.as_deref(), Some("conn-1"));
        assert_eq!(row.sync_round_id.as_deref(), Some("round-1"));
        assert_eq!(row.source_tag, "sync_responder");
    }

    #[test]
    fn count_events_in_round_query() {
        let conn = setup();
        let ids = vec![
            "event-1".to_string(),
            "event-2".to_string(),
            "event-3".to_string(),
        ];
        record_ingress_batch(
            &conn,
            "tenant-a",
            &ids,
            None,
            Some("round-42"),
            "peer-y",
            "sync_initiator",
        )
        .unwrap();

        assert_eq!(
            count_events_in_round(&conn, "tenant-a", "round-42").unwrap(),
            3
        );
    }

    #[test]
    fn provenance_traces_event_to_connection_and_round() {
        // E2E: simulate what the production ingest path does — record provenance
        // for canonical events, then verify the system can answer "how did this
        // event enter the node?"
        let conn = setup();
        let tenant = "tenant-ingest";
        let peer = "peer-abc";
        let conn_id = "conn-77";
        let round_id = "session:42";

        // Simulate ingesting 2 canonical events from a sync round
        let event_ids = vec!["ev-canonical-1".to_string(), "ev-canonical-2".to_string()];
        let recorded = record_ingress_batch(
            &conn,
            tenant,
            &event_ids,
            Some(conn_id),
            Some(round_id),
            peer,
            "receive_log",
        )
        .unwrap();
        assert_eq!(recorded, 2);

        // Now answer: "how did ev-canonical-1 enter this node?"
        let prov = query_provenance(&conn, tenant, "ev-canonical-1").unwrap().unwrap();
        assert_eq!(prov.peer_id, peer);
        assert_eq!(prov.connection_id.as_deref(), Some(conn_id));
        assert_eq!(prov.sync_round_id.as_deref(), Some(round_id));
        assert_eq!(prov.source_tag, "receive_log");

        // Count: how many events arrived in that sync round?
        assert_eq!(count_events_in_round(&conn, tenant, round_id).unwrap(), 2);
    }

    #[test]
    fn provenance_absent_when_event_not_ingested() {
        let conn = setup();
        // No provenance recorded — query should return None
        assert!(query_provenance(&conn, "tenant-x", "ev-never-ingested").unwrap().is_none());
    }

    #[test]
    fn duplicate_event_ids_are_ignored() {
        let conn = setup();
        let ids = vec!["event-dup".to_string()];
        record_ingress_batch(&conn, "t-a", &ids, None, None, "peer-z", "tag1").unwrap();
        let count =
            record_ingress_batch(&conn, "t-a", &ids, None, None, "peer-z", "tag2").unwrap();
        assert_eq!(count, 0);
    }
}
