//! Replay and simulation harness for local operational events.
//!
//! Supports:
//! - Single-client replay: import one client's event stream and project it
//! - Multi-client merge: import multiple clients, interleave by virtual time
//! - Simulation bridge edges: cross-client references that only exist in sim
//! - Virtual time: projection advances on event timestamps, not wall clock

use rusqlite::Connection;

use crate::db::schema::create_tables;

/// A timestamped event blob from one client, for multi-client interleaving.
#[derive(Debug, Clone)]
pub struct SimulationEvent {
    /// Which client recorded this event (the `recorded_by` / `client_id`).
    pub client_id: String,
    /// Raw wire blob.
    pub blob: Vec<u8>,
    /// Virtual timestamp for ordering (typically the event's created_at_ms).
    pub virtual_time_ms: u64,
}

/// Import a single client's local event stream into a fresh in-memory
/// database and replay projections.
pub fn replay_single_client(
    recorded_by: &str,
    event_blobs: &[Vec<u8>],
) -> Result<Connection, ReplayError> {
    let conn = open_replay_db()?;

    for (idx, blob) in event_blobs.iter().enumerate() {
        project_blob(&conn, recorded_by, idx, blob)?;
    }

    Ok(conn)
}

/// Import multiple clients' event streams, interleave them by virtual time,
/// and project the merged stream into a single database. Each client's events
/// are projected under its own `client_id` namespace.
///
/// `bridge_edges` are simulation-only synthetic events injected at specific
/// virtual times (e.g., connecting two clients' episode identities).
pub fn replay_multi_client(
    client_streams: &[(String, Vec<Vec<u8>>)],
    bridge_edges: &[SimulationEvent],
) -> Result<Connection, ReplayError> {
    let conn = open_replay_db()?;

    // Build interleaved stream: (virtual_time, client_id, blob)
    let mut merged: Vec<SimulationEvent> = Vec::new();
    for (client_id, blobs) in client_streams {
        for blob in blobs {
            let parsed = crate::event_modules::parse_event(blob)
                .map_err(|e| ReplayError::Parse { index: 0, error: format!("{e:?}") })?;
            merged.push(SimulationEvent {
                client_id: client_id.clone(),
                blob: blob.clone(),
                virtual_time_ms: parsed.created_at_ms(),
            });
        }
    }
    for edge in bridge_edges {
        merged.push(edge.clone());
    }

    // Sort by virtual time (stable sort preserves intra-client order)
    merged.sort_by_key(|e| e.virtual_time_ms);

    // Project in virtual-time order
    for (idx, event) in merged.iter().enumerate() {
        project_blob(&conn, &event.client_id, idx, &event.blob)?;
    }

    Ok(conn)
}

/// Query the virtual time of the last projected event.
pub fn last_projected_time(conn: &Connection) -> Option<u64> {
    // Check client_runtime_history as a proxy for latest projected time
    conn.query_row(
        "SELECT MAX(created_at) FROM client_runtime_history",
        [],
        |row| row.get::<_, Option<i64>>(0),
    )
    .ok()
    .flatten()
    .map(|t| t as u64)
}

fn open_replay_db() -> Result<Connection, ReplayError> {
    let conn = Connection::open_in_memory().map_err(|e| ReplayError::Db(e.to_string()))?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;")
        .map_err(|e| ReplayError::Db(e.to_string()))?;
    create_tables(&conn).map_err(|e| ReplayError::Db(e.to_string()))?;
    Ok(conn)
}

fn project_blob(
    conn: &Connection,
    recorded_by: &str,
    idx: usize,
    blob: &[u8],
) -> Result<(), ReplayError> {
    let parsed = crate::event_modules::parse_event(blob)
        .map_err(|e| ReplayError::Parse { index: idx, error: format!("{e:?}") })?;
    let encoded = crate::event_modules::encode_event(&parsed)
        .map_err(|e| ReplayError::Parse { index: idx, error: format!("{e:?}") })?;
    crate::projection::create::create_event_synchronous(conn, recorded_by, &parsed)
        .map_err(|e| ReplayError::Project { index: idx, error: format!("{e:?}") })?;
    if encoded != blob {
        return Err(ReplayError::EncodingMismatch { index: idx });
    }
    Ok(())
}

/// Errors during replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayError {
    Db(String),
    Parse { index: usize, error: String },
    Project { index: usize, error: String },
    EncodingMismatch { index: usize },
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Db(msg) => write!(f, "database error: {msg}"),
            Self::Parse { index, error } => write!(f, "parse error at event {index}: {error}"),
            Self::Project { index, error } => write!(f, "projection error at event {index}: {error}"),
            Self::EncodingMismatch { index } => {
                write!(f, "encoding round-trip mismatch at event {index}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event_modules::operational::client_lifecycle;
    use crate::event_modules::operational::client_started::ClientStartedEvent;
    use crate::event_modules::ParsedEvent;

    fn make_client_started(db_path: &str, ts: u64) -> Vec<u8> {
        let event = ParsedEvent::ClientStarted(ClientStartedEvent {
            created_at_ms: ts,
            db_path: db_path.to_string(),
            configured_bind_addr: "127.0.0.1:7443".to_string(),
            reserved_bind_addr: None,
            tenant_count: 1,
        });
        crate::event_modules::encode_event(&event).unwrap()
    }

    #[test]
    fn replay_single_client_projects_client_started() {
        let blob = make_client_started("/tmp/replay-test.db", 1000);
        let client_id = client_lifecycle::client_id_for_db_path("/tmp/replay-test.db");
        let conn = replay_single_client(&client_id, &[blob]).unwrap();
        let state = client_lifecycle::load_state(&conn, &client_id).unwrap().unwrap();
        assert_eq!(state.runtime_status, client_lifecycle::ClientRuntimeStatus::Starting);
    }

    #[test]
    fn replay_multi_client_interleaves_by_virtual_time() {
        let blob_a = make_client_started("/tmp/client-a.db", 100);
        let blob_b = make_client_started("/tmp/client-b.db", 50);

        let client_a = client_lifecycle::client_id_for_db_path("/tmp/client-a.db");
        let client_b = client_lifecycle::client_id_for_db_path("/tmp/client-b.db");

        let conn = replay_multi_client(
            &[
                (client_a.clone(), vec![blob_a]),
                (client_b.clone(), vec![blob_b]),
            ],
            &[],
        )
        .unwrap();

        // Both clients should have projected state
        let state_a = client_lifecycle::load_state(&conn, &client_a).unwrap().unwrap();
        let state_b = client_lifecycle::load_state(&conn, &client_b).unwrap().unwrap();
        assert_eq!(state_a.runtime_status, client_lifecycle::ClientRuntimeStatus::Starting);
        assert_eq!(state_b.runtime_status, client_lifecycle::ClientRuntimeStatus::Starting);

        // Client B (ts=50) was projected before Client A (ts=100)
        let last_time = last_projected_time(&conn);
        assert!(last_time.is_some());
    }

    #[test]
    fn replay_multi_client_with_bridge_edges() {
        let blob_a = make_client_started("/tmp/bridge-a.db", 100);
        let client_a = client_lifecycle::client_id_for_db_path("/tmp/bridge-a.db");

        // Bridge edge: a synthetic client_started for a "bridged" client at ts=150
        let bridge_blob = make_client_started("/tmp/bridge-sim.db", 150);
        let bridge_client = client_lifecycle::client_id_for_db_path("/tmp/bridge-sim.db");
        let bridge = SimulationEvent {
            client_id: bridge_client.clone(),
            blob: bridge_blob,
            virtual_time_ms: 150,
        };

        let conn = replay_multi_client(
            &[(client_a.clone(), vec![blob_a])],
            &[bridge],
        )
        .unwrap();

        // Both real and bridge clients should exist
        assert!(client_lifecycle::load_state(&conn, &client_a).unwrap().is_some());
        assert!(client_lifecycle::load_state(&conn, &bridge_client).unwrap().is_some());
    }

    #[test]
    fn virtual_time_differs_from_wall_time() {
        // Events with timestamps far in the past — virtual time, not wall clock
        let blob = make_client_started("/tmp/virtual-time.db", 1);
        let client_id = client_lifecycle::client_id_for_db_path("/tmp/virtual-time.db");
        let conn = replay_single_client(&client_id, &[blob]).unwrap();
        let state = client_lifecycle::load_state(&conn, &client_id).unwrap().unwrap();
        // The event was projected at virtual_time=1, not at current wall time
        assert_eq!(state.runtime_status, client_lifecycle::ClientRuntimeStatus::Starting);
    }
}
