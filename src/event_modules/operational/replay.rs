//! Replay harness: project a sequence of local operational events from an
//! exported event stream. Supports single-client replay and the foundation
//! for multi-client virtual-time simulation.
//!
//! This module provides the import and replay path described in Phase 8 of
//! the local operational runtime completion plan. Full multi-client merge
//! and virtual-time simulation are deferred to a separate module once the
//! single-client replay path is validated.

use rusqlite::Connection;

use crate::db::schema::create_tables;

/// Import a single client's local event stream into a fresh in-memory
/// database and replay projections. Returns the projected database for
/// assertion.
///
/// `event_blobs` should be the raw wire blobs in causal order. Local
/// operational events and canonical events are both supported.
pub fn replay_single_client(
    recorded_by: &str,
    event_blobs: &[Vec<u8>],
) -> Result<Connection, ReplayError> {
    let conn = crate::db::open_in_memory().map_err(|e| ReplayError::Db(e.to_string()))?;
    create_tables(&conn).map_err(|e| ReplayError::Db(e.to_string()))?;

    for (idx, blob) in event_blobs.iter().enumerate() {
        let parsed = crate::event_modules::parse_event(blob)
            .map_err(|e| ReplayError::Parse { index: idx, error: format!("{e:?}") })?;
        let encoded = crate::event_modules::encode_event(&parsed)
            .map_err(|e| ReplayError::Parse { index: idx, error: format!("{e:?}") })?;
        crate::projection::create::create_event_synchronous(&conn, recorded_by, &parsed)
            .map_err(|e| ReplayError::Project { index: idx, error: format!("{e:?}") })?;
        // Verify round-trip encoding
        if encoded != *blob {
            return Err(ReplayError::EncodingMismatch { index: idx });
        }
    }

    Ok(conn)
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

    #[test]
    fn replay_single_client_projects_client_started() {
        let event = ParsedEvent::ClientStarted(ClientStartedEvent {
            created_at_ms: 1000,
            db_path: "/tmp/replay-test.db".to_string(),
            configured_bind_addr: "127.0.0.1:7443".to_string(),
            reserved_bind_addr: None,
            tenant_count: 1,
        });
        let blob = crate::event_modules::encode_event(&event).unwrap();
        let client_id = client_lifecycle::client_id_for_db_path("/tmp/replay-test.db");

        let conn = replay_single_client(&client_id, &[blob]).unwrap();

        let state = client_lifecycle::load_state(&conn, &client_id).unwrap().unwrap();
        assert_eq!(
            state.runtime_status,
            client_lifecycle::ClientRuntimeStatus::Starting
        );
    }
}
