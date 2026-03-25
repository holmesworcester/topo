use rusqlite::Connection;

use super::super::layout::common::COMMON_HEADER_BYTES;
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{Describe, EventError, ParsedEvent, EVENT_TYPE_JOB_DUE};
use super::common::{expect_wire, fresh_blob, read_created_at_ms, read_text, write_text};
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

pub const JOB_KIND_BYTES: usize = 64;
pub const CLIENT_ID_BYTES: usize = 256;
pub const JOB_DUE_WIRE_SIZE: usize = COMMON_HEADER_BYTES + JOB_KIND_BYTES + CLIENT_ID_BYTES;

mod offsets {
    pub const CREATED_AT: usize = 1;
    pub const JOB_KIND: usize = 9;
    pub const CLIENT_ID: usize = JOB_KIND + super::JOB_KIND_BYTES;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobDueEvent {
    pub created_at_ms: u64,
    pub job_kind: String,
    pub client_id: String,
}

impl Describe for JobDueEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("job_kind", self.job_kind.clone()),
            ("client_id", self.client_id.clone()),
        ]
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS job_due_history (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            job_kind TEXT NOT NULL,
            client_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        ",
    )?;
    Ok(())
}

pub fn parse_job_due(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    expect_wire(blob, EVENT_TYPE_JOB_DUE, JOB_DUE_WIRE_SIZE)?;
    let created_at_ms = read_created_at_ms(blob, offsets::CREATED_AT..offsets::JOB_KIND);
    let job_kind = read_text(&blob[offsets::JOB_KIND..offsets::CLIENT_ID])?;
    let client_id = read_text(&blob[offsets::CLIENT_ID..offsets::CLIENT_ID + CLIENT_ID_BYTES])?;

    Ok(ParsedEvent::JobDue(JobDueEvent {
        created_at_ms,
        job_kind,
        client_id,
    }))
}

pub fn encode_job_due(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let due = match event {
        ParsedEvent::JobDue(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = fresh_blob(
        EVENT_TYPE_JOB_DUE,
        JOB_DUE_WIRE_SIZE,
        offsets::CREATED_AT..offsets::JOB_KIND,
        due.created_at_ms,
    );
    write_text(
        &mut buf[offsets::JOB_KIND..offsets::CLIENT_ID],
        &due.job_kind,
    )?;
    write_text(
        &mut buf[offsets::CLIENT_ID..offsets::CLIENT_ID + CLIENT_ID_BYTES],
        &due.client_id,
    )?;
    Ok(buf)
}

fn validate(event: &JobDueEvent) -> Result<(), String> {
    if event.job_kind.trim().is_empty() {
        return Err("job_due requires non-empty job_kind".to_string());
    }
    if event.client_id.trim().is_empty() {
        return Err("job_due requires non-empty client_id".to_string());
    }
    Ok(())
}

pub fn build_projector_context(
    _conn: &Connection,
    _recorded_by: &str,
    _event_id_b64: &str,
    _parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    Ok(ContextSnapshot::default())
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let due = match parsed {
        ParsedEvent::JobDue(event) => event,
        _ => return ProjectorResult::reject("not a job_due event".to_string()),
    };

    if let Err(reason) = validate(due) {
        return ProjectorResult::reject(reason);
    }

    ProjectorResult::valid_with_commands(
        vec![WriteOp::InsertOrIgnore {
            table: "job_due_history",
            columns: vec![
                "recorded_by",
                "event_id",
                "job_kind",
                "client_id",
                "created_at",
            ],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(due.job_kind.clone()),
                SqlVal::Text(due.client_id.clone()),
                SqlVal::Int(due.created_at_ms as i64),
            ],
        }],
        vec![EmitCommand::WakeConnectionPlan {
            connection_id: due.client_id.clone(),
        }],
    )
}

pub static JOB_DUE_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_JOB_DUE,
    type_name: "job_due",
    projection_table: "job_due_history",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_job_due,
    encode: encode_job_due,
    projector: project_pure,
    context_loader: build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::projection::create::create_event_synchronous;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn job_due_roundtrip_encode_parse() {
        let event = JobDueEvent {
            created_at_ms: 12345,
            job_kind: "connection_plan_refresh".to_string(),
            client_id: "client-abc".to_string(),
        };
        let parsed = ParsedEvent::JobDue(event.clone());
        let blob = encode_job_due(&parsed).unwrap();
        assert_eq!(blob.len(), JOB_DUE_WIRE_SIZE);
        let reparsed = parse_job_due(&blob).unwrap();
        assert_eq!(reparsed, parsed);
    }

    #[test]
    fn job_due_projects_history_row() {
        let conn = setup();
        let event = ParsedEvent::JobDue(JobDueEvent {
            created_at_ms: 100,
            job_kind: "sync_cadence".to_string(),
            client_id: "client-abc".to_string(),
        });
        let event_id = create_event_synchronous(&conn, "client-abc", &event).unwrap();
        let event_id_b64 = crate::crypto::event_id_to_base64(&event_id);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM job_due_history WHERE recorded_by = ?1 AND event_id = ?2",
                rusqlite::params!["client-abc", event_id_b64],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn job_due_rejects_empty_job_kind() {
        let conn = setup();
        let event = ParsedEvent::JobDue(JobDueEvent {
            created_at_ms: 100,
            job_kind: "".to_string(),
            client_id: "client-abc".to_string(),
        });
        let err = create_event_synchronous(&conn, "client-abc", &event).unwrap_err();
        match err {
            crate::projection::create::CreateEventError::Rejected { reason, .. } => {
                assert!(reason.contains("non-empty job_kind"));
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn job_due_rejects_empty_client_id() {
        let conn = setup();
        let event = ParsedEvent::JobDue(JobDueEvent {
            created_at_ms: 100,
            job_kind: "sync_cadence".to_string(),
            client_id: "".to_string(),
        });
        let err = create_event_synchronous(&conn, "client-abc", &event).unwrap_err();
        match err {
            crate::projection::create::CreateEventError::Rejected { reason, .. } => {
                assert!(reason.contains("non-empty client_id"));
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }
}
