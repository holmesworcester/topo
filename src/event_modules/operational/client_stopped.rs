use rusqlite::Connection;

use super::super::layout::field_spec::{decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{Describe, EventError, ParsedEvent, EVENT_TYPE_CLIENT_STOPPED};

use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

pub const CLIENT_STOP_REASON_BYTES: usize = 128;
pub const CLIENT_STOPPED_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("basis_event_id"),
    FieldSpec::Text("stop_reason", CLIENT_STOP_REASON_BYTES),
];
pub const CLIENT_STOPPED_WIRE_SIZE: usize = wire_size_for_fields(CLIENT_STOPPED_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientStoppedEvent {
    pub created_at_ms: u64,
    pub basis_event_id: [u8; 32],
    pub stop_reason: String,
}

impl Describe for ClientStoppedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "basis_event_id",
                super::super::short_id_b64(&self.basis_event_id),
            ),
            ("stop_reason", self.stop_reason.clone()),
        ]
    }
}

pub fn ensure_schema(_conn: &Connection) -> rusqlite::Result<()> {
    Ok(())
}

pub fn parse_client_stopped(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_CLIENT_STOPPED, CLIENT_STOPPED_FIELDS, blob)?;
    let created_at_ms = values[0].as_timestamp().unwrap();
    let basis_event_id = values[1].as_event_id().unwrap();
    let stop_reason = values[2].as_text().unwrap().to_string();

    Ok(ParsedEvent::ClientStopped(ClientStoppedEvent {
        created_at_ms,
        basis_event_id,
        stop_reason,
    }))
}

pub fn encode_client_stopped(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let stopped = match event {
        ParsedEvent::ClientStopped(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(stopped.created_at_ms),
        FieldValue::EventId(stopped.basis_event_id),
        FieldValue::Text(stopped.stop_reason.clone()),
    ];
    Ok(encode_fields(EVENT_TYPE_CLIENT_STOPPED, CLIENT_STOPPED_FIELDS, &values)?)
}

pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let stopped = match parsed {
        ParsedEvent::ClientStopped(event) => event,
        _ => return Err("client_stopped context loader called for wrong event".into()),
    };

    super::common::build_client_run_basis_context(
        conn,
        recorded_by,
        &stopped.basis_event_id,
        "client_stopped",
    )
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let stopped = match parsed {
        ParsedEvent::ClientStopped(event) => event,
        _ => return ProjectorResult::reject("not a client_stopped event".to_string()),
    };

    if stopped.stop_reason.trim().is_empty() {
        return ProjectorResult::reject(
            "client_stopped requires non-empty stop_reason".to_string(),
        );
    }
    if let Some(reason) = &ctx.client_runtime_basis_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }
    let Some(snapshot) = &ctx.client_runtime_snapshot else {
        return ProjectorResult::reject(
            "client_stopped missing client runtime snapshot context".to_string(),
        );
    };

    ProjectorResult::valid_with_commands(
        vec![WriteOp::InsertOrIgnore {
            table: "client_runtime_history",
            columns: vec![
                "client_id",
                "event_id",
                "run_id",
                "db_path",
                "configured_bind_addr",
                "reserved_bind_addr",
                "listen_addr",
                "runtime_status",
                "tenant_count",
                "started_at_ms",
                "activated_at_ms",
                "stopped_at_ms",
                "stop_reason",
                "basis_event_id",
                "created_at",
            ],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(snapshot.run_id.clone()),
                SqlVal::Text(snapshot.db_path.clone()),
                SqlVal::Text(snapshot.configured_bind_addr.clone()),
                snapshot
                    .reserved_bind_addr
                    .as_ref()
                    .map(|addr| SqlVal::Text(addr.clone()))
                    .unwrap_or(SqlVal::Null),
                snapshot
                    .listen_addr
                    .as_ref()
                    .map(|addr| SqlVal::Text(addr.clone()))
                    .unwrap_or(SqlVal::Null),
                SqlVal::Text("stopped".to_string()),
                SqlVal::Int(snapshot.tenant_count),
                SqlVal::Int(snapshot.started_at_ms),
                snapshot
                    .activated_at_ms
                    .map(SqlVal::Int)
                    .unwrap_or(SqlVal::Null),
                SqlVal::Int(stopped.created_at_ms as i64),
                SqlVal::Text(stopped.stop_reason.clone()),
                SqlVal::Text(snapshot.event_id.clone()),
                SqlVal::Int(stopped.created_at_ms as i64),
            ],
        }],
        vec![EmitCommand::WakeClientRuntime {
            client_id: recorded_by.to_string(),
        }],
    )
}

pub static CLIENT_STOPPED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_CLIENT_STOPPED,
    type_name: "client_stopped",
    projection_table: "client_runtime_history",
    share_scope: ShareScope::Local,
    dep_fields: &["basis_event_id"],
    dep_field_type_codes: &[&[
        super::super::EVENT_TYPE_CLIENT_STARTED,
        super::super::EVENT_TYPE_CLIENT_ACTIVATED,
        super::super::EVENT_TYPE_CLIENT_STOPPED,
        super::super::EVENT_TYPE_LISTENER_BIND_FAILED,
    ]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_client_stopped,
    encode: encode_client_stopped,
    projector: project_pure,
    context_loader: build_projector_context,
};
