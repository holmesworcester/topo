use rusqlite::Connection;

use super::super::layout::common::COMMON_HEADER_BYTES;
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{Describe, EventError, ParsedEvent, EVENT_TYPE_CLIENT_STOPPED};
use super::common::{
    expect_wire, fresh_blob, read_created_at_ms, read_event_id, read_text, write_event_id,
    write_text,
};
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

pub const CLIENT_STOP_REASON_BYTES: usize = 128;
pub const CLIENT_STOPPED_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32 + CLIENT_STOP_REASON_BYTES;

mod client_stopped_offsets {
    pub const CREATED_AT: usize = 1;
    pub const BASIS_EVENT_ID: usize = 9;
    pub const STOP_REASON: usize = BASIS_EVENT_ID + 32;
}

use client_stopped_offsets as off;

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
    expect_wire(blob, EVENT_TYPE_CLIENT_STOPPED, CLIENT_STOPPED_WIRE_SIZE)?;
    let created_at_ms = read_created_at_ms(blob, off::CREATED_AT..off::BASIS_EVENT_ID);
    let basis_event_id = read_event_id(&blob[off::BASIS_EVENT_ID..off::STOP_REASON]);
    let stop_reason =
        read_text(&blob[off::STOP_REASON..off::STOP_REASON + CLIENT_STOP_REASON_BYTES])?;

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

    let mut buf = fresh_blob(
        EVENT_TYPE_CLIENT_STOPPED,
        CLIENT_STOPPED_WIRE_SIZE,
        off::CREATED_AT..off::BASIS_EVENT_ID,
        stopped.created_at_ms,
    );
    write_event_id(
        &mut buf[off::BASIS_EVENT_ID..off::STOP_REASON],
        &stopped.basis_event_id,
    );
    write_text(
        &mut buf[off::STOP_REASON..off::STOP_REASON + CLIENT_STOP_REASON_BYTES],
        &stopped.stop_reason,
    )?;
    Ok(buf)
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
    ]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_client_stopped,
    encode: encode_client_stopped,
    projector: project_pure,
    context_loader: build_projector_context,
};
