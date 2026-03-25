use rusqlite::Connection;

use super::super::layout::common::COMMON_HEADER_BYTES;
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{Describe, EventError, ParsedEvent, EVENT_TYPE_CLIENT_ACTIVATED};
use super::client_started::CLIENT_SOCKET_ADDR_BYTES;
use super::common::{
    expect_wire, fresh_blob, read_created_at_ms, read_event_id, read_text, read_u64,
    write_event_id, write_text, write_u64,
};
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

pub const CLIENT_ACTIVATED_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + CLIENT_SOCKET_ADDR_BYTES + 8;

mod client_activated_offsets {
    pub const CREATED_AT: usize = 1;
    pub const BASIS_EVENT_ID: usize = 9;
    pub const LISTEN_ADDR: usize = BASIS_EVENT_ID + 32;
    pub const TENANT_COUNT: usize = LISTEN_ADDR + super::CLIENT_SOCKET_ADDR_BYTES;
}

use client_activated_offsets as off;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientActivatedEvent {
    pub created_at_ms: u64,
    pub basis_event_id: [u8; 32],
    pub listen_addr: String,
    pub tenant_count: u64,
}

impl Describe for ClientActivatedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "basis_event_id",
                super::super::short_id_b64(&self.basis_event_id),
            ),
            ("listen_addr", self.listen_addr.clone()),
            ("tenant_count", self.tenant_count.to_string()),
        ]
    }
}

pub fn ensure_schema(_conn: &Connection) -> rusqlite::Result<()> {
    Ok(())
}

pub fn parse_client_activated(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    expect_wire(
        blob,
        EVENT_TYPE_CLIENT_ACTIVATED,
        CLIENT_ACTIVATED_WIRE_SIZE,
    )?;
    let created_at_ms = read_created_at_ms(blob, off::CREATED_AT..off::BASIS_EVENT_ID);
    let basis_event_id = read_event_id(&blob[off::BASIS_EVENT_ID..off::LISTEN_ADDR]);
    let listen_addr = read_text(&blob[off::LISTEN_ADDR..off::TENANT_COUNT])?;
    let tenant_count = read_u64(&blob[off::TENANT_COUNT..off::TENANT_COUNT + 8]);

    Ok(ParsedEvent::ClientActivated(ClientActivatedEvent {
        created_at_ms,
        basis_event_id,
        listen_addr,
        tenant_count,
    }))
}

pub fn encode_client_activated(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let activated = match event {
        ParsedEvent::ClientActivated(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = fresh_blob(
        EVENT_TYPE_CLIENT_ACTIVATED,
        CLIENT_ACTIVATED_WIRE_SIZE,
        off::CREATED_AT..off::BASIS_EVENT_ID,
        activated.created_at_ms,
    );
    write_event_id(
        &mut buf[off::BASIS_EVENT_ID..off::LISTEN_ADDR],
        &activated.basis_event_id,
    );
    write_text(
        &mut buf[off::LISTEN_ADDR..off::TENANT_COUNT],
        &activated.listen_addr,
    )?;
    write_u64(
        &mut buf[off::TENANT_COUNT..off::TENANT_COUNT + 8],
        activated.tenant_count,
    );
    Ok(buf)
}

pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let activated = match parsed {
        ParsedEvent::ClientActivated(event) => event,
        _ => return Err("client_activated context loader called for wrong event".into()),
    };

    super::common::build_client_run_basis_context(
        conn,
        recorded_by,
        &activated.basis_event_id,
        "client_activated",
    )
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let activated = match parsed {
        ParsedEvent::ClientActivated(event) => event,
        _ => return ProjectorResult::reject("not a client_activated event".to_string()),
    };

    if activated
        .listen_addr
        .parse::<std::net::SocketAddr>()
        .is_err()
    {
        return ProjectorResult::reject(
            "client_activated listen_addr must be a socket address".to_string(),
        );
    }
    if let Some(reason) = &ctx.client_runtime_basis_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }
    let Some(snapshot) = &ctx.client_runtime_snapshot else {
        return ProjectorResult::reject(
            "client_activated missing client runtime snapshot context".to_string(),
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
                SqlVal::Text(activated.listen_addr.clone()),
                SqlVal::Text("active".to_string()),
                SqlVal::Int(activated.tenant_count as i64),
                SqlVal::Int(snapshot.started_at_ms),
                SqlVal::Int(activated.created_at_ms as i64),
                SqlVal::Null,
                SqlVal::Null,
                SqlVal::Text(snapshot.event_id.clone()),
                SqlVal::Int(activated.created_at_ms as i64),
            ],
        }],
        vec![EmitCommand::WakeClientRuntime {
            client_id: recorded_by.to_string(),
        }],
    )
}

pub static CLIENT_ACTIVATED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_CLIENT_ACTIVATED,
    type_name: "client_activated",
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
    parse: parse_client_activated,
    encode: encode_client_activated,
    projector: project_pure,
    context_loader: build_projector_context,
};
