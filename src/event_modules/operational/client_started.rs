use rusqlite::Connection;

use super::super::layout::common::COMMON_HEADER_BYTES;
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{Describe, EventError, ParsedEvent, EVENT_TYPE_CLIENT_STARTED};
use super::common::{
    expect_wire, fresh_blob, read_created_at_ms, read_optional_text, read_text, read_u64,
    write_optional_text, write_text, write_u64,
};
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

pub const CLIENT_DB_PATH_BYTES: usize = 384;
pub const CLIENT_SOCKET_ADDR_BYTES: usize = 96;
pub const CLIENT_STARTED_WIRE_SIZE: usize = COMMON_HEADER_BYTES
    + CLIENT_DB_PATH_BYTES
    + CLIENT_SOCKET_ADDR_BYTES
    + CLIENT_SOCKET_ADDR_BYTES
    + 8;

mod client_started_offsets {
    pub const CREATED_AT: usize = 1;
    pub const DB_PATH: usize = 9;
    pub const CONFIGURED_BIND_ADDR: usize = DB_PATH + super::CLIENT_DB_PATH_BYTES;
    pub const RESERVED_BIND_ADDR: usize = CONFIGURED_BIND_ADDR + super::CLIENT_SOCKET_ADDR_BYTES;
    pub const TENANT_COUNT: usize = RESERVED_BIND_ADDR + super::CLIENT_SOCKET_ADDR_BYTES;
}

use client_started_offsets as off;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientStartedEvent {
    pub created_at_ms: u64,
    pub db_path: String,
    pub configured_bind_addr: String,
    pub reserved_bind_addr: Option<String>,
    pub tenant_count: u64,
}

impl Describe for ClientStartedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("db_path", self.db_path.clone()),
            ("configured_bind_addr", self.configured_bind_addr.clone()),
            ("tenant_count", self.tenant_count.to_string()),
        ];
        if let Some(reserved) = &self.reserved_bind_addr {
            fields.push(("reserved_bind_addr", reserved.clone()));
        }
        fields
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS client_runtime_history (
            client_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            run_id TEXT NOT NULL,
            db_path TEXT NOT NULL,
            configured_bind_addr TEXT NOT NULL,
            reserved_bind_addr TEXT,
            listen_addr TEXT,
            runtime_status TEXT NOT NULL,
            tenant_count INTEGER NOT NULL DEFAULT 0,
            started_at_ms INTEGER NOT NULL,
            activated_at_ms INTEGER,
            stopped_at_ms INTEGER,
            stop_reason TEXT,
            basis_event_id TEXT,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (client_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_client_runtime_history_latest
            ON client_runtime_history(client_id, created_at DESC, event_id DESC);
        CREATE INDEX IF NOT EXISTS idx_client_runtime_history_run_latest
            ON client_runtime_history(client_id, run_id, created_at DESC, event_id DESC);
        ",
    )?;
    Ok(())
}

pub fn parse_client_started(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    expect_wire(blob, EVENT_TYPE_CLIENT_STARTED, CLIENT_STARTED_WIRE_SIZE)?;

    let created_at_ms = read_created_at_ms(blob, off::CREATED_AT..off::DB_PATH);
    let db_path = read_text(&blob[off::DB_PATH..off::CONFIGURED_BIND_ADDR])?;
    let configured_bind_addr =
        read_text(&blob[off::CONFIGURED_BIND_ADDR..off::RESERVED_BIND_ADDR])?;
    let reserved_bind_addr = read_optional_text(&blob[off::RESERVED_BIND_ADDR..off::TENANT_COUNT])?;
    let tenant_count = read_u64(&blob[off::TENANT_COUNT..off::TENANT_COUNT + 8]);

    Ok(ParsedEvent::ClientStarted(ClientStartedEvent {
        created_at_ms,
        db_path,
        configured_bind_addr,
        reserved_bind_addr,
        tenant_count,
    }))
}

pub fn encode_client_started(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let started = match event {
        ParsedEvent::ClientStarted(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = fresh_blob(
        EVENT_TYPE_CLIENT_STARTED,
        CLIENT_STARTED_WIRE_SIZE,
        off::CREATED_AT..off::DB_PATH,
        started.created_at_ms,
    );
    write_text(
        &mut buf[off::DB_PATH..off::CONFIGURED_BIND_ADDR],
        &started.db_path,
    )?;
    write_text(
        &mut buf[off::CONFIGURED_BIND_ADDR..off::RESERVED_BIND_ADDR],
        &started.configured_bind_addr,
    )?;
    write_optional_text(
        &mut buf[off::RESERVED_BIND_ADDR..off::TENANT_COUNT],
        started.reserved_bind_addr.as_deref(),
    )?;
    write_u64(
        &mut buf[off::TENANT_COUNT..off::TENANT_COUNT + 8],
        started.tenant_count,
    );
    Ok(buf)
}

fn validate_started(event: &ClientStartedEvent) -> Result<(), String> {
    if event.db_path.trim().is_empty() {
        return Err("client_started requires non-empty db_path".to_string());
    }
    let configured: std::net::SocketAddr = event
        .configured_bind_addr
        .parse()
        .map_err(|_| "client_started configured_bind_addr must be a socket address".to_string())?;
    if configured.port() == 0 {
        return Err("client_started configured_bind_addr port must be non-zero".to_string());
    }
    if let Some(reserved) = &event.reserved_bind_addr {
        let reserved: std::net::SocketAddr = reserved.parse().map_err(|_| {
            "client_started reserved_bind_addr must be a socket address".to_string()
        })?;
        if reserved.port() == 0 {
            return Err("client_started reserved_bind_addr port must be non-zero".to_string());
        }
    }
    Ok(())
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let started = match parsed {
        ParsedEvent::ClientStarted(event) => event,
        _ => return ProjectorResult::reject("not a client_started event".to_string()),
    };

    if let Err(reason) = validate_started(started) {
        return ProjectorResult::reject(reason);
    }

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
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(started.db_path.clone()),
                SqlVal::Text(started.configured_bind_addr.clone()),
                started
                    .reserved_bind_addr
                    .as_ref()
                    .map(|addr| SqlVal::Text(addr.clone()))
                    .unwrap_or(SqlVal::Null),
                SqlVal::Null,
                SqlVal::Text("starting".to_string()),
                SqlVal::Int(started.tenant_count as i64),
                SqlVal::Int(started.created_at_ms as i64),
                SqlVal::Null,
                SqlVal::Null,
                SqlVal::Null,
                SqlVal::Null,
                SqlVal::Int(started.created_at_ms as i64),
            ],
        }],
        vec![EmitCommand::WakeClientRuntime {
            client_id: recorded_by.to_string(),
        }],
    )
}

pub static CLIENT_STARTED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_CLIENT_STARTED,
    type_name: "client_started",
    projection_table: "client_runtime_history",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_client_started,
    encode: encode_client_started,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};
