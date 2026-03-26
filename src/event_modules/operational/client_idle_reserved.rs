use rusqlite::Connection;

use super::super::layout::field_spec::{decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{Describe, EventError, ParsedEvent, EVENT_TYPE_CLIENT_IDLE_RESERVED};

use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

pub const CLIENT_DB_PATH_BYTES: usize = 384;
pub const CLIENT_SOCKET_ADDR_BYTES: usize = 96;
pub const CLIENT_IDLE_RESERVED_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::Text("db_path", CLIENT_DB_PATH_BYTES),
    FieldSpec::Text("configured_bind_addr", CLIENT_SOCKET_ADDR_BYTES),
    FieldSpec::Text("reserved_bind_addr", CLIENT_SOCKET_ADDR_BYTES),
    FieldSpec::U64("tenant_count"),
];
pub const CLIENT_IDLE_RESERVED_WIRE_SIZE: usize = wire_size_for_fields(CLIENT_IDLE_RESERVED_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIdleReservedEvent {
    pub created_at_ms: u64,
    pub db_path: String,
    pub configured_bind_addr: String,
    pub reserved_bind_addr: String,
    pub tenant_count: u64,
}

impl Describe for ClientIdleReservedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("db_path", self.db_path.clone()),
            ("configured_bind_addr", self.configured_bind_addr.clone()),
            ("reserved_bind_addr", self.reserved_bind_addr.clone()),
            ("tenant_count", self.tenant_count.to_string()),
        ]
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    super::client_started::ensure_schema(conn)
}

pub fn parse_client_idle_reserved(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_CLIENT_IDLE_RESERVED, CLIENT_IDLE_RESERVED_FIELDS, blob)?;
    let created_at_ms = values[0].as_timestamp().unwrap();
    let db_path = values[1].as_text().unwrap().to_string();
    let configured_bind_addr = values[2].as_text().unwrap().to_string();
    let reserved_bind_addr = values[3].as_text().unwrap().to_string();
    let tenant_count = values[4].as_u64().unwrap();

    Ok(ParsedEvent::ClientIdleReserved(ClientIdleReservedEvent {
        created_at_ms,
        db_path,
        configured_bind_addr,
        reserved_bind_addr,
        tenant_count,
    }))
}

pub fn encode_client_idle_reserved(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let reserved = match event {
        ParsedEvent::ClientIdleReserved(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(reserved.created_at_ms),
        FieldValue::Text(reserved.db_path.clone()),
        FieldValue::Text(reserved.configured_bind_addr.clone()),
        FieldValue::Text(reserved.reserved_bind_addr.clone()),
        FieldValue::U64(reserved.tenant_count),
    ];
    Ok(encode_fields(EVENT_TYPE_CLIENT_IDLE_RESERVED, CLIENT_IDLE_RESERVED_FIELDS, &values)?)
}

fn validate_reserved(event: &ClientIdleReservedEvent) -> Result<(), String> {
    if event.db_path.trim().is_empty() {
        return Err("client_idle_reserved requires non-empty db_path".to_string());
    }
    let configured: std::net::SocketAddr = event.configured_bind_addr.parse().map_err(|_| {
        "client_idle_reserved configured_bind_addr must be a socket address".to_string()
    })?;
    if configured.port() == 0 {
        return Err("client_idle_reserved configured_bind_addr port must be non-zero".to_string());
    }
    let reserved: std::net::SocketAddr = event.reserved_bind_addr.parse().map_err(|_| {
        "client_idle_reserved reserved_bind_addr must be a socket address".to_string()
    })?;
    if reserved.port() == 0 {
        return Err("client_idle_reserved reserved_bind_addr port must be non-zero".to_string());
    }
    Ok(())
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let reserved = match parsed {
        ParsedEvent::ClientIdleReserved(event) => event,
        _ => return ProjectorResult::reject("not a client_idle_reserved event".to_string()),
    };

    if let Err(reason) = validate_reserved(reserved) {
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
                SqlVal::Text(reserved.db_path.clone()),
                SqlVal::Text(reserved.configured_bind_addr.clone()),
                SqlVal::Text(reserved.reserved_bind_addr.clone()),
                SqlVal::Null,
                SqlVal::Text("idle_no_tenants".to_string()),
                SqlVal::Int(reserved.tenant_count as i64),
                SqlVal::Int(reserved.created_at_ms as i64),
                SqlVal::Null,
                SqlVal::Null,
                SqlVal::Null,
                SqlVal::Null,
                SqlVal::Int(reserved.created_at_ms as i64),
            ],
        }],
        vec![EmitCommand::WakeClientRuntime {
            client_id: recorded_by.to_string(),
        }],
    )
}

pub static CLIENT_IDLE_RESERVED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_CLIENT_IDLE_RESERVED,
    type_name: "client_idle_reserved",
    projection_table: "client_runtime_history",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_client_idle_reserved,
    encode: encode_client_idle_reserved,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::event_modules::operational::client_lifecycle;
    use crate::projection::create::{create_event_synchronous, CreateEventError};

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn client_idle_reserved_projects_idle_state() {
        let conn = setup();
        let event = ParsedEvent::ClientIdleReserved(ClientIdleReservedEvent {
            created_at_ms: 10,
            db_path: "/tmp/topo-idle.db".to_string(),
            configured_bind_addr: "127.0.0.1:4433".to_string(),
            reserved_bind_addr: "127.0.0.1:7443".to_string(),
            tenant_count: 0,
        });

        let client_id = "client:test";
        create_event_synchronous(&conn, client_id, &event).unwrap();

        let state = client_lifecycle::load_state(&conn, client_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            state.runtime_status,
            client_lifecycle::ClientRuntimeStatus::IdleNoTenants
        );
        assert_eq!(state.reserved_bind_addr.as_deref(), Some("127.0.0.1:7443"));
    }

    #[test]
    fn client_idle_reserved_rejects_invalid_reserved_port() {
        let conn = setup();
        let event = ParsedEvent::ClientIdleReserved(ClientIdleReservedEvent {
            created_at_ms: 10,
            db_path: "/tmp/topo-idle.db".to_string(),
            configured_bind_addr: "127.0.0.1:4433".to_string(),
            reserved_bind_addr: "127.0.0.1:0".to_string(),
            tenant_count: 0,
        });

        let err = create_event_synchronous(&conn, "client:test", &event).unwrap_err();
        match err {
            CreateEventError::Rejected { reason, .. } => {
                assert!(reason.contains("reserved_bind_addr port must be non-zero"));
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }
}
