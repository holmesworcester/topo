use std::net::SocketAddr;

use rusqlite::Connection;

use super::super::layout::field_spec::{decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{Describe, EventError, ParsedEvent, EVENT_TYPE_INBOUND_CONNECTION_REJECTED};
use crate::crypto::event_id_to_base64;
use crate::db::open_connection;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::projection::create::{create_event_synchronous, CreateEventError};

pub const INBOUND_REJECTION_KIND_BYTES: usize = 64;
pub const INBOUND_REJECTION_DETAIL_BYTES: usize = 160;
pub const INBOUND_CONNECTION_REJECTED_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("basis_event_id"),
    FieldSpec::Text("connection_id", super::inbound_connection_authenticated::INBOUND_CONNECTION_ID_BYTES),
    FieldSpec::OptionalText("tenant_id", super::inbound_connection_authenticated::INBOUND_TENANT_ID_BYTES),
    FieldSpec::OptionalText("requested_local_transport_peer_id", super::inbound_connection_authenticated::INBOUND_REQUESTED_LOCAL_PEER_ID_BYTES),
    FieldSpec::Text("remote_peer_id", super::inbound_connection_authenticated::INBOUND_REMOTE_PEER_ID_BYTES),
    FieldSpec::Text("remote_addr", super::inbound_connection_authenticated::INBOUND_REMOTE_ADDR_BYTES),
    FieldSpec::Text("rejection_kind", INBOUND_REJECTION_KIND_BYTES),
    FieldSpec::OptionalText("detail", INBOUND_REJECTION_DETAIL_BYTES),
];
pub const INBOUND_CONNECTION_REJECTED_WIRE_SIZE: usize = wire_size_for_fields(INBOUND_CONNECTION_REJECTED_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundConnectionRejectedEvent {
    pub created_at_ms: u64,
    pub basis_event_id: [u8; 32],
    pub connection_id: String,
    pub tenant_id: Option<String>,
    pub requested_local_transport_peer_id: Option<String>,
    pub remote_peer_id: String,
    pub remote_addr: String,
    pub rejection_kind: String,
    pub detail: Option<String>,
}

impl Describe for InboundConnectionRejectedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "basis_event_id",
                super::super::short_id_b64(&self.basis_event_id),
            ),
            ("connection_id", self.connection_id.clone()),
            ("remote_peer_id", self.remote_peer_id.clone()),
            ("remote_addr", self.remote_addr.clone()),
            ("rejection_kind", self.rejection_kind.clone()),
        ];
        if let Some(tenant_id) = &self.tenant_id {
            fields.push(("tenant_id", tenant_id.clone()));
        }
        if let Some(requested) = &self.requested_local_transport_peer_id {
            fields.push(("requested_local_transport_peer_id", requested.clone()));
        }
        if let Some(detail) = &self.detail {
            fields.push(("detail", detail.clone()));
        }
        fields
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    super::inbound_connection_authenticated::ensure_schema(conn)
}

pub fn parse_inbound_connection_rejected(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_INBOUND_CONNECTION_REJECTED, INBOUND_CONNECTION_REJECTED_FIELDS, blob)?;
    let created_at_ms = values[0].as_timestamp().unwrap();
    let basis_event_id = values[1].as_event_id().unwrap();
    let connection_id = values[2].as_text().unwrap().to_string();
    let tenant_id = values[3].as_optional_text().unwrap().map(str::to_string);
    let requested_local_transport_peer_id = values[4].as_optional_text().unwrap().map(str::to_string);
    let remote_peer_id = values[5].as_text().unwrap().to_string();
    let remote_addr = values[6].as_text().unwrap().to_string();
    let rejection_kind = values[7].as_text().unwrap().to_string();
    let detail = values[8].as_optional_text().unwrap().map(str::to_string);

    Ok(ParsedEvent::InboundConnectionRejected(
        InboundConnectionRejectedEvent {
            created_at_ms,
            basis_event_id,
            connection_id,
            tenant_id,
            requested_local_transport_peer_id,
            remote_peer_id,
            remote_addr,
            rejection_kind,
            detail,
        },
    ))
}
pub fn encode_inbound_connection_rejected(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let rejected = match event {
        ParsedEvent::InboundConnectionRejected(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(rejected.created_at_ms),
        FieldValue::EventId(rejected.basis_event_id),
        FieldValue::Text(rejected.connection_id.clone()),
        FieldValue::OptionalText(rejected.tenant_id.clone()),
        FieldValue::OptionalText(rejected.requested_local_transport_peer_id.clone()),
        FieldValue::Text(rejected.remote_peer_id.clone()),
        FieldValue::Text(rejected.remote_addr.clone()),
        FieldValue::Text(rejected.rejection_kind.clone()),
        FieldValue::OptionalText(rejected.detail.clone()),
    ];
    Ok(encode_fields(EVENT_TYPE_INBOUND_CONNECTION_REJECTED, INBOUND_CONNECTION_REJECTED_FIELDS, &values)?)
}
fn validate(event: &InboundConnectionRejectedEvent) -> Result<(), String> {
    if event.connection_id.trim().is_empty() {
        return Err("inbound_connection_rejected requires non-empty connection_id".to_string());
    }
    if event.remote_peer_id.trim().is_empty() {
        return Err("inbound_connection_rejected requires non-empty remote_peer_id".to_string());
    }
    let remote: SocketAddr = event.remote_addr.parse().map_err(|_| {
        "inbound_connection_rejected remote_addr must be a socket address".to_string()
    })?;
    if remote.port() == 0 {
        return Err("inbound_connection_rejected remote_addr port must be non-zero".to_string());
    }
    if event.rejection_kind.trim().is_empty() {
        return Err("inbound_connection_rejected requires non-empty rejection_kind".to_string());
    }
    Ok(())
}

pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let rejected = match parsed {
        ParsedEvent::InboundConnectionRejected(event) => event,
        _ => {
            return Err("inbound_connection_rejected context loader called for wrong event".into())
        }
    };

    super::common::build_client_state_basis_context(
        conn,
        recorded_by,
        &rejected.basis_event_id,
        "inbound_connection_rejected",
    )
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let rejected = match parsed {
        ParsedEvent::InboundConnectionRejected(event) => event,
        _ => {
            return ProjectorResult::reject("not an inbound_connection_rejected event".to_string())
        }
    };

    if let Err(reason) = validate(rejected) {
        return ProjectorResult::reject(reason);
    }
    if let Some(reason) = &ctx.client_runtime_basis_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }
    let Some(snapshot) = &ctx.client_runtime_snapshot else {
        return ProjectorResult::reject(
            "inbound_connection_rejected missing client runtime snapshot context".to_string(),
        );
    };
    if snapshot.runtime_status == "stopped" {
        return ProjectorResult::reject(
            "inbound_connection_rejected cannot project against stopped client runtime".to_string(),
        );
    }

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "inbound_connection_history",
        columns: vec![
            "recorded_by",
            "event_id",
            "tenant_id",
            "connection_id",
            "lifecycle_kind",
            "requested_local_transport_peer_id",
            "remote_peer_id",
            "remote_addr",
            "basis_event_id",
            "rejection_kind",
            "detail",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            rejected
                .tenant_id
                .as_ref()
                .map(|value| SqlVal::Text(value.clone()))
                .unwrap_or(SqlVal::Null),
            SqlVal::Text(rejected.connection_id.clone()),
            SqlVal::Text("rejected".to_string()),
            rejected
                .requested_local_transport_peer_id
                .as_ref()
                .map(|value| SqlVal::Text(value.clone()))
                .unwrap_or(SqlVal::Null),
            SqlVal::Text(rejected.remote_peer_id.clone()),
            SqlVal::Text(rejected.remote_addr.clone()),
            SqlVal::Text(event_id_to_base64(&rejected.basis_event_id)),
            SqlVal::Text(rejected.rejection_kind.clone()),
            rejected
                .detail
                .as_ref()
                .map(|value| SqlVal::Text(value.clone()))
                .unwrap_or(SqlVal::Null),
            SqlVal::Int(rejected.created_at_ms as i64),
        ],
    }])
}

pub static INBOUND_CONNECTION_REJECTED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_INBOUND_CONNECTION_REJECTED,
    type_name: "inbound_connection_rejected",
    projection_table: "inbound_connection_history",
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
    parse: parse_inbound_connection_rejected,
    encode: encode_inbound_connection_rejected,
    projector: project_pure,
    context_loader: build_projector_context,
};

pub fn create_inbound_connection_rejected(
    conn: &Connection,
    recorded_by: &str,
    basis_event_id: [u8; 32],
    connection_id: &str,
    tenant_id: Option<&str>,
    requested_local_transport_peer_id: Option<&str>,
    remote_peer_id: &str,
    remote_addr: SocketAddr,
    rejection_kind: &str,
    detail: Option<&str>,
) -> Result<[u8; 32], CreateEventError> {
    let event = ParsedEvent::InboundConnectionRejected(InboundConnectionRejectedEvent {
        created_at_ms: crate::db::queue::current_timestamp_ms() as u64,
        basis_event_id,
        connection_id: connection_id.to_string(),
        tenant_id: tenant_id.map(str::to_string),
        requested_local_transport_peer_id: requested_local_transport_peer_id.map(str::to_string),
        remote_peer_id: remote_peer_id.to_string(),
        remote_addr: remote_addr.to_string(),
        rejection_kind: rejection_kind.to_string(),
        detail: detail.map(str::to_string),
    });
    create_event_synchronous(conn, recorded_by, &event)
}

pub fn record_inbound_connection_rejected(
    db_path: &str,
    tenant_id: Option<&str>,
    connection_id: &str,
    requested_local_transport_peer_id: Option<&str>,
    remote_peer_id: &str,
    remote_addr: SocketAddr,
    rejection_kind: &str,
    detail: Option<&str>,
) -> Result<[u8; 32], String> {
    let conn = open_connection(db_path).map_err(|e| e.to_string())?;
    let client_id = super::client_lifecycle::client_id_for_db_path(db_path);
    let basis_event_id =
        super::client_lifecycle::require_current_basis_event_id(&conn, &client_id)?;
    create_inbound_connection_rejected(
        &conn,
        &client_id,
        basis_event_id,
        connection_id,
        tenant_id,
        requested_local_transport_peer_id,
        remote_peer_id,
        remote_addr,
        rejection_kind,
        detail,
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::event_modules::operational::client_lifecycle::{mark_runtime_active, start_runtime};
    use crate::projection::create::CreateEventError;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn rejected_projects_history_row() {
        let conn = setup();
        let run = start_runtime(
            &conn,
            "/tmp/topo.db",
            "127.0.0.1:7443".parse().unwrap(),
            Some("127.0.0.1:7443".parse().unwrap()),
            1,
        )
        .unwrap();
        mark_runtime_active(&conn, &run, "127.0.0.1:7443".parse().unwrap(), 1).unwrap();
        let state =
            crate::event_modules::operational::client_lifecycle::load_state(&conn, &run.client_id)
                .unwrap()
                .unwrap();
        let basis = crate::crypto::event_id_from_base64(&state.latest_event_id).unwrap();

        create_inbound_connection_rejected(
            &conn,
            &run.client_id,
            basis,
            "inbound:unknown:peer:1",
            None,
            None,
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
            "missing_sni",
            Some("missing exact target"),
        )
        .unwrap();

        let history_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM inbound_connection_history
                 WHERE recorded_by = ?1 AND lifecycle_kind = 'rejected'",
                rusqlite::params![&run.client_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(history_count, 1);
    }

    #[test]
    fn rejected_rejects_stale_basis() {
        let conn = setup();
        let run = start_runtime(
            &conn,
            "/tmp/topo.db",
            "127.0.0.1:7443".parse().unwrap(),
            Some("127.0.0.1:7443".parse().unwrap()),
            1,
        )
        .unwrap();
        let started_basis = crate::crypto::event_id_from_base64(&run.run_id).unwrap();
        mark_runtime_active(&conn, &run, "127.0.0.1:7443".parse().unwrap(), 1).unwrap();

        let err = create_inbound_connection_rejected(
            &conn,
            &run.client_id,
            started_basis,
            "inbound:unknown:peer:2",
            None,
            None,
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
            "missing_sni",
            None,
        )
        .unwrap_err();

        match err {
            CreateEventError::Rejected { reason, .. } => assert!(reason.contains("stale")),
            other => panic!("expected stale rejection, got {other:?}"),
        }
    }
}
