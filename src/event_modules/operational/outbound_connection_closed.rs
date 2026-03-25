use std::net::SocketAddr;

use rusqlite::Connection;

use super::super::layout::common::{read_text_slot, write_text_slot, COMMON_HEADER_BYTES};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{
    Describe, EventError, ParsedEvent, EVENT_TYPE_CONNECTION_PLAN_TRANSITIONED,
    EVENT_TYPE_OUTBOUND_CONNECTION_CLOSED,
};
use super::connection_planned::{
    require_current_plan_basis, CONNECTION_ID_BYTES, CONNECTION_PLANNED_META,
};
use crate::db::open_connection;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::projection::create::{create_event_synchronous, CreateEventError};

pub const CLOSE_REASON_BYTES: usize = 128;
pub const OUTBOUND_REMOTE_PEER_ID_BYTES: usize = 64;
pub const OUTBOUND_REMOTE_ADDR_BYTES: usize = 96;
pub const OUTBOUND_CONNECTION_CLOSED_WIRE_SIZE: usize = COMMON_HEADER_BYTES
    + 32
    + CONNECTION_ID_BYTES
    + OUTBOUND_REMOTE_PEER_ID_BYTES
    + OUTBOUND_REMOTE_ADDR_BYTES
    + CLOSE_REASON_BYTES;

mod offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const BASIS_EVENT_ID: usize = 9;
    pub const CONNECTION_ID: usize = BASIS_EVENT_ID + 32;
    pub const REMOTE_PEER_ID: usize = CONNECTION_ID + super::CONNECTION_ID_BYTES;
    pub const REMOTE_ADDR: usize = REMOTE_PEER_ID + super::OUTBOUND_REMOTE_PEER_ID_BYTES;
    pub const CLOSE_REASON: usize = REMOTE_ADDR + super::OUTBOUND_REMOTE_ADDR_BYTES;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundConnectionClosedEvent {
    pub created_at_ms: u64,
    pub basis_event_id: [u8; 32],
    pub connection_id: String,
    pub remote_peer_id: String,
    pub remote_addr: String,
    pub close_reason: String,
}

impl Describe for OutboundConnectionClosedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "basis_event_id",
                super::super::short_id_b64(&self.basis_event_id),
            ),
            ("connection_id", self.connection_id.clone()),
            ("remote_peer_id", self.remote_peer_id.clone()),
            ("remote_addr", self.remote_addr.clone()),
            ("close_reason", self.close_reason.clone()),
        ]
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    super::outbound_connection_authenticated::ensure_schema(conn)
}

pub fn parse_outbound_connection_closed(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < OUTBOUND_CONNECTION_CLOSED_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: OUTBOUND_CONNECTION_CLOSED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > OUTBOUND_CONNECTION_CLOSED_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: OUTBOUND_CONNECTION_CLOSED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[offsets::TYPE_CODE] != EVENT_TYPE_OUTBOUND_CONNECTION_CLOSED {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_OUTBOUND_CONNECTION_CLOSED,
            actual: blob[offsets::TYPE_CODE],
        });
    }

    let created_at_ms = u64::from_le_bytes(
        blob[offsets::CREATED_AT..offsets::BASIS_EVENT_ID]
            .try_into()
            .unwrap(),
    );
    let mut basis_event_id = [0u8; 32];
    basis_event_id.copy_from_slice(&blob[offsets::BASIS_EVENT_ID..offsets::CONNECTION_ID]);
    let connection_id = read_text_slot(&blob[offsets::CONNECTION_ID..offsets::REMOTE_PEER_ID])
        .map_err(EventError::TextSlot)?;
    let remote_peer_id = read_text_slot(&blob[offsets::REMOTE_PEER_ID..offsets::REMOTE_ADDR])
        .map_err(EventError::TextSlot)?;
    let remote_addr = read_text_slot(&blob[offsets::REMOTE_ADDR..offsets::CLOSE_REASON])
        .map_err(EventError::TextSlot)?;
    let close_reason =
        read_text_slot(&blob[offsets::CLOSE_REASON..offsets::CLOSE_REASON + CLOSE_REASON_BYTES])
            .map_err(EventError::TextSlot)?;

    Ok(ParsedEvent::OutboundConnectionClosed(
        OutboundConnectionClosedEvent {
            created_at_ms,
            basis_event_id,
            connection_id,
            remote_peer_id,
            remote_addr,
            close_reason,
        },
    ))
}

pub fn encode_outbound_connection_closed(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let closed = match event {
        ParsedEvent::OutboundConnectionClosed(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = vec![0u8; OUTBOUND_CONNECTION_CLOSED_WIRE_SIZE];
    buf[offsets::TYPE_CODE] = EVENT_TYPE_OUTBOUND_CONNECTION_CLOSED;
    buf[offsets::CREATED_AT..offsets::BASIS_EVENT_ID]
        .copy_from_slice(&closed.created_at_ms.to_le_bytes());
    buf[offsets::BASIS_EVENT_ID..offsets::CONNECTION_ID].copy_from_slice(&closed.basis_event_id);
    write_text_slot(
        &closed.connection_id,
        &mut buf[offsets::CONNECTION_ID..offsets::REMOTE_PEER_ID],
    )
    .map_err(EventError::TextSlot)?;
    write_text_slot(
        &closed.remote_peer_id,
        &mut buf[offsets::REMOTE_PEER_ID..offsets::REMOTE_ADDR],
    )
    .map_err(EventError::TextSlot)?;
    write_text_slot(
        &closed.remote_addr,
        &mut buf[offsets::REMOTE_ADDR..offsets::CLOSE_REASON],
    )
    .map_err(EventError::TextSlot)?;
    write_text_slot(
        &closed.close_reason,
        &mut buf[offsets::CLOSE_REASON..offsets::CLOSE_REASON + CLOSE_REASON_BYTES],
    )
    .map_err(EventError::TextSlot)?;
    Ok(buf)
}

fn validate(event: &OutboundConnectionClosedEvent) -> Result<(), String> {
    if event.connection_id.trim().is_empty() {
        return Err("outbound_connection_closed requires non-empty connection_id".to_string());
    }
    if event.remote_peer_id.trim().is_empty() {
        return Err("outbound_connection_closed requires non-empty remote_peer_id".to_string());
    }
    let remote: SocketAddr = event.remote_addr.parse().map_err(|_| {
        "outbound_connection_closed remote_addr must be a socket address".to_string()
    })?;
    if remote.port() == 0 {
        return Err("outbound_connection_closed remote_addr port must be non-zero".to_string());
    }
    if event.close_reason.trim().is_empty() {
        return Err("outbound_connection_closed requires non-empty close_reason".to_string());
    }
    Ok(())
}

pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let closed = match parsed {
        ParsedEvent::OutboundConnectionClosed(event) => event,
        _ => return Err("outbound_connection_closed context loader called for wrong event".into()),
    };

    super::common::build_connection_plan_basis_context(
        conn,
        recorded_by,
        &closed.basis_event_id,
        "outbound_connection_closed",
    )
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let closed = match parsed {
        ParsedEvent::OutboundConnectionClosed(event) => event,
        _ => return ProjectorResult::reject("not an outbound_connection_closed event".to_string()),
    };

    if let Err(reason) = validate(closed) {
        return ProjectorResult::reject(reason);
    }
    if let Some(reason) = &ctx.connection_plan_basis_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }
    let Some(snapshot) = &ctx.connection_plan_snapshot else {
        return ProjectorResult::reject(
            "outbound_connection_closed missing connection plan snapshot context".to_string(),
        );
    };
    if snapshot.connection_id != closed.connection_id {
        return ProjectorResult::reject(
            "outbound_connection_closed connection_id does not match basis snapshot".to_string(),
        );
    }

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "outbound_connection_history",
        columns: vec![
            "tenant_id",
            "event_id",
            "connection_id",
            "lifecycle_kind",
            "remote_peer_id",
            "remote_addr",
            "basis_event_id",
            "used_bootstrap_fallback",
            "failure_kind",
            "detail",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(closed.connection_id.clone()),
            SqlVal::Text("closed".to_string()),
            SqlVal::Text(closed.remote_peer_id.clone()),
            SqlVal::Text(closed.remote_addr.clone()),
            SqlVal::Text(snapshot.event_id.clone()),
            SqlVal::Int(0),
            SqlVal::Null,
            SqlVal::Text(closed.close_reason.clone()),
            SqlVal::Int(closed.created_at_ms as i64),
        ],
    }])
}

pub static OUTBOUND_CONNECTION_CLOSED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_OUTBOUND_CONNECTION_CLOSED,
    type_name: "outbound_connection_closed",
    projection_table: "outbound_connection_history",
    share_scope: ShareScope::Local,
    dep_fields: &["basis_event_id"],
    dep_field_type_codes: &[&[
        CONNECTION_PLANNED_META.type_code,
        EVENT_TYPE_CONNECTION_PLAN_TRANSITIONED,
    ]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_outbound_connection_closed,
    encode: encode_outbound_connection_closed,
    projector: project_pure,
    context_loader: build_projector_context,
};

pub fn create_outbound_connection_closed(
    conn: &Connection,
    tenant_id: &str,
    basis_event_id: [u8; 32],
    connection_id: &str,
    remote_peer_id: &str,
    remote_addr: SocketAddr,
    close_reason: &str,
) -> Result<[u8; 32], CreateEventError> {
    let event = ParsedEvent::OutboundConnectionClosed(OutboundConnectionClosedEvent {
        created_at_ms: crate::db::queue::current_timestamp_ms() as u64,
        basis_event_id,
        connection_id: connection_id.to_string(),
        remote_peer_id: remote_peer_id.to_string(),
        remote_addr: remote_addr.to_string(),
        close_reason: close_reason.to_string(),
    });
    create_event_synchronous(conn, tenant_id, &event)
}

pub fn record_outbound_connection_closed(
    db_path: &str,
    connection_id: &str,
    remote_peer_id: &str,
    remote_addr: SocketAddr,
    close_reason: &str,
) -> Result<[u8; 32], String> {
    let conn = open_connection(db_path).map_err(|e| e.to_string())?;
    let (tenant_id, basis_event_id) = require_current_plan_basis(&conn, connection_id)?;
    create_outbound_connection_closed(
        &conn,
        &tenant_id,
        basis_event_id,
        connection_id,
        remote_peer_id,
        remote_addr,
        close_reason,
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::event_modules::operational::connection_plan_transitioned::create_connection_plan_transitioned;
    use crate::event_modules::operational::connection_planned::{
        create_connection_planned, discovery_connection_id, ConnectionPlanSourceKind,
        ConnectionPlanStatus,
    };
    use crate::projection::create::CreateEventError;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn closed_projects_history_row() {
        let conn = setup();
        let plan_event_id = create_connection_planned(
            &conn,
            "tenant-a",
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
            ConnectionPlanSourceKind::Discovery,
            None,
        )
        .unwrap()
        .unwrap();
        let connection_id = discovery_connection_id("tenant-a", &"a".repeat(64));
        create_connection_plan_transitioned(
            &conn,
            "tenant-a",
            plan_event_id,
            &connection_id,
            ConnectionPlanStatus::Active,
            Some("spawned"),
            0,
        )
        .unwrap();
        let active_basis =
            crate::event_modules::operational::connection_planned::load(&conn, &connection_id)
                .unwrap()
                .unwrap();
        let basis = crate::crypto::event_id_from_base64(&active_basis.latest_event_id).unwrap();

        create_outbound_connection_closed(
            &conn,
            "tenant-a",
            basis,
            &connection_id,
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
            "session_ended",
        )
        .unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbound_connection_history
                 WHERE tenant_id = ?1 AND connection_id = ?2 AND lifecycle_kind = 'closed'",
                rusqlite::params!["tenant-a", &connection_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn closed_rejects_stale_basis() {
        let conn = setup();
        let plan_event_id = create_connection_planned(
            &conn,
            "tenant-a",
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
            ConnectionPlanSourceKind::Discovery,
            None,
        )
        .unwrap()
        .unwrap();
        let connection_id = discovery_connection_id("tenant-a", &"a".repeat(64));
        create_connection_plan_transitioned(
            &conn,
            "tenant-a",
            plan_event_id,
            &connection_id,
            ConnectionPlanStatus::Active,
            Some("spawned"),
            0,
        )
        .unwrap();

        let err = create_outbound_connection_closed(
            &conn,
            "tenant-a",
            plan_event_id,
            &connection_id,
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
            "session_ended",
        )
        .unwrap_err();

        match err {
            CreateEventError::Rejected { reason, .. } => assert!(reason.contains("stale")),
            other => panic!("expected stale rejection, got {other:?}"),
        }
    }
}
