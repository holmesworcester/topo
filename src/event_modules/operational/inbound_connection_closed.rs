use rusqlite::Connection;

use super::super::layout::common::{read_text_slot, write_text_slot, COMMON_HEADER_BYTES};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{Describe, EventError, ParsedEvent, EVENT_TYPE_INBOUND_CONNECTION_CLOSED};
use crate::db::open_connection;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::projection::create::{create_event_synchronous, CreateEventError};

pub const INBOUND_CLOSE_DETAIL_BYTES: usize = 160;
pub const INBOUND_CONNECTION_CLOSED_WIRE_SIZE: usize = COMMON_HEADER_BYTES
    + 32
    + super::inbound_connection_authenticated::INBOUND_CONNECTION_ID_BYTES
    + INBOUND_CLOSE_DETAIL_BYTES;

mod offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const BASIS_EVENT_ID: usize = 9;
    pub const CONNECTION_ID: usize = BASIS_EVENT_ID + 32;
    pub const DETAIL: usize =
        CONNECTION_ID
            + crate::event_modules::operational::inbound_connection_authenticated::INBOUND_CONNECTION_ID_BYTES;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundConnectionClosedEvent {
    pub created_at_ms: u64,
    pub basis_event_id: [u8; 32],
    pub connection_id: String,
    pub detail: Option<String>,
}

impl Describe for InboundConnectionClosedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "basis_event_id",
                super::super::short_id_b64(&self.basis_event_id),
            ),
            ("connection_id", self.connection_id.clone()),
        ];
        if let Some(detail) = &self.detail {
            fields.push(("detail", detail.clone()));
        }
        fields
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    super::inbound_connection_authenticated::ensure_schema(conn)
}

fn parse_optional_text(raw: String) -> Option<String> {
    if raw.is_empty() {
        None
    } else {
        Some(raw)
    }
}

pub fn parse_inbound_connection_closed(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < INBOUND_CONNECTION_CLOSED_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: INBOUND_CONNECTION_CLOSED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > INBOUND_CONNECTION_CLOSED_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: INBOUND_CONNECTION_CLOSED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[offsets::TYPE_CODE] != EVENT_TYPE_INBOUND_CONNECTION_CLOSED {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_INBOUND_CONNECTION_CLOSED,
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
    let connection_id = read_text_slot(&blob[offsets::CONNECTION_ID..offsets::DETAIL])
        .map_err(EventError::TextSlot)?;
    let detail = parse_optional_text(
        read_text_slot(&blob[offsets::DETAIL..]).map_err(EventError::TextSlot)?,
    );

    Ok(ParsedEvent::InboundConnectionClosed(
        InboundConnectionClosedEvent {
            created_at_ms,
            basis_event_id,
            connection_id,
            detail,
        },
    ))
}

pub fn encode_inbound_connection_closed(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let closed = match event {
        ParsedEvent::InboundConnectionClosed(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = vec![0u8; INBOUND_CONNECTION_CLOSED_WIRE_SIZE];
    buf[offsets::TYPE_CODE] = EVENT_TYPE_INBOUND_CONNECTION_CLOSED;
    buf[offsets::CREATED_AT..offsets::BASIS_EVENT_ID]
        .copy_from_slice(&closed.created_at_ms.to_le_bytes());
    buf[offsets::BASIS_EVENT_ID..offsets::CONNECTION_ID].copy_from_slice(&closed.basis_event_id);
    write_text_slot(
        &closed.connection_id,
        &mut buf[offsets::CONNECTION_ID..offsets::DETAIL],
    )
    .map_err(EventError::TextSlot)?;
    write_text_slot(
        closed.detail.as_deref().unwrap_or(""),
        &mut buf[offsets::DETAIL..],
    )
    .map_err(EventError::TextSlot)?;
    Ok(buf)
}

pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let closed = match parsed {
        ParsedEvent::InboundConnectionClosed(event) => event,
        _ => return Err("inbound_connection_closed context loader called for wrong event".into()),
    };

    super::common::build_inbound_connection_basis_context(
        conn,
        recorded_by,
        &closed.basis_event_id,
        "inbound_connection_closed",
    )
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let closed = match parsed {
        ParsedEvent::InboundConnectionClosed(event) => event,
        _ => return ProjectorResult::reject("not an inbound_connection_closed event".to_string()),
    };

    if closed.connection_id.trim().is_empty() {
        return ProjectorResult::reject(
            "inbound_connection_closed requires non-empty connection_id".to_string(),
        );
    }
    if let Some(reason) = &ctx.inbound_connection_basis_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }
    let Some(snapshot) = &ctx.inbound_connection_snapshot else {
        return ProjectorResult::reject(
            "inbound_connection_closed missing inbound connection snapshot context".to_string(),
        );
    };
    if snapshot.connection_id != closed.connection_id {
        return ProjectorResult::reject(
            "inbound_connection_closed connection_id does not match basis snapshot".to_string(),
        );
    }
    if snapshot.lifecycle_kind != "authenticated" {
        return ProjectorResult::reject(
            "inbound_connection_closed basis snapshot must be authenticated".to_string(),
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
            snapshot
                .tenant_id
                .as_ref()
                .map(|value| SqlVal::Text(value.clone()))
                .unwrap_or(SqlVal::Null),
            SqlVal::Text(closed.connection_id.clone()),
            SqlVal::Text("closed".to_string()),
            snapshot
                .requested_local_transport_peer_id
                .as_ref()
                .map(|value| SqlVal::Text(value.clone()))
                .unwrap_or(SqlVal::Null),
            SqlVal::Text(snapshot.remote_peer_id.clone()),
            SqlVal::Text(snapshot.remote_addr.clone()),
            SqlVal::Text(snapshot.event_id.clone()),
            SqlVal::Null,
            closed
                .detail
                .as_ref()
                .map(|value| SqlVal::Text(value.clone()))
                .unwrap_or(SqlVal::Null),
            SqlVal::Int(closed.created_at_ms as i64),
        ],
    }])
}

pub static INBOUND_CONNECTION_CLOSED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_INBOUND_CONNECTION_CLOSED,
    type_name: "inbound_connection_closed",
    projection_table: "inbound_connection_history",
    share_scope: ShareScope::Local,
    dep_fields: &["basis_event_id"],
    dep_field_type_codes: &[&[super::super::EVENT_TYPE_INBOUND_CONNECTION_AUTHENTICATED]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_inbound_connection_closed,
    encode: encode_inbound_connection_closed,
    projector: project_pure,
    context_loader: build_projector_context,
};

pub fn create_inbound_connection_closed(
    conn: &Connection,
    recorded_by: &str,
    basis_event_id: [u8; 32],
    connection_id: &str,
    detail: Option<&str>,
) -> Result<[u8; 32], CreateEventError> {
    let event = ParsedEvent::InboundConnectionClosed(InboundConnectionClosedEvent {
        created_at_ms: crate::db::queue::current_timestamp_ms() as u64,
        basis_event_id,
        connection_id: connection_id.to_string(),
        detail: detail.map(str::to_string),
    });
    create_event_synchronous(conn, recorded_by, &event)
}

pub fn record_inbound_connection_closed(
    db_path: &str,
    connection_id: &str,
    detail: Option<&str>,
) -> Result<bool, String> {
    let conn = open_connection(db_path).map_err(|e| e.to_string())?;
    let client_id = super::client_lifecycle::client_id_for_db_path(db_path);
    let Some(latest) =
        super::inbound_connection_authenticated::load(&conn, &client_id, connection_id)
            .map_err(|e| e.to_string())?
    else {
        return Ok(false);
    };
    if latest.lifecycle_kind != "authenticated" {
        return Ok(false);
    }
    let basis_event_id =
        crate::crypto::event_id_from_base64(&latest.latest_event_id).ok_or_else(|| {
            format!(
                "invalid inbound connection latest_event_id {}",
                latest.latest_event_id
            )
        })?;
    match create_inbound_connection_closed(&conn, &client_id, basis_event_id, connection_id, detail)
    {
        Ok(_) => Ok(true),
        Err(CreateEventError::Rejected { .. } | CreateEventError::Blocked { .. }) => Ok(false),
        Err(err) => Err(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::event_modules::operational::client_lifecycle::{mark_runtime_active, start_runtime};
    use crate::event_modules::operational::inbound_connection_authenticated::{
        create_inbound_connection_authenticated, inbound_connection_id,
    };
    use crate::projection::create::CreateEventError;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    fn authenticated_basis(conn: &Connection) -> (String, String, [u8; 32]) {
        let run = start_runtime(
            conn,
            "/tmp/topo.db",
            "127.0.0.1:7443".parse().unwrap(),
            Some("127.0.0.1:7443".parse().unwrap()),
            1,
        )
        .unwrap();
        mark_runtime_active(conn, &run, "127.0.0.1:7443".parse().unwrap(), 1).unwrap();
        let client_state =
            crate::event_modules::operational::client_lifecycle::load_state(conn, &run.client_id)
                .unwrap()
                .unwrap();
        let client_basis =
            crate::crypto::event_id_from_base64(&client_state.latest_event_id).unwrap();
        let connection_id = inbound_connection_id(&"b".repeat(64), &"a".repeat(64), 9);
        let authenticated_event_id = create_inbound_connection_authenticated(
            conn,
            &run.client_id,
            "tenant-a",
            client_basis,
            &connection_id,
            &"b".repeat(64),
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
        )
        .unwrap();
        (run.client_id, connection_id, authenticated_event_id)
    }

    #[test]
    fn closed_projects_history_row() {
        let conn = setup();
        let (client_id, connection_id, basis) = authenticated_basis(&conn);

        create_inbound_connection_closed(&conn, &client_id, basis, &connection_id, Some("done"))
            .unwrap();

        let history_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM inbound_connection_history
                 WHERE recorded_by = ?1 AND tenant_id = ?2 AND connection_id = ?3 AND lifecycle_kind = 'closed'",
                rusqlite::params![&client_id, "tenant-a", &connection_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(history_count, 1);
    }

    #[test]
    fn closed_rejects_stale_basis() {
        let conn = setup();
        let (client_id, connection_id, basis) = authenticated_basis(&conn);
        create_inbound_connection_closed(&conn, &client_id, basis, &connection_id, None).unwrap();

        let err = create_inbound_connection_closed(&conn, &client_id, basis, &connection_id, None)
            .unwrap_err();

        match err {
            CreateEventError::Rejected { reason, .. } => assert!(reason.contains("stale")),
            other => panic!("expected stale rejection, got {other:?}"),
        }
    }
}
