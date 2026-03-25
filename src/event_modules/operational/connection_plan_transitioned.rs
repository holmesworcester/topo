use rusqlite::Connection;

use super::super::layout::common::COMMON_HEADER_BYTES;
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{Describe, EventError, ParsedEvent, EVENT_TYPE_CONNECTION_PLAN_TRANSITIONED};
use super::connection_planned::{
    require_current_plan_basis, ConnectionPlanStatus, CONNECTION_ID_BYTES, CONNECTION_PLANNED_META,
};
use crate::db::open_connection;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::projection::create::CreateEventError;

pub const CONNECTION_TRANSITION_REASON_BYTES: usize = 128;
pub const CONNECTION_PLAN_TRANSITIONED_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + CONNECTION_ID_BYTES + 1 + 8 + CONNECTION_TRANSITION_REASON_BYTES;

mod connection_plan_transitioned_offsets {
    pub const CREATED_AT: usize = 1;
    pub const BASIS_EVENT_ID: usize = 9;
    pub const CONNECTION_ID: usize = BASIS_EVENT_ID + 32;
    pub const STATUS: usize = CONNECTION_ID + super::CONNECTION_ID_BYTES;
    pub const RETRY_AFTER_MS: usize = STATUS + 1;
    pub const REASON: usize = RETRY_AFTER_MS + 8;
}

use connection_plan_transitioned_offsets as off;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPlanTransitionedEvent {
    pub created_at_ms: u64,
    pub basis_event_id: [u8; 32],
    pub connection_id: String,
    pub new_status: ConnectionPlanStatus,
    pub retry_after_ms: u64,
    pub decision_reason: Option<String>,
}

impl Describe for ConnectionPlanTransitionedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "basis_event_id",
                super::super::short_id_b64(&self.basis_event_id),
            ),
            ("connection_id", self.connection_id.clone()),
            ("new_status", self.new_status.as_str().to_string()),
            ("retry_after_ms", self.retry_after_ms.to_string()),
        ];
        if let Some(reason) = &self.decision_reason {
            fields.push(("decision_reason", reason.clone()));
        }
        fields
    }
}

fn status_code(status: ConnectionPlanStatus) -> u8 {
    match status {
        ConnectionPlanStatus::Planned => 1,
        ConnectionPlanStatus::Deferred => 2,
        ConnectionPlanStatus::Active => 3,
        ConnectionPlanStatus::Superseded => 4,
        ConnectionPlanStatus::Finished => 5,
    }
}

fn status_from_code(code: u8) -> Option<ConnectionPlanStatus> {
    match code {
        1 => Some(ConnectionPlanStatus::Planned),
        2 => Some(ConnectionPlanStatus::Deferred),
        3 => Some(ConnectionPlanStatus::Active),
        4 => Some(ConnectionPlanStatus::Superseded),
        5 => Some(ConnectionPlanStatus::Finished),
        _ => None,
    }
}

pub fn ensure_schema(_conn: &Connection) -> rusqlite::Result<()> {
    Ok(())
}

pub fn parse_connection_plan_transitioned(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    super::common::expect_wire(
        blob,
        EVENT_TYPE_CONNECTION_PLAN_TRANSITIONED,
        CONNECTION_PLAN_TRANSITIONED_WIRE_SIZE,
    )?;

    let created_at_ms =
        super::common::read_created_at_ms(blob, off::CREATED_AT..off::BASIS_EVENT_ID);
    let basis_event_id =
        super::common::read_event_id(&blob[off::BASIS_EVENT_ID..off::CONNECTION_ID]);
    let connection_id = super::common::read_text(&blob[off::CONNECTION_ID..off::STATUS])?;
    let new_status = status_from_code(blob[off::STATUS]).ok_or(EventError::InvalidMetadata(
        "invalid connection plan status",
    ))?;
    let retry_after_ms = super::common::read_u64(&blob[off::RETRY_AFTER_MS..off::REASON]);
    let decision_reason = super::common::read_optional_text(
        &blob[off::REASON..off::REASON + CONNECTION_TRANSITION_REASON_BYTES],
    )?;

    Ok(ParsedEvent::ConnectionPlanTransitioned(
        ConnectionPlanTransitionedEvent {
            created_at_ms,
            basis_event_id,
            connection_id,
            new_status,
            retry_after_ms,
            decision_reason,
        },
    ))
}

pub fn encode_connection_plan_transitioned(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let transitioned = match event {
        ParsedEvent::ConnectionPlanTransitioned(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = super::common::fresh_blob(
        EVENT_TYPE_CONNECTION_PLAN_TRANSITIONED,
        CONNECTION_PLAN_TRANSITIONED_WIRE_SIZE,
        off::CREATED_AT..off::BASIS_EVENT_ID,
        transitioned.created_at_ms,
    );
    super::common::write_event_id(
        &mut buf[off::BASIS_EVENT_ID..off::CONNECTION_ID],
        &transitioned.basis_event_id,
    );
    super::common::write_text(
        &mut buf[off::CONNECTION_ID..off::STATUS],
        &transitioned.connection_id,
    )?;
    buf[off::STATUS] = status_code(transitioned.new_status);
    super::common::write_u64(
        &mut buf[off::RETRY_AFTER_MS..off::REASON],
        transitioned.retry_after_ms,
    );
    super::common::write_optional_text(
        &mut buf[off::REASON..off::REASON + CONNECTION_TRANSITION_REASON_BYTES],
        transitioned.decision_reason.as_deref(),
    )?;
    Ok(buf)
}

fn validate_transition(event: &ConnectionPlanTransitionedEvent) -> Result<(), String> {
    if event.connection_id.trim().is_empty() {
        return Err("connection_plan_transitioned requires non-empty connection_id".to_string());
    }
    if matches!(event.new_status, ConnectionPlanStatus::Planned) {
        return Err("connection_plan_transitioned may not transition back to planned".to_string());
    }
    Ok(())
}

pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let transitioned = match parsed {
        ParsedEvent::ConnectionPlanTransitioned(event) => event,
        _ => {
            return Err("connection_plan_transitioned context loader called for wrong event".into())
        }
    };

    super::common::build_connection_plan_basis_context(
        conn,
        recorded_by,
        &transitioned.basis_event_id,
        "connection_plan_transitioned",
    )
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let transitioned = match parsed {
        ParsedEvent::ConnectionPlanTransitioned(event) => event,
        _ => {
            return ProjectorResult::reject("not a connection_plan_transitioned event".to_string())
        }
    };

    if let Err(reason) = validate_transition(transitioned) {
        return ProjectorResult::reject(reason);
    }
    if let Some(reason) = &ctx.connection_plan_basis_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }
    let Some(snapshot) = &ctx.connection_plan_snapshot else {
        return ProjectorResult::reject(
            "connection_plan_transitioned missing connection plan snapshot context".to_string(),
        );
    };
    if snapshot.connection_id != transitioned.connection_id {
        return ProjectorResult::reject(
            "connection_plan_transitioned connection_id does not match basis snapshot".to_string(),
        );
    }

    let next_attempt_not_before_ms = match transitioned.new_status {
        ConnectionPlanStatus::Deferred => {
            Some((transitioned.created_at_ms + transitioned.retry_after_ms) as i64)
        }
        ConnectionPlanStatus::Active
        | ConnectionPlanStatus::Superseded
        | ConnectionPlanStatus::Finished => None,
        ConnectionPlanStatus::Planned => unreachable!(),
    };

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "connection_plan_history",
        columns: vec![
            "tenant_id",
            "event_id",
            "connection_id",
            "remote_peer_id",
            "remote_addr",
            "source_kind",
            "invite_event_id",
            "plan_status",
            "decision_reason",
            "basis_event_id",
            "next_attempt_not_before_ms",
            "created_at",
        ],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(snapshot.connection_id.clone()),
            SqlVal::Text(snapshot.remote_peer_id.clone()),
            SqlVal::Text(snapshot.remote_addr.clone()),
            SqlVal::Text(snapshot.source_kind.clone()),
            snapshot
                .invite_event_id
                .as_ref()
                .map(|invite| SqlVal::Text(invite.clone()))
                .unwrap_or(SqlVal::Null),
            SqlVal::Text(transitioned.new_status.as_str().to_string()),
            transitioned
                .decision_reason
                .as_ref()
                .map(|reason| SqlVal::Text(reason.clone()))
                .unwrap_or(SqlVal::Null),
            SqlVal::Text(snapshot.event_id.clone()),
            next_attempt_not_before_ms
                .map(SqlVal::Int)
                .unwrap_or(SqlVal::Null),
            SqlVal::Int(transitioned.created_at_ms as i64),
        ],
    }])
}

pub static CONNECTION_PLAN_TRANSITIONED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_CONNECTION_PLAN_TRANSITIONED,
    type_name: "connection_plan_transitioned",
    projection_table: "connection_plan_history",
    share_scope: ShareScope::Local,
    dep_fields: &["basis_event_id"],
    dep_field_type_codes: &[&[
        CONNECTION_PLANNED_META.type_code,
        EVENT_TYPE_CONNECTION_PLAN_TRANSITIONED,
    ]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_connection_plan_transitioned,
    encode: encode_connection_plan_transitioned,
    projector: project_pure,
    context_loader: build_projector_context,
};

pub fn create_connection_plan_transitioned(
    conn: &Connection,
    tenant_id: &str,
    basis_event_id: [u8; 32],
    connection_id: &str,
    new_status: ConnectionPlanStatus,
    decision_reason: Option<&str>,
    retry_after_ms: u64,
) -> Result<[u8; 32], crate::projection::create::CreateEventError> {
    let event = ParsedEvent::ConnectionPlanTransitioned(ConnectionPlanTransitionedEvent {
        created_at_ms: crate::db::queue::current_timestamp_ms() as u64,
        basis_event_id,
        connection_id: connection_id.to_string(),
        new_status,
        retry_after_ms,
        decision_reason: decision_reason.map(str::to_string),
    });
    crate::projection::create::create_event_synchronous(conn, tenant_id, &event)
}

pub fn record_connection_plan_transition(
    db_path: &str,
    connection_id: &str,
    new_status: ConnectionPlanStatus,
    decision_reason: Option<&str>,
    retry_after_ms: u64,
) -> Result<(), String> {
    let conn = open_connection(db_path).map_err(|e| e.to_string())?;
    let (tenant_id, basis_event_id) = require_current_plan_basis(&conn, connection_id)?;
    match create_connection_plan_transitioned(
        &conn,
        &tenant_id,
        basis_event_id,
        connection_id,
        new_status,
        decision_reason,
        retry_after_ms,
    ) {
        Ok(_) => Ok(()),
        Err(CreateEventError::Rejected { reason, .. }) => Err(reason),
        Err(CreateEventError::Blocked { .. }) => Err(format!(
            "connection plan transition blocked for {connection_id}"
        )),
        Err(err) => Err(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::event_modules::operational::connection_planned::{
        create_connection_planned, discovery_connection_id, load, load_due_effects,
        ConnectionPlanSourceKind,
    };
    use crate::projection::create::CreateEventError;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn create_transitioned_blocks_without_basis_event() {
        let conn = setup();
        let err = create_connection_plan_transitioned(
            &conn,
            "tenant-a",
            [0x11; 32],
            "tenant-a@peer:abc",
            ConnectionPlanStatus::Deferred,
            Some("missing_basis"),
            1000,
        )
        .unwrap_err();
        match err {
            CreateEventError::Blocked { .. } => {}
            other => panic!("expected blocked transition, got {other:?}"),
        }
    }

    #[test]
    fn create_transitioned_appends_deferred_snapshot() {
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
            ConnectionPlanStatus::Deferred,
            Some("policy_skipped_non_preferred_direction"),
            1000,
        )
        .unwrap();

        let row = load(&conn, &connection_id).unwrap().unwrap();
        assert_eq!(row.plan_status, ConnectionPlanStatus::Deferred);
        assert_eq!(
            row.decision_reason.as_deref(),
            Some("policy_skipped_non_preferred_direction")
        );
        assert!(row.next_attempt_not_before_ms.unwrap_or(0) >= row.created_at_ms);
        assert!(load_due_effects(&conn, 10).unwrap().is_empty());
    }

    #[test]
    fn create_transitioned_can_remove_due_work_via_active_status() {
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
            Some("connect_worker_spawned"),
            0,
        )
        .unwrap();

        let row = load(&conn, &connection_id).unwrap().unwrap();
        assert_eq!(row.plan_status, ConnectionPlanStatus::Active);
        assert_eq!(load_due_effects(&conn, 10).unwrap().len(), 0);
    }

    #[test]
    fn stale_transition_is_rejected() {
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

        let newer_event_id = create_connection_plan_transitioned(
            &conn,
            "tenant-a",
            plan_event_id,
            &connection_id,
            ConnectionPlanStatus::Deferred,
            Some("first"),
            0,
        )
        .unwrap();

        let err = create_connection_plan_transitioned(
            &conn,
            "tenant-a",
            plan_event_id,
            &connection_id,
            ConnectionPlanStatus::Active,
            Some("stale"),
            0,
        )
        .unwrap_err();
        match err {
            CreateEventError::Rejected { reason, .. } => {
                assert!(reason.contains("stale"));
            }
            other => panic!("expected stale rejection, got {other:?}"),
        }

        let row = load(&conn, &connection_id).unwrap().unwrap();
        assert_eq!(
            row.latest_event_id,
            crate::crypto::event_id_to_base64(&newer_event_id)
        );
    }
}
