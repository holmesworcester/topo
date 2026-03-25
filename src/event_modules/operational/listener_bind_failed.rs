use rusqlite::Connection;

use super::super::layout::common::COMMON_HEADER_BYTES;
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{Describe, EventError, ParsedEvent, EVENT_TYPE_LISTENER_BIND_FAILED};
use super::client_started::CLIENT_SOCKET_ADDR_BYTES;
use super::common::{
    expect_wire, fresh_blob, read_created_at_ms, read_event_id, read_optional_text, read_text,
    write_event_id, write_optional_text, write_text,
};
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

pub const ERROR_KIND_BYTES: usize = 64;
pub const ERROR_DETAIL_BYTES: usize = 128;
pub const LISTENER_BIND_FAILED_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + CLIENT_SOCKET_ADDR_BYTES + ERROR_KIND_BYTES + ERROR_DETAIL_BYTES;

mod offsets {
    pub const CREATED_AT: usize = 1;
    pub const BASIS_EVENT_ID: usize = 9;
    pub const BIND_ADDR: usize = BASIS_EVENT_ID + 32;
    pub const ERROR_KIND: usize = BIND_ADDR + super::CLIENT_SOCKET_ADDR_BYTES;
    pub const DETAIL: usize = ERROR_KIND + super::ERROR_KIND_BYTES;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerBindFailedEvent {
    pub created_at_ms: u64,
    pub basis_event_id: [u8; 32],
    pub bind_addr: String,
    pub error_kind: String,
    pub detail: Option<String>,
}

impl Describe for ListenerBindFailedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "basis_event_id",
                super::super::short_id_b64(&self.basis_event_id),
            ),
            ("bind_addr", self.bind_addr.clone()),
            ("error_kind", self.error_kind.clone()),
        ];
        if let Some(detail) = &self.detail {
            fields.push(("detail", detail.clone()));
        }
        fields
    }
}

pub fn ensure_schema(_conn: &Connection) -> rusqlite::Result<()> {
    // Projects to client_runtime_history; schema owned by client_started.
    Ok(())
}

pub fn parse_listener_bind_failed(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    expect_wire(
        blob,
        EVENT_TYPE_LISTENER_BIND_FAILED,
        LISTENER_BIND_FAILED_WIRE_SIZE,
    )?;
    let created_at_ms = read_created_at_ms(blob, offsets::CREATED_AT..offsets::BASIS_EVENT_ID);
    let basis_event_id = read_event_id(&blob[offsets::BASIS_EVENT_ID..offsets::BIND_ADDR]);
    let bind_addr = read_text(&blob[offsets::BIND_ADDR..offsets::ERROR_KIND])?;
    let error_kind = read_text(&blob[offsets::ERROR_KIND..offsets::DETAIL])?;
    let detail =
        read_optional_text(&blob[offsets::DETAIL..offsets::DETAIL + ERROR_DETAIL_BYTES])?;

    Ok(ParsedEvent::ListenerBindFailed(ListenerBindFailedEvent {
        created_at_ms,
        basis_event_id,
        bind_addr,
        error_kind,
        detail,
    }))
}

pub fn encode_listener_bind_failed(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let failed = match event {
        ParsedEvent::ListenerBindFailed(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = fresh_blob(
        EVENT_TYPE_LISTENER_BIND_FAILED,
        LISTENER_BIND_FAILED_WIRE_SIZE,
        offsets::CREATED_AT..offsets::BASIS_EVENT_ID,
        failed.created_at_ms,
    );
    write_event_id(
        &mut buf[offsets::BASIS_EVENT_ID..offsets::BIND_ADDR],
        &failed.basis_event_id,
    );
    write_text(
        &mut buf[offsets::BIND_ADDR..offsets::ERROR_KIND],
        &failed.bind_addr,
    )?;
    write_text(
        &mut buf[offsets::ERROR_KIND..offsets::DETAIL],
        &failed.error_kind,
    )?;
    write_optional_text(
        &mut buf[offsets::DETAIL..offsets::DETAIL + ERROR_DETAIL_BYTES],
        failed.detail.as_deref(),
    )?;
    Ok(buf)
}

fn validate(event: &ListenerBindFailedEvent) -> Result<(), String> {
    if event
        .bind_addr
        .parse::<std::net::SocketAddr>()
        .is_err()
    {
        return Err(
            "listener_bind_failed bind_addr must be a valid socket address".to_string(),
        );
    }
    if event.error_kind.trim().is_empty() {
        return Err("listener_bind_failed requires non-empty error_kind".to_string());
    }
    Ok(())
}

pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let failed = match parsed {
        ParsedEvent::ListenerBindFailed(event) => event,
        _ => return Err("listener_bind_failed context loader called for wrong event".into()),
    };

    super::common::build_client_run_basis_context(
        conn,
        recorded_by,
        &failed.basis_event_id,
        "listener_bind_failed",
    )
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let failed = match parsed {
        ParsedEvent::ListenerBindFailed(event) => event,
        _ => return ProjectorResult::reject("not a listener_bind_failed event".to_string()),
    };

    if let Err(reason) = validate(failed) {
        return ProjectorResult::reject(reason);
    }
    if let Some(reason) = &ctx.client_runtime_basis_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }
    let Some(snapshot) = &ctx.client_runtime_snapshot else {
        return ProjectorResult::reject(
            "listener_bind_failed missing client runtime snapshot context".to_string(),
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
                SqlVal::Null, // listen_addr stays null — bind never succeeded
                SqlVal::Text("bind_failed".to_string()),
                SqlVal::Int(snapshot.tenant_count),
                SqlVal::Int(snapshot.started_at_ms),
                SqlVal::Null, // activated_at_ms
                SqlVal::Null, // stopped_at_ms
                SqlVal::Text(format!(
                    "{}: {}",
                    failed.error_kind,
                    failed.detail.as_deref().unwrap_or("")
                )),
                SqlVal::Text(snapshot.event_id.clone()),
                SqlVal::Int(failed.created_at_ms as i64),
            ],
        }],
        vec![EmitCommand::WakeClientRuntime {
            client_id: recorded_by.to_string(),
        }],
    )
}

pub static LISTENER_BIND_FAILED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_LISTENER_BIND_FAILED,
    type_name: "listener_bind_failed",
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
    parse: parse_listener_bind_failed,
    encode: encode_listener_bind_failed,
    projector: project_pure,
    context_loader: build_projector_context,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::event_id_from_base64;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::event_modules::operational::client_activated;
    use crate::event_modules::operational::client_lifecycle::{
        load_run, load_state, mark_runtime_active, start_runtime, ClientRuntimeStatus,
    };
    use crate::projection::create::{create_event_synchronous, CreateEventError};
    use std::net::SocketAddr;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new("127.0.0.1".parse().unwrap(), port)
    }

    #[test]
    fn bind_failed_projects_history_row() {
        let conn = setup();
        let db_path = "/tmp/topo-bind-fail.db";
        let run = start_runtime(&conn, db_path, addr(7000), Some(addr(7001)), 2).unwrap();

        // Get the basis event id (latest for this run)
        let run_row = load_run(&conn, &run.client_id, &run.run_id)
            .unwrap()
            .unwrap();
        let basis = event_id_from_base64(&run_row.latest_event_id).unwrap();

        let event = ParsedEvent::ListenerBindFailed(ListenerBindFailedEvent {
            created_at_ms: 100,
            basis_event_id: basis,
            bind_addr: "127.0.0.1:7000".to_string(),
            error_kind: "address_in_use".to_string(),
            detail: Some("os error 98".to_string()),
        });
        create_event_synchronous(&conn, &run.client_id, &event).unwrap();

        // Verify the history row was written with bind_failed status
        let state = load_state(&conn, &run.client_id).unwrap().unwrap();
        assert_eq!(
            state.runtime_status,
            ClientRuntimeStatus::BindFailed,
            "expected bind_failed status after listener bind failure"
        );

        // Verify history count: client_started + listener_bind_failed = 2
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM client_runtime_history WHERE client_id = ?1",
                rusqlite::params![run.client_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn bind_failed_rejects_stale_basis() {
        let conn = setup();
        let db_path = "/tmp/topo-bind-fail-stale.db";
        let run = start_runtime(&conn, db_path, addr(7000), Some(addr(7001)), 1).unwrap();

        // Activate the runtime to advance the basis
        mark_runtime_active(&conn, &run, addr(7443), 1).unwrap();

        // Try to record bind_failed with the stale started basis
        let stale_basis = event_id_from_base64(&run.run_id).unwrap();
        let event = ParsedEvent::ListenerBindFailed(ListenerBindFailedEvent {
            created_at_ms: 200,
            basis_event_id: stale_basis,
            bind_addr: "127.0.0.1:7000".to_string(),
            error_kind: "address_in_use".to_string(),
            detail: None,
        });
        let err = create_event_synchronous(&conn, &run.client_id, &event).unwrap_err();

        match err {
            CreateEventError::Rejected { reason, .. } => {
                assert!(reason.contains("stale"), "expected stale rejection: {reason}");
            }
            other => panic!("expected stale rejection, got {other:?}"),
        }
    }

    #[test]
    fn bind_failed_rejects_invalid_bind_addr() {
        let conn = setup();
        let db_path = "/tmp/topo-bind-fail-invalid.db";
        let run = start_runtime(&conn, db_path, addr(7000), Some(addr(7001)), 1).unwrap();

        let run_row = load_run(&conn, &run.client_id, &run.run_id)
            .unwrap()
            .unwrap();
        let basis = event_id_from_base64(&run_row.latest_event_id).unwrap();

        let event = ParsedEvent::ListenerBindFailed(ListenerBindFailedEvent {
            created_at_ms: 100,
            basis_event_id: basis,
            bind_addr: "not-a-socket-addr".to_string(),
            error_kind: "address_in_use".to_string(),
            detail: None,
        });
        let err = create_event_synchronous(&conn, &run.client_id, &event).unwrap_err();

        match err {
            CreateEventError::Rejected { reason, .. } => {
                assert!(reason.contains("socket address"));
            }
            other => panic!("expected validation rejection, got {other:?}"),
        }
    }

    #[test]
    fn bind_failed_rejects_empty_error_kind() {
        let conn = setup();
        let db_path = "/tmp/topo-bind-fail-empty.db";
        let run = start_runtime(&conn, db_path, addr(7000), Some(addr(7001)), 1).unwrap();

        let run_row = load_run(&conn, &run.client_id, &run.run_id)
            .unwrap()
            .unwrap();
        let basis = event_id_from_base64(&run_row.latest_event_id).unwrap();

        let event = ParsedEvent::ListenerBindFailed(ListenerBindFailedEvent {
            created_at_ms: 100,
            basis_event_id: basis,
            bind_addr: "127.0.0.1:7000".to_string(),
            error_kind: "".to_string(),
            detail: None,
        });
        let err = create_event_synchronous(&conn, &run.client_id, &event).unwrap_err();

        match err {
            CreateEventError::Rejected { reason, .. } => {
                assert!(reason.contains("non-empty error_kind"));
            }
            other => panic!("expected validation rejection, got {other:?}"),
        }
    }

    #[test]
    fn bind_failed_roundtrip_encode_parse() {
        let event = ListenerBindFailedEvent {
            created_at_ms: 12345,
            basis_event_id: [0xAB; 32],
            bind_addr: "127.0.0.1:7000".to_string(),
            error_kind: "address_in_use".to_string(),
            detail: Some("os error 98".to_string()),
        };
        let parsed = ParsedEvent::ListenerBindFailed(event.clone());
        let blob = encode_listener_bind_failed(&parsed).unwrap();
        assert_eq!(blob.len(), LISTENER_BIND_FAILED_WIRE_SIZE);
        let reparsed = parse_listener_bind_failed(&blob).unwrap();
        assert_eq!(reparsed, parsed);
    }

    #[test]
    fn bind_failed_then_retry_succeeds() {
        // E2E: client_started -> bind failure -> retry -> activation succeeds
        let conn = setup();
        let db_path = "/tmp/topo-bind-retry.db";
        let run = start_runtime(&conn, db_path, addr(7000), Some(addr(7001)), 1).unwrap();

        // Record bind failure
        let run_row = load_run(&conn, &run.client_id, &run.run_id)
            .unwrap()
            .unwrap();
        let basis = event_id_from_base64(&run_row.latest_event_id).unwrap();

        let bf_event = ParsedEvent::ListenerBindFailed(ListenerBindFailedEvent {
            created_at_ms: 100,
            basis_event_id: basis,
            bind_addr: "127.0.0.1:7000".to_string(),
            error_kind: "address_in_use".to_string(),
            detail: Some("EADDRINUSE".to_string()),
        });
        create_event_synchronous(&conn, &run.client_id, &bf_event).unwrap();

        let state = load_state(&conn, &run.client_id).unwrap().unwrap();
        assert_eq!(state.runtime_status, ClientRuntimeStatus::BindFailed);

        // Now the port is free; record activation from the bind_failed basis
        let run_row2 = load_run(&conn, &run.client_id, &run.run_id)
            .unwrap()
            .unwrap();
        let basis2 = event_id_from_base64(&run_row2.latest_event_id).unwrap();

        let act_event =
            ParsedEvent::ClientActivated(client_activated::ClientActivatedEvent {
                created_at_ms: 200,
                basis_event_id: basis2,
                listen_addr: "127.0.0.1:7443".to_string(),
                tenant_count: 1,
            });
        create_event_synchronous(&conn, &run.client_id, &act_event).unwrap();

        let state2 = load_state(&conn, &run.client_id).unwrap().unwrap();
        assert_eq!(state2.runtime_status, ClientRuntimeStatus::Active);
        assert_eq!(state2.listen_addr.as_deref(), Some("127.0.0.1:7443"));

        // History should have 3 entries: started, bind_failed, activated
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM client_runtime_history WHERE client_id = ?1",
                rusqlite::params![run.client_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);
    }
}
