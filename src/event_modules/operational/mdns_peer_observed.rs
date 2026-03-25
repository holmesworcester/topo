use std::net::SocketAddr;

use rusqlite::Connection;

use super::super::layout::common::COMMON_HEADER_BYTES;
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{Describe, EventError, ParsedEvent, EVENT_TYPE_MDNS_PEER_OBSERVED};
use super::connection_planned::{emit_deterministic_connection_planned, ConnectionPlanSourceKind};
use crate::db::open_connection;
use crate::db::queue::current_timestamp_ms;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::projection::create::{create_event_synchronous, CreateEventError};

pub const MDNS_PEER_ID_BYTES: usize = 64;
pub const MDNS_ADDR_BYTES: usize = 96;
pub const MDNS_PEER_OBSERVED_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + MDNS_PEER_ID_BYTES + MDNS_ADDR_BYTES;

mod mdns_peer_observed_offsets {
    pub const CREATED_AT: usize = 1;
    pub const PEER_ID: usize = 9;
    pub const ADDR: usize = PEER_ID + super::MDNS_PEER_ID_BYTES;
}

use mdns_peer_observed_offsets as off;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsPeerObservedEvent {
    pub created_at_ms: u64,
    pub peer_id: String,
    pub addr: String,
}

impl Describe for MdnsPeerObservedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            ("peer_id", self.peer_id.clone()),
            ("addr", self.addr.clone()),
        ]
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS mdns_peer_observation_history (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            peer_id TEXT NOT NULL,
            addr TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_mdns_peer_observation_history_peer
            ON mdns_peer_observation_history(tenant_id, peer_id, created_at DESC, event_id DESC);
        ",
    )?;
    Ok(())
}

pub fn parse_mdns_peer_observed(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    super::common::expect_wire(
        blob,
        EVENT_TYPE_MDNS_PEER_OBSERVED,
        MDNS_PEER_OBSERVED_WIRE_SIZE,
    )?;

    let created_at_ms = super::common::read_created_at_ms(blob, off::CREATED_AT..off::PEER_ID);
    let peer_id = super::common::read_text(&blob[off::PEER_ID..off::ADDR])?;
    let addr = super::common::read_text(&blob[off::ADDR..off::ADDR + MDNS_ADDR_BYTES])?;

    Ok(ParsedEvent::MdnsPeerObserved(MdnsPeerObservedEvent {
        created_at_ms,
        peer_id,
        addr,
    }))
}

pub fn encode_mdns_peer_observed(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let observed = match event {
        ParsedEvent::MdnsPeerObserved(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = super::common::fresh_blob(
        EVENT_TYPE_MDNS_PEER_OBSERVED,
        MDNS_PEER_OBSERVED_WIRE_SIZE,
        off::CREATED_AT..off::PEER_ID,
        observed.created_at_ms,
    );
    super::common::write_text(&mut buf[off::PEER_ID..off::ADDR], &observed.peer_id)?;
    super::common::write_text(
        &mut buf[off::ADDR..off::ADDR + MDNS_ADDR_BYTES],
        &observed.addr,
    )?;
    Ok(buf)
}

fn validate(event: &MdnsPeerObservedEvent) -> Result<(), String> {
    if event.peer_id.trim().is_empty() {
        return Err("mdns_peer_observed requires non-empty peer_id".to_string());
    }
    let addr: SocketAddr = event
        .addr
        .parse()
        .map_err(|_| "mdns_peer_observed addr must be a socket address".to_string())?;
    if addr.port() == 0 {
        return Err("mdns_peer_observed addr port must be non-zero".to_string());
    }
    Ok(())
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let observed = match parsed {
        ParsedEvent::MdnsPeerObserved(event) => event,
        _ => return ProjectorResult::reject("not an mdns_peer_observed event".to_string()),
    };

    if let Err(reason) = validate(observed) {
        return ProjectorResult::reject(reason);
    }

    let addr = match observed.addr.parse() {
        Ok(addr) => addr,
        Err(err) => {
            return ProjectorResult::reject(format!(
                "mdns_peer_observed could not parse discovered addr {}: {err}",
                observed.addr
            ))
        }
    };
    let planned_command = match emit_deterministic_connection_planned(
        recorded_by,
        &observed.peer_id,
        addr,
        ConnectionPlanSourceKind::Discovery,
        None,
        observed.created_at_ms,
    ) {
        Ok(command) => command,
        Err(err) => {
            return ProjectorResult::reject(format!(
                "mdns_peer_observed could not encode connection_planned: {err}"
            ))
        }
    };

    ProjectorResult::valid_with_commands(
        vec![WriteOp::InsertOrIgnore {
            table: "mdns_peer_observation_history",
            columns: vec!["tenant_id", "event_id", "peer_id", "addr", "created_at"],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(observed.peer_id.clone()),
                SqlVal::Text(observed.addr.clone()),
                SqlVal::Int(observed.created_at_ms as i64),
            ],
        }],
        vec![planned_command],
    )
}

pub static MDNS_PEER_OBSERVED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_MDNS_PEER_OBSERVED,
    type_name: "mdns_peer_observed",
    projection_table: "mdns_peer_observation_history",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_mdns_peer_observed,
    encode: encode_mdns_peer_observed,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

pub fn create_mdns_peer_observed(
    conn: &Connection,
    tenant_id: &str,
    peer_id: &str,
    addr: SocketAddr,
) -> Result<[u8; 32], CreateEventError> {
    let event = ParsedEvent::MdnsPeerObserved(MdnsPeerObservedEvent {
        created_at_ms: current_timestamp_ms() as u64,
        peer_id: peer_id.to_string(),
        addr: addr.to_string(),
    });
    create_event_synchronous(conn, tenant_id, &event)
}

pub fn record_mdns_peer_observed(
    db_path: &str,
    tenant_id: &str,
    peer_id: &str,
    addr: SocketAddr,
) -> Result<[u8; 32], String> {
    let conn = open_connection(db_path).map_err(|e| e.to_string())?;
    create_mdns_peer_observed(&conn, tenant_id, peer_id, addr).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::event_modules::operational::connection_planned::{
        discovery_connection_id, load, ConnectionPlanStatus,
    };
    use crate::projection::create::CreateEventError;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn mdns_peer_observed_projects_history_and_emits_connection_plan() {
        let conn = setup();
        create_mdns_peer_observed(
            &conn,
            "tenant-a",
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
        )
        .unwrap();

        let mdns_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM mdns_peer_observation_history WHERE tenant_id = ?1",
                rusqlite::params!["tenant-a"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(mdns_count, 1);

        let plan = load(&conn, &discovery_connection_id("tenant-a", &"a".repeat(64)))
            .unwrap()
            .unwrap();
        assert_eq!(plan.plan_status, ConnectionPlanStatus::Planned);
    }

    #[test]
    fn mdns_peer_observed_rejects_invalid_addr() {
        let conn = setup();
        let event = ParsedEvent::MdnsPeerObserved(MdnsPeerObservedEvent {
            created_at_ms: 10,
            peer_id: "a".repeat(64),
            addr: "127.0.0.1:0".to_string(),
        });
        let err = create_event_synchronous(&conn, "tenant-a", &event).unwrap_err();
        match err {
            CreateEventError::Rejected { reason, .. } => {
                assert!(reason.contains("port must be non-zero"));
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }
}
