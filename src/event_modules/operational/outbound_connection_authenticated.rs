use std::net::SocketAddr;

use rusqlite::Connection;

use super::super::layout::field_spec::{decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{
    Describe, EventError, ParsedEvent, EVENT_TYPE_CONNECTION_PLAN_TRANSITIONED,
    EVENT_TYPE_OUTBOUND_CONNECTION_AUTHENTICATED,
};
use super::connection_planned::{
    require_current_plan_basis, CONNECTION_ID_BYTES, CONNECTION_PLANNED_META,
};
use crate::db::open_connection;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::projection::create::{create_event_synchronous, CreateEventError};

const OUTBOUND_CONNECTION_ENDPOINT_TTL_MS: i64 = 24 * 60 * 60 * 1000;
pub const OUTBOUND_REMOTE_PEER_ID_BYTES: usize = 64;
pub const OUTBOUND_REMOTE_ADDR_BYTES: usize = 96;
pub const OUTBOUND_CONNECTION_AUTHENTICATED_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("basis_event_id"),
    FieldSpec::Text("connection_id", CONNECTION_ID_BYTES),
    FieldSpec::Text("remote_peer_id", OUTBOUND_REMOTE_PEER_ID_BYTES),
    FieldSpec::Text("remote_addr", OUTBOUND_REMOTE_ADDR_BYTES),
    FieldSpec::Bool("used_bootstrap_fallback"),
];
pub const OUTBOUND_CONNECTION_AUTHENTICATED_WIRE_SIZE: usize = wire_size_for_fields(OUTBOUND_CONNECTION_AUTHENTICATED_FIELDS);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundConnectionAuthenticatedEvent {
    pub created_at_ms: u64,
    pub basis_event_id: [u8; 32],
    pub connection_id: String,
    pub remote_peer_id: String,
    pub remote_addr: String,
    pub used_bootstrap_fallback: bool,
}

impl Describe for OutboundConnectionAuthenticatedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "basis_event_id",
                super::super::short_id_b64(&self.basis_event_id),
            ),
            ("connection_id", self.connection_id.clone()),
            ("remote_peer_id", self.remote_peer_id.clone()),
            ("remote_addr", self.remote_addr.clone()),
            (
                "used_bootstrap_fallback",
                self.used_bootstrap_fallback.to_string(),
            ),
        ]
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS outbound_connection_history (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            lifecycle_kind TEXT NOT NULL,
            remote_peer_id TEXT NOT NULL,
            remote_addr TEXT NOT NULL,
            basis_event_id TEXT NOT NULL,
            used_bootstrap_fallback INTEGER NOT NULL DEFAULT 0,
            failure_kind TEXT,
            detail TEXT,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_outbound_connection_history_latest
            ON outbound_connection_history(tenant_id, connection_id, created_at DESC, event_id DESC);
        ",
    )?;
    Ok(())
}

pub fn parse_outbound_connection_authenticated(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    let values = decode_fields(EVENT_TYPE_OUTBOUND_CONNECTION_AUTHENTICATED, OUTBOUND_CONNECTION_AUTHENTICATED_FIELDS, blob)?;
    let created_at_ms = values[0].as_timestamp().unwrap();
    let basis_event_id = values[1].as_event_id().unwrap();
    let connection_id = values[2].as_text().unwrap().to_string();
    let remote_peer_id = values[3].as_text().unwrap().to_string();
    let remote_addr = values[4].as_text().unwrap().to_string();
    let used_bootstrap_fallback = values[5].as_bool().unwrap();

    Ok(ParsedEvent::OutboundConnectionAuthenticated(
        OutboundConnectionAuthenticatedEvent {
            created_at_ms,
            basis_event_id,
            connection_id,
            remote_peer_id,
            remote_addr,
            used_bootstrap_fallback,
        },
    ))
}

pub fn encode_outbound_connection_authenticated(
    event: &ParsedEvent,
) -> Result<Vec<u8>, EventError> {
    let authenticated = match event {
        ParsedEvent::OutboundConnectionAuthenticated(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let values = vec![
        FieldValue::Timestamp(authenticated.created_at_ms),
        FieldValue::EventId(authenticated.basis_event_id),
        FieldValue::Text(authenticated.connection_id.clone()),
        FieldValue::Text(authenticated.remote_peer_id.clone()),
        FieldValue::Text(authenticated.remote_addr.clone()),
        FieldValue::Bool(authenticated.used_bootstrap_fallback),
    ];
    Ok(encode_fields(EVENT_TYPE_OUTBOUND_CONNECTION_AUTHENTICATED, OUTBOUND_CONNECTION_AUTHENTICATED_FIELDS, &values)?)
}

fn validate(event: &OutboundConnectionAuthenticatedEvent) -> Result<[u8; 32], String> {
    if event.connection_id.trim().is_empty() {
        return Err(
            "outbound_connection_authenticated requires non-empty connection_id".to_string(),
        );
    }
    if event.remote_peer_id.trim().is_empty() {
        return Err(
            "outbound_connection_authenticated requires non-empty remote_peer_id".to_string(),
        );
    }
    let remote: SocketAddr = event.remote_addr.parse().map_err(|_| {
        "outbound_connection_authenticated remote_addr must be a socket address".to_string()
    })?;
    if remote.port() == 0 {
        return Err(
            "outbound_connection_authenticated remote_addr port must be non-zero".to_string(),
        );
    }
    let decoded = hex::decode(&event.remote_peer_id)
        .map_err(|_| "outbound_connection_authenticated remote_peer_id must be hex".to_string())?;
    if decoded.len() != 32 {
        return Err(
            "outbound_connection_authenticated remote_peer_id must decode to 32 bytes".to_string(),
        );
    }
    let mut spki = [0u8; 32];
    spki.copy_from_slice(&decoded);
    Ok(spki)
}

pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let authenticated = match parsed {
        ParsedEvent::OutboundConnectionAuthenticated(event) => event,
        _ => {
            return Err(
                "outbound_connection_authenticated context loader called for wrong event".into(),
            )
        }
    };

    super::common::build_connection_plan_basis_context(
        conn,
        recorded_by,
        &authenticated.basis_event_id,
        "outbound_connection_authenticated",
    )
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let authenticated = match parsed {
        ParsedEvent::OutboundConnectionAuthenticated(event) => event,
        _ => {
            return ProjectorResult::reject(
                "not an outbound_connection_authenticated event".to_string(),
            )
        }
    };

    let spki = match validate(authenticated) {
        Ok(spki) => spki,
        Err(reason) => return ProjectorResult::reject(reason),
    };
    if let Some(reason) = &ctx.connection_plan_basis_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }
    let Some(snapshot) = &ctx.connection_plan_snapshot else {
        return ProjectorResult::reject(
            "outbound_connection_authenticated missing connection plan snapshot context"
                .to_string(),
        );
    };
    if snapshot.connection_id != authenticated.connection_id {
        return ProjectorResult::reject(
            "outbound_connection_authenticated connection_id does not match basis snapshot"
                .to_string(),
        );
    }
    let remote: SocketAddr = authenticated.remote_addr.parse().unwrap();

    ProjectorResult::valid(vec![
        WriteOp::InsertOrIgnore {
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
                SqlVal::Text(authenticated.connection_id.clone()),
                SqlVal::Text("authenticated".to_string()),
                SqlVal::Text(authenticated.remote_peer_id.clone()),
                SqlVal::Text(authenticated.remote_addr.clone()),
                SqlVal::Text(snapshot.event_id.clone()),
                SqlVal::Int(authenticated.used_bootstrap_fallback as i64),
                SqlVal::Null,
                SqlVal::Null,
                SqlVal::Int(authenticated.created_at_ms as i64),
            ],
        },
        WriteOp::InsertOrIgnore {
            table: "peer_endpoint_observations",
            columns: vec![
                "recorded_by",
                "via_peer_id",
                "origin_ip",
                "origin_port",
                "observed_at",
                "expires_at",
            ],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(authenticated.remote_peer_id.clone()),
                SqlVal::Text(remote.ip().to_string()),
                SqlVal::Int(remote.port() as i64),
                SqlVal::Int(authenticated.created_at_ms as i64),
                SqlVal::Int(
                    authenticated.created_at_ms as i64 + OUTBOUND_CONNECTION_ENDPOINT_TTL_MS,
                ),
            ],
        },
        WriteOp::InsertOrIgnore {
            table: "peer_transport_bindings",
            columns: vec!["recorded_by", "peer_id", "spki_fingerprint", "bound_at"],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(authenticated.remote_peer_id.clone()),
                SqlVal::Blob(spki.to_vec()),
                SqlVal::Int(authenticated.created_at_ms as i64),
            ],
        },
    ])
}

pub static OUTBOUND_CONNECTION_AUTHENTICATED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_OUTBOUND_CONNECTION_AUTHENTICATED,
    type_name: "outbound_connection_authenticated",
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
    parse: parse_outbound_connection_authenticated,
    encode: encode_outbound_connection_authenticated,
    projector: project_pure,
    context_loader: build_projector_context,
};

pub fn create_outbound_connection_authenticated(
    conn: &Connection,
    tenant_id: &str,
    basis_event_id: [u8; 32],
    connection_id: &str,
    remote_peer_id: &str,
    remote_addr: SocketAddr,
    used_bootstrap_fallback: bool,
) -> Result<[u8; 32], CreateEventError> {
    let event =
        ParsedEvent::OutboundConnectionAuthenticated(OutboundConnectionAuthenticatedEvent {
            created_at_ms: crate::db::queue::current_timestamp_ms() as u64,
            basis_event_id,
            connection_id: connection_id.to_string(),
            remote_peer_id: remote_peer_id.to_string(),
            remote_addr: remote_addr.to_string(),
            used_bootstrap_fallback,
        });
    create_event_synchronous(conn, tenant_id, &event)
}

pub fn record_outbound_connection_authenticated(
    db_path: &str,
    connection_id: &str,
    remote_peer_id: &str,
    remote_addr: SocketAddr,
    used_bootstrap_fallback: bool,
) -> Result<[u8; 32], String> {
    let conn = open_connection(db_path).map_err(|e| e.to_string())?;
    let (tenant_id, basis_event_id) = require_current_plan_basis(&conn, connection_id)?;
    create_outbound_connection_authenticated(
        &conn,
        &tenant_id,
        basis_event_id,
        connection_id,
        remote_peer_id,
        remote_addr,
        used_bootstrap_fallback,
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_connection;
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
    fn authenticated_projects_connection_history_and_endpoint_rows() {
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

        create_outbound_connection_authenticated(
            &conn,
            "tenant-a",
            basis,
            &connection_id,
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
            true,
        )
        .unwrap();

        let history_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbound_connection_history
                 WHERE tenant_id = ?1 AND connection_id = ?2 AND lifecycle_kind = 'authenticated'",
                rusqlite::params!["tenant-a", &connection_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(history_count, 1);

        let endpoint_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM peer_endpoint_observations
                 WHERE recorded_by = ?1 AND via_peer_id = ?2",
                rusqlite::params!["tenant-a", &"a".repeat(64)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(endpoint_count, 1);

        let binding_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM peer_transport_bindings
                 WHERE recorded_by = ?1 AND peer_id = ?2",
                rusqlite::params!["tenant-a", &"a".repeat(64)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(binding_count, 1);
    }

    #[test]
    fn authenticated_rejects_stale_basis() {
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

        let err = create_outbound_connection_authenticated(
            &conn,
            "tenant-a",
            plan_event_id,
            &connection_id,
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
            false,
        )
        .unwrap_err();

        match err {
            CreateEventError::Rejected { reason, .. } => assert!(reason.contains("stale")),
            other => panic!("expected stale rejection, got {other:?}"),
        }
    }

    #[test]
    fn record_authenticated_for_current_plan_uses_latest_plan_basis() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("outbound-auth.db");
        let db_path = db_path.to_string_lossy().to_string();
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        create_connection_planned(
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

        record_outbound_connection_authenticated(
            &db_path,
            &connection_id,
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
            false,
        )
        .unwrap();

        let history_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbound_connection_history
                 WHERE tenant_id = ?1 AND connection_id = ?2 AND lifecycle_kind = 'authenticated'",
                rusqlite::params!["tenant-a", &connection_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(history_count, 1);
    }
}
