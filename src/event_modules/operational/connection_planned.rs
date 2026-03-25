use std::net::SocketAddr;

use rusqlite::{params, Connection, OptionalExtension, Result as SqliteResult};

use super::super::layout::common::COMMON_HEADER_BYTES;
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{Describe, EventError, ParsedEvent, EVENT_TYPE_CONNECTION_PLANNED};
use crate::db::open_connection;
use crate::db::queue::{current_timestamp_ms, with_sqlite_busy_retry};
use crate::event_modules::encode_event;
use crate::projection::contract::{
    ConnectionPlanSnapshot, ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp,
};
use crate::projection::create::{create_event_synchronous, CreateEventError};

pub const CONNECTION_ID_BYTES: usize = 256;
pub const CONNECTION_PEER_ID_BYTES: usize = 64;
pub const CONNECTION_REMOTE_ADDR_BYTES: usize = 96;
pub const CONNECTION_INVITE_EVENT_ID_BYTES: usize = 64;

pub const CONNECTION_PLANNED_WIRE_SIZE: usize = COMMON_HEADER_BYTES
    + CONNECTION_ID_BYTES
    + CONNECTION_PEER_ID_BYTES
    + CONNECTION_REMOTE_ADDR_BYTES
    + 1
    + CONNECTION_INVITE_EVENT_ID_BYTES;

mod connection_planned_offsets {
    pub const CREATED_AT: usize = 1;
    pub const CONNECTION_ID: usize = 9;
    pub const REMOTE_PEER_ID: usize = CONNECTION_ID + super::CONNECTION_ID_BYTES;
    pub const REMOTE_ADDR: usize = REMOTE_PEER_ID + super::CONNECTION_PEER_ID_BYTES;
    pub const SOURCE_KIND: usize = REMOTE_ADDR + super::CONNECTION_REMOTE_ADDR_BYTES;
    pub const INVITE_EVENT_ID: usize = SOURCE_KIND + 1;
}

use connection_planned_offsets as off;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPlanSourceKind {
    Bootstrap,
    ObservedPeer,
    Discovery,
}

impl ConnectionPlanSourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::ObservedPeer => "observed_peer",
            Self::Discovery => "discovery",
        }
    }

    pub fn from_str(raw: &str) -> Option<Self> {
        match raw {
            "bootstrap" => Some(Self::Bootstrap),
            "observed_peer" => Some(Self::ObservedPeer),
            "discovery" => Some(Self::Discovery),
            _ => None,
        }
    }

    fn code(self) -> u8 {
        match self {
            Self::Bootstrap => 1,
            Self::ObservedPeer => 2,
            Self::Discovery => 3,
        }
    }

    fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Bootstrap),
            2 => Some(Self::ObservedPeer),
            3 => Some(Self::Discovery),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionPlanStatus {
    Planned,
    Deferred,
    Active,
    Superseded,
    Finished,
}

impl ConnectionPlanStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Deferred => "deferred",
            Self::Active => "active",
            Self::Superseded => "superseded",
            Self::Finished => "finished",
        }
    }

    pub fn from_str(raw: &str) -> Option<Self> {
        match raw {
            "planned" => Some(Self::Planned),
            "deferred" => Some(Self::Deferred),
            "active" => Some(Self::Active),
            "superseded" => Some(Self::Superseded),
            "finished" => Some(Self::Finished),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPlannedEvent {
    pub created_at_ms: u64,
    pub connection_id: String,
    pub remote_peer_id: String,
    pub remote_addr: String,
    pub source_kind: ConnectionPlanSourceKind,
    pub invite_event_id: Option<String>,
}

impl Describe for ConnectionPlannedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            ("connection_id", self.connection_id.clone()),
            ("remote_peer_id", self.remote_peer_id.clone()),
            ("remote_addr", self.remote_addr.clone()),
            ("source_kind", self.source_kind.as_str().to_string()),
        ];
        if let Some(invite_event_id) = &self.invite_event_id {
            fields.push(("invite_event_id", invite_event_id.clone()));
        }
        fields
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPlanRow {
    pub latest_event_id: String,
    pub connection_id: String,
    pub tenant_id: String,
    pub remote_peer_id: String,
    pub remote_addr: String,
    pub source_kind: ConnectionPlanSourceKind,
    pub invite_event_id: Option<String>,
    pub plan_status: ConnectionPlanStatus,
    pub decision_reason: Option<String>,
    pub basis_event_id: Option<String>,
    pub next_attempt_not_before_ms: Option<i64>,
    pub created_at_ms: i64,
}

impl ConnectionPlanRow {
    pub fn snapshot(&self) -> ConnectionPlanSnapshot {
        ConnectionPlanSnapshot {
            event_id: self.latest_event_id.clone(),
            tenant_id: self.tenant_id.clone(),
            connection_id: self.connection_id.clone(),
            remote_peer_id: self.remote_peer_id.clone(),
            remote_addr: self.remote_addr.clone(),
            source_kind: self.source_kind.as_str().to_string(),
            invite_event_id: self.invite_event_id.clone(),
            plan_status: self.plan_status.as_str().to_string(),
            decision_reason: self.decision_reason.clone(),
            basis_event_id: self.basis_event_id.clone(),
            next_attempt_not_before_ms: self.next_attempt_not_before_ms,
            created_at_ms: self.created_at_ms,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPlanEffect {
    pub connection_id: String,
    pub tenant_id: String,
    pub available_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionPlanDispatchTarget {
    pub connection_id: String,
    pub tenant_id: String,
    pub remote_peer_id: String,
    pub remote: SocketAddr,
    pub source_kind: ConnectionPlanSourceKind,
    pub invite_event_id: Option<String>,
}

impl ConnectionPlanDispatchTarget {
    pub fn known_peer_key(&self) -> String {
        discovery_connection_id(&self.tenant_id, &self.remote_peer_id)
    }

    pub fn bootstrap_worker_prefix(&self) -> String {
        bootstrap_connection_id_prefix(&self.tenant_id, &self.remote_peer_id)
    }
}

pub fn ensure_schema(conn: &Connection) -> SqliteResult<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS connection_plan_history (
            tenant_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            connection_id TEXT NOT NULL,
            remote_peer_id TEXT NOT NULL,
            remote_addr TEXT NOT NULL,
            source_kind TEXT NOT NULL,
            invite_event_id TEXT,
            plan_status TEXT NOT NULL,
            decision_reason TEXT,
            basis_event_id TEXT,
            next_attempt_not_before_ms INTEGER,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (tenant_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_connection_plan_history_latest
            ON connection_plan_history(tenant_id, connection_id, created_at DESC, event_id DESC);
        CREATE INDEX IF NOT EXISTS idx_connection_plan_history_due
            ON connection_plan_history(tenant_id, plan_status, next_attempt_not_before_ms, created_at DESC, event_id DESC);
        ",
    )?;
    Ok(())
}

pub fn bootstrap_connection_id(
    tenant_id: &str,
    transport_peer_id: &str,
    remote: SocketAddr,
) -> String {
    format!("{tenant_id}@bootstrap:{transport_peer_id}@{remote}")
}

pub fn bootstrap_connection_id_prefix(tenant_id: &str, transport_peer_id: &str) -> String {
    format!("{tenant_id}@bootstrap:{transport_peer_id}@")
}

pub fn known_peer_connection_id(tenant_id: &str, transport_peer_id: &str) -> String {
    format!("{tenant_id}@peer:{transport_peer_id}")
}

pub fn discovery_connection_id(tenant_id: &str, transport_peer_id: &str) -> String {
    known_peer_connection_id(tenant_id, transport_peer_id)
}

fn connection_id_for_target(
    tenant_id: &str,
    remote_peer_id: &str,
    remote: SocketAddr,
    source_kind: ConnectionPlanSourceKind,
) -> String {
    match source_kind {
        ConnectionPlanSourceKind::Bootstrap => {
            bootstrap_connection_id(tenant_id, remote_peer_id, remote)
        }
        ConnectionPlanSourceKind::ObservedPeer | ConnectionPlanSourceKind::Discovery => {
            discovery_connection_id(tenant_id, remote_peer_id)
        }
    }
}

pub fn parse_connection_planned(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    super::common::expect_wire(
        blob,
        EVENT_TYPE_CONNECTION_PLANNED,
        CONNECTION_PLANNED_WIRE_SIZE,
    )?;

    let created_at_ms =
        super::common::read_created_at_ms(blob, off::CREATED_AT..off::CONNECTION_ID);
    let connection_id = super::common::read_text(&blob[off::CONNECTION_ID..off::REMOTE_PEER_ID])?;
    let remote_peer_id = super::common::read_text(&blob[off::REMOTE_PEER_ID..off::REMOTE_ADDR])?;
    let remote_addr = super::common::read_text(&blob[off::REMOTE_ADDR..off::SOURCE_KIND])?;
    let source_kind = ConnectionPlanSourceKind::from_code(blob[off::SOURCE_KIND]).ok_or(
        EventError::InvalidMetadata("invalid connection plan source kind"),
    )?;
    let invite_event_id = super::common::read_optional_text(
        &blob[off::INVITE_EVENT_ID..off::INVITE_EVENT_ID + CONNECTION_INVITE_EVENT_ID_BYTES],
    )?;

    Ok(ParsedEvent::ConnectionPlanned(ConnectionPlannedEvent {
        created_at_ms,
        connection_id,
        remote_peer_id,
        remote_addr,
        source_kind,
        invite_event_id,
    }))
}

pub fn encode_connection_planned(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let planned = match event {
        ParsedEvent::ConnectionPlanned(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = super::common::fresh_blob(
        EVENT_TYPE_CONNECTION_PLANNED,
        CONNECTION_PLANNED_WIRE_SIZE,
        off::CREATED_AT..off::CONNECTION_ID,
        planned.created_at_ms,
    );
    super::common::write_text(
        &mut buf[off::CONNECTION_ID..off::REMOTE_PEER_ID],
        &planned.connection_id,
    )?;
    super::common::write_text(
        &mut buf[off::REMOTE_PEER_ID..off::REMOTE_ADDR],
        &planned.remote_peer_id,
    )?;
    super::common::write_text(
        &mut buf[off::REMOTE_ADDR..off::SOURCE_KIND],
        &planned.remote_addr,
    )?;
    buf[off::SOURCE_KIND] = planned.source_kind.code();
    super::common::write_optional_text(
        &mut buf[off::INVITE_EVENT_ID..off::INVITE_EVENT_ID + CONNECTION_INVITE_EVENT_ID_BYTES],
        planned.invite_event_id.as_deref(),
    )?;
    Ok(buf)
}

fn validate_planned(event: &ConnectionPlannedEvent) -> Result<(), String> {
    if event.connection_id.trim().is_empty() {
        return Err("connection_planned requires non-empty connection_id".to_string());
    }
    if event.remote_peer_id.trim().is_empty() {
        return Err("connection_planned requires non-empty remote_peer_id".to_string());
    }
    let remote: SocketAddr = event
        .remote_addr
        .parse()
        .map_err(|_| "connection_planned remote_addr must be a socket address".to_string())?;
    if remote.port() == 0 {
        return Err("connection_planned remote_addr port must be non-zero".to_string());
    }
    if matches!(event.source_kind, ConnectionPlanSourceKind::Bootstrap)
        && event
            .invite_event_id
            .as_deref()
            .is_none_or(|invite| invite.trim().is_empty())
    {
        return Err("bootstrap connection_planned requires invite_event_id".to_string());
    }
    Ok(())
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let planned = match parsed {
        ParsedEvent::ConnectionPlanned(event) => event,
        _ => return ProjectorResult::reject("not a connection_planned event".to_string()),
    };

    if let Err(reason) = validate_planned(planned) {
        return ProjectorResult::reject(reason);
    }

    ProjectorResult::valid_with_commands(
        vec![WriteOp::InsertOrIgnore {
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
                SqlVal::Text(planned.connection_id.clone()),
                SqlVal::Text(planned.remote_peer_id.clone()),
                SqlVal::Text(planned.remote_addr.clone()),
                SqlVal::Text(planned.source_kind.as_str().to_string()),
                planned
                    .invite_event_id
                    .as_ref()
                    .map(|invite| SqlVal::Text(invite.clone()))
                    .unwrap_or(SqlVal::Null),
                SqlVal::Text(ConnectionPlanStatus::Planned.as_str().to_string()),
                SqlVal::Null,
                SqlVal::Null,
                SqlVal::Int(planned.created_at_ms as i64),
                SqlVal::Int(planned.created_at_ms as i64),
            ],
        }],
        vec![EmitCommand::WakeConnectionPlan {
            connection_id: planned.connection_id.clone(),
        }],
    )
}

pub static CONNECTION_PLANNED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_CONNECTION_PLANNED,
    type_name: "connection_planned",
    projection_table: "connection_plan_history",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_connection_planned,
    encode: encode_connection_planned,
    projector: project_pure,
    context_loader: crate::event_modules::registry::load_empty_context,
};

pub fn source_precedence(source_kind: ConnectionPlanSourceKind) -> u8 {
    match source_kind {
        ConnectionPlanSourceKind::Bootstrap => 0,
        ConnectionPlanSourceKind::ObservedPeer | ConnectionPlanSourceKind::Discovery => 1,
    }
}

pub fn existing_source_has_higher_precedence(
    existing: ConnectionPlanSourceKind,
    incoming: ConnectionPlanSourceKind,
) -> bool {
    source_precedence(existing) > source_precedence(incoming)
}

/// Event-owned policy: should this connection plan be activated?
/// Checks preferred direction and bootstrap auth state. This replaces
/// the runtime-local `should_initiate_connect_for_source_with_db`.
pub fn should_activate_plan(
    conn: &Connection,
    tenant_id: &str,
    source_kind: ConnectionPlanSourceKind,
    peer_id: &str,
) -> bool {
    use super::connection_runtime::preferred_connection_direction;
    use crate::contracts::peering_contract::SessionDirection;
    match source_kind {
        ConnectionPlanSourceKind::Bootstrap | ConnectionPlanSourceKind::ObservedPeer => true,
        ConnectionPlanSourceKind::Discovery => {
            // For discovery targets, check if we are the preferred initiator
            // (deterministic tiebreak by peer ID comparison), unless bootstrap
            // auth state overrides.
            let direction_ok = matches!(
                preferred_connection_direction(tenant_id, peer_id),
                Some(SessionDirection::Outbound)
            );
            if direction_ok {
                return true;
            }
            // Check if bootstrap auth gives us discovery+observed permission
            let accepted_and_discovered =
                check_bootstrap_discovery_auth(conn, tenant_id, peer_id);
            accepted_and_discovered
        }
    }
}

/// Check if the peer has accepted bootstrap trust that grants discovery
/// connection permission.
fn check_bootstrap_discovery_auth(
    conn: &Connection,
    tenant_id: &str,
    peer_id: &str,
) -> bool {
    let Ok(fp_bytes) = hex::decode(peer_id) else {
        return false;
    };
    if fp_bytes.len() != 32 {
        return false;
    }
    let mut fp = [0u8; 32];
    fp.copy_from_slice(&fp_bytes);

    let now_ms = crate::db::queue::current_timestamp_ms();
    let accepted = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1 FROM invite_bootstrap_trust
                 WHERE recorded_by = ?1
                   AND bootstrap_spki_fingerprint = ?2
                   AND expires_at > ?3
             )",
            params![tenant_id, fp.as_slice(), now_ms],
            |row| row.get::<_, bool>(0),
        )
        .unwrap_or(false);
    let local_bootstrap = crate::db::transport_creds::resolve_tenant_transport_target(conn, tenant_id)
        .ok()
        .flatten()
        .map(|t| t.source == crate::db::transport_creds::CRED_SOURCE_BOOTSTRAP)
        .unwrap_or(false);
    accepted && local_bootstrap
}

pub fn dispatch_target_from_row(
    plan: &ConnectionPlanRow,
) -> Result<ConnectionPlanDispatchTarget, String> {
    let remote = plan
        .remote_addr
        .parse::<SocketAddr>()
        .map_err(|e| format!("invalid planned remote_addr {}: {}", plan.remote_addr, e))?;
    Ok(ConnectionPlanDispatchTarget {
        connection_id: plan.connection_id.clone(),
        tenant_id: plan.tenant_id.clone(),
        remote_peer_id: plan.remote_peer_id.clone(),
        remote,
        source_kind: plan.source_kind,
        invite_event_id: plan.invite_event_id.clone(),
    })
}

pub fn emit_deterministic_connection_planned(
    tenant_id: &str,
    remote_peer_id: &str,
    remote: SocketAddr,
    source_kind: ConnectionPlanSourceKind,
    invite_event_id: Option<&str>,
    created_at_ms: u64,
) -> Result<EmitCommand, EventError> {
    let planned = ParsedEvent::ConnectionPlanned(ConnectionPlannedEvent {
        created_at_ms,
        connection_id: connection_id_for_target(tenant_id, remote_peer_id, remote, source_kind),
        remote_peer_id: remote_peer_id.to_string(),
        remote_addr: remote.to_string(),
        source_kind,
        invite_event_id: invite_event_id.map(str::to_string),
    });
    Ok(EmitCommand::EmitDeterministicBlob {
        blob: encode_event(&planned)?,
    })
}

fn query_latest_row(
    conn: &Connection,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
) -> SqliteResult<Option<ConnectionPlanRow>> {
    with_sqlite_busy_retry(|| {
        conn.query_row(sql, params, |row| {
            let source_kind_raw: String = row.get(5)?;
            let plan_status_raw: String = row.get(7)?;
            Ok(ConnectionPlanRow {
                latest_event_id: row.get(0)?,
                connection_id: row.get(1)?,
                tenant_id: row.get(2)?,
                remote_peer_id: row.get(3)?,
                remote_addr: row.get(4)?,
                source_kind: ConnectionPlanSourceKind::from_str(&source_kind_raw)
                    .unwrap_or(ConnectionPlanSourceKind::Discovery),
                invite_event_id: row.get(6)?,
                plan_status: ConnectionPlanStatus::from_str(&plan_status_raw)
                    .unwrap_or(ConnectionPlanStatus::Finished),
                decision_reason: row.get(8)?,
                basis_event_id: row.get(9)?,
                next_attempt_not_before_ms: row.get(10)?,
                created_at_ms: row.get(11)?,
            })
        })
        .optional()
    })
}

pub fn load(conn: &Connection, connection_id: &str) -> SqliteResult<Option<ConnectionPlanRow>> {
    query_latest_row(
        conn,
        "SELECT
             event_id,
             connection_id,
             tenant_id,
             remote_peer_id,
             remote_addr,
             source_kind,
             invite_event_id,
             plan_status,
             decision_reason,
             basis_event_id,
             next_attempt_not_before_ms,
             created_at
         FROM connection_plan_history
         WHERE connection_id = ?1
           AND NOT EXISTS (
               SELECT 1
               FROM connection_plan_history newer
               WHERE newer.tenant_id = connection_plan_history.tenant_id
                 AND newer.connection_id = connection_plan_history.connection_id
                 AND newer.basis_event_id = connection_plan_history.event_id
           )
         ORDER BY created_at DESC, event_id DESC
         LIMIT 1",
        &[&connection_id],
    )
}

pub fn load_snapshot_by_event_id(
    conn: &Connection,
    tenant_id: &str,
    event_id: &str,
) -> SqliteResult<Option<ConnectionPlanRow>> {
    query_latest_row(
        conn,
        "SELECT
             event_id,
             connection_id,
             tenant_id,
             remote_peer_id,
             remote_addr,
             source_kind,
             invite_event_id,
             plan_status,
             decision_reason,
             basis_event_id,
             next_attempt_not_before_ms,
             created_at
         FROM connection_plan_history
         WHERE tenant_id = ?1 AND event_id = ?2",
        &[&tenant_id, &event_id],
    )
}

pub fn require_current_plan_basis(
    conn: &Connection,
    connection_id: &str,
) -> Result<(String, [u8; 32]), String> {
    let Some(plan) = load(conn, connection_id).map_err(|e| e.to_string())? else {
        return Err(format!("missing connection plan state for {connection_id}"));
    };
    let basis = crate::crypto::event_id_from_base64(&plan.latest_event_id).ok_or_else(|| {
        format!(
            "invalid connection plan latest_event_id {} for {}",
            plan.latest_event_id, connection_id
        )
    })?;
    Ok((plan.tenant_id, basis))
}

pub fn create_connection_planned(
    conn: &Connection,
    tenant_id: &str,
    remote_peer_id: &str,
    remote: SocketAddr,
    source_kind: ConnectionPlanSourceKind,
    invite_event_id: Option<&str>,
) -> Result<Option<[u8; 32]>, CreateEventError> {
    let connection_id = connection_id_for_target(tenant_id, remote_peer_id, remote, source_kind);
    if let Some(existing) = load(conn, &connection_id)? {
        let same_target = existing.remote_peer_id == remote_peer_id
            && existing.remote_addr == remote.to_string()
            && existing.source_kind == source_kind
            && existing.invite_event_id.as_deref() == invite_event_id;
        if same_target
            && matches!(
                existing.plan_status,
                ConnectionPlanStatus::Planned
                    | ConnectionPlanStatus::Deferred
                    | ConnectionPlanStatus::Active
            )
        {
            return Ok(None);
        }
    }

    let event = ParsedEvent::ConnectionPlanned(ConnectionPlannedEvent {
        created_at_ms: current_timestamp_ms() as u64,
        connection_id,
        remote_peer_id: remote_peer_id.to_string(),
        remote_addr: remote.to_string(),
        source_kind,
        invite_event_id: invite_event_id.map(str::to_string),
    });
    create_event_synchronous(conn, tenant_id, &event).map(Some)
}

pub fn record_connection_planned(
    db_path: &str,
    tenant_id: &str,
    remote_peer_id: &str,
    remote: SocketAddr,
    source_kind: ConnectionPlanSourceKind,
    invite_event_id: Option<&str>,
) -> Result<Option<[u8; 32]>, String> {
    let conn = open_connection(db_path).map_err(|e| e.to_string())?;
    create_connection_planned(
        &conn,
        tenant_id,
        remote_peer_id,
        remote,
        source_kind,
        invite_event_id,
    )
    .map_err(|e| e.to_string())
}

pub fn load_due_effects(
    conn: &Connection,
    limit: usize,
) -> SqliteResult<Vec<ConnectionPlanEffect>> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let now = current_timestamp_ms();
    with_sqlite_busy_retry(|| {
        let mut stmt = conn.prepare(
            "SELECT h.connection_id, h.tenant_id, COALESCE(h.next_attempt_not_before_ms, h.created_at)
             FROM connection_plan_history h
             WHERE h.plan_status IN ('planned', 'deferred')
               AND COALESCE(h.next_attempt_not_before_ms, h.created_at) <= ?1
               AND NOT EXISTS (
                   SELECT 1
                   FROM connection_plan_history newer
                   WHERE newer.tenant_id = h.tenant_id
                     AND newer.connection_id = h.connection_id
                     AND newer.basis_event_id = h.event_id
               )
             ORDER BY COALESCE(h.next_attempt_not_before_ms, h.created_at) ASC,
                      h.created_at ASC,
                      h.event_id ASC
             LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![now, limit as i64], |row| {
            Ok(ConnectionPlanEffect {
                connection_id: row.get(0)?,
                tenant_id: row.get(1)?,
                available_at_ms: row.get(2)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::event_id_to_base64;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::projection::create::CreateEventError;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::new("127.0.0.1".parse().unwrap(), port)
    }

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn bootstrap_connection_id_is_remote_scoped() {
        let peer_id = format!("{:064x}", 7);
        let a = bootstrap_connection_id("tenant-a", &peer_id, addr(4433));
        let b = bootstrap_connection_id("tenant-a", &peer_id, addr(4434));
        assert_ne!(a, b);
    }

    #[test]
    fn known_peer_connection_id_is_peer_stable() {
        let a = known_peer_connection_id("tenant-a", "peer-a");
        let b = known_peer_connection_id("tenant-a", "peer-a");
        assert_eq!(a, b);
    }

    #[test]
    fn connection_planned_roundtrips() {
        let event = ParsedEvent::ConnectionPlanned(ConnectionPlannedEvent {
            created_at_ms: 1234,
            connection_id: discovery_connection_id("tenant-a", &"a".repeat(64)),
            remote_peer_id: "a".repeat(64),
            remote_addr: "127.0.0.1:7443".to_string(),
            source_kind: ConnectionPlanSourceKind::Discovery,
            invite_event_id: None,
        });

        let blob = crate::event_modules::encode_event(&event).unwrap();
        let parsed = crate::event_modules::parse_event(&blob).unwrap();
        assert_eq!(parsed, event);
    }

    #[test]
    fn create_connection_planned_projects_history_and_due_view() {
        let conn = setup();
        let created = create_connection_planned(
            &conn,
            "tenant-a",
            &"a".repeat(64),
            addr(7443),
            ConnectionPlanSourceKind::Discovery,
            None,
        )
        .unwrap()
        .expect("new plan should create an event");
        let event_id = event_id_to_base64(&created);

        let row = load(&conn, &discovery_connection_id("tenant-a", &"a".repeat(64)))
            .unwrap()
            .unwrap();
        assert_eq!(row.plan_status, ConnectionPlanStatus::Planned);
        assert_eq!(row.latest_event_id, event_id);

        let effects = load_due_effects(&conn, 10).unwrap();
        assert_eq!(effects.len(), 1);
        assert_eq!(effects[0].tenant_id, "tenant-a");
        assert_eq!(effects[0].connection_id, row.connection_id);
    }

    #[test]
    fn create_connection_planned_rejects_invalid_remote_addr() {
        let conn = setup();
        let event = ParsedEvent::ConnectionPlanned(ConnectionPlannedEvent {
            created_at_ms: 1234,
            connection_id: "tenant-a@peer:abc".to_string(),
            remote_peer_id: "a".repeat(64),
            remote_addr: "127.0.0.1:0".to_string(),
            source_kind: ConnectionPlanSourceKind::Discovery,
            invite_event_id: None,
        });

        let err = create_event_synchronous(&conn, "tenant-a", &event).unwrap_err();
        match err {
            CreateEventError::Rejected { reason, .. } => {
                assert!(reason.contains("port must be non-zero"));
            }
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn create_connection_planned_ignores_duplicate_live_target() {
        let conn = setup();
        create_connection_planned(
            &conn,
            "tenant-a",
            &"a".repeat(64),
            addr(7443),
            ConnectionPlanSourceKind::Discovery,
            None,
        )
        .unwrap();

        let second = create_connection_planned(
            &conn,
            "tenant-a",
            &"a".repeat(64),
            addr(7443),
            ConnectionPlanSourceKind::Discovery,
            None,
        )
        .unwrap();
        assert!(
            second.is_none(),
            "unchanged live plan should not spam local events"
        );
    }
}
