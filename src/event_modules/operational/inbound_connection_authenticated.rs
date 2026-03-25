use std::net::SocketAddr;

use rusqlite::{Connection, OptionalExtension};

use super::super::layout::common::{read_text_slot, write_text_slot, COMMON_HEADER_BYTES};
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{
    Describe, EventError, ParsedEvent, EVENT_TYPE_INBOUND_CONNECTION_AUTHENTICATED,
};
use super::inbound_connection_rejected::record_inbound_connection_rejected;
use crate::contracts::peering_contract::SessionDirection;
use crate::crypto::event_id_to_base64;
use crate::db::open_connection;
use crate::db::transport_creds::resolve_local_transport_targets;
use crate::db::transport_trust::is_authorized_for_tenant;
use crate::projection::contract::{
    ContextSnapshot, InboundConnectionSnapshot, ProjectorResult, SqlVal, WriteOp,
};
use crate::projection::create::{create_event_synchronous, CreateEventError};
use crate::transport::{
    requested_server_name_from_connection, ConnectionLifecycleError, TransportConnection,
};

use super::connection_runtime::{
    claim_live_connection_slot, peer_fingerprint_from_hex, LiveConnectionClaim, LiveConnectionLease,
};

const INBOUND_CONNECTION_ENDPOINT_TTL_MS: i64 = 24 * 60 * 60 * 1000;
pub const INBOUND_CONNECTION_ID_BYTES: usize = 256;
pub const INBOUND_TENANT_ID_BYTES: usize = 64;
pub const INBOUND_REQUESTED_LOCAL_PEER_ID_BYTES: usize = 64;
pub const INBOUND_REMOTE_PEER_ID_BYTES: usize = 64;
pub const INBOUND_REMOTE_ADDR_BYTES: usize = 96;
pub const INBOUND_CONNECTION_AUTHENTICATED_WIRE_SIZE: usize = COMMON_HEADER_BYTES
    + 32
    + INBOUND_CONNECTION_ID_BYTES
    + INBOUND_TENANT_ID_BYTES
    + INBOUND_REQUESTED_LOCAL_PEER_ID_BYTES
    + INBOUND_REMOTE_PEER_ID_BYTES
    + INBOUND_REMOTE_ADDR_BYTES;

mod offsets {
    pub const TYPE_CODE: usize = 0;
    pub const CREATED_AT: usize = 1;
    pub const BASIS_EVENT_ID: usize = 9;
    pub const CONNECTION_ID: usize = BASIS_EVENT_ID + 32;
    pub const TENANT_ID: usize = CONNECTION_ID + super::INBOUND_CONNECTION_ID_BYTES;
    pub const REQUESTED_LOCAL_TRANSPORT_PEER_ID: usize = TENANT_ID + super::INBOUND_TENANT_ID_BYTES;
    pub const REMOTE_PEER_ID: usize =
        REQUESTED_LOCAL_TRANSPORT_PEER_ID + super::INBOUND_REQUESTED_LOCAL_PEER_ID_BYTES;
    pub const REMOTE_ADDR: usize = REMOTE_PEER_ID + super::INBOUND_REMOTE_PEER_ID_BYTES;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundConnectionAuthenticatedEvent {
    pub created_at_ms: u64,
    pub basis_event_id: [u8; 32],
    pub connection_id: String,
    pub tenant_id: String,
    pub requested_local_transport_peer_id: String,
    pub remote_peer_id: String,
    pub remote_addr: String,
}

impl Describe for InboundConnectionAuthenticatedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "basis_event_id",
                super::super::short_id_b64(&self.basis_event_id),
            ),
            ("connection_id", self.connection_id.clone()),
            ("tenant_id", self.tenant_id.clone()),
            (
                "requested_local_transport_peer_id",
                self.requested_local_transport_peer_id.clone(),
            ),
            ("remote_peer_id", self.remote_peer_id.clone()),
            ("remote_addr", self.remote_addr.clone()),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundConnectionRow {
    pub latest_event_id: String,
    pub recorded_by: String,
    pub tenant_id: Option<String>,
    pub connection_id: String,
    pub lifecycle_kind: String,
    pub requested_local_transport_peer_id: Option<String>,
    pub remote_peer_id: String,
    pub remote_addr: String,
    pub basis_event_id: String,
    pub rejection_kind: Option<String>,
    pub detail: Option<String>,
    pub created_at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundAuthContext {
    pub requested_local_transport_peer_id: String,
    pub authenticated_remote_transport_peer_id: String,
    pub tenant_id: String,
}

pub enum InboundConnectionObservation {
    Authenticated {
        recorded_by: String,
        connection_id: String,
        lease: Option<LiveConnectionLease>,
    },
    Rejected {
        close_code: u32,
        close_reason: String,
    },
}

impl InboundConnectionRow {
    pub fn snapshot(&self) -> InboundConnectionSnapshot {
        InboundConnectionSnapshot {
            event_id: self.latest_event_id.clone(),
            recorded_by: self.recorded_by.clone(),
            tenant_id: self.tenant_id.clone(),
            connection_id: self.connection_id.clone(),
            lifecycle_kind: self.lifecycle_kind.clone(),
            requested_local_transport_peer_id: self.requested_local_transport_peer_id.clone(),
            remote_peer_id: self.remote_peer_id.clone(),
            remote_addr: self.remote_addr.clone(),
            basis_event_id: self.basis_event_id.clone(),
            rejection_kind: self.rejection_kind.clone(),
            detail: self.detail.clone(),
            created_at_ms: self.created_at_ms,
        }
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS inbound_connection_history (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            tenant_id TEXT,
            connection_id TEXT NOT NULL,
            lifecycle_kind TEXT NOT NULL,
            requested_local_transport_peer_id TEXT,
            remote_peer_id TEXT NOT NULL,
            remote_addr TEXT NOT NULL,
            basis_event_id TEXT NOT NULL,
            rejection_kind TEXT,
            detail TEXT,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_inbound_connection_history_latest
            ON inbound_connection_history(recorded_by, connection_id, created_at DESC, event_id DESC);
        CREATE INDEX IF NOT EXISTS idx_inbound_connection_history_tenant
            ON inbound_connection_history(tenant_id, created_at DESC, event_id DESC);
        ",
    )?;
    Ok(())
}

pub fn inbound_connection_id(
    requested_local_transport_peer_id: &str,
    remote_peer_id: &str,
    stable_id: u64,
) -> String {
    format!(
        "inbound:{}:{}:{}",
        requested_local_transport_peer_id, remote_peer_id, stable_id
    )
}

pub fn describe_accept_failure(err: &ConnectionLifecycleError) -> String {
    let msg = err.to_string();
    let m = msg.to_ascii_lowercase();
    if m.contains("trust_rejected") {
        let fp = msg
            .split("peer fingerprint ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .unwrap_or("unknown");
        format!(
            "Rejected incoming connection: remote peer presented TLS fingerprint {} \
             which is not trusted by any local workspace. This is normal during bootstrap \
             when the remote peer's transport identity has not been derived yet",
            fp
        )
    } else if m.contains("connection reset") {
        "Incoming connection was reset by the remote peer before handshake completed".to_string()
    } else {
        format!("Failed to accept incoming connection: {}", msg)
    }
}

pub fn requested_transport_from_connection(
    connection: &TransportConnection,
) -> Option<crate::transport::multi_workspace::TransportSniTarget> {
    let sni = requested_server_name_from_connection(connection)?;
    crate::transport::multi_workspace::parse_transport_sni(&sni)
}

pub fn resolve_inbound_auth_context(
    db_path: &str,
    connection: &TransportConnection,
    remote_peer_id: &str,
) -> Result<InboundAuthContext, String> {
    let requested = requested_transport_from_connection(connection).ok_or_else(|| {
        format!(
            "Rejected peer {}: missing exact transport-target SNI",
            short_peer_id(remote_peer_id)
        )
    })?;
    resolve_requested_tenant_for_peer(db_path, &requested, remote_peer_id)
}

pub fn observe_inbound_connection(
    db_path: &str,
    connection: &TransportConnection,
    peer_id: &str,
) -> Result<InboundConnectionObservation, String> {
    let remote_addr = connection.remote_address();
    let requested_local_transport_peer_id =
        requested_transport_from_connection(connection).map(|target| target.transport_peer_id);
    let preauth_connection_id = inbound_connection_id(
        requested_local_transport_peer_id
            .as_deref()
            .unwrap_or("unknown"),
        peer_id,
        connection.stable_id() as u64,
    );

    let auth_context = match resolve_inbound_auth_context(db_path, connection, peer_id) {
        Ok(context) => context,
        Err(message) => {
            record_inbound_connection_rejected(
                db_path,
                None,
                &preauth_connection_id,
                requested_local_transport_peer_id.as_deref(),
                peer_id,
                remote_addr,
                "tenant_scoped_auth_failed",
                Some(message.as_str()),
            )?;
            return Ok(InboundConnectionObservation::Rejected {
                close_code: 1,
                close_reason: "tenant-scoped auth failed".to_string(),
            });
        }
    };

    let recorded_by = auth_context.tenant_id.clone();
    let connection_id = inbound_connection_id(
        &auth_context.requested_local_transport_peer_id,
        peer_id,
        connection.stable_id() as u64,
    );
    let connection_lease = match claim_live_connection_slot(
        db_path,
        &recorded_by,
        peer_id,
        SessionDirection::Inbound,
        connection.clone(),
    ) {
        LiveConnectionClaim::Acquired(lease) => Some(lease),
        LiveConnectionClaim::Occupied(_occupied) => {
            record_inbound_connection_rejected(
                db_path,
                Some(&recorded_by),
                &connection_id,
                Some(&auth_context.requested_local_transport_peer_id),
                peer_id,
                remote_addr,
                "duplicate_live_connection",
                Some("duplicate peer connection"),
            )?;
            return Ok(InboundConnectionObservation::Rejected {
                close_code: 0,
                close_reason: "duplicate peer connection".to_string(),
            });
        }
    };

    record_inbound_connection_authenticated(
        db_path,
        &recorded_by,
        &connection_id,
        &auth_context.requested_local_transport_peer_id,
        peer_id,
        remote_addr,
    )?;

    Ok(InboundConnectionObservation::Authenticated {
        recorded_by,
        connection_id,
        lease: connection_lease,
    })
}

pub fn resolve_requested_tenant_for_peer(
    db_path: &str,
    requested: &crate::transport::multi_workspace::TransportSniTarget,
    remote_peer_id: &str,
) -> Result<InboundAuthContext, String> {
    let remote_fp = peer_fingerprint_from_hex(remote_peer_id).ok_or_else(|| {
        format!(
            "Rejected peer {}: invalid transport fingerprint for tenant-scoped auth",
            short_peer_id(remote_peer_id)
        )
    })?;
    let db = open_connection(db_path).map_err(|e| {
        format!(
            "Failed to open auth DB for inbound tenant-scoped auth: {}",
            e
        )
    })?;
    let tenants = resolve_local_transport_targets(&db, &requested.transport_peer_id)
        .map_err(|e| format!("Failed to resolve requested local transport target: {}", e))?;
    if tenants.is_empty() {
        return Err(format!(
            "Rejected peer {}: requested local transport fingerprint {} is not present on this node",
            short_peer_id(remote_peer_id),
            short_peer_id(&requested.transport_peer_id)
        ));
    }
    for tenant in tenants {
        let authorized = is_authorized_for_tenant(&db, &tenant.tenant_id, &remote_fp)
            .map_err(|e| format!("Inbound tenant-scoped auth query failed: {}", e))?;
        if authorized {
            return Ok(InboundAuthContext {
                requested_local_transport_peer_id: requested.transport_peer_id.clone(),
                authenticated_remote_transport_peer_id: remote_peer_id.to_string(),
                tenant_id: tenant.tenant_id.clone(),
            });
        }
    }
    Err(format!(
        "Rejected peer {}: no local tenant for requested transport {} authorizes this fingerprint",
        short_peer_id(remote_peer_id),
        short_peer_id(&requested.transport_peer_id)
    ))
}

fn short_peer_id(peer_id: &str) -> &str {
    &peer_id[..16.min(peer_id.len())]
}

fn query_row(
    conn: &Connection,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
) -> rusqlite::Result<Option<InboundConnectionRow>> {
    conn.query_row(sql, params, |row| {
        Ok(InboundConnectionRow {
            latest_event_id: row.get(0)?,
            recorded_by: row.get(1)?,
            tenant_id: row.get(2)?,
            connection_id: row.get(3)?,
            lifecycle_kind: row.get(4)?,
            requested_local_transport_peer_id: row.get(5)?,
            remote_peer_id: row.get(6)?,
            remote_addr: row.get(7)?,
            basis_event_id: row.get(8)?,
            rejection_kind: row.get(9)?,
            detail: row.get(10)?,
            created_at_ms: row.get(11)?,
        })
    })
    .optional()
}

pub fn load(
    conn: &Connection,
    recorded_by: &str,
    connection_id: &str,
) -> rusqlite::Result<Option<InboundConnectionRow>> {
    query_row(
        conn,
        "SELECT
             event_id,
             recorded_by,
             tenant_id,
             connection_id,
             lifecycle_kind,
             requested_local_transport_peer_id,
             remote_peer_id,
             remote_addr,
             basis_event_id,
             rejection_kind,
             detail,
             created_at
         FROM inbound_connection_history
         WHERE recorded_by = ?1
           AND connection_id = ?2
           AND NOT EXISTS (
               SELECT 1
               FROM inbound_connection_history newer
               WHERE newer.recorded_by = inbound_connection_history.recorded_by
                 AND newer.connection_id = inbound_connection_history.connection_id
                 AND newer.basis_event_id = inbound_connection_history.event_id
           )
         ORDER BY created_at DESC, event_id DESC
         LIMIT 1",
        &[&recorded_by, &connection_id],
    )
}

pub fn load_snapshot_by_event_id(
    conn: &Connection,
    recorded_by: &str,
    event_id: &str,
) -> rusqlite::Result<Option<InboundConnectionRow>> {
    query_row(
        conn,
        "SELECT
             event_id,
             recorded_by,
             tenant_id,
             connection_id,
             lifecycle_kind,
             requested_local_transport_peer_id,
             remote_peer_id,
             remote_addr,
             basis_event_id,
             rejection_kind,
             detail,
             created_at
         FROM inbound_connection_history
         WHERE recorded_by = ?1 AND event_id = ?2",
        &[&recorded_by, &event_id],
    )
}

pub fn parse_inbound_connection_authenticated(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < INBOUND_CONNECTION_AUTHENTICATED_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: INBOUND_CONNECTION_AUTHENTICATED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > INBOUND_CONNECTION_AUTHENTICATED_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: INBOUND_CONNECTION_AUTHENTICATED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[offsets::TYPE_CODE] != EVENT_TYPE_INBOUND_CONNECTION_AUTHENTICATED {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_INBOUND_CONNECTION_AUTHENTICATED,
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
    let connection_id = read_text_slot(&blob[offsets::CONNECTION_ID..offsets::TENANT_ID])
        .map_err(EventError::TextSlot)?;
    let tenant_id =
        read_text_slot(&blob[offsets::TENANT_ID..offsets::REQUESTED_LOCAL_TRANSPORT_PEER_ID])
            .map_err(EventError::TextSlot)?;
    let requested_local_transport_peer_id =
        read_text_slot(&blob[offsets::REQUESTED_LOCAL_TRANSPORT_PEER_ID..offsets::REMOTE_PEER_ID])
            .map_err(EventError::TextSlot)?;
    let remote_peer_id = read_text_slot(&blob[offsets::REMOTE_PEER_ID..offsets::REMOTE_ADDR])
        .map_err(EventError::TextSlot)?;
    let remote_addr =
        read_text_slot(&blob[offsets::REMOTE_ADDR..]).map_err(EventError::TextSlot)?;

    Ok(ParsedEvent::InboundConnectionAuthenticated(
        InboundConnectionAuthenticatedEvent {
            created_at_ms,
            basis_event_id,
            connection_id,
            tenant_id,
            requested_local_transport_peer_id,
            remote_peer_id,
            remote_addr,
        },
    ))
}

pub fn encode_inbound_connection_authenticated(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let authenticated = match event {
        ParsedEvent::InboundConnectionAuthenticated(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = vec![0u8; INBOUND_CONNECTION_AUTHENTICATED_WIRE_SIZE];
    buf[offsets::TYPE_CODE] = EVENT_TYPE_INBOUND_CONNECTION_AUTHENTICATED;
    buf[offsets::CREATED_AT..offsets::BASIS_EVENT_ID]
        .copy_from_slice(&authenticated.created_at_ms.to_le_bytes());
    buf[offsets::BASIS_EVENT_ID..offsets::CONNECTION_ID]
        .copy_from_slice(&authenticated.basis_event_id);
    write_text_slot(
        &authenticated.connection_id,
        &mut buf[offsets::CONNECTION_ID..offsets::TENANT_ID],
    )
    .map_err(EventError::TextSlot)?;
    write_text_slot(
        &authenticated.tenant_id,
        &mut buf[offsets::TENANT_ID..offsets::REQUESTED_LOCAL_TRANSPORT_PEER_ID],
    )
    .map_err(EventError::TextSlot)?;
    write_text_slot(
        &authenticated.requested_local_transport_peer_id,
        &mut buf[offsets::REQUESTED_LOCAL_TRANSPORT_PEER_ID..offsets::REMOTE_PEER_ID],
    )
    .map_err(EventError::TextSlot)?;
    write_text_slot(
        &authenticated.remote_peer_id,
        &mut buf[offsets::REMOTE_PEER_ID..offsets::REMOTE_ADDR],
    )
    .map_err(EventError::TextSlot)?;
    write_text_slot(&authenticated.remote_addr, &mut buf[offsets::REMOTE_ADDR..])
        .map_err(EventError::TextSlot)?;
    Ok(buf)
}

fn validate(event: &InboundConnectionAuthenticatedEvent) -> Result<[u8; 32], String> {
    if event.connection_id.trim().is_empty() {
        return Err("inbound_connection_authenticated requires non-empty connection_id".into());
    }
    if event.tenant_id.trim().is_empty() {
        return Err("inbound_connection_authenticated requires non-empty tenant_id".into());
    }
    if event.requested_local_transport_peer_id.trim().is_empty() {
        return Err(
            "inbound_connection_authenticated requires requested_local_transport_peer_id".into(),
        );
    }
    if event.remote_peer_id.trim().is_empty() {
        return Err("inbound_connection_authenticated requires non-empty remote_peer_id".into());
    }
    let remote: SocketAddr = event.remote_addr.parse().map_err(|_| {
        "inbound_connection_authenticated remote_addr must be a socket address".to_string()
    })?;
    if remote.port() == 0 {
        return Err(
            "inbound_connection_authenticated remote_addr port must be non-zero".to_string(),
        );
    }
    let decoded = hex::decode(&event.remote_peer_id)
        .map_err(|_| "inbound_connection_authenticated remote_peer_id must be hex".to_string())?;
    if decoded.len() != 32 {
        return Err(
            "inbound_connection_authenticated remote_peer_id must decode to 32 bytes".to_string(),
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
        ParsedEvent::InboundConnectionAuthenticated(event) => event,
        _ => {
            return Err(
                "inbound_connection_authenticated context loader called for wrong event".into(),
            )
        }
    };

    super::common::build_client_state_basis_context(
        conn,
        recorded_by,
        &authenticated.basis_event_id,
        "inbound_connection_authenticated",
    )
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let authenticated = match parsed {
        ParsedEvent::InboundConnectionAuthenticated(event) => event,
        _ => {
            return ProjectorResult::reject(
                "not an inbound_connection_authenticated event".to_string(),
            )
        }
    };

    let spki = match validate(authenticated) {
        Ok(spki) => spki,
        Err(reason) => return ProjectorResult::reject(reason),
    };
    if let Some(reason) = &ctx.client_runtime_basis_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }
    let Some(snapshot) = &ctx.client_runtime_snapshot else {
        return ProjectorResult::reject(
            "inbound_connection_authenticated missing client runtime snapshot context".into(),
        );
    };
    if snapshot.runtime_status == "stopped" {
        return ProjectorResult::reject(
            "inbound_connection_authenticated cannot project against stopped client runtime"
                .to_string(),
        );
    }
    let remote: SocketAddr = authenticated.remote_addr.parse().unwrap();

    ProjectorResult::valid(vec![
        WriteOp::InsertOrIgnore {
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
                SqlVal::Text(authenticated.tenant_id.clone()),
                SqlVal::Text(authenticated.connection_id.clone()),
                SqlVal::Text("authenticated".to_string()),
                SqlVal::Text(authenticated.requested_local_transport_peer_id.clone()),
                SqlVal::Text(authenticated.remote_peer_id.clone()),
                SqlVal::Text(authenticated.remote_addr.clone()),
                SqlVal::Text(event_id_to_base64(&authenticated.basis_event_id)),
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
                SqlVal::Text(authenticated.tenant_id.clone()),
                SqlVal::Text(authenticated.remote_peer_id.clone()),
                SqlVal::Text(remote.ip().to_string()),
                SqlVal::Int(remote.port() as i64),
                SqlVal::Int(authenticated.created_at_ms as i64),
                SqlVal::Int(
                    authenticated.created_at_ms as i64 + INBOUND_CONNECTION_ENDPOINT_TTL_MS,
                ),
            ],
        },
        WriteOp::InsertOrIgnore {
            table: "peer_transport_bindings",
            columns: vec!["recorded_by", "peer_id", "spki_fingerprint", "bound_at"],
            values: vec![
                SqlVal::Text(authenticated.tenant_id.clone()),
                SqlVal::Text(authenticated.remote_peer_id.clone()),
                SqlVal::Blob(spki.to_vec()),
                SqlVal::Int(authenticated.created_at_ms as i64),
            ],
        },
    ])
}

pub static INBOUND_CONNECTION_AUTHENTICATED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_INBOUND_CONNECTION_AUTHENTICATED,
    type_name: "inbound_connection_authenticated",
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
    parse: parse_inbound_connection_authenticated,
    encode: encode_inbound_connection_authenticated,
    projector: project_pure,
    context_loader: build_projector_context,
};

pub fn create_inbound_connection_authenticated(
    conn: &Connection,
    recorded_by: &str,
    tenant_id: &str,
    basis_event_id: [u8; 32],
    connection_id: &str,
    requested_local_transport_peer_id: &str,
    remote_peer_id: &str,
    remote_addr: SocketAddr,
) -> Result<[u8; 32], CreateEventError> {
    let event = ParsedEvent::InboundConnectionAuthenticated(InboundConnectionAuthenticatedEvent {
        created_at_ms: crate::db::queue::current_timestamp_ms() as u64,
        basis_event_id,
        connection_id: connection_id.to_string(),
        tenant_id: tenant_id.to_string(),
        requested_local_transport_peer_id: requested_local_transport_peer_id.to_string(),
        remote_peer_id: remote_peer_id.to_string(),
        remote_addr: remote_addr.to_string(),
    });
    create_event_synchronous(conn, recorded_by, &event)
}

pub fn record_inbound_connection_authenticated(
    db_path: &str,
    tenant_id: &str,
    connection_id: &str,
    requested_local_transport_peer_id: &str,
    remote_peer_id: &str,
    remote_addr: SocketAddr,
) -> Result<[u8; 32], String> {
    let conn = open_connection(db_path).map_err(|e| e.to_string())?;
    let client_id = super::client_lifecycle::client_id_for_db_path(db_path);
    let basis_event_id =
        super::client_lifecycle::require_current_basis_event_id(&conn, &client_id)?;
    create_inbound_connection_authenticated(
        &conn,
        &client_id,
        tenant_id,
        basis_event_id,
        connection_id,
        requested_local_transport_peer_id,
        remote_peer_id,
        remote_addr,
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_connection;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::event_modules::operational::client_lifecycle::{mark_runtime_active, start_runtime};
    use crate::projection::create::CreateEventError;

    fn setup() -> Connection {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        conn
    }

    fn active_client_basis(conn: &Connection) -> (String, [u8; 32]) {
        let run = start_runtime(
            conn,
            "/tmp/topo.db",
            "127.0.0.1:7443".parse().unwrap(),
            Some("127.0.0.1:7443".parse().unwrap()),
            1,
        )
        .unwrap();
        mark_runtime_active(conn, &run, "127.0.0.1:7443".parse().unwrap(), 1).unwrap();
        let client =
            crate::event_modules::operational::client_lifecycle::load_state(conn, &run.client_id)
                .unwrap()
                .unwrap();
        (
            run.client_id,
            crate::crypto::event_id_from_base64(&client.latest_event_id).unwrap(),
        )
    }

    #[test]
    fn authenticated_projects_connection_history_and_endpoint_rows() {
        let conn = setup();
        let (client_id, basis) = active_client_basis(&conn);
        let connection_id = inbound_connection_id(&"b".repeat(64), &"a".repeat(64), 7);

        create_inbound_connection_authenticated(
            &conn,
            &client_id,
            "tenant-a",
            basis,
            &connection_id,
            &"b".repeat(64),
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
        )
        .unwrap();

        let history_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM inbound_connection_history
                 WHERE recorded_by = ?1 AND tenant_id = ?2 AND connection_id = ?3 AND lifecycle_kind = 'authenticated'",
                rusqlite::params![&client_id, "tenant-a", &connection_id],
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
    }

    #[test]
    fn authenticated_rejects_stale_basis() {
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
        let connection_id = inbound_connection_id(&"b".repeat(64), &"a".repeat(64), 8);

        let err = create_inbound_connection_authenticated(
            &conn,
            &run.client_id,
            "tenant-a",
            started_basis,
            &connection_id,
            &"b".repeat(64),
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
        )
        .unwrap_err();

        match err {
            CreateEventError::Rejected { reason, .. } => assert!(reason.contains("stale")),
            other => panic!("expected stale rejection, got {other:?}"),
        }
    }

    #[test]
    fn record_authenticated_for_current_client_uses_client_runtime_basis() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("inbound-auth.db");
        let db_path = db_path.to_string_lossy().to_string();
        let conn = open_connection(&db_path).unwrap();
        create_tables(&conn).unwrap();

        let run = start_runtime(
            &conn,
            &db_path,
            "127.0.0.1:7443".parse().unwrap(),
            Some("127.0.0.1:7443".parse().unwrap()),
            1,
        )
        .unwrap();
        mark_runtime_active(&conn, &run, "127.0.0.1:7443".parse().unwrap(), 1).unwrap();

        let connection_id = inbound_connection_id(&"b".repeat(64), &"a".repeat(64), 77);
        record_inbound_connection_authenticated(
            &db_path,
            "tenant-a",
            &connection_id,
            &"b".repeat(64),
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
        )
        .unwrap();

        let history_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM inbound_connection_history
                 WHERE recorded_by = ?1 AND connection_id = ?2 AND lifecycle_kind = 'authenticated'",
                rusqlite::params![&run.client_id, &connection_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(history_count, 1);
    }
}
