use std::net::SocketAddr;
use std::sync::Arc;

use rusqlite::Connection;

use super::super::layout::common::COMMON_HEADER_BYTES;
use super::super::registry::{EventTypeMeta, ShareScope};
use super::super::{
    Describe, EventError, ParsedEvent, EVENT_TYPE_CONNECTION_PLAN_TRANSITIONED,
    EVENT_TYPE_OUTBOUND_CONNECTION_FAILED,
};
use super::common::{
    expect_wire, fresh_blob, read_created_at_ms, read_event_id, read_flag, read_optional_text,
    read_text, write_event_id, write_flag, write_optional_text, write_text,
};
use super::connection_planned::{
    require_current_plan_basis, CONNECTION_ID_BYTES, CONNECTION_PLANNED_META,
};
use super::outbound_connection_authenticated::record_outbound_connection_authenticated;
use crate::contracts::peering_contract::SessionDirection;
use crate::db::open_connection;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::projection::create::{create_event_synchronous, CreateEventError};
use crate::transport::{
    derive_bootstrap_dial_context, dial_session_provider, BootstrapDialMode,
    ConnectionLifecycleError, SessionProvider, TransportClientConfig, TransportEndpoint,
};

use super::connection_runtime::{
    claim_live_connection_slot, peer_fingerprint_from_hex, LiveConnectionClaim, LiveConnectionLease,
};

pub const FAILURE_KIND_BYTES: usize = 64;
pub const FAILURE_DETAIL_BYTES: usize = 128;
pub const OUTBOUND_CONNECTION_FAILED_WIRE_SIZE: usize =
    COMMON_HEADER_BYTES + 32 + CONNECTION_ID_BYTES + FAILURE_KIND_BYTES + FAILURE_DETAIL_BYTES + 1;

mod offsets {
    pub const CREATED_AT: usize = 1;
    pub const BASIS_EVENT_ID: usize = 9;
    pub const CONNECTION_ID: usize = BASIS_EVENT_ID + 32;
    pub const FAILURE_KIND: usize = CONNECTION_ID + super::CONNECTION_ID_BYTES;
    pub const DETAIL: usize = FAILURE_KIND + super::FAILURE_KIND_BYTES;
    pub const USED_BOOTSTRAP_FALLBACK: usize = DETAIL + super::FAILURE_DETAIL_BYTES;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundConnectionFailedEvent {
    pub created_at_ms: u64,
    pub basis_event_id: [u8; 32],
    pub connection_id: String,
    pub failure_kind: String,
    pub detail: Option<String>,
    pub used_bootstrap_fallback: bool,
}

pub struct OutboundDialOutcome {
    pub provider: SessionProvider,
    pub used_bootstrap_fallback: bool,
}

pub struct OutboundDialFailure {
    pub error: ConnectionLifecycleError,
    pub used_bootstrap_fallback: bool,
}

pub enum OutboundConnectionObservation {
    Authenticated {
        lease: Option<LiveConnectionLease>,
        peer_fp: [u8; 32],
    },
    Occupied {
        released: Arc<tokio::sync::Notify>,
    },
    Retry {
        detail: String,
    },
}

impl Describe for OutboundConnectionFailedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        let mut fields = vec![
            (
                "basis_event_id",
                super::super::short_id_b64(&self.basis_event_id),
            ),
            ("connection_id", self.connection_id.clone()),
            ("failure_kind", self.failure_kind.clone()),
            (
                "used_bootstrap_fallback",
                self.used_bootstrap_fallback.to_string(),
            ),
        ];
        if let Some(detail) = &self.detail {
            fields.push(("detail", detail.clone()));
        }
        fields
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    super::outbound_connection_authenticated::ensure_schema(conn)
}

pub fn describe_connect_failure(remote: SocketAddr, err: &ConnectionLifecycleError) -> String {
    match err {
        ConnectionLifecycleError::DialTrustRejected(msg) => {
            let fp = msg
                .split("peer fingerprint ")
                .nth(1)
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("unknown");
            format!(
                "Certificate mismatch connecting to {}: TLS fingerprint {} is not trusted. \
                 Either (a) the remote peer's certificate does not match the expected fingerprint, \
                 or (b) the remote rejected our certificate. This usually means: (1) transport \
                 identity has not been derived yet (bootstrap in progress), (2) the invite was \
                 created by a different peer, or (3) a certificate was rotated",
                remote, fp
            )
        }
        ConnectionLifecycleError::Dial(msg) => {
            let m = msg.to_ascii_lowercase();
            if m.contains("connection refused") {
                format!(
                    "Connection refused by {}: nothing is listening on that address. \
                     Is the peer's daemon running? (start it with: topo start)",
                    remote
                )
            } else if m.contains("timed out") || m.contains("timeout") {
                format!(
                    "Connection to {} timed out: the peer may be offline, \
                     behind a firewall, or the address may be stale",
                    remote
                )
            } else if m.contains("network is unreachable") || m.contains("no route to host") {
                format!(
                    "Cannot reach {}: network is unreachable. Check that the peer's \
                     address is correct and that you have network connectivity to it",
                    remote
                )
            } else if m.contains("host unreachable") || m.contains("unreachable") {
                format!(
                    "Host {} is unreachable. The address may be on a different network \
                     or the peer may be offline",
                    remote
                )
            } else {
                format!("Failed to connect to {}: {}", remote, msg)
            }
        }
        ConnectionLifecycleError::Accept(msg) => {
            format!(
                "Unexpected accept error during outbound dial to {}: {}",
                remote, msg
            )
        }
        ConnectionLifecycleError::MissingPeerIdentity => {
            format!(
                "Connected to {} but peer did not present a TLS certificate. \
                 This should not happen with a topo peer — the remote may not be a topo node",
                remote
            )
        }
    }
}

pub fn is_stale_dial_failure(err: &ConnectionLifecycleError) -> bool {
    match err {
        ConnectionLifecycleError::Dial(msg) => {
            let m = msg.to_ascii_lowercase();
            m.contains("timed out")
                || m.contains("timeout")
                || m.contains("connection refused")
                || m.contains("network is unreachable")
                || m.contains("no route to host")
                || m.contains("unreachable")
        }
        ConnectionLifecycleError::DialTrustRejected(_) => false,
        ConnectionLifecycleError::Accept(_) | ConnectionLifecycleError::MissingPeerIdentity => {
            false
        }
    }
}

pub fn should_warn_for_connect_failure(
    has_connected_once: bool,
    err: &ConnectionLifecycleError,
) -> bool {
    has_connected_once || !is_stale_dial_failure(err)
}

pub fn bootstrap_fallback_mode(
    primary_err: Option<&ConnectionLifecycleError>,
    has_bootstrap_fallback_cfg: bool,
) -> BootstrapDialMode {
    derive_bootstrap_dial_context(primary_err, has_bootstrap_fallback_cfg).mode
}

pub async fn dial_provider_with_bootstrap_policy(
    endpoint: &TransportEndpoint,
    remote: SocketAddr,
    sni: &str,
    ongoing_client_config: Option<&TransportClientConfig>,
    bootstrap_fallback_client_config: Option<&TransportClientConfig>,
) -> Result<OutboundDialOutcome, OutboundDialFailure> {
    match dial_session_provider(endpoint, remote, sni, ongoing_client_config).await {
        Ok(provider) => Ok(OutboundDialOutcome {
            provider,
            used_bootstrap_fallback: false,
        }),
        Err(primary_err) => {
            if bootstrap_fallback_mode(
                Some(&primary_err),
                bootstrap_fallback_client_config.is_some(),
            ) != BootstrapDialMode::BootstrapFallback
            {
                return Err(OutboundDialFailure {
                    error: primary_err,
                    used_bootstrap_fallback: false,
                });
            }
            let Some(fallback_cfg) = bootstrap_fallback_client_config else {
                return Err(OutboundDialFailure {
                    error: primary_err,
                    used_bootstrap_fallback: false,
                });
            };
            match dial_session_provider(endpoint, remote, sni, Some(fallback_cfg)).await {
                Ok(provider) => Ok(OutboundDialOutcome {
                    provider,
                    used_bootstrap_fallback: true,
                }),
                Err(fallback_err) => {
                    if is_stale_dial_failure(&fallback_err) {
                        Err(OutboundDialFailure {
                            error: ConnectionLifecycleError::Dial(format!(
                                "primary and bootstrap-fallback dials both failed to {}: \
                                 primary: {}, fallback: {}",
                                remote, primary_err, fallback_err
                            )),
                            used_bootstrap_fallback: true,
                        })
                    } else if matches!(primary_err, ConnectionLifecycleError::DialTrustRejected(_))
                    {
                        Err(OutboundDialFailure {
                            error: primary_err,
                            used_bootstrap_fallback: true,
                        })
                    } else {
                        Err(OutboundDialFailure {
                            error: ConnectionLifecycleError::Dial(format!(
                                "primary and bootstrap-fallback dials both failed to {}: \
                                 primary: {}, fallback: {}",
                                remote, primary_err, fallback_err
                            )),
                            used_bootstrap_fallback: true,
                        })
                    }
                }
            }
        }
    }
}

pub fn observe_outbound_authenticated_connection(
    db_path: &str,
    recorded_by: &str,
    peer_id: &str,
    connection: &crate::transport::TransportConnection,
    connection_plan_id: Option<&str>,
    used_bootstrap_fallback: bool,
) -> Result<OutboundConnectionObservation, String> {
    let Some(peer_fp) = peer_fingerprint_from_hex(peer_id) else {
        let detail = format!(
            "Could not decode peer fingerprint from identity {}",
            &peer_id[..16.min(peer_id.len())]
        );
        if let Some(connection_plan_id) = connection_plan_id {
            let _ = record_outbound_connection_failed(
                db_path,
                connection_plan_id,
                "invalid_peer_fingerprint",
                Some(detail.as_str()),
                used_bootstrap_fallback,
            );
        }
        return Ok(OutboundConnectionObservation::Retry { detail });
    };

    let connection_lease = match claim_live_connection_slot(
        db_path,
        recorded_by,
        peer_id,
        SessionDirection::Outbound,
        connection.clone(),
    ) {
        LiveConnectionClaim::Acquired(lease) => Some(lease),
        LiveConnectionClaim::Occupied(occupied) => {
            if let Some(connection_plan_id) = connection_plan_id {
                let detail = format!(
                    "active_direction={:?} preferred_direction={:?}",
                    occupied.active_direction, occupied.preferred_direction
                );
                record_outbound_connection_failed(
                    db_path,
                    connection_plan_id,
                    "duplicate_live_connection",
                    Some(detail.as_str()),
                    used_bootstrap_fallback,
                )?;
            }
            return Ok(OutboundConnectionObservation::Occupied {
                released: occupied.released,
            });
        }
    };

    if let Some(connection_plan_id) = connection_plan_id {
        record_outbound_connection_authenticated(
            db_path,
            connection_plan_id,
            peer_id,
            connection.remote_address(),
            used_bootstrap_fallback,
        )?;
    }

    Ok(OutboundConnectionObservation::Authenticated {
        lease: connection_lease,
        peer_fp,
    })
}

pub fn failure_kind(err: &ConnectionLifecycleError) -> &'static str {
    match err {
        ConnectionLifecycleError::DialTrustRejected(_) => "dial_trust_rejected",
        ConnectionLifecycleError::Dial(_) => {
            if is_stale_dial_failure(err) {
                "dial_stale"
            } else {
                "dial_error"
            }
        }
        ConnectionLifecycleError::Accept(_) => "accept_error",
        ConnectionLifecycleError::MissingPeerIdentity => "missing_peer_identity",
    }
}

pub fn parse_outbound_connection_failed(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    expect_wire(
        blob,
        EVENT_TYPE_OUTBOUND_CONNECTION_FAILED,
        OUTBOUND_CONNECTION_FAILED_WIRE_SIZE,
    )?;
    let created_at_ms = read_created_at_ms(blob, offsets::CREATED_AT..offsets::BASIS_EVENT_ID);
    let basis_event_id = read_event_id(&blob[offsets::BASIS_EVENT_ID..offsets::CONNECTION_ID]);
    let connection_id = read_text(&blob[offsets::CONNECTION_ID..offsets::FAILURE_KIND])?;
    let failure_kind = read_text(&blob[offsets::FAILURE_KIND..offsets::DETAIL])?;
    let detail = read_optional_text(&blob[offsets::DETAIL..offsets::USED_BOOTSTRAP_FALLBACK])?;
    let used_bootstrap_fallback = read_flag(blob, offsets::USED_BOOTSTRAP_FALLBACK);

    Ok(ParsedEvent::OutboundConnectionFailed(
        OutboundConnectionFailedEvent {
            created_at_ms,
            basis_event_id,
            connection_id,
            failure_kind,
            detail,
            used_bootstrap_fallback,
        },
    ))
}

pub fn encode_outbound_connection_failed(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let failed = match event {
        ParsedEvent::OutboundConnectionFailed(event) => event,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = fresh_blob(
        EVENT_TYPE_OUTBOUND_CONNECTION_FAILED,
        OUTBOUND_CONNECTION_FAILED_WIRE_SIZE,
        offsets::CREATED_AT..offsets::BASIS_EVENT_ID,
        failed.created_at_ms,
    );
    write_event_id(
        &mut buf[offsets::BASIS_EVENT_ID..offsets::CONNECTION_ID],
        &failed.basis_event_id,
    );
    write_text(
        &mut buf[offsets::CONNECTION_ID..offsets::FAILURE_KIND],
        &failed.connection_id,
    )?;
    write_text(
        &mut buf[offsets::FAILURE_KIND..offsets::DETAIL],
        &failed.failure_kind,
    )?;
    write_optional_text(
        &mut buf[offsets::DETAIL..offsets::USED_BOOTSTRAP_FALLBACK],
        failed.detail.as_deref(),
    )?;
    write_flag(
        &mut buf,
        offsets::USED_BOOTSTRAP_FALLBACK,
        failed.used_bootstrap_fallback,
    );
    Ok(buf)
}

fn validate(event: &OutboundConnectionFailedEvent) -> Result<(), String> {
    if event.connection_id.trim().is_empty() {
        return Err("outbound_connection_failed requires non-empty connection_id".to_string());
    }
    if event.failure_kind.trim().is_empty() {
        return Err("outbound_connection_failed requires non-empty failure_kind".to_string());
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
        ParsedEvent::OutboundConnectionFailed(event) => event,
        _ => return Err("outbound_connection_failed context loader called for wrong event".into()),
    };

    super::common::build_connection_plan_basis_context(
        conn,
        recorded_by,
        &failed.basis_event_id,
        "outbound_connection_failed",
    )
}

pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let failed = match parsed {
        ParsedEvent::OutboundConnectionFailed(event) => event,
        _ => return ProjectorResult::reject("not an outbound_connection_failed event".to_string()),
    };

    if let Err(reason) = validate(failed) {
        return ProjectorResult::reject(reason);
    }
    if let Some(reason) = &ctx.connection_plan_basis_mismatch_reason {
        return ProjectorResult::reject(reason.clone());
    }
    let Some(snapshot) = &ctx.connection_plan_snapshot else {
        return ProjectorResult::reject(
            "outbound_connection_failed missing connection plan snapshot context".to_string(),
        );
    };
    if snapshot.connection_id != failed.connection_id {
        return ProjectorResult::reject(
            "outbound_connection_failed connection_id does not match basis snapshot".to_string(),
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
            SqlVal::Text(failed.connection_id.clone()),
            SqlVal::Text("failed".to_string()),
            SqlVal::Text(snapshot.remote_peer_id.clone()),
            SqlVal::Text(snapshot.remote_addr.clone()),
            SqlVal::Text(snapshot.event_id.clone()),
            SqlVal::Int(failed.used_bootstrap_fallback as i64),
            SqlVal::Text(failed.failure_kind.clone()),
            failed
                .detail
                .as_ref()
                .map(|detail| SqlVal::Text(detail.clone()))
                .unwrap_or(SqlVal::Null),
            SqlVal::Int(failed.created_at_ms as i64),
        ],
    }])
}

pub static OUTBOUND_CONNECTION_FAILED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_OUTBOUND_CONNECTION_FAILED,
    type_name: "outbound_connection_failed",
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
    parse: parse_outbound_connection_failed,
    encode: encode_outbound_connection_failed,
    projector: project_pure,
    context_loader: build_projector_context,
};

pub fn create_outbound_connection_failed(
    conn: &Connection,
    tenant_id: &str,
    basis_event_id: [u8; 32],
    connection_id: &str,
    failure_kind: &str,
    detail: Option<&str>,
    used_bootstrap_fallback: bool,
) -> Result<[u8; 32], CreateEventError> {
    let event = ParsedEvent::OutboundConnectionFailed(OutboundConnectionFailedEvent {
        created_at_ms: crate::db::queue::current_timestamp_ms() as u64,
        basis_event_id,
        connection_id: connection_id.to_string(),
        failure_kind: failure_kind.to_string(),
        detail: detail.map(str::to_string),
        used_bootstrap_fallback,
    });
    create_event_synchronous(conn, tenant_id, &event)
}

pub fn record_outbound_connection_failed(
    db_path: &str,
    connection_id: &str,
    failure_kind: &str,
    detail: Option<&str>,
    used_bootstrap_fallback: bool,
) -> Result<[u8; 32], String> {
    let conn = open_connection(db_path).map_err(|e| e.to_string())?;
    let (tenant_id, basis_event_id) = require_current_plan_basis(&conn, connection_id)?;
    create_outbound_connection_failed(
        &conn,
        &tenant_id,
        basis_event_id,
        connection_id,
        failure_kind,
        detail,
        used_bootstrap_fallback,
    )
    .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Event-owned stale-dial streak helpers
// ---------------------------------------------------------------------------

/// Count consecutive `dial_stale` failures for `connection_id` since the last
/// non-stale event (success, close, or non-stale failure). Returns 0 if no
/// stale failures or the history is empty.
pub fn consecutive_stale_failure_count(
    conn: &rusqlite::Connection,
    connection_id: &str,
) -> Result<u32, String> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM outbound_connection_history
             WHERE connection_id = ?1
               AND lifecycle_kind = 'failed'
               AND failure_kind = 'dial_stale'
               AND created_at > COALESCE(
                   (SELECT MAX(created_at) FROM outbound_connection_history
                    WHERE connection_id = ?1
                      AND (lifecycle_kind != 'failed' OR failure_kind != 'dial_stale')),
                   0
               )",
            rusqlite::params![connection_id],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    Ok(count as u32)
}

/// Whether any `authenticated` event exists for this `connection_id`.
pub fn has_ever_authenticated(
    conn: &rusqlite::Connection,
    connection_id: &str,
) -> Result<bool, String> {
    let exists: bool = conn
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM outbound_connection_history
                WHERE connection_id = ?1 AND lifecycle_kind = 'authenticated'
            )",
            rusqlite::params![connection_id],
            |row| row.get(0),
        )
        .map_err(|e| e.to_string())?;
    Ok(exists)
}

/// Evaluate whether the stale-dial threshold has been reached for this
/// connection. Returns `Some(count)` if `count >= threshold`, meaning the
/// caller should treat the target as terminally stale. Returns `None` if
/// below threshold.
pub fn evaluate_stale_dial_terminal(
    conn: &rusqlite::Connection,
    connection_id: &str,
    threshold: u32,
) -> Result<Option<u32>, String> {
    let count = consecutive_stale_failure_count(conn, connection_id)?;
    if count >= threshold {
        Ok(Some(count))
    } else {
        Ok(None)
    }
}

/// Combined stale-dial evaluation from db_path. Opens a connection, checks
/// both `has_ever_authenticated` and `evaluate_stale_dial_terminal`.
pub fn check_stale_dial_state(
    db_path: &str,
    connection_id: &str,
    threshold: u32,
) -> Result<StaleDialState, String> {
    let conn = open_connection(db_path).map_err(|e| e.to_string())?;
    let has_connected = has_ever_authenticated(&conn, connection_id)?;
    let terminal = evaluate_stale_dial_terminal(&conn, connection_id, threshold)?;
    Ok(StaleDialState {
        has_connected_once: has_connected,
        terminal_stale_count: terminal,
    })
}

/// Result of evaluating stale-dial state from projected connection history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleDialState {
    /// Whether this connection has ever successfully authenticated.
    pub has_connected_once: bool,
    /// If `Some(count)`, the stale threshold has been reached.
    pub terminal_stale_count: Option<u32>,
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
    fn failed_projects_history_row() {
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

        create_outbound_connection_failed(
            &conn,
            "tenant-a",
            basis,
            &connection_id,
            "dial_error",
            Some("timed out"),
            true,
        )
        .unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM outbound_connection_history
                 WHERE tenant_id = ?1 AND connection_id = ?2 AND lifecycle_kind = 'failed'",
                rusqlite::params!["tenant-a", &connection_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }

    fn setup_active_plan(conn: &Connection) -> (String, [u8; 32]) {
        let plan_event_id = create_connection_planned(
            conn,
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
            conn,
            "tenant-a",
            plan_event_id,
            &connection_id,
            ConnectionPlanStatus::Active,
            Some("spawned"),
            0,
        )
        .unwrap();
        let active_basis =
            crate::event_modules::operational::connection_planned::load(conn, &connection_id)
                .unwrap()
                .unwrap();
        let basis = crate::crypto::event_id_from_base64(&active_basis.latest_event_id).unwrap();
        (connection_id, basis)
    }

    use std::sync::atomic::{AtomicU32, Ordering as AtomicOrd};
    static TEST_SEQ: AtomicU32 = AtomicU32::new(0);

    fn record_stale_failure(conn: &Connection, connection_id: &str) {
        let (_, basis) = super::require_current_plan_basis(conn, connection_id).unwrap();
        let seq = TEST_SEQ.fetch_add(1, AtomicOrd::Relaxed);
        create_outbound_connection_failed(
            conn,
            "tenant-a",
            basis,
            connection_id,
            "dial_stale",
            Some(&format!("timed out #{seq}")),
            false,
        )
        .unwrap();
    }

    fn record_non_stale_failure(conn: &Connection, connection_id: &str) {
        let (_, basis) = super::require_current_plan_basis(conn, connection_id).unwrap();
        let seq = TEST_SEQ.fetch_add(1, AtomicOrd::Relaxed);
        create_outbound_connection_failed(
            conn,
            "tenant-a",
            basis,
            connection_id,
            "dial_trust_rejected",
            Some(&format!("trust rejected #{seq}")),
            false,
        )
        .unwrap();
    }

    fn record_success(conn: &Connection, connection_id: &str) {
        use crate::event_modules::operational::outbound_connection_authenticated::create_outbound_connection_authenticated;
        let (_, basis) = super::require_current_plan_basis(conn, connection_id).unwrap();
        create_outbound_connection_authenticated(
            conn,
            "tenant-a",
            basis,
            connection_id,
            &"a".repeat(64),
            "127.0.0.1:7443".parse().unwrap(),
            false,
        )
        .unwrap();
    }

    #[test]
    fn stale_failure_streak_accumulates_from_projected_history() {
        let conn = setup();
        let (connection_id, _basis) = setup_active_plan(&conn);

        assert_eq!(consecutive_stale_failure_count(&conn, &connection_id).unwrap(), 0);
        assert!(!has_ever_authenticated(&conn, &connection_id).unwrap());

        record_stale_failure(&conn, &connection_id);
        assert_eq!(consecutive_stale_failure_count(&conn, &connection_id).unwrap(), 1);

        record_stale_failure(&conn, &connection_id);
        assert_eq!(consecutive_stale_failure_count(&conn, &connection_id).unwrap(), 2);

        record_stale_failure(&conn, &connection_id);
        assert_eq!(consecutive_stale_failure_count(&conn, &connection_id).unwrap(), 3);
    }

    #[test]
    fn stale_failure_streak_resets_after_success() {
        let conn = setup();
        let (connection_id, _basis) = setup_active_plan(&conn);

        record_stale_failure(&conn, &connection_id);
        record_stale_failure(&conn, &connection_id);
        assert_eq!(consecutive_stale_failure_count(&conn, &connection_id).unwrap(), 2);

        record_success(&conn, &connection_id);
        assert_eq!(consecutive_stale_failure_count(&conn, &connection_id).unwrap(), 0);
        assert!(has_ever_authenticated(&conn, &connection_id).unwrap());
    }

    #[test]
    fn stale_failure_streak_resets_after_non_stale_failure() {
        let conn = setup();
        let (connection_id, _basis) = setup_active_plan(&conn);

        record_stale_failure(&conn, &connection_id);
        record_stale_failure(&conn, &connection_id);
        assert_eq!(consecutive_stale_failure_count(&conn, &connection_id).unwrap(), 2);

        record_non_stale_failure(&conn, &connection_id);
        assert_eq!(consecutive_stale_failure_count(&conn, &connection_id).unwrap(), 0);
    }

    #[test]
    fn evaluate_stale_terminal_reports_threshold_reached() {
        let conn = setup();
        let (connection_id, _basis) = setup_active_plan(&conn);

        for _ in 0..3 {
            record_stale_failure(&conn, &connection_id);
        }
        assert_eq!(evaluate_stale_dial_terminal(&conn, &connection_id, 4).unwrap(), None);

        record_stale_failure(&conn, &connection_id);
        assert_eq!(evaluate_stale_dial_terminal(&conn, &connection_id, 4).unwrap(), Some(4));
    }

    #[test]
    fn failure_kind_distinguishes_stale_from_non_stale() {
        let stale = ConnectionLifecycleError::Dial("connection refused".to_string());
        assert_eq!(failure_kind(&stale), "dial_stale");

        let non_stale = ConnectionLifecycleError::Dial("TLS handshake error".to_string());
        assert_eq!(failure_kind(&non_stale), "dial_error");

        let trust = ConnectionLifecycleError::DialTrustRejected("trust_rejected".to_string());
        assert_eq!(failure_kind(&trust), "dial_trust_rejected");
    }

    #[test]
    fn failed_rejects_stale_basis() {
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

        let err = create_outbound_connection_failed(
            &conn,
            "tenant-a",
            plan_event_id,
            &connection_id,
            "dial_error",
            None,
            false,
        )
        .unwrap_err();

        match err {
            CreateEventError::Rejected { reason, .. } => assert!(reason.contains("stale")),
            other => panic!("expected stale rejection, got {other:?}"),
        }
    }
}
