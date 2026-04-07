use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OptionalExtension};
use crate::contracts::peering_contract::TransportSessionIo;
use crate::crypto::{
    event_id_to_base64, sign_event_bytes, spki_fingerprint_from_ed25519_pubkey,
    verify_ed25519_signature,
};
use crate::db::open_connection;
use crate::db::transport_trust::is_authorized_for_tenant;
use crate::event_modules::{parse_event, ParsedEvent};
use crate::protocol::{
    encode_frame, parse_frame, Frame, OpenSessionAuthAck, OpenSessionAuthInvite, OpenSessionRoute,
};
use super::{load_daemon_identity_from_db, DaemonConnection};

pub const MAX_SESSION_AUTH_TTL_MS: u64 = 5 * 60 * 1000;
const SESSION_AUTH_CLOCK_SKEW_MS: u64 = 30 * 1000;
const MAX_SESSION_AUTH_FRAME_BYTES: usize = 4096;

const INVITE_SIGNING_DOMAIN: &[u8] = b"poc7-session-auth-v1-invite";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutboundSessionAuthPlan {
    PeerShared { target_peer_id: String },
    InviteBootstrap { invite_event_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundSessionAuthResult {
    pub session_peer_id: String,
    pub canonical_remote_peer_id: Option<String>,
    pub remote_daemon_peer_id: String,
    pub used_bootstrap_auth: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InboundSessionAuthContext {
    pub tenant_id: String,
    pub remote_peer_id: String,
    pub remote_daemon_peer_id: String,
    pub used_bootstrap_auth: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BootstrapSessionTenantContext {
    CandidateTenants { tenant_ids: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BootstrapSessionTenantDecision {
    RejectMissing,
    Accept { tenant_id: String },
    RejectAmbiguous,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OutboundSessionAuthContext {
    requested_plan: OutboundSessionAuthPlan,
    remote_session_peer_id: String,
    bootstrap_auth_still_valid: bool,
    daemon_connection_admits_route: bool,
    bound_daemon_matches_remote: bool,
    remote_session_peer_authorized: bool,
}

fn decide_bootstrap_session_tenant(
    context: &BootstrapSessionTenantContext,
) -> BootstrapSessionTenantDecision {
    match context {
        BootstrapSessionTenantContext::CandidateTenants { tenant_ids } => {
            let mut tenant_ids = tenant_ids.clone();
            tenant_ids.sort();
            tenant_ids.dedup();
            match tenant_ids.as_slice() {
                [] => BootstrapSessionTenantDecision::RejectMissing,
                [tenant_id] => BootstrapSessionTenantDecision::Accept {
                    tenant_id: tenant_id.clone(),
                },
                _ => BootstrapSessionTenantDecision::RejectAmbiguous,
            }
        }
    }
}

fn decide_outbound_session_auth_plan(
    context: &OutboundSessionAuthContext,
) -> OutboundSessionAuthPlan {
    match &context.requested_plan {
        OutboundSessionAuthPlan::PeerShared { .. } => context.requested_plan.clone(),
        OutboundSessionAuthPlan::InviteBootstrap { .. } => {
            if context.bootstrap_auth_still_valid {
                if context.daemon_connection_admits_route
                    && context.bound_daemon_matches_remote
                    && context.remote_session_peer_authorized
                {
                    return OutboundSessionAuthPlan::PeerShared {
                        target_peer_id: context.remote_session_peer_id.clone(),
                    };
                }
                return context.requested_plan.clone();
            }

            if context.bound_daemon_matches_remote && context.remote_session_peer_authorized {
                return OutboundSessionAuthPlan::PeerShared {
                    target_peer_id: context.remote_session_peer_id.clone(),
                };
            }

            context.requested_plan.clone()
        }
    }
}

fn now_ms() -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64)
}

fn decode_hex32(
    value: &str,
    label: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        return Err(format!("{label} must be 32-byte hex, got {} bytes", bytes.len()).into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn validate_expiry(expires_at_ms: u64) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let now = now_ms()?;
    if expires_at_ms + SESSION_AUTH_CLOCK_SKEW_MS < now {
        return Err("session auth expired".into());
    }
    if expires_at_ms > now + MAX_SESSION_AUTH_TTL_MS + SESSION_AUTH_CLOCK_SKEW_MS {
        return Err("session auth expiry exceeds maximum TTL".into());
    }
    Ok(())
}

fn ensure_daemon_binding(
    auth_local_daemon_peer_id: &[u8; 32],
    auth_remote_daemon_peer_id: &[u8; 32],
    local_daemon_peer_id: &[u8; 32],
    remote_daemon_peer_id: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if auth_local_daemon_peer_id != local_daemon_peer_id {
        return Err("session auth local daemon fingerprint mismatch".into());
    }
    if auth_remote_daemon_peer_id != remote_daemon_peer_id {
        return Err("session auth remote daemon fingerprint mismatch".into());
    }
    Ok(())
}

fn encode_invite_signing_bytes(auth: &OpenSessionAuthInvite) -> Vec<u8> {
    let mut buf = Vec::with_capacity(INVITE_SIGNING_DOMAIN.len() + 32 * 5 + 8);
    buf.extend_from_slice(INVITE_SIGNING_DOMAIN);
    buf.extend_from_slice(&auth.source_peer_id);
    buf.extend_from_slice(&auth.source_peer_public_key);
    buf.extend_from_slice(&auth.target_invite_event_id);
    buf.extend_from_slice(&auth.local_daemon_peer_id);
    buf.extend_from_slice(&auth.remote_daemon_peer_id);
    buf.extend_from_slice(&auth.expires_at_ms.to_le_bytes());
    buf
}

fn load_invite_secret_key(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id_b64: &str,
) -> Result<SigningKey, Box<dyn std::error::Error + Send + Sync>> {
    let key_bytes: Vec<u8> = conn.query_row(
        "SELECT private_key
         FROM invite_secrets
         WHERE recorded_by = ?1
           AND invite_event_id = ?2
           AND length(private_key) = 32
         ORDER BY created_at DESC, event_id DESC
         LIMIT 1",
        params![recorded_by, invite_event_id_b64],
        |row| row.get(0),
    )?;
    let key_arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "invite_secret private_key is not 32 bytes")?;
    Ok(SigningKey::from_bytes(&key_arr))
}

fn load_invite_public_key(
    conn: &Connection,
    invite_event_id_b64: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let blob: Vec<u8> = conn.query_row(
        "SELECT blob
         FROM events
         WHERE event_id = ?1
         LIMIT 1",
        params![invite_event_id_b64],
        |row| row.get(0),
    )?;
    match parse_event(&blob)? {
        ParsedEvent::Signed(signed) => match parse_event(&signed.payload)? {
            ParsedEvent::UserInvite(event) => Ok(event.public_key),
            ParsedEvent::DeviceInvite(event) => Ok(event.public_key),
            other => Err(format!(
                "invite event {invite_event_id_b64} has wrong inner type: {other:?}"
            )
            .into()),
        },
        ParsedEvent::UserInvite(event) => Ok(event.public_key),
        ParsedEvent::DeviceInvite(event) => Ok(event.public_key),
        other => {
            Err(format!("invite event {invite_event_id_b64} has wrong type: {other:?}").into())
        }
    }
}

fn load_bootstrap_session_tenant_context(
    conn: &Connection,
    invite_event_id_b64: &str,
    remote_daemon_peer_id: &[u8; 32],
) -> Result<BootstrapSessionTenantContext, Box<dyn std::error::Error + Send + Sync>> {
    let now = now_ms()? as i64;
    let tenant_ids = conn
        .prepare(
            "SELECT recorded_by
               FROM (
                    SELECT recorded_by
                      FROM pending_invite_bootstrap_trust
                     WHERE invite_event_id = ?1
                       AND expires_at > ?3
                    UNION
                    SELECT recorded_by
                      FROM invite_bootstrap_trust
                     WHERE invite_event_id = ?1
                       AND bootstrap_spki_fingerprint = ?2
                       AND expires_at > ?3
               )
              ORDER BY recorded_by ASC",
        )?
        .query_map(
            params![invite_event_id_b64, remote_daemon_peer_id.as_slice(), now],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(BootstrapSessionTenantContext::CandidateTenants { tenant_ids })
}

fn resolve_bootstrap_session_tenant(
    conn: &Connection,
    invite_event_id_b64: &str,
    remote_daemon_peer_id: &[u8; 32],
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let context =
        load_bootstrap_session_tenant_context(conn, invite_event_id_b64, remote_daemon_peer_id)?;
    match decide_bootstrap_session_tenant(&context) {
        BootstrapSessionTenantDecision::RejectMissing => Err(format!(
            "no active bootstrap trust for invite {} and daemon {}",
            invite_event_id_b64,
            hex::encode(remote_daemon_peer_id)
        )
        .into()),
        BootstrapSessionTenantDecision::Accept { tenant_id } => Ok(tenant_id),
        BootstrapSessionTenantDecision::RejectAmbiguous => Err(format!(
            "invite {} and daemon {} resolve to multiple local tenants; bootstrap auth is ambiguous",
            invite_event_id_b64,
            hex::encode(remote_daemon_peer_id)
        )
        .into()),
    }
}

async fn send_auth_frame(
    io: &mut dyn TransportSessionIo,
    frame: &Frame,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let encoded = encode_frame(frame);
    io.send_control_frame(&encoded).await?;
    io.flush_control().await?;
    Ok(())
}

async fn send_session_route(
    io: &mut dyn TransportSessionIo,
    source_peer_id: [u8; 32],
    target_tenant_id: [u8; 32],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    send_auth_frame(
        io,
        &Frame::OpenSessionRoute {
            route: OpenSessionRoute {
                source_peer_id,
                target_tenant_id,
            },
        },
    )
    .await
}

fn peer_route_is_authorized_for_daemon(
    conn: &Connection,
    daemon_connection: Option<&DaemonConnection>,
    tenant_id: &str,
    remote_peer_id: &str,
    actual_remote_daemon_peer_id: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(daemon_connection) = daemon_connection {
        if daemon_connection.admits_session_route(tenant_id, remote_peer_id) {
            return Ok(true);
        }
    }

    let remote_peer_id_raw = match decode_hex32(remote_peer_id, "remote peer id") {
        Ok(value) => value,
        Err(_) => return Ok(false),
    };
    if !is_authorized_for_tenant(conn, tenant_id, &remote_peer_id_raw)? {
        return Ok(false);
    }

    let Some(bound_daemon_peer_id) = resolve_bound_daemon_peer_id(conn, tenant_id, remote_peer_id)?
    else {
        return Ok(false);
    };
    let admitted = bound_daemon_peer_id == actual_remote_daemon_peer_id;
    if admitted {
        if let Some(daemon_connection) = daemon_connection {
            daemon_connection.remember_admitted_session_route(tenant_id, remote_peer_id);
        }
    }
    Ok(admitted)
}

async fn read_auth_ack(
    io: &mut dyn TransportSessionIo,
) -> Result<OpenSessionAuthAck, Box<dyn std::error::Error + Send + Sync>> {
    let previous_recv_limit = io.swap_control_recv_limit(MAX_SESSION_AUTH_FRAME_BYTES);
    let bytes = io.recv_control_frame().await;
    io.swap_control_recv_limit(previous_recv_limit);
    let bytes = bytes?;
    let (frame, consumed) = parse_frame(&bytes)?;
    if consumed != bytes.len() {
        return Err("session auth ack frame contained trailing bytes".into());
    }
    match frame {
        Frame::OpenSessionAuthAck { ack } => Ok(ack),
        other => Err(format!("expected session auth ack frame, got {other:?}").into()),
    }
}

pub(crate) async fn send_inbound_session_auth_ack(
    io: &mut dyn TransportSessionIo,
    tenant_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let target_tenant_id = decode_hex32(tenant_id, "tenant_id")?;
    send_auth_frame(
        io,
        &Frame::OpenSessionAuthAck {
            ack: OpenSessionAuthAck { target_tenant_id },
        },
    )
    .await
}

pub async fn send_outbound_session_auth(
    io: &mut dyn TransportSessionIo,
    db_path: &str,
    recorded_by: &str,
    daemon_connection: Option<&DaemonConnection>,
    actual_remote_daemon_peer_id: &str,
    expected_remote_daemon_peer_id: Option<&str>,
    plan: &OutboundSessionAuthPlan,
) -> Result<OutboundSessionAuthResult, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(expected) = expected_remote_daemon_peer_id {
        if expected != actual_remote_daemon_peer_id {
            return Err(format!(
                "connected daemon fingerprint mismatch: expected {}, got {}",
                expected, actual_remote_daemon_peer_id
            )
            .into());
        }
    }

    let (local_daemon_peer_id, _cert, _key) = load_daemon_identity_from_db(db_path)?;
    let local_daemon_peer_id_raw = decode_hex32(&local_daemon_peer_id, "local daemon peer id")?;
    let remote_daemon_peer_id_raw =
        decode_hex32(&actual_remote_daemon_peer_id, "remote daemon peer id")?;
    let source_peer_id = decode_hex32(recorded_by, "recorded_by")?;
    let expires_at_ms = now_ms()? + MAX_SESSION_AUTH_TTL_MS;

    let db = open_connection(db_path)?;
    match plan {
        OutboundSessionAuthPlan::PeerShared { target_peer_id } => {
            let target_tenant_id = decode_hex32(target_peer_id, "target peer id")?;
            if !is_authorized_for_tenant(&db, recorded_by, &target_tenant_id)? {
                return Err(format!(
                    "target peer {} is not authorized for tenant {}",
                    target_peer_id, recorded_by
                )
                .into());
            }
            if !peer_route_is_authorized_for_daemon(
                &db,
                daemon_connection,
                recorded_by,
                target_peer_id,
                actual_remote_daemon_peer_id,
            )? {
                return Err(format!(
                    "session route not admitted for tenant {} peer {} on daemon {}",
                    recorded_by, target_peer_id, actual_remote_daemon_peer_id
                )
                .into());
            }
            send_session_route(io, source_peer_id, target_tenant_id).await?;
            let ack = read_auth_ack(io).await?;
            let ack_target_tenant_id = hex::encode(ack.target_tenant_id);
            if ack_target_tenant_id != *target_peer_id {
                return Err(format!(
                    "session auth ack target mismatch: expected {}, got {}",
                    target_peer_id, ack_target_tenant_id
                )
                .into());
            }
            if let Some(daemon_connection) = daemon_connection {
                daemon_connection
                    .remember_admitted_session_route(recorded_by, &ack_target_tenant_id);
            }
            Ok(OutboundSessionAuthResult {
                session_peer_id: ack_target_tenant_id.clone(),
                canonical_remote_peer_id: Some(ack_target_tenant_id),
                remote_daemon_peer_id: actual_remote_daemon_peer_id.to_string(),
                used_bootstrap_auth: false,
            })
        }
        OutboundSessionAuthPlan::InviteBootstrap { invite_event_id } => {
            let invite_signing_key = load_invite_secret_key(&db, recorded_by, invite_event_id)?;
            let (_peer_shared_event_id, peer_shared_signing_key) =
                crate::event_modules::peer_shared::load_local_peer_signer_required(
                    &db,
                    recorded_by,
                )?;
            let target_invite_event_id = crate::crypto::event_id_from_base64(invite_event_id)
                .ok_or_else(|| {
                    format!("invalid invite_event_id encoding for session auth: {invite_event_id}")
                })?;
            let mut auth = OpenSessionAuthInvite {
                source_peer_id,
                source_peer_public_key: peer_shared_signing_key.verifying_key().to_bytes(),
                target_invite_event_id,
                local_daemon_peer_id: local_daemon_peer_id_raw,
                remote_daemon_peer_id: remote_daemon_peer_id_raw,
                expires_at_ms,
                signature: [0u8; 64],
            };
            let signing_bytes = encode_invite_signing_bytes(&auth);
            auth.signature = sign_event_bytes(&invite_signing_key, &signing_bytes);
            send_auth_frame(io, &Frame::OpenSessionAuthInvite { auth }).await?;
            let ack = read_auth_ack(io).await?;
            let canonical_remote_peer_id = hex::encode(ack.target_tenant_id);
            if let Some(daemon_connection) = daemon_connection {
                daemon_connection
                    .remember_admitted_session_route(recorded_by, &canonical_remote_peer_id);
            }
            Ok(OutboundSessionAuthResult {
                session_peer_id: canonical_remote_peer_id.clone(),
                canonical_remote_peer_id: Some(canonical_remote_peer_id),
                remote_daemon_peer_id: actual_remote_daemon_peer_id.to_string(),
                used_bootstrap_auth: true,
            })
        }
    }
}

async fn read_inbound_session_auth_inner(
    io: &mut dyn TransportSessionIo,
    db_path: &str,
    actual_remote_daemon_peer_id: &str,
    daemon_connection: Option<&DaemonConnection>,
) -> Result<InboundSessionAuthContext, Box<dyn std::error::Error + Send + Sync>> {
    let previous_recv_limit = io.swap_control_recv_limit(MAX_SESSION_AUTH_FRAME_BYTES);
    let bytes = io.recv_control_frame().await;
    io.swap_control_recv_limit(previous_recv_limit);
    let bytes = bytes?;
    let (frame, consumed) = parse_frame(&bytes)?;
    if consumed != bytes.len() {
        return Err("session auth frame contained trailing bytes".into());
    }

    let actual_remote_daemon_peer_id_raw =
        decode_hex32(&actual_remote_daemon_peer_id, "remote daemon peer id")?;
    let (local_daemon_peer_id, _cert, _key) = load_daemon_identity_from_db(db_path)?;
    let local_daemon_peer_id_raw = decode_hex32(&local_daemon_peer_id, "local daemon peer id")?;
    let db = open_connection(db_path)?;

    match frame {
        Frame::OpenSessionRoute { route } => {
            let tenant_id = hex::encode(route.target_tenant_id);
            let remote_peer_id = hex::encode(route.source_peer_id);
            if !peer_route_is_authorized_for_daemon(
                &db,
                daemon_connection,
                &tenant_id,
                &remote_peer_id,
                actual_remote_daemon_peer_id,
            )? {
                return Err(format!(
                    "session route not admitted for tenant {} peer {} on daemon {}",
                    tenant_id, remote_peer_id, actual_remote_daemon_peer_id
                )
                .into());
            }
            if let Some(conn) = daemon_connection {
                conn.remember_admitted_session_route(&tenant_id, &remote_peer_id);
            }
            Ok(InboundSessionAuthContext {
                tenant_id,
                remote_peer_id,
                remote_daemon_peer_id: actual_remote_daemon_peer_id.to_string(),
                used_bootstrap_auth: false,
            })
        }
        Frame::OpenSessionAuthInvite { auth } => {
            validate_expiry(auth.expires_at_ms)?;
            ensure_daemon_binding(
                &auth.remote_daemon_peer_id,
                &auth.local_daemon_peer_id,
                &local_daemon_peer_id_raw,
                &actual_remote_daemon_peer_id_raw,
            )?;
            let derived_source_peer_id =
                spki_fingerprint_from_ed25519_pubkey(&auth.source_peer_public_key);
            if auth.source_peer_id != derived_source_peer_id {
                return Err(
                    "bootstrap session auth peer_id does not match claimed public key".into(),
                );
            }
            let invite_event_id_b64 = event_id_to_base64(&auth.target_invite_event_id);
            let remote_peer_id = hex::encode(auth.source_peer_id);
            let tenant_id = match resolve_bootstrap_session_tenant(
                &db,
                &invite_event_id_b64,
                &actual_remote_daemon_peer_id_raw,
            ) {
                Ok(tenant_id) => tenant_id,
                Err(err) => daemon_connection
                    .and_then(|conn| {
                        conn.accepted_bootstrap_tenant(&invite_event_id_b64, &remote_peer_id)
                    })
                    .ok_or(err)?,
            };
            let invite_public_key = load_invite_public_key(&db, &invite_event_id_b64)?;
            let signing_bytes = encode_invite_signing_bytes(&auth);
            if !verify_ed25519_signature(&invite_public_key, &signing_bytes, &auth.signature) {
                return Err("session auth invite signature verification failed".into());
            }
            if let Some(conn) = daemon_connection {
                conn.remember_accepted_bootstrap_auth(
                    &invite_event_id_b64,
                    &remote_peer_id,
                    &tenant_id,
                );
                conn.remember_admitted_session_route(&tenant_id, &remote_peer_id);
            }
            Ok(InboundSessionAuthContext {
                tenant_id,
                remote_peer_id,
                remote_daemon_peer_id: actual_remote_daemon_peer_id.to_string(),
                used_bootstrap_auth: true,
            })
        }
        other => Err(format!("expected session auth frame, got {other:?}").into()),
    }
}

pub async fn read_inbound_session_auth(
    io: &mut dyn TransportSessionIo,
    db_path: &str,
    actual_remote_daemon_peer_id: &str,
) -> Result<InboundSessionAuthContext, Box<dyn std::error::Error + Send + Sync>> {
    read_inbound_session_auth_inner(io, db_path, actual_remote_daemon_peer_id, None).await
}

pub async fn read_inbound_session_auth_for_connection(
    io: &mut dyn TransportSessionIo,
    db_path: &str,
    daemon_connection: &DaemonConnection,
) -> Result<InboundSessionAuthContext, Box<dyn std::error::Error + Send + Sync>> {
    read_inbound_session_auth_inner(
        io,
        db_path,
        daemon_connection.remote_daemon_peer_id(),
        Some(daemon_connection),
    )
    .await
}

pub fn resolve_bound_daemon_peer_id(
    conn: &Connection,
    recorded_by: &str,
    peer_id: &str,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let endpoint_id: Option<String> = conn
        .query_row(
            "SELECT COALESCE(
                 (
                     SELECT endpoint_id
                     FROM peers_shared
                     WHERE recorded_by = ?1
                       AND lower(hex(transport_fingerprint)) = ?2
                       AND endpoint_id IS NOT NULL
                     LIMIT 1
                 ),
                 (
                     SELECT lower(hex(spki_fingerprint))
                     FROM peer_transport_bindings
                     WHERE recorded_by = ?1
                       AND peer_id = ?2
                     ORDER BY bound_at DESC
                     LIMIT 1
                 )
             )",
            params![recorded_by, peer_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten();
    Ok(endpoint_id)
}

fn has_active_local_bootstrap_session_auth(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id_b64: &str,
    actual_remote_daemon_peer_id: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let now = now_ms()? as i64;
    let remote_daemon_peer_id =
        decode_hex32(actual_remote_daemon_peer_id, "actual remote daemon peer id")?;
    let has_pending: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1
               AND invite_event_id = ?2
               AND expires_at > ?3
         )",
        params![recorded_by, invite_event_id_b64, now],
        |row| row.get(0),
    )?;
    if has_pending {
        return Ok(true);
    }

    let has_accepted: bool = conn.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM invite_bootstrap_trust
             WHERE recorded_by = ?1
               AND invite_event_id = ?2
               AND bootstrap_spki_fingerprint = ?3
               AND expires_at > ?4
         )",
        params![
            recorded_by,
            invite_event_id_b64,
            remote_daemon_peer_id.as_slice(),
            now
        ],
        |row| row.get(0),
    )?;
    Ok(has_accepted)
}

pub fn resolve_bootstrap_fallback_invite_for_daemon(
    conn: &Connection,
    recorded_by: &str,
    actual_remote_daemon_peer_id: &str,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let now = now_ms()? as i64;
    let remote_daemon_peer_id =
        decode_hex32(actual_remote_daemon_peer_id, "actual remote daemon peer id")?;
    let mut invite_event_ids = conn
        .prepare(
            "SELECT invite_event_id
             FROM pending_invite_bootstrap_trust
             WHERE recorded_by = ?1
               AND expected_bootstrap_spki_fingerprint = ?2
               AND expires_at > ?3
             UNION ALL
             SELECT invite_event_id
             FROM invite_bootstrap_trust
             WHERE recorded_by = ?1
               AND bootstrap_spki_fingerprint = ?2
               AND expires_at > ?3",
        )?
        .query_map(
            params![recorded_by, remote_daemon_peer_id.as_slice(), now],
            |row| row.get::<_, String>(0),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    invite_event_ids.sort();
    invite_event_ids.dedup();
    Ok(match invite_event_ids.as_slice() {
        [invite_event_id] => Some(invite_event_id.clone()),
        _ => None,
    })
}

fn load_outbound_session_auth_context(
    conn: &Connection,
    daemon_connection: Option<&DaemonConnection>,
    recorded_by: &str,
    remote_session_peer_id: &str,
    actual_remote_daemon_peer_id: &str,
    requested_plan: &OutboundSessionAuthPlan,
) -> Result<OutboundSessionAuthContext, Box<dyn std::error::Error + Send + Sync>> {
    let bootstrap_auth_still_valid = match requested_plan {
        OutboundSessionAuthPlan::InviteBootstrap { invite_event_id } => {
            has_active_local_bootstrap_session_auth(
                conn,
                recorded_by,
                invite_event_id,
                actual_remote_daemon_peer_id,
            )?
        }
        OutboundSessionAuthPlan::PeerShared { .. } => false,
    };
    let daemon_connection_admits_route = daemon_connection
        .map(|conn| conn.admits_session_route(recorded_by, remote_session_peer_id))
        .unwrap_or(false);

    let bound_daemon_matches_remote =
        resolve_bound_daemon_peer_id(conn, recorded_by, remote_session_peer_id)?
            .map(|bound| bound == actual_remote_daemon_peer_id)
            .unwrap_or(false);

    let remote_session_peer_authorized =
        match decode_hex32(remote_session_peer_id, "remote session peer id") {
            Ok(remote_session_peer_id_raw) => {
                is_authorized_for_tenant(conn, recorded_by, &remote_session_peer_id_raw)?
            }
            Err(_) => false,
        };

    Ok(OutboundSessionAuthContext {
        requested_plan: requested_plan.clone(),
        remote_session_peer_id: remote_session_peer_id.to_string(),
        bootstrap_auth_still_valid,
        daemon_connection_admits_route,
        bound_daemon_matches_remote,
        remote_session_peer_authorized,
    })
}

pub fn resolve_outbound_session_auth_plan(
    conn: &Connection,
    daemon_connection: Option<&DaemonConnection>,
    recorded_by: &str,
    remote_session_peer_id: &str,
    actual_remote_daemon_peer_id: &str,
    requested_plan: &OutboundSessionAuthPlan,
) -> Result<OutboundSessionAuthPlan, Box<dyn std::error::Error + Send + Sync>> {
    let context = load_outbound_session_auth_context(
        conn,
        daemon_connection,
        recorded_by,
        remote_session_peer_id,
        actual_remote_daemon_peer_id,
        requested_plan,
    )?;
    Ok(decide_outbound_session_auth_plan(&context))
}

pub fn resolve_bootstrap_inviter_peer_id(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id_b64: &str,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let invite_blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT blob
             FROM events
             WHERE event_id = ?1
             LIMIT 1",
            params![invite_event_id_b64],
            |row| row.get(0),
        )
        .optional()?;
    let Some(invite_blob) = invite_blob else {
        return Ok(None);
    };

    let signer_event_id = match parse_event(&invite_blob)? {
        ParsedEvent::Signed(event) => match parse_event(&event.payload)? {
            ParsedEvent::UserInvite(_) | ParsedEvent::DeviceInvite(_) => event.signer_event_id,
            other => {
                return Err(format!(
                    "invite event {invite_event_id_b64} has wrong inner type for bootstrap binding: {other:?}"
                )
                .into())
            }
        },
        ParsedEvent::UserInvite(_) | ParsedEvent::DeviceInvite(_) => return Ok(None),
        other => {
            return Err(format!(
                "invite event {invite_event_id_b64} has wrong type for bootstrap binding: {other:?}"
            )
            .into())
        }
    };
    let signer_event_id_b64 = event_id_to_base64(&signer_event_id);

    let signer_blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT blob
             FROM events
             WHERE event_id = ?1
             LIMIT 1",
            params![signer_event_id_b64],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(signer_blob) = signer_blob {
        return match parse_event(&signer_blob)? {
            ParsedEvent::PeerShared(event) => Ok(Some(hex::encode(
                spki_fingerprint_from_ed25519_pubkey(&event.public_key),
            ))),
            ParsedEvent::Signed(signed) => match parse_event(&signed.payload)? {
                ParsedEvent::PeerShared(event) => Ok(Some(hex::encode(
                    spki_fingerprint_from_ed25519_pubkey(&event.public_key),
                ))),
                other => Err(format!(
                    "invite signer {} resolved to non-peer_shared event: {other:?}",
                    signer_event_id_b64
                )
                .into()),
            },
            other => Err(format!(
                "invite signer {} resolved to non-peer_shared event: {other:?}",
                signer_event_id_b64
            )
            .into()),
        };
    }

    let projected_transport_peer_id: Option<String> = conn
        .query_row(
            "SELECT lower(hex(transport_fingerprint))
             FROM peers_shared
             WHERE recorded_by = ?1
               AND event_id = ?2
               AND length(transport_fingerprint) = 32
             LIMIT 1",
            params![recorded_by, signer_event_id_b64],
            |row| row.get(0),
        )
        .optional()?;
    Ok(projected_transport_peer_id)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rusqlite::params;
    use tokio::time::{timeout, Duration};

    use crate::crypto::{event_id_to_base64, spki_fingerprint_from_ed25519_pubkey};
    use crate::db::open_connection;
    use crate::db::transport_trust::{
        record_invite_bootstrap_trust, record_pending_invite_bootstrap_trust,
        record_transport_binding,
    };
    use crate::event_modules::{encode_event, ParsedEvent, UserInviteEvent};
    use crate::transport::{
        accept_daemon_connection, create_runtime_endpoint_for_tenants, dial_daemon_connection,
        ensure_daemon_identity_from_db, load_daemon_identity_from_db,
        multi_workspace::transport_sni, TransportEndpoint,
    };

    use super::*;

    fn store_test_daemon_identity(db_path: &str) -> String {
        ensure_daemon_identity_from_db(db_path)
            .expect("ensure daemon identity")
            .0
    }

    fn insert_local_peer_secret(
        db_path: &str,
        recorded_by: &str,
        signer_event_id: &[u8; 32],
        signing_key: &SigningKey,
    ) {
        let db = open_connection(db_path).expect("open peer-secret db");
        db.execute(
            "INSERT INTO peer_secrets
             (recorded_by, event_id, signer_event_id, private_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                recorded_by,
                "peer-secret-row",
                event_id_to_base64(signer_event_id),
                signing_key.to_bytes().to_vec(),
                1_i64
            ],
        )
        .expect("insert peer secret");
    }

    fn insert_authorized_peer_shared(
        db_path: &str,
        tenant_id: &str,
        signer_event_id: &[u8; 32],
        source_public_key: &[u8; 32],
        source_peer_id: &[u8; 32],
    ) {
        let db = open_connection(db_path).expect("open peer-shared db");
        db.execute(
            "INSERT INTO peers_shared
             (recorded_by, event_id, public_key, transport_fingerprint)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                tenant_id,
                event_id_to_base64(signer_event_id),
                source_public_key.as_slice(),
                source_peer_id.as_slice(),
            ],
        )
        .expect("insert peers_shared auth row");
    }

    fn insert_event_blob(db_path: &str, event_id_b64: &str, event_type: &str, blob: Vec<u8>) {
        let db = open_connection(db_path).expect("open events db");
        db.execute(
            "INSERT INTO events (event_id, event_type, blob, share_scope, created_at, inserted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![event_id_b64, event_type, blob, "shared", 1_i64, 1_i64],
        )
        .expect("insert event blob");
    }

    fn insert_invite_secret(
        db_path: &str,
        recorded_by: &str,
        invite_event_id_b64: &str,
        private_key: [u8; 32],
    ) {
        let db = open_connection(db_path).expect("open invite secret db");
        db.execute(
            "INSERT INTO invite_secrets
             (recorded_by, event_id, invite_event_id, private_key, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                recorded_by,
                format!("invite-secret-{invite_event_id_b64}"),
                invite_event_id_b64,
                private_key.to_vec(),
                1_i64
            ],
        )
        .expect("insert invite secret");
    }

    async fn connect_test_daemons(
        server_db_path: &str,
        client_db_path: &str,
    ) -> Result<
        (
            TransportEndpoint,
            TransportEndpoint,
            crate::transport::DaemonConnection,
            crate::transport::DaemonConnection,
            std::net::SocketAddr,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let server_ep =
            create_runtime_endpoint_for_tenants("127.0.0.1:0".parse().unwrap(), server_db_path)
                .await?;
        let client_ep =
            create_runtime_endpoint_for_tenants("127.0.0.1:0".parse().unwrap(), client_db_path)
                .await?;
        let server_peer_id = load_daemon_identity_from_db(server_db_path)?.0;
        let server_sni = transport_sni(&server_peer_id);
        let server_addr = server_ep.local_addr()?;
        let (accepted, dialed) = tokio::join!(
            accept_daemon_connection(&server_ep),
            dial_daemon_connection(&client_ep, server_addr, &server_sni)
        );
        let accepted = accepted?.expect("accepted provider");
        let dialed = dialed?;
        Ok((server_ep, client_ep, accepted, dialed, server_addr))
    }

    #[test]
    fn bootstrap_session_tenant_decision_accepts_unique_tenant_after_dedup() {
        let decision =
            decide_bootstrap_session_tenant(&BootstrapSessionTenantContext::CandidateTenants {
                tenant_ids: vec!["tenant-a".to_string(), "tenant-a".to_string()],
            });
        assert_eq!(
            decision,
            BootstrapSessionTenantDecision::Accept {
                tenant_id: "tenant-a".to_string(),
            }
        );
    }

    #[test]
    fn resolve_bootstrap_session_tenant_rejects_ambiguous_candidates() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("server.sqlite3");
        let db = open_connection(db_path.to_str().unwrap()).unwrap();
        crate::db::schema::create_tables(&db).unwrap();

        let invite_event_id = "invite-ambiguous";
        let daemon_fp = [0x44; 32];
        record_pending_invite_bootstrap_trust(
            &db,
            "tenant-a",
            invite_event_id,
            "workspace",
            &[0x11; 32],
        )
        .unwrap();
        record_invite_bootstrap_trust(
            &db,
            "tenant-b",
            "accepted-b",
            invite_event_id,
            "workspace",
            "",
            &daemon_fp,
        )
        .unwrap();

        let err = resolve_bootstrap_session_tenant(&db, invite_event_id, &daemon_fp)
            .expect_err("multiple local tenants must be ambiguous");
        assert!(
            err.to_string().contains("ambiguous"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn outbound_session_auth_planner_keeps_active_bootstrap_without_admitted_route() {
        let plan = decide_outbound_session_auth_plan(&OutboundSessionAuthContext {
            requested_plan: OutboundSessionAuthPlan::InviteBootstrap {
                invite_event_id: "invite-1".to_string(),
            },
            remote_session_peer_id: "peer-1".to_string(),
            bootstrap_auth_still_valid: true,
            daemon_connection_admits_route: false,
            bound_daemon_matches_remote: true,
            remote_session_peer_authorized: true,
        });
        assert_eq!(
            plan,
            OutboundSessionAuthPlan::InviteBootstrap {
                invite_event_id: "invite-1".to_string(),
            }
        );
    }

    #[test]
    fn outbound_session_auth_planner_upgrades_only_when_binding_and_auth_hold() {
        let plan = decide_outbound_session_auth_plan(&OutboundSessionAuthContext {
            requested_plan: OutboundSessionAuthPlan::InviteBootstrap {
                invite_event_id: "invite-1".to_string(),
            },
            remote_session_peer_id: "peer-1".to_string(),
            bootstrap_auth_still_valid: false,
            daemon_connection_admits_route: false,
            bound_daemon_matches_remote: true,
            remote_session_peer_authorized: true,
        });
        assert_eq!(
            plan,
            OutboundSessionAuthPlan::PeerShared {
                target_peer_id: "peer-1".to_string(),
            }
        );

        let no_upgrade = decide_outbound_session_auth_plan(&OutboundSessionAuthContext {
            requested_plan: OutboundSessionAuthPlan::InviteBootstrap {
                invite_event_id: "invite-1".to_string(),
            },
            remote_session_peer_id: "peer-1".to_string(),
            bootstrap_auth_still_valid: false,
            daemon_connection_admits_route: false,
            bound_daemon_matches_remote: false,
            remote_session_peer_authorized: true,
        });
        assert_eq!(
            no_upgrade,
            OutboundSessionAuthPlan::InviteBootstrap {
                invite_event_id: "invite-1".to_string(),
            }
        );
    }

    #[test]
    fn outbound_session_auth_planner_upgrades_active_bootstrap_after_route_admission() {
        let plan = decide_outbound_session_auth_plan(&OutboundSessionAuthContext {
            requested_plan: OutboundSessionAuthPlan::InviteBootstrap {
                invite_event_id: "invite-1".to_string(),
            },
            remote_session_peer_id: "peer-1".to_string(),
            bootstrap_auth_still_valid: true,
            daemon_connection_admits_route: true,
            bound_daemon_matches_remote: true,
            remote_session_peer_authorized: true,
        });
        assert_eq!(
            plan,
            OutboundSessionAuthPlan::PeerShared {
                target_peer_id: "peer-1".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn open_session_route_rejects_when_only_other_tenant_authorizes_remote_peer() {
        let server_temp = tempfile::tempdir().unwrap();
        let client_temp = tempfile::tempdir().unwrap();
        let server_db_path = server_temp.path().join("server.sqlite3");
        let client_db_path = client_temp.path().join("client.sqlite3");

        let server_daemon_peer_id = store_test_daemon_identity(server_db_path.to_str().unwrap());
        let client_daemon_peer_id = store_test_daemon_identity(client_db_path.to_str().unwrap());
        let client_daemon_peer_id_raw =
            decode_hex32(&client_daemon_peer_id, "client daemon peer id").unwrap();
        let server_daemon_peer_id_raw =
            decode_hex32(&server_daemon_peer_id, "server daemon peer id").unwrap();

        let source_signing_key = SigningKey::from_bytes(&[0x12; 32]);
        let source_public_key = source_signing_key.verifying_key().to_bytes();
        let source_peer_id_raw = spki_fingerprint_from_ed25519_pubkey(&source_public_key);
        let source_peer_id = hex::encode(source_peer_id_raw);
        let requested_tenant_id = hex::encode([0x66; 32]);
        let other_authorizing_tenant_id = hex::encode([0x77; 32]);

        insert_authorized_peer_shared(
            client_db_path.to_str().unwrap(),
            &source_peer_id,
            &[0x65; 32],
            &[0x65; 32],
            &[0x66; 32],
        );
        insert_authorized_peer_shared(
            server_db_path.to_str().unwrap(),
            &other_authorizing_tenant_id,
            &[0x55; 32],
            &source_public_key,
            &source_peer_id_raw,
        );

        let client_db = open_connection(client_db_path.to_str().unwrap()).unwrap();
        record_transport_binding(
            &client_db,
            &source_peer_id,
            &requested_tenant_id,
            &server_daemon_peer_id_raw,
        )
        .unwrap();
        drop(client_db);

        let server_db = open_connection(server_db_path.to_str().unwrap()).unwrap();
        record_transport_binding(
            &server_db,
            &other_authorizing_tenant_id,
            &source_peer_id,
            &client_daemon_peer_id_raw,
        )
        .unwrap();
        drop(server_db);

        let (_server_ep, _client_ep, server_daemon, client_daemon, _server_addr) =
            connect_test_daemons(
                server_db_path.to_str().unwrap(),
                client_db_path.to_str().unwrap(),
            )
            .await
            .expect("connect daemon endpoints");
        let (server_session_res, client_session_res) = tokio::join!(
            server_daemon.accept_inbound_session(),
            client_daemon.open_outbound_session(crate::transport::SessionClass::Range)
        );
        let mut server_session = server_session_res.expect("accept inbound session");
        let mut client_session = client_session_res.expect("open outbound session");

        let auth_plan = OutboundSessionAuthPlan::PeerShared {
            target_peer_id: requested_tenant_id.clone(),
        };
        let (outbound, inbound) = tokio::join!(
            send_outbound_session_auth(
                client_session.io.as_mut(),
                client_db_path.to_str().unwrap(),
                &source_peer_id,
                Some(&client_daemon),
                client_daemon.remote_daemon_peer_id(),
                Some(&server_daemon_peer_id),
                &auth_plan,
            ),
            async {
                let inbound = read_inbound_session_auth(
                    server_session.io.as_mut(),
                    server_db_path.to_str().unwrap(),
                    server_daemon.remote_daemon_peer_id(),
                )
                .await;
                if inbound.is_err() {
                    server_daemon
                        .connection()
                        .close(1u32.into(), b"expected auth rejection");
                }
                inbound
            },
        );
        let outbound_err =
            outbound.expect_err("outbound route auth should fail when server rejects");
        assert!(
            outbound_err.to_string().contains("expected auth rejection")
                || outbound_err.to_string().contains("connection lost"),
            "unexpected outbound auth error: {outbound_err}"
        );
        let err = inbound.expect_err("wrong target tenant must be rejected");
        assert!(
            err.to_string().contains("session route not admitted"),
            "unexpected auth error: {err}"
        );
    }

    #[test]
    fn resolve_outbound_session_auth_plan_keeps_bootstrap_without_peer_shared_authorization() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("client.sqlite3");
        let _daemon_peer_id = store_test_daemon_identity(db_path.to_str().unwrap());

        let recorded_by = hex::encode([0x11; 32]);
        let remote_session_peer_id = hex::encode([0x22; 32]);
        let remote_daemon_peer_id = hex::encode([0x33; 32]);
        let db = open_connection(db_path.to_str().unwrap()).unwrap();
        record_transport_binding(&db, &recorded_by, &remote_session_peer_id, &[0x33; 32]).unwrap();

        let plan = resolve_outbound_session_auth_plan(
            &db,
            None,
            &recorded_by,
            &remote_session_peer_id,
            &remote_daemon_peer_id,
            &OutboundSessionAuthPlan::InviteBootstrap {
                invite_event_id: "invite".to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            plan,
            OutboundSessionAuthPlan::InviteBootstrap {
                invite_event_id: "invite".to_string(),
            }
        );
    }

    #[test]
    fn resolve_outbound_session_auth_plan_upgrades_after_binding_auth_exists() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("client.sqlite3");
        let _daemon_peer_id = store_test_daemon_identity(db_path.to_str().unwrap());

        let recorded_by = hex::encode([0x44; 32]);
        let remote_session_peer_id = hex::encode([0x66; 32]);
        let remote_daemon_peer_id = hex::encode([0x77; 32]);

        insert_authorized_peer_shared(
            db_path.to_str().unwrap(),
            &recorded_by,
            &[0x88; 32],
            &[0x88; 32],
            &[0x66; 32],
        );

        let db = open_connection(db_path.to_str().unwrap()).unwrap();
        record_transport_binding(&db, &recorded_by, &remote_session_peer_id, &[0x77; 32]).unwrap();

        let plan = resolve_outbound_session_auth_plan(
            &db,
            None,
            &recorded_by,
            &remote_session_peer_id,
            &remote_daemon_peer_id,
            &OutboundSessionAuthPlan::InviteBootstrap {
                invite_event_id: "invite".to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            plan,
            OutboundSessionAuthPlan::PeerShared {
                target_peer_id: remote_session_peer_id,
            }
        );
    }

    #[tokio::test]
    async fn resolve_outbound_session_auth_plan_upgrades_after_daemon_route_is_admitted() {
        let server_temp = tempfile::tempdir().unwrap();
        let client_temp = tempfile::tempdir().unwrap();
        let server_db_path = server_temp.path().join("server.sqlite3");
        let client_db_path = client_temp.path().join("client.sqlite3");

        let server_daemon_peer_id = store_test_daemon_identity(server_db_path.to_str().unwrap());
        let server_daemon_peer_id_raw =
            decode_hex32(&server_daemon_peer_id, "server daemon peer id").unwrap();
        let _client_daemon_peer_id = store_test_daemon_identity(client_db_path.to_str().unwrap());

        let recorded_by = hex::encode([0xA4; 32]);
        let remote_session_peer_id = hex::encode([0xA5; 32]);

        insert_authorized_peer_shared(
            client_db_path.to_str().unwrap(),
            &recorded_by,
            &[0xA6; 32],
            &[0xA7; 32],
            &[0xA5; 32],
        );

        let client_db = open_connection(client_db_path.to_str().unwrap()).unwrap();
        record_transport_binding(
            &client_db,
            &recorded_by,
            &remote_session_peer_id,
            &server_daemon_peer_id_raw,
        )
        .unwrap();
        record_invite_bootstrap_trust(
            &client_db,
            &recorded_by,
            "accepted-1",
            "invite-bootstrap",
            "ws-1",
            "127.0.0.1:1",
            &server_daemon_peer_id_raw,
        )
        .unwrap();
        drop(client_db);

        let (_server_ep, _client_ep, _server_daemon, client_daemon, _server_addr) =
            connect_test_daemons(
                server_db_path.to_str().unwrap(),
                client_db_path.to_str().unwrap(),
            )
            .await
            .expect("connect daemon endpoints");
        client_daemon.remember_admitted_session_route(&recorded_by, &remote_session_peer_id);

        let client_db = open_connection(client_db_path.to_str().unwrap()).unwrap();
        let plan = resolve_outbound_session_auth_plan(
            &client_db,
            Some(&client_daemon),
            &recorded_by,
            &remote_session_peer_id,
            &server_daemon_peer_id,
            &OutboundSessionAuthPlan::InviteBootstrap {
                invite_event_id: "invite-bootstrap".to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            plan,
            OutboundSessionAuthPlan::PeerShared {
                target_peer_id: remote_session_peer_id,
            }
        );
    }

    #[test]
    fn resolve_outbound_session_auth_plan_keeps_peer_shared_when_exact_bootstrap_exists() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("client.sqlite3");
        let _daemon_peer_id = store_test_daemon_identity(db_path.to_str().unwrap());

        let recorded_by = hex::encode([0x91; 32]);
        let remote_session_peer_id = hex::encode([0x92; 32]);
        let remote_daemon_peer_id = hex::encode([0x93; 32]);

        let db = open_connection(db_path.to_str().unwrap()).unwrap();
        record_invite_bootstrap_trust(
            &db,
            &recorded_by,
            "accepted-1",
            "invite-bootstrap",
            "ws-1",
            "127.0.0.1:1",
            &[0x93; 32],
        )
        .unwrap();

        let plan = resolve_outbound_session_auth_plan(
            &db,
            None,
            &recorded_by,
            &remote_session_peer_id,
            &remote_daemon_peer_id,
            &OutboundSessionAuthPlan::PeerShared {
                target_peer_id: remote_session_peer_id.clone(),
            },
        )
        .unwrap();

        assert_eq!(
            plan,
            OutboundSessionAuthPlan::PeerShared {
                target_peer_id: remote_session_peer_id,
            }
        );
    }

    #[test]
    fn resolve_outbound_session_auth_plan_keeps_peer_shared_until_connection_route_is_admitted() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("client.sqlite3");
        let _daemon_peer_id = store_test_daemon_identity(db_path.to_str().unwrap());

        let recorded_by = hex::encode([0x97; 32]);
        let remote_session_peer_id = hex::encode([0x98; 32]);
        let remote_daemon_peer_id = hex::encode([0x99; 32]);

        insert_authorized_peer_shared(
            db_path.to_str().unwrap(),
            &recorded_by,
            &[0x9A; 32],
            &[0x9B; 32],
            &[0x98; 32],
        );

        let db = open_connection(db_path.to_str().unwrap()).unwrap();
        record_transport_binding(&db, &recorded_by, &remote_session_peer_id, &[0x99; 32]).unwrap();
        record_invite_bootstrap_trust(
            &db,
            &recorded_by,
            "accepted-1",
            "invite-bootstrap",
            "ws-1",
            "127.0.0.1:1",
            &[0x99; 32],
        )
        .unwrap();

        let plan = resolve_outbound_session_auth_plan(
            &db,
            None,
            &recorded_by,
            &remote_session_peer_id,
            &remote_daemon_peer_id,
            &OutboundSessionAuthPlan::PeerShared {
                target_peer_id: remote_session_peer_id.clone(),
            },
        )
        .unwrap();

        assert_eq!(
            plan,
            OutboundSessionAuthPlan::PeerShared {
                target_peer_id: remote_session_peer_id,
            }
        );
    }

    #[test]
    fn resolve_outbound_session_auth_plan_keeps_peer_shared_when_pending_bootstrap_exists() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("client.sqlite3");
        let _daemon_peer_id = store_test_daemon_identity(db_path.to_str().unwrap());

        let recorded_by = hex::encode([0x94; 32]);
        let remote_session_peer_id = hex::encode([0x95; 32]);
        let remote_daemon_peer_id = hex::encode([0x96; 32]);

        let db = open_connection(db_path.to_str().unwrap()).unwrap();
        record_pending_invite_bootstrap_trust(
            &db,
            &recorded_by,
            "pending-bootstrap",
            "ws-1",
            &[0x96; 32],
        )
        .unwrap();

        let plan = resolve_outbound_session_auth_plan(
            &db,
            None,
            &recorded_by,
            &remote_session_peer_id,
            &remote_daemon_peer_id,
            &OutboundSessionAuthPlan::PeerShared {
                target_peer_id: remote_session_peer_id.clone(),
            },
        )
        .unwrap();

        assert_eq!(
            plan,
            OutboundSessionAuthPlan::PeerShared {
                target_peer_id: remote_session_peer_id,
            }
        );
    }

    #[test]
    fn resolve_bootstrap_fallback_invite_for_daemon_finds_exact_pending_match() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("client.sqlite3");
        let _daemon_peer_id = store_test_daemon_identity(db_path.to_str().unwrap());

        let recorded_by = hex::encode([0xB1; 32]);
        let remote_daemon_peer_id = hex::encode([0xB2; 32]);

        let db = open_connection(db_path.to_str().unwrap()).unwrap();
        record_pending_invite_bootstrap_trust(
            &db,
            &recorded_by,
            "pending-bootstrap",
            "ws-1",
            &[0xB2; 32],
        )
        .unwrap();

        let invite =
            resolve_bootstrap_fallback_invite_for_daemon(&db, &recorded_by, &remote_daemon_peer_id)
                .unwrap();

        assert_eq!(invite.as_deref(), Some("pending-bootstrap"));
    }

    #[tokio::test]
    async fn invite_bootstrap_auth_stays_valid_for_later_sessions_on_same_daemon_connection() {
        let server_temp = tempfile::tempdir().unwrap();
        let client_temp = tempfile::tempdir().unwrap();
        let server_db_path = server_temp.path().join("server.sqlite3");
        let client_db_path = client_temp.path().join("client.sqlite3");

        let server_daemon_peer_id = store_test_daemon_identity(server_db_path.to_str().unwrap());
        let client_daemon_peer_id = store_test_daemon_identity(client_db_path.to_str().unwrap());

        let source_signing_key = SigningKey::from_bytes(&[0x31; 32]);
        let source_public_key = source_signing_key.verifying_key().to_bytes();
        let source_peer_id_raw = spki_fingerprint_from_ed25519_pubkey(&source_public_key);
        let source_peer_id = hex::encode(source_peer_id_raw);
        let signer_event_id = [0x32; 32];
        let target_tenant_id = hex::encode([0x33; 32]);

        let invite_signing_key = SigningKey::from_bytes(&[0x41; 32]);
        let invite_event_id_raw = [0x42; 32];
        let invite_event_id_b64 = event_id_to_base64(&invite_event_id_raw);
        let invite_blob = encode_event(&ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: 1,
            public_key: invite_signing_key.verifying_key().to_bytes(),
            workspace_id: [0x43; 32],
            authority_event_id: [0x44; 32],
        }))
        .expect("encode invite");

        insert_local_peer_secret(
            client_db_path.to_str().unwrap(),
            &source_peer_id,
            &signer_event_id,
            &source_signing_key,
        );
        insert_event_blob(
            client_db_path.to_str().unwrap(),
            &invite_event_id_b64,
            "user_invite_shared",
            invite_blob.clone(),
        );
        insert_event_blob(
            server_db_path.to_str().unwrap(),
            &invite_event_id_b64,
            "user_invite_shared",
            invite_blob,
        );
        insert_invite_secret(
            client_db_path.to_str().unwrap(),
            &source_peer_id,
            &invite_event_id_b64,
            invite_signing_key.to_bytes(),
        );

        let server_db = open_connection(server_db_path.to_str().unwrap()).unwrap();
        record_pending_invite_bootstrap_trust(
            &server_db,
            &target_tenant_id,
            &invite_event_id_b64,
            "workspace",
            &source_peer_id_raw,
        )
        .unwrap();
        drop(server_db);

        let (_server_ep, _client_ep, server_daemon, client_daemon, _server_addr) =
            connect_test_daemons(
                server_db_path.to_str().unwrap(),
                client_db_path.to_str().unwrap(),
            )
            .await
            .expect("connect daemon endpoints");

        let auth_plan = OutboundSessionAuthPlan::InviteBootstrap {
            invite_event_id: invite_event_id_b64.clone(),
        };

        let (server_session_res, client_session_res) = tokio::join!(
            server_daemon.accept_inbound_session(),
            client_daemon.open_outbound_session(crate::transport::SessionClass::Range)
        );
        let mut server_session = server_session_res.expect("accept first inbound session");
        let mut client_session = client_session_res.expect("open first outbound session");
        let (first_outbound, first_inbound) = tokio::join!(
            send_outbound_session_auth(
                client_session.io.as_mut(),
                client_db_path.to_str().unwrap(),
                &source_peer_id,
                Some(&client_daemon),
                client_daemon.remote_daemon_peer_id(),
                Some(&server_daemon_peer_id),
                &auth_plan,
            ),
            async {
                let inbound = read_inbound_session_auth_for_connection(
                    server_session.io.as_mut(),
                    server_db_path.to_str().unwrap(),
                    &server_daemon,
                )
                .await?;
                send_inbound_session_auth_ack(server_session.io.as_mut(), &inbound.tenant_id)
                    .await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(inbound)
            },
        );
        let first_outbound = first_outbound.expect("first outbound invite auth");
        let first_inbound = first_inbound.expect("first inbound invite auth");
        assert!(first_outbound.used_bootstrap_auth);
        assert!(first_inbound.used_bootstrap_auth);
        assert_eq!(first_inbound.tenant_id, target_tenant_id);
        assert_eq!(first_inbound.remote_daemon_peer_id, client_daemon_peer_id);

        let server_db = open_connection(server_db_path.to_str().unwrap()).unwrap();
        server_db
            .execute("DELETE FROM pending_invite_bootstrap_trust", [])
            .unwrap();
        drop(server_db);

        let (server_session_res, client_session_res) = tokio::join!(
            server_daemon.accept_inbound_session(),
            client_daemon.open_outbound_session(crate::transport::SessionClass::Range)
        );
        let mut server_session = server_session_res.expect("accept second inbound session");
        let mut client_session = client_session_res.expect("open second outbound session");
        let (second_outbound, second_inbound) = tokio::join!(
            send_outbound_session_auth(
                client_session.io.as_mut(),
                client_db_path.to_str().unwrap(),
                &source_peer_id,
                Some(&client_daemon),
                client_daemon.remote_daemon_peer_id(),
                Some(&server_daemon_peer_id),
                &auth_plan,
            ),
            async {
                let inbound = read_inbound_session_auth_for_connection(
                    server_session.io.as_mut(),
                    server_db_path.to_str().unwrap(),
                    &server_daemon,
                )
                .await?;
                send_inbound_session_auth_ack(server_session.io.as_mut(), &inbound.tenant_id)
                    .await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(inbound)
            },
        );
        let second_outbound = second_outbound.expect("second outbound invite auth");
        let second_inbound = second_inbound.expect("second inbound invite auth");
        assert!(second_outbound.used_bootstrap_auth);
        assert!(second_inbound.used_bootstrap_auth);
        assert_eq!(second_inbound.tenant_id, target_tenant_id);
    }

    #[tokio::test]
    async fn invite_bootstrap_auth_accepts_accepted_bootstrap_trust_without_pending_row() {
        let server_temp = tempfile::tempdir().unwrap();
        let client_temp = tempfile::tempdir().unwrap();
        let server_db_path = server_temp.path().join("server.sqlite3");
        let client_db_path = client_temp.path().join("client.sqlite3");

        let server_daemon_peer_id = store_test_daemon_identity(server_db_path.to_str().unwrap());
        let client_daemon_peer_id = store_test_daemon_identity(client_db_path.to_str().unwrap());
        let client_daemon_peer_id_raw =
            decode_hex32(&client_daemon_peer_id, "client daemon peer id").unwrap();

        let source_signing_key = SigningKey::from_bytes(&[0x51; 32]);
        let source_public_key = source_signing_key.verifying_key().to_bytes();
        let source_peer_id_raw = spki_fingerprint_from_ed25519_pubkey(&source_public_key);
        let source_peer_id = hex::encode(source_peer_id_raw);
        let signer_event_id = [0x52; 32];
        let target_tenant_id = hex::encode([0x53; 32]);

        let invite_signing_key = SigningKey::from_bytes(&[0x61; 32]);
        let invite_event_id_raw = [0x62; 32];
        let invite_event_id_b64 = event_id_to_base64(&invite_event_id_raw);
        let invite_blob = encode_event(&ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: 1,
            public_key: invite_signing_key.verifying_key().to_bytes(),
            workspace_id: [0x63; 32],
            authority_event_id: [0x64; 32],
        }))
        .expect("encode invite");

        insert_local_peer_secret(
            client_db_path.to_str().unwrap(),
            &source_peer_id,
            &signer_event_id,
            &source_signing_key,
        );
        insert_event_blob(
            client_db_path.to_str().unwrap(),
            &invite_event_id_b64,
            "user_invite_shared",
            invite_blob.clone(),
        );
        insert_event_blob(
            server_db_path.to_str().unwrap(),
            &invite_event_id_b64,
            "user_invite_shared",
            invite_blob,
        );
        insert_invite_secret(
            client_db_path.to_str().unwrap(),
            &source_peer_id,
            &invite_event_id_b64,
            invite_signing_key.to_bytes(),
        );

        let server_db = open_connection(server_db_path.to_str().unwrap()).unwrap();
        record_invite_bootstrap_trust(
            &server_db,
            &target_tenant_id,
            "invite-accepted",
            &invite_event_id_b64,
            "workspace",
            "",
            &client_daemon_peer_id_raw,
        )
        .unwrap();
        drop(server_db);

        let (_server_ep, _client_ep, server_daemon, client_daemon, _server_addr) =
            connect_test_daemons(
                server_db_path.to_str().unwrap(),
                client_db_path.to_str().unwrap(),
            )
            .await
            .expect("connect daemon endpoints");

        let (server_session_res, client_session_res) = tokio::join!(
            server_daemon.accept_inbound_session(),
            client_daemon.open_outbound_session(crate::transport::SessionClass::Range)
        );
        let mut server_session = server_session_res.expect("accept inbound session");
        let mut client_session = client_session_res.expect("open outbound session");
        let auth_plan = OutboundSessionAuthPlan::InviteBootstrap {
            invite_event_id: invite_event_id_b64.clone(),
        };

        let (outbound, inbound) = tokio::join!(
            send_outbound_session_auth(
                client_session.io.as_mut(),
                client_db_path.to_str().unwrap(),
                &source_peer_id,
                Some(&client_daemon),
                client_daemon.remote_daemon_peer_id(),
                Some(&server_daemon_peer_id),
                &auth_plan,
            ),
            async {
                let inbound = read_inbound_session_auth(
                    server_session.io.as_mut(),
                    server_db_path.to_str().unwrap(),
                    server_daemon.remote_daemon_peer_id(),
                )
                .await?;
                send_inbound_session_auth_ack(server_session.io.as_mut(), &inbound.tenant_id)
                    .await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(inbound)
            },
        );

        let outbound = outbound.expect("outbound invite auth");
        let inbound = inbound.expect("inbound invite auth");
        assert!(outbound.used_bootstrap_auth);
        assert!(inbound.used_bootstrap_auth);
        assert_eq!(inbound.tenant_id, target_tenant_id);
        assert_eq!(inbound.remote_daemon_peer_id, client_daemon_peer_id);
    }

    #[tokio::test]
    async fn invite_bootstrap_auth_rejects_when_bootstrap_trust_targets_other_daemon() {
        let server_temp = tempfile::tempdir().unwrap();
        let client_temp = tempfile::tempdir().unwrap();
        let server_db_path = server_temp.path().join("server.sqlite3");
        let client_db_path = client_temp.path().join("client.sqlite3");

        let server_daemon_peer_id = store_test_daemon_identity(server_db_path.to_str().unwrap());
        let _client_daemon_peer_id = store_test_daemon_identity(client_db_path.to_str().unwrap());

        let source_signing_key = SigningKey::from_bytes(&[0x81; 32]);
        let source_public_key = source_signing_key.verifying_key().to_bytes();
        let source_peer_id_raw = spki_fingerprint_from_ed25519_pubkey(&source_public_key);
        let source_peer_id = hex::encode(source_peer_id_raw);
        let signer_event_id = [0x82; 32];
        let target_tenant_id = hex::encode([0x83; 32]);

        let invite_signing_key = SigningKey::from_bytes(&[0x91; 32]);
        let invite_event_id_raw = [0x92; 32];
        let invite_event_id_b64 = event_id_to_base64(&invite_event_id_raw);
        let invite_blob = encode_event(&ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: 1,
            public_key: invite_signing_key.verifying_key().to_bytes(),
            workspace_id: [0x93; 32],
            authority_event_id: [0x94; 32],
        }))
        .expect("encode invite");

        insert_local_peer_secret(
            client_db_path.to_str().unwrap(),
            &source_peer_id,
            &signer_event_id,
            &source_signing_key,
        );
        insert_event_blob(
            client_db_path.to_str().unwrap(),
            &invite_event_id_b64,
            "user_invite_shared",
            invite_blob.clone(),
        );
        insert_event_blob(
            server_db_path.to_str().unwrap(),
            &invite_event_id_b64,
            "user_invite_shared",
            invite_blob,
        );
        insert_invite_secret(
            client_db_path.to_str().unwrap(),
            &source_peer_id,
            &invite_event_id_b64,
            invite_signing_key.to_bytes(),
        );

        let wrong_daemon = [0xEE; 32];
        let server_db = open_connection(server_db_path.to_str().unwrap()).unwrap();
        record_invite_bootstrap_trust(
            &server_db,
            &target_tenant_id,
            "invite-accepted",
            &invite_event_id_b64,
            "workspace",
            "",
            &wrong_daemon,
        )
        .unwrap();
        drop(server_db);

        let (_server_ep, _client_ep, server_daemon, client_daemon, _server_addr) =
            connect_test_daemons(
                server_db_path.to_str().unwrap(),
                client_db_path.to_str().unwrap(),
            )
            .await
            .expect("connect daemon endpoints");

        let (server_session_res, client_session_res) = tokio::join!(
            server_daemon.accept_inbound_session(),
            client_daemon.open_outbound_session(crate::transport::SessionClass::Range)
        );
        let mut server_session = server_session_res.expect("accept inbound session");
        let mut client_session = client_session_res.expect("open outbound session");
        let auth_plan = OutboundSessionAuthPlan::InviteBootstrap {
            invite_event_id: invite_event_id_b64.clone(),
        };

        let (outbound, inbound) = tokio::join!(
            send_outbound_session_auth(
                client_session.io.as_mut(),
                client_db_path.to_str().unwrap(),
                &source_peer_id,
                Some(&client_daemon),
                client_daemon.remote_daemon_peer_id(),
                Some(&server_daemon_peer_id),
                &auth_plan,
            ),
            async {
                let inbound = read_inbound_session_auth(
                    server_session.io.as_mut(),
                    server_db_path.to_str().unwrap(),
                    server_daemon.remote_daemon_peer_id(),
                )
                .await;
                if inbound.is_err() {
                    server_daemon
                        .connection()
                        .close(1u32.into(), b"expected bootstrap rejection");
                }
                inbound
            },
        );

        let outbound_err = outbound.expect_err("bootstrap auth should fail for the wrong daemon");
        assert!(
            outbound_err
                .to_string()
                .contains("expected bootstrap rejection")
                || outbound_err.to_string().contains("connection lost"),
            "unexpected outbound auth error: {outbound_err}"
        );
        let err = inbound.expect_err("wrong-daemon bootstrap trust must be rejected");
        assert!(
            err.to_string().contains("no active bootstrap trust"),
            "unexpected inbound auth error: {err}"
        );
    }

    #[tokio::test]
    async fn open_session_route_accepts_known_daemon_binding_without_local_signer() {
        let server_temp = tempfile::tempdir().unwrap();
        let client_temp = tempfile::tempdir().unwrap();
        let server_db_path = server_temp.path().join("server.sqlite3");
        let client_db_path = client_temp.path().join("client.sqlite3");

        let server_daemon_peer_id = store_test_daemon_identity(server_db_path.to_str().unwrap());
        let client_daemon_peer_id = store_test_daemon_identity(client_db_path.to_str().unwrap());
        let server_daemon_peer_id_raw =
            decode_hex32(&server_daemon_peer_id, "server daemon peer id").unwrap();
        let client_daemon_peer_id_raw =
            decode_hex32(&client_daemon_peer_id, "client daemon peer id").unwrap();

        let source_signing_key = SigningKey::from_bytes(&[0x71; 32]);
        let source_public_key = source_signing_key.verifying_key().to_bytes();
        let source_peer_id_raw = spki_fingerprint_from_ed25519_pubkey(&source_public_key);
        let source_peer_id = hex::encode(source_peer_id_raw);
        let target_tenant_id_raw = [0x72; 32];
        let target_tenant_id = hex::encode(target_tenant_id_raw);

        insert_authorized_peer_shared(
            client_db_path.to_str().unwrap(),
            &source_peer_id,
            &[0x73; 32],
            &[0x74; 32],
            &target_tenant_id_raw,
        );
        insert_authorized_peer_shared(
            server_db_path.to_str().unwrap(),
            &target_tenant_id,
            &[0x75; 32],
            &source_public_key,
            &source_peer_id_raw,
        );

        let client_db = open_connection(client_db_path.to_str().unwrap()).unwrap();
        record_transport_binding(
            &client_db,
            &source_peer_id,
            &target_tenant_id,
            &server_daemon_peer_id_raw,
        )
        .unwrap();
        drop(client_db);

        let server_db = open_connection(server_db_path.to_str().unwrap()).unwrap();
        record_transport_binding(
            &server_db,
            &target_tenant_id,
            &source_peer_id,
            &client_daemon_peer_id_raw,
        )
        .unwrap();
        drop(server_db);

        let (_server_ep, _client_ep, server_daemon, client_daemon, _server_addr) = timeout(
            Duration::from_secs(10),
            connect_test_daemons(
                server_db_path.to_str().unwrap(),
                client_db_path.to_str().unwrap(),
            ),
        )
        .await
        .expect("connect daemon endpoints timed out")
        .expect("connect daemon endpoints");
        let (server_session_res, client_session_res) = timeout(Duration::from_secs(10), async {
            tokio::join!(
                server_daemon.accept_inbound_session(),
                client_daemon.open_outbound_session(crate::transport::SessionClass::Range)
            )
        })
        .await
        .expect("open/accept session timed out");
        let mut server_session = server_session_res.expect("accept inbound session");
        let mut client_session = client_session_res.expect("open outbound session");

        let auth_plan = OutboundSessionAuthPlan::PeerShared {
            target_peer_id: target_tenant_id.clone(),
        };
        let outbound_fut = async {
            timeout(
                Duration::from_secs(10),
                send_outbound_session_auth(
                    client_session.io.as_mut(),
                    client_db_path.to_str().unwrap(),
                    &source_peer_id,
                    Some(&client_daemon),
                    client_daemon.remote_daemon_peer_id(),
                    Some(&server_daemon_peer_id),
                    &auth_plan,
                ),
            )
            .await
            .map_err(|_| "outbound route auth timed out")?
        };
        let inbound_fut = async {
            let inbound = timeout(
                Duration::from_secs(10),
                read_inbound_session_auth_for_connection(
                    server_session.io.as_mut(),
                    server_db_path.to_str().unwrap(),
                    &server_daemon,
                ),
            )
            .await
            .map_err(|_| "inbound route auth timed out")??;
            timeout(
                Duration::from_secs(10),
                send_inbound_session_auth_ack(server_session.io.as_mut(), &inbound.tenant_id),
            )
            .await
            .map_err(|_| "inbound route auth ack timed out")??;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(inbound)
        };
        let (outbound, inbound) = tokio::join!(outbound_fut, inbound_fut);

        let outbound = outbound.expect("route-only outbound auth");
        let inbound = inbound.expect("route-only inbound auth");
        assert_eq!(outbound.session_peer_id, target_tenant_id);
        assert_eq!(
            outbound.canonical_remote_peer_id.as_deref(),
            Some(target_tenant_id.as_str())
        );
        assert_eq!(outbound.remote_daemon_peer_id, server_daemon_peer_id);
        assert!(!outbound.used_bootstrap_auth);
        assert_eq!(inbound.tenant_id, target_tenant_id);
        assert_eq!(inbound.remote_peer_id, source_peer_id);
        assert_eq!(inbound.remote_daemon_peer_id, client_daemon_peer_id);
        assert!(!inbound.used_bootstrap_auth);
    }
}
