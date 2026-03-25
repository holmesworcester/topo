use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OptionalExtension};

use crate::crypto::{
    event_id_to_base64, sign_event_bytes, spki_fingerprint_from_ed25519_pubkey,
    verify_ed25519_signature,
};
use crate::db::open_connection;
use crate::db::transport_trust::is_authorized_for_tenant;
use crate::event_modules::{parse_event, ParsedEvent};
use crate::protocol::{
    encode_frame, parse_frame, Frame, OpenSessionAuthAck, OpenSessionAuthInvite,
    OpenSessionAuthPeerShared,
};

use super::{load_daemon_identity_from_db, peer_identity_from_connection};

pub const MAX_SESSION_AUTH_TTL_MS: u64 = 5 * 60 * 1000;
const SESSION_AUTH_CLOCK_SKEW_MS: u64 = 30 * 1000;
const MAX_SESSION_AUTH_FRAME_BYTES: usize = 4096;

const PEER_SHARED_SIGNING_DOMAIN: &[u8] = b"poc7-session-auth-v1-peer-shared";
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

fn encode_peer_shared_signing_bytes(auth: &OpenSessionAuthPeerShared) -> Vec<u8> {
    let mut buf = Vec::with_capacity(PEER_SHARED_SIGNING_DOMAIN.len() + 32 * 5 + 8);
    buf.extend_from_slice(PEER_SHARED_SIGNING_DOMAIN);
    buf.extend_from_slice(&auth.source_peer_id);
    buf.extend_from_slice(&auth.target_tenant_id);
    buf.extend_from_slice(&auth.signer_event_id);
    buf.extend_from_slice(&auth.local_daemon_peer_id);
    buf.extend_from_slice(&auth.remote_daemon_peer_id);
    buf.extend_from_slice(&auth.expires_at_ms.to_le_bytes());
    buf
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
        ParsedEvent::UserInvite(event) => Ok(event.public_key),
        ParsedEvent::DeviceInvite(event) => Ok(event.public_key),
        other => {
            Err(format!("invite event {invite_event_id_b64} has wrong type: {other:?}").into())
        }
    }
}

fn load_peer_shared_signer_public_key(
    conn: &Connection,
    recorded_by: &str,
    signer_event_id_b64: &str,
    source_peer_id: &[u8; 32],
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let public_key: Vec<u8> = conn
        .query_row(
            "SELECT p.public_key
             FROM peers_shared p
             WHERE p.recorded_by = ?1
               AND p.event_id = ?2
               AND p.transport_fingerprint = ?3
               AND NOT EXISTS (
                   SELECT 1 FROM removed_entities r
                   WHERE r.recorded_by = p.recorded_by
                     AND r.target_event_id = p.event_id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM removed_entities r
                   WHERE r.recorded_by = p.recorded_by
                     AND p.user_event_id IS NOT NULL
                     AND r.target_event_id = p.user_event_id
                     AND r.removal_type = 'user'
               )
             LIMIT 1",
            params![recorded_by, signer_event_id_b64, source_peer_id.as_slice()],
            |row| row.get(0),
        )
        .optional()?
        .ok_or_else(|| {
            format!(
                "remote peer {} signer {} is not projected in tenant {}",
                hex::encode(source_peer_id),
                signer_event_id_b64,
                recorded_by
            )
        })?;
    let key_arr: [u8; 32] = public_key
        .try_into()
        .map_err(|_| "peer_shared public_key is not 32 bytes")?;
    Ok(key_arr)
}

fn resolve_pending_bootstrap_tenant(
    conn: &Connection,
    invite_event_id_b64: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let now = now_ms()? as i64;
    let mut stmt = conn.prepare(
        "SELECT recorded_by
         FROM pending_invite_bootstrap_trust
         WHERE invite_event_id = ?1
           AND expires_at > ?2
         ORDER BY recorded_by ASC",
    )?;
    let tenant_ids = stmt
        .query_map(params![invite_event_id_b64, now], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    match tenant_ids.as_slice() {
        [] => Err(format!(
            "no active pending bootstrap trust for invite {}",
            invite_event_id_b64
        )
        .into()),
        [tenant_id] => Ok(tenant_id.clone()),
        _ => Err(format!(
            "invite {} resolves to multiple local tenants; bootstrap auth is ambiguous",
            invite_event_id_b64
        )
        .into()),
    }
}

async fn send_auth_frame(
    conn: &quinn::Connection,
    frame: &Frame,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let encoded = encode_frame(frame);
    let mut send = conn.open_uni().await?;
    send.write_all(&encoded).await?;
    send.finish()?;
    Ok(())
}

async fn read_auth_ack(
    conn: &quinn::Connection,
) -> Result<OpenSessionAuthAck, Box<dyn std::error::Error + Send + Sync>> {
    let mut recv = conn.accept_uni().await?;
    let bytes = recv.read_to_end(MAX_SESSION_AUTH_FRAME_BYTES).await?;
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
    conn: &quinn::Connection,
    tenant_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let target_tenant_id = decode_hex32(tenant_id, "tenant_id")?;
    send_auth_frame(
        conn,
        &Frame::OpenSessionAuthAck {
            ack: OpenSessionAuthAck { target_tenant_id },
        },
    )
    .await
}

pub async fn send_outbound_session_auth(
    conn: &quinn::Connection,
    db_path: &str,
    recorded_by: &str,
    expected_remote_daemon_peer_id: Option<&str>,
    plan: &OutboundSessionAuthPlan,
) -> Result<OutboundSessionAuthResult, Box<dyn std::error::Error + Send + Sync>> {
    let actual_remote_daemon_peer_id =
        peer_identity_from_connection(conn).ok_or("missing remote daemon identity from TLS")?;
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
            let (signer_event_id, signing_key) =
                crate::event_modules::peer_shared::load_local_peer_signer_required(
                    &db,
                    recorded_by,
                )?;
            let mut auth = OpenSessionAuthPeerShared {
                source_peer_id,
                target_tenant_id,
                signer_event_id,
                local_daemon_peer_id: local_daemon_peer_id_raw,
                remote_daemon_peer_id: remote_daemon_peer_id_raw,
                expires_at_ms,
                signature: [0u8; 64],
            };
            let signing_bytes = encode_peer_shared_signing_bytes(&auth);
            auth.signature = sign_event_bytes(&signing_key, &signing_bytes);
            send_auth_frame(conn, &Frame::OpenSessionAuthPeerShared { auth }).await?;
            let ack = read_auth_ack(conn).await?;
            let ack_target_tenant_id = hex::encode(ack.target_tenant_id);
            if ack_target_tenant_id != *target_peer_id {
                return Err(format!(
                    "session auth ack target mismatch: expected {}, got {}",
                    target_peer_id, ack_target_tenant_id
                )
                .into());
            }
            Ok(OutboundSessionAuthResult {
                session_peer_id: ack_target_tenant_id.clone(),
                canonical_remote_peer_id: Some(ack_target_tenant_id),
                remote_daemon_peer_id: actual_remote_daemon_peer_id,
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
            send_auth_frame(conn, &Frame::OpenSessionAuthInvite { auth }).await?;
            let ack = read_auth_ack(conn).await?;
            let canonical_remote_peer_id = hex::encode(ack.target_tenant_id);
            Ok(OutboundSessionAuthResult {
                session_peer_id: canonical_remote_peer_id.clone(),
                canonical_remote_peer_id: Some(canonical_remote_peer_id),
                remote_daemon_peer_id: actual_remote_daemon_peer_id,
                used_bootstrap_auth: true,
            })
        }
    }
}

pub async fn read_inbound_session_auth(
    conn: &quinn::Connection,
    db_path: &str,
) -> Result<InboundSessionAuthContext, Box<dyn std::error::Error + Send + Sync>> {
    let mut recv = conn.accept_uni().await?;
    let bytes = recv.read_to_end(MAX_SESSION_AUTH_FRAME_BYTES).await?;
    let (frame, consumed) = parse_frame(&bytes)?;
    if consumed != bytes.len() {
        return Err("session auth frame contained trailing bytes".into());
    }

    let actual_remote_daemon_peer_id =
        peer_identity_from_connection(conn).ok_or("missing remote daemon identity from TLS")?;
    let actual_remote_daemon_peer_id_raw =
        decode_hex32(&actual_remote_daemon_peer_id, "remote daemon peer id")?;
    let (local_daemon_peer_id, _cert, _key) = load_daemon_identity_from_db(db_path)?;
    let local_daemon_peer_id_raw = decode_hex32(&local_daemon_peer_id, "local daemon peer id")?;
    let db = open_connection(db_path)?;

    match frame {
        Frame::OpenSessionAuthPeerShared { auth } => {
            validate_expiry(auth.expires_at_ms)?;
            ensure_daemon_binding(
                &auth.remote_daemon_peer_id,
                &auth.local_daemon_peer_id,
                &local_daemon_peer_id_raw,
                &actual_remote_daemon_peer_id_raw,
            )?;
            let tenant_id = hex::encode(auth.target_tenant_id);
            let remote_peer_id = hex::encode(auth.source_peer_id);
            let signer_event_id_b64 = event_id_to_base64(&auth.signer_event_id);
            let signer_public_key = load_peer_shared_signer_public_key(
                &db,
                &tenant_id,
                &signer_event_id_b64,
                &auth.source_peer_id,
            )?;
            let signing_bytes = encode_peer_shared_signing_bytes(&auth);
            if !verify_ed25519_signature(&signer_public_key, &signing_bytes, &auth.signature) {
                return Err("session auth peer_shared signature verification failed".into());
            }
            if !is_authorized_for_tenant(&db, &tenant_id, &auth.source_peer_id)? {
                return Err(format!(
                    "remote peer {} is not authorized for tenant {}",
                    remote_peer_id, tenant_id
                )
                .into());
            }
            Ok(InboundSessionAuthContext {
                tenant_id,
                remote_peer_id,
                remote_daemon_peer_id: actual_remote_daemon_peer_id,
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
            let tenant_id = resolve_pending_bootstrap_tenant(&db, &invite_event_id_b64)?;
            let invite_public_key = load_invite_public_key(&db, &invite_event_id_b64)?;
            let signing_bytes = encode_invite_signing_bytes(&auth);
            if !verify_ed25519_signature(&invite_public_key, &signing_bytes, &auth.signature) {
                return Err("session auth invite signature verification failed".into());
            }
            Ok(InboundSessionAuthContext {
                tenant_id,
                remote_peer_id: hex::encode(auth.source_peer_id),
                remote_daemon_peer_id: actual_remote_daemon_peer_id,
                used_bootstrap_auth: true,
            })
        }
        other => Err(format!("expected session auth frame, got {other:?}").into()),
    }
}

pub fn resolve_bound_daemon_peer_id(
    conn: &Connection,
    recorded_by: &str,
    peer_id: &str,
) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
    let fp: Option<Vec<u8>> = conn
        .query_row(
            "SELECT spki_fingerprint
             FROM peer_transport_bindings
             WHERE recorded_by = ?1
               AND peer_id = ?2
             LIMIT 1",
            params![recorded_by, peer_id],
            |row| row.get(0),
        )
        .optional()?;
    Ok(fp.and_then(|bytes| {
        (bytes.len() == 32).then(|| {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            hex::encode(arr)
        })
    }))
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
        ParsedEvent::UserInvite(event) if event.signer_type == 5 => event.signed_by,
        ParsedEvent::DeviceInvite(event) if event.signer_type == 5 => event.signed_by,
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
    use std::net::SocketAddr;

    use ed25519_dalek::SigningKey;
    use rusqlite::params;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

    use crate::crypto::{event_id_to_base64, spki_fingerprint_from_ed25519_pubkey};
    use crate::db::open_connection;
    use crate::db::schema::create_tables;
    use crate::transport::{
        accept_session_provider, dial_session_provider, extract_spki_fingerprint,
        generate_self_signed_cert, COVER_SERVER_NAME,
    };

    use super::{
        super::{create_single_port_endpoint_with_identity, workspace_client_config_with_identity},
        *,
    };

    fn store_test_daemon_identity(
        db_path: &str,
        cert_der: &CertificateDer<'static>,
        key_der: &PrivatePkcs8KeyDer<'static>,
    ) -> String {
        let db = open_connection(db_path).expect("open daemon db");
        create_tables(&db).expect("create tables");
        let peer_id = hex::encode(
            extract_spki_fingerprint(cert_der.as_ref()).expect("extract daemon fingerprint"),
        );
        crate::db::daemon_identity::store(
            &db,
            &peer_id,
            cert_der.as_ref(),
            key_der.secret_pkcs8_der().as_ref(),
        )
        .expect("store daemon identity");
        peer_id
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

    async fn connect_test_daemons(
        server_cert: CertificateDer<'static>,
        server_key: PrivatePkcs8KeyDer<'static>,
        client_cert: CertificateDer<'static>,
        client_key: PrivatePkcs8KeyDer<'static>,
    ) -> Result<
        (
            quinn::Endpoint,
            quinn::Endpoint,
            quinn::Connection,
            quinn::Connection,
            SocketAddr,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let server_ep = create_single_port_endpoint_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            server_cert,
            server_key,
        )?;
        let client_ep = create_single_port_endpoint_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            client_cert.clone(),
            client_key.clone_key(),
        )?;
        let client_cfg = workspace_client_config_with_identity(client_cert, client_key)?;
        let server_addr = server_ep.local_addr()?;
        let (accepted, dialed) = tokio::join!(
            accept_session_provider(&server_ep),
            dial_session_provider(
                &client_ep,
                server_addr,
                COVER_SERVER_NAME,
                Some(&client_cfg)
            )
        );
        let accepted = accepted?.expect("accepted provider");
        let dialed = dialed?;
        Ok((
            server_ep,
            client_ep,
            accepted.connection(),
            dialed.connection(),
            server_addr,
        ))
    }

    #[tokio::test]
    async fn open_session_auth_peer_shared_accepts_authorized_target_tenant() {
        let server_temp = tempfile::tempdir().unwrap();
        let client_temp = tempfile::tempdir().unwrap();
        let server_db_path = server_temp.path().join("server.sqlite3");
        let client_db_path = client_temp.path().join("client.sqlite3");

        let (server_cert, server_key) = generate_self_signed_cert().unwrap();
        let (client_cert, client_key) = generate_self_signed_cert().unwrap();
        let server_daemon_peer_id =
            store_test_daemon_identity(server_db_path.to_str().unwrap(), &server_cert, &server_key);
        let client_daemon_peer_id =
            store_test_daemon_identity(client_db_path.to_str().unwrap(), &client_cert, &client_key);

        let source_signing_key = SigningKey::from_bytes(&[0x11; 32]);
        let source_public_key = source_signing_key.verifying_key().to_bytes();
        let source_peer_id_raw = spki_fingerprint_from_ed25519_pubkey(&source_public_key);
        let source_peer_id = hex::encode(source_peer_id_raw);
        let signer_event_id = [0x44; 32];
        let target_tenant_id = hex::encode([0x22; 32]);

        insert_local_peer_secret(
            client_db_path.to_str().unwrap(),
            &source_peer_id,
            &signer_event_id,
            &source_signing_key,
        );
        insert_authorized_peer_shared(
            client_db_path.to_str().unwrap(),
            &source_peer_id,
            &[0x21; 32],
            &[0x21; 32],
            &[0x22; 32],
        );
        insert_authorized_peer_shared(
            server_db_path.to_str().unwrap(),
            &target_tenant_id,
            &signer_event_id,
            &source_public_key,
            &source_peer_id_raw,
        );

        let (_server_ep, _client_ep, server_conn, client_conn, _server_addr) =
            connect_test_daemons(server_cert, server_key, client_cert, client_key)
                .await
                .expect("connect daemon endpoints");

        let auth_plan = OutboundSessionAuthPlan::PeerShared {
            target_peer_id: target_tenant_id.clone(),
        };
        let (outbound, inbound) = tokio::join!(
            send_outbound_session_auth(
                &client_conn,
                client_db_path.to_str().unwrap(),
                &source_peer_id,
                Some(&server_daemon_peer_id),
                &auth_plan,
            ),
            async {
                let inbound =
                    read_inbound_session_auth(&server_conn, server_db_path.to_str().unwrap())
                        .await?;
                send_inbound_session_auth_ack(&server_conn, &inbound.tenant_id).await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(inbound)
            },
        );
        let outbound = outbound.expect("send outbound auth");
        let inbound = inbound.expect("read inbound auth");

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

    #[tokio::test]
    async fn open_session_auth_peer_shared_rejects_when_only_other_tenant_authorizes_remote_peer() {
        let server_temp = tempfile::tempdir().unwrap();
        let client_temp = tempfile::tempdir().unwrap();
        let server_db_path = server_temp.path().join("server.sqlite3");
        let client_db_path = client_temp.path().join("client.sqlite3");

        let (server_cert, server_key) = generate_self_signed_cert().unwrap();
        let (client_cert, client_key) = generate_self_signed_cert().unwrap();
        let server_daemon_peer_id =
            store_test_daemon_identity(server_db_path.to_str().unwrap(), &server_cert, &server_key);
        store_test_daemon_identity(client_db_path.to_str().unwrap(), &client_cert, &client_key);

        let source_signing_key = SigningKey::from_bytes(&[0x12; 32]);
        let source_public_key = source_signing_key.verifying_key().to_bytes();
        let source_peer_id_raw = spki_fingerprint_from_ed25519_pubkey(&source_public_key);
        let source_peer_id = hex::encode(source_peer_id_raw);
        let signer_event_id = [0x55; 32];
        let requested_tenant_id = hex::encode([0x66; 32]);
        let other_authorizing_tenant_id = hex::encode([0x77; 32]);

        insert_local_peer_secret(
            client_db_path.to_str().unwrap(),
            &source_peer_id,
            &signer_event_id,
            &source_signing_key,
        );
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
            &signer_event_id,
            &source_public_key,
            &source_peer_id_raw,
        );

        let (_server_ep, _client_ep, server_conn, client_conn, _server_addr) =
            connect_test_daemons(server_cert, server_key, client_cert, client_key)
                .await
                .expect("connect daemon endpoints");

        let auth_plan = OutboundSessionAuthPlan::PeerShared {
            target_peer_id: requested_tenant_id.clone(),
        };
        let (outbound, inbound) = tokio::join!(
            send_outbound_session_auth(
                &client_conn,
                client_db_path.to_str().unwrap(),
                &source_peer_id,
                Some(&server_daemon_peer_id),
                &auth_plan,
            ),
            async {
                let inbound =
                    read_inbound_session_auth(&server_conn, server_db_path.to_str().unwrap()).await;
                if inbound.is_err() {
                    server_conn.close(1u32.into(), b"expected auth rejection");
                }
                inbound
            },
        );
        let outbound_err = outbound.expect_err("outbound auth should fail when server rejects");
        assert!(
            outbound_err.to_string().contains("expected auth rejection")
                || outbound_err
                    .to_string()
                    .contains("Connection lost while waiting for peer"),
            "unexpected outbound auth error: {outbound_err}"
        );
        let err = inbound.expect_err("wrong target tenant must be rejected");
        assert!(
            err.to_string().contains("is not projected in tenant"),
            "unexpected auth error: {err}"
        );
    }
}
