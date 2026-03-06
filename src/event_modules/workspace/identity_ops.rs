//! Identity primitives and helpers.
//!
//! This module owns reusable crypto/data helpers for identity operations.
//! Workflow orchestration (event creation sequences, invite flows) is owned
//! by `event_modules::workspace::commands`.

use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::event_modules::*;
use crate::projection::create::{
    create_event_synchronous, create_signed_event_synchronous, event_id_or_blocked, project_event,
    store_signed_event_only,
};
use crate::projection::encrypted::wrap_key_for_recipient;
use crate::transport::{extract_spki_fingerprint, generate_self_signed_cert_from_signing_key};

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Ensure a local `tenant` event exists for this tenant and return its event id.
/// `tenant` is the local root for local-only identity events.
pub(crate) fn ensure_local_tenant_event(
    conn: &Connection,
    recorded_by: &str,
    peer_key: &SigningKey,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT event_id
             FROM tenants
             WHERE recorded_by = ?1
             ORDER BY created_at ASC, event_id ASC
             LIMIT 1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .ok();
    let tenant_event_id = if let Some(eid_b64) = existing {
        event_id_from_base64(&eid_b64).ok_or("invalid tenants.event_id base64")?
    } else {
        let tenant_evt = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: now_ms(),
            public_key: peer_key.verifying_key().to_bytes(),
        });
        event_id_or_blocked(create_event_synchronous(conn, recorded_by, &tenant_evt))?
    };

    Ok(tenant_event_id)
}

fn create_deterministic_key_secret_event(
    conn: &Connection,
    recorded_by: &str,
    key_bytes: [u8; 32],
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let expected = crate::event_modules::key_secret::deterministic_key_secret_event_id(&key_bytes);
    let sk_evt = crate::event_modules::key_secret::deterministic_key_secret_event(key_bytes);
    let created = create_event_synchronous(conn, recorded_by, &sk_evt)?;
    if created != expected {
        return Err("key_secret event_id mismatch for deterministic key material".into());
    }
    Ok(created)
}

// ---------------------------------------------------------------------------
// Data types (shared across modules)
// ---------------------------------------------------------------------------

/// Result of accepting a user invite.
pub struct JoinChain {
    pub user_event_id: EventId,
    pub user_key: SigningKey,
    pub device_invite_event_id: EventId,
    pub device_invite_key: SigningKey,
    pub peer_shared_event_id: EventId,
    pub peer_shared_key: SigningKey,
    pub invite_accepted_event_id: EventId,
    pub content_key_event_id: Option<EventId>,
}

/// Result of accepting a device link invite.
pub struct LinkChain {
    pub peer_shared_event_id: EventId,
    pub peer_shared_key: SigningKey,
    pub invite_accepted_event_id: EventId,
}

/// Data needed to transfer an invite between accounts.
#[derive(Clone)]
pub struct InviteData {
    pub invite_event_id: EventId,
    pub invite_key: SigningKey,
    pub workspace_id: EventId,
    pub invite_type: InviteType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteType {
    User,
    DeviceLink { user_event_id: EventId },
}

/// Bootstrap context for invite creation. When provided, bootstrap_context
/// is written between event storage and projection so the projector can
/// emit trust commands.
pub struct InviteBootstrapContext<'a> {
    pub bootstrap_addrs: &'a [String],
    pub bootstrap_spki: &'a [u8; 32],
}

/// Derive the expected bootstrap transport SPKI fingerprint for an invitee from
/// invite signing key material.
pub(crate) fn expected_invite_bootstrap_spki_from_invite_key(
    invite_key: &SigningKey,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let (cert_der, _) = generate_self_signed_cert_from_signing_key(invite_key)?;
    extract_spki_fingerprint(cert_der.as_ref())
}

// ---------------------------------------------------------------------------
// Reusable primitive helpers (pub(crate) for event-module command use)
// ---------------------------------------------------------------------------

/// Ensure the local tenant has at least one content key materialized.
/// Returns the canonical key_event_id to use in key-wrap and encrypted deps.
pub(crate) fn ensure_content_key_for_peer(
    conn: &Connection,
    recorded_by: &str,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT event_id FROM key_secrets WHERE recorded_by = ?1 ORDER BY rowid ASC LIMIT 1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .ok();
    if let Some(eid_b64) = existing {
        let eid = event_id_from_base64(&eid_b64).ok_or("invalid key_secrets.event_id base64")?;
        return Ok(eid);
    }
    create_content_key(conn, recorded_by)
}

/// Wrap the workspace's content key for an invitee's invite public key.
/// Looks up the first Secret event for this tenant, wraps it, and creates
/// a KeyShared event with explicit dep on deterministic invite_secret.
pub(crate) fn wrap_content_key_for_invite(
    conn: &Connection,
    recorded_by: &str,
    sender_peer_shared_key: &SigningKey,
    sender_peer_shared_event_id: &EventId,
    invite_key: &SigningKey,
    invite_event_id: &EventId,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let key_event_id = ensure_content_key_for_peer(conn, recorded_by)?;
    let key_event_b64 = event_id_to_base64(&key_event_id);
    let key_bytes: Vec<u8> = conn.query_row(
        "SELECT key_bytes FROM key_secrets WHERE recorded_by = ?1 AND event_id = ?2 LIMIT 1",
        rusqlite::params![recorded_by, &key_event_b64],
        |row| row.get(0),
    )?;
    if key_bytes.len() != 32 {
        return Err("corrupt key_bytes in key_secrets".into());
    }

    let mut plaintext_key = [0u8; 32];
    plaintext_key.copy_from_slice(&key_bytes);

    let invite_private = invite_key.to_bytes();
    let invite_secret_event_id =
        crate::event_modules::invite_secret::deterministic_invite_secret_event_id(
            invite_event_id,
            &invite_private,
        );
    let invite_secret_evt = crate::event_modules::invite_secret::deterministic_invite_secret_event(
        *invite_event_id,
        invite_private,
    );
    let created_invite_secret_event_id = event_id_or_blocked(create_event_synchronous(
        conn,
        recorded_by,
        &invite_secret_evt,
    ))?;
    if created_invite_secret_event_id != invite_secret_event_id {
        return Err("invite_secret event_id mismatch for deterministic key material".into());
    }

    let wrapped = wrap_key_for_recipient(
        sender_peer_shared_key,
        &invite_key.verifying_key(),
        &plaintext_key,
    );

    let ss_evt = ParsedEvent::KeyShared(KeySharedEvent {
        created_at_ms: now_ms(),
        key_event_id,
        recipient_event_id: *invite_event_id,
        unwrap_key_event_id: invite_secret_event_id,
        wrapped_key: wrapped,
        signed_by: *sender_peer_shared_event_id,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let _ss_event_id = event_id_or_blocked(create_signed_event_synchronous(
        conn,
        recorded_by,
        &ss_evt,
        sender_peer_shared_key,
    ))?;

    Ok(())
}

/// Persist local invite private key material as deterministic invite_secret.
/// Returns the deterministic invite_secret event id.
pub(crate) fn store_invite_secret(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id: &EventId,
    invite_key: &SigningKey,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let private_key = invite_key.to_bytes();
    let expected = crate::event_modules::invite_secret::deterministic_invite_secret_event_id(
        invite_event_id,
        &private_key,
    );
    let evt = crate::event_modules::invite_secret::deterministic_invite_secret_event(
        *invite_event_id,
        private_key,
    );
    let created = event_id_or_blocked(create_event_synchronous(conn, recorded_by, &evt))?;
    if created != expected {
        return Err("invite_secret event_id mismatch for deterministic key material".into());
    }
    Ok(created)
}

fn create_invite_event_with_optional_bootstrap_context(
    conn: &Connection,
    recorded_by: &str,
    event: &ParsedEvent,
    signer: &SigningKey,
    workspace_id: &EventId,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ctx) = bootstrap_ctx {
        let event_id = store_signed_event_only(conn, recorded_by, event, signer)?;
        let eid_b64 = event_id_to_base64(&event_id);
        let ws_b64 = event_id_to_base64(workspace_id);
        for addr in ctx.bootstrap_addrs {
            crate::db::transport_trust::append_bootstrap_context(
                conn,
                recorded_by,
                &eid_b64,
                &ws_b64,
                addr,
                ctx.bootstrap_spki,
            )?;
        }
        project_event(conn, recorded_by, &event_id)?;
        Ok(event_id)
    } else {
        Ok(create_signed_event_synchronous(
            conn,
            recorded_by,
            event,
            signer,
        )?)
    }
}

/// Create an ongoing user invite signed by an admin peer_shared signer.
pub(crate) fn create_user_invite_events_as_admin(
    conn: &Connection,
    recorded_by: &str,
    admin_peer_shared_key: &SigningKey,
    admin_peer_shared_event_id: &EventId,
    admin_event_id: &EventId,
    workspace_id: &EventId,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<InviteData, Box<dyn std::error::Error + Send + Sync>> {
    create_user_invite_events_with_signer(
        conn,
        recorded_by,
        admin_peer_shared_key,
        admin_peer_shared_event_id,
        admin_event_id,
        5,
        workspace_id,
        Some(admin_peer_shared_key),
        Some(admin_peer_shared_event_id),
        bootstrap_ctx,
    )
}

fn create_user_invite_events_with_signer(
    conn: &Connection,
    recorded_by: &str,
    signer_key: &SigningKey,
    signer_event_id: &EventId,
    authority_event_id: &EventId,
    signer_type: u8,
    workspace_id: &EventId,
    sender_peer_shared_key: Option<&SigningKey>,
    sender_peer_shared_event_id: Option<&EventId>,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<InviteData, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pub = invite_key.verifying_key().to_bytes();

    let evt = ParsedEvent::UserInvite(UserInviteEvent {
        created_at_ms: now_ms(),
        public_key: invite_pub,
        workspace_id: *workspace_id,
        authority_event_id: *authority_event_id,
        signed_by: *signer_event_id,
        signer_type,
        signature: [0u8; 64],
    });

    let invite_event_id = create_invite_event_with_optional_bootstrap_context(
        conn,
        recorded_by,
        &evt,
        signer_key,
        workspace_id,
        bootstrap_ctx,
    )?;

    if let (Some(ps_key), Some(ps_eid)) = (sender_peer_shared_key, sender_peer_shared_event_id) {
        wrap_content_key_for_invite(
            conn,
            recorded_by,
            ps_key,
            ps_eid,
            &invite_key,
            &invite_event_id,
        )?;
    }

    Ok(InviteData {
        invite_event_id,
        invite_key,
        workspace_id: *workspace_id,
        invite_type: InviteType::User,
    })
}

/// Create an ongoing device-link invite signed by an admin peer_shared signer.
pub(crate) fn create_device_link_invite_events_as_admin(
    conn: &Connection,
    recorded_by: &str,
    admin_peer_shared_key: &SigningKey,
    admin_peer_shared_event_id: &EventId,
    admin_event_id: &EventId,
    user_event_id: &EventId,
    workspace_id: &EventId,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<InviteData, Box<dyn std::error::Error + Send + Sync>> {
    create_device_link_invite_events_with_signer(
        conn,
        recorded_by,
        admin_peer_shared_key,
        admin_peer_shared_event_id,
        admin_event_id,
        5,
        user_event_id,
        workspace_id,
        bootstrap_ctx,
    )
}

fn create_device_link_invite_events_with_signer(
    conn: &Connection,
    recorded_by: &str,
    signer_key: &SigningKey,
    signer_event_id: &EventId,
    authority_event_id: &EventId,
    signer_type: u8,
    user_event_id: &EventId,
    workspace_id: &EventId,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<InviteData, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pub = device_invite_key.verifying_key().to_bytes();

    let evt = ParsedEvent::DeviceInvite(DeviceInviteEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_pub,
        authority_event_id: *authority_event_id,
        signed_by: *signer_event_id,
        signer_type,
        signature: [0u8; 64],
    });

    let invite_event_id = create_invite_event_with_optional_bootstrap_context(
        conn,
        recorded_by,
        &evt,
        signer_key,
        workspace_id,
        bootstrap_ctx,
    )?;

    Ok(InviteData {
        invite_event_id,
        invite_key: device_invite_key,
        workspace_id: *workspace_id,
        invite_type: InviteType::DeviceLink {
            user_event_id: *user_event_id,
        },
    })
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Generate a random 32-byte content secret key and create a local Secret event.
fn create_content_key(
    conn: &Connection,
    recorded_by: &str,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();

    let mut content_key_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut content_key_bytes);

    create_deterministic_key_secret_event(conn, recorded_by, content_key_bytes)
}
