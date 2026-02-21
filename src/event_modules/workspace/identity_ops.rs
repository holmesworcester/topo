//! Identity primitives and helpers.
//!
//! This module owns reusable crypto/data helpers for identity operations.
//! Workflow orchestration (event creation sequences, invite flows) is owned
//! by `event_modules::workspace::commands`.

use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use crate::crypto::{EventId, event_id_from_base64, event_id_to_base64, hash_event};
use crate::event_modules::*;
use crate::projection::create::{
    create_event_sync, create_signed_event_sync,
    store_signed_event_only, project_event,
};
use crate::projection::encrypted::{wrap_key_for_recipient, unwrap_key_from_sender};
use crate::projection::signer::{resolve_signer_key, SignerResolution};

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const SIGNER_KIND_PENDING_INVITE_UNWRAP: i64 = 4;

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Deterministic timestamp derivation for wrapped content keys.
///
/// This keeps SecretKey event IDs stable across inviter/invitee when they
/// materialize the same 32-byte key bytes.
fn deterministic_content_key_created_at_ms(key_bytes: &[u8; 32]) -> u64 {
    use blake2::digest::consts::U8;
    use blake2::{Blake2b, Digest};

    let mut hasher = Blake2b::<U8>::new();
    hasher.update(b"poc7-content-key-created-at-v1");
    hasher.update(key_bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(out)
}

fn create_deterministic_secret_key_event(
    conn: &Connection,
    recorded_by: &str,
    key_bytes: [u8; 32],
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let expected = deterministic_secret_key_event_id(&key_bytes)?;
    let sk_evt = ParsedEvent::SecretKey(SecretKeyEvent {
        created_at_ms: deterministic_content_key_created_at_ms(&key_bytes),
        key_bytes,
    });
    let created = create_event_sync(conn, recorded_by, &sk_evt)?;
    if created != expected {
        return Err("secret_key event_id mismatch for deterministic key material".into());
    }
    Ok(created)
}

fn deterministic_secret_key_event_id(
    key_bytes: &[u8; 32],
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let sk_evt = ParsedEvent::SecretKey(SecretKeyEvent {
        created_at_ms: deterministic_content_key_created_at_ms(&key_bytes),
        key_bytes: *key_bytes,
    });
    Ok(hash_event(&encode_event(&sk_evt)?))
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
    pub bootstrap_addr: &'a str,
    pub bootstrap_spki: &'a [u8; 32],
}

// ---------------------------------------------------------------------------
// Reusable primitive helpers (pub(crate) for event-module command use)
// ---------------------------------------------------------------------------

/// Ensure the local tenant has at least one content key + self-wrap materialized.
/// Returns the canonical key_event_id to use in key-wrap and encrypted deps.
pub(crate) fn ensure_content_key_for_peer(
    conn: &Connection,
    recorded_by: &str,
    peer_shared_key: &SigningKey,
    peer_shared_event_id: &EventId,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT event_id FROM secret_keys WHERE recorded_by = ?1 ORDER BY rowid ASC LIMIT 1",
            rusqlite::params![recorded_by],
            |row| row.get(0),
        )
        .ok();
    if let Some(eid_b64) = existing {
        let eid = event_id_from_base64(&eid_b64)
            .ok_or("invalid secret_keys.event_id base64")?;
        return Ok(eid);
    }
    create_content_key_and_self_wrap(conn, recorded_by, peer_shared_key, peer_shared_event_id)
}

/// Wrap the workspace's content key for an invitee's invite public key.
/// Looks up the first SecretKey event for this tenant, wraps it, and
/// creates a SecretShared event with recipient_event_id = invite_event_id.
pub(crate) fn wrap_content_key_for_invite(
    conn: &Connection,
    recorded_by: &str,
    sender_peer_shared_key: &SigningKey,
    sender_peer_shared_event_id: &EventId,
    invite_public_key: &ed25519_dalek::VerifyingKey,
    invite_event_id: &EventId,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let key_event_id = ensure_content_key_for_peer(
        conn,
        recorded_by,
        sender_peer_shared_key,
        sender_peer_shared_event_id,
    )?;
    let key_event_b64 = event_id_to_base64(&key_event_id);
    let key_bytes: Vec<u8> = conn.query_row(
        "SELECT key_bytes FROM secret_keys WHERE recorded_by = ?1 AND event_id = ?2 LIMIT 1",
        rusqlite::params![recorded_by, &key_event_b64],
        |row| row.get(0),
    )?;
    if key_bytes.len() != 32 {
        return Err("corrupt key_bytes in secret_keys".into());
    }

    let mut plaintext_key = [0u8; 32];
    plaintext_key.copy_from_slice(&key_bytes);

    let wrapped = wrap_key_for_recipient(
        sender_peer_shared_key,
        invite_public_key,
        &plaintext_key,
    );

    let ss_evt = ParsedEvent::SecretShared(SecretSharedEvent {
        created_at_ms: now_ms(),
        key_event_id,
        recipient_event_id: *invite_event_id,
        wrapped_key: wrapped,
        signed_by: *sender_peer_shared_event_id,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let _ss_event_id = create_signed_event_sync(
        conn,
        recorded_by,
        &ss_evt,
        sender_peer_shared_key,
    )?;

    Ok(())
}

/// After accepting an invite, look up any SecretShared events targeted at
/// the invite_event_id, unwrap using the invite private key and the sender's
/// public key, and create a local SecretKey event for the decrypted content key.
pub(crate) fn unwrap_content_key_from_invite(
    conn: &Connection,
    recorded_by: &str,
    invite_key: &SigningKey,
    invite_event_id: &EventId,
) -> Result<Option<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT e.blob FROM events e
         INNER JOIN recorded_events re ON re.event_id = e.event_id
         WHERE re.peer_id = ?1 AND e.event_type = ?2",
    )?;
    let mut rows = stmt.query(rusqlite::params![recorded_by, "secret_shared"])?;

    while let Some(row) = rows.next()? {
        let blob: Vec<u8> = row.get(0)?;
        let parsed = match parse_event(&blob) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let ss = match parsed {
            ParsedEvent::SecretShared(ss) => ss,
            _ => continue,
        };
        if ss.recipient_event_id != *invite_event_id {
            continue;
        }

        let sender_key = match resolve_signer_key(conn, recorded_by, ss.signer_type, &ss.signed_by) {
            Ok(SignerResolution::Found(k)) => k,
            Ok(_) => continue,
            Err(_) => continue,
        };
        let sender_pub = match ed25519_dalek::VerifyingKey::from_bytes(&sender_key) {
            Ok(vk) => vk,
            Err(_) => continue,
        };

        let plaintext_key = unwrap_key_from_sender(invite_key, &sender_pub, &ss.wrapped_key);
        let expected_key_event_id = deterministic_secret_key_event_id(&plaintext_key)?;
        if expected_key_event_id != ss.key_event_id {
            continue;
        }
        let local_key_event_id = create_deterministic_secret_key_event(conn, recorded_by, plaintext_key)?;
        return Ok(Some(local_key_event_id));
    }

    Ok(None)
}

/// Persist invite key material so content-key unwrap can be retried after
/// late-arriving SecretShared prerequisites.
pub(crate) fn store_pending_invite_unwrap_key(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id: &EventId,
    invite_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    conn.execute(
        "INSERT OR REPLACE INTO local_signer_material
         (recorded_by, signer_event_id, signer_kind, private_key, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            recorded_by,
            event_id_to_base64(invite_event_id),
            SIGNER_KIND_PENDING_INVITE_UNWRAP,
            invite_key.to_bytes().to_vec(),
            now_ms() as i64,
        ],
    )?;
    Ok(())
}

pub(crate) fn clear_pending_invite_unwrap_key(
    conn: &Connection,
    recorded_by: &str,
    invite_event_id: &EventId,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    conn.execute(
        "DELETE FROM local_signer_material
         WHERE recorded_by = ?1 AND signer_event_id = ?2 AND signer_kind = ?3",
        rusqlite::params![
            recorded_by,
            event_id_to_base64(invite_event_id),
            SIGNER_KIND_PENDING_INVITE_UNWRAP,
        ],
    )?;
    Ok(())
}

/// Create a user invite event and wrap content key for invitee.
/// This is the core event-creation primitive for user invites.
pub(crate) fn create_user_invite_events(
    conn: &Connection,
    recorded_by: &str,
    workspace_key: &SigningKey,
    workspace_id: &EventId,
    sender_peer_shared_key: Option<&SigningKey>,
    sender_peer_shared_event_id: Option<&EventId>,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<InviteData, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pub = invite_key.verifying_key().to_bytes();

    let evt = ParsedEvent::UserInviteBoot(UserInviteBootEvent {
        created_at_ms: now_ms(),
        public_key: invite_pub,
        workspace_id: *workspace_id,
        signed_by: *workspace_id,
        signer_type: 1,
        signature: [0u8; 64],
    });

    let invite_event_id = if let Some(ctx) = bootstrap_ctx {
        let eid = store_signed_event_only(conn, recorded_by, &evt, workspace_key)?;
        crate::db::transport_trust::append_bootstrap_context(
            conn,
            recorded_by,
            &event_id_to_base64(&eid),
            &event_id_to_base64(workspace_id),
            ctx.bootstrap_addr,
            ctx.bootstrap_spki,
        )?;
        project_event(conn, recorded_by, &eid)?;
        eid
    } else {
        create_signed_event_sync(conn, recorded_by, &evt, workspace_key)?
    };

    if let (Some(ps_key), Some(ps_eid)) = (sender_peer_shared_key, sender_peer_shared_event_id) {
        wrap_content_key_for_invite(
            conn,
            recorded_by,
            ps_key,
            ps_eid,
            &invite_key.verifying_key(),
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

/// Create a device link invite event.
/// This is the core event-creation primitive for device-link invites.
pub(crate) fn create_device_link_invite_events(
    conn: &Connection,
    recorded_by: &str,
    user_key: &SigningKey,
    user_event_id: &EventId,
    workspace_id: &EventId,
    bootstrap_ctx: Option<&InviteBootstrapContext<'_>>,
) -> Result<InviteData, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pub = device_invite_key.verifying_key().to_bytes();

    let evt = ParsedEvent::DeviceInviteFirst(DeviceInviteFirstEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_pub,
        signed_by: *user_event_id,
        signer_type: 4,
        signature: [0u8; 64],
    });

    let invite_event_id = if let Some(ctx) = bootstrap_ctx {
        let eid = store_signed_event_only(conn, recorded_by, &evt, user_key)?;
        crate::db::transport_trust::append_bootstrap_context(
            conn,
            recorded_by,
            &event_id_to_base64(&eid),
            &event_id_to_base64(workspace_id),
            ctx.bootstrap_addr,
            ctx.bootstrap_spki,
        )?;
        project_event(conn, recorded_by, &eid)?;
        eid
    } else {
        create_signed_event_sync(conn, recorded_by, &evt, user_key)?
    };

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

/// Generate a random 32-byte content secret key, create a local SecretKey event,
/// then wrap it for our own peer_shared public key via SecretShared (self-wrap).
fn create_content_key_and_self_wrap(
    conn: &Connection,
    recorded_by: &str,
    peer_shared_key: &SigningKey,
    peer_shared_event_id: &EventId,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();

    let mut content_key_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut content_key_bytes);

    let key_event_id = create_deterministic_secret_key_event(conn, recorded_by, content_key_bytes)?;

    let wrapped = wrap_key_for_recipient(
        peer_shared_key,
        &peer_shared_key.verifying_key(),
        &content_key_bytes,
    );

    let ss_evt = ParsedEvent::SecretShared(SecretSharedEvent {
        created_at_ms: now_ms(),
        key_event_id: key_event_id,
        recipient_event_id: *peer_shared_event_id,
        wrapped_key: wrapped,
        signed_by: *peer_shared_event_id,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let _ss_event_id = create_signed_event_sync(
        conn,
        recorded_by,
        &ss_evt,
        peer_shared_key,
    )?;

    Ok(key_event_id)
}
