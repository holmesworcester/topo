use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use crate::crypto::{EventId, event_id_from_base64, event_id_to_base64, hash_event};
use crate::events::*;
use crate::projection::create::{
    create_event_sync, create_event_staged, create_signed_event_sync, create_signed_event_staged,
};
use crate::projection::encrypted::{wrap_key_for_recipient, unwrap_key_from_sender};
use crate::projection::signer::{resolve_signer_key, SignerResolution};

use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
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

/// Ensure the local tenant has at least one content key + self-wrap materialized.
/// Returns the canonical key_event_id to use in key-wrap and encrypted deps.
pub fn ensure_content_key_for_peer(
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

/// Result of bootstrapping a full workspace identity chain.
pub struct IdentityChain {
    pub workspace_id: EventId,
    pub workspace_key: SigningKey,
    pub user_invite_event_id: EventId,
    pub invite_key: SigningKey,
    pub user_event_id: EventId,
    pub user_key: SigningKey,
    pub device_invite_event_id: EventId,
    pub device_invite_key: SigningKey,
    pub peer_shared_event_id: EventId,
    pub peer_shared_key: SigningKey,
    pub admin_event_id: EventId,
    pub admin_key: SigningKey,
    pub content_key_event_id: Option<EventId>,
}

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

/// Bootstrap a full workspace identity chain following the canonical sequence from scenario tests:
/// Workspace -> UserInviteBoot -> InviteAccepted (trust anchor) -> UserBoot ->
/// DeviceInviteFirst -> PeerSharedFirst -> AdminBoot.
///
/// InviteAccepted must come early to bind the trust anchor, which triggers a
/// guard-cascade that unblocks the Workspace event and all its dependents.
pub fn bootstrap_workspace(
    conn: &Connection,
    recorded_by: &str,
    workspace_name: &str,
    username: &str,
    device_name: &str,
) -> Result<IdentityChain, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();

    // 1. Workspace event (unsigned) — guard-blocked until trust anchor exists
    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pub = workspace_key.verifying_key().to_bytes();
    let net_evt = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: workspace_pub,
        name: workspace_name.to_string(),
    });
    let workspace_id = create_event_staged(conn, recorded_by, &net_evt)?;

    // 2. UserInviteBoot (signed by workspace_key) — blocked until Workspace is valid
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pub = invite_key.verifying_key().to_bytes();
    let uib_evt = ParsedEvent::UserInviteBoot(UserInviteBootEvent {
        created_at_ms: now_ms(),
        public_key: invite_pub,
        workspace_id: workspace_id,
        signed_by: workspace_id,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let user_invite_event_id = create_signed_event_staged(
        conn,
        recorded_by,
        &uib_evt,
        &workspace_key,
    )?;

    // 3. InviteAccepted (local event) — binds trust anchor, triggers guard cascade
    //    that unblocks Workspace -> UserInviteBoot -> and all downstream events
    let ia_evt = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: now_ms(),
        invite_event_id: user_invite_event_id,
        workspace_id: workspace_id,
    });
    let _invite_accepted_event_id = create_event_sync(conn, recorded_by, &ia_evt)?;

    // 4. UserBoot (signed by invite_key) — should now project since cascade unblocked chain
    let user_key = SigningKey::generate(&mut rng);
    let user_pub = user_key.verifying_key().to_bytes();
    let ub_evt = ParsedEvent::UserBoot(UserBootEvent {
        created_at_ms: now_ms(),
        public_key: user_pub,
        username: username.to_string(),
        signed_by: user_invite_event_id,
        signer_type: 2,
        signature: [0u8; 64],
    });
    let user_event_id = create_signed_event_sync(
        conn,
        recorded_by,
        &ub_evt,
        &invite_key,
    )?;

    // 5. DeviceInviteFirst (signed by user_key)
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pub = device_invite_key.verifying_key().to_bytes();
    let dif_evt = ParsedEvent::DeviceInviteFirst(DeviceInviteFirstEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_pub,
        signed_by: user_event_id,
        signer_type: 4,
        signature: [0u8; 64],
    });
    let device_invite_event_id = create_signed_event_sync(
        conn,
        recorded_by,
        &dif_evt,
        &user_key,
    )?;

    // 6. PeerSharedFirst (signed by device_invite_key)
    let peer_shared_key = SigningKey::generate(&mut rng);
    let peer_shared_pub = peer_shared_key.verifying_key().to_bytes();
    let psf_evt = ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
        created_at_ms: now_ms(),
        public_key: peer_shared_pub,
        user_event_id,
        device_name: device_name.to_string(),
        signed_by: device_invite_event_id,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let peer_shared_event_id = create_signed_event_sync(
        conn,
        recorded_by,
        &psf_evt,
        &device_invite_key,
    )?;

    // 7. AdminBoot (signed by workspace_key, dep: user_event)
    let admin_key = SigningKey::generate(&mut rng);
    let admin_pub = admin_key.verifying_key().to_bytes();
    let ab_evt = ParsedEvent::AdminBoot(AdminBootEvent {
        created_at_ms: now_ms(),
        public_key: admin_pub,
        user_event_id,
        signed_by: workspace_id,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let admin_event_id = create_signed_event_sync(
        conn,
        recorded_by,
        &ab_evt,
        &workspace_key,
    )?;

    // 8. Create deterministic local content key + self-wrap (bootstrap key seed).
    let content_key_event_id = Some(ensure_content_key_for_peer(
        conn,
        recorded_by,
        &peer_shared_key,
        &peer_shared_event_id,
    )?);

    Ok(IdentityChain {
        workspace_id,
        workspace_key,
        user_invite_event_id,
        invite_key,
        user_event_id,
        user_key,
        device_invite_event_id,
        device_invite_key,
        peer_shared_event_id,
        peer_shared_key,
        admin_event_id,
        admin_key,
        content_key_event_id,
    })
}

/// Create a user invite (admin creates this). Returns InviteData with the private key
/// needed for the invitee to accept.
///
/// If `sender_peer_shared_key` and `sender_peer_shared_event_id` are provided,
/// wraps the workspace content key for the invitee's invite public key and
/// creates a SecretShared event so the joiner can unwrap on acceptance.
pub fn create_user_invite(
    conn: &Connection,
    recorded_by: &str,
    workspace_key: &SigningKey,
    workspace_id: &EventId,
    sender_peer_shared_key: Option<&SigningKey>,
    sender_peer_shared_event_id: Option<&EventId>,
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

    let invite_event_id = create_signed_event_sync(
        conn,
        recorded_by,
        &evt,
        workspace_key,
    )?;

    // Wrap content key for invitee if sender has peer_shared identity
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

/// Accept a user invite: InviteAccepted (trust anchor) -> UserBoot -> DeviceInviteFirst ->
/// PeerSharedFirst.
///
/// InviteAccepted must come first to bind the trust anchor and trigger the guard cascade
/// that makes the copied Workspace/UserInviteBoot events valid.
pub fn accept_user_invite(
    conn: &Connection,
    recorded_by: &str,
    invite_key: &SigningKey,
    invite_event_id: &EventId,
    workspace_id: EventId,
    username: &str,
    device_name: &str,
) -> Result<JoinChain, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();

    // 1. InviteAccepted (local event) — binds trust anchor, triggers guard cascade
    let ia_evt = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: now_ms(),
        invite_event_id: *invite_event_id,
        workspace_id: workspace_id,
    });
    let invite_accepted_event_id = create_event_sync(conn, recorded_by, &ia_evt)?;

    // 2. UserBoot (signed by invite_key) — must be Valid after trust anchor cascade
    let user_key = SigningKey::generate(&mut rng);
    let user_pub = user_key.verifying_key().to_bytes();
    let ub_evt = ParsedEvent::UserBoot(UserBootEvent {
        created_at_ms: now_ms(),
        public_key: user_pub,
        username: username.to_string(),
        signed_by: *invite_event_id,
        signer_type: 2,
        signature: [0u8; 64],
    });
    let user_event_id = create_signed_event_sync(
        conn,
        recorded_by,
        &ub_evt,
        invite_key,
    )?;

    // 3. DeviceInviteFirst (signed by user_key)
    let device_invite_key = SigningKey::generate(&mut rng);
    let device_invite_pub = device_invite_key.verifying_key().to_bytes();
    let dif_evt = ParsedEvent::DeviceInviteFirst(DeviceInviteFirstEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_pub,
        signed_by: user_event_id,
        signer_type: 4,
        signature: [0u8; 64],
    });
    let device_invite_event_id = create_signed_event_sync(
        conn,
        recorded_by,
        &dif_evt,
        &user_key,
    )?;

    // 4. PeerSharedFirst (signed by device_invite_key)
    let peer_shared_key = SigningKey::generate(&mut rng);
    let peer_shared_pub = peer_shared_key.verifying_key().to_bytes();
    let psf_evt = ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
        created_at_ms: now_ms(),
        public_key: peer_shared_pub,
        user_event_id,
        device_name: device_name.to_string(),
        signed_by: device_invite_event_id,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let peer_shared_event_id = create_signed_event_sync(
        conn,
        recorded_by,
        &psf_evt,
        &device_invite_key,
    )?;

    // 5. Unwrap inviter-provided content key targeted at this invite (if present).
    let content_key_event_id = unwrap_content_key_from_invite(
        conn,
        recorded_by,
        invite_key,
        invite_event_id,
    )?;

    Ok(JoinChain {
        user_event_id,
        user_key,
        device_invite_event_id,
        device_invite_key,
        peer_shared_event_id,
        peer_shared_key,
        invite_accepted_event_id,
        content_key_event_id,
    })
}

/// Create a device link invite (user creates this for linking another device).
pub fn create_device_link_invite(
    conn: &Connection,
    recorded_by: &str,
    user_key: &SigningKey,
    user_event_id: &EventId,
    workspace_id: &EventId,
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

    let invite_event_id = create_signed_event_sync(conn, recorded_by, &evt, user_key)?;

    Ok(InviteData {
        invite_event_id,
        invite_key: device_invite_key,
        workspace_id: *workspace_id,
        invite_type: InviteType::DeviceLink {
            user_event_id: *user_event_id,
        },
    })
}

/// Accept a device link invite: InviteAccepted (trust anchor) -> PeerSharedFirst.
pub fn accept_device_link(
    conn: &Connection,
    recorded_by: &str,
    device_invite_key: &SigningKey,
    device_invite_event_id: &EventId,
    workspace_id: EventId,
    user_event_id: EventId,
    device_name: &str,
) -> Result<LinkChain, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();

    // 1. InviteAccepted (local event) — binds trust anchor, triggers guard cascade
    let ia_evt = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: now_ms(),
        invite_event_id: *device_invite_event_id,
        workspace_id: workspace_id,
    });
    let invite_accepted_event_id = create_event_sync(conn, recorded_by, &ia_evt)?;

    // 2. PeerSharedFirst (signed by device_invite_key) — must be Valid after trust anchor cascade
    let peer_shared_key = SigningKey::generate(&mut rng);
    let peer_shared_pub = peer_shared_key.verifying_key().to_bytes();
    let psf_evt = ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
        created_at_ms: now_ms(),
        public_key: peer_shared_pub,
        user_event_id,
        device_name: device_name.to_string(),
        signed_by: *device_invite_event_id,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let peer_shared_event_id = create_signed_event_sync(
        conn,
        recorded_by,
        &psf_evt,
        device_invite_key,
    )?;

    Ok(LinkChain {
        peer_shared_event_id,
        peer_shared_key,
        invite_accepted_event_id,
    })
}

/// Generate a random 32-byte content secret key, create a local SecretKey event,
/// then wrap it for our own peer_shared public key via SecretShared (self-wrap).
/// Returns the SecretKey event_id on success.
fn create_content_key_and_self_wrap(
    conn: &Connection,
    recorded_by: &str,
    peer_shared_key: &SigningKey,
    peer_shared_event_id: &EventId,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();

    // 1. Generate random content key
    let mut content_key_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut content_key_bytes);

    // 2. Create deterministic SecretKey event (local-only, stores the raw key)
    let key_event_id = create_deterministic_secret_key_event(conn, recorded_by, content_key_bytes)?;

    // 3. Wrap content key for self (peer_shared -> peer_shared)
    let wrapped = wrap_key_for_recipient(
        peer_shared_key,
        &peer_shared_key.verifying_key(),
        &content_key_bytes,
    );

    // 4. Create SecretShared event (self-wrap, signed by peer_shared_key)
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

/// Wrap the workspace's content key for an invitee's invite public key.
/// Looks up the first SecretKey event for this tenant, wraps it, and
/// creates a SecretShared event with recipient_event_id = invite_event_id.
fn wrap_content_key_for_invite(
    conn: &Connection,
    recorded_by: &str,
    sender_peer_shared_key: &SigningKey,
    sender_peer_shared_event_id: &EventId,
    invite_public_key: &ed25519_dalek::VerifyingKey,
    invite_event_id: &EventId,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Ensure there is a canonical content key to wrap for the invitee.
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

    // Wrap for invitee's public key
    let wrapped = wrap_key_for_recipient(
        sender_peer_shared_key,
        invite_public_key,
        &plaintext_key,
    );

    // Create SecretShared event (signed by sender's peer_shared_key)
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
fn unwrap_content_key_from_invite(
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

