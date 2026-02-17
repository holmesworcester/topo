use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use crate::crypto::{EventId, event_id_to_base64};
use crate::events::*;
use crate::projection::create::{
    create_event_sync, create_event_staged, create_signed_event_sync, create_signed_event_staged,
};
use crate::projection::encrypted::{wrap_key_for_recipient, unwrap_key_from_sender};
use crate::db::transport_creds::load_local_creds;
use crate::transport::extract_spki_fingerprint;

use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
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
    pub transport_key_event_id: Option<EventId>,
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
    pub transport_key_event_id: Option<EventId>,
    pub content_key_event_id: Option<EventId>,
}

/// Result of accepting a device link invite.
pub struct LinkChain {
    pub peer_shared_event_id: EventId,
    pub peer_shared_key: SigningKey,
    pub invite_accepted_event_id: EventId,
    pub transport_key_event_id: Option<EventId>,
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
/// DeviceInviteFirst -> PeerSharedFirst -> AdminBoot -> TransportKey.
///
/// InviteAccepted must come early to bind the trust anchor, which triggers a
/// guard-cascade that unblocks the Workspace event and all its dependents.
pub fn bootstrap_workspace(
    conn: &Connection,
    recorded_by: &str,
) -> Result<IdentityChain, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();

    // 1. Workspace event (unsigned) — guard-blocked until trust anchor exists
    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pub = workspace_key.verifying_key().to_bytes();
    let net_evt = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: workspace_pub,
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

    // 8. Content-key wrap bootstrap is staged but not enabled by default yet.
    // Keep runtime behavior unchanged in this round to avoid semantic drift in
    // existing scenario invariants; follow-up rounds can wire this in once
    // ordering/invariant updates land.
    let content_key_event_id = None;

    // 9. TransportKey (signed by peer_shared_key)
    let transport_key_event_id = create_transport_key_if_possible(
        conn,
        recorded_by,
        &peer_shared_key,
        &peer_shared_event_id,
    )?;

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
        transport_key_event_id,
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
/// PeerSharedFirst -> TransportKey.
///
/// InviteAccepted must come first to bind the trust anchor and trigger the guard cascade
/// that makes the copied Workspace/UserInviteBoot events valid.
pub fn accept_user_invite(
    conn: &Connection,
    recorded_by: &str,
    invite_key: &SigningKey,
    invite_event_id: &EventId,
    workspace_id: EventId,
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

    // 5. Invite key-wrap unwrap path is staged but not enabled by default yet.
    let content_key_event_id = None;

    // 6. TransportKey (signed by peer_shared_key)
    let transport_key_event_id = create_transport_key_if_possible(
        conn,
        recorded_by,
        &peer_shared_key,
        &peer_shared_event_id,
    )?;

    Ok(JoinChain {
        user_event_id,
        user_key,
        device_invite_event_id,
        device_invite_key,
        peer_shared_event_id,
        peer_shared_key,
        invite_accepted_event_id,
        transport_key_event_id,
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

/// Accept a device link invite: InviteAccepted (trust anchor) -> PeerSharedFirst -> TransportKey.
pub fn accept_device_link(
    conn: &Connection,
    recorded_by: &str,
    device_invite_key: &SigningKey,
    device_invite_event_id: &EventId,
    workspace_id: EventId,
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

    // 3. TransportKey (signed by peer_shared_key)
    let transport_key_event_id = create_transport_key_if_possible(
        conn,
        recorded_by,
        &peer_shared_key,
        &peer_shared_event_id,
    )?;

    Ok(LinkChain {
        peer_shared_event_id,
        peer_shared_key,
        invite_accepted_event_id,
        transport_key_event_id,
    })
}

/// Generate a random 32-byte content secret key, create a local SecretKey event,
/// then wrap it for our own peer_shared public key via SecretShared (self-wrap).
/// Returns the SecretKey event_id on success, None if creation fails non-fatally.
fn create_content_key_and_self_wrap(
    conn: &Connection,
    recorded_by: &str,
    peer_shared_key: &SigningKey,
    peer_shared_event_id: &EventId,
) -> Result<Option<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();

    // 1. Generate random content key
    let mut content_key_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rng, &mut content_key_bytes);

    // 2. Create SecretKey event (local-only, stores the raw key)
    let sk_evt = ParsedEvent::SecretKey(SecretKeyEvent {
        created_at_ms: now_ms(),
        key_bytes: content_key_bytes,
    });
    let key_event_id = create_event_sync(conn, recorded_by, &sk_evt)?;

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

    Ok(Some(key_event_id))
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
    // Look up first content key for this tenant from secret_keys table
    let row: Option<(String, Vec<u8>)> = conn.query_row(
        "SELECT event_id, key_bytes FROM secret_keys WHERE recorded_by = ?1 LIMIT 1",
        rusqlite::params![recorded_by],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
    ).ok();

    let (key_eid_b64, key_bytes) = match row {
        Some(r) => r,
        None => return Ok(()), // No content key yet — skip silently
    };

    if key_bytes.len() != 32 {
        return Ok(()); // Corrupt key — skip silently
    }

    let key_event_id = crate::crypto::event_id_from_base64(&key_eid_b64)
        .ok_or("invalid key event_id in secret_keys table")?;

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
    let invite_eid_b64 = event_id_to_base64(invite_event_id);

    // Look up SecretShared events where recipient_event_id = invite_event_id
    let row: Option<(Vec<u8>, String)> = conn.query_row(
        "SELECT wrapped_key, key_event_id FROM secret_shared
         WHERE recorded_by = ?1 AND recipient_event_id = ?2 LIMIT 1",
        rusqlite::params![recorded_by, &invite_eid_b64],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
    ).ok();

    let (wrapped_key_bytes, _key_eid_b64) = match row {
        Some(r) => r,
        None => return Ok(None), // No wrapped key found — skip
    };

    if wrapped_key_bytes.len() != 32 {
        return Ok(None); // Corrupt wrapped key
    }

    // Find the sender's public key from the SecretShared event's signed_by field.
    // We need to look up the event blob to get signed_by, then look up that
    // signer's public key from peers_shared.
    let sender_pub_bytes: Option<Vec<u8>> = conn.query_row(
        "SELECT p.public_key FROM secret_shared ss
         INNER JOIN events e ON e.event_id = ss.event_id
         INNER JOIN peers_shared p ON p.recorded_by = ss.recorded_by
         WHERE ss.recorded_by = ?1 AND ss.recipient_event_id = ?2
         LIMIT 1",
        rusqlite::params![recorded_by, &invite_eid_b64],
        |row| row.get(0),
    ).ok();

    let sender_pub = match sender_pub_bytes {
        Some(ref bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            match ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                Ok(vk) => vk,
                Err(_) => return Ok(None),
            }
        }
        _ => return Ok(None),
    };

    let mut wrapped_key = [0u8; 32];
    wrapped_key.copy_from_slice(&wrapped_key_bytes);

    // Unwrap: derive same shared secret using invite_private + sender_public
    let plaintext_key = unwrap_key_from_sender(
        invite_key,
        &sender_pub,
        &wrapped_key,
    );

    // Create local SecretKey event with the unwrapped content key
    let sk_evt = ParsedEvent::SecretKey(SecretKeyEvent {
        created_at_ms: now_ms(),
        key_bytes: plaintext_key,
    });
    let key_event_id = create_event_sync(conn, recorded_by, &sk_evt)?;

    Ok(Some(key_event_id))
}

/// Try to create a TransportKey event binding the local TLS cert to the peer_shared identity.
fn create_transport_key_if_possible(
    conn: &Connection,
    recorded_by: &str,
    peer_shared_key: &SigningKey,
    peer_shared_event_id: &EventId,
) -> Result<Option<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    let cert_bytes = match load_local_creds(conn, recorded_by)? {
        Some((cert, _)) => cert,
        None => return Ok(None),
    };

    let spki_fp = extract_spki_fingerprint(&cert_bytes)?;

    let evt = ParsedEvent::TransportKey(TransportKeyEvent {
        created_at_ms: now_ms(),
        spki_fingerprint: spki_fp,
        signed_by: *peer_shared_event_id,
        signer_type: 5,
        signature: [0u8; 64],
    });

    let event_id = create_signed_event_sync(conn, recorded_by, &evt, peer_shared_key)?;
    Ok(Some(event_id))
}
