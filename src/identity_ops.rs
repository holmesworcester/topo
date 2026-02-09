use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use crate::crypto::EventId;
use crate::events::*;
use crate::projection::create::{create_event_sync, create_signed_event_sync, event_id_or_blocked, require_valid_event_id};
use crate::transport::extract_spki_fingerprint;
use crate::transport_identity::transport_cert_paths_from_db;

use std::time::{SystemTime, UNIX_EPOCH};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Result of bootstrapping a full workspace identity chain.
pub struct IdentityChain {
    pub workspace_event_id: EventId,
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
}

/// Result of accepting a device link invite.
pub struct LinkChain {
    pub peer_shared_event_id: EventId,
    pub peer_shared_key: SigningKey,
    pub invite_accepted_event_id: EventId,
    pub transport_key_event_id: Option<EventId>,
}

/// Data needed to transfer an invite between accounts.
pub struct InviteData {
    pub invite_event_id: EventId,
    pub invite_key: SigningKey,
    pub workspace_id: [u8; 32],
    pub workspace_event_id: EventId,
    pub invite_type: InviteType,
}

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
    workspace_id: [u8; 32],
    db_path: &str,
) -> Result<IdentityChain, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();

    // 1. Workspace event (unsigned) — guard-blocked until trust anchor exists
    let workspace_key = SigningKey::generate(&mut rng);
    let workspace_pub = workspace_key.verifying_key().to_bytes();
    let net_evt = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: workspace_pub,
        workspace_id: workspace_id,
    });
    let workspace_event_id = event_id_or_blocked(create_event_sync(conn, recorded_by, &net_evt))?;

    // 2. UserInviteBoot (signed by workspace_key) — blocked until Workspace is valid
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pub = invite_key.verifying_key().to_bytes();
    let uib_evt = ParsedEvent::UserInviteBoot(UserInviteBootEvent {
        created_at_ms: now_ms(),
        public_key: invite_pub,
        workspace_id: workspace_id,
        signed_by: workspace_event_id,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let user_invite_event_id =
        event_id_or_blocked(create_signed_event_sync(conn, recorded_by, &uib_evt, &workspace_key))?;

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
    let user_event_id =
        event_id_or_blocked(create_signed_event_sync(conn, recorded_by, &ub_evt, &invite_key))?;

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
    let device_invite_event_id =
        event_id_or_blocked(create_signed_event_sync(conn, recorded_by, &dif_evt, &user_key))?;

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
    let peer_shared_event_id = event_id_or_blocked(create_signed_event_sync(
        conn,
        recorded_by,
        &psf_evt,
        &device_invite_key,
    ))?;

    // 7. AdminBoot (signed by workspace_key, dep: user_event)
    let admin_key = SigningKey::generate(&mut rng);
    let admin_pub = admin_key.verifying_key().to_bytes();
    let ab_evt = ParsedEvent::AdminBoot(AdminBootEvent {
        created_at_ms: now_ms(),
        public_key: admin_pub,
        user_event_id,
        signed_by: workspace_event_id,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let admin_event_id =
        event_id_or_blocked(create_signed_event_sync(conn, recorded_by, &ab_evt, &workspace_key))?;

    // 8. TransportKey (signed by peer_shared_key)
    let transport_key_event_id = create_transport_key_if_possible(
        conn,
        recorded_by,
        db_path,
        &peer_shared_key,
        &peer_shared_event_id,
    )?;

    Ok(IdentityChain {
        workspace_event_id,
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
    })
}

/// Create a user invite (admin creates this). Returns InviteData with the private key
/// needed for the invitee to accept.
pub fn create_user_invite(
    conn: &Connection,
    recorded_by: &str,
    workspace_key: &SigningKey,
    workspace_event_id: &EventId,
    workspace_id: [u8; 32],
) -> Result<InviteData, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();
    let invite_key = SigningKey::generate(&mut rng);
    let invite_pub = invite_key.verifying_key().to_bytes();

    let evt = ParsedEvent::UserInviteBoot(UserInviteBootEvent {
        created_at_ms: now_ms(),
        public_key: invite_pub,
        workspace_id: workspace_id,
        signed_by: *workspace_event_id,
        signer_type: 1,
        signature: [0u8; 64],
    });

    let invite_event_id =
        event_id_or_blocked(create_signed_event_sync(conn, recorded_by, &evt, workspace_key))?;

    Ok(InviteData {
        invite_event_id,
        invite_key,
        workspace_id,
        workspace_event_id: *workspace_event_id,
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
    workspace_id: [u8; 32],
    db_path: &str,
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
    let user_event_id =
        require_valid_event_id(create_signed_event_sync(conn, recorded_by, &ub_evt, invite_key))?;

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
    let device_invite_event_id =
        require_valid_event_id(create_signed_event_sync(conn, recorded_by, &dif_evt, &user_key))?;

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
    let peer_shared_event_id = require_valid_event_id(create_signed_event_sync(
        conn,
        recorded_by,
        &psf_evt,
        &device_invite_key,
    ))?;

    // 5. TransportKey (signed by peer_shared_key)
    let transport_key_event_id = create_transport_key_if_possible(
        conn,
        recorded_by,
        db_path,
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
    })
}

/// Create a device link invite (user creates this for linking another device).
pub fn create_device_link_invite(
    conn: &Connection,
    recorded_by: &str,
    user_key: &SigningKey,
    user_event_id: &EventId,
    workspace_id: [u8; 32],
    workspace_event_id: &EventId,
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

    let invite_event_id =
        event_id_or_blocked(create_signed_event_sync(conn, recorded_by, &evt, user_key))?;

    Ok(InviteData {
        invite_event_id,
        invite_key: device_invite_key,
        workspace_id,
        workspace_event_id: *workspace_event_id,
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
    workspace_id: [u8; 32],
    db_path: &str,
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
    let peer_shared_event_id = require_valid_event_id(create_signed_event_sync(
        conn,
        recorded_by,
        &psf_evt,
        device_invite_key,
    ))?;

    // 3. TransportKey (signed by peer_shared_key)
    let transport_key_event_id = create_transport_key_if_possible(
        conn,
        recorded_by,
        db_path,
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

/// Try to create a TransportKey event binding the local TLS cert to the peer_shared identity.
fn create_transport_key_if_possible(
    conn: &Connection,
    recorded_by: &str,
    db_path: &str,
    peer_shared_key: &SigningKey,
    peer_shared_event_id: &EventId,
) -> Result<Option<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    let (cert_path, _key_path) = transport_cert_paths_from_db(db_path);
    if !cert_path.exists() {
        return Ok(None);
    }

    let cert_bytes = std::fs::read(&cert_path)?;
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
