//! Workspace lifecycle commands.
//!
//! These commands own the event-domain logic for workspace membership operations:
//! - Creating a new workspace (full identity chain bootstrap)
//! - Joining a workspace as a new user (invite acceptance)
//! - Adding a new device to an existing workspace (device-link acceptance)
//! - Creating user invites and device-link invites
//! - Retrying pending invite content-key unwraps
//!
//! Service.rs calls these for event-domain work; transport/sync orchestration
//! stays in service.

use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use super::identity_ops::{
    self as ops, InviteBootstrapContext, JoinChain, LinkChain, SIGNER_KIND_PENDING_INVITE_UNWRAP,
};
use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::event_modules::{
    local_signer_secret::{
        LocalSignerSecretEvent, SIGNER_KIND_PEER_SHARED, SIGNER_KIND_USER, SIGNER_KIND_WORKSPACE,
    },
    DeviceInviteFirstEvent, InviteAcceptedEvent, ParsedEvent, PeerSharedFirstEvent, UserBootEvent,
    UserInviteBootEvent, WorkspaceEvent,
};
use crate::projection::apply::project_one;
use crate::projection::create::{
    create_event_staged, create_event_synchronous, create_signed_event_synchronous,
    event_id_or_blocked,
};

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Emit a local_signer_secret event for the given signer identity.
/// The event is projected into `local_signer_material` via the projector.
fn emit_local_signer_secret(
    db: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
    signer_kind: u8,
    signing_key: &SigningKey,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let evt = ParsedEvent::LocalSignerSecret(LocalSignerSecretEvent {
        created_at_ms: now_ms(),
        signer_event_id: *signer_event_id,
        signer_kind,
        private_key_bytes: signing_key.to_bytes(),
    });
    event_id_or_blocked(create_event_synchronous(db, recorded_by, &evt))
        .map_err(|e| format!("emit local_signer_secret failed: {}", e).into())
}

// ─── Result types ───

/// Result of creating a new workspace (full identity chain bootstrap).
pub struct CreateWorkspaceResult {
    pub workspace_id: EventId,
    pub peer_shared_event_id: EventId,
    pub peer_shared_key: SigningKey,
}

// ─── 1. Start workspace ───

/// Create a new workspace with a full identity chain.
///
/// Creates: Workspace → InviteAccepted (trust anchor) → UserInviteBoot →
/// UserBoot → DeviceInviteFirst → PeerSharedFirst + local signer secrets +
/// content key material.
///
/// Returns the peer_shared event ID and signing key needed for transport
/// identity derivation.
///
/// Idempotent: if a local peer signer already exists, returns it without
/// creating new events.
pub fn create_workspace(
    db: &Connection,
    recorded_by: &str,
    workspace_name: &str,
    username: &str,
    device_name: &str,
) -> Result<CreateWorkspaceResult, Box<dyn std::error::Error + Send + Sync>> {
    // Idempotent check: if this tenant identity already exists, return it.
    // Strictly scoped by the provided recorded_by; no cross-tenant fallback.
    if let Some((eid, signing_key)) = load_local_peer_signer(db, recorded_by)? {
        let workspace_id = db
            .query_row(
                "SELECT workspace_id FROM trust_anchors WHERE peer_id = ?1",
                rusqlite::params![recorded_by],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .and_then(|b64| crate::crypto::event_id_from_base64(&b64))
            .unwrap_or([0u8; 32]);
        return Ok(CreateWorkspaceResult {
            workspace_id,
            peer_shared_event_id: eid,
            peer_shared_key: signing_key,
        });
    }
    // Strict scope check:
    // - Fresh DB (no local creds): allow bootstrap.
    // - Existing DB with local creds: recorded_by must identify a known tenant.
    // This prevents unscoped aliases (e.g. "bootstrap") from acting on an
    // arbitrary tenant in multi-tenant databases.
    let known_tenant: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM local_transport_creds WHERE peer_id = ?1 LIMIT 1)",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )?;
    let creds_count: i64 =
        db.query_row("SELECT COUNT(*) FROM local_transport_creds", [], |row| {
            row.get(0)
        })?;
    if !known_tenant && creds_count > 0 {
        return Err(format!(
            "create_workspace requires scoped tenant identity; recorded_by {} has no local transport creds",
            recorded_by
        )
        .into());
    }

    let mut rng = rand::thread_rng();

    // Pre-derive peer_id from PeerShared key so all events are written under
    // the correct recorded_by from the start (no finalize_identity needed).
    // Pure crypto derivation — transport cert is installed via projection when
    // the PeerShared LocalSignerSecret is emitted in step 7.
    let peer_shared_key = SigningKey::generate(&mut rng);
    let derived_peer_id = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &peer_shared_key.verifying_key().to_bytes(),
    ));

    // 1. Pre-compute workspace event_id so we can seed the trust anchor
    //    before any events are stored. This ensures lookup_workspace_id()
    //    returns the correct value for neg_items insertion from the start,
    //    avoiding empty-workspace_id rows.
    let workspace_key = SigningKey::generate(&mut rng);
    let ws = ParsedEvent::Workspace(WorkspaceEvent {
        created_at_ms: now_ms(),
        public_key: workspace_key.verifying_key().to_bytes(),
        name: workspace_name.to_string(),
    });
    let ws_blob = crate::event_modules::encode_event(&ws)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;
    let ws_eid = crate::crypto::hash_event(&ws_blob);
    let ws_eid_b64 = event_id_to_base64(&ws_eid);

    // 2. Seed trust anchor before any event storage. InviteAccepted's
    //    INSERT OR IGNORE will be a no-op since the row already exists.
    db.execute(
        "INSERT OR IGNORE INTO trust_anchors (peer_id, workspace_id) VALUES (?1, ?2)",
        rusqlite::params![&derived_peer_id, &ws_eid_b64],
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    // 3. Workspace event (staged — guard may still block, re-projected below)
    let ws_eid2 = create_event_staged(db, &derived_peer_id, &ws)?;
    assert_eq!(ws_eid, ws_eid2, "pre-computed workspace event_id mismatch");

    // 4. InviteAccepted (local event — trust anchor already seeded above)
    let ia = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: now_ms(),
        invite_event_id: ws_eid,
        workspace_id: ws_eid,
    });
    let _ia_eid = create_event_synchronous(db, &derived_peer_id, &ia)?;
    project_one(db, &derived_peer_id, &ws_eid)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    // 3. UserInviteBoot (signed by workspace_key)
    let invite_key = SigningKey::generate(&mut rng);
    let uib = ParsedEvent::UserInviteBoot(UserInviteBootEvent {
        created_at_ms: now_ms(),
        public_key: invite_key.verifying_key().to_bytes(),
        workspace_id: ws_eid,
        signed_by: ws_eid,
        signer_type: 1,
        signature: [0u8; 64],
    });
    let uib_eid = create_signed_event_synchronous(db, &derived_peer_id, &uib, &workspace_key)?;

    // 4. UserBoot (signed by invite_key)
    let user_key = SigningKey::generate(&mut rng);
    let ub = ParsedEvent::UserBoot(UserBootEvent {
        created_at_ms: now_ms(),
        public_key: user_key.verifying_key().to_bytes(),
        username: username.to_string(),
        signed_by: uib_eid,
        signer_type: 2,
        signature: [0u8; 64],
    });
    let ub_eid = create_signed_event_synchronous(db, &derived_peer_id, &ub, &invite_key)?;

    // 5. DeviceInviteFirst (signed by user_key)
    let device_invite_key = SigningKey::generate(&mut rng);
    let dif = ParsedEvent::DeviceInviteFirst(DeviceInviteFirstEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_key.verifying_key().to_bytes(),
        signed_by: ub_eid,
        signer_type: 4,
        signature: [0u8; 64],
    });
    let dif_eid = create_signed_event_synchronous(db, &derived_peer_id, &dif, &user_key)?;

    // 6. PeerSharedFirst (signed by device_invite_key; key pre-generated above)
    let psf = ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
        created_at_ms: now_ms(),
        public_key: peer_shared_key.verifying_key().to_bytes(),
        user_event_id: ub_eid,
        device_name: device_name.to_string(),
        signed_by: dif_eid,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let psf_eid = create_signed_event_synchronous(db, &derived_peer_id, &psf, &device_invite_key)?;

    // 7. Emit local_signer_secret events for all three signing keys.
    // Transport identity is already installed, so all writes use derived_peer_id.
    emit_local_signer_secret(
        db,
        &derived_peer_id,
        &psf_eid,
        SIGNER_KIND_PEER_SHARED,
        &peer_shared_key,
    )?;
    emit_local_signer_secret(db, &derived_peer_id, &ub_eid, SIGNER_KIND_USER, &user_key)?;
    emit_local_signer_secret(
        db,
        &derived_peer_id,
        &ws_eid,
        SIGNER_KIND_WORKSPACE,
        &workspace_key,
    )?;

    // 8. Seed deterministic local content-key material.
    let _ = ops::ensure_content_key_for_peer(db, &derived_peer_id, &peer_shared_key, &psf_eid)?;

    Ok(CreateWorkspaceResult {
        workspace_id: ws_eid,
        peer_shared_event_id: psf_eid,
        peer_shared_key,
    })
}

// ─── 2. Join workspace as new user ───

/// Join a workspace by accepting a user invite.
///
/// Creates: InviteAccepted → UserBoot → DeviceInviteFirst → PeerSharedFirst +
/// unwraps bootstrap content key.
///
/// Returns the JoinChain with keys/ids needed by service for transport setup.
/// Signer secrets are NOT emitted here — call `persist_join_signer_secrets`
/// after push-back sync completes.
pub fn join_workspace_as_new_user(
    db: &Connection,
    recorded_by: &str,
    invite_key: &SigningKey,
    invite_event_id: &EventId,
    workspace_id: EventId,
    username: &str,
    device_name: &str,
    peer_shared_key: SigningKey,
) -> Result<JoinChain, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::thread_rng();

    // Persist invite key material so content-key unwrap can be retried after
    // late-arriving SecretShared prerequisites.
    ops::store_pending_invite_unwrap_key(db, recorded_by, invite_event_id, invite_key)?;

    // 1. InviteAccepted (local event) — binds trust anchor, triggers guard cascade
    let ia_evt = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: now_ms(),
        invite_event_id: *invite_event_id,
        workspace_id,
    });
    let invite_accepted_event_id = create_event_synchronous(db, recorded_by, &ia_evt)?;

    // 2. UserBoot (signed by invite_key) — may block if invite event not yet synced.
    // Tolerates Blocked: the event is stored and will project via cascade when
    // the invite event arrives.
    let user_key = SigningKey::generate(&mut rng);
    let ub_evt = ParsedEvent::UserBoot(UserBootEvent {
        created_at_ms: now_ms(),
        public_key: user_key.verifying_key().to_bytes(),
        username: username.to_string(),
        signed_by: *invite_event_id,
        signer_type: 2,
        signature: [0u8; 64],
    });
    let user_event_id = event_id_or_blocked(create_signed_event_synchronous(
        db,
        recorded_by,
        &ub_evt,
        invite_key,
    ))?;

    // 3. DeviceInviteFirst (signed by user_key) — may block if UserBoot is blocked.
    let device_invite_key = SigningKey::generate(&mut rng);
    let dif_evt = ParsedEvent::DeviceInviteFirst(DeviceInviteFirstEvent {
        created_at_ms: now_ms(),
        public_key: device_invite_key.verifying_key().to_bytes(),
        signed_by: user_event_id,
        signer_type: 4,
        signature: [0u8; 64],
    });
    let device_invite_event_id = event_id_or_blocked(create_signed_event_synchronous(
        db,
        recorded_by,
        &dif_evt,
        &user_key,
    ))?;

    // 4. PeerSharedFirst (signed by device_invite_key) — may block.
    let psf_evt = ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
        created_at_ms: now_ms(),
        public_key: peer_shared_key.verifying_key().to_bytes(),
        user_event_id,
        device_name: device_name.to_string(),
        signed_by: device_invite_event_id,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let peer_shared_event_id = event_id_or_blocked(create_signed_event_synchronous(
        db,
        recorded_by,
        &psf_evt,
        &device_invite_key,
    ))?;

    // 5. Unwrap inviter-provided content key targeted at this invite (if present).
    // May return None if the content key event hasn't been synced yet.
    let content_key_event_id =
        ops::unwrap_content_key_from_invite(db, recorded_by, invite_key, invite_event_id)?;
    if content_key_event_id.is_some() {
        ops::clear_pending_invite_unwrap_key(db, recorded_by, invite_event_id)?;
    }

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

/// Persist signer secrets for a join.
///
/// The peer_shared LocalSignerSecret triggers ApplyTransportIdentityIntent
/// on projection, which installs the PeerShared-derived transport identity.
/// Events may block if the identity chain hasn't completed yet; they will
/// project via cascade when prerequisites arrive.
///
/// With pre-derive, `recorded_by` is already the final PeerShared-derived
/// identity, so no scoping or load_transport_peer_id is needed.
pub fn persist_join_signer_secrets(
    db: &Connection,
    recorded_by: &str,
    join: &JoinChain,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    emit_local_signer_secret(
        db,
        recorded_by,
        &join.peer_shared_event_id,
        SIGNER_KIND_PEER_SHARED,
        &join.peer_shared_key,
    )?;
    emit_local_signer_secret(
        db,
        recorded_by,
        &join.user_event_id,
        SIGNER_KIND_USER,
        &join.user_key,
    )?;
    Ok(())
}

// ─── 3. Add new device ───

/// Add a new device to an existing workspace by accepting a device link invite.
///
/// Creates: InviteAccepted → PeerSharedFirst.
///
/// Returns the LinkChain with keys/ids needed by service for transport setup.
/// Signer secrets are NOT emitted here — call `persist_link_signer_secrets`
/// separately.
pub fn add_device_to_workspace(
    db: &Connection,
    recorded_by: &str,
    device_invite_key: &SigningKey,
    device_invite_event_id: &EventId,
    workspace_id: EventId,
    user_event_id: EventId,
    device_name: &str,
    peer_shared_key: SigningKey,
) -> Result<LinkChain, Box<dyn std::error::Error + Send + Sync>> {
    // 1. InviteAccepted (local event) — binds trust anchor, triggers guard cascade
    let ia_evt = ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: now_ms(),
        invite_event_id: *device_invite_event_id,
        workspace_id,
    });
    let invite_accepted_event_id = create_event_synchronous(db, recorded_by, &ia_evt)?;

    // 2. PeerSharedFirst (signed by device_invite_key) — may block if device invite
    // event not yet synced. Tolerates Blocked: the event is stored and will project
    // via cascade when prerequisites arrive.
    let psf_evt = ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
        created_at_ms: now_ms(),
        public_key: peer_shared_key.verifying_key().to_bytes(),
        user_event_id,
        device_name: device_name.to_string(),
        signed_by: *device_invite_event_id,
        signer_type: 3,
        signature: [0u8; 64],
    });
    let peer_shared_event_id = event_id_or_blocked(create_signed_event_synchronous(
        db,
        recorded_by,
        &psf_evt,
        device_invite_key,
    ))?;

    Ok(LinkChain {
        peer_shared_event_id,
        peer_shared_key,
        invite_accepted_event_id,
    })
}

/// Persist signer secrets for a device link.
///
/// Events may block if the identity chain hasn't completed yet.
pub fn persist_link_signer_secrets(
    db: &Connection,
    recorded_by: &str,
    link: &LinkChain,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    emit_local_signer_secret(
        db,
        recorded_by,
        &link.peer_shared_event_id,
        SIGNER_KIND_PEER_SHARED,
        &link.peer_shared_key,
    )?;
    Ok(())
}

// ─── 4. Create user invite ───

/// Result of creating a user or device-link invite.
pub struct InviteResult {
    pub invite_link: String,
    pub invite_event_id: EventId,
}

/// Create a user invite for the workspace.
///
/// Event-domain logic: ensures content key material → creates invite event chain
/// (UserInviteBoot + optional wrapped content key) → formats invite link.
pub fn create_user_invite(
    db: &Connection,
    recorded_by: &str,
    workspace_key: &SigningKey,
    workspace_id: &EventId,
    peer_shared_key: &SigningKey,
    peer_shared_event_id: &EventId,
    bootstrap_addr: &str,
    bootstrap_spki: &[u8; 32],
) -> Result<InviteResult, Box<dyn std::error::Error + Send + Sync>> {
    let _ =
        ops::ensure_content_key_for_peer(db, recorded_by, peer_shared_key, peer_shared_event_id)?;

    let ctx = InviteBootstrapContext {
        bootstrap_addr,
        bootstrap_spki,
    };
    let invite = ops::create_user_invite_events(
        db,
        recorded_by,
        workspace_key,
        workspace_id,
        Some(peer_shared_key),
        Some(peer_shared_event_id),
        Some(&ctx),
    )?;

    let invite_link =
        super::invite_link::create_invite_link(&invite, bootstrap_addr, bootstrap_spki)?;

    Ok(InviteResult {
        invite_link,
        invite_event_id: invite.invite_event_id,
    })
}

// ─── 5. Create device-link invite ───

/// Create a device-link invite for an existing user.
///
/// Event-domain logic: creates device invite event (DeviceInviteFirst) →
/// formats invite link.
pub fn create_device_link_invite(
    db: &Connection,
    recorded_by: &str,
    user_key: &SigningKey,
    user_event_id: &EventId,
    workspace_id: &EventId,
    bootstrap_addr: &str,
    bootstrap_spki: &[u8; 32],
) -> Result<InviteResult, Box<dyn std::error::Error + Send + Sync>> {
    let ctx = InviteBootstrapContext {
        bootstrap_addr,
        bootstrap_spki,
    };
    let invite = ops::create_device_link_invite_events(
        db,
        recorded_by,
        user_key,
        user_event_id,
        workspace_id,
        Some(&ctx),
    )?;

    let invite_link =
        super::invite_link::create_invite_link(&invite, bootstrap_addr, bootstrap_spki)?;

    Ok(InviteResult {
        invite_link,
        invite_event_id: invite.invite_event_id,
    })
}

// ─── 6. Retry pending invite content-key unwraps ───

/// Retry pending content-key unwraps for invite accept flows.
///
/// Accept paths persist invite private keys in `local_signer_material` with
/// `signer_kind=4` so runtime projection can retry unwrap when SecretShared
/// arrives later via sync.
pub fn retry_pending_invite_content_key_unwraps(
    db: &Connection,
    recorded_by: &str,
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = db.prepare(
        "SELECT signer_event_id, private_key
         FROM local_signer_material
         WHERE recorded_by = ?1 AND signer_kind = ?2",
    )?;
    let rows = stmt
        .query_map(
            rusqlite::params![recorded_by, SIGNER_KIND_PENDING_INVITE_UNWRAP],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )?
        .collect::<Result<Vec<_>, _>>()?;
    drop(stmt);

    let mut unwrapped = 0usize;
    for (invite_event_b64, key_bytes) in rows {
        let invite_event_id = match event_id_from_base64(&invite_event_b64) {
            Some(eid) => eid,
            None => continue,
        };
        if key_bytes.len() != 32 {
            continue;
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        let invite_key = SigningKey::from_bytes(&key_arr);

        if ops::unwrap_content_key_from_invite(db, recorded_by, &invite_key, &invite_event_id)?
            .is_some()
        {
            ops::clear_pending_invite_unwrap_key(db, recorded_by, &invite_event_id)?;
            unwrapped += 1;
        }
    }

    Ok(unwrapped)
}

// ─── 7. Key loading helpers ───

/// Load workspace signing key from local signer material.
///
/// Returns the workspace event ID and signing key, or None if not found.
pub fn load_workspace_signing_key(
    db: &Connection,
    recorded_by: &str,
) -> Result<Option<(EventId, SigningKey)>, Box<dyn std::error::Error + Send + Sync>> {
    use rusqlite::OptionalExtension;
    if let Some((eid_b64, key_bytes)) = db
        .query_row(
            "SELECT signer_event_id, private_key FROM local_signer_material
             WHERE recorded_by = ?1 AND signer_kind = 1
             LIMIT 1",
            rusqlite::params![recorded_by],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
    {
        let key_arr: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| "bad signing key length in local signer table")?;
        let signing_key = SigningKey::from_bytes(&key_arr);
        let eid =
            crate::crypto::event_id_from_base64(&eid_b64).ok_or("bad workspace signer event_id")?;
        return Ok(Some((eid, signing_key)));
    }
    Ok(None)
}

// ─── 8. Test-only helpers ───

/// Create a user invite without bootstrap context.
/// Returns InviteData directly without formatting an invite link.
/// Used by test fixtures and scenarios that handle bootstrap separately.
pub fn create_user_invite_raw(
    db: &Connection,
    recorded_by: &str,
    workspace_key: &SigningKey,
    workspace_id: &EventId,
    sender_peer_shared_key: Option<&SigningKey>,
    sender_peer_shared_event_id: Option<&EventId>,
) -> Result<super::identity_ops::InviteData, Box<dyn std::error::Error + Send + Sync>> {
    ops::create_user_invite_events(
        db,
        recorded_by,
        workspace_key,
        workspace_id,
        sender_peer_shared_key,
        sender_peer_shared_event_id,
        None,
    )
}

/// Create a device-link invite without bootstrap context.
/// Returns InviteData directly without formatting an invite link.
/// Used by test fixtures and scenarios that handle bootstrap separately.
pub fn create_device_link_invite_raw(
    db: &Connection,
    recorded_by: &str,
    user_key: &SigningKey,
    user_event_id: &EventId,
    workspace_id: &EventId,
) -> Result<super::identity_ops::InviteData, Box<dyn std::error::Error + Send + Sync>> {
    ops::create_device_link_invite_events(
        db,
        recorded_by,
        user_key,
        user_event_id,
        workspace_id,
        None,
    )
}

// ─── Private helpers ───

pub(super) fn load_local_peer_signer(
    db: &Connection,
    recorded_by: &str,
) -> Result<Option<(EventId, SigningKey)>, Box<dyn std::error::Error + Send + Sync>> {
    crate::event_modules::peer_shared::load_local_peer_signer(db, recorded_by)
}

// ─── Response types ───

pub use super::commands_api::{
    accept_device_link, accept_invite, create_device_link_for_peer, create_invite_for_db,
    create_invite_with_spki, create_workspace_for_db, AcceptDeviceLinkResponse,
    AcceptInviteResponse, CreateInviteResponse, CreateWorkspaceResponse,
};


#[cfg(test)]
mod tests;
