use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::commands::{
    add_device_to_workspace, create_device_link_invite, create_user_invite, create_workspace,
    join_workspace_as_new_user, load_local_peer_signer, load_workspace_signing_key,
    persist_join_signer_secrets, persist_link_signer_secrets,
};
use crate::crypto::{event_id_to_base64, EventId};
use crate::service::{open_db_for_peer, open_db_load};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateWorkspaceResponse {
    pub peer_id: String,
    pub workspace_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateInviteResponse {
    pub invite_link: String,
    pub invite_event_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptInviteResponse {
    pub peer_id: String,
    pub user_event_id: String,
    pub peer_shared_event_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptDeviceLinkResponse {
    pub peer_id: String,
    pub peer_shared_event_id: String,
}

// DB-path-level command wrappers (moved from service.rs)

pub fn create_workspace_for_db(
    db_path: &str,
    workspace_name: &str,
    username: &str,
    device_name: &str,
) -> Result<CreateWorkspaceResponse, Box<dyn std::error::Error + Send + Sync>> {
    use crate::db::{open_connection, schema::create_tables};
    use crate::transport::identity::load_transport_peer_id;

    let conn = open_connection(db_path)?;
    create_tables(&conn)?;

    let mut create_scope: Option<String> = None;

    // Check if identity already exists
    if let Ok(peer_id) = load_transport_peer_id(&conn) {
        create_scope = Some(peer_id.clone());
        // Already bootstrapped — return existing workspace info
        let workspaces = super::list_items(&conn, &peer_id)?;
        if let Some(ws) = workspaces.first() {
            return Ok(CreateWorkspaceResponse {
                peer_id,
                workspace_id: ws.event_id.clone(),
            });
        }
    }

    // Bootstrap new identity chain via workspace command API.
    // create_workspace pre-derives the PeerShared transport identity and writes
    // all events under it, so no finalize_identity rewrite is needed.
    let recorded_by = create_scope.as_deref().unwrap_or("bootstrap");
    let _result = create_workspace(&conn, recorded_by, workspace_name, username, device_name)?;
    let derived =
        load_transport_peer_id(&conn).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("load transport peer id failed: {}", e).into()
        })?;

    let workspaces = super::list_items(&conn, &derived)?;
    let workspace_id = workspaces
        .first()
        .map(|ws| ws.event_id.clone())
        .unwrap_or_default();

    Ok(CreateWorkspaceResponse {
        peer_id: derived,
        workspace_id,
    })
}

/// Create a user invite for the active workspace.
pub fn create_invite_for_db(
    db_path: &str,
    bootstrap_addr: &str,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) =
        open_db_load(db_path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("No transport identity: {}", e).into()
        })?;

    let ws_eid = super::resolve_workspace_for_peer(&db, &recorded_by)?;
    let (_ws_signer_eid, workspace_key) = load_workspace_signing_key(&db, &recorded_by)?
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            "No workspace signing key found. Only workspace creators can invite.".into()
        })?;

    let (sender_peer_eid, sender_peer_key) = load_local_peer_signer(&db, &recorded_by)?
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            "No local peer signer found for invite creation.".into()
        })?;

    // Get local SPKI for the bootstrap address
    let spki_bytes = hex::decode(&recorded_by)?;
    let mut bootstrap_spki = [0u8; 32];
    bootstrap_spki.copy_from_slice(&spki_bytes);

    let result = create_user_invite(
        &db,
        &recorded_by,
        &workspace_key,
        &ws_eid,
        &sender_peer_key,
        &sender_peer_eid,
        bootstrap_addr,
        &bootstrap_spki,
    )?;

    Ok(CreateInviteResponse {
        invite_link: result.invite_link,
        invite_event_id: event_id_to_base64(&result.invite_event_id),
    })
}

/// Create invite with an explicit SPKI hex.
pub fn create_invite_with_spki(
    db_path: &str,
    public_addr: &str,
    public_spki_hex: &str,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) =
        open_db_load(db_path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("No transport identity: {}", e).into()
        })?;

    let ws_eid = super::resolve_workspace_for_peer(&db, &recorded_by)?;
    let (_ws_signer_eid, workspace_key) = load_workspace_signing_key(&db, &recorded_by)?
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            "No workspace signing key found.".into()
        })?;

    let (sender_peer_eid, sender_peer_key) = load_local_peer_signer(&db, &recorded_by)?
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            "No local peer signer found.".into()
        })?;

    let spki_bytes = hex::decode(public_spki_hex)?;
    if spki_bytes.len() != 32 {
        return Err("SPKI must be 32 bytes hex".into());
    }
    let mut bootstrap_spki = [0u8; 32];
    bootstrap_spki.copy_from_slice(&spki_bytes);

    let result = create_user_invite(
        &db,
        &recorded_by,
        &workspace_key,
        &ws_eid,
        &sender_peer_key,
        &sender_peer_eid,
        public_addr,
        &bootstrap_spki,
    )?;

    Ok(CreateInviteResponse {
        invite_link: result.invite_link,
        invite_event_id: event_id_to_base64(&result.invite_event_id),
    })
}

struct PreparedInviteAcceptance {
    db: Connection,
    invite: super::invite_link::ParsedInviteLink,
    invite_key: SigningKey,
    invite_event_id: EventId,
    workspace_id: EventId,
    derived_peer_id: String,
    peer_shared_key: SigningKey,
}

fn prepare_invite_acceptance(
    db_path: &str,
    invite_link_str: &str,
    expected_kind: super::invite_link::InviteLinkKind,
    expected_kind_error: &str,
) -> Result<PreparedInviteAcceptance, Box<dyn std::error::Error + Send + Sync>> {
    use crate::contracts::transport_identity_contract::{
        TransportIdentityAdapter, TransportIdentityIntent,
    };
    use crate::db::{open_connection, schema::create_tables};
    use crate::transport::identity_adapter::ConcreteTransportIdentityAdapter;

    let invite = super::invite_link::parse_invite_link(invite_link_str).map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("Invalid invite link: {}", e).into()
        },
    )?;
    if invite.kind != expected_kind {
        return Err(expected_kind_error.into());
    }

    let invite_key = invite.invite_signing_key();
    let invite_event_id = invite.invite_event_id;
    let workspace_id = invite.workspace_id;

    // Pre-derive peer_id from PeerShared key so all events are written under
    // the correct recorded_by from the start (no finalize_identity needed).
    let mut rng = rand::thread_rng();
    let peer_shared_key = SigningKey::generate(&mut rng);
    let derived_peer_id = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &peer_shared_key.verifying_key().to_bytes(),
    ));

    // Install invite-derived bootstrap transport identity for the initial handshake.
    let db = {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
        let adapter = ConcreteTransportIdentityAdapter;
        adapter
            .apply_intent(
                &db,
                TransportIdentityIntent::InstallBootstrapIdentityFromInviteKey {
                    invite_private_key: invite_key.to_bytes(),
                },
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("Failed to install bootstrap transport identity: {}", e).into()
            })?;
        db
    };

    // Record bootstrap context before accept so InviteAccepted projection can
    // materialize trust rows for this tenant.
    crate::db::transport_trust::append_bootstrap_context(
        &db,
        &derived_peer_id,
        &event_id_to_base64(&invite_event_id),
        &event_id_to_base64(&workspace_id),
        &invite.bootstrap_addr,
        &invite.bootstrap_spki_fingerprint,
    )?;

    Ok(PreparedInviteAcceptance {
        db,
        invite,
        invite_key,
        invite_event_id,
        workspace_id,
        derived_peer_id,
        peer_shared_key,
    })
}

/// Accept a user invite via projection-first flow.
///
/// NOT async. Parses link, pre-derives PeerShared identity, records bootstrap
/// context, creates identity chain, and persists secrets. No finalize_identity
/// needed — all events are written under the final peer_id from the start.
pub fn accept_invite(
    db_path: &str,
    invite_link_str: &str,
    username: &str,
    devicename: &str,
) -> Result<AcceptInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let PreparedInviteAcceptance {
        db,
        invite_key,
        invite_event_id,
        workspace_id,
        derived_peer_id,
        peer_shared_key,
        ..
    } = prepare_invite_acceptance(
        db_path,
        invite_link_str,
        super::invite_link::InviteLinkKind::User,
        "Expected a user invite link (topo://invite/...)",
    )?;

    // Accept the invite: creates identity chain via workspace command API.
    let join = join_workspace_as_new_user(
        &db,
        &derived_peer_id,
        &invite_key,
        &invite_event_id,
        workspace_id,
        username,
        devicename,
        peer_shared_key,
    )?;

    let psf_b64 = event_id_to_base64(&join.peer_shared_event_id);

    // Persist signer secrets.
    persist_join_signer_secrets(&db, &derived_peer_id, &join)?;

    Ok(AcceptInviteResponse {
        peer_id: derived_peer_id,
        user_event_id: event_id_to_base64(&join.user_event_id),
        peer_shared_event_id: psf_b64,
    })
}

/// Accept a device link invite via projection-first flow.
///
/// NOT async. Mirrors `accept_invite` but for device-link invites.
/// Pre-derives PeerShared identity so no finalize_identity is needed.
pub fn accept_device_link(
    db_path: &str,
    invite_link_str: &str,
    devicename: &str,
) -> Result<AcceptDeviceLinkResponse, Box<dyn std::error::Error + Send + Sync>> {
    let PreparedInviteAcceptance {
        db,
        invite,
        invite_key,
        invite_event_id,
        workspace_id,
        derived_peer_id,
        peer_shared_key,
    } = prepare_invite_acceptance(
        db_path,
        invite_link_str,
        super::invite_link::InviteLinkKind::DeviceLink,
        "Expected a device link (topo://link/...)",
    )?;

    let user_event_id = match invite.invite_type {
        super::identity_ops::InviteType::DeviceLink { user_event_id: uid } => uid,
        _ => return Err("Expected DeviceLink invite type".into()),
    };

    // Accept the device link: creates identity chain.
    let link = add_device_to_workspace(
        &db,
        &derived_peer_id,
        &invite_key,
        &invite_event_id,
        workspace_id,
        user_event_id,
        devicename,
        peer_shared_key,
    )?;

    let psf_b64 = event_id_to_base64(&link.peer_shared_event_id);

    // Persist signer secrets.
    persist_link_signer_secrets(&db, &derived_peer_id, &link)?;

    Ok(AcceptDeviceLinkResponse {
        peer_id: derived_peer_id,
        peer_shared_event_id: psf_b64,
    })
}

/// Create a device link for a specific peer (daemon provides the peer_id).
pub fn create_device_link_for_peer(
    db_path: &str,
    peer_id: &str,
    public_addr: &str,
    public_spki_hex: Option<&str>,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;

    // Load user key from local_user_keys
    let (user_event_id, user_key) = crate::event_modules::peer_shared::load_local_user_key(
        &db, peer_id,
    )?
    .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
        "No local user key found. Only workspace creators/inviters can create device links.".into()
    })?;

    let workspace_id = super::resolve_workspace_for_peer(&db, peer_id)?;

    // Resolve SPKI: use provided or fall back to peer's transport SPKI
    let bootstrap_spki = if let Some(spki_hex) = public_spki_hex {
        let spki_bytes = hex::decode(spki_hex)?;
        if spki_bytes.len() != 32 {
            return Err("SPKI must be 32 bytes hex".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&spki_bytes);
        arr
    } else {
        let spki_bytes = hex::decode(peer_id)?;
        if spki_bytes.len() != 32 {
            return Err("peer_id is not valid 32-byte hex SPKI".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&spki_bytes);
        arr
    };

    let result = create_device_link_invite(
        &db,
        peer_id,
        &user_key,
        &user_event_id,
        &workspace_id,
        public_addr,
        &bootstrap_spki,
    )?;

    Ok(CreateInviteResponse {
        invite_link: result.invite_link,
        invite_event_id: event_id_to_base64(&result.invite_event_id),
    })
}
