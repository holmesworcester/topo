use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::commands::{
    add_device_to_workspace, create_device_link_invite, create_user_invite,
    create_workspace_with_options, grant_admin, join_workspace_as_new_user,
    persist_join_peer_secret, persist_link_peer_secret, remove_member, CreateWorkspaceOptions,
};
use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
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

#[derive(Debug, Serialize, Deserialize)]
pub struct RotateKeyResponse {
    pub key_event_id: String,
    pub rotation_event_id: String,
    pub proactive_share_count: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemoveMemberResponse {
    pub target_event_id: String,
    pub target_kind: String,
    pub removal_event_id: String,
    pub key_event_id: String,
    pub rotation_event_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GrantAdminResponse {
    pub target_event_id: String,
    pub admin_event_id: String,
}

fn signer_is_admin(
    db: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let signer_b64 = event_id_to_base64(signer_event_id);
    let is_admin: bool = db.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM peers_shared ps
             JOIN users u
               ON u.recorded_by = ps.recorded_by
              AND u.event_id = ps.user_event_id
             JOIN admins a
               ON a.recorded_by = u.recorded_by
              AND a.public_key = u.public_key
             WHERE ps.recorded_by = ?1
               AND ps.event_id = ?2
         )",
        rusqlite::params![recorded_by, signer_b64],
        |row| row.get(0),
    )?;
    Ok(is_admin)
}

fn resolve_admin_event_for_signer(
    db: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
) -> Result<Option<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    use rusqlite::OptionalExtension;
    let signer_b64 = event_id_to_base64(signer_event_id);
    let admin_b64: Option<String> = db
        .query_row(
            "SELECT a.event_id
             FROM peers_shared ps
             JOIN users u
               ON u.recorded_by = ps.recorded_by
              AND u.event_id = ps.user_event_id
             JOIN admins a
               ON a.recorded_by = u.recorded_by
              AND a.public_key = u.public_key
             WHERE ps.recorded_by = ?1
               AND ps.event_id = ?2
             ORDER BY a.event_id ASC
             LIMIT 1",
            rusqlite::params![recorded_by, signer_b64],
            |row| row.get(0),
        )
        .optional()?;

    match admin_b64 {
        Some(v) => {
            let eid = event_id_from_base64(&v)
                .ok_or_else(|| format!("invalid admin event_id encoding in DB: {}", v))?;
            Ok(Some(eid))
        }
        None => Ok(None),
    }
}

fn require_admin_peer_signer(
    db: &Connection,
    recorded_by: &str,
) -> Result<(EventId, SigningKey), Box<dyn std::error::Error + Send + Sync>> {
    let _ = super::load_local_authoring_context(db, recorded_by)?;
    let (signer_event_id, signer_key) =
        crate::event_modules::peer_shared::load_local_peer_signer_required(db, recorded_by)?;
    if !signer_is_admin(db, recorded_by, &signer_event_id)? {
        return Err("Local peer signer is not admin for this workspace.".into());
    }
    Ok((signer_event_id, signer_key))
}

fn removal_target_already_removed(
    db: &Connection,
    recorded_by: &str,
    target_event_id: &EventId,
    removal_type: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM removed_entities
             WHERE recorded_by = ?1
               AND target_event_id = ?2
               AND removal_type = ?3
         )",
        rusqlite::params![
            recorded_by,
            event_id_to_base64(target_event_id),
            removal_type,
        ],
        |row| row.get(0),
    )?;
    Ok(exists)
}

fn user_is_admin(
    db: &Connection,
    recorded_by: &str,
    target_user_event_id: &EventId,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let exists: bool = db.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM users u
             JOIN admins a
               ON a.recorded_by = u.recorded_by
              AND a.public_key = u.public_key
             WHERE u.recorded_by = ?1
               AND u.event_id = ?2
         )",
        rusqlite::params![recorded_by, event_id_to_base64(target_user_event_id)],
        |row| row.get(0),
    )?;
    Ok(exists)
}

fn resolve_invite_bootstrap_endpoint_id(
    db: &Connection,
    public_endpoint_id_hex: Option<&str>,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let decision_context = super::command_plans::load_invite_bootstrap_endpoint_decision_context(
        db,
        public_endpoint_id_hex,
    )?;
    let plan = super::command_plans::decide_invite_bootstrap_endpoint_plan(&decision_context);
    super::command_plans::resolve_invite_bootstrap_endpoint_plan(plan)
}

// DB-path-level command wrappers (moved from service.rs)

pub fn create_workspace_for_db(
    db_path: &str,
    workspace_name: &str,
    username: &str,
    device_name: &str,
) -> Result<CreateWorkspaceResponse, Box<dyn std::error::Error + Send + Sync>> {
    create_workspace_for_db_with_seed(db_path, workspace_name, username, device_name, 0, None)
}

pub fn create_workspace_for_db_with_seed(
    db_path: &str,
    workspace_name: &str,
    username: &str,
    device_name: &str,
    message_count: usize,
    network_age: Option<&str>,
) -> Result<CreateWorkspaceResponse, Box<dyn std::error::Error + Send + Sync>> {
    use crate::db::{open_connection, schema::create_tables};

    let conn = open_connection(db_path)?;
    create_tables(&conn)?;
    crate::transport::materialize_daemon_identity(&conn)?;

    let network_age_ms = match network_age.map(str::trim).filter(|value| !value.is_empty()) {
        Some(spec) => Some(
            crate::event_modules::message::commands::parse_history_span_ms(spec)
                .ok_or_else(|| format!("invalid network_age: {spec}"))?,
        ),
        None => None,
    };

    // Workspace creation is tenant-agnostic at the control plane: it always
    // mints a fresh local tenant/workspace instead of reusing the active one.
    let result = create_workspace_with_options(
        &conn,
        "bootstrap",
        workspace_name,
        username,
        device_name,
        CreateWorkspaceOptions {
            message_count,
            network_age_ms,
            end_at_ms: Some(crate::state::db::queue::current_timestamp_ms_u64()),
        },
    )?;
    let peer_id = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &result.peer_shared_key.verifying_key().to_bytes(),
    ));

    Ok(CreateWorkspaceResponse {
        peer_id,
        workspace_id: event_id_to_base64(&result.workspace_id),
    })
}

/// Create a user invite for the active workspace.
fn create_invite_for_recorded_by(
    db: &Connection,
    recorded_by: &str,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    _listen_port: u16,
    public_spki_hex: Option<&str>,
    relay_url: Option<&str>,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let _ = super::load_local_authoring_context(db, recorded_by)?;
    let ws_eid = super::resolve_workspace_for_peer(db, recorded_by)?;
    let (sender_peer_eid, sender_peer_key) = require_admin_peer_signer(db, recorded_by)?;
    let admin_event_id = resolve_admin_event_for_signer(db, recorded_by, &sender_peer_eid)?
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            "Could not resolve admin event for local peer signer.".into()
        })?;

    let bootstrap_endpoint_id = resolve_invite_bootstrap_endpoint_id(db, public_spki_hex)?;

    let addrs = bootstrap_addrs.to_vec();

    let result = create_user_invite(
        db,
        recorded_by,
        &sender_peer_key,
        &sender_peer_eid,
        &admin_event_id,
        &ws_eid,
        &addrs,
        &bootstrap_endpoint_id,
        relay_url,
    )?;

    Ok(CreateInviteResponse {
        invite_link: result.invite_link,
        invite_event_id: event_id_to_base64(&result.invite_event_id),
    })
}

fn rotate_key_for_recorded_by(
    db: &Connection,
    recorded_by: &str,
) -> Result<RotateKeyResponse, Box<dyn std::error::Error + Send + Sync>> {
    let _ = super::load_local_authoring_context(db, recorded_by)?;
    let result = super::identity_ops::rotate_content_key_for_peer(db, recorded_by)?;
    Ok(RotateKeyResponse {
        key_event_id: event_id_to_base64(&result.key_event_id),
        rotation_event_id: event_id_to_base64(&result.rotation_event_id),
        proactive_share_count: result.proactive_share_count,
    })
}

fn ban_user_for_recorded_by(
    db: &Connection,
    recorded_by: &str,
    target: &str,
) -> Result<RemoveMemberResponse, Box<dyn std::error::Error + Send + Sync>> {
    let authoring = super::load_local_authoring_context(db, recorded_by)?;
    let target_event_id = crate::event_modules::user::resolve(db, recorded_by, target)
        .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> { err.into() })?;
    let is_admin = signer_is_admin(db, recorded_by, &authoring.signer_event_id)?;
    let plan = super::command_plans::decide_remove_member_plan(
        &super::command_plans::RemoveMemberDecisionContext {
            actor_is_admin: is_admin,
            targets_self: target_event_id == authoring.author_id,
            already_removed: removal_target_already_removed(
                db,
                recorded_by,
                &target_event_id,
                "user",
            )?,
            target_kind: super::command_plans::RemoveMemberTargetKind::User,
        },
    );
    super::command_plans::resolve_remove_member_plan(
        plan,
        super::command_plans::RemoveMemberTargetKind::User,
    )?;
    let result = remove_member(db, recorded_by, &target_event_id)?;
    Ok(RemoveMemberResponse {
        target_event_id: event_id_to_base64(&target_event_id),
        target_kind: "user".to_string(),
        removal_event_id: event_id_to_base64(&result.removal_event_id),
        key_event_id: event_id_to_base64(&result.key_event_id),
        rotation_event_id: event_id_to_base64(&result.rotation_event_id),
    })
}

fn grant_admin_for_recorded_by(
    db: &Connection,
    recorded_by: &str,
    target: &str,
) -> Result<GrantAdminResponse, Box<dyn std::error::Error + Send + Sync>> {
    let authoring = super::load_local_authoring_context(db, recorded_by)?;
    let target_event_id = crate::event_modules::user::resolve(db, recorded_by, target)
        .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> { err.into() })?;
    let is_admin = signer_is_admin(db, recorded_by, &authoring.signer_event_id)?;
    let plan = super::command_plans::decide_grant_admin_plan(
        &super::command_plans::GrantAdminDecisionContext {
            actor_is_admin: is_admin,
            target_already_admin: user_is_admin(db, recorded_by, &target_event_id)?,
        },
    );
    super::command_plans::resolve_grant_admin_plan(plan)?;
    let authority_admin_event_id =
        resolve_admin_event_for_signer(db, recorded_by, &authoring.signer_event_id)?.ok_or_else(
            || -> Box<dyn std::error::Error + Send + Sync> {
                "Could not resolve admin event for local peer signer.".into()
            },
        )?;
    let result = grant_admin(
        db,
        recorded_by,
        &authoring.signing_key,
        &authoring.signer_event_id,
        &authority_admin_event_id,
        &target_event_id,
    )?;
    Ok(GrantAdminResponse {
        target_event_id: event_id_to_base64(&result.target_user_event_id),
        admin_event_id: event_id_to_base64(&result.admin_event_id),
    })
}

fn unlink_device_for_recorded_by(
    db: &Connection,
    recorded_by: &str,
    target: &str,
) -> Result<RemoveMemberResponse, Box<dyn std::error::Error + Send + Sync>> {
    let authoring = super::load_local_authoring_context(db, recorded_by)?;
    let target_event_id = crate::event_modules::peer_shared::resolve_peer(db, recorded_by, target)
        .map_err(|err| -> Box<dyn std::error::Error + Send + Sync> { err.into() })?;
    let is_admin = signer_is_admin(db, recorded_by, &authoring.signer_event_id)?;
    let plan = super::command_plans::decide_remove_member_plan(
        &super::command_plans::RemoveMemberDecisionContext {
            actor_is_admin: is_admin,
            targets_self: target_event_id == authoring.signer_event_id,
            already_removed: removal_target_already_removed(
                db,
                recorded_by,
                &target_event_id,
                "peer",
            )?,
            target_kind: super::command_plans::RemoveMemberTargetKind::Peer,
        },
    );
    super::command_plans::resolve_remove_member_plan(
        plan,
        super::command_plans::RemoveMemberTargetKind::Peer,
    )?;
    let result = remove_member(db, recorded_by, &target_event_id)?;
    Ok(RemoveMemberResponse {
        target_event_id: event_id_to_base64(&target_event_id),
        target_kind: "peer".to_string(),
        removal_event_id: event_id_to_base64(&result.removal_event_id),
        key_event_id: event_id_to_base64(&result.key_event_id),
        rotation_event_id: event_id_to_base64(&result.rotation_event_id),
    })
}

pub fn create_invite_for_db(
    db_path: &str,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    listen_port: u16,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) =
        open_db_load(db_path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("No transport identity: {}", e).into()
        })?;
    create_invite_for_recorded_by(&db, &recorded_by, bootstrap_addrs, listen_port, None, None)
}

pub fn rotate_key_for_db(
    db_path: &str,
) -> Result<RotateKeyResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) =
        open_db_load(db_path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("No transport identity: {}", e).into()
        })?;
    rotate_key_for_recorded_by(&db, &recorded_by)
}

pub fn ban_user_for_db(
    db_path: &str,
    target: &str,
) -> Result<RemoveMemberResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) =
        open_db_load(db_path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("No transport identity: {}", e).into()
        })?;
    ban_user_for_recorded_by(&db, &recorded_by, target)
}

pub fn grant_admin_for_db(
    db_path: &str,
    target: &str,
) -> Result<GrantAdminResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) =
        open_db_load(db_path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("No transport identity: {}", e).into()
        })?;
    grant_admin_for_recorded_by(&db, &recorded_by, target)
}

pub fn ban_user_for_peer(
    db_path: &str,
    peer_id: &str,
    target: &str,
) -> Result<RemoveMemberResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    ban_user_for_recorded_by(&db, peer_id, target)
}

pub fn grant_admin_for_peer(
    db_path: &str,
    peer_id: &str,
    target: &str,
) -> Result<GrantAdminResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    grant_admin_for_recorded_by(&db, peer_id, target)
}

pub fn unlink_device_for_db(
    db_path: &str,
    target: &str,
) -> Result<RemoveMemberResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) =
        open_db_load(db_path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("No transport identity: {}", e).into()
        })?;
    unlink_device_for_recorded_by(&db, &recorded_by, target)
}

pub fn unlink_device_for_peer(
    db_path: &str,
    peer_id: &str,
    target: &str,
) -> Result<RemoveMemberResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    unlink_device_for_recorded_by(&db, peer_id, target)
}

/// Create invite with an explicit SPKI hex.
pub fn create_invite_with_spki(
    db_path: &str,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    public_spki_hex: &str,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) =
        open_db_load(db_path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("No transport identity: {}", e).into()
        })?;
    create_invite_for_recorded_by(
        &db,
        &recorded_by,
        bootstrap_addrs,
        crate::event_modules::workspace::invite_link::DEFAULT_PORT,
        Some(public_spki_hex),
        None,
    )
}

/// Create a user invite for a specific peer (daemon provides the peer_id).
pub fn create_invite_for_peer(
    db_path: &str,
    peer_id: &str,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    listen_port: u16,
    public_spki_hex: Option<&str>,
    relay_url: Option<&str>,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    create_invite_for_recorded_by(
        &db,
        peer_id,
        bootstrap_addrs,
        listen_port,
        public_spki_hex,
        relay_url,
    )
}

pub fn rotate_key_for_peer(
    db_path: &str,
    peer_id: &str,
) -> Result<RotateKeyResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    rotate_key_for_recorded_by(&db, peer_id)
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
    use crate::db::{open_connection, schema::create_tables};

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

    // Open DB and ensure schema. Bootstrap transport identity is now installed
    // via invite_accepted projection when local invite_secret material exists.
    let db = {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
        db
    };

    // Record bootstrap context before accept so InviteAccepted projection can
    // materialize trust rows for this tenant. Prefer explicit bootstrap
    // addresses when present; use the relay hint only for endpoint-id-only
    // invites so bootstrap planning does not race duplicate transports to the
    // same remote daemon.
    let invite_eid_b64 = event_id_to_base64(&invite_event_id);
    let ws_b64 = event_id_to_base64(&workspace_id);
    for addr in &invite.bootstrap_addrs {
        crate::db::transport_trust::append_bootstrap_context(
            &db,
            &derived_peer_id,
            &invite_eid_b64,
            &ws_b64,
            &addr.to_bootstrap_addr_string(),
            &invite.endpoint_id,
        )?;
    }
    if invite.bootstrap_addrs.is_empty() {
        if let Some(relay_url) = invite.relay_url.as_deref() {
            crate::db::transport_trust::append_bootstrap_context(
                &db,
                &derived_peer_id,
                &invite_eid_b64,
                &ws_b64,
                relay_url,
                &invite.endpoint_id,
            )?;
        }
    }
    if invite.bootstrap_addrs.is_empty() && invite.relay_url.is_none() {
        crate::db::transport_trust::append_bootstrap_context(
            &db,
            &derived_peer_id,
            &invite_eid_b64,
            &ws_b64,
            "",
            &invite.endpoint_id,
        )?;
    }

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
    persist_join_peer_secret(&db, &derived_peer_id, &join)?;

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
    persist_link_peer_secret(&db, &derived_peer_id, &link)?;

    Ok(AcceptDeviceLinkResponse {
        peer_id: derived_peer_id,
        peer_shared_event_id: psf_b64,
    })
}

/// Create a device link for a specific peer (daemon provides the peer_id).
pub fn create_device_link_for_peer(
    db_path: &str,
    peer_id: &str,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    _listen_port: u16,
    public_spki_hex: Option<&str>,
    relay_url: Option<&str>,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    let _ = super::load_local_authoring_context(&db, peer_id)?;

    let (sender_peer_eid, sender_peer_key) =
        crate::event_modules::peer_shared::load_local_peer_signer_required(&db, peer_id)?;
    let user_event_id =
        crate::event_modules::peer_shared::resolve_user_event_id(&db, peer_id, &sender_peer_eid)?;

    let workspace_id = super::resolve_workspace_for_peer(&db, peer_id)?;

    let bootstrap_endpoint_id = resolve_invite_bootstrap_endpoint_id(&db, public_spki_hex)?;

    let addrs = bootstrap_addrs.to_vec();

    let result = create_device_link_invite(
        &db,
        peer_id,
        &sender_peer_key,
        &sender_peer_eid,
        &user_event_id,
        &workspace_id,
        &addrs,
        &bootstrap_endpoint_id,
        relay_url,
    )?;

    Ok(CreateInviteResponse {
        invite_link: result.invite_link,
        invite_event_id: event_id_to_base64(&result.invite_event_id),
    })
}

#[cfg(test)]
mod tests {
    use super::accept_device_link;
    use super::accept_invite;
    use super::create_invite_for_peer;
    use super::create_workspace_for_db;
    use super::resolve_invite_bootstrap_endpoint_id;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::event_modules::workspace::invite_link::parse_invite_link;
    use crate::transport::{materialize_daemon_identity, MISSING_DAEMON_IDENTITY_ERROR};

    #[test]
    fn resolve_invite_bootstrap_endpoint_id_uses_daemon_identity_by_default() {
        let db = open_in_memory().expect("open in-memory db");
        create_tables(&db).expect("create tables");
        let (daemon_peer_id, _cert, _key) =
            materialize_daemon_identity(&db).expect("materialize daemon identity");

        let endpoint_id =
            resolve_invite_bootstrap_endpoint_id(&db, None).expect("resolve endpoint id");
        let expected: [u8; 32] = hex::decode(daemon_peer_id)
            .unwrap()
            .try_into()
            .expect("daemon peer id bytes");
        assert_eq!(endpoint_id, expected);
    }

    #[test]
    fn resolve_invite_bootstrap_endpoint_id_accepts_explicit_override() {
        let db = open_in_memory().expect("open in-memory db");
        create_tables(&db).expect("create tables");

        let explicit = hex::encode([0x33; 32]);
        let endpoint_id = resolve_invite_bootstrap_endpoint_id(&db, Some(&explicit))
            .expect("resolve endpoint id");
        assert_eq!(endpoint_id, [0x33; 32]);
    }

    #[test]
    fn resolve_invite_bootstrap_endpoint_id_rejects_missing_daemon_identity_without_explicit() {
        let db = open_in_memory().expect("open in-memory db");
        create_tables(&db).expect("create tables");

        let err = resolve_invite_bootstrap_endpoint_id(&db, None).unwrap_err();
        assert_eq!(err.to_string(), MISSING_DAEMON_IDENTITY_ERROR);
    }

    #[test]
    fn create_invite_for_peer_leaves_bootstrap_addresses_empty_by_default() {
        let temp = tempfile::tempdir().expect("tempdir");
        let db_path = temp.path().join("invite.sqlite3");
        let db_path = db_path.to_str().expect("db path");
        crate::transport::materialize_daemon_identity_from_db(db_path)
            .expect("materialize daemon identity");
        let workspace =
            create_workspace_for_db(db_path, "alpha", "alice", "laptop").expect("create workspace");

        let invite = create_invite_for_peer(
            db_path,
            &workspace.peer_id,
            &[],
            crate::event_modules::workspace::invite_link::DEFAULT_PORT,
            None,
            None,
        )
        .expect("create invite");

        let parsed = parse_invite_link(&invite.invite_link).expect("parse invite");
        assert!(
            parsed.bootstrap_addrs.is_empty(),
            "default invite should not embed direct bootstrap addresses"
        );
        assert!(
            parsed.relay_url.is_none(),
            "without a live runtime relay, the invite should remain endpoint-id only"
        );
    }

    #[test]
    fn accept_invite_materializes_daemon_identity_when_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let creator_db = temp.path().join("creator.sqlite3");
        let creator_db = creator_db.to_str().expect("creator db");
        crate::transport::materialize_daemon_identity_from_db(creator_db)
            .expect("materialize creator daemon identity");
        let workspace =
            create_workspace_for_db(creator_db, "alpha", "alice", "laptop").expect("workspace");
        let invite = create_invite_for_peer(
            creator_db,
            &workspace.peer_id,
            &[],
            crate::event_modules::workspace::invite_link::DEFAULT_PORT,
            None,
            None,
        )
        .expect("create invite");

        let joiner_db = temp.path().join("joiner.sqlite3");
        let joiner_db = joiner_db.to_str().expect("joiner db");
        let accepted =
            accept_invite(joiner_db, &invite.invite_link, "bob", "tablet").expect("accept invite");
        assert!(
            !accepted.peer_id.is_empty(),
            "accepted invite should return the derived local peer id"
        );

        let joiner = crate::db::open_connection(joiner_db).expect("open joiner db");
        assert!(
            crate::transport::load_local_daemon_endpoint_id(&joiner)
                .expect("load local daemon endpoint id")
                .is_some(),
            "accept invite should lazily materialize daemon endpoint identity"
        );
        assert!(
            crate::event_modules::endpoint_shared::load_local_endpoint_shared(&joiner)
                .expect("load endpoint_shared row")
                .is_some(),
            "accept invite should persist local endpoint_shared projection"
        );
    }

    #[test]
    fn accept_device_link_materializes_daemon_identity_when_missing() {
        let temp = tempfile::tempdir().expect("tempdir");
        let creator_db = temp.path().join("creator.sqlite3");
        let creator_db = creator_db.to_str().expect("creator db");
        crate::transport::materialize_daemon_identity_from_db(creator_db)
            .expect("materialize creator daemon identity");
        let workspace =
            create_workspace_for_db(creator_db, "alpha", "alice", "laptop").expect("workspace");
        let invite = super::create_device_link_for_peer(
            creator_db,
            &workspace.peer_id,
            &[],
            crate::event_modules::workspace::invite_link::DEFAULT_PORT,
            None,
            None,
        )
        .expect("create device link");

        let joiner_db = temp.path().join("joiner.sqlite3");
        let joiner_db = joiner_db.to_str().expect("joiner db");
        let accepted =
            accept_device_link(joiner_db, &invite.invite_link, "phone").expect("accept link");
        assert!(
            !accepted.peer_id.is_empty(),
            "accepted device link should return the derived local peer id"
        );

        let joiner = crate::db::open_connection(joiner_db).expect("open joiner db");
        assert!(
            crate::transport::load_local_daemon_endpoint_id(&joiner)
                .expect("load local daemon endpoint id")
                .is_some(),
            "accept device link should lazily materialize daemon endpoint identity"
        );
        assert!(
            crate::event_modules::endpoint_shared::load_local_endpoint_shared(&joiner)
                .expect("load endpoint_shared row")
                .is_some(),
            "accept device link should persist local endpoint_shared projection"
        );
    }
}
