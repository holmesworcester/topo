use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::commands::{
    add_device_to_workspace, create_device_link_invite, create_user_invite, create_workspace,
    join_workspace_as_new_user, persist_join_peer_secret, persist_link_peer_secret,
};
use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::db::transport_creds;
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

fn decode_hex32(
    value: &str,
    what: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        return Err(format!("{what} is not valid 32-byte hex SPKI").into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn resolve_invite_bootstrap_spki(
    db: &Connection,
    recorded_by: &str,
    public_spki_hex: Option<&str>,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    if let Some(spki_hex) = public_spki_hex {
        return decode_hex32(spki_hex, "SPKI");
    }

    if let Some(target) = transport_creds::resolve_tenant_transport_target(db, recorded_by)? {
        return decode_hex32(&target.transport_peer_id, "transport_peer_id");
    }

    if transport_creds::load_local_creds(db, recorded_by)?.is_some() {
        return decode_hex32(recorded_by, "peer_id");
    }

    Err(format!(
        "no local transport target is materialized for tenant {}; cannot create invite",
        recorded_by
    )
    .into())
}

// DB-path-level command wrappers (moved from service.rs)

pub fn create_workspace_for_db(
    db_path: &str,
    workspace_name: &str,
    username: &str,
    device_name: &str,
) -> Result<CreateWorkspaceResponse, Box<dyn std::error::Error + Send + Sync>> {
    use crate::db::{open_connection, schema::create_tables};

    let conn = open_connection(db_path)?;
    create_tables(&conn)?;

    // Workspace creation is tenant-agnostic at the control plane: it always
    // mints a fresh local tenant/workspace instead of reusing the active one.
    let result = create_workspace(&conn, "bootstrap", workspace_name, username, device_name)?;
    let peer_id = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &result.peer_shared_key.verifying_key().to_bytes(),
    ));

    Ok(CreateWorkspaceResponse {
        peer_id,
        workspace_id: event_id_to_base64(&result.workspace_id),
    })
}

/// Create a user invite for the active workspace.
///
/// When `bootstrap_addrs` is empty, auto-detects non-loopback addresses.
fn create_invite_for_recorded_by(
    db: &Connection,
    recorded_by: &str,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    listen_port: u16,
    public_spki_hex: Option<&str>,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let ws_eid = super::resolve_workspace_for_peer(db, recorded_by)?;
    let (sender_peer_eid, sender_peer_key) =
        crate::event_modules::peer_shared::load_local_peer_signer_required(db, recorded_by)?;
    if !signer_is_admin(db, recorded_by, &sender_peer_eid)? {
        return Err("Local peer signer is not admin for this workspace.".into());
    }
    let admin_event_id = resolve_admin_event_for_signer(db, recorded_by, &sender_peer_eid)?
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            "Could not resolve admin event for local peer signer.".into()
        })?;

    let bootstrap_spki = resolve_invite_bootstrap_spki(db, recorded_by, public_spki_hex)?;

    let addrs = if bootstrap_addrs.is_empty() {
        let detected = super::invite_link::detect_bootstrap_addrs(listen_port);
        if detected.is_empty() {
            return Err(
                "No non-loopback addresses detected. Provide --public-addr explicitly.".into(),
            );
        }
        detected
    } else {
        bootstrap_addrs.to_vec()
    };

    let result = create_user_invite(
        db,
        recorded_by,
        &sender_peer_key,
        &sender_peer_eid,
        &admin_event_id,
        &ws_eid,
        &addrs,
        &bootstrap_spki,
    )?;

    Ok(CreateInviteResponse {
        invite_link: result.invite_link,
        invite_event_id: event_id_to_base64(&result.invite_event_id),
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
    create_invite_for_recorded_by(&db, &recorded_by, bootstrap_addrs, listen_port, None)
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
    )
}

/// Create a user invite for a specific peer (daemon provides the peer_id).
///
/// When `bootstrap_addrs` is empty, auto-detects non-loopback addresses.
pub fn create_invite_for_peer(
    db_path: &str,
    peer_id: &str,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    listen_port: u16,
    public_spki_hex: Option<&str>,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    create_invite_for_recorded_by(&db, peer_id, bootstrap_addrs, listen_port, public_spki_hex)
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
    // materialize trust rows for this tenant. When the invite carries no
    // bootstrap addresses, persist one empty-address marker row so discovery
    // recovery can still use the invite SPKI without generating a bootstrap
    // autodial target.
    let invite_eid_b64 = event_id_to_base64(&invite_event_id);
    let ws_b64 = event_id_to_base64(&workspace_id);
    if invite.bootstrap_addrs.is_empty() {
        crate::db::transport_trust::append_bootstrap_context(
            &db,
            &derived_peer_id,
            &invite_eid_b64,
            &ws_b64,
            "",
            &invite.bootstrap_spki_fingerprint,
        )?;
    } else {
        for addr in &invite.bootstrap_addrs {
            crate::db::transport_trust::append_bootstrap_context(
                &db,
                &derived_peer_id,
                &invite_eid_b64,
                &ws_b64,
                &addr.to_bootstrap_addr_string(),
                &invite.bootstrap_spki_fingerprint,
            )?;
        }
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
///
/// When `bootstrap_addrs` is empty, auto-detects non-loopback addresses.
pub fn create_device_link_for_peer(
    db_path: &str,
    peer_id: &str,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    listen_port: u16,
    public_spki_hex: Option<&str>,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;

    let (sender_peer_eid, sender_peer_key) =
        crate::event_modules::peer_shared::load_local_peer_signer_required(&db, peer_id)?;
    let user_event_id =
        crate::event_modules::peer_shared::resolve_user_event_id(&db, peer_id, &sender_peer_eid)?;

    let workspace_id = super::resolve_workspace_for_peer(&db, peer_id)?;

    let bootstrap_spki = resolve_invite_bootstrap_spki(&db, peer_id, public_spki_hex)?;

    let addrs = if bootstrap_addrs.is_empty() {
        let detected = super::invite_link::detect_bootstrap_addrs(listen_port);
        if detected.is_empty() {
            return Err(
                "No non-loopback addresses detected. Provide --public-addr explicitly.".into(),
            );
        }
        detected
    } else {
        bootstrap_addrs.to_vec()
    };

    let result = create_device_link_invite(
        &db,
        peer_id,
        &sender_peer_key,
        &sender_peer_eid,
        &user_event_id,
        &workspace_id,
        &addrs,
        &bootstrap_spki,
    )?;

    Ok(CreateInviteResponse {
        invite_link: result.invite_link,
        invite_event_id: event_id_to_base64(&result.invite_event_id),
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_invite_bootstrap_spki;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::db::transport_creds::{
        set_local_transport_target, store_local_creds_with_source, CRED_SOURCE_PEER_SHARED,
    };

    #[test]
    fn resolve_invite_bootstrap_spki_prefers_current_transport_target() {
        let db = open_in_memory().expect("open in-memory db");
        create_tables(&db).expect("create tables");

        let tenant_id = hex::encode([0x11; 32]);
        let target_id = hex::encode([0x22; 32]);

        store_local_creds_with_source(&db, &target_id, b"cert", b"key", CRED_SOURCE_PEER_SHARED)
            .expect("store target creds");
        set_local_transport_target(&db, &tenant_id, &target_id, CRED_SOURCE_PEER_SHARED)
            .expect("set local transport target");

        let spki = resolve_invite_bootstrap_spki(&db, &tenant_id, None).expect("resolve spki");
        assert_eq!(spki, [0x22; 32]);
    }

    #[test]
    fn resolve_invite_bootstrap_spki_accepts_explicit_override() {
        let db = open_in_memory().expect("open in-memory db");
        create_tables(&db).expect("create tables");

        let explicit = hex::encode([0x33; 32]);
        let spki =
            resolve_invite_bootstrap_spki(&db, "tenant", Some(&explicit)).expect("resolve spki");
        assert_eq!(spki, [0x33; 32]);
    }

    #[test]
    fn resolve_invite_bootstrap_spki_falls_back_to_direct_peer_creds() {
        let db = open_in_memory().expect("open in-memory db");
        create_tables(&db).expect("create tables");

        let tenant_id = hex::encode([0x44; 32]);
        store_local_creds_with_source(&db, &tenant_id, b"cert", b"key", CRED_SOURCE_PEER_SHARED)
            .expect("store direct creds");

        let spki = resolve_invite_bootstrap_spki(&db, &tenant_id, None).expect("resolve spki");
        assert_eq!(spki, [0x44; 32]);
    }
}
