use rusqlite::Connection;

use crate::crypto::{event_id_to_base64, event_id_from_base64};
use crate::events::ParsedEvent;
use super::decision::ProjectionDecision;

/// Dispatch identity event projections. Called from apply_projection in pipeline.rs.
pub fn apply_identity_projection(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    match parsed {
        ParsedEvent::Network(net) => project_network(conn, recorded_by, event_id_b64, net),
        ParsedEvent::InviteAccepted(ia) => project_invite_accepted(conn, recorded_by, event_id_b64, ia),
        ParsedEvent::UserInviteBoot(ui) => project_user_invite_boot(conn, recorded_by, event_id_b64, ui),
        ParsedEvent::UserInviteOngoing(ui) => project_user_invite(conn, recorded_by, event_id_b64, &ui.public_key),
        ParsedEvent::DeviceInviteFirst(di) => project_device_invite(conn, recorded_by, event_id_b64, &di.public_key),
        ParsedEvent::DeviceInviteOngoing(di) => project_device_invite(conn, recorded_by, event_id_b64, &di.public_key),
        ParsedEvent::UserBoot(u) => project_user(conn, recorded_by, event_id_b64, &u.public_key),
        ParsedEvent::UserOngoing(u) => project_user(conn, recorded_by, event_id_b64, &u.public_key),
        ParsedEvent::PeerSharedFirst(p) => project_peer_shared(conn, recorded_by, event_id_b64, &p.public_key),
        ParsedEvent::PeerSharedOngoing(p) => project_peer_shared(conn, recorded_by, event_id_b64, &p.public_key),
        ParsedEvent::AdminBoot(a) => project_admin(conn, recorded_by, event_id_b64, &a.public_key),
        ParsedEvent::AdminOngoing(a) => project_admin(conn, recorded_by, event_id_b64, &a.public_key),
        ParsedEvent::UserRemoved(r) => project_user_removed(conn, recorded_by, event_id_b64, &r.target_event_id),
        ParsedEvent::PeerRemoved(r) => project_peer_removed(conn, recorded_by, event_id_b64, &r.target_event_id),
        ParsedEvent::SecretShared(s) => project_secret_shared(conn, recorded_by, event_id_b64, s),
        _ => Ok(ProjectionDecision::Reject {
            reason: "not an identity event".to_string(),
        }),
    }
}

/// Network guard: trust_anchors must match event's network_id.
/// Returns Block if no trust anchor yet, Reject if mismatch.
fn project_network(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    net: &crate::events::NetworkEvent,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    let network_id_b64 = event_id_to_base64(&net.network_id);

    // Check trust anchor
    let anchor: Option<String> = match conn.query_row(
        "SELECT network_id FROM trust_anchors WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
        |row| row.get::<_, String>(0),
    ) {
        Ok(a) => Some(a),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };

    match anchor {
        None => {
            // No trust anchor yet — block until invite_accepted sets it
            Ok(ProjectionDecision::Block { missing: vec![] })
        }
        Some(ref anchor_nid) if anchor_nid == &network_id_b64 => {
            // Trust anchor matches — project
            conn.execute(
                "INSERT OR IGNORE INTO networks (recorded_by, event_id, network_id, public_key)
                 VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![recorded_by, event_id_b64, &network_id_b64, net.public_key.as_slice()],
            )?;
            Ok(ProjectionDecision::Valid)
        }
        Some(_) => {
            // Foreign network — reject
            Ok(ProjectionDecision::Reject {
                reason: "network_id does not match trust anchor".to_string(),
            })
        }
    }
}

/// HasRecordedInvite guard + trust anchor binding.
fn project_invite_accepted(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    ia: &crate::events::InviteAcceptedEvent,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    let invite_eid_b64 = event_id_to_base64(&ia.invite_event_id);
    let network_id_b64 = event_id_to_base64(&ia.network_id);

    // HasRecordedInvite guard: check that at least one invite event (types 10-13) is recorded
    let has_invite: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM recorded_events re
         INNER JOIN events e ON re.event_id = e.event_id
         WHERE re.peer_id = ?1 AND e.event_type IN ('user_invite_boot', 'user_invite_ongoing', 'device_invite_first', 'device_invite_ongoing')",
        rusqlite::params![recorded_by],
        |row| row.get(0),
    )?;

    if !has_invite {
        return Ok(ProjectionDecision::Block { missing: vec![] });
    }

    // Check invite_network_bindings for this peer (captured in recording path)
    let bound_network: Option<String> = match conn.query_row(
        "SELECT network_id FROM invite_network_bindings WHERE peer_id = ?1",
        rusqlite::params![recorded_by],
        |row| row.get::<_, String>(0),
    ) {
        Ok(n) => Some(n),
        Err(rusqlite::Error::QueryReturnedNoRows) => None,
        Err(e) => return Err(e.into()),
    };

    // Use the bound network if available, otherwise use the event's network_id
    let effective_network = bound_network.unwrap_or_else(|| network_id_b64.clone());

    // Write invite_accepted projection table
    conn.execute(
        "INSERT OR IGNORE INTO invite_accepted (recorded_by, event_id, invite_event_id, network_id)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![recorded_by, event_id_b64, &invite_eid_b64, &effective_network],
    )?;

    // Write trust_anchors — deterministic binding from inviteNet
    conn.execute(
        "INSERT OR REPLACE INTO trust_anchors (peer_id, network_id) VALUES (?1, ?2)",
        rusqlite::params![recorded_by, &effective_network],
    )?;

    Ok(ProjectionDecision::Valid)
}

/// Project UserInviteBoot: insert into user_invites.
/// NOTE: invite_network_bindings capture happens in recording path (capture_invite_network_binding),
/// not here, because it must be available before invite_accepted projects.
fn project_user_invite_boot(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    ui: &crate::events::UserInviteBootEvent,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    conn.execute(
        "INSERT OR IGNORE INTO user_invites (recorded_by, event_id, public_key)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, event_id_b64, ui.public_key.as_slice()],
    )?;

    Ok(ProjectionDecision::Valid)
}

/// Project UserInvite (ongoing variant — no network capture needed).
fn project_user_invite(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    public_key: &[u8; 32],
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    conn.execute(
        "INSERT OR IGNORE INTO user_invites (recorded_by, event_id, public_key)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, event_id_b64, public_key.as_slice()],
    )?;
    Ok(ProjectionDecision::Valid)
}

fn project_device_invite(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    public_key: &[u8; 32],
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    conn.execute(
        "INSERT OR IGNORE INTO device_invites (recorded_by, event_id, public_key)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, event_id_b64, public_key.as_slice()],
    )?;
    Ok(ProjectionDecision::Valid)
}

fn project_user(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    public_key: &[u8; 32],
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    conn.execute(
        "INSERT OR IGNORE INTO users (recorded_by, event_id, public_key)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, event_id_b64, public_key.as_slice()],
    )?;
    Ok(ProjectionDecision::Valid)
}

fn project_peer_shared(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    public_key: &[u8; 32],
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    conn.execute(
        "INSERT OR IGNORE INTO peers_shared (recorded_by, event_id, public_key)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, event_id_b64, public_key.as_slice()],
    )?;
    Ok(ProjectionDecision::Valid)
}

fn project_admin(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    public_key: &[u8; 32],
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    conn.execute(
        "INSERT OR IGNORE INTO admins (recorded_by, event_id, public_key)
         VALUES (?1, ?2, ?3)",
        rusqlite::params![recorded_by, event_id_b64, public_key.as_slice()],
    )?;
    Ok(ProjectionDecision::Valid)
}

fn project_user_removed(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    target_event_id: &[u8; 32],
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    let target_b64 = event_id_to_base64(target_event_id);
    conn.execute(
        "INSERT OR IGNORE INTO removed_entities (recorded_by, event_id, target_event_id, removal_type)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![recorded_by, event_id_b64, &target_b64, "user"],
    )?;
    Ok(ProjectionDecision::Valid)
}

fn project_peer_removed(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    target_event_id: &[u8; 32],
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    let target_b64 = event_id_to_base64(target_event_id);
    conn.execute(
        "INSERT OR IGNORE INTO removed_entities (recorded_by, event_id, target_event_id, removal_type)
         VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![recorded_by, event_id_b64, &target_b64, "peer"],
    )?;
    Ok(ProjectionDecision::Valid)
}

fn project_secret_shared(
    conn: &Connection,
    recorded_by: &str,
    event_id_b64: &str,
    ss: &crate::events::SecretSharedEvent,
) -> Result<ProjectionDecision, Box<dyn std::error::Error>> {
    let key_b64 = event_id_to_base64(&ss.key_event_id);
    let recipient_b64 = event_id_to_base64(&ss.recipient_event_id);
    conn.execute(
        "INSERT OR IGNORE INTO secret_shared (recorded_by, event_id, key_event_id, recipient_event_id, wrapped_key)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![recorded_by, event_id_b64, &key_b64, &recipient_b64, ss.wrapped_key.as_slice()],
    )?;
    Ok(ProjectionDecision::Valid)
}

/// Capture invite_network_bindings from invite event blobs during recording.
/// Called from store_blob_and_project (recording path), before projection.
/// For UserInviteBoot (type 10), extracts network_id from blob[41..73].
/// INSERT OR IGNORE: first invite sets the binding.
pub fn capture_invite_network_binding(
    conn: &Connection,
    recorded_by: &str,
    blob: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if blob.is_empty() {
        return Ok(());
    }
    let type_code = blob[0];
    // Only UserInviteBoot carries network_id directly
    if type_code == crate::events::EVENT_TYPE_USER_INVITE_BOOT && blob.len() >= 73 {
        let mut network_id = [0u8; 32];
        network_id.copy_from_slice(&blob[41..73]);
        let network_id_b64 = event_id_to_base64(&network_id);
        conn.execute(
            "INSERT OR IGNORE INTO invite_network_bindings (peer_id, network_id) VALUES (?1, ?2)",
            rusqlite::params![recorded_by, &network_id_b64],
        )?;
    }
    Ok(())
}

/// After guard state changes (e.g., trust anchor set by invite_accepted),
/// find events that are recorded but stuck in guard-blocked limbo
/// (not valid, not rejected, not in blocked_event_deps) and re-project them.
/// Called from project_one after InviteAccepted projects as Valid.
pub fn retry_guard_blocked_events(
    conn: &Connection,
    recorded_by: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Find events that are recorded for this peer, but not valid, not rejected,
    // and have no remaining entries in blocked_event_deps.
    // These are events that returned Block from a guard (empty missing).
    let mut stmt = conn.prepare(
        "SELECT re.event_id FROM recorded_events re
         WHERE re.peer_id = ?1
           AND re.event_id NOT IN (SELECT event_id FROM valid_events WHERE peer_id = ?1)
           AND re.event_id NOT IN (SELECT event_id FROM rejected_events WHERE peer_id = ?1)
           AND re.event_id NOT IN (SELECT DISTINCT event_id FROM blocked_event_deps WHERE peer_id = ?1)"
    )?;
    let candidates: Vec<String> = stmt.query_map(
        rusqlite::params![recorded_by],
        |row| row.get::<_, String>(0),
    )?.collect::<Result<Vec<_>, _>>()?;
    drop(stmt);

    for eid_b64 in candidates {
        if let Some(event_id) = event_id_from_base64(&eid_b64) {
            // Re-project via project_one — it will re-check guards
            let _ = super::pipeline::project_one(conn, recorded_by, &event_id)?;
        }
    }
    Ok(())
}
