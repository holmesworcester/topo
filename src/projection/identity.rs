use crate::crypto::event_id_to_base64;
use crate::event_modules::ParsedEvent;
use super::result::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};

/// Dispatch identity event projections to pure projectors.
pub fn apply_identity_projection_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    match parsed {
        ParsedEvent::Workspace(ws) => project_workspace_pure(recorded_by, event_id_b64, ws, ctx),
        ParsedEvent::InviteAccepted(ia) => project_invite_accepted_pure(recorded_by, event_id_b64, ia, ctx),
        ParsedEvent::UserInviteBoot(ui) => project_user_invite_boot_pure(recorded_by, event_id_b64, ui),
        ParsedEvent::UserInviteOngoing(ui) => project_user_invite_pure(recorded_by, event_id_b64, &ui.public_key),
        ParsedEvent::DeviceInviteFirst(di) => project_device_invite_pure(recorded_by, event_id_b64, &di.public_key),
        ParsedEvent::DeviceInviteOngoing(di) => project_device_invite_pure(recorded_by, event_id_b64, &di.public_key),
        ParsedEvent::UserBoot(u) => {
            project_user_pure(recorded_by, event_id_b64, &u.public_key, &u.username)
        }
        ParsedEvent::UserOngoing(u) => {
            project_user_pure(recorded_by, event_id_b64, &u.public_key, &u.username)
        }
        ParsedEvent::PeerSharedFirst(p) => {
            project_peer_shared_pure(
                recorded_by,
                event_id_b64,
                &p.public_key,
                &p.user_event_id,
                &p.device_name,
            )
        }
        ParsedEvent::PeerSharedOngoing(p) => {
            project_peer_shared_pure(
                recorded_by,
                event_id_b64,
                &p.public_key,
                &p.user_event_id,
                &p.device_name,
            )
        }
        ParsedEvent::AdminBoot(a) => project_admin_pure(recorded_by, event_id_b64, &a.public_key),
        ParsedEvent::AdminOngoing(a) => project_admin_pure(recorded_by, event_id_b64, &a.public_key),
        ParsedEvent::UserRemoved(r) => project_user_removed_pure(recorded_by, event_id_b64, &r.target_event_id),
        ParsedEvent::PeerRemoved(r) => project_peer_removed_pure(recorded_by, event_id_b64, &r.target_event_id),
        ParsedEvent::SecretShared(s) => project_secret_shared_pure(recorded_by, event_id_b64, s, ctx),
        ParsedEvent::TransportKey(t) => project_transport_key_pure(recorded_by, event_id_b64, t),
        _ => ProjectorResult::reject("not an identity event".to_string()),
    }
}

/// Pure projector: Workspace guard — trust_anchors must match workspace event_id.
/// Returns Block if no trust anchor yet, Reject if mismatch.
fn project_workspace_pure(
    recorded_by: &str,
    event_id_b64: &str,
    ws: &crate::event_modules::WorkspaceEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let workspace_id_b64 = event_id_b64.to_string();

    match &ctx.trust_anchor_workspace_id {
        None => {
            // No trust anchor yet — block until invite_accepted sets it
            ProjectorResult::block(vec![])
        }
        Some(anchor_wid) if anchor_wid == &workspace_id_b64 => {
            // Trust anchor matches — project
            let ops = vec![
                WriteOp::InsertOrIgnore {
                    table: "workspaces",
                    columns: vec!["recorded_by", "event_id", "workspace_id", "public_key", "name"],
                    values: vec![
                        SqlVal::Text(recorded_by.to_string()),
                        SqlVal::Text(event_id_b64.to_string()),
                        SqlVal::Text(workspace_id_b64),
                        SqlVal::Blob(ws.public_key.to_vec()),
                        SqlVal::Text(ws.name.clone()),
                    ],
                },
            ];
            ProjectorResult::valid(ops)
        }
        Some(_) => {
            // Foreign workspace — reject
            ProjectorResult::reject("workspace_id does not match trust anchor".to_string())
        }
    }
}

/// Pure projector: InviteAccepted — local trust-anchor binding.
///
/// Binds directly from InviteAcceptedEvent fields. Uses first-write-wins
/// (INSERT OR IGNORE) for trust anchor immutability; rejects on mismatch.
/// Emits RetryWorkspaceGuards command so blocked workspace events can unblock.
fn project_invite_accepted_pure(
    recorded_by: &str,
    event_id_b64: &str,
    ia: &crate::event_modules::InviteAcceptedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let invite_eid_b64 = event_id_to_base64(&ia.invite_event_id);
    let workspace_id_b64 = event_id_to_base64(&ia.workspace_id);

    // Check existing trust anchor — reject on mismatch.
    if let Some(ref stored) = ctx.trust_anchor_workspace_id {
        if stored != &workspace_id_b64 {
            return ProjectorResult::reject(format!(
                "invite_accepted workspace_id {} conflicts with existing trust anchor {}",
                workspace_id_b64, stored
            ));
        }
    }

    let ops = vec![
        // Projection table
        WriteOp::InsertOrIgnore {
            table: "invite_accepted",
            columns: vec!["recorded_by", "event_id", "invite_event_id", "workspace_id"],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(invite_eid_b64),
                SqlVal::Text(workspace_id_b64.clone()),
            ],
        },
        // Trust anchor (first-write-wins)
        WriteOp::InsertOrIgnore {
            table: "trust_anchors",
            columns: vec!["peer_id", "workspace_id"],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(workspace_id_b64),
            ],
        },
    ];

    // Force-valid workspace is represented as an emitted command — not ad hoc
    // service-side imperative logic (per instructions §InviteAccepted).
    ProjectorResult::valid_with_commands(ops, vec![EmitCommand::RetryWorkspaceGuards])
}

/// Pure projector: UserInviteBoot → user_invites table.
fn project_user_invite_boot_pure(
    recorded_by: &str,
    event_id_b64: &str,
    ui: &crate::event_modules::UserInviteBootEvent,
) -> ProjectorResult {
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "user_invites",
        columns: vec!["recorded_by", "event_id", "public_key"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(ui.public_key.to_vec()),
        ],
    }];
    ProjectorResult::valid(ops)
}

/// Pure projector: UserInviteOngoing → user_invites table.
fn project_user_invite_pure(
    recorded_by: &str,
    event_id_b64: &str,
    public_key: &[u8; 32],
) -> ProjectorResult {
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "user_invites",
        columns: vec!["recorded_by", "event_id", "public_key"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
        ],
    }];
    ProjectorResult::valid(ops)
}

/// Pure projector: DeviceInvite → device_invites table.
fn project_device_invite_pure(
    recorded_by: &str,
    event_id_b64: &str,
    public_key: &[u8; 32],
) -> ProjectorResult {
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "device_invites",
        columns: vec!["recorded_by", "event_id", "public_key"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
        ],
    }];
    ProjectorResult::valid(ops)
}

/// Pure projector: User → users table.
fn project_user_pure(
    recorded_by: &str,
    event_id_b64: &str,
    public_key: &[u8; 32],
    username: &str,
) -> ProjectorResult {
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "users",
        columns: vec!["recorded_by", "event_id", "public_key", "username"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
            SqlVal::Text(username.to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}

/// Pure projector: PeerShared → peers_shared table.
fn project_peer_shared_pure(
    recorded_by: &str,
    event_id_b64: &str,
    public_key: &[u8; 32],
    user_event_id: &[u8; 32],
    device_name: &str,
) -> ProjectorResult {
    let user_event_id_b64 = event_id_to_base64(user_event_id);
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "peers_shared",
        columns: vec!["recorded_by", "event_id", "public_key", "user_event_id", "device_name"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
            SqlVal::Text(user_event_id_b64),
            SqlVal::Text(device_name.to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}

/// Pure projector: Admin → admins table.
fn project_admin_pure(
    recorded_by: &str,
    event_id_b64: &str,
    public_key: &[u8; 32],
) -> ProjectorResult {
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "admins",
        columns: vec!["recorded_by", "event_id", "public_key"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(public_key.to_vec()),
        ],
    }];
    ProjectorResult::valid(ops)
}

/// Pure projector: UserRemoved → removed_entities table.
fn project_user_removed_pure(
    recorded_by: &str,
    event_id_b64: &str,
    target_event_id: &[u8; 32],
) -> ProjectorResult {
    let target_b64 = event_id_to_base64(target_event_id);
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "removed_entities",
        columns: vec!["recorded_by", "event_id", "target_event_id", "removal_type"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(target_b64),
            SqlVal::Text("user".to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}

/// Pure projector: PeerRemoved → removed_entities table.
fn project_peer_removed_pure(
    recorded_by: &str,
    event_id_b64: &str,
    target_event_id: &[u8; 32],
) -> ProjectorResult {
    let target_b64 = event_id_to_base64(target_event_id);
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "removed_entities",
        columns: vec!["recorded_by", "event_id", "target_event_id", "removal_type"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(target_b64),
            SqlVal::Text("peer".to_string()),
        ],
    }];
    ProjectorResult::valid(ops)
}

/// Pure projector: SecretShared → secret_shared table.
/// Rejects if recipient has been removed (InvRemovalExclusion).
fn project_secret_shared_pure(
    recorded_by: &str,
    event_id_b64: &str,
    ss: &crate::event_modules::SecretSharedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let key_b64 = event_id_to_base64(&ss.key_event_id);
    let recipient_b64 = event_id_to_base64(&ss.recipient_event_id);

    if ctx.recipient_removed {
        return ProjectorResult::reject(format!("recipient {} has been removed", recipient_b64));
    }

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "secret_shared",
        columns: vec!["recorded_by", "event_id", "key_event_id", "recipient_event_id", "wrapped_key"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(key_b64),
            SqlVal::Text(recipient_b64),
            SqlVal::Blob(ss.wrapped_key.to_vec()),
        ],
    }];
    ProjectorResult::valid(ops)
}

/// Pure projector: TransportKey → transport_keys table.
fn project_transport_key_pure(
    recorded_by: &str,
    event_id_b64: &str,
    tk: &crate::event_modules::TransportKeyEvent,
) -> ProjectorResult {
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "transport_keys",
        columns: vec!["recorded_by", "event_id", "spki_fingerprint"],
        values: vec![
            SqlVal::Text(recorded_by.to_string()),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(tk.spki_fingerprint.to_vec()),
        ],
    }];
    ProjectorResult::valid(ops)
}

/// After guard state changes, find and re-project guard-blocked events.
/// This is now triggered by the RetryWorkspaceGuards command.
pub fn retry_guard_blocked_events(
    conn: &rusqlite::Connection,
    recorded_by: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use crate::crypto::event_id_from_base64;

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
            let _ = super::apply::project_one(conn, recorded_by, &event_id)?;
        }
    }
    Ok(())
}
