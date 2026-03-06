use super::layout::common::COMMON_HEADER_BYTES;
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_INVITE_ACCEPTED};

// ─── Layout (owned by this module) ───

/// InviteAccepted (type 9): type(1) + created_at(8) + tenant_event_id(32) + invite_event_id(32)
/// + workspace_id(32) = 105
pub const INVITE_ACCEPTED_WIRE_SIZE: usize = COMMON_HEADER_BYTES + 32 + 32 + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteAcceptedEvent {
    pub created_at_ms: u64,
    pub tenant_event_id: [u8; 32], // dep: local tenant event
    pub invite_event_id: [u8; 32], // the invite event being accepted
    pub workspace_id: [u8; 32],    // workspace being joined
}

impl super::Describe for InviteAcceptedEvent {
    fn human_fields(&self) -> Vec<(&'static str, String)> {
        vec![
            (
                "invite_event_id",
                super::short_id_b64(&self.invite_event_id),
            ),
            ("workspace_id", super::short_id_b64(&self.workspace_id)),
        ]
    }
}

/// Wire format (105 bytes fixed):
/// [0]      type_code = 9
/// [1..9]   created_at_ms (u64 LE)
/// [9..41]  tenant_event_id (32 bytes)
/// [41..73] invite_event_id (32 bytes)
/// [73..105] workspace_id (32 bytes)
pub fn parse_invite_accepted(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    if blob.len() < INVITE_ACCEPTED_WIRE_SIZE {
        return Err(EventError::TooShort {
            expected: INVITE_ACCEPTED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob.len() > INVITE_ACCEPTED_WIRE_SIZE {
        return Err(EventError::TrailingData {
            expected: INVITE_ACCEPTED_WIRE_SIZE,
            actual: blob.len(),
        });
    }
    if blob[0] != EVENT_TYPE_INVITE_ACCEPTED {
        return Err(EventError::WrongType {
            expected: EVENT_TYPE_INVITE_ACCEPTED,
            actual: blob[0],
        });
    }

    let created_at_ms = u64::from_le_bytes(blob[1..9].try_into().unwrap());
    let mut tenant_event_id = [0u8; 32];
    tenant_event_id.copy_from_slice(&blob[9..41]);

    let mut invite_event_id = [0u8; 32];
    invite_event_id.copy_from_slice(&blob[41..73]);

    let mut workspace_id = [0u8; 32];
    workspace_id.copy_from_slice(&blob[73..105]);

    Ok(ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms,
        tenant_event_id,
        invite_event_id,
        workspace_id,
    }))
}

pub fn encode_invite_accepted(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ia = match event {
        ParsedEvent::InviteAccepted(a) => a,
        _ => return Err(EventError::WrongVariant),
    };

    let mut buf = Vec::with_capacity(INVITE_ACCEPTED_WIRE_SIZE);
    buf.push(EVENT_TYPE_INVITE_ACCEPTED);
    buf.extend_from_slice(&ia.created_at_ms.to_le_bytes());
    buf.extend_from_slice(&ia.tenant_event_id);
    buf.extend_from_slice(&ia.invite_event_id);
    buf.extend_from_slice(&ia.workspace_id);
    Ok(buf)
}

// === Projector (event-module locality) ===

use crate::contracts::transport_identity_contract::TransportIdentityIntent;
use crate::crypto::event_id_to_base64;
use crate::db::transport_creds::{has_creds_with_source, CRED_SOURCE_PEER_SHARED};
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

fn bootstrap_spki_already_peer_shared(
    conn: &Connection,
    recorded_by: &str,
    spki_fingerprint: &[u8; 32],
) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM peers_shared p
            WHERE p.recorded_by = ?1
              AND p.transport_fingerprint = ?2
              AND NOT EXISTS (
                SELECT 1 FROM removed_entities r
                WHERE r.recorded_by = p.recorded_by
                  AND r.target_event_id = p.event_id
              )
              AND NOT EXISTS (
                SELECT 1 FROM removed_entities r
                WHERE r.recorded_by = p.recorded_by
                  AND p.user_event_id IS NOT NULL
                  AND r.target_event_id = p.user_event_id
                  AND r.removal_type = 'user'
              )
        )",
        rusqlite::params![recorded_by, spki_fingerprint.as_slice()],
        |row| row.get(0),
    )
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS invites_accepted (
            recorded_by TEXT NOT NULL,
            event_id TEXT NOT NULL,
            tenant_event_id TEXT NOT NULL,
            invite_event_id TEXT NOT NULL,
            workspace_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (recorded_by, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_invites_accepted_scope
            ON invites_accepted(recorded_by, created_at, event_id);
        ",
    )?;
    Ok(())
}

/// Build projector-local context for InviteAccepted projection.
pub fn build_projector_context(
    conn: &Connection,
    recorded_by: &str,
    _event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
    let ia = match parsed {
        ParsedEvent::InviteAccepted(ia) => ia,
        _ => {
            return Err(
                "invite_accepted context loader called for non-invite_accepted event".into(),
            )
        }
    };

    let mut ctx = ContextSnapshot::default();
    let invite_event_id_b64 = event_id_to_base64(&ia.invite_event_id);

    let has_local_invite_secret: bool = conn
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM invite_secrets
                 WHERE recorded_by = ?1
                   AND invite_event_id = ?2
                   AND length(private_key) = 32
             )",
            rusqlite::params![recorded_by, &invite_event_id_b64],
            |row| row.get(0),
        )
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    ctx.has_local_invite_secret = has_local_invite_secret;
    ctx.peer_shared_transport_identity_active =
        has_creds_with_source(conn, CRED_SOURCE_PEER_SHARED).unwrap_or(false);

    if let Some(bc) =
        crate::db::transport_trust::read_bootstrap_context(conn, recorded_by, &invite_event_id_b64)
            .map_err(|e| -> Box<dyn std::error::Error> { e })?
    {
        ctx.bootstrap_spki_already_peer_shared =
            bootstrap_spki_already_peer_shared(conn, recorded_by, &bc.bootstrap_spki_fingerprint)?;
        ctx.bootstrap_context = Some(crate::projection::contract::BootstrapContextSnapshot {
            workspace_id: bc.workspace_id,
            bootstrap_addrs: bc.bootstrap_addrs,
            bootstrap_spki_fingerprint: bc.bootstrap_spki_fingerprint,
        });
    }

    Ok(ctx)
}

/// Pure projector: InviteAccepted — local trust-anchor binding.
///
/// Binds directly from InviteAcceptedEvent fields. Winner selection is done
/// at read time (earliest created_at/event_id), so projection does not inspect
/// previously-accepted rows.
/// Emits RetryWorkspaceEvent targeting the specific workspace_id so the
/// guard-blocked workspace event can unblock through normal projection + cascade.
/// When bootstrap_context is available (and not already superseded by a
/// projected PeerShared transport fingerprint), also writes invite_bootstrap_trust.
pub fn project_pure(
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ia = match parsed {
        ParsedEvent::InviteAccepted(a) => a,
        _ => return ProjectorResult::reject("not an invite_accepted event".to_string()),
    };

    let invite_eid_b64 = event_id_to_base64(&ia.invite_event_id);
    let workspace_id_b64 = event_id_to_base64(&ia.workspace_id);

    let mut ops = vec![
        // Projection table
        WriteOp::InsertOrIgnore {
            table: "invites_accepted",
            columns: vec![
                "recorded_by",
                "event_id",
                "tenant_event_id",
                "invite_event_id",
                "workspace_id",
                "created_at",
            ],
            values: vec![
                SqlVal::Text(recorded_by.to_string()),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(event_id_to_base64(&ia.tenant_event_id)),
                SqlVal::Text(invite_eid_b64.clone()),
                SqlVal::Text(workspace_id_b64.clone()),
                SqlVal::Int(ia.created_at_ms as i64),
            ],
        },
    ];

    let mut commands = vec![EmitCommand::RetryWorkspaceEvent {
        workspace_id: workspace_id_b64.clone(),
    }];

    if ctx.has_local_invite_secret && !ctx.peer_shared_transport_identity_active {
        commands.push(EmitCommand::ApplyTransportIdentityIntent {
            intent: TransportIdentityIntent::InstallBootstrapIdentityFromInviteSecret {
                recorded_by: recorded_by.to_string(),
                invite_event_id: ia.invite_event_id,
            },
        });
    }

    // Materialize accepted bootstrap trust when local context exists (joiner side)
    // and no matching steady-state PeerShared trust has already projected.
    if !ctx.bootstrap_spki_already_peer_shared {
        if let Some(ref bc) = ctx.bootstrap_context {
            let accepted_at = ia.created_at_ms as i64;
            let expires_at =
                accepted_at + crate::db::transport_trust::ACCEPTED_INVITE_BOOTSTRAP_TTL_MS;
            for addr in &bc.bootstrap_addrs {
                ops.push(WriteOp::InsertOrIgnore {
                    table: "invite_bootstrap_trust",
                    columns: vec![
                        "recorded_by",
                        "invite_accepted_event_id",
                        "invite_event_id",
                        "workspace_id",
                        "bootstrap_addr",
                        "bootstrap_spki_fingerprint",
                        "accepted_at",
                        "expires_at",
                    ],
                    values: vec![
                        SqlVal::Text(recorded_by.to_string()),
                        SqlVal::Text(event_id_b64.to_string()),
                        SqlVal::Text(invite_eid_b64.clone()),
                        SqlVal::Text(workspace_id_b64.clone()),
                        SqlVal::Text(addr.clone()),
                        SqlVal::Blob(bc.bootstrap_spki_fingerprint.to_vec()),
                        SqlVal::Int(accepted_at),
                        SqlVal::Int(expires_at),
                    ],
                });
            }
        }
    }

    ProjectorResult::valid_with_commands(ops, commands)
}
pub static INVITE_ACCEPTED_META: EventTypeMeta = EventTypeMeta {
    type_code: EVENT_TYPE_INVITE_ACCEPTED,
    type_name: "invite_accepted",
    projection_table: "invites_accepted",
    share_scope: ShareScope::Local,
    dep_fields: &["tenant_event_id"],
    dep_field_type_codes: &[&[super::EVENT_TYPE_TENANT]],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_invite_accepted,
    encode: encode_invite_accepted,
    projector: project_pure,
    context_loader: build_projector_context,
};
