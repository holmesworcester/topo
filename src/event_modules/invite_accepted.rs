use super::layout::field_spec::{
    decode_fields, encode_fields, wire_size_for_fields, FieldSpec, FieldValue,
};
use super::registry::{EventTypeMeta, ShareScope};
use super::{EventError, ParsedEvent, EVENT_TYPE_INVITE_ACCEPTED};

// ─── Layout (owned by this module) ───

pub const INVITE_ACCEPTED_FIELDS: &[FieldSpec] = &[
    FieldSpec::Timestamp("created_at_ms"),
    FieldSpec::EventId("tenant_event_id"),
    FieldSpec::EventId("invite_event_id"),
    FieldSpec::EventId("workspace_id"),
];

/// InviteAccepted (type 9): type(1) + created_at(8) + tenant_event_id(32) + invite_event_id(32)
/// + workspace_id(32) = 105
pub const INVITE_ACCEPTED_WIRE_SIZE: usize = wire_size_for_fields(INVITE_ACCEPTED_FIELDS);

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
    if let Some((ts, tenant_event_id, invite_event_id, workspace_id)) =
        topo_verus_proofs::event_modules::layout::ts_id3::parse_ts_id3(
            EVENT_TYPE_INVITE_ACCEPTED,
            blob,
        )
    {
        return Ok(ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: ts,
            tenant_event_id,
            invite_event_id,
            workspace_id,
        }));
    }
    let values = decode_fields(EVENT_TYPE_INVITE_ACCEPTED, INVITE_ACCEPTED_FIELDS, blob)?;
    Ok(ParsedEvent::InviteAccepted(InviteAcceptedEvent {
        created_at_ms: values[0].as_timestamp().unwrap(),
        tenant_event_id: values[1].as_event_id().unwrap(),
        invite_event_id: values[2].as_event_id().unwrap(),
        workspace_id: values[3].as_event_id().unwrap(),
    }))
}

pub fn encode_invite_accepted(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ia = match event {
        ParsedEvent::InviteAccepted(a) => a,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(topo_verus_proofs::event_modules::layout::ts_id3::encode_ts_id3(
        EVENT_TYPE_INVITE_ACCEPTED,
        ia.created_at_ms,
        &ia.tenant_event_id,
        &ia.invite_event_id,
        &ia.workspace_id,
    ))
}

// === Projector (event-module locality) ===

use crate::contracts::transport_identity_contract::TransportIdentitySpec;
use crate::crypto::event_id_to_base64;
use crate::projection::projector::{
    EmitCommand, ProjectorDecisionContext, ProjectorResult, SqlVal, WriteOp,
};
use crate::projection::decision_context::{ProjectionFrameContext, ProjectionQueries};
use rusqlite::Connection;

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
    queries: &dyn ProjectionQueries,
    frame: &ProjectionFrameContext,
    recorded_by: &str,
    event_id_b64: &str,
    parsed: &ParsedEvent,
) -> Result<crate::projection::decision_context::ContextLoadResult, Box<dyn std::error::Error>> {
    let ia = match parsed {
        ParsedEvent::InviteAccepted(ia) => ia,
        _ => {
            return Err(
                "invite_accepted context loader called for non-invite_accepted event".into(),
            )
        }
    };

    let ctx = queries.load_invite_accepted_context(frame, recorded_by, event_id_b64, ia)?;

    // Delegate the accept/reject decision to the Verus-verified core.
    use topo_verus_proofs::event_modules::invite_accepted::{
        decide_invite_accepted_acceptance_core, InviteAcceptedAcceptanceCore,
        InviteAcceptedAcceptanceFlags,
    };
    let flags = InviteAcceptedAcceptanceFlags {
        link_workspace_match_ok: ctx.invite_accepted_link_workspace_mismatch_reason.is_none(),
    };
    match decide_invite_accepted_acceptance_core(flags) {
        InviteAcceptedAcceptanceCore::RejectLinkWorkspaceMismatch => {
            let reason = ctx
                .invite_accepted_link_workspace_mismatch_reason
                .clone()
                .expect("verified LinkWorkspaceMismatch requires reason to be present");
            Ok(crate::projection::decision_context::ContextLoadResult::reject(reason))
        }
        InviteAcceptedAcceptanceCore::Valid => {
            Ok(crate::projection::decision_context::ContextLoadResult::ready(ctx))
        }
    }
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
    ctx: &ProjectorDecisionContext,
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
        commands.push(EmitCommand::MaterializeTransportIdentity {
            spec: TransportIdentitySpec::InstallBootstrapIdentityFromInviteSecret {
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
pub static INVITE_ACCEPTED_META: EventTypeMeta = crate::event_modules::registry::event_type_meta! {
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
