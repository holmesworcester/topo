//! Pure projector conformance tests for InviteAccepted (type 9).
//!
//! TLA+ guards tested:
//!   SPEC_ANCHOR_SOURCE_01   — InvTrustAnchorSource (invites_accepted written)
//!   SPEC_IA_LINK_WORKSPACE_01 — InvInviteAcceptedLinkWorkspace (accept link matches workspace)
//!   SPEC_BOOTSTRAP_TRUST_01 — InvBootstrapTrustSource (write/no-write)

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::contracts::transport_identity_contract::TransportIdentitySpec;
    use topo::event_modules::invite_accepted::{
        build_projector_context, project_pure, InviteAcceptedEvent,
    };
    use topo::event_modules::ParsedEvent;
    use topo::projection::projector::{EmitCommand, SqlVal, WriteOp};
    use topo::projection::decision_context::ProjectionFrameContext;

    const PEER: &str = "peer_joiner";

    fn make_invite_accepted(invite_id: [u8; 32], workspace_id: [u8; 32]) -> ParsedEvent {
        ParsedEvent::InviteAccepted(InviteAcceptedEvent {
            created_at_ms: 2000,
            tenant_event_id: [7u8; 32],
            invite_event_id: invite_id,
            workspace_id,
        })
    }

    // ── SPEC_ANCHOR_SOURCE_01: pass ──

    #[test]
    fn test_invite_accepted_writes_workspace_binding() {
        let ws_id = [10u8; 32];
        let parsed = make_invite_accepted([5u8; 32], ws_id);
        let ctx = ctx_with_bootstrap(&b64(&ws_id), false);

        let result = project_pure(PEER, "event_ia_1", &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "invites_accepted");
    }

    #[test]
    fn test_invite_accepted_allows_self_accept_without_bootstrap_context() {
        let ws_id = [11u8; 32];
        let parsed = make_invite_accepted(ws_id, ws_id);

        let result = project_pure(PEER, "event_ia_self", &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "invites_accepted");
    }

    // ── SPEC_BOOTSTRAP_TRUST_01: pass ──

    #[test]
    fn test_invite_accepted_writes_bootstrap_trust() {
        let ws_id = [10u8; 32];
        let parsed = make_invite_accepted([5u8; 32], ws_id);
        let mut ctx = ctx_with_bootstrap(&b64(&ws_id), false); // bootstrap_context present
        ctx.has_local_invite_secret = true;

        let result = project_pure(PEER, "event_ia_2", &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "invite_bootstrap_trust");
        assert_emits_command(&result, "RetryWorkspaceEvent", |c| {
            matches!(c, EmitCommand::RetryWorkspaceEvent { .. })
        });
        assert_emits_command(&result, "InstallBootstrapIdentityFromInviteSecret", |c| {
            matches!(
                c,
                EmitCommand::MaterializeTransportIdentity {
                    spec: TransportIdentitySpec::InstallBootstrapIdentityFromInviteSecret { .. }
                }
            )
        });
    }

    // ── SPEC_BOOTSTRAP_TRUST_01: break ──

    #[test]
    fn test_invite_accepted_no_bootstrap_without_context() {
        let ws_id = [10u8; 32];
        let parsed = make_invite_accepted(ws_id, ws_id);
        let ctx = empty_ctx(); // self-accept: no bootstrap context required

        let result = project_pure(PEER, "event_ia_3", &parsed, &ctx);
        assert_valid(&result);
        // Should emit RetryWorkspaceEvent but NOT write invite_bootstrap_trust.
        assert_emits_command(&result, "RetryWorkspaceEvent", |c| {
            matches!(c, EmitCommand::RetryWorkspaceEvent { .. })
        });
        assert_no_write_to_table(&result, "invite_bootstrap_trust");
        assert_no_command(&result, |c| {
            matches!(
                c,
                EmitCommand::MaterializeTransportIdentity {
                    spec: TransportIdentitySpec::InstallBootstrapIdentityFromInviteSecret { .. }
                }
            )
        });
    }

    #[test]
    fn test_invite_accepted_rejects_missing_local_link_workspace_binding() {
        let ws_id = [12u8; 32];
        let parsed = make_invite_accepted([6u8; 32], ws_id);
        let mut ctx = empty_ctx();
        ctx.invite_accepted_link_workspace_mismatch_reason = Some(
            "invite_accepted missing locally recorded invite-link workspace binding".to_string(),
        );
        let queries = queries_with_ctx(ctx);

        let result = build_projector_context(
            &queries,
            &ProjectionFrameContext::default(),
            PEER,
            "event_ia_missing_link",
            &parsed,
        )
        .unwrap();
        assert_context_reject_contains(
            &result,
            "missing locally recorded invite-link workspace binding",
        );
    }

    #[test]
    fn test_invite_accepted_rejects_local_link_workspace_mismatch() {
        let ws_id = [13u8; 32];
        let parsed = make_invite_accepted([7u8; 32], ws_id);
        let mut ctx = ctx_with_bootstrap(&b64(&[14u8; 32]), false);
        ctx.invite_accepted_link_workspace_mismatch_reason = Some(
            "invite_accepted workspace_id does not match locally recorded invite-link workspace"
                .to_string(),
        );
        let queries = queries_with_ctx(ctx);

        let result = build_projector_context(
            &queries,
            &ProjectionFrameContext::default(),
            PEER,
            "event_ia_mismatch",
            &parsed,
        )
        .unwrap();
        assert_context_reject_contains(
            &result,
            "workspace_id does not match locally recorded invite-link workspace",
        );
    }

    #[test]
    fn test_invite_accepted_no_bootstrap_install_when_peer_shared_active() {
        let ws_id = [10u8; 32];
        let parsed = make_invite_accepted([5u8; 32], ws_id);
        let mut ctx = ctx_with_bootstrap(&b64(&ws_id), false);
        ctx.has_local_invite_secret = true;
        ctx.peer_shared_transport_identity_active = true;

        let result = project_pure(PEER, "event_ia_4", &parsed, &ctx);
        assert_valid(&result);
        assert_no_command(&result, |c| {
            matches!(
                c,
                EmitCommand::MaterializeTransportIdentity {
                    spec: TransportIdentitySpec::InstallBootstrapIdentityFromInviteSecret { .. }
                }
            )
        });
    }

    #[test]
    fn test_invite_accepted_writes_are_scoped_to_recorded_by() {
        let recorded_by = "tenant_scope_a";
        let ws_id = [10u8; 32];
        let parsed = make_invite_accepted([5u8; 32], ws_id);
        let mut ctx = ctx_with_bootstrap(&b64(&ws_id), false);
        ctx.has_local_invite_secret = true;

        let result = project_pure(recorded_by, "event_ia_scope", &parsed, &ctx);
        assert_valid(&result);

        let binding_insert = result.write_ops.iter().find(|op| {
            matches!(
                op,
                WriteOp::InsertOrIgnore {
                    table: "invites_accepted",
                    ..
                }
            )
        });
        let Some(WriteOp::InsertOrIgnore {
            columns, values, ..
        }) = binding_insert
        else {
            panic!(
                "expected invites_accepted insert, got {:?}",
                result.write_ops
            );
        };
        let recorded_by_idx = columns
            .iter()
            .position(|c| *c == "recorded_by")
            .expect("invites_accepted insert should include recorded_by");
        assert_eq!(
            values[recorded_by_idx],
            SqlVal::Text(recorded_by.to_string())
        );

        let trust_inserts: Vec<_> = result
            .write_ops
            .iter()
            .filter_map(|op| match op {
                WriteOp::InsertOrIgnore {
                    table: "invite_bootstrap_trust",
                    columns,
                    values,
                } => Some((columns, values)),
                _ => None,
            })
            .collect();
        assert!(
            !trust_inserts.is_empty(),
            "expected invite_bootstrap_trust insert ops"
        );
        for (columns, values) in trust_inserts {
            let recorded_by_idx = columns
                .iter()
                .position(|c| *c == "recorded_by")
                .expect("invite_bootstrap_trust insert should include recorded_by");
            assert_eq!(
                values[recorded_by_idx],
                SqlVal::Text(recorded_by.to_string())
            );
        }
    }
}
