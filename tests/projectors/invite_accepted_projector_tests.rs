//! Pure projector conformance tests for InviteAccepted (type 9).
//!
//! TLA+ guards tested:
//!   SPEC_ANCHOR_SOURCE_01   — InvTrustAnchorSource (invites_accepted written)
//!   SPEC_BOOTSTRAP_TRUST_01 — InvBootstrapTrustSource (write/no-write)

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::invite_accepted::{project_pure, InviteAcceptedEvent};
    use topo::event_modules::ParsedEvent;
    use topo::projection::contract::EmitCommand;

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
        let ctx = empty_ctx(); // no existing anchor

        let result = project_pure(PEER, "event_ia_1", &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "invites_accepted");
    }

    // ── SPEC_BOOTSTRAP_TRUST_01: pass ──

    #[test]
    fn test_invite_accepted_writes_bootstrap_trust() {
        let ws_id = [10u8; 32];
        let parsed = make_invite_accepted([5u8; 32], ws_id);
        let ctx = ctx_with_bootstrap(&b64(&ws_id), false); // bootstrap_context present

        let result = project_pure(PEER, "event_ia_2", &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "invite_bootstrap_trust");
        assert_emits_command(&result, "RetryWorkspaceEvent", |c| {
            matches!(c, EmitCommand::RetryWorkspaceEvent { .. })
        });
    }

    // ── SPEC_BOOTSTRAP_TRUST_01: break ──

    #[test]
    fn test_invite_accepted_no_bootstrap_without_context() {
        let ws_id = [10u8; 32];
        let parsed = make_invite_accepted([5u8; 32], ws_id);
        let ctx = empty_ctx(); // no bootstrap context

        let result = project_pure(PEER, "event_ia_3", &parsed, &ctx);
        assert_valid(&result);
        // Should emit RetryWorkspaceEvent but NOT write invite_bootstrap_trust.
        assert_emits_command(&result, "RetryWorkspaceEvent", |c| {
            matches!(c, EmitCommand::RetryWorkspaceEvent { .. })
        });
        assert_no_write_to_table(&result, "invite_bootstrap_trust");
    }
}
