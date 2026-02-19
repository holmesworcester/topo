//! Pure projector conformance tests for UserInvite (types 10-11).
//!
//! TLA+ guards tested:
//!   SPEC_PENDING_TRUST_01 — InvPendingBootstrapTrustSource (emit + no-emit)
//!   SPEC_PENDING_INVITER_01 — InvPendingTrustOnlyOnInviter (local gate)

#[cfg(test)]
mod tests {
    use crate::event_modules::projector_test_harness::fixtures::*;
    use crate::event_modules::user_invite::project_pure;
    use crate::event_modules::user_invite::{UserInviteBootEvent, UserInviteOngoingEvent};
    use crate::event_modules::ParsedEvent;
    use crate::projection::result::EmitCommand;

    const PEER: &str = "peer_inviter";
    const EVENT_ID: &str = "ui_event_1";

    fn make_user_invite_boot(public_key: [u8; 32]) -> ParsedEvent {
        ParsedEvent::UserInviteBoot(UserInviteBootEvent {
            created_at_ms: 8000,
            public_key,
            workspace_id: [10u8; 32],
            signed_by: [3u8; 32],
            signer_type: 1,
            signature: [0u8; 64],
        })
    }

    fn make_user_invite_ongoing(public_key: [u8; 32]) -> ParsedEvent {
        ParsedEvent::UserInviteOngoing(UserInviteOngoingEvent {
            created_at_ms: 8001,
            public_key,
            admin_event_id: [11u8; 32],
            signed_by: [3u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    // ── SPEC_PENDING_TRUST_01: pass (Boot + local + bootstrap) ──

    #[test]
    fn test_user_invite_boot_emits_pending_trust() {
        let parsed = make_user_invite_boot([5u8; 32]);
        let ctx = ctx_with_bootstrap("ws_1", true); // is_local_create = true

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "user_invites");
        assert_emits_command(&result, "WritePendingBootstrapTrust", |c| {
            matches!(c, EmitCommand::WritePendingBootstrapTrust { .. })
        });
    }

    // ── SPEC_PENDING_TRUST_01: break (Ongoing — never emits pending trust) ──

    #[test]
    fn test_user_invite_ongoing_no_pending_trust() {
        let parsed = make_user_invite_ongoing([5u8; 32]);
        let ctx = ctx_with_bootstrap("ws_1", true);

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "user_invites");
        assert!(
            !result
                .emit_commands
                .iter()
                .any(|c| matches!(c, EmitCommand::WritePendingBootstrapTrust { .. })),
            "Ongoing variant should never emit WritePendingBootstrapTrust"
        );
    }

    // ── SPEC_PENDING_INVITER_01: break (Boot but NOT local create) ──

    #[test]
    fn test_user_invite_no_pending_when_not_local() {
        let parsed = make_user_invite_boot([5u8; 32]);
        let ctx = ctx_with_bootstrap("ws_1", false); // is_local_create = false

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert!(
            !result
                .emit_commands
                .iter()
                .any(|c| matches!(c, EmitCommand::WritePendingBootstrapTrust { .. })),
            "non-local Boot invite should not emit WritePendingBootstrapTrust"
        );
    }

    // ── basic valid projection ──

    #[test]
    fn test_user_invite_boot_basic_valid() {
        let parsed = make_user_invite_boot([5u8; 32]);
        let ctx = empty_ctx();

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "user_invites");
        assert_no_commands(&result);
    }
}
