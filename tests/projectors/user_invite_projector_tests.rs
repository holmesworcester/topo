//! Pure projector conformance tests for UserInvite (type 10).
//!
//! TLA+ guards tested:
//!   SPEC_PENDING_TRUST_01 — InvPendingBootstrapTrustSource (write + no-write)
//!   SPEC_PENDING_INVITER_01 — InvPendingTrustOnlyOnInviter (local gate)

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::user_invite::project_pure;
    use topo::event_modules::user_invite::UserInviteEvent;
    use topo::event_modules::ParsedEvent;

    const PEER: &str = "peer_inviter";
    const EVENT_ID: &str = "ui_event_1";

    fn make_user_invite(public_key: [u8; 32]) -> ParsedEvent {
        ParsedEvent::UserInvite(UserInviteEvent {
            created_at_ms: 8000,
            public_key,
            workspace_id: [10u8; 32],
            signed_by: [3u8; 32],
            signer_type: 1,
            signature: [0u8; 64],
        })
    }

    // ── SPEC_PENDING_TRUST_01: pass (Boot + local + bootstrap) ──

    #[test]
    fn test_user_invite_writes_pending_trust() {
        let parsed = make_user_invite([5u8; 32]);
        let ctx = ctx_with_bootstrap("ws_1", true); // is_local_create = true

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "user_invites");
        assert_writes_to_table(&result, "pending_invite_bootstrap_trust");
        assert_no_commands(&result);
    }

    // ── SPEC_PENDING_INVITER_01: break (Boot but NOT local create) ──

    #[test]
    fn test_user_invite_no_pending_when_not_local() {
        let parsed = make_user_invite([5u8; 32]);
        let ctx = ctx_with_bootstrap("ws_1", false); // is_local_create = false

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_no_write_to_table(&result, "pending_invite_bootstrap_trust");
        assert_no_commands(&result);
    }

    // ── basic valid projection ──

    #[test]
    fn test_user_invite_basic_valid() {
        let parsed = make_user_invite([5u8; 32]);
        let ctx = empty_ctx();

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "user_invites");
        assert_no_commands(&result);
    }

    #[test]
    fn test_user_invite_rejects_non_user_invite_event() {
        let parsed = ParsedEvent::SecretKey(topo::event_modules::secret_key::SecretKeyEvent {
            created_at_ms: 1,
            key_bytes: [1u8; 32],
        });
        let result = project_pure(PEER, EVENT_ID, &parsed, &empty_ctx());
        assert_reject(&result);
    }
}
