//! Pure projector conformance tests for DeviceInvite (type 12).
//!
//! TLA+ guards tested:
//!   SPEC_PENDING_TRUST_02 — InvPendingBootstrapTrustSource (write + no-write)
//!   SPEC_PENDING_INVITER_02 — InvPendingTrustOnlyOnInviter (local gate)

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::device_invite::project_pure;
    use topo::event_modules::device_invite::DeviceInviteEvent;
    use topo::event_modules::ParsedEvent;

    const PEER: &str = "peer_inviter";

    fn make_device_invite(public_key: [u8; 32]) -> ParsedEvent {
        ParsedEvent::DeviceInvite(DeviceInviteEvent {
            created_at_ms: 9000,
            public_key,
            signed_by: [3u8; 32],
            signer_type: 4,
            signature: [0u8; 64],
        })
    }

    // ── SPEC_PENDING_TRUST_02: pass (First + local + bootstrap) ──

    #[test]
    fn test_device_invite_writes_pending_trust() {
        let parsed = make_device_invite([5u8; 32]);
        let ctx = ctx_with_bootstrap("ws_1", true);
        let event_id = b64(&[11u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "device_invites");
        assert_writes_to_table(&result, "pending_invite_bootstrap_trust");
    }

    // ── SPEC_PENDING_INVITER_02: break (First but NOT local create) ──

    #[test]
    fn test_device_invite_no_pending_when_not_local() {
        let parsed = make_device_invite([5u8; 32]);
        let ctx = ctx_with_bootstrap("ws_1", false); // not local
        let event_id = b64(&[12u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_no_write_to_table(&result, "pending_invite_bootstrap_trust");
    }

    #[test]
    fn test_device_invite_rejects_non_device_invite_event() {
        let parsed = ParsedEvent::SecretKey(topo::event_modules::secret_key::SecretKeyEvent {
            created_at_ms: 1,
            key_bytes: [1u8; 32],
        });
        let event_id = b64(&[13u8; 32]);
        let result = project_pure(PEER, &event_id, &parsed, &empty_ctx());
        assert_reject(&result);
    }
}
