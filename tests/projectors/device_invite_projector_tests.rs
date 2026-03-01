//! Pure projector conformance tests for DeviceInvite (types 12-13).
//!
//! TLA+ guards tested:
//!   SPEC_PENDING_TRUST_02 — InvPendingBootstrapTrustSource (write + no-write)
//!   SPEC_PENDING_INVITER_02 — InvPendingTrustOnlyOnInviter (local gate)

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::device_invite::project_pure;
    use topo::event_modules::device_invite::{DeviceInviteFirstEvent, DeviceInviteOngoingEvent};
    use topo::event_modules::ParsedEvent;

    const PEER: &str = "peer_inviter";
    const EVENT_ID: &str = "di_event_1";

    fn make_device_invite_first(public_key: [u8; 32]) -> ParsedEvent {
        ParsedEvent::DeviceInviteFirst(DeviceInviteFirstEvent {
            created_at_ms: 9000,
            public_key,
            signed_by: [3u8; 32],
            signer_type: 4,
            signature: [0u8; 64],
        })
    }

    fn make_device_invite_ongoing(public_key: [u8; 32]) -> ParsedEvent {
        ParsedEvent::DeviceInviteOngoing(DeviceInviteOngoingEvent {
            created_at_ms: 9001,
            public_key,
            signed_by: [3u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    // ── SPEC_PENDING_TRUST_02: pass (First + local + bootstrap) ──

    #[test]
    fn test_device_invite_first_writes_pending_trust() {
        let parsed = make_device_invite_first([5u8; 32]);
        let ctx = ctx_with_bootstrap("ws_1", true);

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "device_invites");
        assert_writes_to_table(&result, "pending_invite_bootstrap_trust");
        assert_no_commands(&result);
    }

    // ── SPEC_PENDING_TRUST_02: break (Ongoing — never emits) ──

    #[test]
    fn test_device_invite_ongoing_no_pending_trust() {
        let parsed = make_device_invite_ongoing([5u8; 32]);
        let ctx = ctx_with_bootstrap("ws_1", true);

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_no_write_to_table(&result, "pending_invite_bootstrap_trust");
        assert_no_commands(&result);
    }

    // ── SPEC_PENDING_INVITER_02: break (First but NOT local create) ──

    #[test]
    fn test_device_invite_no_pending_when_not_local() {
        let parsed = make_device_invite_first([5u8; 32]);
        let ctx = ctx_with_bootstrap("ws_1", false); // not local

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_no_write_to_table(&result, "pending_invite_bootstrap_trust");
        assert_no_commands(&result);
    }
}
