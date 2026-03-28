//! Pure projector conformance tests for KeyRequest (type 30).
//!
//! TLA+ guards tested:
//!   SPEC_KR_INSERT_01 — repair request primitive insert

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::key_request::{project_pure, KeyRequestEvent};
    use topo::event_modules::ParsedEvent;
    use topo::projection::contract::ContextSnapshot;

    const PEER: &str = "peer_alice";

    fn make_key_request() -> ParsedEvent {
        ParsedEvent::KeyRequest(KeyRequestEvent {
            created_at_ms: 7_000,
            blocked_event_id: [1u8; 32],
            key_event_id: [2u8; 32],
            recipient_event_id: [3u8; 32],
            unwrap_key_event_id: [4u8; 32],
            signed_by: [5u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    #[test]
    fn test_key_request_valid() {
        let parsed = make_key_request();
        let event_id = b64(&[9u8; 32]);
        let ctx = ContextSnapshot::default();

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "key_requests");
    }

    #[test]
    fn test_key_request_rejects_non_key_request_event() {
        let parsed = topo::event_modules::ParsedEvent::Tenant(topo::event_modules::TenantEvent {
            created_at_ms: 1,
            public_key: [7u8; 32],
        });
        let event_id = b64(&[8u8; 32]);
        let ctx = ContextSnapshot::default();

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "not a key_request event");
    }
}
