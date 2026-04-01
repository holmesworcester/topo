//! Pure projector conformance tests for KeyRequest (type 30).
//!
//! TLA+ guards tested:
//!   SPEC_KR_INSERT_01 — repair request primitive insert

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::key_request::{delivery_target_id, project_pure, KeyRequestEvent};
    use topo::event_modules::{ParsedEvent, EVENT_TYPE_KEY_REQUEST};

    const PEER: &str = "peer_alice";

    fn make_key_request(frontier_hash: [u8; 32], delivery_target_id: [u8; 32]) -> ParsedEvent {
        ParsedEvent::KeyRequest(KeyRequestEvent {
            created_at_ms: 7_000,
            blocked_event_id: [1u8; 32],
            key_event_id: [2u8; 32],
            frontier_hash,
            delivery_target_id,
            recipient_event_id: [3u8; 32],
            unwrap_key_event_id: [4u8; 32],
        })
    }

    #[test]
    fn test_key_request_valid() {
        let frontier_hash = [9u8; 32];
        let parsed = make_key_request(
            frontier_hash,
            delivery_target_id(&[2u8; 32], &frontier_hash, &[3u8; 32], &[4u8; 32]),
        );
        let event_id = b64(&[9u8; 32]);
        let ctx = ctx_with_current_signer(&event_id, EVENT_TYPE_KEY_REQUEST);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "key_requests");
    }

    #[test]
    fn test_key_request_rejects_delivery_target_mismatch() {
        let parsed = make_key_request([9u8; 32], [8u8; 32]);
        let event_id = b64(&[7u8; 32]);
        let ctx = ctx_with_current_signer(&event_id, EVENT_TYPE_KEY_REQUEST);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(
            &result,
            "delivery_target_id does not match key request target",
        );
    }

    #[test]
    fn test_key_request_rejects_non_key_request_event() {
        let parsed = topo::event_modules::ParsedEvent::Tenant(topo::event_modules::TenantEvent {
            created_at_ms: 1,
            public_key: [7u8; 32],
        });
        let event_id = b64(&[8u8; 32]);
        let ctx = ctx_with_current_signer(&event_id, EVENT_TYPE_KEY_REQUEST);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "not a key_request event");
    }
}
