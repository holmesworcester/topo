//! Pure projector conformance tests for KeyRotation (type 32).
//!
//! TLA+ guards tested:
//!   SPEC_KROT_SIGNER_01 — rotation signer self-binding
//!   SPEC_KROT_FRONTIER_01 — carried frontier hash matches declared frontier refs

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::key_rotation::{project_pure, KeyRotationEvent};
    use topo::event_modules::removal::frontier_hash_from_refs;
    use topo::event_modules::{ParsedEvent, TenantEvent, EVENT_TYPE_KEY_ROTATION};

    const PEER: &str = "peer_alice";

    fn make_key_rotation(
        frontier_count: u8,
        frontier_ref_1: [u8; 32],
        frontier_ref_2: [u8; 32],
        frontier_hash: [u8; 32],
        rotated_by: [u8; 32],
    ) -> ParsedEvent {
        ParsedEvent::KeyRotation(KeyRotationEvent {
            created_at_ms: 8_000,
            key_event_id: [1u8; 32],
            frontier_count,
            frontier_ref_1,
            frontier_ref_2,
            frontier_ref_3: [0u8; 32],
            frontier_ref_4: [0u8; 32],
            frontier_hash,
            rotated_by,
        })
    }

    #[test]
    fn test_key_rotation_valid_root_frontier() {
        let signer = [9u8; 32];
        let parsed = make_key_rotation(
            0,
            [0u8; 32],
            [0u8; 32],
            frontier_hash_from_refs(&[]),
            signer,
        );
        let event_id = b64(&[7u8; 32]);
        let ctx = ctx_with_current_signer(&b64(&signer), EVENT_TYPE_KEY_ROTATION);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "key_rotations");
    }

    #[test]
    fn test_key_rotation_valid_multi_parent_frontier() {
        let signer = [9u8; 32];
        let parsed = make_key_rotation(
            2,
            [2u8; 32],
            [3u8; 32],
            frontier_hash_from_refs(&[[2u8; 32], [3u8; 32]]),
            signer,
        );
        let event_id = b64(&[8u8; 32]);
        let ctx = ctx_with_current_signer(&b64(&signer), EVENT_TYPE_KEY_ROTATION);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "key_rotations");
    }

    #[test]
    fn test_key_rotation_rejects_rotated_by_signer_mismatch() {
        let parsed = make_key_rotation(
            1,
            [2u8; 32],
            [0u8; 32],
            frontier_hash_from_refs(&[[2u8; 32]]),
            [8u8; 32],
        );
        let event_id = b64(&[6u8; 32]);
        let ctx = ctx_with_current_signer(&b64(&[88u8; 32]), EVENT_TYPE_KEY_ROTATION);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "rotated_by must equal current signer");
    }

    #[test]
    fn test_key_rotation_rejects_frontier_hash_mismatch() {
        let signer = [9u8; 32];
        let parsed = make_key_rotation(1, [2u8; 32], [0u8; 32], [7u8; 32], signer);
        let event_id = b64(&[5u8; 32]);
        let ctx = ctx_with_current_signer(&b64(&signer), EVENT_TYPE_KEY_ROTATION);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "frontier_hash does not match frontier refs");
    }

    #[test]
    fn test_key_rotation_rejects_unsorted_multi_parent_frontier_refs() {
        let signer = [9u8; 32];
        let parsed = make_key_rotation(
            2,
            [3u8; 32],
            [2u8; 32],
            frontier_hash_from_refs(&[[2u8; 32], [3u8; 32]]),
            signer,
        );
        let event_id = b64(&[3u8; 32]);
        let ctx = ctx_with_current_signer(&b64(&signer), EVENT_TYPE_KEY_ROTATION);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "frontier refs must be sorted in canonical order");
    }

    #[test]
    fn test_key_rotation_rejects_non_key_rotation_event() {
        let parsed = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: 1,
            public_key: [7u8; 32],
        });
        let event_id = b64(&[4u8; 32]);
        let ctx = ctx_with_current_signer(&b64(&[9u8; 32]), EVENT_TYPE_KEY_ROTATION);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "not a key_rotation event");
    }
}
