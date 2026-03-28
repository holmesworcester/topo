//! Pure projector conformance tests for Removal (type 31).
//!
//! TLA+ guards tested:
//!   SPEC_RM_SIGNER_01 — remover signer self-binding
//!   SPEC_RM_FRONTIER_01 — carried frontier hash matches declared parent refs

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::removal::{frontier_hash_from_refs, project_pure, RemovalEvent};
    use topo::event_modules::{ParsedEvent, TenantEvent};
    use topo::projection::contract::ContextSnapshot;

    const PEER: &str = "peer_alice";

    fn make_removal(
        parent_count: u8,
        parent_1: [u8; 32],
        parent_2: [u8; 32],
        frontier_hash: [u8; 32],
        removed_by: [u8; 32],
        signed_by: [u8; 32],
    ) -> ParsedEvent {
        ParsedEvent::Removal(RemovalEvent {
            created_at_ms: 7_000,
            removed_member_ref: [1u8; 32],
            parent_count,
            parent_1,
            parent_2,
            parent_3: [0u8; 32],
            parent_4: [0u8; 32],
            frontier_hash,
            removed_by,
            signed_by,
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    #[test]
    fn test_removal_valid() {
        let signer = [9u8; 32];
        let parsed = make_removal(
            1,
            [2u8; 32],
            [0u8; 32],
            frontier_hash_from_refs(&[[2u8; 32]]),
            signer,
            signer,
        );
        let event_id = b64(&[7u8; 32]);
        let ctx = ContextSnapshot::default();

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "removals");
    }

    #[test]
    fn test_removal_valid_multi_parent_frontier() {
        let signer = [9u8; 32];
        let parsed = make_removal(
            2,
            [2u8; 32],
            [3u8; 32],
            frontier_hash_from_refs(&[[2u8; 32], [3u8; 32]]),
            signer,
            signer,
        );
        let event_id = b64(&[8u8; 32]);
        let ctx = ContextSnapshot::default();

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "removals");
    }

    #[test]
    fn test_removal_rejects_removed_by_signer_mismatch() {
        let parsed = make_removal(
            1,
            [2u8; 32],
            [0u8; 32],
            frontier_hash_from_refs(&[[2u8; 32]]),
            [8u8; 32],
            [9u8; 32],
        );
        let event_id = b64(&[6u8; 32]);
        let ctx = ContextSnapshot::default();

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "removed_by must equal signed_by");
    }

    #[test]
    fn test_removal_rejects_frontier_hash_mismatch() {
        let signer = [9u8; 32];
        let parsed = make_removal(1, [2u8; 32], [0u8; 32], [7u8; 32], signer, signer);
        let event_id = b64(&[5u8; 32]);
        let ctx = ContextSnapshot::default();

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "frontier_hash does not match parent frontier");
    }

    #[test]
    fn test_removal_rejects_unsorted_multi_parent_frontier_refs() {
        let signer = [9u8; 32];
        let parsed = make_removal(
            2,
            [3u8; 32],
            [2u8; 32],
            frontier_hash_from_refs(&[[2u8; 32], [3u8; 32]]),
            signer,
            signer,
        );
        let event_id = b64(&[3u8; 32]);
        let ctx = ContextSnapshot::default();

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "frontier refs must be sorted in canonical order");
    }

    #[test]
    fn test_removal_rejects_non_removal_event() {
        let parsed = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: 1,
            public_key: [7u8; 32],
        });
        let event_id = b64(&[4u8; 32]);
        let ctx = ContextSnapshot::default();

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "not a removal event");
    }
}
