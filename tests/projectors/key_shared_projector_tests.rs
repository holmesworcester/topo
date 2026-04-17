//! Pure projector conformance tests for KeyShared (type 22).
//!
//! TLA+ guards tested:
//!   SPEC_SECRET_SHARED_KEY_01 — InvKeySharedKey (valid insert)
//!   SPEC_KS_FRONTIER_01 — carried frontier hash matches declared frontier refs

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::key_request::delivery_target_id;
    use topo::event_modules::key_shared::{project_pure, KeySharedEvent};
    use topo::event_modules::removal::frontier_hash_from_refs;
    use topo::event_modules::ParsedEvent;
    use topo::projection::projector::{
        EmitCommand, ProjectorDecisionContext, UnwrappedSecretMaterial,
    };

    const PEER: &str = "peer_alice";
    fn make_key_shared(
        key_event_id: [u8; 32],
        frontier_count: u8,
        frontier_ref_1: [u8; 32],
        frontier_ref_2: [u8; 32],
        frontier_hash: [u8; 32],
        delivery_target_id: [u8; 32],
    ) -> ParsedEvent {
        ParsedEvent::KeyShared(KeySharedEvent {
            created_at_ms: 6000,
            key_event_id,
            frontier_count,
            frontier_ref_1,
            frontier_ref_2,
            frontier_ref_3: [0u8; 32],
            frontier_ref_4: [0u8; 32],
            frontier_hash,
            delivery_target_id,
            recipient_event_id: [2u8; 32],
            unwrap_key_event_id: [3u8; 32],
            wrapped_key: [3u8; 32],
        })
    }

    #[test]
    fn test_key_shared_valid() {
        let key_bytes = [42u8; 32];
        let key_event_id =
            topo::event_modules::key_secret::deterministic_key_secret_event_id(&key_bytes);
        let frontier_hash = frontier_hash_from_refs(&[]);
        let parsed = make_key_shared(
            key_event_id,
            0,
            [0u8; 32],
            [0u8; 32],
            frontier_hash,
            delivery_target_id(&key_event_id, &frontier_hash, &[2u8; 32], &[3u8; 32]),
        );
        let ctx = ProjectorDecisionContext {
            unwrapped_secret_material: Some(UnwrappedSecretMaterial { key_bytes }),
            ..Default::default()
        };
        let event_id = b64(&[9u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "key_shared");
        assert_emits_command(&result, "EmitDeterministicBlob", |cmd| {
            matches!(cmd, EmitCommand::EmitDeterministicBlob { .. })
        });
    }

    #[test]
    fn test_key_shared_rejects_key_event_id_mismatch() {
        let frontier_hash = frontier_hash_from_refs(&[]);
        let parsed = make_key_shared(
            [7u8; 32],
            0,
            [0u8; 32],
            [0u8; 32],
            frontier_hash,
            delivery_target_id(&[7u8; 32], &frontier_hash, &[2u8; 32], &[3u8; 32]),
        );
        let ctx = ProjectorDecisionContext {
            unwrapped_secret_material: Some(UnwrappedSecretMaterial {
                key_bytes: [42u8; 32],
            }),
            ..Default::default()
        };
        let event_id = b64(&[8u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "does not match claimed key_event_id");
    }

    #[test]
    fn test_key_shared_rejects_delivery_target_mismatch() {
        let key_bytes = [42u8; 32];
        let key_event_id =
            topo::event_modules::key_secret::deterministic_key_secret_event_id(&key_bytes);
        let parsed = make_key_shared(
            key_event_id,
            0,
            [0u8; 32],
            [0u8; 32],
            frontier_hash_from_refs(&[]),
            [8u8; 32],
        );
        let ctx = ProjectorDecisionContext {
            unwrapped_secret_material: Some(UnwrappedSecretMaterial { key_bytes }),
            ..Default::default()
        };
        let event_id = b64(&[6u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(
            &result,
            "delivery_target_id does not match key_shared target",
        );
    }

    #[test]
    fn test_key_shared_rejects_frontier_hash_mismatch() {
        let key_bytes = [42u8; 32];
        let key_event_id =
            topo::event_modules::key_secret::deterministic_key_secret_event_id(&key_bytes);
        let parsed = make_key_shared(
            key_event_id,
            1,
            [0xAA; 32],
            [0u8; 32],
            [0xBB; 32],
            delivery_target_id(&key_event_id, &[0xBB; 32], &[2u8; 32], &[3u8; 32]),
        );
        let ctx = ProjectorDecisionContext {
            unwrapped_secret_material: Some(UnwrappedSecretMaterial { key_bytes }),
            ..Default::default()
        };
        let event_id = b64(&[5u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "frontier_hash does not match key_shared frontier");
    }

    #[test]
    fn test_key_shared_valid_multi_parent_frontier() {
        let key_bytes = [42u8; 32];
        let key_event_id =
            topo::event_modules::key_secret::deterministic_key_secret_event_id(&key_bytes);
        let frontier_hash = frontier_hash_from_refs(&[[0xAA; 32], [0xBB; 32]]);
        let parsed = make_key_shared(
            key_event_id,
            2,
            [0xAA; 32],
            [0xBB; 32],
            frontier_hash,
            delivery_target_id(&key_event_id, &frontier_hash, &[2u8; 32], &[3u8; 32]),
        );
        let ctx = ProjectorDecisionContext {
            unwrapped_secret_material: Some(UnwrappedSecretMaterial { key_bytes }),
            ..Default::default()
        };
        let event_id = b64(&[4u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "key_shared");
    }

    #[test]
    fn test_key_shared_rejects_unsorted_multi_parent_frontier_refs() {
        let key_bytes = [42u8; 32];
        let key_event_id =
            topo::event_modules::key_secret::deterministic_key_secret_event_id(&key_bytes);
        let frontier_hash = frontier_hash_from_refs(&[[0xAA; 32], [0xBB; 32]]);
        let parsed = make_key_shared(
            key_event_id,
            2,
            [0xBB; 32],
            [0xAA; 32],
            frontier_hash,
            delivery_target_id(&key_event_id, &frontier_hash, &[2u8; 32], &[3u8; 32]),
        );
        let ctx = ProjectorDecisionContext {
            unwrapped_secret_material: Some(UnwrappedSecretMaterial { key_bytes }),
            ..Default::default()
        };
        let event_id = b64(&[3u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "frontier refs must be sorted in canonical order");
    }
}
