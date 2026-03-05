//! Pure projector conformance tests for SecretShared (type 22).
//!
//! TLA+ guards tested:
//!   SPEC_REMOVAL_EXCLUSION_01 — InvRemovalExclusion (recipient removed reject + pass)
//!   SPEC_SECRET_SHARED_KEY_01 — InvSecretSharedKey (valid insert)

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::secret_shared::{project_pure, SecretSharedEvent};
    use topo::event_modules::ParsedEvent;
    use topo::projection::contract::{ContextSnapshot, EmitCommand, UnwrappedSecretMaterial};

    const PEER: &str = "peer_alice";
    fn make_secret_shared(key_event_id: [u8; 32]) -> ParsedEvent {
        ParsedEvent::SecretShared(SecretSharedEvent {
            created_at_ms: 6000,
            key_event_id,
            recipient_event_id: [2u8; 32],
            unwrap_key_event_id: [3u8; 32],
            wrapped_key: [3u8; 32],
            signed_by: [4u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    // ── SPEC_REMOVAL_EXCLUSION_01: pass ──

    #[test]
    fn test_secret_shared_valid() {
        let key_bytes = [42u8; 32];
        let key_event_id =
            topo::event_modules::secret_key::deterministic_secret_key_event_id(&key_bytes);
        let parsed = make_secret_shared(key_event_id);
        let ctx = ContextSnapshot {
            unwrapped_secret_material: Some(UnwrappedSecretMaterial { key_bytes }),
            ..Default::default()
        };
        let event_id = b64(&[9u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "secret_shared");
        assert_emits_command(&result, "EmitDeterministicBlob", |cmd| {
            matches!(cmd, EmitCommand::EmitDeterministicBlob { .. })
        });
    }

    // ── SPEC_REMOVAL_EXCLUSION_01: break ──

    #[test]
    fn test_secret_shared_rejects_removed_recipient() {
        let parsed = make_secret_shared([9u8; 32]);
        let ctx = ctx_with_recipient_removed();
        let event_id = b64(&[9u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "has been removed");
    }

    #[test]
    fn test_secret_shared_rejects_key_event_id_mismatch() {
        let parsed = make_secret_shared([7u8; 32]);
        let ctx = ContextSnapshot {
            unwrapped_secret_material: Some(UnwrappedSecretMaterial {
                key_bytes: [42u8; 32],
            }),
            ..Default::default()
        };
        let event_id = b64(&[8u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_reject_contains(&result, "does not match claimed key_event_id");
    }
}
