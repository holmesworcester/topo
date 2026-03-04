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
    use topo::projection::contract::{ContextSnapshot, EmitCommand, UnwrappedKeyMaterial};

    const PEER: &str = "peer_alice";
    const EVENT_ID: &str = "ss_event_1";

    fn make_secret_shared() -> ParsedEvent {
        ParsedEvent::SecretShared(SecretSharedEvent {
            created_at_ms: 6000,
            key_event_id: [1u8; 32],
            recipient_event_id: [2u8; 32],
            wrapped_key: [3u8; 32],
            signed_by: [4u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    // ── SPEC_REMOVAL_EXCLUSION_01: pass ──

    #[test]
    fn test_secret_shared_valid_no_local_key() {
        let parsed = make_secret_shared();
        let ctx = empty_ctx();

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "secret_shared");
        // No MaterializeSecretKey when context has no unwrapped_key_material
        assert!(result.emit_commands.is_empty());
    }

    #[test]
    fn test_secret_shared_valid_with_unwrapped_key() {
        let parsed = make_secret_shared();
        let ctx = ContextSnapshot {
            unwrapped_key_material: Some(UnwrappedKeyMaterial {
                key_bytes: [42u8; 32],
                clear_invite_signer_event_id: None,
            }),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "secret_shared");
        assert_emits_command(&result, "MaterializeSecretKey", |cmd| {
            matches!(cmd, EmitCommand::MaterializeSecretKey { .. })
        });
    }

    // ── SPEC_REMOVAL_EXCLUSION_01: break ──

    #[test]
    fn test_secret_shared_rejects_removed_recipient() {
        let parsed = make_secret_shared();
        let ctx = ctx_with_recipient_removed();

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "has been removed");
    }
}
