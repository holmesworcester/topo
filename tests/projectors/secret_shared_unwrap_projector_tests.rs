//! Pure projector conformance tests for SecretSharedUnwrap (type 29).

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::secret_shared_unwrap::{project_pure, SecretSharedUnwrapEvent};
    use topo::event_modules::ParsedEvent;
    use topo::projection::contract::{ContextSnapshot, EmitCommand, UnwrappedSecretMaterial};

    const PEER: &str = "peer_alice";
    const EVENT_ID: &str = "ssu_event_1";

    fn make_unwrap() -> ParsedEvent {
        ParsedEvent::SecretSharedUnwrap(SecretSharedUnwrapEvent {
            created_at_ms: 7000,
            secret_shared_event_id: [1u8; 32],
            recipient_event_id: [2u8; 32],
            wrapped_key: [3u8; 32],
            signed_by: [4u8; 32],
            signer_type: 5,
        })
    }

    #[test]
    fn test_unwrap_valid_no_material() {
        let parsed = make_unwrap();
        let ctx = empty_ctx();

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "secret_shared_unwrap");
        assert_no_commands(&result);
    }

    #[test]
    fn test_unwrap_emits_deterministic_secret_key() {
        let parsed = make_unwrap();
        let ctx = ContextSnapshot {
            unwrapped_secret_material: Some(UnwrappedSecretMaterial {
                key_bytes: [42u8; 32],
                clear_invite_signer_event_id: None,
            }),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "secret_shared_unwrap");
        assert_emits_command(&result, "EmitDeterministicBlob", |cmd| {
            matches!(cmd, EmitCommand::EmitDeterministicBlob { .. })
        });
    }

    #[test]
    fn test_unwrap_emits_secret_key_and_invite_clear() {
        let parsed = make_unwrap();
        let ctx = ContextSnapshot {
            unwrapped_secret_material: Some(UnwrappedSecretMaterial {
                key_bytes: [55u8; 32],
                clear_invite_signer_event_id: Some([9u8; 32]),
            }),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_eq!(
            result.emit_commands.len(),
            2,
            "expected secret_key emit and pending-invite tombstone emit"
        );
    }
}
