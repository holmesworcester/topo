//! Pure projector conformance tests for envelope-only projectors.
//!
//! Covers: Signed and Encrypted, which should never reach projector dispatch.

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::encrypted::{project_pure as project_encrypted, EncryptedEvent};
    use topo::event_modules::signed::{project_pure as project_signed, SignedEvent};
    use topo::event_modules::ParsedEvent;

    const RECORDED_BY: &str = "tenant-envelope";
    const EVENT_ID: &str = "envelope-event";

    fn unrelated_event() -> ParsedEvent {
        ParsedEvent::BenchDep(topo::event_modules::bench_dep::BenchDepEvent {
            created_at_ms: 7,
            dep_ids: vec![],
            payload: [0u8; 16],
        })
    }

    #[test]
    fn test_signed_projector_rejects_signed_event() {
        let parsed = ParsedEvent::Signed(SignedEvent {
            signer_event_id: [0x11u8; 32],
            inner_type_code: 1,
            inner_created_at_ms: 123,
            payload: vec![1, 0, 0, 0, 0, 0, 0, 0, 0],
            signature: [0x22u8; 64],
        });

        let result = project_signed(RECORDED_BY, EVENT_ID, &parsed, &empty_ctx());
        assert_reject_contains(&result, "should not reach projector dispatch");
        assert!(result.write_ops.is_empty());
        assert_no_commands(&result);
    }

    #[test]
    fn test_signed_projector_rejects_non_signed_event() {
        let result = project_signed(RECORDED_BY, EVENT_ID, &unrelated_event(), &empty_ctx());
        assert_reject_contains(&result, "should not reach projector dispatch");
        assert!(result.write_ops.is_empty());
        assert_no_commands(&result);
    }

    #[test]
    fn test_encrypted_projector_rejects_encrypted_event() {
        let parsed = ParsedEvent::Encrypted(EncryptedEvent {
            created_at_ms: 456,
            key_event_id: [0x31u8; 32],
            owner_event_id: [0x32u8; 32],
            inner_type_code: 1,
            nonce: [0x33u8; 12],
            ciphertext: vec![0x44u8; 9],
            auth_tag: [0x55u8; 16],
        });

        let result = project_encrypted(RECORDED_BY, EVENT_ID, &parsed, &empty_ctx());
        assert_reject_contains(&result, "should not reach projector dispatch");
        assert!(result.write_ops.is_empty());
        assert_no_commands(&result);
    }

    #[test]
    fn test_encrypted_projector_rejects_non_encrypted_event() {
        let result = project_encrypted(RECORDED_BY, EVENT_ID, &unrelated_event(), &empty_ctx());
        assert_reject_contains(&result, "should not reach projector dispatch");
        assert!(result.write_ops.is_empty());
        assert_no_commands(&result);
    }
}
