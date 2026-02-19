//! Pure projector conformance tests for SecretShared (type 22).
//!
//! TLA+ guards tested:
//!   SPEC_REMOVAL_EXCLUSION_01 — InvRemovalExclusion (recipient removed reject + pass)
//!   SPEC_SECRET_SHARED_KEY_01 — InvSecretSharedKey (valid insert)

#[cfg(test)]
mod tests {
    use crate::event_modules::projector_test_harness::fixtures::*;
    use crate::event_modules::secret_shared::{project_pure, SecretSharedEvent};
    use crate::event_modules::ParsedEvent;

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
    fn test_secret_shared_valid() {
        let parsed = make_secret_shared();
        let ctx = empty_ctx();

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "secret_shared");
        assert_no_commands(&result);
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
