//! Pure projector conformance tests for Reaction (type 2).
//!
//! TLA+ guards tested:
//!   SPEC_RXN_SIGNER_01 — InvSigner (signer-user mismatch reject + pass)
//!   CHK_RXN_SKIP_DELETED — post-tombstone skip behavior

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::reaction::project_pure;
    use topo::event_modules::reaction::ReactionEvent;
    use topo::event_modules::ParsedEvent;

    const PEER: &str = "peer_alice";
    const EVENT_ID: &str = "rxn_event_1";

    fn make_reaction() -> ParsedEvent {
        ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: 4000,
            target_event_id: [1u8; 32],
            author_id: [2u8; 32],
            emoji: "👍".to_string(),
            signed_by: [3u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    // ── SPEC_RXN_SIGNER_01: pass ──

    #[test]
    fn test_reaction_valid() {
        let parsed = make_reaction();
        let ctx = empty_ctx();

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "reactions");
        assert_no_commands(&result);
    }

    // ── SPEC_RXN_SIGNER_01: break ──

    #[test]
    fn test_reaction_rejects_signer_user_mismatch() {
        let parsed = make_reaction();
        let ctx = ctx_with_signer_mismatch("signer peer not linked to author user");

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "signer peer not linked to author user");
    }

    // ── CHK_RXN_SKIP_DELETED: pass (valid but no write) ──

    #[test]
    fn test_reaction_skips_when_target_deleted() {
        let parsed = make_reaction();
        let ctx = topo::projection::contract::ContextSnapshot {
            target_message_deleted: true,
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert!(
            result.write_ops.is_empty(),
            "should produce no write ops when target deleted"
        );
    }
}
