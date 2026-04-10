//! Pure projector conformance tests for Reaction (type 2).
//!
//! TLA+ guards tested:
//!   SPEC_RXN_SIGNER_01 — InvSigner (signer-user mismatch reject + pass)

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::reaction::ReactionEvent;
    use topo::event_modules::reaction::{build_projector_context, project_pure};
    use topo::event_modules::ParsedEvent;
    use topo::projection::queries::ProjectionFrameContext;

    const PEER: &str = "peer_alice";
    const EVENT_ID: &str = "rxn_event_1";

    fn make_reaction() -> ParsedEvent {
        ParsedEvent::Reaction(ReactionEvent {
            created_at_ms: 4000,
            target_event_id: [1u8; 32],
            author_id: [2u8; 32],
            emoji: "👍".to_string(),
        })
    }

    // ── SPEC_RXN_SIGNER_01: pass ──

    #[test]
    fn test_reaction_valid() {
        let parsed = make_reaction();
        let ctx = topo::projection::contract::ProjectorDecisionContext {
            current_owner_event_id: Some(b64(&[1u8; 32])),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "reactions");
        assert_no_commands(&result);
    }

    // ── SPEC_RXN_SIGNER_01: break ──

    #[test]
    fn test_reaction_rejects_signer_user_mismatch() {
        let parsed = make_reaction();
        let queries = queries_with_ctx(ctx_with_signer_mismatch(
            "signer peer not linked to author user",
        ));

        let result = build_projector_context(
            &queries,
            &ProjectionFrameContext::default(),
            PEER,
            EVENT_ID,
            &parsed,
        )
        .unwrap();
        assert_context_reject_contains(&result, "signer peer not linked to author user");
    }

    #[test]
    fn test_reaction_rejects_owner_mismatch() {
        let parsed = make_reaction();
        let ctx = topo::projection::contract::ProjectorDecisionContext {
            current_owner_event_id: Some(b64(&[9u8; 32])),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "owner_event_id");
    }
}
