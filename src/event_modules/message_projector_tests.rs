//! Pure projector conformance tests for Message (type 1).
//!
//! TLA+ guards tested:
//!   SPEC_MSG_SIGNER_01 — InvSigner (signer-user mismatch reject + pass)
//!   CHK_MSG_DELETE_BEFORE_CREATE — convergence optimization

#[cfg(test)]
mod tests {
    use crate::event_modules::message::project_pure;
    use crate::event_modules::message::MessageEvent;
    use crate::event_modules::projector_test_harness::fixtures::*;
    use crate::event_modules::ParsedEvent;
    use crate::projection::result::DeletionIntentInfo;

    const PEER: &str = "peer_alice";
    const EVENT_ID: &str = "msg_event_1";

    fn make_message(author_id: [u8; 32]) -> ParsedEvent {
        ParsedEvent::Message(MessageEvent {
            created_at_ms: 3000,
            workspace_id: [1u8; 32],
            author_id,
            content: "hello".to_string(),
            signed_by: [3u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    // ── SPEC_MSG_SIGNER_01: pass ──

    #[test]
    fn test_message_valid() {
        let parsed = make_message([2u8; 32]);
        let ctx = empty_ctx();

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "messages");
        assert_no_commands(&result);
    }

    // ── SPEC_MSG_SIGNER_01: break ──

    #[test]
    fn test_message_rejects_signer_user_mismatch() {
        let parsed = make_message([2u8; 32]);
        let ctx = ctx_with_signer_mismatch("signer peer not linked to author user");

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "signer peer not linked to author user");
    }

    // ── CHK_MSG_DELETE_BEFORE_CREATE: pass (tombstone on arrival) ──

    #[test]
    fn test_message_tombstoned_by_deletion_intent() {
        let author = [2u8; 32];
        let author_b64 = b64(&author);
        let parsed = make_message(author);
        let ctx = crate::projection::result::ContextSnapshot {
            deletion_intents: vec![DeletionIntentInfo {
                deletion_event_id: "del_event_1".to_string(),
                author_id: author_b64,
                created_at: 2500,
            }],
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        // Should write to deleted_messages, not messages
        assert_writes_to_table(&result, "deleted_messages");
        assert_no_write_to_table(&result, "messages");
    }

    // ── CHK_MSG_DELETE_BEFORE_CREATE: break (wrong-author intent ignored) ──

    #[test]
    fn test_message_ignores_wrong_author_deletion_intent() {
        let author = [2u8; 32];
        let parsed = make_message(author);
        let ctx = crate::projection::result::ContextSnapshot {
            deletion_intents: vec![DeletionIntentInfo {
                deletion_event_id: "del_event_2".to_string(),
                author_id: b64(&[99u8; 32]), // different author
                created_at: 2500,
            }],
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "messages");
        assert_no_write_to_table(&result, "deleted_messages");
    }
}
