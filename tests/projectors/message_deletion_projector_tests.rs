//! Pure projector conformance tests for MessageDeletion (type 7).
//!
//! TLA+ guards tested:
//!   SPEC_DEL_SIGNER_01 — signer-derived deletion authorization
//!   CHK_DEL_NON_MESSAGE — type constraint rejection
//!   CHK_DEL_INTENT — intent always recorded
//!   CHK_DEL_TOMBSTONE — tombstone + cascade when target exists
//!   CHK_DEL_IDEMPOTENT — valid no-op when already tombstoned

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::message_deletion::MessageDeletionEvent;
    use topo::event_modules::message_deletion::{build_projector_context, project_pure};
    use topo::event_modules::ParsedEvent;
    use topo::projection::projector::{EmitCommand, ProjectorDecisionContext};
    use topo::projection::decision_context::ProjectionFrameContext;

    const PEER: &str = "peer_alice";
    const EVENT_ID: &str = "del_event_1";

    fn make_deletion(target: [u8; 32]) -> ParsedEvent {
        ParsedEvent::MessageDeletion(MessageDeletionEvent {
            created_at_ms: 5000,
            target_event_id: target,
        })
    }

    #[test]
    fn test_deletion_valid() {
        let author_b64 = b64(&[2u8; 32]);
        let parsed = make_deletion([1u8; 32]);
        let ctx = ProjectorDecisionContext {
            target_message_author: Some(author_b64.clone()),
            deletion_signer_user_id: Some(author_b64),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "deletion_intents");
        assert_writes_to_table(&result, "deleted_messages");
        assert!(
            result.write_ops.len() >= 2,
            "expected intent + tombstone writes before purge command"
        );
        assert_emits_command(&result, "HardPurgeMessageGraph", |cmd| {
            matches!(
                cmd,
                EmitCommand::HardPurgeMessageGraph { message_event_id } if message_event_id == &b64(&[1u8; 32])
            )
        });
    }

    #[test]
    fn test_deletion_valid_for_admin_signer() {
        let parsed = make_deletion([1u8; 32]);
        let ctx = ProjectorDecisionContext {
            target_message_author: Some(b64(&[9u8; 32])),
            deletion_signer_is_admin: true,
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "deletion_intents");
        assert_writes_to_table(&result, "deleted_messages");
    }

    #[test]
    fn test_deletion_rejects_wrong_author() {
        let parsed = make_deletion([1u8; 32]);
        let ctx = ProjectorDecisionContext {
            target_message_author: Some(b64(&[99u8; 32])),
            deletion_signer_user_id: Some(b64(&[2u8; 32])),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "does not match message author");
    }

    #[test]
    fn test_deletion_rejects_non_message_target() {
        let parsed = make_deletion([1u8; 32]);
        let ctx = ProjectorDecisionContext {
            deletion_signer_user_id: Some(b64(&[2u8; 32])),
            target_is_non_message: true,
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "non-message event");
    }

    #[test]
    fn test_deletion_intent_only_when_no_target() {
        let parsed = make_deletion([1u8; 32]);
        let ctx = ProjectorDecisionContext {
            deletion_signer_user_id: Some(b64(&[2u8; 32])),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "deletion_intents");
        assert_no_write_to_table(&result, "deleted_messages");
    }

    #[test]
    fn test_deletion_idempotent_when_tombstoned() {
        let author_b64 = b64(&[2u8; 32]);
        let parsed = make_deletion([1u8; 32]);
        let ctx = ProjectorDecisionContext {
            target_tombstone_author: Some(author_b64.clone()),
            deletion_signer_user_id: Some(author_b64),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "deletion_intents");
        assert_emits_command(&result, "HardPurgeMessageGraph", |cmd| {
            matches!(
                cmd,
                EmitCommand::HardPurgeMessageGraph { message_event_id } if message_event_id == &b64(&[1u8; 32])
            )
        });
    }

    #[test]
    fn test_deletion_rejects_when_tombstoned_wrong_author() {
        let parsed = make_deletion([1u8; 32]);
        let ctx = ProjectorDecisionContext {
            target_tombstone_author: Some(b64(&[99u8; 32])),
            deletion_signer_user_id: Some(b64(&[2u8; 32])),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "does not match message author");
    }

    #[test]
    fn test_deletion_rejects_invalid_signer_auth() {
        let parsed = make_deletion([1u8; 32]);
        let queries = queries_with_ctx(ProjectorDecisionContext {
            deletion_signer_reject_reason: Some(
                "message_deletion signer must be peer_shared or admin".to_string(),
            ),
            ..Default::default()
        });

        let result = build_projector_context(
            &queries,
            &ProjectionFrameContext::default(),
            PEER,
            EVENT_ID,
            &parsed,
        )
        .unwrap();
        assert_context_reject_contains(&result, "peer_shared or admin");
    }

    #[test]
    fn test_deletion_rejects_outer_owner_event_id() {
        let parsed = make_deletion([1u8; 32]);
        let ctx = ProjectorDecisionContext {
            deletion_signer_user_id: Some(b64(&[2u8; 32])),
            current_owner_event_id: Some(b64(&[9u8; 32])),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "owner_event_id");
    }
}
