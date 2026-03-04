//! Pure projector conformance tests for MessageDeletion (type 7).
//!
//! TLA+ guards tested:
//!   SPEC_DEL_AUTHOR_01 — InvRemovalAdmin (author check: pass + break)
//!   CHK_DEL_NON_MESSAGE — type constraint rejection
//!   CHK_DEL_INTENT — intent always recorded
//!   CHK_DEL_TOMBSTONE — tombstone + cascade when target exists
//!   CHK_DEL_IDEMPOTENT — valid no-op when already tombstoned

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::message_deletion::project_pure;
    use topo::event_modules::message_deletion::MessageDeletionEvent;
    use topo::event_modules::ParsedEvent;

    const PEER: &str = "peer_alice";
    const EVENT_ID: &str = "del_event_1";

    fn make_deletion(target: [u8; 32], author: [u8; 32]) -> ParsedEvent {
        ParsedEvent::MessageDeletion(MessageDeletionEvent {
            created_at_ms: 5000,
            target_event_id: target,
            author_id: author,
            signed_by: [3u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    // ── SPEC_DEL_AUTHOR_01: pass (matching author, target exists) ──

    #[test]
    fn test_deletion_valid() {
        let author = [2u8; 32];
        let author_b64 = b64(&author);
        let parsed = make_deletion([1u8; 32], author);
        let ctx = ctx_with_target_author(&author_b64);

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "deletion_intents");
        assert_writes_to_table(&result, "deleted_messages");
        // Cascade: should also delete from messages and reactions
        assert!(
            result.write_ops.len() >= 3,
            "expected intent + tombstone + cascade ops"
        );
    }

    // ── SPEC_DEL_AUTHOR_01: break (wrong author) ──

    #[test]
    fn test_deletion_rejects_wrong_author() {
        let author = [2u8; 32];
        let parsed = make_deletion([1u8; 32], author);
        let ctx = ctx_with_target_author(&b64(&[99u8; 32])); // different author

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "does not match message author");
    }

    // ── CHK_DEL_NON_MESSAGE: break ──

    #[test]
    fn test_deletion_rejects_non_message_target() {
        let parsed = make_deletion([1u8; 32], [2u8; 32]);
        let ctx = topo::projection::contract::ContextSnapshot {
            target_is_non_message: true,
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "non-message event");
    }

    // ── CHK_DEL_INTENT: pass (target doesn't exist yet, only intent) ──

    #[test]
    fn test_deletion_intent_only_when_no_target() {
        let parsed = make_deletion([1u8; 32], [2u8; 32]);
        let ctx = empty_ctx(); // target not yet projected

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "deletion_intents");
        assert_no_write_to_table(&result, "deleted_messages");
    }

    // ── CHK_DEL_IDEMPOTENT: pass (already tombstoned, matching author) ──

    #[test]
    fn test_deletion_idempotent_when_tombstoned() {
        let author = [2u8; 32];
        let author_b64 = b64(&author);
        let parsed = make_deletion([1u8; 32], author);
        let ctx = topo::projection::contract::ContextSnapshot {
            target_tombstone_author: Some(author_b64),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        // Should still record intent
        assert_writes_to_table(&result, "deletion_intents");
    }

    // ── CHK_DEL_IDEMPOTENT: break (tombstoned but wrong author) ──

    #[test]
    fn test_deletion_rejects_when_tombstoned_wrong_author() {
        let parsed = make_deletion([1u8; 32], [2u8; 32]);
        let ctx = topo::projection::contract::ContextSnapshot {
            target_tombstone_author: Some(b64(&[99u8; 32])),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "does not match message author");
    }

    // ── CHK_DEL_SIGNER_USER_MISMATCH: break ──

    #[test]
    fn test_deletion_rejects_signer_user_mismatch() {
        let parsed = make_deletion([1u8; 32], [2u8; 32]);
        let ctx = ctx_with_signer_mismatch("signer peer not linked to author user");

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "signer peer not linked to author user");
    }

    // ── SC-14: Crypto-shred cascade — file slices and attachments deleted ──

    #[test]
    fn test_deletion_cascades_file_slices_and_attachments() {
        let author = [2u8; 32];
        let author_b64 = b64(&author);
        let parsed = make_deletion([1u8; 32], author);

        let file_id_a = b64(&[10u8; 32]);
        let file_id_b = b64(&[11u8; 32]);

        let ctx = topo::projection::contract::ContextSnapshot {
            target_message_author: Some(author_b64),
            target_attachment_file_ids: vec![file_id_a.clone(), file_id_b.clone()],
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);

        // Should have: intent + tombstone + delete messages + delete reactions
        //   + delete file_slices(file_a) + delete file_slices(file_b) + delete message_attachments
        assert_writes_to_table(&result, "deletion_intents");
        assert_writes_to_table(&result, "deleted_messages");

        let delete_ops: Vec<_> = result
            .write_ops
            .iter()
            .filter(|op| matches!(op, topo::projection::contract::WriteOp::Delete { .. }))
            .collect();

        // Expect: messages, reactions, file_slices(a), file_slices(b), message_attachments = 5 deletes
        assert_eq!(
            delete_ops.len(),
            5,
            "expected 5 delete ops (messages + reactions + 2 file_slices + message_attachments), got {}",
            delete_ops.len()
        );

        // Verify file_slices deletes reference correct file_ids
        let file_slice_deletes: Vec<_> = result
            .write_ops
            .iter()
            .filter(|op| {
                matches!(op, topo::projection::contract::WriteOp::Delete { table: "file_slices", .. })
            })
            .collect();
        assert_eq!(file_slice_deletes.len(), 2, "expected 2 file_slices deletes");

        // Verify message_attachments delete exists
        let attachment_deletes: Vec<_> = result
            .write_ops
            .iter()
            .filter(|op| {
                matches!(op, topo::projection::contract::WriteOp::Delete { table: "message_attachments", .. })
            })
            .collect();
        assert_eq!(attachment_deletes.len(), 1, "expected 1 message_attachments delete");
    }
}
