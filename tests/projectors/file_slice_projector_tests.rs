//! Pure projector conformance tests for FileSlice (type 25).
//!
//! TLA+ guards tested:
//!   SPEC_FILE_AUTH_01 — InvFileSliceAuth (dep-block on no descriptor)
//!   SPEC_FILE_AUTH_02 — InvFileSliceAuth (signer mismatch reject + valid)
//!   CHK_FS_SLOT_CONFLICT — slot uniqueness (conflict reject)
//!   CHK_FS_IDEMPOTENT — idempotent replay

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::file_slice::FileSliceEvent;
    use topo::event_modules::file_slice::{build_projector_context, project_pure};
    use topo::event_modules::{ParsedEvent, EVENT_TYPE_FILE_SLICE};
    use topo::projection::contract::FileDescriptorInfo;
    use topo::projection::queries::ProjectionFrameContext;

    const PEER: &str = "peer_alice";
    const EVENT_ID: &str = "fs_event_1";

    fn make_file_slice(file_id: [u8; 32]) -> ParsedEvent {
        ParsedEvent::FileSlice(FileSliceEvent {
            created_at_ms: 7000,
            file_id,
            slice_number: 0,
            ciphertext: vec![0u8; topo::event_modules::file_slice::FILE_SLICE_CIPHERTEXT_BYTES],
        })
    }

    fn descriptor(
        message_id: &str,
        signer_event_id: &str,
        key_event_id: &str,
    ) -> FileDescriptorInfo {
        FileDescriptorInfo {
            event_id: "desc_1".to_string(),
            message_id: message_id.to_string(),
            signer_event_id: signer_event_id.to_string(),
            key_event_id: key_event_id.to_string(),
            root_hash: [0u8; 32],
            blob_bytes: 0,
            slice_bytes: 0,
        }
    }

    // ── SPEC_FILE_AUTH_01: break (no descriptor → guard block) ──

    #[test]
    fn test_file_slice_blocks_no_descriptor() {
        let parsed = make_file_slice([1u8; 32]);
        let mut ctx = empty_ctx(); // no file_descriptors
        ctx.current_owner_event_id = Some(b64(&[9u8; 32]));
        ctx.current_signer = Some(topo::projection::contract::CurrentSignerInfo {
            event_id: b64(&[3u8; 32]),
            semantic_type_code: EVENT_TYPE_FILE_SLICE,
        });

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_block(&result);
        // FileSlice now dep-blocks on file_id (no guard table commands needed).
        // The cascade algorithm resolves this when the File descriptor projects.
        assert!(
            result.emit_commands.is_empty(),
            "no emit commands needed — dep-blocking on file_id handles unblocking"
        );
    }

    #[test]
    fn test_file_slice_context_purges_when_owner_message_deleted() {
        let parsed = make_file_slice([1u8; 32]);
        let root_message = b64(&[9u8; 32]);
        let queries = queries_with_ctx(topo::projection::contract::ContextSnapshot {
            purge_message_event_id: Some(root_message.clone()),
            file_descriptors: vec![descriptor(&root_message, &b64(&[3u8; 32]), "key_1")],
            current_owner_event_id: Some(root_message.clone()),
            current_signer: Some(topo::projection::contract::CurrentSignerInfo {
                event_id: b64(&[3u8; 32]),
                semantic_type_code: EVENT_TYPE_FILE_SLICE,
            }),
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

        assert_context_purge(&result, &root_message);
    }

    #[test]
    fn test_file_slice_context_ready_when_owner_message_live() {
        let parsed = make_file_slice([1u8; 32]);
        let root_message = b64(&[9u8; 32]);
        let queries = queries_with_ctx(topo::projection::contract::ContextSnapshot {
            file_descriptors: vec![descriptor(&root_message, &b64(&[3u8; 32]), "key_1")],
            current_owner_event_id: Some(root_message),
            current_signer: Some(topo::projection::contract::CurrentSignerInfo {
                event_id: b64(&[3u8; 32]),
                semantic_type_code: EVENT_TYPE_FILE_SLICE,
            }),
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

        let ctx = expect_context_ready(result);
        assert!(ctx.purge_message_event_id.is_none());
    }

    // ── SPEC_FILE_AUTH_02: pass ──

    #[test]
    fn test_file_slice_valid() {
        let signer = [3u8; 32];
        let signer_b64 = b64(&signer);
        let owner_b64 = b64(&[9u8; 32]);
        let parsed = make_file_slice([1u8; 32]);
        let mut ctx = ctx_with_file_descriptors(vec![descriptor(&owner_b64, &signer_b64, "key_1")]);
        ctx.current_owner_event_id = Some(owner_b64);
        ctx.current_signer = Some(topo::projection::contract::CurrentSignerInfo {
            event_id: b64(&signer),
            semantic_type_code: EVENT_TYPE_FILE_SLICE,
        });

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "file_slices");
    }

    // ── SPEC_FILE_AUTH_02: break (signer mismatch) ──

    #[test]
    fn test_file_slice_rejects_signer_mismatch() {
        let different_signer_b64 = b64(&[99u8; 32]);
        let owner_b64 = b64(&[9u8; 32]);
        let parsed = make_file_slice([1u8; 32]);
        let mut ctx =
            ctx_with_file_descriptors(vec![descriptor(&owner_b64, &different_signer_b64, "key_1")]);
        ctx.current_owner_event_id = Some(owner_b64);
        ctx.current_signer = Some(topo::projection::contract::CurrentSignerInfo {
            event_id: b64(&[3u8; 32]),
            semantic_type_code: EVENT_TYPE_FILE_SLICE,
        });

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "does not match file descriptor signer");
    }

    #[test]
    fn test_file_slice_rejects_owner_mismatch() {
        let signer = [3u8; 32];
        let signer_b64 = b64(&signer);
        let parsed = make_file_slice([1u8; 32]);
        let mut ctx =
            ctx_with_file_descriptors(vec![descriptor(&b64(&[8u8; 32]), &signer_b64, "key_1")]);
        ctx.current_owner_event_id = Some(b64(&[9u8; 32]));
        ctx.current_signer = Some(topo::projection::contract::CurrentSignerInfo {
            event_id: b64(&signer),
            semantic_type_code: EVENT_TYPE_FILE_SLICE,
        });

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "owner_event_id");
    }

    #[test]
    fn test_file_slice_rejects_wrapper_key_mismatch() {
        let signer = [3u8; 32];
        let signer_b64 = b64(&signer);
        let owner_b64 = b64(&[9u8; 32]);
        let parsed = make_file_slice([1u8; 32]);
        let ctx = topo::projection::contract::ContextSnapshot {
            file_descriptors: vec![descriptor(&owner_b64, &signer_b64, "key_expected")],
            current_owner_event_id: Some(owner_b64),
            current_signer: Some(topo::projection::contract::CurrentSignerInfo {
                event_id: b64(&signer),
                semantic_type_code: EVENT_TYPE_FILE_SLICE,
            }),
            current_transport_key_event_id: Some("key_other".to_string()),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "wrapper key");
    }

    // ── CHK_FS_SLOT_CONFLICT: break ──

    #[test]
    fn test_file_slice_rejects_slot_conflict() {
        let signer = [3u8; 32];
        let signer_b64 = b64(&signer);
        let owner_b64 = b64(&[9u8; 32]);
        let parsed = make_file_slice([1u8; 32]);
        let ctx = topo::projection::contract::ContextSnapshot {
            file_descriptors: vec![descriptor(&owner_b64, &signer_b64, "key_1")],
            current_owner_event_id: Some(owner_b64),
            current_signer: Some(topo::projection::contract::CurrentSignerInfo {
                event_id: b64(&signer),
                semantic_type_code: EVENT_TYPE_FILE_SLICE,
            }),
            existing_file_slice: Some(("other_event".to_string(), "desc_1".to_string())),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "duplicate file_slice");
    }

    // ── CHK_FS_IDEMPOTENT: pass ──

    #[test]
    fn test_file_slice_idempotent_replay() {
        let signer = [3u8; 32];
        let signer_b64 = b64(&signer);
        let owner_b64 = b64(&[9u8; 32]);
        let parsed = make_file_slice([1u8; 32]);
        let ctx = topo::projection::contract::ContextSnapshot {
            file_descriptors: vec![descriptor(&owner_b64, &signer_b64, "key_1")],
            current_owner_event_id: Some(owner_b64),
            current_signer: Some(topo::projection::contract::CurrentSignerInfo {
                event_id: b64(&signer),
                semantic_type_code: EVENT_TYPE_FILE_SLICE,
            }),
            existing_file_slice: Some((EVENT_ID.to_string(), "desc_1".to_string())),
            ..Default::default()
        };

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert!(
            result.write_ops.is_empty(),
            "idempotent replay should produce no writes"
        );
    }
}
