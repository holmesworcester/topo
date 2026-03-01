//! Pure projector conformance tests for FileSlice (type 25).
//!
//! TLA+ guards tested:
//!   SPEC_FILE_AUTH_01 — InvFileSliceAuth (guard-block on no descriptor)
//!   SPEC_FILE_AUTH_02 — InvFileSliceAuth (signer mismatch reject + valid)
//!   CHK_FS_SLOT_CONFLICT — slot uniqueness (conflict reject)
//!   CHK_FS_IDEMPOTENT — idempotent replay

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::file_slice::project_pure;
    use topo::event_modules::file_slice::FileSliceEvent;
    use topo::event_modules::ParsedEvent;
    use topo::projection::result::EmitCommand;

    const PEER: &str = "peer_alice";
    const EVENT_ID: &str = "fs_event_1";

    fn make_file_slice(file_id: [u8; 32], signed_by: [u8; 32]) -> ParsedEvent {
        ParsedEvent::FileSlice(FileSliceEvent {
            created_at_ms: 7000,
            file_id,
            slice_number: 0,
            ciphertext: vec![0u8; 262144],
            signed_by,
            signer_type: 5,
            signature: [0u8; 64],
        })
    }

    // ── SPEC_FILE_AUTH_01: break (no descriptor → guard block) ──

    #[test]
    fn test_file_slice_blocks_no_descriptor() {
        let parsed = make_file_slice([1u8; 32], [3u8; 32]);
        let ctx = empty_ctx(); // no file_descriptors

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_block(&result);
        assert!(
            result
                .emit_commands
                .iter()
                .any(|c| matches!(c, EmitCommand::RecordFileSliceGuardBlock { .. })),
            "should emit RecordFileSliceGuardBlock on guard-block"
        );
    }

    // ── SPEC_FILE_AUTH_02: pass ──

    #[test]
    fn test_file_slice_valid() {
        let signer = [3u8; 32];
        let signer_b64 = b64(&signer);
        let parsed = make_file_slice([1u8; 32], signer);
        let ctx = ctx_with_file_descriptors(vec![("desc_1".to_string(), signer_b64)]);

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "file_slices");
    }

    // ── SPEC_FILE_AUTH_02: break (signer mismatch) ──

    #[test]
    fn test_file_slice_rejects_signer_mismatch() {
        let signer = [3u8; 32];
        let different_signer_b64 = b64(&[99u8; 32]);
        let parsed = make_file_slice([1u8; 32], signer);
        let ctx = ctx_with_file_descriptors(vec![("desc_1".to_string(), different_signer_b64)]);

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "does not match attachment descriptor signer");
    }

    // ── CHK_FS_SLOT_CONFLICT: break ──

    #[test]
    fn test_file_slice_rejects_slot_conflict() {
        let signer = [3u8; 32];
        let signer_b64 = b64(&signer);
        let parsed = make_file_slice([1u8; 32], signer);
        let ctx = topo::projection::result::ContextSnapshot {
            file_descriptors: vec![("desc_1".to_string(), signer_b64)],
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
        let parsed = make_file_slice([1u8; 32], signer);
        let ctx = topo::projection::result::ContextSnapshot {
            file_descriptors: vec![("desc_1".to_string(), signer_b64)],
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
