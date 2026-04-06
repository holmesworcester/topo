//! Pure projector conformance tests for mostly simple projectors.
//!
//! Covers: User, Admin, KeySecret, File, BenchDep.

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::ParsedEvent;
    use topo::event_modules::EVENT_TYPE_FILE;
    use topo::projection::contract::EmitCommand;

    const PEER: &str = "peer_alice";
    const EVENT_ID: &str = "simple_event_1";

    fn unrelated_event() -> ParsedEvent {
        ParsedEvent::BenchDep(topo::event_modules::bench_dep::BenchDepEvent {
            created_at_ms: 42,
            dep_ids: vec![],
            payload: [0u8; 16],
        })
    }

    // ── User ──

    #[test]
    fn test_user_valid() {
        use topo::event_modules::user::{project_pure, UserEvent};
        let parsed = ParsedEvent::User(UserEvent {
            created_at_ms: 1000,
            public_key: [1u8; 32],
            username: "alice".to_string(),
        });
        let result = project_pure(PEER, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "users");
        assert_no_commands(&result);
    }

    #[test]
    fn test_user_valid_second_sample() {
        use topo::event_modules::user::{project_pure, UserEvent};
        let parsed = ParsedEvent::User(UserEvent {
            created_at_ms: 1001,
            public_key: [1u8; 32],
            username: "alice".to_string(),
        });
        let result = project_pure(PEER, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "users");
    }

    #[test]
    fn test_user_rejects_non_user_event() {
        use topo::event_modules::user::project_pure;
        let result = project_pure(PEER, EVENT_ID, &unrelated_event(), &empty_ctx());
        assert_reject(&result);
    }

    // ── Admin ──

    #[test]
    fn test_admin_valid() {
        use topo::event_modules::admin::{project_pure, AdminEvent};
        let parsed = ParsedEvent::Admin(AdminEvent {
            created_at_ms: 2000,
            public_key: [1u8; 32],
            user_event_id: [2u8; 32],
        });
        let result = project_pure(PEER, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "admins");
        assert_no_commands(&result);
    }

    #[test]
    fn test_admin_rejects_non_admin_event() {
        use topo::event_modules::admin::project_pure;
        let result = project_pure(PEER, EVENT_ID, &unrelated_event(), &empty_ctx());
        assert_reject(&result);
    }

    // ── KeySecret ──

    #[test]
    fn test_key_secret_valid() {
        use topo::event_modules::key_secret::{project_pure, KeySecretEvent};
        let parsed = ParsedEvent::KeySecret(KeySecretEvent {
            created_at_ms: 5000,
            key_bytes: [0xAB; 32],
        });
        let result = project_pure(PEER, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "key_secrets");
        assert_no_commands(&result);
    }

    #[test]
    fn test_key_secret_rejects_non_key_secret_event() {
        use topo::event_modules::key_secret::project_pure;
        let result = project_pure(PEER, EVENT_ID, &unrelated_event(), &empty_ctx());
        assert_reject(&result);
    }

    // ── File ──

    #[test]
    fn test_file_valid() {
        use topo::event_modules::file::{project_pure, FileEvent};
        let parsed = ParsedEvent::File(FileEvent {
            created_at_ms: 8000,
            message_id: [1u8; 32],
            file_id: [2u8; 32],
            blob_bytes: 1024,
            total_slices: 1,
            slice_bytes: 262144,
            root_hash: [3u8; 32],
            key_event_id: [4u8; 32],
            filename: "test.txt".to_string(),
            mime_type: "text/plain".to_string(),
        });
        let mut ctx = ctx_with_current_signer(EVENT_ID, EVENT_TYPE_FILE);
        ctx.current_owner_event_id = Some(b64(&[1u8; 32]));
        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "files");
        // File_slice unblocking is now handled by cascade_file_id_if_file
        // in cascade.rs via the synthetic file_id dependency blocker.
        assert!(
            result.emit_commands.is_empty(),
            "File projector should not emit commands (cascade handles file_slice unblocking)"
        );
    }

    #[test]
    fn test_file_skips_when_target_message_deleted() {
        use topo::event_modules::file::{project_pure, FileEvent};
        let message_id = [1u8; 32];
        let file_id = [2u8; 32];
        let parsed = ParsedEvent::File(FileEvent {
            created_at_ms: 8000,
            message_id,
            file_id,
            blob_bytes: 1024,
            total_slices: 1,
            slice_bytes: 262144,
            root_hash: [3u8; 32],
            key_event_id: [4u8; 32],
            filename: "test.txt".to_string(),
            mime_type: "text/plain".to_string(),
        });
        let mut ctx = ctx_with_target_message_deleted();
        ctx.current_signer = Some(topo::projection::contract::CurrentSignerInfo {
            event_id: EVENT_ID.to_string(),
            semantic_type_code: EVENT_TYPE_FILE,
        });
        ctx.current_owner_event_id = Some(b64(&message_id));
        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_no_write_to_table(&result, "files");
        assert_emits_command(&result, "HardPurgeMessageGraph", |cmd| {
            matches!(
                cmd,
                EmitCommand::HardPurgeMessageGraph { message_event_id }
                    if message_event_id == &b64(&message_id)
            )
        });
    }

    #[test]
    fn test_file_rejects_owner_mismatch() {
        use topo::event_modules::file::{project_pure, FileEvent};
        let parsed = ParsedEvent::File(FileEvent {
            created_at_ms: 8000,
            message_id: [1u8; 32],
            file_id: [2u8; 32],
            blob_bytes: 1024,
            total_slices: 1,
            slice_bytes: 262144,
            root_hash: [3u8; 32],
            key_event_id: [4u8; 32],
            filename: "test.txt".to_string(),
            mime_type: "text/plain".to_string(),
        });
        let mut ctx = ctx_with_current_signer(EVENT_ID, EVENT_TYPE_FILE);
        ctx.current_owner_event_id = Some(b64(&[9u8; 32]));

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_reject_contains(&result, "owner_event_id");
    }

    #[test]
    fn test_file_rejects_non_attachment_event() {
        use topo::event_modules::file::project_pure;
        let result = project_pure(PEER, EVENT_ID, &unrelated_event(), &empty_ctx());
        assert_reject(&result);
    }

    // ── BenchDep (no-op projector) ──

    #[test]
    fn test_bench_dep_noop() {
        use topo::event_modules::bench_dep::{project_pure, BenchDepEvent};
        let parsed = ParsedEvent::BenchDep(BenchDepEvent {
            created_at_ms: 9000,
            dep_ids: vec![],
            payload: [0u8; 16],
        });
        let result = project_pure(PEER, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert!(
            result.write_ops.is_empty(),
            "bench_dep should have no write_ops"
        );
        assert_no_commands(&result);
    }

    #[test]
    fn test_bench_dep_rejects_non_bench_dep_event() {
        use topo::event_modules::bench_dep::project_pure;
        let result = project_pure(
            PEER,
            EVENT_ID,
            &ParsedEvent::KeySecret(topo::event_modules::key_secret::KeySecretEvent {
                created_at_ms: 1,
                key_bytes: [9u8; 32],
            }),
            &empty_ctx(),
        );
        assert_reject(&result);
    }
}
