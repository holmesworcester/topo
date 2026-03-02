//! Pure projector conformance tests for simple projectors that do straight inserts
//! with no guards beyond type matching.
//!
//! Covers: User, Admin, UserRemoved, PeerRemoved, SecretKey,
//!         MessageAttachment, BenchDep.

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::ParsedEvent;
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

    // ── User (Boot) ──

    #[test]
    fn test_user_boot_valid() {
        use topo::event_modules::user::{project_pure, UserBootEvent};
        let parsed = ParsedEvent::UserBoot(UserBootEvent {
            created_at_ms: 1000,
            public_key: [1u8; 32],
            username: "alice".to_string(),
            signed_by: [2u8; 32],
            signer_type: 2,
            signature: [0u8; 64],
        });
        let result = project_pure(PEER, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "users");
        assert_no_commands(&result);
    }

    #[test]
    fn test_user_ongoing_valid() {
        use topo::event_modules::user::{project_pure, UserOngoingEvent};
        let parsed = ParsedEvent::UserOngoing(UserOngoingEvent {
            created_at_ms: 1001,
            public_key: [1u8; 32],
            username: "alice".to_string(),
            signed_by: [2u8; 32],
            signer_type: 2,
            signature: [0u8; 64],
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

    // ── Admin (Boot) ──

    #[test]
    fn test_admin_boot_valid() {
        use topo::event_modules::admin::{project_pure, AdminBootEvent};
        let parsed = ParsedEvent::AdminBoot(AdminBootEvent {
            created_at_ms: 2000,
            public_key: [1u8; 32],
            user_event_id: [2u8; 32],
            signed_by: [3u8; 32],
            signer_type: 1,
            signature: [0u8; 64],
        });
        let result = project_pure(PEER, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "admins");
        assert_no_commands(&result);
    }

    #[test]
    fn test_admin_ongoing_valid() {
        use topo::event_modules::admin::{project_pure, AdminOngoingEvent};
        let parsed = ParsedEvent::AdminOngoing(AdminOngoingEvent {
            created_at_ms: 2001,
            public_key: [1u8; 32],
            admin_boot_event_id: [2u8; 32],
            signed_by: [3u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        });
        let result = project_pure(PEER, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "admins");
    }

    #[test]
    fn test_admin_rejects_non_admin_event() {
        use topo::event_modules::admin::project_pure;
        let result = project_pure(PEER, EVENT_ID, &unrelated_event(), &empty_ctx());
        assert_reject(&result);
    }

    // ── UserRemoved ──

    #[test]
    fn test_user_removed_writes_row() {
        use topo::event_modules::user_removed::{project_pure, UserRemovedEvent};
        let parsed = ParsedEvent::UserRemoved(UserRemovedEvent {
            created_at_ms: 3000,
            target_event_id: [1u8; 32],
            signed_by: [2u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        });
        let result = project_pure(PEER, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "removed_entities");
        assert_no_commands(&result);
    }

    // ── PeerRemoved ──

    #[test]
    fn test_peer_removed_writes_row() {
        use topo::event_modules::peer_removed::{project_pure, PeerRemovedEvent};
        let parsed = ParsedEvent::PeerRemoved(PeerRemovedEvent {
            created_at_ms: 4000,
            target_event_id: [1u8; 32],
            signed_by: [2u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        });
        let result = project_pure(PEER, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "removed_entities");
        assert_no_commands(&result);
    }

    // ── SecretKey ──

    #[test]
    fn test_secret_key_valid() {
        use topo::event_modules::secret_key::{project_pure, SecretKeyEvent};
        let parsed = ParsedEvent::SecretKey(SecretKeyEvent {
            created_at_ms: 5000,
            key_bytes: [0xAB; 32],
        });
        let result = project_pure(PEER, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "secret_keys");
        assert_no_commands(&result);
    }

    #[test]
    fn test_secret_key_rejects_non_secret_key_event() {
        use topo::event_modules::secret_key::project_pure;
        let result = project_pure(PEER, EVENT_ID, &unrelated_event(), &empty_ctx());
        assert_reject(&result);
    }

    // ── MessageAttachment ──

    #[test]
    fn test_message_attachment_valid() {
        use topo::event_modules::message_attachment::{project_pure, MessageAttachmentEvent};
        let parsed = ParsedEvent::MessageAttachment(MessageAttachmentEvent {
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
            signed_by: [5u8; 32],
            signer_type: 5,
            signature: [0u8; 64],
        });
        let result = project_pure(PEER, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "message_attachments");
        assert_emits_command(&result, "RetryFileSliceGuards", |c| {
            matches!(c, EmitCommand::RetryFileSliceGuards { .. })
        });
    }

    #[test]
    fn test_message_attachment_rejects_non_attachment_event() {
        use topo::event_modules::message_attachment::project_pure;
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
            &ParsedEvent::SecretKey(topo::event_modules::secret_key::SecretKeyEvent {
                created_at_ms: 1,
                key_bytes: [9u8; 32],
            }),
            &empty_ctx(),
        );
        assert_reject(&result);
    }
}
