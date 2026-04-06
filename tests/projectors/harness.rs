//! Shared test harness for pure projector conformance tests.
//!
//! Provides fixture builders for ParsedEvent variants and ContextSnapshot,
//! plus assertion helpers for ProjectorResult inspection.

#[cfg(test)]
pub mod fixtures {
    use topo::event_modules::{
        AdminEvent, DeviceInviteEvent, FileEvent, FileSliceEvent, InviteAcceptedEvent,
        KeySharedEvent, MessageDeletionEvent, MessageEvent, PeerSharedEvent, ReactionEvent,
        UserInviteEvent, WorkspaceEvent,
    };
    use topo::projection::contract::{
        BootstrapContextSnapshot, ContextSnapshot, CurrentSignerInfo, EmitCommand,
        FileDescriptorInfo, ProjectorResult, WriteOp,
    };
    use topo::projection::decision::ProjectionDecision;
    use topo::projection::queries::{
        ContextLoadResult, DepLoadResult, ProjectionFrameContext, ProjectionQueries,
    };

    #[derive(Clone)]
    pub struct FixtureProjectionQueries {
        ctx: ContextSnapshot,
    }

    impl FixtureProjectionQueries {
        pub fn new(ctx: ContextSnapshot) -> Self {
            Self { ctx }
        }
    }

    impl ProjectionQueries for FixtureProjectionQueries {
        fn load_dep_result(
            &self,
            _recorded_by: &str,
            _parsed: &topo::event_modules::ParsedEvent,
            _field_name: &str,
            _dep_id: &[u8; 32],
        ) -> Result<DepLoadResult, Box<dyn std::error::Error>> {
            Ok(DepLoadResult::ready(None))
        }

        fn load_key_secret_bytes(
            &self,
            _recorded_by: &str,
            _key_event_id: &[u8; 32],
        ) -> Result<Option<[u8; 32]>, Box<dyn std::error::Error>> {
            Ok(None)
        }

        fn message_is_deleted(
            &self,
            _recorded_by: &str,
            _message_id_b64: &str,
        ) -> Result<bool, Box<dyn std::error::Error>> {
            Ok(false)
        }

        fn load_workspace_context(
            &self,
            _frame: &ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _workspace: &WorkspaceEvent,
        ) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
            Ok(self.ctx.clone())
        }

        fn load_admin_context(
            &self,
            _frame: &ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _admin: &AdminEvent,
        ) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
            Ok(self.ctx.clone())
        }

        fn load_peer_shared_context(
            &self,
            _frame: &ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _peer_shared: &PeerSharedEvent,
        ) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
            Ok(self.ctx.clone())
        }

        fn load_user_invite_context(
            &self,
            _frame: &ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _user_invite: &UserInviteEvent,
        ) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
            Ok(self.ctx.clone())
        }

        fn load_device_invite_context(
            &self,
            _frame: &ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _device_invite: &DeviceInviteEvent,
        ) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
            Ok(self.ctx.clone())
        }

        fn load_message_context(
            &self,
            _frame: &ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _message: &MessageEvent,
        ) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
            Ok(self.ctx.clone())
        }

        fn load_message_deletion_context(
            &self,
            _frame: &ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _message_deletion: &MessageDeletionEvent,
        ) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
            Ok(self.ctx.clone())
        }

        fn load_reaction_context(
            &self,
            _frame: &ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _reaction: &ReactionEvent,
        ) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
            Ok(self.ctx.clone())
        }

        fn load_file_context(
            &self,
            _frame: &ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _file: &FileEvent,
        ) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
            Ok(self.ctx.clone())
        }

        fn load_file_slice_context(
            &self,
            _frame: &ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _file_slice: &FileSliceEvent,
        ) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
            Ok(self.ctx.clone())
        }

        fn load_invite_accepted_context(
            &self,
            _frame: &ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _invite_accepted: &InviteAcceptedEvent,
        ) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
            Ok(self.ctx.clone())
        }

        fn load_key_shared_context(
            &self,
            _frame: &ProjectionFrameContext,
            _recorded_by: &str,
            _event_id_b64: &str,
            _key_shared: &KeySharedEvent,
        ) -> Result<ContextSnapshot, Box<dyn std::error::Error>> {
            Ok(self.ctx.clone())
        }
    }

    /// Default ContextSnapshot with all fields at their zero/empty/false defaults.
    pub fn empty_ctx() -> ContextSnapshot {
        ContextSnapshot::default()
    }

    pub fn queries_with_ctx(ctx: ContextSnapshot) -> FixtureProjectionQueries {
        FixtureProjectionQueries::new(ctx)
    }

    /// ContextSnapshot with trust anchor set to the given workspace_id base64.
    pub fn ctx_with_anchor(workspace_id_b64: &str) -> ContextSnapshot {
        ContextSnapshot {
            accepted_workspace_id: Some(workspace_id_b64.to_string()),
            ..Default::default()
        }
    }

    /// ContextSnapshot with signer-user mismatch reason set.
    pub fn ctx_with_signer_mismatch(reason: &str) -> ContextSnapshot {
        ContextSnapshot {
            signer_user_mismatch_reason: Some(reason.to_string()),
            ..Default::default()
        }
    }

    /// ContextSnapshot for message deletion with target message author.
    pub fn ctx_with_target_author(author_b64: &str) -> ContextSnapshot {
        ContextSnapshot {
            target_message_author: Some(author_b64.to_string()),
            ..Default::default()
        }
    }

    /// ContextSnapshot with file descriptors.
    pub fn ctx_with_file_descriptors(descriptors: Vec<FileDescriptorInfo>) -> ContextSnapshot {
        ContextSnapshot {
            file_descriptors: descriptors,
            ..Default::default()
        }
    }

    /// ContextSnapshot with target message deletion state set.
    pub fn ctx_with_target_message_deleted() -> ContextSnapshot {
        ContextSnapshot {
            target_message_deleted: true,
            ..Default::default()
        }
    }

    /// ContextSnapshot with an explicit current signer envelope.
    pub fn ctx_with_current_signer(
        signer_event_id_b64: &str,
        semantic_type_code: u8,
    ) -> ContextSnapshot {
        ContextSnapshot {
            current_signer: Some(CurrentSignerInfo {
                event_id: signer_event_id_b64.to_string(),
                semantic_type_code,
            }),
            ..Default::default()
        }
    }

    /// ContextSnapshot with bootstrap context and is_local_create flag.
    pub fn ctx_with_bootstrap(workspace_id: &str, is_local: bool) -> ContextSnapshot {
        ContextSnapshot {
            bootstrap_context: Some(BootstrapContextSnapshot {
                workspace_id: workspace_id.to_string(),
                bootstrap_addrs: vec!["127.0.0.1:9000".to_string()],
                bootstrap_spki_fingerprint: [0xAA; 32],
            }),
            is_local_create: is_local,
            ..Default::default()
        }
    }

    /// Base64-encode a 32-byte ID (matches crypto::event_id_to_base64).
    pub fn b64(id: &[u8; 32]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(id)
    }

    // ── Assertion helpers ──

    pub fn assert_valid(result: &ProjectorResult) {
        assert!(
            matches!(result.decision, ProjectionDecision::Valid),
            "expected Valid, got {:?}",
            result.decision
        );
    }

    pub fn assert_block(result: &ProjectorResult) {
        assert!(
            matches!(result.decision, ProjectionDecision::Block { .. }),
            "expected Block, got {:?}",
            result.decision
        );
    }

    pub fn assert_reject(result: &ProjectorResult) {
        assert!(
            matches!(result.decision, ProjectionDecision::Reject { .. }),
            "expected Reject, got {:?}",
            result.decision
        );
    }

    pub fn assert_reject_contains(result: &ProjectorResult, substring: &str) {
        match &result.decision {
            ProjectionDecision::Reject { reason } => {
                assert!(
                    reason.contains(substring),
                    "expected rejection containing '{}', got '{}'",
                    substring,
                    reason
                );
            }
            other => panic!("expected Reject, got {:?}", other),
        }
    }

    /// Assert that write_ops contain an InsertOrIgnore to the given table.
    pub fn assert_writes_to_table(result: &ProjectorResult, table: &str) {
        assert!(
            result.write_ops.iter().any(|op| matches!(
                op, WriteOp::InsertOrIgnore { table: t, .. } if *t == table
            )),
            "expected InsertOrIgnore to table '{}', ops: {:?}",
            table,
            result.write_ops
        );
    }

    /// Assert that no write_ops target the given table.
    pub fn assert_no_write_to_table(result: &ProjectorResult, table: &str) {
        assert!(
            !result.write_ops.iter().any(|op| match op {
                WriteOp::InsertOrIgnore { table: t, .. } => *t == table,
                WriteOp::Delete { table: t, .. } => *t == table,
            }),
            "expected no write to table '{}', but found one",
            table
        );
    }

    /// Assert that emit_commands contains a specific command variant.
    pub fn assert_emits_command<F: Fn(&EmitCommand) -> bool>(
        result: &ProjectorResult,
        name: &str,
        predicate: F,
    ) {
        assert!(
            result.emit_commands.iter().any(&predicate),
            "expected emit command '{}', commands: {:?}",
            name,
            result.emit_commands
        );
    }

    /// Assert that emit_commands does not contain a command matching predicate.
    pub fn assert_no_command<F: Fn(&EmitCommand) -> bool>(result: &ProjectorResult, predicate: F) {
        assert!(
            !result.emit_commands.iter().any(&predicate),
            "expected no matching command, got: {:?}",
            result.emit_commands
        );
    }

    /// Assert that emit_commands is empty.
    pub fn assert_no_commands(result: &ProjectorResult) {
        assert!(
            result.emit_commands.is_empty(),
            "expected no emit commands, got: {:?}",
            result.emit_commands
        );
    }

    pub fn assert_context_block(result: &ContextLoadResult) {
        assert!(
            matches!(result, ContextLoadResult::Block { .. }),
            "expected ContextLoadResult::Block, got {:?}",
            result
        );
    }

    pub fn assert_context_reject_contains(result: &ContextLoadResult, substring: &str) {
        match result {
            ContextLoadResult::Reject { reason } => {
                assert!(
                    reason.contains(substring),
                    "expected context rejection containing '{}', got '{}'",
                    substring,
                    reason
                );
            }
            other => panic!("expected ContextLoadResult::Reject, got {:?}", other),
        }
    }

    pub fn expect_context_ready(result: ContextLoadResult) -> ContextSnapshot {
        match result {
            ContextLoadResult::Ready(ctx) => ctx,
            other => panic!("expected ContextLoadResult::Ready, got {:?}", other),
        }
    }
}
