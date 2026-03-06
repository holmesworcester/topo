//! Shared test harness for pure projector conformance tests.
//!
//! Provides fixture builders for ParsedEvent variants and ContextSnapshot,
//! plus assertion helpers for ProjectorResult inspection.

#[cfg(test)]
pub mod fixtures {
    use topo::projection::contract::{
        BootstrapContextSnapshot, ContextSnapshot, EmitCommand, ProjectorResult, WriteOp,
    };
    use topo::projection::decision::ProjectionDecision;

    /// Default ContextSnapshot with all fields at their zero/empty/false defaults.
    pub fn empty_ctx() -> ContextSnapshot {
        ContextSnapshot::default()
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

    /// ContextSnapshot with recipient_removed flag set.
    pub fn ctx_with_recipient_removed() -> ContextSnapshot {
        ContextSnapshot {
            recipient_removed: true,
            ..Default::default()
        }
    }

    /// ContextSnapshot with file descriptors.
    pub fn ctx_with_file_descriptors(descriptors: Vec<(String, String)>) -> ContextSnapshot {
        ContextSnapshot {
            file_descriptors: descriptors,
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

    /// Assert that write_ops contain a Delete from the given table.
    pub fn assert_deletes_from_table(result: &ProjectorResult, table: &str) {
        assert!(
            result.write_ops.iter().any(|op| matches!(
                op, WriteOp::Delete { table: t, .. } if *t == table
            )),
            "expected Delete from table '{}', ops: {:?}",
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
}
