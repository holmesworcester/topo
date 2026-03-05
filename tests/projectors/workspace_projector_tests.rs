//! Pure projector conformance tests for Workspace (type 8).
//!
//! TLA+ guards tested:
//!   SPEC_WS_ANCHOR_01 — InvWorkspaceAnchor (block + pass)
//!   SPEC_WS_ANCHOR_02 — InvForeignWorkspaceExcluded (reject)
//!   SPEC_WS_SINGLE_01 — InvSingleWorkspace (InsertOrIgnore idempotence)

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::event_modules::workspace::{project_pure, WorkspaceEvent};
    use topo::event_modules::ParsedEvent;

    const PEER: &str = "peer_alice";

    fn make_workspace(public_key: [u8; 32]) -> ParsedEvent {
        ParsedEvent::Workspace(WorkspaceEvent {
            created_at_ms: 1000,
            public_key,
            name: "test-ws".to_string(),
        })
    }

    // ── SPEC_WS_ANCHOR_01: pass ──

    #[test]
    fn test_workspace_valid_with_matching_anchor() {
        let ws_id = [1u8; 32];
        let ws_id_b64 = b64(&ws_id);
        let parsed = make_workspace([2u8; 32]);
        let ctx = ctx_with_anchor(&ws_id_b64);

        let result = project_pure(PEER, &ws_id_b64, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "workspaces");
        assert_no_commands(&result);
    }

    // ── SPEC_WS_ANCHOR_01: break ──

    #[test]
    fn test_workspace_blocks_without_trust_anchor() {
        let ws_id = [1u8; 32];
        let ws_id_b64 = b64(&ws_id);
        let parsed = make_workspace([2u8; 32]);
        let ctx = empty_ctx(); // no trust anchor

        let result = project_pure(PEER, &ws_id_b64, &parsed, &ctx);
        assert_block(&result);
    }

    // ── SPEC_WS_ANCHOR_02: break ──

    #[test]
    fn test_workspace_rejects_anchor_mismatch() {
        let ws_id = [1u8; 32];
        let ws_id_b64 = b64(&ws_id);
        let other_anchor = b64(&[99u8; 32]);
        let parsed = make_workspace([2u8; 32]);
        let ctx = ctx_with_anchor(&other_anchor);

        let result = project_pure(PEER, &ws_id_b64, &parsed, &ctx);
        assert_reject_contains(&result, "does not match accepted invite binding");
    }

    // ── SPEC_WS_SINGLE_01: pass (InsertOrIgnore ensures at-most-one) ──

    #[test]
    fn test_workspace_insert_or_ignore() {
        let ws_id = [1u8; 32];
        let ws_id_b64 = b64(&ws_id);
        let parsed = make_workspace([2u8; 32]);
        let ctx = ctx_with_anchor(&ws_id_b64);

        let result = project_pure(PEER, &ws_id_b64, &parsed, &ctx);
        assert_valid(&result);
        assert_eq!(result.write_ops.len(), 1);
        assert_writes_to_table(&result, "workspaces");
    }
}
