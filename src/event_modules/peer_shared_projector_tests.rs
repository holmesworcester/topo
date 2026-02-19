//! Pure projector conformance tests for PeerShared (types 16-17).
//!
//! TLA+ guards tested:
//!   SPEC_PEER_SHARED_TRUST_01 — InvPeerSharedTrustSource (valid insert)
//!   SPEC_PEER_SHARED_TRUST_02 — InvPeerSharedTrustMatchesCarried (correct fields)
//!   SPEC_BOOTSTRAP_CONSUMED_01 — InvBootstrapConsumedByPeerShared (SupersedeBootstrapTrust)
//!   SPEC_PENDING_CONSUMED_01 — InvPendingBootstrapTrustConsumedByPeerShared (same command)

#[cfg(test)]
mod tests {
    use crate::event_modules::peer_shared::project_pure;
    use crate::event_modules::peer_shared::{PeerSharedFirstEvent, PeerSharedOngoingEvent};
    use crate::event_modules::projector_test_harness::fixtures::*;
    use crate::event_modules::ParsedEvent;
    use crate::projection::result::{EmitCommand, SqlVal, WriteOp};

    const PEER: &str = "peer_alice";
    const EVENT_ID: &str = "ps_event_1";

    fn make_peer_shared_first(public_key: [u8; 32], user_event_id: [u8; 32]) -> ParsedEvent {
        ParsedEvent::PeerSharedFirst(PeerSharedFirstEvent {
            created_at_ms: 10000,
            public_key,
            user_event_id,
            device_name: "device-1".to_string(),
            signed_by: [3u8; 32],
            signer_type: 3,
            signature: [0u8; 64],
        })
    }

    fn make_peer_shared_ongoing(public_key: [u8; 32], user_event_id: [u8; 32]) -> ParsedEvent {
        ParsedEvent::PeerSharedOngoing(PeerSharedOngoingEvent {
            created_at_ms: 10001,
            public_key,
            user_event_id,
            device_name: "device-2".to_string(),
            signed_by: [3u8; 32],
            signer_type: 3,
            signature: [0u8; 64],
        })
    }

    // ── SPEC_PEER_SHARED_TRUST_01: pass ──

    #[test]
    fn test_peer_shared_writes_row() {
        let parsed = make_peer_shared_first([5u8; 32], [6u8; 32]);
        let ctx = empty_ctx();

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "peers_shared");
    }

    // ── SPEC_PEER_SHARED_TRUST_02: pass (correct column values) ──

    #[test]
    fn test_peer_shared_writes_correct_fields() {
        let pk = [5u8; 32];
        let user_eid = [6u8; 32];
        let parsed = make_peer_shared_first(pk, user_eid);
        let ctx = empty_ctx();

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);

        let insert = result.write_ops.iter().find(|op| {
            matches!(op, WriteOp::InsertOrIgnore { table: "peers_shared", .. })
        });
        assert!(insert.is_some(), "expected InsertOrIgnore to peers_shared");

        if let Some(WriteOp::InsertOrIgnore { columns, values, .. }) = insert {
            // public_key column should contain our key
            let pk_idx = columns.iter().position(|c| *c == "public_key").unwrap();
            assert_eq!(values[pk_idx], SqlVal::Blob(pk.to_vec()));
            // user_event_id column should be base64 of our user event
            let ue_idx = columns.iter().position(|c| *c == "user_event_id").unwrap();
            assert_eq!(values[ue_idx], SqlVal::Text(b64(&user_eid)));
        }
    }

    // ── SPEC_BOOTSTRAP_CONSUMED_01 + SPEC_PENDING_CONSUMED_01: pass ──

    #[test]
    fn test_peer_shared_emits_supersede() {
        let pk = [5u8; 32];
        let parsed = make_peer_shared_first(pk, [6u8; 32]);
        let ctx = empty_ctx();

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_emits_command(&result, "SupersedeBootstrapTrust", |c| match c {
            EmitCommand::SupersedeBootstrapTrust {
                peer_shared_public_key,
            } => *peer_shared_public_key == pk,
            _ => false,
        });
    }

    // ── Both variants emit the same command ──

    #[test]
    fn test_peer_shared_ongoing_also_emits_supersede() {
        let pk = [5u8; 32];
        let parsed = make_peer_shared_ongoing(pk, [6u8; 32]);
        let ctx = empty_ctx();

        let result = project_pure(PEER, EVENT_ID, &parsed, &ctx);
        assert_valid(&result);
        assert_emits_command(&result, "SupersedeBootstrapTrust", |c| {
            matches!(c, EmitCommand::SupersedeBootstrapTrust { .. })
        });
    }
}
