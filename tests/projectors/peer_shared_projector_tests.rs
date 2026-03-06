//! Pure projector conformance tests for PeerShared (type 16).
//!
//! TLA+ guards tested:
//!   SPEC_PEER_SHARED_TRUST_01 — InvPeerSharedTrustSource (valid insert)
//!   SPEC_PEER_SHARED_TRUST_02 — InvPeerSharedTrustMatchesCarried (correct fields)
//!   SPEC_BOOTSTRAP_CONSUMED_01 — InvBootstrapConsumedByPeerShared (write-time delete)
//!   SPEC_PENDING_CONSUMED_01 — InvPendingBootstrapTrustConsumedByPeerShared (write-time delete)

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::crypto::spki_fingerprint_from_ed25519_pubkey;
    use topo::event_modules::peer_shared::project_pure;
    use topo::event_modules::peer_shared::PeerSharedEvent;
    use topo::event_modules::ParsedEvent;
    use topo::projection::contract::{SqlVal, WriteOp};

    const PEER: &str = "peer_alice";

    fn make_peer_shared(public_key: [u8; 32], user_event_id: [u8; 32]) -> ParsedEvent {
        ParsedEvent::PeerShared(PeerSharedEvent {
            created_at_ms: 10000,
            public_key,
            user_event_id,
            device_name: "device-1".to_string(),
            signed_by: [3u8; 32],
            signer_type: 3,
            signature: [0u8; 64],
        })
    }

    // ── SPEC_PEER_SHARED_TRUST_01: pass ──

    #[test]
    fn test_peer_shared_writes_row() {
        let parsed = make_peer_shared([5u8; 32], [6u8; 32]);
        let ctx = empty_ctx();
        let event_id = b64(&[21u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_writes_to_table(&result, "peers_shared");
    }

    // ── SPEC_PEER_SHARED_TRUST_02: pass (correct column values) ──

    #[test]
    fn test_peer_shared_writes_correct_fields() {
        let pk = [5u8; 32];
        let user_eid = [6u8; 32];
        let parsed = make_peer_shared(pk, user_eid);
        let ctx = empty_ctx();
        let event_id = b64(&[22u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);

        let insert = result.write_ops.iter().find(|op| {
            matches!(
                op,
                WriteOp::InsertOrIgnore {
                    table: "peers_shared",
                    ..
                }
            )
        });
        assert!(insert.is_some(), "expected InsertOrIgnore to peers_shared");

        if let Some(WriteOp::InsertOrIgnore {
            columns, values, ..
        }) = insert
        {
            // public_key column should contain our key
            let pk_idx = columns.iter().position(|c| *c == "public_key").unwrap();
            assert_eq!(values[pk_idx], SqlVal::Blob(pk.to_vec()));
            // transport_fingerprint is deterministic from public_key
            let fp_idx = columns
                .iter()
                .position(|c| *c == "transport_fingerprint")
                .unwrap();
            assert_eq!(
                values[fp_idx],
                SqlVal::Blob(spki_fingerprint_from_ed25519_pubkey(&pk).to_vec())
            );
            // user_event_id column should be base64 of our user event
            let ue_idx = columns.iter().position(|c| *c == "user_event_id").unwrap();
            assert_eq!(values[ue_idx], SqlVal::Text(b64(&user_eid)));
        }
    }

    // ── SPEC_BOOTSTRAP_CONSUMED_01 + SPEC_PENDING_CONSUMED_01: pass ──

    #[test]
    fn test_peer_shared_consumes_bootstrap_trust() {
        let pk = [5u8; 32];
        let parsed = make_peer_shared(pk, [6u8; 32]);
        let ctx = empty_ctx();
        let event_id = b64(&[23u8; 32]);

        let result = project_pure(PEER, &event_id, &parsed, &ctx);
        assert_valid(&result);
        assert_deletes_from_table(&result, "pending_invite_bootstrap_trust");
        assert_deletes_from_table(&result, "invite_bootstrap_trust");
    }

    #[test]
    fn test_peer_shared_rejects_non_peer_shared_event() {
        let parsed = ParsedEvent::KeySecret(topo::event_modules::key_secret::KeySecretEvent {
            created_at_ms: 1,
            key_bytes: [1u8; 32],
        });
        let event_id = b64(&[24u8; 32]);
        let result = project_pure(PEER, &event_id, &parsed, &empty_ctx());
        assert_reject(&result);
    }

    #[test]
    fn test_peer_shared_consumption_deletes_are_scoped_to_recorded_by() {
        let recorded_by = "tenant_b";
        let pk = [9u8; 32];
        let transport_fingerprint = spki_fingerprint_from_ed25519_pubkey(&pk);
        let parsed = make_peer_shared(pk, [8u8; 32]);
        let event_id = b64(&[25u8; 32]);

        let result = project_pure(recorded_by, &event_id, &parsed, &empty_ctx());
        assert_valid(&result);

        for table in ["pending_invite_bootstrap_trust", "invite_bootstrap_trust"] {
            let delete = result
                .write_ops
                .iter()
                .find(|op| matches!(op, WriteOp::Delete { table: t, .. } if *t == table));
            let Some(WriteOp::Delete { where_clause, .. }) = delete else {
                panic!("expected delete from {table}, got {:?}", result.write_ops);
            };
            assert!(
                where_clause.contains(&("recorded_by", SqlVal::Text(recorded_by.to_string()))),
                "delete for {table} must be tenant-scoped: {:?}",
                where_clause
            );

            let expected_fp_column = if table == "pending_invite_bootstrap_trust" {
                "expected_bootstrap_spki_fingerprint"
            } else {
                "bootstrap_spki_fingerprint"
            };
            assert!(
                where_clause.contains(&(
                    expected_fp_column,
                    SqlVal::Blob(transport_fingerprint.to_vec())
                )),
                "delete for {table} must match the carried transport fingerprint: {:?}",
                where_clause
            );
        }
    }
}
