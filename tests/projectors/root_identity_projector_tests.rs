//! Pure projector conformance tests for local/root identity families.
//!
//! Covers: Tenant, InviteSecret, PeerSecret, EndpointSecret, EndpointShared.

#[cfg(test)]
mod tests {
    use crate::harness::fixtures::*;
    use topo::crypto::event_id_to_base64;
    use topo::event_modules::endpoint_secret::{
        endpoint_id_from_private_key_bytes, project_pure as project_endpoint_secret,
        EndpointSecretEvent,
    };
    use topo::event_modules::endpoint_shared::{
        deterministic_endpoint_shared_event, endpoint_id_from_public_key_bytes,
        project_pure as project_endpoint_shared, EndpointSharedEvent,
    };
    use topo::event_modules::invite_secret::{
        project_pure as project_invite_secret, InviteSecretEvent,
    };
    use topo::event_modules::peer_secret::{project_pure as project_peer_secret, PeerSecretEvent};
    use topo::event_modules::tenant::{project_pure as project_tenant, TenantEvent};
    use topo::event_modules::ParsedEvent;
    use topo::projection::projector::{EmitCommand, SqlVal, WriteOp};
    use topo::shared::contracts::transport_identity_contract::TransportIdentitySpec;

    const EVENT_ID: &str = "root_identity_event";

    fn unrelated_event() -> ParsedEvent {
        ParsedEvent::BenchDep(topo::event_modules::bench_dep::BenchDepEvent {
            created_at_ms: 42,
            dep_ids: vec![],
            payload: [0u8; 16],
        })
    }

    fn insert_op<'a>(
        result: &'a topo::projection::projector::ProjectorResult,
        table: &str,
    ) -> &'a WriteOp {
        result
            .write_ops
            .iter()
            .find(|op| matches!(op, WriteOp::InsertOrIgnore { table: t, .. } if *t == table))
            .unwrap_or_else(|| {
                panic!(
                    "expected InsertOrIgnore to {table}, got {:?}",
                    result.write_ops
                )
            })
    }

    #[test]
    fn test_tenant_valid_writes_tenant_row() {
        let public_key = [0x11u8; 32];
        let parsed = ParsedEvent::Tenant(TenantEvent {
            created_at_ms: 1000,
            public_key,
        });
        let recorded_by = "tenant-recorder";

        let result = project_tenant(recorded_by, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "tenants");
        assert_no_commands(&result);

        let WriteOp::InsertOrIgnore {
            columns, values, ..
        } = insert_op(&result, "tenants")
        else {
            unreachable!()
        };
        let peer_id_idx = columns.iter().position(|c| *c == "peer_id").unwrap();
        let recorded_by_idx = columns.iter().position(|c| *c == "recorded_by").unwrap();
        assert_eq!(
            values[peer_id_idx],
            SqlVal::Text(hex::encode(
                topo::crypto::spki_fingerprint_from_ed25519_pubkey(&public_key)
            ))
        );
        assert_eq!(
            values[recorded_by_idx],
            SqlVal::Text(recorded_by.to_string())
        );
    }

    #[test]
    fn test_tenant_rejects_non_tenant_event() {
        let result = project_tenant(
            "tenant-recorder",
            EVENT_ID,
            &unrelated_event(),
            &empty_ctx(),
        );
        assert_reject(&result);
    }

    #[test]
    fn test_invite_secret_valid_writes_invite_secret_row() {
        let invite_event_id = [0x21u8; 32];
        let private_key_bytes = [0x22u8; 32];
        let parsed = ParsedEvent::InviteSecret(InviteSecretEvent {
            created_at_ms: 2000,
            invite_event_id,
            private_key_bytes,
        });

        let result = project_invite_secret("tenant-a", EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "invite_secrets");
        assert_no_commands(&result);

        let WriteOp::InsertOrIgnore {
            columns, values, ..
        } = insert_op(&result, "invite_secrets")
        else {
            unreachable!()
        };
        let invite_idx = columns
            .iter()
            .position(|c| *c == "invite_event_id")
            .unwrap();
        assert_eq!(
            values[invite_idx],
            SqlVal::Text(event_id_to_base64(&invite_event_id))
        );
    }

    #[test]
    fn test_invite_secret_rejects_non_invite_secret_event() {
        let result = project_invite_secret("tenant-a", EVENT_ID, &unrelated_event(), &empty_ctx());
        assert_reject(&result);
    }

    #[test]
    fn test_peer_secret_valid_emits_transport_identity_materialization() {
        let signer_event_id = [0x31u8; 32];
        let parsed = ParsedEvent::PeerSecret(PeerSecretEvent {
            created_at_ms: 3000,
            signer_event_id,
            private_key_bytes: [0x32u8; 32],
        });
        let recorded_by = "tenant-peer";

        let result = project_peer_secret(recorded_by, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "peer_secrets");
        assert_emits_command(&result, "MaterializeTransportIdentity", |cmd| {
            matches!(
                cmd,
                EmitCommand::MaterializeTransportIdentity {
                    spec: TransportIdentitySpec::InstallPeerSharedIdentityFromSigner {
                        recorded_by: actual_recorded_by,
                        signer_event_id: actual_signer_event_id,
                    }
                } if actual_recorded_by == recorded_by && actual_signer_event_id == &signer_event_id
            )
        });
    }

    #[test]
    fn test_peer_secret_rejects_non_peer_secret_event() {
        let result = project_peer_secret("tenant-peer", EVENT_ID, &unrelated_event(), &empty_ctx());
        assert_reject(&result);
    }

    #[test]
    fn test_endpoint_secret_valid_requires_matching_endpoint_id() {
        let private_key_bytes = [0x41u8; 32];
        let parsed = ParsedEvent::EndpointSecret(EndpointSecretEvent {
            created_at_ms: 4000,
            private_key_bytes,
        });
        let recorded_by = endpoint_id_from_private_key_bytes(&private_key_bytes);

        let result = project_endpoint_secret(&recorded_by, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "endpoint_secrets");
        assert_no_commands(&result);

        let WriteOp::InsertOrIgnore {
            columns, values, ..
        } = insert_op(&result, "endpoint_secrets")
        else {
            unreachable!()
        };
        let endpoint_idx = columns.iter().position(|c| *c == "endpoint_id").unwrap();
        assert_eq!(values[endpoint_idx], SqlVal::Text(recorded_by));
    }

    #[test]
    fn test_endpoint_secret_rejects_recorded_by_mismatch() {
        let private_key_bytes = [0x42u8; 32];
        let parsed = ParsedEvent::EndpointSecret(EndpointSecretEvent {
            created_at_ms: 4001,
            private_key_bytes,
        });

        let result = project_endpoint_secret("wrong-endpoint", EVENT_ID, &parsed, &empty_ctx());
        assert_reject_contains(&result, "recorded_by must equal endpoint_id");
    }

    #[test]
    fn test_endpoint_secret_rejects_non_endpoint_secret_event() {
        let result =
            project_endpoint_secret("endpoint", EVENT_ID, &unrelated_event(), &empty_ctx());
        assert_reject(&result);
    }

    #[test]
    fn test_endpoint_shared_valid_requires_matching_endpoint_id_and_signature() {
        let ParsedEvent::EndpointShared(event) = deterministic_endpoint_shared_event([0x51u8; 32])
        else {
            unreachable!()
        };
        let recorded_by = endpoint_id_from_public_key_bytes(&event.public_key);
        let parsed = ParsedEvent::EndpointShared(event.clone());

        let result = project_endpoint_shared(&recorded_by, EVENT_ID, &parsed, &empty_ctx());
        assert_valid(&result);
        assert_writes_to_table(&result, "endpoints_shared");
        assert_no_commands(&result);

        let WriteOp::InsertOrIgnore {
            columns, values, ..
        } = insert_op(&result, "endpoints_shared")
        else {
            unreachable!()
        };
        let public_key_idx = columns.iter().position(|c| *c == "public_key").unwrap();
        assert_eq!(
            values[public_key_idx],
            SqlVal::Blob(event.public_key.to_vec())
        );
    }

    #[test]
    fn test_endpoint_shared_rejects_recorded_by_mismatch() {
        let ParsedEvent::EndpointShared(event) = deterministic_endpoint_shared_event([0x52u8; 32])
        else {
            unreachable!()
        };
        let parsed = ParsedEvent::EndpointShared(event);

        let result = project_endpoint_shared("wrong-endpoint", EVENT_ID, &parsed, &empty_ctx());
        assert_reject_contains(&result, "recorded_by must equal endpoint_id");
    }

    #[test]
    fn test_endpoint_shared_rejects_invalid_self_signature() {
        let ParsedEvent::EndpointShared(mut event) =
            deterministic_endpoint_shared_event([0x53u8; 32])
        else {
            unreachable!()
        };
        event.signature[0] ^= 0xFF;
        let recorded_by = endpoint_id_from_public_key_bytes(&event.public_key);
        let parsed = ParsedEvent::EndpointShared(EndpointSharedEvent { ..event });

        let result = project_endpoint_shared(&recorded_by, EVENT_ID, &parsed, &empty_ctx());
        assert_reject_contains(&result, "self-signature verification failed");
    }

    #[test]
    fn test_endpoint_shared_rejects_non_endpoint_shared_event() {
        let result =
            project_endpoint_shared("endpoint", EVENT_ID, &unrelated_event(), &empty_ctx());
        assert_reject(&result);
    }
}
