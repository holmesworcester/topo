//! Contract tests: verify exact intents emitted by the adapter and projector.

use topo::contracts::transport_identity_contract::{
    TransportIdentityAdapter, TransportIdentityError, TransportIdentityIntent,
};
use topo::transport::identity_adapter::ConcreteTransportIdentityAdapter;

use super::fake_adapter::FakeTransportIdentityAdapter;

fn setup_db() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    topo::db::schema::create_tables(&conn).unwrap();
    conn
}

// --- Concrete adapter tests ---

#[test]
fn concrete_adapter_install_bootstrap_from_invite_key_roundtrip() {
    let conn = setup_db();
    let adapter = ConcreteTransportIdentityAdapter;
    let key_bytes = [7u8; 32];

    let peer_id = adapter
        .apply_intent(
            &conn,
            TransportIdentityIntent::InstallBootstrapIdentityFromInviteKey {
                invite_private_key: key_bytes,
            },
        )
        .unwrap();

    // Verify deterministic: same key -> same peer_id.
    let peer_id2 = adapter
        .apply_intent(
            &conn,
            TransportIdentityIntent::InstallBootstrapIdentityFromInviteKey {
                invite_private_key: key_bytes,
            },
        )
        .unwrap();
    assert_eq!(peer_id, peer_id2);
    assert_eq!(peer_id.len(), 64, "peer_id should be 32-byte hex");
}

#[test]
fn concrete_adapter_install_peer_shared_from_signer() {
    let conn = setup_db();
    let adapter = ConcreteTransportIdentityAdapter;
    let recorded_by = "test-peer";

    // Store a peer_shared key in peer_secrets
    let signer_event_id = [5u8; 32];
    let signer_eid_b64 = topo::crypto::event_id_to_base64(&signer_event_id);
    let private_key = [42u8; 32];
    conn.execute(
        "INSERT INTO peer_secrets (recorded_by, event_id, signer_event_id, private_key, created_at)
         VALUES (?1, ?2, ?2, ?3, 0)",
        rusqlite::params![recorded_by, signer_eid_b64, private_key.to_vec()],
    )
    .unwrap();

    let peer_id = adapter
        .apply_intent(
            &conn,
            TransportIdentityIntent::InstallPeerSharedIdentityFromSigner {
                recorded_by: recorded_by.to_string(),
                signer_event_id,
            },
        )
        .unwrap();

    assert_eq!(peer_id.len(), 64, "peer_id should be 32-byte hex");

    // Verify loaded peer_id matches
    let loaded = topo::transport::identity::load_transport_peer_id(&conn).unwrap();
    assert_eq!(loaded, peer_id);
}

#[test]
fn concrete_adapter_signer_not_found_error() {
    let conn = setup_db();
    let adapter = ConcreteTransportIdentityAdapter;

    let result = adapter.apply_intent(
        &conn,
        TransportIdentityIntent::InstallPeerSharedIdentityFromSigner {
            recorded_by: "nonexistent".to_string(),
            signer_event_id: [0u8; 32],
        },
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        TransportIdentityError::SignerKeyNotFound { recorded_by } => {
            assert_eq!(recorded_by, "nonexistent");
        }
        other => panic!("expected SignerKeyNotFound, got {:?}", other),
    }
}

#[test]
fn concrete_adapter_invalid_key_material_error() {
    let conn = setup_db();
    let adapter = ConcreteTransportIdentityAdapter;
    let recorded_by = "test-peer";
    let signer_event_id = [11u8; 32];
    let signer_eid_b64 = topo::crypto::event_id_to_base64(&signer_event_id);

    // Insert a row with wrong key length (16 bytes instead of 32)
    conn.execute(
        "INSERT INTO peer_secrets (recorded_by, event_id, signer_event_id, private_key, created_at)
         VALUES (?1, ?2, ?2, ?3, 0)",
        rusqlite::params![recorded_by, signer_eid_b64, vec![0u8; 16]],
    )
    .unwrap();

    let result = adapter.apply_intent(
        &conn,
        TransportIdentityIntent::InstallPeerSharedIdentityFromSigner {
            recorded_by: recorded_by.to_string(),
            signer_event_id,
        },
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        TransportIdentityError::InvalidKeyMaterial(msg) => {
            assert!(
                msg.contains("16"),
                "should mention actual key length, got: {}",
                msg
            );
        }
        other => panic!("expected InvalidKeyMaterial, got {:?}", other),
    }
}

// --- Fake adapter tests ---

#[test]
fn fake_adapter_records_intents() {
    let conn = setup_db();
    let fake = FakeTransportIdentityAdapter::new("fake-peer-id");

    fake.apply_intent(
        &conn,
        TransportIdentityIntent::InstallBootstrapIdentityFromInviteKey {
            invite_private_key: [1u8; 32],
        },
    )
    .unwrap();

    fake.apply_intent(
        &conn,
        TransportIdentityIntent::InstallPeerSharedIdentityFromSigner {
            recorded_by: "rb2".to_string(),
            signer_event_id: [2u8; 32],
        },
    )
    .unwrap();

    fake.apply_intent(
        &conn,
        TransportIdentityIntent::InstallPeerSharedIdentityFromSigner {
            recorded_by: "rb3".to_string(),
            signer_event_id: [3u8; 32],
        },
    )
    .unwrap();

    let intents = fake.applied_intents();
    assert_eq!(intents.len(), 3);
    assert_eq!(
        intents[0],
        TransportIdentityIntent::InstallBootstrapIdentityFromInviteKey {
            invite_private_key: [1u8; 32],
        }
    );
    assert_eq!(
        intents[1],
        TransportIdentityIntent::InstallPeerSharedIdentityFromSigner {
            recorded_by: "rb2".to_string(),
            signer_event_id: [2u8; 32],
        }
    );
    assert_eq!(
        intents[2],
        TransportIdentityIntent::InstallPeerSharedIdentityFromSigner {
            recorded_by: "rb3".to_string(),
            signer_event_id: [3u8; 32],
        }
    );
}

#[test]
fn fake_adapter_returns_configured_peer_id() {
    let conn = setup_db();
    let fake = FakeTransportIdentityAdapter::new("custom-peer-id-42");

    let result = fake
        .apply_intent(
            &conn,
            TransportIdentityIntent::InstallBootstrapIdentityFromInviteKey {
                invite_private_key: [0u8; 32],
            },
        )
        .unwrap();

    assert_eq!(result, "custom-peer-id-42");
}
