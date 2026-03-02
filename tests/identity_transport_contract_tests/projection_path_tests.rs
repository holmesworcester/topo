//! Projection command path tests: verify that the local_signer_secret projector
//! emits the correct ApplyTransportIdentityIntent for peer_shared signer kind,
//! and does NOT emit it for other signer kinds.

use topo::contracts::transport_identity_contract::TransportIdentityIntent;
use topo::event_modules::local_signer_secret::{
    LocalSignerSecretEvent, SIGNER_KIND_PEER_SHARED, SIGNER_KIND_USER, SIGNER_KIND_WORKSPACE,
};
use topo::event_modules::ParsedEvent;
use topo::projection::contract::{ContextSnapshot, EmitCommand};

fn project(recorded_by: &str, event: &ParsedEvent) -> Vec<EmitCommand> {
    let result = topo::event_modules::local_signer_secret::project_pure(
        recorded_by,
        "test-event-id",
        event,
        &ContextSnapshot::default(),
    );
    result.emit_commands
}

#[test]
fn peer_shared_signer_emits_install_intent() {
    let signer_event_id = [5u8; 32];
    let event = ParsedEvent::LocalSignerSecret(LocalSignerSecretEvent {
        created_at_ms: 1000,
        signer_event_id,
        signer_kind: SIGNER_KIND_PEER_SHARED,
        private_key_bytes: [42u8; 32],
    });

    let cmds = project("test-peer", &event);

    assert_eq!(cmds.len(), 1, "should emit exactly one command");
    match &cmds[0] {
        EmitCommand::ApplyTransportIdentityIntent { intent } => {
            assert_eq!(
                *intent,
                TransportIdentityIntent::InstallPeerSharedIdentityFromSigner {
                    recorded_by: "test-peer".to_string(),
                    signer_event_id,
                }
            );
        }
        other => panic!("expected ApplyTransportIdentityIntent, got {:?}", other),
    }
}

#[test]
fn workspace_signer_does_not_emit_intent() {
    let event = ParsedEvent::LocalSignerSecret(LocalSignerSecretEvent {
        created_at_ms: 1000,
        signer_event_id: [1u8; 32],
        signer_kind: SIGNER_KIND_WORKSPACE,
        private_key_bytes: [2u8; 32],
    });

    let cmds = project("test-peer", &event);
    assert!(cmds.is_empty(), "workspace signer should emit no commands");
}

#[test]
fn user_signer_does_not_emit_intent() {
    let event = ParsedEvent::LocalSignerSecret(LocalSignerSecretEvent {
        created_at_ms: 1000,
        signer_event_id: [3u8; 32],
        signer_kind: SIGNER_KIND_USER,
        private_key_bytes: [4u8; 32],
    });

    let cmds = project("test-peer", &event);
    assert!(cmds.is_empty(), "user signer should emit no commands");
}

#[test]
fn intent_carries_correct_recorded_by() {
    let event = ParsedEvent::LocalSignerSecret(LocalSignerSecretEvent {
        created_at_ms: 1000,
        signer_event_id: [9u8; 32],
        signer_kind: SIGNER_KIND_PEER_SHARED,
        private_key_bytes: [10u8; 32],
    });

    let cmds = project("specific-recorded-by-value", &event);
    assert_eq!(cmds.len(), 1);
    match &cmds[0] {
        EmitCommand::ApplyTransportIdentityIntent { intent } => match intent {
            TransportIdentityIntent::InstallPeerSharedIdentityFromSigner {
                recorded_by, ..
            } => {
                assert_eq!(recorded_by, "specific-recorded-by-value");
            }
            other => panic!("wrong intent variant: {:?}", other),
        },
        other => panic!("wrong command: {:?}", other),
    }
}

#[test]
fn no_duplicate_intents_emitted() {
    let event = ParsedEvent::LocalSignerSecret(LocalSignerSecretEvent {
        created_at_ms: 1000,
        signer_event_id: [7u8; 32],
        signer_kind: SIGNER_KIND_PEER_SHARED,
        private_key_bytes: [8u8; 32],
    });

    let cmds = project("rb", &event);
    assert_eq!(cmds.len(), 1, "must emit exactly one intent, no duplicates");
}
