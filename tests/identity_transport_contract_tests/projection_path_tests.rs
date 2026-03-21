//! Projection command path tests: verify that peer_secret projection
//! emits the correct MaterializeTransportIdentity for peer_shared signer key material.

use topo::contracts::transport_identity_contract::TransportIdentitySpec;
use topo::event_modules::peer_secret::PeerSecretEvent;
use topo::event_modules::ParsedEvent;
use topo::projection::contract::EmitCommand;

fn project(recorded_by: &str, event: &ParsedEvent) -> Vec<EmitCommand> {
    let result = topo::event_modules::peer_secret::project_pure(
        recorded_by,
        "test-event-id",
        event,
        &Default::default(),
    );
    result.emit_commands
}

#[test]
fn peer_secret_emits_install_spec() {
    let signer_event_id = [5u8; 32];
    let event = ParsedEvent::PeerSecret(PeerSecretEvent {
        created_at_ms: 1000,
        signer_event_id,
        private_key_bytes: [42u8; 32],
    });

    let cmds = project("test-peer", &event);

    assert_eq!(
        cmds.len(),
        1,
        "peer_secret should emit exactly one transport spec"
    );
    let spec = cmds
        .iter()
        .find_map(|c| match c {
            EmitCommand::MaterializeTransportIdentity { spec } => Some(spec),
            _ => None,
        })
        .expect("missing MaterializeTransportIdentity");
    assert_eq!(
        *spec,
        TransportIdentitySpec::InstallPeerSharedIdentityFromSigner {
            recorded_by: "test-peer".to_string(),
            signer_event_id,
        }
    );
}

#[test]
fn spec_carries_correct_recorded_by() {
    let event = ParsedEvent::PeerSecret(PeerSecretEvent {
        created_at_ms: 1000,
        signer_event_id: [9u8; 32],
        private_key_bytes: [10u8; 32],
    });

    let cmds = project("specific-recorded-by-value", &event);
    let spec = cmds
        .iter()
        .find_map(|c| match c {
            EmitCommand::MaterializeTransportIdentity { spec } => Some(spec),
            _ => None,
        })
        .expect("missing MaterializeTransportIdentity");
    match spec {
        TransportIdentitySpec::InstallPeerSharedIdentityFromSigner { recorded_by, .. } => {
            assert_eq!(recorded_by, "specific-recorded-by-value");
        }
        other => panic!("wrong spec variant: {:?}", other),
    }
}

#[test]
fn no_duplicate_specs_emitted() {
    let event = ParsedEvent::PeerSecret(PeerSecretEvent {
        created_at_ms: 1000,
        signer_event_id: [7u8; 32],
        private_key_bytes: [8u8; 32],
    });

    let cmds = project("rb", &event);
    let spec_count = cmds
        .iter()
        .filter(|c| matches!(c, EmitCommand::MaterializeTransportIdentity { .. }))
        .count();
    assert_eq!(spec_count, 1, "must emit exactly one spec, no duplicates");
}
