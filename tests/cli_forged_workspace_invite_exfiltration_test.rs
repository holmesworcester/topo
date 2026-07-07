//! CLI regression test for forged-workspace invite exfiltration.
//!
//! Security property:
//! accepting an invite whose link workspace was tampered to point at an
//! existing local workspace must never cause raw victim events to appear in the
//! attacker's database.

mod cli_harness;

use cli_harness::*;
use ed25519_dalek::SigningKey;
use std::process::Command;
use std::time::Duration;
use topo::db::open_connection;
use topo::event_modules::workspace::identity_ops::InviteData;
use topo::event_modules::workspace::invite_link::{
    create_invite_link_with_relay, parse_invite_link, ParsedInviteLink,
};
use topo::event_modules::workspace::queries::resolve_workspace_for_peer;

fn workspace_hex_for_active_tenant(db: &str) -> String {
    let conn = open_connection(db).expect("open db");
    let active_peer_id = active_tenant_peer_id(db).expect("active tenant peer id");
    let workspace_id = resolve_workspace_for_peer(&conn, &active_peer_id)
        .expect("resolve active tenant workspace");
    hex::encode(workspace_id)
}

fn forge_invite_workspace(link: &str, workspace_hex: &str) -> String {
    let parsed = parse_invite_link(link).expect("parse attacker invite link");
    let mut workspace_id = [0u8; 32];
    hex::decode_to_slice(workspace_hex, &mut workspace_id).expect("decode forged workspace hex");

    let invite = InviteData {
        invite_event_id: parsed.invite_event_id,
        invite_key: SigningKey::from_bytes(&parsed.invite_private_key),
        workspace_id,
        invite_type: parsed.invite_type,
    };
    create_invite_link_with_relay(
        &invite,
        &parsed.bootstrap_addrs,
        &parsed.endpoint_id,
        parsed.relay_url.as_deref(),
    )
    .expect("rebuild forged invite link")
}

fn assert_only_workspace_field_changed(
    original: &ParsedInviteLink,
    forged: &ParsedInviteLink,
    expected_workspace_hex: &str,
) {
    let mut expected_workspace = [0u8; 32];
    hex::decode_to_slice(expected_workspace_hex, &mut expected_workspace)
        .expect("decode expected workspace hex");

    assert_eq!(
        forged.invite_event_id, original.invite_event_id,
        "forged link must keep the real invite_event_id"
    );
    assert_eq!(
        forged.invite_private_key, original.invite_private_key,
        "forged link must keep the real invite private key"
    );
    assert_eq!(
        forged.invite_type, original.invite_type,
        "forged link must keep the same invite type"
    );
    assert_eq!(
        forged.bootstrap_addrs, original.bootstrap_addrs,
        "forged link must keep the same bootstrap addresses"
    );
    assert_eq!(
        forged.endpoint_id, original.endpoint_id,
        "forged link must keep the same bootstrap endpoint"
    );
    assert_eq!(
        forged.relay_url, original.relay_url,
        "forged link must keep the same relay hint"
    );
    assert_eq!(
        forged.workspace_id, expected_workspace,
        "forged link must retarget only the workspace field"
    );
    assert_ne!(
        forged.workspace_id, original.workspace_id,
        "the test requires a real invite event plus a forged workspace claim"
    );
}

fn assert_event_never_appears(db: &str, event_hex: &str, what: &str, timeout_ms: u64) {
    let out = topo_assert_eventually(db, &format!("has_event:{event_hex} >= 1"), timeout_ms);
    assert!(
        !out.status.success(),
        "{what} unexpectedly appeared in attacker db={db} within {timeout_ms}ms\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[test]
fn test_cli_forged_workspace_invite_does_not_exfiltrate_raw_victim_events() {
    let tmpdir = tempfile::tempdir().unwrap();
    let attacker_db = tmpdir
        .path()
        .join("attacker.db")
        .to_str()
        .unwrap()
        .to_string();
    let victim_db = tmpdir
        .path()
        .join("victim.db")
        .to_str()
        .unwrap()
        .to_string();

    create_workspace(&victim_db);
    let _victim_daemon = start_daemon(&victim_db);
    wait_for_daemon_ready(&victim_db, Duration::from_secs(10));

    let victim_workspace_hex = workspace_hex_for_active_tenant(&victim_db);
    let victim_message_hex = send_message(
        &victim_db,
        "victim secret: this shared event must never reach attacker raw storage",
    );

    create_workspace(&attacker_db);
    let _attacker_daemon = start_daemon(&attacker_db);
    wait_for_daemon_ready(&attacker_db, Duration::from_secs(10));

    // The attacker starts from a legitimate invite they are allowed to create,
    // then forges only the workspace claim inside the link.
    let attacker_invite = topo_create_invite_retry(&attacker_db, &daemon_listen_addr(&attacker_db));
    let forged_invite = forge_invite_workspace(&attacker_invite, &victim_workspace_hex);
    let original_parsed = parse_invite_link(&attacker_invite).expect("parse original attacker invite");
    let forged_parsed = parse_invite_link(&forged_invite).expect("parse forged attacker invite");
    assert_only_workspace_field_changed(&original_parsed, &forged_parsed, &victim_workspace_hex);

    let accept = Command::new(bin())
        .args([
            "accept",
            "--db",
            &victim_db,
            &forged_invite,
            "--username",
            "victim-second-tenant",
            "--devicename",
            "forged-link",
        ])
        .output()
        .expect("run forged accept");

    if accept.status.success() {
        std::thread::sleep(Duration::from_secs(2));
    }

    assert_event_never_appears(
        &attacker_db,
        &victim_message_hex,
        "victim message event",
        20_000,
    );
    assert_event_never_appears(
        &attacker_db,
        &victim_workspace_hex,
        "victim workspace event",
        20_000,
    );
}
