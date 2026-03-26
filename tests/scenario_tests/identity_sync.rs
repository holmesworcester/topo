use topo::db::open_connection;
use topo::testutil::{Peer, ScenarioHarness};

/// Policy boundary: a joined non-admin user may only create a device-link
/// invite for their own user identity, not someone else's.
/// This requires calling the raw internal API — CLI `topo link` always links
/// for the calling peer's own user and cannot target another user.
#[tokio::test]
async fn test_non_admin_joined_user_cannot_issue_device_link_invite_for_other_user() {
    let alice = Peer::new_with_identity("alice");
    let bob_phone = Peer::new_in_workspace("bob-phone", &alice).await;
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob_phone);

    let device_invites_before = bob_phone.device_invite_count();
    let bob_db = open_connection(&bob_phone.db_path).expect("open bob db");
    let bob_peer_key = bob_phone
        .peer_shared_signing_key
        .as_ref()
        .expect("Bob should have a peer_shared signer");
    let bob_peer_eid = bob_phone
        .peer_shared_event_id
        .expect("Bob should have a peer_shared event");

    let err = match topo::event_modules::workspace::commands::create_device_link_invite_raw(
        &bob_db,
        &bob_phone.identity,
        bob_peer_key,
        &bob_peer_eid,
        &alice.author_id,
        &bob_phone.workspace_id,
    ) {
        Ok(_) => {
            panic!("non-admin joined user should not be able to link a device for another user")
        }
        Err(err) => err,
    };

    let err_text = format!("{err:?}");
    assert!(
        err_text
            .contains("peer-signed device_invite authority does not match signer user identity"),
        "unexpected error for cross-user device-link invite attempt: {err_text}",
    );
    assert_eq!(
        bob_phone.device_invite_count(),
        device_invites_before,
        "Rejected cross-user device-link invite should not change Bob's projected device_invites",
    );

    harness.finish();
}
