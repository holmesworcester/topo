use topo::crypto::event_id_from_base64;
use topo::db::open_connection;
use topo::testutil::{Peer, ScenarioHarness};

/// Policy boundary: a joined non-admin user receives the workspace admin
/// projection for validation, but cannot issue a new user invite on behalf
/// of that admin identity.
#[tokio::test]
async fn test_non_admin_joined_user_cannot_issue_user_invite() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    assert_eq!(
        bob.admin_count(),
        1,
        "Bob should receive the workspace admin projection during bootstrap",
    );

    let user_invites_before = bob.user_invite_count();
    let bob_db = open_connection(&bob.db_path).expect("open bob db");
    let bob_peer_key = bob
        .peer_shared_signing_key
        .as_ref()
        .expect("Bob should have a peer_shared signer");
    let bob_peer_eid = bob
        .peer_shared_event_id
        .expect("Bob should have a peer_shared event");
    let admin_event_id = bob_db
        .query_row(
            "SELECT event_id
             FROM admins
             WHERE recorded_by = ?1
             ORDER BY event_id ASC
             LIMIT 1",
            rusqlite::params![&bob.identity],
            |row| row.get::<_, String>(0),
        )
        .ok()
        .and_then(|b64| event_id_from_base64(&b64))
        .expect("Bob should have an admin event available");

    let err = match topo::event_modules::workspace::commands::create_user_invite_raw(
        &bob_db,
        &bob.identity,
        bob_peer_key,
        &bob_peer_eid,
        &admin_event_id,
        &bob.workspace_id,
    ) {
        Ok(_) => panic!("non-admin joined user should not be able to create a user invite"),
        Err(err) => err,
    };

    let err_text = format!("{err:?}");
    assert!(
        err_text.contains("peer-signed user_invite authority does not match signer admin identity"),
        "unexpected error for non-admin user invite attempt: {err_text}",
    );
    assert_eq!(
        bob.user_invite_count(),
        user_invites_before,
        "Rejected user invite should not change Bob's projected user_invites",
    );

    harness.finish();
}

/// Policy boundary: a joined non-admin user may only create a device-link
/// invite for their own user identity, not someone else's.
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

