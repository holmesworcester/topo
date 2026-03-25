#![allow(dead_code)]

use std::time::Duration;
use topo::crypto::{event_id_from_base64, event_id_to_base64};
use topo::db::open_connection;
use topo::testutil::{
    assert_eventually, create_dynamic_endpoint_for_peer, start_peers, Peer, ScenarioHarness,
};
use topo::transport::multi_workspace::transport_sni;

async fn assert_direct_message_exchange(
    peer_a: &Peer,
    peer_b: &Peer,
    peer_a_marker: &str,
    peer_b_marker: &str,
    timeout: Duration,
    reason: &str,
) {
    let peer_a_event = peer_a.create_message(peer_a_marker);
    let peer_a_event_b64 = event_id_to_base64(&peer_a_event);
    let peer_b_event = peer_b.create_message(peer_b_marker);
    let peer_b_event_b64 = event_id_to_base64(&peer_b_event);

    let _sync = start_peers(peer_a, peer_b);
    assert_eventually(
        || peer_a.has_event(&peer_b_event_b64) && peer_b.has_event(&peer_a_event_b64),
        timeout,
        reason,
    )
    .await;
}

/// Identity chain events arrive out of order via sync and cascade to valid.
/// Bob creates his own events but they depend on Alice's chain. Sync delivers
/// Alice's events, which unblock Bob's chain via cascade.
#[tokio::test]
async fn test_identity_cascade_via_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    let bob_peer_shared_eid = bob
        .peer_shared_event_id
        .expect("joined peer should materialize peer_shared during invite acceptance");
    let bob_peer_shared_b64 = event_id_to_base64(&bob_peer_shared_eid);

    let _sync = start_peers(&alice, &bob);
    assert_eventually(
        || {
            let db = open_connection(&alice.db_path).unwrap();
            let valid: bool = db
                .query_row(
                    "SELECT COUNT(*) > 0 FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
                    rusqlite::params![&alice.identity, &bob_peer_shared_b64],
                    |row| row.get(0),
                )
                .unwrap_or(false);
            valid
        },
        Duration::from_secs(20),
        "Bob's peer_shared should become valid on Alice after sync",
    )
    .await;

    assert_eq!(
        alice.peer_shared_count(),
        2,
        "Alice should now project Bob's peer_shared"
    );
    assert_eq!(
        bob.peer_shared_count(),
        2,
        "Bob should retain both peer_shared rows"
    );
    assert_eq!(alice.user_count(), 2, "Alice should now project Bob's user");
    assert_eq!(bob.user_count(), 2, "Bob should retain both users");

    harness.finish();
}

/// Mixed 3-peer topology: a second device joins via device-link, then that
/// linked device invites a new user. After convergence, the original device
/// and the invited user must be able to sync directly without the inviter.
#[tokio::test]
async fn test_three_peer_device_link_then_user_invite_from_linked_device() {
    let phone = Peer::new_with_identity("phone");
    let laptop = Peer::new_device_in_workspace("laptop", &phone).await;
    let bob = Peer::new_in_workspace("bob", &laptop).await;
    let harness = ScenarioHarness::new();
    harness.track(&phone);
    harness.track(&laptop);
    harness.track(&bob);

    // Phase 1: the original device and linked device converge, then the linked
    // device relays Bob's identity chain into the workspace.
    let _sync_phone_laptop = start_peers(&phone, &laptop);
    let _sync_laptop_bob = start_peers(&laptop, &bob);

    assert_eventually(
        || {
            phone.peer_shared_count() == 3
                && laptop.peer_shared_count() == 3
                && bob.peer_shared_count() == 3
        },
        Duration::from_secs(20),
        "phone, laptop, and bob should converge on all three peer identities",
    )
    .await;

    assert_eq!(
        phone.user_count(),
        2,
        "phone should see Alice and Bob users"
    );
    assert_eq!(
        laptop.user_count(),
        2,
        "laptop should see Alice and Bob users"
    );
    assert_eq!(bob.user_count(), 2, "bob should see Alice and Bob users");

    // Phase 2: phone and Bob sync directly, without the linked device
    // participating, proving the workspace converged beyond the inviter edge.
    let phone_marker = phone.create_message("phone-direct-to-bob");
    let phone_marker_b64 = event_id_to_base64(&phone_marker);
    let bob_marker = bob.create_message("bob-direct-to-phone");
    let bob_marker_b64 = event_id_to_base64(&bob_marker);

    let _sync_phone_bob = start_peers(&phone, &bob);
    assert_eventually(
        || phone.has_event(&bob_marker_b64) && bob.has_event(&phone_marker_b64),
        Duration::from_secs(20),
        "phone and bob should sync directly after laptop-originated invite convergence",
    )
    .await;

    harness.finish();
}

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

/// One user across three devices, with the third device linked by the second
/// device rather than by the original one. This exercises chained device-link
/// acceptance and relay.
#[tokio::test]
async fn test_three_peer_chained_device_links_enable_direct_sync_between_root_and_leaf() {
    let phone = Peer::new_with_identity("phone");
    let laptop = Peer::new_device_in_workspace("laptop", &phone).await;
    assert_eq!(
        laptop.admin_count(),
        1,
        "Linked device should receive admin state needed to issue another device-link invite",
    );
    let tablet = Peer::new_device_in_workspace("tablet", &laptop).await;
    let harness = ScenarioHarness::new();
    harness.track(&phone);
    harness.track(&laptop);
    harness.track(&tablet);

    let _sync_phone_laptop = start_peers(&phone, &laptop);
    let _sync_laptop_tablet = start_peers(&laptop, &tablet);

    assert_eventually(
        || {
            phone.peer_shared_count() == 3
                && laptop.peer_shared_count() == 3
                && tablet.peer_shared_count() == 3
        },
        Duration::from_secs(20),
        "Phone, laptop, and tablet should converge after chained device links",
    )
    .await;

    assert_eq!(
        phone.user_count(),
        1,
        "All devices should resolve to one user"
    );
    assert_eq!(
        laptop.user_count(),
        1,
        "All devices should resolve to one user"
    );
    assert_eq!(
        tablet.user_count(),
        1,
        "All devices should resolve to one user"
    );
    assert_eq!(
        phone.device_invite_count(),
        3,
        "Phone should see three device invites"
    );
    assert_eq!(
        laptop.device_invite_count(),
        3,
        "Laptop should see three device invites",
    );
    assert_eq!(
        tablet.device_invite_count(),
        3,
        "Tablet should see three device invites",
    );

    assert_direct_message_exchange(
        &phone,
        &tablet,
        "phone-direct-to-tablet",
        "tablet-direct-to-phone",
        Duration::from_secs(20),
        "Phone and tablet should sync directly after chained device-link convergence",
    )
    .await;

    harness.finish();
}

/// One user across three devices, with the original device linking both
/// additional devices independently. The two non-originating devices should
/// still become directly connected once the root device relays both joins.
#[tokio::test]
async fn test_three_peer_parallel_device_links_enable_direct_sync_between_non_inviters() {
    let phone = Peer::new_with_identity("phone");
    let laptop = Peer::new_device_in_workspace("laptop", &phone).await;
    let tablet = Peer::new_device_in_workspace("tablet", &phone).await;
    let harness = ScenarioHarness::new();
    harness.track(&phone);
    harness.track(&laptop);
    harness.track(&tablet);

    let _sync_phone_laptop = start_peers(&phone, &laptop);
    let _sync_phone_tablet = start_peers(&phone, &tablet);

    assert_eventually(
        || {
            phone.peer_shared_count() == 3
                && laptop.peer_shared_count() == 3
                && tablet.peer_shared_count() == 3
        },
        Duration::from_secs(20),
        "Phone should relay both independent device-link joins into one converged workspace",
    )
    .await;

    assert_eq!(
        phone.user_count(),
        1,
        "All devices should resolve to one user"
    );
    assert_eq!(
        laptop.user_count(),
        1,
        "All devices should resolve to one user"
    );
    assert_eq!(
        tablet.user_count(),
        1,
        "All devices should resolve to one user"
    );
    assert_eq!(
        phone.device_invite_count(),
        3,
        "Phone should see three device invites"
    );
    assert_eq!(
        laptop.device_invite_count(),
        3,
        "Laptop should see three device invites",
    );
    assert_eq!(
        tablet.device_invite_count(),
        3,
        "Tablet should see three device invites",
    );

    assert_direct_message_exchange(
        &laptop,
        &tablet,
        "laptop-direct-to-tablet",
        "tablet-direct-to-laptop",
        Duration::from_secs(20),
        "Laptop and tablet should sync directly after root-relayed parallel device links",
    )
    .await;

    harness.finish();
}

/// Alice and Bob are on different workspaces. When they sync, Bob's workspace events
/// are rejected by Alice's trust anchor, and vice versa. Neither peer's identity
/// state is corrupted.
#[tokio::test]
async fn test_foreign_workspace_rejected_via_sync() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_with_identity("bob");
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    assert_ne!(
        alice.workspace_id, bob.workspace_id,
        "workspaces should differ"
    );
    assert_eq!(alice.workspace_count(), 1);
    assert_eq!(bob.workspace_count(), 1);

    let server_ep = create_dynamic_endpoint_for_peer(&alice);
    let server_addr = server_ep.local_addr().expect("alice listen addr");
    let client_ep = create_dynamic_endpoint_for_peer(&bob);
    let server_sni = transport_sni(&alice.transport_peer_id());
    let server_ep_clone = server_ep.clone();
    let server_accept = tokio::spawn(async move {
        match server_ep_clone.accept().await {
            Some(incoming) => incoming.await.err(),
            None => None,
        }
    });

    let result = client_ep
        .connect(server_addr, &server_sni)
        .expect("initiate cross-workspace connect")
        .await;

    assert!(
        result.is_err(),
        "cross-workspace peers should be rejected during transport handshake"
    );
    let server_result = server_accept.await.expect("join server accept task");
    assert!(
        server_result.is_some(),
        "server should observe the failed unauthorized inbound handshake"
    );

    assert_eq!(
        alice.workspace_count(),
        1,
        "Alice should retain only her workspace"
    );
    assert_eq!(
        bob.workspace_count(),
        1,
        "Bob should retain only his workspace"
    );
    assert_eq!(alice.user_count(), 1, "Alice's own user unchanged");
    assert_eq!(bob.user_count(), 1, "Bob's own user unchanged");
    assert_eq!(
        alice.peer_shared_count(),
        1,
        "Alice should retain only her own peer_shared"
    );
    assert_eq!(
        bob.peer_shared_count(),
        1,
        "Bob should retain only his own peer_shared"
    );

    server_ep.close(0u32.into(), b"done");
    client_ep.close(0u32.into(), b"done");

    harness.finish();
}
