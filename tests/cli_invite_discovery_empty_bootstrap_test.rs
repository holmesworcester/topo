mod cli_invite_discovery_common;

use cli_invite_discovery_common::*;
use topo::event_modules::workspace::invite_link::parse_invite_link;

/// Two separate local daemons should recover endpoint state via mDNS and then
/// sync successfully even when the invite carries no bootstrap addresses.
#[test]
#[cfg(feature = "discovery")]
fn test_cli_local_mdns_discovery_without_bootstrap_addresses() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let timeout_ms = 180_000;

    create_workspace(&alice_db);
    let _alice = start_discovery_daemon(&alice_db);
    let bootstrap_eid = send_message(&alice_db, "bootstrap");
    assert_event_visible_on_all(&[&alice_db], &bootstrap_eid, timeout_ms);

    let invite_link = rewrite_invite_addrs(
        &create_invite(&alice_db, &daemon_listen_addr(&alice_db)),
        &[],
    );
    assert!(
        parse_invite_link(&invite_link)
            .expect("parse empty-address invite")
            .bootstrap_addrs
            .is_empty(),
        "invite should carry no bootstrap addresses"
    );

    let mut bob =
        start_joined_cli_peer_via_discovery(&tmpdir, "bob.db", &invite_link, "user", "device");
    assert_event_visible_on_all(&[&bob.db], &bootstrap_eid, timeout_ms);
    assert_identity_eventually_materialized(&bob.db, timeout_ms);
    let alice_peer_id = active_tenant_peer_id(&alice_db).expect("alice active tenant");
    wait_for_bootstrap_supersession_and_endpoint_observation(
        &bob.db,
        &alice_peer_id,
        std::time::Duration::from_secs(120),
    );
    stop_daemon(&bob.db, &mut bob.daemon);
    bob.daemon = start_daemon(&bob.db);

    assert_event_visible_on_all(&[&bob.db], &bootstrap_eid, timeout_ms);
    assert_identity_eventually_materialized(&bob.db, timeout_ms);

    let alice_live_eid = send_message(&alice_db, "alice-via-mdns-empty-bootstrap");
    assert_eventually(
        &bob.db,
        &format!("has_event:{} >= 1", alice_live_eid),
        timeout_ms,
    );

    let bob_msg_eid = send_message(&bob.db, "bob-via-mdns-empty-bootstrap");
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_msg_eid),
        timeout_ms,
    );
}
