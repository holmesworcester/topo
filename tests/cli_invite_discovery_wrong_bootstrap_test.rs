mod cli_invite_discovery_common;

use cli_invite_discovery_common::*;
use topo::event_modules::workspace::invite_link::parse_invite_link;

/// A rewritten invite with only wrong bootstrap addresses should still recover
/// via mDNS once both daemons are running.
#[test]
#[cfg(feature = "discovery")]
fn test_cli_local_mdns_discovery_with_wrong_bootstrap_address_only() {
    let _guard = cli_test_lock();
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let timeout_ms = 90000;

    create_workspace(&alice_db);
    let _alice = start_discovery_daemon(&alice_db);
    let (_wrong_addr_guard, wrong_addr) = reserve_wrong_bootstrap_addr();
    let invite_link = rewrite_invite_addrs(
        &create_invite(&alice_db, &daemon_listen_addr(&alice_db)),
        &[&wrong_addr],
    );
    assert_eq!(
        parse_invite_link(&invite_link)
            .expect("parse wrong-address invite")
            .bootstrap_addr_strings(),
        vec![wrong_addr.clone()],
        "invite should carry only the wrong bootstrap address"
    );

    let bob =
        start_joined_cli_peer_via_discovery(&tmpdir, "bob.db", &invite_link, "bob", "bob-box");

    let alice_live_eid = send_message(&alice_db, "alice-via-mdns-wrong-bootstrap");
    assert_eventually(
        &bob.db,
        &format!("has_event:{} >= 1", alice_live_eid),
        timeout_ms,
    );

    let bob_live_eid = send_message(&bob.db, "bob-via-mdns-wrong-bootstrap");
    assert_eventually(
        &alice_db,
        &format!("has_event:{} >= 1", bob_live_eid),
        timeout_ms,
    );
}
