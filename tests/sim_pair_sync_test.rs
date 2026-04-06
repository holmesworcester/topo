use std::collections::BTreeSet;

use topo::rpc::protocol::RpcMethod;
use topo::sim::{
    import_peer_state, plan_pair_sync_intents, run_pair_sync_session, PairSyncIntent, SimPeerNode,
    VirtualDaemon,
};

fn active_peer_id(daemon: &VirtualDaemon) -> String {
    daemon
        .call_ok_value(RpcMethod::ActiveTenant)
        .expect("active tenant")["peer_id"]
        .as_str()
        .expect("active tenant peer id")
        .to_string()
}

fn create_invite(daemon: &VirtualDaemon, public_addr: &str) -> String {
    daemon
        .call_ok_value(RpcMethod::CreateInvite {
            public_addr: Some(public_addr.to_string()),
            public_spki: None,
        })
        .expect("create invite")["invite_link"]
        .as_str()
        .expect("invite link")
        .to_string()
}

fn create_device_link(daemon: &VirtualDaemon, public_addr: &str) -> String {
    daemon
        .call_ok_value(RpcMethod::CreateDeviceLink {
            public_addr: Some(public_addr.to_string()),
            public_spki: None,
        })
        .expect("create device link")["invite_link"]
        .as_str()
        .expect("device link")
        .to_string()
}

fn send_message(daemon: &VirtualDaemon, content: &str) -> String {
    daemon
        .call_ok_value(RpcMethod::Send {
            content: content.to_string(),
            client_op_id: None,
        })
        .expect("send message")["event_id"]
        .as_str()
        .expect("message event id")
        .to_string()
}

fn assert_has_event(daemon: &VirtualDaemon, event_id: &str) {
    let response = daemon.call(RpcMethod::AssertNow {
        predicate: format!("has_event:{event_id} >= 1"),
    });
    assert!(
        response.ok,
        "expected daemon {} to have event {}: {:?}",
        daemon.db_path(),
        event_id,
        response.error
    );
}

fn assert_lacks_event(daemon: &VirtualDaemon, event_id: &str) {
    let response = daemon.call(RpcMethod::AssertNow {
        predicate: format!("has_event:{event_id} == 0"),
    });
    assert!(
        response.ok,
        "expected daemon {} to lack event {}: {:?}",
        daemon.db_path(),
        event_id,
        response.error
    );
}

fn event_ids_of_type(daemon: &VirtualDaemon, event_type: &str) -> BTreeSet<String> {
    let conn = topo::db::open_connection(daemon.db_path()).expect("open db for raw event scan");
    let recorded_by = active_peer_id(daemon);
    let mut stmt = conn
        .prepare(
            "SELECT re.event_id
             FROM recorded_events re
             JOIN events e ON e.event_id = re.event_id
             WHERE re.peer_id = ?1
               AND e.event_type = ?2
             ORDER BY re.id ASC",
        )
        .expect("prepare raw event scan");
    stmt.query_map(rusqlite::params![recorded_by, event_type], |row| {
        row.get::<_, String>(0)
    })
    .expect("query raw event scan")
    .collect::<Result<BTreeSet<_>, _>>()
    .expect("collect raw event ids")
}

fn import_node(daemon: &VirtualDaemon, recorded_by: &str) -> SimPeerNode {
    let imported = import_peer_state(daemon.db_path(), recorded_by).expect("import peer state");
    SimPeerNode::from_imported(daemon.db_path(), &imported)
}

fn intent_between<'a>(
    intents: &'a [PairSyncIntent],
    initiator_recorded_by: &str,
    target_recorded_by: &str,
) -> &'a PairSyncIntent {
    intents
        .iter()
        .find(|intent| {
            intent.initiator_recorded_by == initiator_recorded_by
                && intent.target_recorded_by == target_recorded_by
        })
        .unwrap_or_else(|| {
            panic!(
                "missing pair-sync intent {} -> {}; intents={:#?}",
                initiator_recorded_by, target_recorded_by, intents
            )
        })
}

fn run_session_for_intent(intent: &PairSyncIntent) {
    run_pair_sync_session(
        &intent.initiator_db_path,
        &intent.initiator_recorded_by,
        &intent.target_db_path,
        &intent.target_recorded_by,
    )
    .expect("pair sync session");
}

#[test]
fn real_pair_sync_is_required_for_replication_between_virtual_daemon_nodes() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db");
    let bob_db = tmpdir.path().join("bob.db");

    let alice = VirtualDaemon::new(alice_db.to_str().unwrap());
    let bob = VirtualDaemon::new(bob_db.to_str().unwrap());

    let created = alice.call(RpcMethod::CreateWorkspace {
        workspace_name: "sim".into(),
        username: "alice".into(),
        device_name: "laptop".into(),
        message_count: 0,
        network_age: None,
        device_chain_length: 0,
    });
    assert!(created.ok, "workspace creation failed: {:?}", created.error);
    let alice_peer = active_peer_id(&alice);

    let invite = create_invite(&alice, "127.0.0.1:4242");
    let accepted = bob.call(RpcMethod::AcceptInvite {
        invite,
        username: "bob".into(),
        devicename: "phone".into(),
    });
    assert!(accepted.ok, "accept invite failed: {:?}", accepted.error);
    let bob_peer = active_peer_id(&bob);

    let alice_message = send_message(&alice, "hello pair sync");
    assert_lacks_event(&bob, &alice_message);

    let intents = plan_pair_sync_intents(&[
        import_node(&alice, &alice_peer),
        import_node(&bob, &bob_peer),
    ]);
    let bob_to_alice = intent_between(&intents, &bob_peer, &alice_peer);
    run_session_for_intent(bob_to_alice);

    assert_has_event(&bob, &alice_message);
}

#[test]
fn planner_drives_hop_by_hop_message_and_key_shared_propagation() {
    let tmpdir = tempfile::tempdir().unwrap();
    let phone_db = tmpdir.path().join("phone.db");
    let laptop_db = tmpdir.path().join("laptop.db");
    let tablet_db = tmpdir.path().join("tablet.db");

    let phone = VirtualDaemon::new(phone_db.to_str().unwrap());
    let laptop = VirtualDaemon::new(laptop_db.to_str().unwrap());
    let tablet = VirtualDaemon::new(tablet_db.to_str().unwrap());

    let created = phone.call(RpcMethod::CreateWorkspace {
        workspace_name: "sim".into(),
        username: "alice".into(),
        device_name: "phone".into(),
        message_count: 0,
        network_age: None,
        device_chain_length: 0,
    });
    assert!(created.ok, "workspace creation failed: {:?}", created.error);
    let phone_peer = active_peer_id(&phone);

    let phone_link = create_device_link(&phone, "127.0.0.1:4242");
    let phone_key_shared_ids = event_ids_of_type(&phone, "key_shared");
    assert!(
        !phone_key_shared_ids.is_empty(),
        "device-link creation on the phone should emit at least one key_shared event"
    );
    let accepted_laptop = laptop.call(RpcMethod::AcceptLink {
        invite: phone_link,
        devicename: "laptop".into(),
    });
    assert!(
        accepted_laptop.ok,
        "laptop accept link failed: {:?}",
        accepted_laptop.error
    );
    let laptop_peer = active_peer_id(&laptop);

    let bootstrap_message = send_message(&phone, "phone-bootstrap");
    let phone_laptop_intents = plan_pair_sync_intents(&[
        import_node(&phone, &phone_peer),
        import_node(&laptop, &laptop_peer),
    ]);
    let laptop_to_phone = intent_between(&phone_laptop_intents, &laptop_peer, &phone_peer);
    run_session_for_intent(laptop_to_phone);

    assert_has_event(&laptop, &bootstrap_message);
    assert!(
        phone_key_shared_ids.iter().all(|event_id| {
            let response = laptop.call(RpcMethod::AssertNow {
                predicate: format!("has_event:{event_id} >= 1"),
            });
            response.ok
        }),
        "the first pair sync should replicate the phone's real key_shared events onto the laptop"
    );

    let laptop_link = create_device_link(&laptop, "127.0.0.1:4343");
    let accepted_tablet = tablet.call(RpcMethod::AcceptLink {
        invite: laptop_link,
        devicename: "tablet".into(),
    });
    assert!(
        accepted_tablet.ok,
        "tablet accept link failed: {:?}",
        accepted_tablet.error
    );
    let tablet_peer = active_peer_id(&tablet);

    let routed_message = send_message(&phone, "phone-through-laptop");
    assert_lacks_event(&laptop, &routed_message);
    assert_lacks_event(&tablet, &routed_message);

    let phone_laptop_after_send = plan_pair_sync_intents(&[
        import_node(&phone, &phone_peer),
        import_node(&laptop, &laptop_peer),
    ]);
    run_session_for_intent(intent_between(
        &phone_laptop_after_send,
        &laptop_peer,
        &phone_peer,
    ));
    assert_has_event(&laptop, &routed_message);
    assert_lacks_event(&tablet, &routed_message);

    let chain_intents = plan_pair_sync_intents(&[
        import_node(&phone, &phone_peer),
        import_node(&laptop, &laptop_peer),
        import_node(&tablet, &tablet_peer),
    ]);
    assert!(
        chain_intents
            .iter()
            .any(|intent| intent.initiator_recorded_by == laptop_peer
                && intent.target_recorded_by == phone_peer),
        "the linked laptop should still target the phone via real imported connect targets"
    );
    assert!(
        chain_intents
            .iter()
            .any(|intent| intent.initiator_recorded_by == tablet_peer
                && intent.target_recorded_by == laptop_peer),
        "the linked tablet should target the laptop via real imported connect targets"
    );
    assert!(
        !chain_intents
            .iter()
            .any(|intent| intent.initiator_recorded_by == tablet_peer
                && intent.target_recorded_by == phone_peer),
        "the tablet must not invent a direct phone sync edge when the real daemon state only knows the laptop link"
    );

    run_session_for_intent(intent_between(&chain_intents, &tablet_peer, &laptop_peer));
    assert_has_event(&tablet, &routed_message);

    assert!(
        phone_key_shared_ids
            .iter()
            .all(|event_id| {
                let response = tablet.call(RpcMethod::AssertNow {
                    predicate: format!("has_event:{event_id} >= 1"),
                });
                response.ok
            }),
        "the phone's real key_shared events should propagate to the tablet through the chained laptop pair sync"
    );
}
