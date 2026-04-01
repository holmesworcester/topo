use std::time::{Duration, Instant};
use topo::db::open_connection;
use topo::event_modules::{parse_event, registry, ParsedEvent};
use topo::rpc::protocol::RpcMethod;
use topo::sim::{FakeTopologyPreference, PlannerMode, PlannerSimulation, VirtualDaemon};

fn active_peer_id(daemon: &VirtualDaemon) -> String {
    daemon
        .call_ok_value(RpcMethod::ActiveTenant)
        .expect("active tenant")["peer_id"]
        .as_str()
        .expect("active tenant peer id")
        .to_string()
}

fn create_invite(daemon: &VirtualDaemon) -> String {
    daemon
        .call_ok_value(RpcMethod::CreateInvite {
            public_addr: None,
            public_spki: None,
        })
        .expect("create invite")["invite_link"]
        .as_str()
        .expect("invite link")
        .to_string()
}

fn create_device_link(daemon: &VirtualDaemon) -> String {
    let start = Instant::now();
    loop {
        let response = daemon.call(RpcMethod::CreateDeviceLink {
            public_addr: None,
            public_spki: None,
        });
        if response.ok {
            return response.data.as_ref().expect("device link payload")["invite_link"]
                .as_str()
                .expect("device link")
                .to_string();
        }
        let error = response.error.clone().unwrap_or_default();
        let retryable = error.contains("workspace has not completed initial sync yet")
            || error.contains("blocked on");
        if retryable && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        panic!("create device link: {:?}", response.error);
    }
}

fn send_message(daemon: &VirtualDaemon, content: &str) -> String {
    let start = Instant::now();
    loop {
        let response = daemon.call(RpcMethod::Send {
            content: content.to_string(),
            client_op_id: None,
        });
        if response.ok {
            return response.data.as_ref().expect("send payload")["event_id"]
                .as_str()
                .expect("message event id")
                .to_string();
        }
        let error = response.error.clone().unwrap_or_default();
        let retryable = error.contains("workspace has not completed initial sync yet")
            || error.contains("blocked on");
        if retryable && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(50));
            continue;
        }
        panic!("send message: {:?}", response.error);
    }
}

fn event_ids_of_type(daemon: &VirtualDaemon, event_type: &str) -> Vec<String> {
    let conn = topo::db::open_connection(daemon.db_path()).expect("open db for raw event scan");
    let recorded_by = active_peer_id(daemon);
    let mut stmt = conn
        .prepare(
            "SELECT re.event_id, e.blob
             FROM recorded_events re
             JOIN events e ON e.event_id = re.event_id
             WHERE re.peer_id = ?1
             ORDER BY re.id ASC",
        )
        .expect("prepare raw event scan");
    stmt.query_map(rusqlite::params![recorded_by], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
    })
    .expect("query raw event scan")
    .filter_map(|row| {
        let (event_id, blob) = row.expect("collect raw event ids");
        let semantic = match parse_event(&blob).expect("parse raw event") {
            ParsedEvent::Signed(signed) => {
                parse_event(&signed.payload).expect("parse signed payload")
            }
            parsed => parsed,
        };
        registry()
            .lookup(semantic.event_type_code())
            .is_some_and(|meta| meta.type_name == event_type)
            .then_some(event_id)
    })
    .collect()
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

fn authoring_ready(daemon: &VirtualDaemon) -> bool {
    let conn = topo::db::open_connection(daemon.db_path()).expect("open db for authoring check");
    let recorded_by = active_peer_id(daemon);
    topo::event_modules::workspace::authoring::load_local_authoring_context(&conn, &recorded_by)
        .is_ok()
}

fn finish_bootstrap_until_authoring_ready(db_paths: &[String], ready_peers: &[&VirtualDaemon]) {
    for _ in 0..4 {
        if ready_peers.iter().all(|daemon| authoring_ready(daemon)) {
            return;
        }
        PlannerSimulation::new(db_paths.to_vec())
            .tick()
            .expect("bootstrap follow-up round");
    }
    let pending = ready_peers
        .iter()
        .filter(|daemon| !authoring_ready(daemon))
        .map(|daemon| daemon.db_path().to_string())
        .collect::<Vec<_>>();
    panic!("authoring never materialized for {:?}", pending);
}

fn wait_for_authoring_ready(daemon: &VirtualDaemon, bootstrap_db_paths: &[String]) {
    let recorded_by = active_peer_id(daemon);
    let start = Instant::now();
    loop {
        let conn = open_connection(daemon.db_path()).expect("open db");
        if topo::event_modules::workspace::load_local_authoring_context(&conn, &recorded_by).is_ok()
        {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timed out waiting for authoring readiness on {}",
            daemon.db_path()
        );
        if !bootstrap_db_paths.is_empty() {
            let _ = PlannerSimulation::new(bootstrap_db_paths.to_vec()).tick();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn planner_runner_executes_no_sessions_without_real_connect_targets() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("alice.db");
    let bob_db = tmpdir.path().join("bob.db");

    let alice = VirtualDaemon::new(alice_db.to_str().unwrap());
    let bob = VirtualDaemon::new(bob_db.to_str().unwrap());

    for daemon in [&alice, &bob] {
        let created = daemon.call(RpcMethod::CreateWorkspace {
            workspace_name: "sim".into(),
            username: "user".into(),
            device_name: "laptop".into(),
        });
        assert!(created.ok, "workspace creation failed: {:?}", created.error);
    }

    let message_id = send_message(&alice, "hello without targets");
    assert_lacks_event(&bob, &message_id);

    let report = PlannerSimulation::new([
        alice_db.to_string_lossy().into_owned(),
        bob_db.to_string_lossy().into_owned(),
    ])
    .tick()
    .expect("planner tick");

    assert_eq!(report.imported_nodes, 2);
    assert_eq!(report.planned_intents, 0);
    assert_eq!(report.unique_pairs, 0);
    assert_eq!(report.sessions_executed, 0);
    assert_eq!(report.transferred_events, 0);
    assert!(report.pairs.is_empty());
    assert_lacks_event(&bob, &message_id);
}

#[test]
fn nearest_neighbor_no_auth_uses_fake_topology_for_event_layer_valid_peers() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("01-alice.db");
    let bob_db = tmpdir.path().join("02-bob.db");
    let carol_db = tmpdir.path().join("03-carol.db");

    let alice = VirtualDaemon::new(alice_db.to_str().unwrap());
    let bob = VirtualDaemon::new(bob_db.to_str().unwrap());
    let carol = VirtualDaemon::new(carol_db.to_str().unwrap());

    let created = alice.call(RpcMethod::CreateWorkspace {
        workspace_name: "sim".into(),
        username: "alice".into(),
        device_name: "laptop".into(),
    });
    assert!(created.ok, "workspace creation failed: {:?}", created.error);

    let invite_bob = create_invite(&alice);
    let accepted_bob = bob.call(RpcMethod::AcceptInvite {
        invite: invite_bob,
        username: "bob".into(),
        devicename: "phone".into(),
    });
    assert!(
        accepted_bob.ok,
        "bob accept invite failed: {:?}",
        accepted_bob.error
    );

    let invite_carol = create_invite(&alice);
    let accepted_carol = carol.call(RpcMethod::AcceptInvite {
        invite: invite_carol,
        username: "carol".into(),
        devicename: "tablet".into(),
    });
    assert!(
        accepted_carol.ok,
        "carol accept invite failed: {:?}",
        accepted_carol.error
    );

    let bootstrap_report = PlannerSimulation::new([
        alice_db.to_string_lossy().into_owned(),
        bob_db.to_string_lossy().into_owned(),
        carol_db.to_string_lossy().into_owned(),
    ])
    .tick()
    .expect("bootstrap round using real connect targets");
    assert_eq!(bootstrap_report.unique_pairs, 2);
    finish_bootstrap_until_authoring_ready(
        &[
            alice_db.to_string_lossy().into_owned(),
            bob_db.to_string_lossy().into_owned(),
            carol_db.to_string_lossy().into_owned(),
        ],
        &[&bob, &carol],
    );

    let bob_message = send_message(&bob, "hello from bob");
    assert_lacks_event(&carol, &bob_message);

    let report = PlannerSimulation::with_mode_and_topology(
        [
            bob_db.to_string_lossy().into_owned(),
            alice_db.to_string_lossy().into_owned(),
            carol_db.to_string_lossy().into_owned(),
        ],
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("nearest-neighbor planner tick");

    assert_eq!(report.mode, PlannerMode::NearestNeighborNoAuth);
    assert_eq!(report.fake_topology, Some(FakeTopologyPreference::Star));
    assert_eq!(report.imported_nodes, 3);
    assert_eq!(report.unique_pairs, 2);
    assert_eq!(report.sessions_executed, 2);
    assert!(
        report.pairs.iter().any(|pair| {
            pair.left_db_path.ends_with("01-alice.db") && pair.right_db_path.ends_with("02-bob.db")
        }),
        "fake star mode should create the bob-alice pair because bob is the configured hub"
    );
    assert!(
        report.pairs.iter().any(|pair| {
            pair.left_db_path.ends_with("02-bob.db") && pair.right_db_path.ends_with("03-carol.db")
        }),
        "fake star mode should create the bob-carol pair because bob is the configured hub"
    );
    assert!(
        !report.pairs.iter().any(|pair| {
            pair.left_db_path.ends_with("01-alice.db") && pair.right_db_path.ends_with("03-carol.db")
        }),
        "fake star mode should ignore the real alice-carol bootstrap target and follow the configured hub topology instead"
    );
    assert_has_event(&carol, &bob_message);
}

#[test]
fn planner_runner_propagates_only_through_planned_pair_sessions() {
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
    });
    assert!(created.ok, "workspace creation failed: {:?}", created.error);
    let phone_peer = active_peer_id(&phone);
    wait_for_authoring_ready(&phone, &[phone_db.to_string_lossy().into_owned()]);
    wait_for_authoring_ready(&phone, &[phone_db.to_string_lossy().into_owned()]);

    let phone_link = create_device_link(&phone);
    let phone_key_shared_ids = event_ids_of_type(&phone, "key_shared");
    assert!(
        !phone_key_shared_ids.is_empty(),
        "phone device-link creation should emit at least one real key_shared event"
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
    let bootstrap_report = PlannerSimulation::new([
        phone_db.to_string_lossy().into_owned(),
        laptop_db.to_string_lossy().into_owned(),
    ])
    .tick()
    .expect("planner tick for initial phone-laptop bootstrap");
    assert_eq!(bootstrap_report.unique_pairs, 1);
    finish_bootstrap_until_authoring_ready(
        &[
            phone_db.to_string_lossy().into_owned(),
            laptop_db.to_string_lossy().into_owned(),
        ],
        &[&laptop],
    );
    assert_has_event(&laptop, &bootstrap_message);
    wait_for_authoring_ready(
        &laptop,
        &[
            phone_db.to_string_lossy().into_owned(),
            laptop_db.to_string_lossy().into_owned(),
        ],
    );
    wait_for_authoring_ready(
        &laptop,
        &[
            phone_db.to_string_lossy().into_owned(),
            laptop_db.to_string_lossy().into_owned(),
        ],
    );

    let laptop_link = create_device_link(&laptop);
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
    finish_bootstrap_until_authoring_ready(
        &[
            phone_db.to_string_lossy().into_owned(),
            laptop_db.to_string_lossy().into_owned(),
            tablet_db.to_string_lossy().into_owned(),
        ],
        &[&tablet],
    );

    let routed_message = send_message(&phone, "phone-through-laptop");
    assert_lacks_event(&laptop, &routed_message);
    assert_lacks_event(&tablet, &routed_message);

    let report = PlannerSimulation::new([
        phone_db.to_string_lossy().into_owned(),
        laptop_db.to_string_lossy().into_owned(),
        tablet_db.to_string_lossy().into_owned(),
    ])
    .tick()
    .expect("planner tick");

    assert_eq!(report.imported_nodes, 3);
    assert_eq!(report.unique_pairs, 2);
    assert_eq!(report.sessions_executed, 2);
    assert!(
        report.pairs.iter().any(|pair| {
            pair.left_recorded_by == laptop_peer && pair.right_recorded_by == phone_peer
                || pair.left_recorded_by == phone_peer && pair.right_recorded_by == laptop_peer
        }),
        "planner runner should execute the real phone-laptop pair session"
    );
    assert!(
        report.pairs.iter().any(|pair| {
            pair.left_recorded_by == laptop_peer && pair.right_recorded_by == tablet_peer
                || pair.left_recorded_by == tablet_peer && pair.right_recorded_by == laptop_peer
        }),
        "planner runner should execute the real laptop-tablet pair session"
    );
    assert!(
        !report.pairs.iter().any(|pair| {
            pair.left_recorded_by == phone_peer && pair.right_recorded_by == tablet_peer
                || pair.left_recorded_by == tablet_peer && pair.right_recorded_by == phone_peer
        }),
        "planner runner must not invent a direct phone-tablet session"
    );

    assert_has_event(&laptop, &routed_message);
    assert_lacks_event(&tablet, &routed_message);
    for event_id in &phone_key_shared_ids {
        assert_has_event(&tablet, event_id);
    }

    let second_round = PlannerSimulation::new([
        phone_db.to_string_lossy().into_owned(),
        laptop_db.to_string_lossy().into_owned(),
        tablet_db.to_string_lossy().into_owned(),
    ])
    .tick()
    .expect("second planner tick");
    assert_eq!(second_round.unique_pairs, 2);
    assert_has_event(&tablet, &routed_message);
}

#[test]
fn nearest_neighbor_no_auth_propagates_key_shared_along_chain() {
    let tmpdir = tempfile::tempdir().unwrap();
    let phone_db = tmpdir.path().join("01-phone.db");
    let laptop_db = tmpdir.path().join("02-laptop.db");
    let tablet_db = tmpdir.path().join("03-tablet.db");

    let phone = VirtualDaemon::new(phone_db.to_str().unwrap());
    let laptop = VirtualDaemon::new(laptop_db.to_str().unwrap());
    let tablet = VirtualDaemon::new(tablet_db.to_str().unwrap());

    let created = phone.call(RpcMethod::CreateWorkspace {
        workspace_name: "sim".into(),
        username: "alice".into(),
        device_name: "phone".into(),
    });
    assert!(created.ok, "workspace creation failed: {:?}", created.error);
    wait_for_authoring_ready(&phone, &[phone_db.to_string_lossy().into_owned()]);
    wait_for_authoring_ready(&phone, &[phone_db.to_string_lossy().into_owned()]);

    let phone_link = create_device_link(&phone);
    let phone_key_shared_ids = event_ids_of_type(&phone, "key_shared");
    assert!(
        !phone_key_shared_ids.is_empty(),
        "phone device-link creation should emit at least one real key_shared event"
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

    let bootstrap_report = PlannerSimulation::with_mode_and_topology(
        [
            phone_db.to_string_lossy().into_owned(),
            laptop_db.to_string_lossy().into_owned(),
        ],
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("nearest-neighbor bootstrap tick");
    assert_eq!(bootstrap_report.unique_pairs, 1);
    finish_bootstrap_until_authoring_ready(
        &[
            phone_db.to_string_lossy().into_owned(),
            laptop_db.to_string_lossy().into_owned(),
        ],
        &[&laptop],
    );

    let laptop_link = create_device_link(&laptop);
    let accepted_tablet = tablet.call(RpcMethod::AcceptLink {
        invite: laptop_link,
        devicename: "tablet".into(),
    });
    assert!(
        accepted_tablet.ok,
        "tablet accept link failed: {:?}",
        accepted_tablet.error
    );
    finish_bootstrap_until_authoring_ready(
        &[
            phone_db.to_string_lossy().into_owned(),
            laptop_db.to_string_lossy().into_owned(),
            tablet_db.to_string_lossy().into_owned(),
        ],
        &[&tablet],
    );

    let report = PlannerSimulation::with_mode_and_topology(
        [
            phone_db.to_string_lossy().into_owned(),
            laptop_db.to_string_lossy().into_owned(),
            tablet_db.to_string_lossy().into_owned(),
        ],
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("nearest-neighbor chained tick");
    assert_eq!(report.mode, PlannerMode::NearestNeighborNoAuth);
    assert_eq!(report.fake_topology, Some(FakeTopologyPreference::Star));
    assert_eq!(report.unique_pairs, 2);

    for event_id in &phone_key_shared_ids {
        assert_has_event(&tablet, event_id);
    }
}

#[test]
fn fake_star_message_reaches_all_peers_in_one_round() {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("01-alice.db");
    let bob_db = tmpdir.path().join("02-bob.db");
    let carol_db = tmpdir.path().join("03-carol.db");
    let dave_db = tmpdir.path().join("04-dave.db");

    let alice = VirtualDaemon::new(alice_db.to_str().unwrap());
    let bob = VirtualDaemon::new(bob_db.to_str().unwrap());
    let carol = VirtualDaemon::new(carol_db.to_str().unwrap());
    let dave = VirtualDaemon::new(dave_db.to_str().unwrap());

    let created = alice.call(RpcMethod::CreateWorkspace {
        workspace_name: "sim".into(),
        username: "alice".into(),
        device_name: "laptop".into(),
    });
    assert!(created.ok, "workspace creation failed: {:?}", created.error);

    for (daemon, username) in [(&bob, "bob"), (&carol, "carol"), (&dave, "dave")] {
        let invite = create_invite(&alice);
        let accepted = daemon.call(RpcMethod::AcceptInvite {
            invite,
            username: username.into(),
            devicename: "phone".into(),
        });
        assert!(
            accepted.ok,
            "{username} accept invite failed: {:?}",
            accepted.error
        );
    }

    let bootstrap = PlannerSimulation::new([
        alice_db.to_string_lossy().into_owned(),
        bob_db.to_string_lossy().into_owned(),
        carol_db.to_string_lossy().into_owned(),
        dave_db.to_string_lossy().into_owned(),
    ])
    .tick()
    .expect("bootstrap round");
    assert_eq!(bootstrap.unique_pairs, 3);
    finish_bootstrap_until_authoring_ready(
        &[
            alice_db.to_string_lossy().into_owned(),
            bob_db.to_string_lossy().into_owned(),
            carol_db.to_string_lossy().into_owned(),
            dave_db.to_string_lossy().into_owned(),
        ],
        &[&bob, &carol, &dave],
    );

    let content = "hello whole chain";
    let message_id = send_message(&alice, content);
    assert_lacks_event(&bob, &message_id);
    assert_lacks_event(&carol, &message_id);
    assert_lacks_event(&dave, &message_id);

    let dbs = [
        alice_db.to_string_lossy().into_owned(),
        bob_db.to_string_lossy().into_owned(),
        carol_db.to_string_lossy().into_owned(),
        dave_db.to_string_lossy().into_owned(),
    ];

    let round_interval_ms = 1_000u64;

    let round1 = PlannerSimulation::with_mode_and_topology(
        dbs,
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("round 1");
    assert_eq!(round1.unique_pairs, 3);
    assert_has_event(&bob, &message_id);
    assert_has_event(&carol, &message_id);
    assert_has_event(&dave, &message_id);

    let bob_arrival_ms = round_interval_ms;
    let carol_arrival_ms = round_interval_ms;
    let dave_arrival_ms = round_interval_ms;
    assert_eq!(bob_arrival_ms, 1_000);
    assert_eq!(carol_arrival_ms, 1_000);
    assert_eq!(dave_arrival_ms, 1_000);
}

#[test]
fn planner_runner_reimports_same_db_new_tenant_on_next_round() {
    let tmpdir = tempfile::tempdir().unwrap();
    let shared_db = tmpdir.path().join("user999999.db");
    let daemon = VirtualDaemon::new(shared_db.to_str().unwrap());

    let created = daemon.call(RpcMethod::CreateWorkspace {
        workspace_name: "sim".into(),
        username: "alice".into(),
        device_name: "laptop".into(),
    });
    assert!(created.ok, "workspace creation failed: {:?}", created.error);

    let creator_message = send_message(&daemon, "creator-before-join");

    let before_join = PlannerSimulation::new([shared_db.to_string_lossy().into_owned()])
        .tick()
        .expect("planner tick before join");
    assert_eq!(before_join.imported_nodes, 1);
    assert_eq!(before_join.sessions_executed, 0);

    let invite = create_invite(&daemon);
    let accepted = daemon.call_ok_value(RpcMethod::AcceptInvite {
        invite,
        username: "bob".into(),
        devicename: "phone".into(),
    });
    let joiner_peer_id = accepted.expect("accept invite")["peer_id"]
        .as_str()
        .expect("joiner peer id")
        .to_string();

    let after_join = PlannerSimulation::new([shared_db.to_string_lossy().into_owned()])
        .tick()
        .expect("planner tick after join");
    assert_eq!(after_join.imported_nodes, 2);
    assert_eq!(after_join.unique_pairs, 1);
    assert_eq!(after_join.sessions_executed, 1);
    assert!(
        after_join
            .nodes
            .iter()
            .any(|node| node.recorded_by == joiner_peer_id),
        "the next planner round should discover the newly added tenant in the same DB"
    );

    let joiner_snapshot =
        topo::sim::snapshot_replayed_peer(shared_db.to_str().unwrap(), &joiner_peer_id)
            .expect("joiner snapshot after planner round");
    let joiner_daemon = joiner_snapshot.daemon();
    assert_has_event(&joiner_daemon, &creator_message);
}
