use std::collections::BTreeSet;

use topo::crypto::event_id_to_base64;
use topo::db::open_connection;
use topo::rpc::protocol::RpcMethod;
use topo::sim::{
    create_encrypted_message_with_key, emit_key_requests_for_dbs,
    emit_key_shared_responses_for_dbs, seed_deterministic_key_secret, FakeTopologyPreference,
    KeyResponsePolicy, PlannerMode, PlannerSimulation, VirtualDaemon,
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

fn snapshot_has_message_content(daemon: &VirtualDaemon, content: &str) -> bool {
    let recorded_by = active_peer_id(daemon);
    let snapshot =
        topo::sim::snapshot_replayed_peer(daemon.db_path(), &recorded_by).expect("peer snapshot");
    let messages = snapshot
        .daemon()
        .call_ok_value(RpcMethod::Messages { limit: 100 })
        .expect("messages via snapshot rpc");
    messages["messages"]
        .as_array()
        .expect("messages array")
        .iter()
        .any(|message| message["content"].as_str() == Some(content))
}

#[derive(Debug, Clone, Default)]
struct RepairBenchmark {
    request_events: usize,
    response_events: usize,
    response_duplicates: usize,
    transferred_key_request_events: usize,
    transferred_key_shared_events: usize,
    suppressed_key_shared_events: usize,
    repair_rounds: usize,
}

fn distinct_key_request_events(db_paths: &[String], blocked_event_id_b64: &str) -> usize {
    let mut seen = BTreeSet::new();
    for db_path in db_paths {
        let conn = open_connection(db_path).expect("open db");
        let mut stmt = conn
            .prepare(
                "SELECT event_id
                 FROM key_requests
                 WHERE blocked_event_id = ?1",
            )
            .expect("prepare key_requests query");
        let rows = stmt
            .query_map(rusqlite::params![blocked_event_id_b64], |row| {
                row.get::<_, String>(0)
            })
            .expect("query key_requests");
        for row in rows {
            seen.insert(row.expect("key_request row"));
        }
    }
    seen.len()
}

fn distinct_key_shared_events_for_key(db_paths: &[String], key_event_id_b64: &str) -> usize {
    let mut seen = BTreeSet::new();
    for db_path in db_paths {
        let conn = open_connection(db_path).expect("open db");
        let mut stmt = conn
            .prepare(
                "SELECT event_id
                 FROM key_shared
                 WHERE key_event_id = ?1",
            )
            .expect("prepare key_shared query");
        let rows = stmt
            .query_map(rusqlite::params![key_event_id_b64], |row| {
                row.get::<_, String>(0)
            })
            .expect("query key_shared");
        for row in rows {
            seen.insert(row.expect("key_shared row"));
        }
    }
    seen.len()
}

fn run_key_repair_benchmark(policy: KeyResponsePolicy) -> RepairBenchmark {
    let tmpdir = tempfile::tempdir().unwrap();
    let alice_db = tmpdir.path().join("01-alice.db");
    let bob_db = tmpdir.path().join("02-bob.db");
    let carol_db = tmpdir.path().join("03-carol.db");
    let dave_db = tmpdir.path().join("04-dave.db");
    let erin_db = tmpdir.path().join("05-erin.db");

    let alice = VirtualDaemon::new(alice_db.to_str().unwrap());
    let bob = VirtualDaemon::new(bob_db.to_str().unwrap());
    let carol = VirtualDaemon::new(carol_db.to_str().unwrap());
    let dave = VirtualDaemon::new(dave_db.to_str().unwrap());
    let erin = VirtualDaemon::new(erin_db.to_str().unwrap());

    let created = alice.call(RpcMethod::CreateWorkspace {
        workspace_name: "sim".into(),
        username: "alice".into(),
        device_name: "laptop".into(),
    });
    assert!(created.ok, "workspace creation failed: {:?}", created.error);

    for (daemon, username, addr) in [
        (&bob, "bob", "127.0.0.1:4242"),
        (&carol, "carol", "127.0.0.1:4343"),
        (&dave, "dave", "127.0.0.1:4444"),
        (&erin, "erin", "127.0.0.1:4545"),
    ] {
        let invite = create_invite(&alice, addr);
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

    let db_paths = vec![
        alice_db.to_string_lossy().into_owned(),
        bob_db.to_string_lossy().into_owned(),
        carol_db.to_string_lossy().into_owned(),
        dave_db.to_string_lossy().into_owned(),
        erin_db.to_string_lossy().into_owned(),
    ];
    let fake_star_db_paths = vec![
        bob_db.to_string_lossy().into_owned(),
        alice_db.to_string_lossy().into_owned(),
        carol_db.to_string_lossy().into_owned(),
        dave_db.to_string_lossy().into_owned(),
        erin_db.to_string_lossy().into_owned(),
    ];

    let bootstrap = PlannerSimulation::new(db_paths.clone())
        .tick()
        .expect("bootstrap round");
    assert_eq!(bootstrap.unique_pairs, 4);

    let alice_peer = active_peer_id(&alice);
    let bob_peer = active_peer_id(&bob);
    let key_bytes = [0xAB; 32];
    let alice_key = seed_deterministic_key_secret(&db_paths[0], &alice_peer, key_bytes)
        .expect("seed alice key");
    let bob_key =
        seed_deterministic_key_secret(&db_paths[1], &bob_peer, key_bytes).expect("seed bob key");
    assert_eq!(
        alice_key, bob_key,
        "holders must share the same key_event_id"
    );

    let content = "fresh-key repair path";
    let encrypted_event_id =
        create_encrypted_message_with_key(&db_paths[0], &alice_peer, &alice_key, content)
            .expect("create encrypted message with fresh key");
    let encrypted_event_id_b64 = event_id_to_base64(&encrypted_event_id);
    let key_event_id_b64 = event_id_to_base64(&alice_key);

    let message_round_to_hub = PlannerSimulation::with_mode_and_topology(
        fake_star_db_paths.clone(),
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("message propagation round to hub");
    assert_eq!(message_round_to_hub.unique_pairs, 4);
    let message_round_to_requesters = PlannerSimulation::with_mode_and_topology(
        fake_star_db_paths.clone(),
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("message propagation round to requesters");
    assert_eq!(message_round_to_requesters.unique_pairs, 4);
    assert!(snapshot_has_message_content(&bob, content));
    assert!(!snapshot_has_message_content(&carol, content));
    assert!(!snapshot_has_message_content(&dave, content));
    assert!(!snapshot_has_message_content(&erin, content));

    let mut benchmark = RepairBenchmark::default();
    let _requests = emit_key_requests_for_dbs(&db_paths).expect("emit key requests");
    let request_round = PlannerSimulation::with_mode_and_topology(
        fake_star_db_paths.clone(),
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("request propagation round to hub");
    benchmark.transferred_key_request_events =
        benchmark.transferred_key_request_events.saturating_add(
            request_round
                .pairs
                .iter()
                .map(|pair| {
                    pair.stats.left_to_right.transferred_key_request_events
                        + pair.stats.right_to_left.transferred_key_request_events
                })
                .sum::<usize>(),
        );

    let _responses = emit_key_shared_responses_for_dbs(&db_paths, policy)
        .expect("emit initial key shared responses");
    let response_round_one = PlannerSimulation::with_mode_and_topology(
        fake_star_db_paths.clone(),
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("initial response propagation round");
    benchmark.transferred_key_shared_events =
        benchmark.transferred_key_shared_events.saturating_add(
            response_round_one
                .pairs
                .iter()
                .map(|pair| {
                    pair.stats.left_to_right.transferred_key_shared_events
                        + pair.stats.right_to_left.transferred_key_shared_events
                })
                .sum::<usize>(),
        );
    benchmark.suppressed_key_shared_events = benchmark.suppressed_key_shared_events.saturating_add(
        response_round_one
            .pairs
            .iter()
            .map(|pair| {
                pair.stats.left_to_right.suppressed_key_shared_events
                    + pair.stats.right_to_left.suppressed_key_shared_events
            })
            .sum::<usize>(),
    );
    benchmark.repair_rounds = 1;

    assert!(snapshot_has_message_content(&carol, content));
    assert!(snapshot_has_message_content(&dave, content));
    assert!(snapshot_has_message_content(&erin, content));

    let _follow_up_responses = emit_key_shared_responses_for_dbs(&db_paths, policy)
        .expect("emit follow-up key shared responses");
    let response_round_two = PlannerSimulation::with_mode_and_topology(
        fake_star_db_paths.clone(),
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("follow-up response propagation round");
    benchmark.transferred_key_shared_events =
        benchmark.transferred_key_shared_events.saturating_add(
            response_round_two
                .pairs
                .iter()
                .map(|pair| {
                    pair.stats.left_to_right.transferred_key_shared_events
                        + pair.stats.right_to_left.transferred_key_shared_events
                })
                .sum::<usize>(),
        );
    benchmark.suppressed_key_shared_events = benchmark.suppressed_key_shared_events.saturating_add(
        response_round_two
            .pairs
            .iter()
            .map(|pair| {
                pair.stats.left_to_right.suppressed_key_shared_events
                    + pair.stats.right_to_left.suppressed_key_shared_events
            })
            .sum::<usize>(),
    );
    benchmark.repair_rounds = 2;

    benchmark.request_events = distinct_key_request_events(&db_paths, &encrypted_event_id_b64);
    benchmark.response_events = distinct_key_shared_events_for_key(&db_paths, &key_event_id_b64);
    benchmark.response_duplicates = benchmark
        .response_events
        .saturating_sub(benchmark.request_events);

    assert!(snapshot_has_message_content(&carol, content));
    assert!(snapshot_has_message_content(&dave, content));
    assert!(snapshot_has_message_content(&erin, content));

    benchmark
}

#[test]
fn fresh_key_request_and_response_propagation_unblocks_all_peers() {
    let stats = run_key_repair_benchmark(KeyResponsePolicy::BestObservedOnly);
    assert_eq!(
        stats.request_events, 3,
        "three blocked invitees should request the key"
    );
    assert!(
        stats.response_events <= 6,
        "best-observed repair should stay bounded to a small multiple of request count: {stats:?}"
    );
    assert!(
        stats.response_duplicates <= 3,
        "best-observed should keep duplicate responses bounded to at most one extra wave: {stats:?}"
    );
    assert!(stats.transferred_key_request_events >= 3);
    assert!(stats.transferred_key_shared_events >= 1);
}

#[test]
fn best_observed_only_reduces_duplicate_responses_vs_all_eligible() {
    let all = run_key_repair_benchmark(KeyResponsePolicy::AllEligible);
    let suppressed = run_key_repair_benchmark(KeyResponsePolicy::BestObservedOnly);
    println!("all={all:?} suppressed={suppressed:?}");

    assert!(
        suppressed.response_duplicates < all.response_duplicates,
        "best-observed-only should not create more duplicate responses: all={all:?} suppressed={suppressed:?}"
    );
    assert!(
        suppressed.response_events < all.response_events,
        "best-observed-only should emit fewer total responses: all={all:?} suppressed={suppressed:?}"
    );
    assert!(
        suppressed.response_duplicates < all.response_duplicates,
        "best-observed-only should emit fewer duplicate responses: all={all:?} suppressed={suppressed:?}"
    );
}
