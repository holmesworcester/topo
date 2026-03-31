use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use topo::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use topo::db::open_connection;
use topo::rpc::protocol::RpcMethod;
use topo::sim::{
    create_encrypted_message_with_key, create_key_rotation, create_removal,
    emit_key_requests_for_dbs, emit_key_shared_responses_for_dbs, seed_deterministic_key_secret,
    FakeTopologyPreference, KeyResponsePolicy, PlannerMode, PlannerSimulation, VirtualDaemon,
};
use topo::state::db::queue::current_timestamp_ms;
use topo::state::pipeline::{drain_project_queue, ingest_now};

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

fn emit_key_requests_retry(db_paths: &[String]) -> topo::sim::KeyRepairEmitStats {
    let start = Instant::now();
    loop {
        match emit_key_requests_for_dbs(db_paths) {
            Ok(stats) => return stats,
            Err(err) => {
                let message = err.to_string();
                let retryable = message.contains("workspace has not completed initial sync yet")
                    || message.contains("blocked on");
                if retryable && start.elapsed() < Duration::from_secs(10) {
                    let _ = PlannerSimulation::new(db_paths.to_vec()).tick();
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                }
                panic!("emit key requests: {message}");
            }
        }
    }
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
            "timed out waiting for authoring readiness on {} (invites_accepted={}, workspaces={}, users={}, peers_shared={}, peer_secrets={}, recorded_peer_secret_events={}, blocked_events={}, blocked_details={:?})",
            daemon.db_path(),
            conn.query_row(
                "SELECT COUNT(*) FROM invites_accepted WHERE recorded_by = ?1",
                rusqlite::params![&recorded_by],
                |row| row.get::<_, i64>(0)
            )
            .unwrap_or(-1),
            conn.query_row(
                "SELECT COUNT(*) FROM workspaces WHERE recorded_by = ?1",
                rusqlite::params![&recorded_by],
                |row| row.get::<_, i64>(0)
            )
            .unwrap_or(-1),
            conn.query_row(
                "SELECT COUNT(*) FROM users WHERE recorded_by = ?1",
                rusqlite::params![&recorded_by],
                |row| row.get::<_, i64>(0)
            )
            .unwrap_or(-1),
            conn.query_row(
                "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
                rusqlite::params![&recorded_by],
                |row| row.get::<_, i64>(0)
            )
            .unwrap_or(-1),
            conn.query_row(
                "SELECT COUNT(*) FROM peer_secrets WHERE recorded_by = ?1",
                rusqlite::params![&recorded_by],
                |row| row.get::<_, i64>(0)
            )
            .unwrap_or(-1),
            conn.query_row(
                "SELECT COUNT(*)
                 FROM recorded_events re
                 JOIN events e ON e.event_id = re.event_id
                 WHERE re.peer_id = ?1
                   AND e.event_type = 'peer_secret'",
                rusqlite::params![&recorded_by],
                |row| row.get::<_, i64>(0)
            )
            .unwrap_or(-1),
            conn.query_row(
                "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1",
                rusqlite::params![&recorded_by],
                |row| row.get::<_, i64>(0)
            )
            .unwrap_or(-1),
            {
                let mut stmt = conn
                    .prepare(
                        "SELECT be.event_id, e.event_type
                         FROM blocked_events be
                         JOIN events e ON e.event_id = be.event_id
                         WHERE be.peer_id = ?1
                         ORDER BY be.event_id ASC
                         LIMIT 8",
                    )
                    .expect("prepare blocked details");
                let rows = stmt
                    .query_map(rusqlite::params![&recorded_by], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })
                    .expect("query blocked details")
                    .collect::<Result<Vec<_>, _>>()
                    .expect("collect blocked details");
                rows
            },
        );
        if !bootstrap_db_paths.is_empty() {
            let _ = PlannerSimulation::new(bootstrap_db_paths.to_vec()).tick();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn snapshot_has_message_content(daemon: &VirtualDaemon, content: &str) -> bool {
    let messages = daemon
        .call_ok_value(RpcMethod::Messages { limit: 100 })
        .expect("messages via daemon rpc");
    messages["messages"]
        .as_array()
        .expect("messages array")
        .iter()
        .any(|message| message["content"].as_str() == Some(content))
}

fn recorded_event_count(db_path: &str, recorded_by: &str, event_id: &EventId) -> i64 {
    let conn = open_connection(db_path).expect("open db");
    conn.query_row(
        "SELECT COUNT(*)
         FROM recorded_events
         WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, event_id_to_base64(event_id)],
        |row| row.get::<_, i64>(0),
    )
    .expect("recorded event count")
}

fn valid_event_count(db_path: &str, recorded_by: &str, event_id: &EventId) -> i64 {
    let conn = open_connection(db_path).expect("open db");
    conn.query_row(
        "SELECT COUNT(*)
         FROM valid_events
         WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, event_id_to_base64(event_id)],
        |row| row.get::<_, i64>(0),
    )
    .expect("valid event count")
}

fn blocked_event_count(db_path: &str, recorded_by: &str, event_id: &EventId) -> i64 {
    let conn = open_connection(db_path).expect("open db");
    conn.query_row(
        "SELECT COUNT(*)
         FROM blocked_events
         WHERE peer_id = ?1 AND event_id = ?2",
        rusqlite::params![recorded_by, event_id_to_base64(event_id)],
        |row| row.get::<_, i64>(0),
    )
    .expect("blocked event count")
}

fn rejected_event_reason(db_path: &str, recorded_by: &str, event_id: &EventId) -> Option<String> {
    let conn = open_connection(db_path).expect("open db");
    conn.query_row(
        "SELECT reason
         FROM rejected_events
         WHERE peer_id = ?1 AND event_id = ?2
         LIMIT 1",
        rusqlite::params![recorded_by, event_id_to_base64(event_id)],
        |row| row.get::<_, String>(0),
    )
    .ok()
}

fn local_repair_recipient_material(daemon: &VirtualDaemon) -> (EventId, EventId) {
    let recorded_by = active_peer_id(daemon);
    let conn = open_connection(daemon.db_path()).expect("open db");
    let invite_event_id_b64: String = conn
        .query_row(
            "SELECT invite_event_id
             FROM invites_accepted
             WHERE recorded_by = ?1
             ORDER BY created_at ASC, event_id ASC
             LIMIT 1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .expect("invite_event_id");
    let invite_secret_event_id_b64: String = conn
        .query_row(
            "SELECT event_id
             FROM invite_secrets
             WHERE recorded_by = ?1
               AND invite_event_id = ?2
             ORDER BY created_at ASC, event_id ASC
             LIMIT 1",
            rusqlite::params![&recorded_by, &invite_event_id_b64],
            |row| row.get(0),
        )
        .expect("invite_secret event_id");
    (
        event_id_from_base64(&invite_event_id_b64).expect("recipient event id"),
        event_id_from_base64(&invite_secret_event_id_b64).expect("unwrap key event id"),
    )
}

#[derive(Debug, Clone, Default)]
struct RepairBenchmark {
    request_events: usize,
    response_events: usize,
    response_duplicates: usize,
    transferred_key_request_events: usize,
    suppressed_key_request_events: usize,
    follow_up_transferred_key_request_events: usize,
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

fn distinct_key_shared_events_for_recipient(
    db_paths: &[String],
    key_event_id_b64: &str,
    recipient_event_id: &EventId,
) -> usize {
    let recipient_b64 = event_id_to_base64(recipient_event_id);
    let mut seen = BTreeSet::new();
    for db_path in db_paths {
        let conn = open_connection(db_path).expect("open db");
        let mut stmt = conn
            .prepare(
                "SELECT event_id
                 FROM key_shared
                 WHERE key_event_id = ?1
                   AND recipient_event_id = ?2",
            )
            .expect("prepare key_shared recipient query");
        let rows = stmt
            .query_map(rusqlite::params![key_event_id_b64, &recipient_b64], |row| {
                row.get::<_, String>(0)
            })
            .expect("query key_shared recipient");
        for row in rows {
            seen.insert(row.expect("key_shared recipient row"));
        }
    }
    seen.len()
}

fn event_blob_by_id(db_path: &str, event_id: &EventId) -> Vec<u8> {
    let conn = open_connection(db_path).expect("open db");
    let event_id_b64 = event_id_to_base64(event_id);
    conn.query_row(
        "SELECT blob FROM events WHERE event_id = ?1",
        rusqlite::params![&event_id_b64],
        |row| row.get(0),
    )
    .expect("event blob by id")
}

fn newest_key_request_event_id(
    db_path: &str,
    recorded_by: &str,
    key_event_id: &EventId,
) -> EventId {
    let conn = open_connection(db_path).expect("open db");
    let key_event_id_b64 = event_id_to_base64(key_event_id);
    let event_id_b64: String = conn
        .query_row(
            "SELECT event_id
             FROM key_requests
             WHERE recorded_by = ?1
               AND key_event_id = ?2
             ORDER BY rowid DESC
             LIMIT 1",
            rusqlite::params![recorded_by, &key_event_id_b64],
            |row| row.get(0),
        )
        .expect("newest key_request event_id");
    event_id_from_base64(&event_id_b64).expect("key_request event id")
}

fn ingest_selected_events(
    dest_db_path: &str,
    dest_recorded_by: &str,
    source_tag: &str,
    event_ids: &[EventId],
    source_db_path: &str,
) {
    let now_ms = current_timestamp_ms();
    let batch = event_ids
        .iter()
        .map(|event_id| {
            (
                *event_id,
                event_blob_by_id(source_db_path, event_id),
                dest_recorded_by.to_string(),
                source_tag.to_string(),
                now_ms,
                now_ms,
            )
        })
        .collect::<Vec<_>>();
    let persisted = ingest_now(dest_db_path, batch).expect("ingest selected events");
    assert!(
        persisted > 0,
        "selected ingest should persist at least one event"
    );
    let _ = drain_project_queue(dest_db_path, dest_recorded_by, 1000);
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
    let bootstrap_follow_up = PlannerSimulation::new(db_paths.clone())
        .tick()
        .expect("bootstrap follow-up round");
    assert_eq!(bootstrap_follow_up.unique_pairs, 4);
    wait_for_authoring_ready(&bob, &db_paths);
    wait_for_authoring_ready(&carol, &db_paths);
    wait_for_authoring_ready(&dave, &db_paths);
    wait_for_authoring_ready(&erin, &db_paths);

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
    assert!(
        snapshot_has_message_content(&bob, content),
        "bob missing content after message rounds: to_hub={:?} to_requesters={:?} bob_recorded_encrypted={} bob_valid_encrypted={} bob_blocked_encrypted={} bob_rejected_encrypted={:?} bob_messages={} bob_users={} bob_peers_shared={} bob_snapshot_messages={}",
        message_round_to_hub,
        message_round_to_requesters,
        recorded_event_count(&db_paths[1], &bob_peer, &encrypted_event_id),
        valid_event_count(&db_paths[1], &bob_peer, &encrypted_event_id),
        blocked_event_count(&db_paths[1], &bob_peer, &encrypted_event_id),
        rejected_event_reason(&db_paths[1], &bob_peer, &encrypted_event_id),
        {
            let conn = open_connection(&db_paths[1]).expect("open bob db");
            conn.query_row(
                "SELECT COUNT(*) FROM messages WHERE recorded_by = ?1",
                rusqlite::params![&bob_peer],
                |row| row.get::<_, i64>(0),
            )
            .expect("bob message count")
        },
        {
            let conn = open_connection(&db_paths[1]).expect("open bob db");
            conn.query_row(
                "SELECT COUNT(*) FROM users WHERE recorded_by = ?1",
                rusqlite::params![&bob_peer],
                |row| row.get::<_, i64>(0),
            )
            .expect("bob user count")
        },
        {
            let conn = open_connection(&db_paths[1]).expect("open bob db");
            conn.query_row(
                "SELECT COUNT(*) FROM peers_shared WHERE recorded_by = ?1",
                rusqlite::params![&bob_peer],
                |row| row.get::<_, i64>(0),
            )
            .expect("bob peer_shared count")
        },
        bob.call_ok_value(RpcMethod::Messages { limit: 100 }).expect("bob messages"),
    );
    assert!(!snapshot_has_message_content(&carol, content));
    assert!(!snapshot_has_message_content(&dave, content));
    assert!(!snapshot_has_message_content(&erin, content));

    let mut benchmark = RepairBenchmark::default();
    let _requests = emit_key_requests_retry(&db_paths);
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
    benchmark.suppressed_key_request_events =
        benchmark.suppressed_key_request_events.saturating_add(
            response_round_one
                .pairs
                .iter()
                .map(|pair| {
                    pair.stats.left_to_right.suppressed_key_request_events
                        + pair.stats.right_to_left.suppressed_key_request_events
                })
                .sum::<usize>(),
        );
    benchmark.repair_rounds = 1;

    assert!(snapshot_has_message_content(&carol, content));
    assert!(snapshot_has_message_content(&dave, content));
    assert!(snapshot_has_message_content(&erin, content));

    let post_response_request_round = PlannerSimulation::with_mode_and_topology(
        fake_star_db_paths.clone(),
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("post-response request suppression round");
    benchmark.follow_up_transferred_key_request_events = benchmark
        .follow_up_transferred_key_request_events
        .saturating_add(
            post_response_request_round
                .pairs
                .iter()
                .map(|pair| {
                    pair.stats.left_to_right.transferred_key_request_events
                        + pair.stats.right_to_left.transferred_key_request_events
                })
                .sum::<usize>(),
        );
    benchmark.suppressed_key_request_events =
        benchmark.suppressed_key_request_events.saturating_add(
            post_response_request_round
                .pairs
                .iter()
                .map(|pair| {
                    pair.stats.left_to_right.suppressed_key_request_events
                        + pair.stats.right_to_left.suppressed_key_request_events
                })
                .sum::<usize>(),
        );

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
    assert_eq!(
        stats.follow_up_transferred_key_request_events, 0,
        "requests should stop propagating once any response is observed: {stats:?}"
    );
    assert!(
        stats.suppressed_key_request_events > 0,
        "post-response request sharing should be actively suppressed: {stats:?}"
    );
}

#[test]
fn request_suppression_keeps_response_policy_no_worse_than_all_eligible() {
    let all = run_key_repair_benchmark(KeyResponsePolicy::AllEligible);
    let suppressed = run_key_repair_benchmark(KeyResponsePolicy::BestObservedOnly);
    println!("all={all:?} suppressed={suppressed:?}");

    assert!(
        suppressed.response_duplicates <= all.response_duplicates,
        "best-observed-only should not create more duplicate responses: all={all:?} suppressed={suppressed:?}"
    );
    assert!(
        suppressed.response_events <= all.response_events,
        "best-observed-only should not emit more total responses: all={all:?} suppressed={suppressed:?}"
    );
    assert!(
        all.follow_up_transferred_key_request_events == 0
            && suppressed.follow_up_transferred_key_request_events == 0,
        "once any response exists, follow-up request propagation should stop under both policies: all={all:?} suppressed={suppressed:?}"
    );
    assert!(
        all.suppressed_key_request_events > 0 && suppressed.suppressed_key_request_events > 0,
        "request suppression should actively block further request sharing under both policies: all={all:?} suppressed={suppressed:?}"
    );
}

#[test]
fn removed_peer_does_not_receive_key_shared_response_for_frontier() {
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

    for (daemon, username, addr) in [
        (&bob, "bob", "127.0.0.1:4242"),
        (&carol, "carol", "127.0.0.1:4343"),
        (&dave, "dave", "127.0.0.1:4444"),
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
    ];
    let fake_star_db_paths = vec![
        bob_db.to_string_lossy().into_owned(),
        alice_db.to_string_lossy().into_owned(),
        carol_db.to_string_lossy().into_owned(),
        dave_db.to_string_lossy().into_owned(),
    ];

    let bootstrap = PlannerSimulation::new(db_paths.clone())
        .tick()
        .expect("bootstrap round");
    assert_eq!(bootstrap.unique_pairs, 3);
    let bootstrap_follow_up = PlannerSimulation::new(db_paths.clone())
        .tick()
        .expect("bootstrap follow-up round");
    assert_eq!(bootstrap_follow_up.unique_pairs, 3);
    wait_for_authoring_ready(&bob, &db_paths);
    wait_for_authoring_ready(&carol, &db_paths);
    wait_for_authoring_ready(&dave, &db_paths);

    let alice_peer = active_peer_id(&alice);
    let bob_peer = active_peer_id(&bob);
    let (carol_recipient_event_id, _) = local_repair_recipient_material(&carol);
    let (dave_recipient_event_id, _) = local_repair_recipient_material(&dave);

    let key_bytes = [0xCD; 32];
    let alice_key = seed_deterministic_key_secret(&db_paths[0], &alice_peer, key_bytes)
        .expect("seed alice key");
    let bob_key =
        seed_deterministic_key_secret(&db_paths[1], &bob_peer, key_bytes).expect("seed bob key");
    assert_eq!(
        alice_key, bob_key,
        "holders must share the same key_event_id"
    );

    let removal_event_id = create_removal(&db_paths[0], &alice_peer, &dave_recipient_event_id, &[])
        .expect("create removal");
    let _rotation_event_id =
        create_key_rotation(&db_paths[0], &alice_peer, &alice_key, &[removal_event_id])
            .expect("create key rotation");

    let content = "post-removal frontier repair";
    create_encrypted_message_with_key(&db_paths[0], &alice_peer, &alice_key, content)
        .expect("create encrypted message with rotated key");

    let first_round = PlannerSimulation::with_mode_and_topology(
        fake_star_db_paths.clone(),
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("first propagation round");
    assert_eq!(first_round.unique_pairs, 3);

    let second_round = PlannerSimulation::with_mode_and_topology(
        fake_star_db_paths.clone(),
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("second propagation round");
    assert_eq!(second_round.unique_pairs, 3);

    assert!(snapshot_has_message_content(&bob, content));
    assert!(!snapshot_has_message_content(&carol, content));
    assert!(!snapshot_has_message_content(&dave, content));

    let request_stats = emit_key_requests_retry(&db_paths);
    assert_eq!(
        request_stats.emitted_requests, 2,
        "only the two blocked non-holders should request"
    );

    let request_round = PlannerSimulation::with_mode_and_topology(
        fake_star_db_paths.clone(),
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("request propagation round");
    assert_eq!(request_round.unique_pairs, 3);

    let response_stats =
        emit_key_shared_responses_for_dbs(&db_paths, KeyResponsePolicy::AllEligible)
            .expect("emit key shared responses");
    assert_eq!(
        response_stats.emitted_responses, 1,
        "only the non-removed recipient should receive a response"
    );

    let response_round = PlannerSimulation::with_mode_and_topology(
        fake_star_db_paths.clone(),
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("response propagation round");
    assert_eq!(response_round.unique_pairs, 3);

    assert!(snapshot_has_message_content(&carol, content));
    assert!(
        !snapshot_has_message_content(&dave, content),
        "removed peer must remain unable to decrypt"
    );

    let key_event_id_b64 = event_id_to_base64(&alice_key);
    assert_eq!(
        distinct_key_shared_events_for_recipient(
            &db_paths,
            &key_event_id_b64,
            &dave_recipient_event_id,
        ),
        0,
        "no key_shared should target the removed recipient"
    );
    assert!(
        distinct_key_shared_events_for_recipient(
            &db_paths,
            &key_event_id_b64,
            &carol_recipient_event_id,
        ) >= 1,
        "allowed recipient should receive a key_shared"
    );

    let rerequest_stats = emit_key_requests_retry(&db_paths);
    assert!(
        rerequest_stats.emitted_requests <= 1,
        "once any response exists, request suppression may collapse follow-up retries: {rerequest_stats:?}"
    );
    PlannerSimulation::with_mode_and_topology(
        fake_star_db_paths.clone(),
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("follow-up request round");
    let follow_up_response_stats =
        emit_key_shared_responses_for_dbs(&db_paths, KeyResponsePolicy::AllEligible)
            .expect("emit follow-up responses");
    assert_eq!(
        follow_up_response_stats.emitted_responses, 0,
        "removed recipient re-requests must still receive no response"
    );
    PlannerSimulation::with_mode_and_topology(
        fake_star_db_paths,
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .tick()
    .expect("follow-up response round");

    assert!(!snapshot_has_message_content(&dave, content));
    assert_eq!(
        distinct_key_shared_events_for_recipient(
            &db_paths,
            &key_event_id_b64,
            &dave_recipient_event_id,
        ),
        0,
        "removed recipient should still have no response after re-request"
    );
}

#[test]
fn holder_with_request_before_removal_emits_no_response_until_frontier_arrives() {
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

    for (daemon, username, addr) in [
        (&bob, "bob", "127.0.0.1:4242"),
        (&carol, "carol", "127.0.0.1:4343"),
        (&dave, "dave", "127.0.0.1:4444"),
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
    ];
    let bootstrap = PlannerSimulation::new(db_paths.clone())
        .tick()
        .expect("bootstrap round");
    assert_eq!(bootstrap.unique_pairs, 3);
    let bootstrap_follow_up = PlannerSimulation::new(db_paths.clone())
        .tick()
        .expect("bootstrap follow-up round");
    assert_eq!(bootstrap_follow_up.unique_pairs, 3);
    wait_for_authoring_ready(&bob, &db_paths);
    wait_for_authoring_ready(&carol, &db_paths);
    wait_for_authoring_ready(&dave, &db_paths);

    let alice_peer = active_peer_id(&alice);
    let bob_peer = active_peer_id(&bob);
    let carol_peer = active_peer_id(&carol);
    let (dave_recipient_event_id, _) = local_repair_recipient_material(&dave);

    let key_bytes = [0xEF; 32];
    let alice_key = seed_deterministic_key_secret(&db_paths[0], &alice_peer, key_bytes)
        .expect("seed alice key");
    let bob_key =
        seed_deterministic_key_secret(&db_paths[1], &bob_peer, key_bytes).expect("seed bob key");
    assert_eq!(alice_key, bob_key);

    let removal_event_id = create_removal(&db_paths[0], &alice_peer, &dave_recipient_event_id, &[])
        .expect("create removal");
    let rotation_event_id =
        create_key_rotation(&db_paths[0], &alice_peer, &alice_key, &[removal_event_id])
            .expect("create key rotation");
    create_encrypted_message_with_key(
        &db_paths[0],
        &alice_peer,
        &alice_key,
        "request-before-removal",
    )
    .expect("create encrypted message");

    let alice_to_carol = PlannerSimulation::with_explicit_fake_pairs(
        db_paths.clone(),
        vec![(alice_peer.clone(), carol_peer.clone())],
    )
    .tick()
    .expect("alice->carol propagation");
    assert_eq!(alice_to_carol.unique_pairs, 1);
    assert!(
        !snapshot_has_message_content(&carol, "request-before-removal"),
        "carol should have the encrypted message but still be blocked before repair"
    );

    let request_stats = emit_key_requests_retry(&db_paths);
    assert_eq!(request_stats.emitted_requests, 1);
    let request_event_id = newest_key_request_event_id(&db_paths[2], &carol_peer, &alice_key);

    ingest_selected_events(
        &db_paths[1],
        &bob_peer,
        "quic_recv:carol-request@sim",
        &[request_event_id],
        &db_paths[2],
    );
    let bob_conn = open_connection(&db_paths[1]).expect("open bob db");
    let bob_request_count: i64 = bob_conn
        .query_row(
            "SELECT COUNT(*) FROM key_requests WHERE recorded_by = ?1",
            rusqlite::params![&bob_peer],
            |row| row.get(0),
        )
        .expect("bob key_request count");
    assert_eq!(
        bob_request_count, 1,
        "bob should project the inbound key request"
    );

    let pre_frontier_response_stats =
        emit_key_shared_responses_for_dbs(&[db_paths[1].clone()], KeyResponsePolicy::AllEligible)
            .expect("emit responses before frontier");
    assert_eq!(
        pre_frontier_response_stats.emitted_responses, 0,
        "holder must not respond when it has the request but not the removal frontier"
    );

    ingest_selected_events(
        &db_paths[1],
        &bob_peer,
        "quic_recv:alice-frontier@sim",
        &[removal_event_id, rotation_event_id],
        &db_paths[0],
    );
    let bob_removal_count: i64 = bob_conn
        .query_row(
            "SELECT COUNT(*) FROM removals WHERE recorded_by = ?1",
            rusqlite::params![&bob_peer],
            |row| row.get(0),
        )
        .expect("bob removal count");
    let bob_rotation_count: i64 = bob_conn
        .query_row(
            "SELECT COUNT(*) FROM key_rotations WHERE recorded_by = ?1 AND key_event_id = ?2",
            rusqlite::params![&bob_peer, &event_id_to_base64(&alice_key)],
            |row| row.get(0),
        )
        .expect("bob key_rotation count");
    assert_eq!(
        bob_removal_count, 1,
        "bob should project the inbound removal before responding"
    );
    assert_eq!(
        bob_rotation_count, 1,
        "bob should project the inbound key rotation before responding"
    );

    let post_frontier_response_stats =
        emit_key_shared_responses_for_dbs(&[db_paths[1].clone()], KeyResponsePolicy::AllEligible)
            .expect("emit responses after frontier");
    assert_eq!(
        post_frontier_response_stats.emitted_responses, 1,
        "once the holder projects removal and rotation locally it can answer"
    );

    let bob_to_carol = PlannerSimulation::with_explicit_fake_pairs(
        db_paths.clone(),
        vec![(bob_peer.clone(), carol_peer.clone())],
    )
    .tick()
    .expect("bob->carol response propagation");
    assert_eq!(bob_to_carol.unique_pairs, 1);
    assert!(
        snapshot_has_message_content(&carol, "request-before-removal"),
        "carol should decrypt after bob learns the frontier and responds"
    );
}
