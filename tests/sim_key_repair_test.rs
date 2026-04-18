use std::collections::BTreeSet;

use topo::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use topo::db::open_connection;
use topo::rpc::protocol::RpcMethod;
use topo::sim::{
    create_encrypted_message_with_key, create_key_rotation, create_removal,
    emit_key_requests_for_dbs, emit_key_shared_responses_for_dbs,
    seed_key_rotation_for_recipients, FakeTopologyPreference, KeyResponsePolicy, PlannerMode,
    PlannerSimulation, VirtualDaemon,
};
use topo::projection::apply::project_one;
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

fn has_event(daemon: &VirtualDaemon, event_id: &str) -> bool {
    daemon
        .call(RpcMethod::AssertNow {
            predicate: format!("has_event:{event_id} >= 1"),
        })
        .ok
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

fn local_repair_recipient_material(daemon: &VirtualDaemon) -> (EventId, EventId) {
    let recorded_by = active_peer_id(daemon);
    let conn = open_connection(daemon.db_path()).expect("open db");
    let (recipient_event_id, _) =
        topo::event_modules::peer_shared::load_local_peer_signer_required(&conn, &recorded_by)
            .expect("local peer_shared signer");
    let recipient_event_id_b64 = event_id_to_base64(&recipient_event_id);
    let peer_secret_event_id_b64: String = conn
        .query_row(
            "SELECT event_id
             FROM peer_secrets
             WHERE recorded_by = ?1
               AND signer_event_id = ?2
             ORDER BY created_at DESC, event_id DESC
             LIMIT 1",
            rusqlite::params![&recorded_by, &recipient_event_id_b64],
            |row| topo::db::sql_types::get_text(row, 0),
        )
        .expect("peer_secret event_id");
    (
        recipient_event_id,
        event_id_from_base64(&peer_secret_event_id_b64).expect("unwrap key event id"),
    )
}

fn seed_shared_holder_rotation(
    source: &VirtualDaemon,
    recipients: &[&VirtualDaemon],
    key_bytes: [u8; 32],
) -> EventId {
    let source_peer = active_peer_id(source);
    let recipient_event_ids = recipients
        .iter()
        .map(|daemon| local_repair_recipient_material(daemon).0)
        .collect::<Vec<_>>();
    seed_key_rotation_for_recipients(
        source.db_path(),
        &source_peer,
        &recipient_event_ids,
        key_bytes,
    )
    .expect("seed shared holder key rotation")
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

fn run_fake_star_round(fake_star_db_paths: &[String], label: &str) -> topo::sim::PlannerRunReport {
    topo::sim::PlannerSimulation::with_mode_and_topology(
        fake_star_db_paths.to_vec(),
        PlannerMode::NearestNeighborNoAuth,
        FakeTopologyPreference::Star,
    )
    .run_rounds(1)
    .unwrap_or_else(|err| panic!("{label}: {err}"))
}

fn accumulate_round_transfers(
    benchmark: &mut RepairBenchmark,
    report: &topo::sim::PlannerRunReport,
) {
    benchmark.transferred_key_request_events =
        benchmark.transferred_key_request_events.saturating_add(
            report
                .rounds
                .iter()
                .flat_map(|round| round.pairs.iter())
                .map(|pair| {
                    pair.stats.left_to_right.transferred_key_request_events
                        + pair.stats.right_to_left.transferred_key_request_events
                })
                .sum::<usize>(),
        );
    benchmark.suppressed_key_request_events =
        benchmark.suppressed_key_request_events.saturating_add(
            report
                .rounds
                .iter()
                .flat_map(|round| round.pairs.iter())
                .map(|pair| {
                    pair.stats.left_to_right.suppressed_key_request_events
                        + pair.stats.right_to_left.suppressed_key_request_events
                })
                .sum::<usize>(),
        );
    benchmark.transferred_key_shared_events =
        benchmark.transferred_key_shared_events.saturating_add(
            report
                .rounds
                .iter()
                .flat_map(|round| round.pairs.iter())
                .map(|pair| {
                    pair.stats.left_to_right.transferred_key_shared_events
                        + pair.stats.right_to_left.transferred_key_shared_events
                })
                .sum::<usize>(),
        );
    benchmark.suppressed_key_shared_events = benchmark.suppressed_key_shared_events.saturating_add(
        report
            .rounds
            .iter()
            .flat_map(|round| round.pairs.iter())
            .map(|pair| {
                pair.stats.left_to_right.suppressed_key_shared_events
                    + pair.stats.right_to_left.suppressed_key_shared_events
            })
            .sum::<usize>(),
    );
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
                topo::db::sql_types::get_text(row, 0)
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
                topo::db::sql_types::get_text(row, 0)
            })
            .expect("query key_shared");
        for row in rows {
            seen.insert(row.expect("key_shared row"));
        }
    }
    seen.len()
}

fn authoring_ready(daemon: &VirtualDaemon) -> bool {
    let conn = open_connection(daemon.db_path()).expect("open db for authoring check");
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
                topo::db::sql_types::get_text(row, 0)
            })
            .expect("query key_shared recipient");
        for row in rows {
            seen.insert(row.expect("key_shared recipient row"));
        }
    }
    seen.len()
}

fn repair_readiness_snapshot(
    daemon: &VirtualDaemon,
    encrypted_event_id: &EventId,
    key_event_id: &EventId,
) -> String {
    let recorded_by = active_peer_id(daemon);
    let conn = open_connection(daemon.db_path()).expect("open db for readiness snapshot");
    let encrypted_event_id_b64 = event_id_to_base64(encrypted_event_id);
    let key_event_id_b64 = event_id_to_base64(key_event_id);
    let invite_row: Option<(String, String)> = conn
        .query_row(
            "SELECT invite_event_id, workspace_id
             FROM invites_accepted
             WHERE recorded_by = ?1
             ORDER BY created_at ASC, event_id ASC
             LIMIT 1",
            rusqlite::params![&recorded_by],
            |row| {
                Ok((
                    topo::db::sql_types::get_text(row, 0)?,
                    topo::db::sql_types::get_text(row, 1)?,
                ))
            },
        )
        .ok();
    let invite_history_b64 = invite_row
        .as_ref()
        .and_then(|(invite_event_id_b64, _)| {
            conn.query_row(
                "SELECT key_history_event_id FROM user_invites WHERE recorded_by = ?1 AND event_id = ?2
                 UNION ALL
                 SELECT key_history_event_id FROM device_invites WHERE recorded_by = ?1 AND event_id = ?2
                 LIMIT 1",
                rusqlite::params![&recorded_by, invite_event_id_b64],
                |row| topo::db::sql_types::get_text(row, 0),
            )
            .ok()
        })
        .unwrap_or_default();
    let key_history_count: i64 = if invite_history_b64.is_empty() {
        0
    } else {
        conn.query_row(
            "SELECT COUNT(*) FROM key_histories WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![&recorded_by, &invite_history_b64],
            |row| row.get(0),
        )
        .unwrap_or(0)
    };
    let key_rotation_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM key_rotations WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![&recorded_by, &key_event_id_b64],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let key_secret_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM key_secrets WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![&recorded_by, &key_event_id_b64],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let blocked_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let encrypted_recorded_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM recorded_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&recorded_by, &encrypted_event_id_b64],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let encrypted_valid_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM valid_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&recorded_by, &encrypted_event_id_b64],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let encrypted_blocked_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_events WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&recorded_by, &encrypted_event_id_b64],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let encrypted_dep_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM blocked_event_deps WHERE peer_id = ?1 AND event_id = ?2",
            rusqlite::params![&recorded_by, &encrypted_event_id_b64],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let replay_decision = topo::state::db::queue::with_immediate_tx_result(
        &conn,
        || -> Result<String, rusqlite::Error> {
            conn.execute("SAVEPOINT readiness_snapshot", [])?;
            let decision = project_one(&conn, &recorded_by, encrypted_event_id)
                .map(|value| format!("{value:?}"))
                .unwrap_or_else(|err| format!("Err({err})"));
            conn.execute("ROLLBACK TO readiness_snapshot", [])?;
            conn.execute("RELEASE readiness_snapshot", [])?;
            Ok(decision)
        },
    )
    .unwrap_or_else(|err| format!("snapshot_err({err})"));
    let rejected_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM rejected_events WHERE peer_id = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    let last_reject_reason: String = conn
        .query_row(
            "SELECT reason FROM rejected_events WHERE peer_id = ?1 ORDER BY rowid DESC LIMIT 1",
            rusqlite::params![&recorded_by],
            |row| topo::db::sql_types::get_text(row, 0),
        )
        .unwrap_or_default();
    let project_queue_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM project_queue WHERE peer_id = ?1",
            rusqlite::params![&recorded_by],
            |row| row.get(0),
        )
        .unwrap_or(0);
    format!(
        "peer={} invite={:?} invite_history={} key_history_rows={} key_rotation_rows={} key_secret_rows={} blocked_events={} encrypted_recorded={} encrypted_valid={} encrypted_blocked={} encrypted_dep_edges={} replay_decision={} rejected_events={} last_reject={:?} project_queue={}",
        recorded_by,
        invite_row,
        invite_history_b64,
        key_history_count,
        key_rotation_count,
        key_secret_count,
        blocked_count,
        encrypted_recorded_count,
        encrypted_valid_count,
        encrypted_blocked_count,
        encrypted_dep_count,
        replay_decision,
        rejected_count,
        last_reject_reason,
        project_queue_count
    )
}

fn event_blob_by_id(db_path: &str, event_id: &EventId) -> Vec<u8> {
    let conn = open_connection(db_path).expect("open db");
    let event_id_b64 = event_id_to_base64(event_id);
    conn.query_row(
        "SELECT blob FROM events WHERE event_id = ?1",
        rusqlite::params![&event_id_b64],
        |row| topo::db::sql_types::get_blob(row, 0),
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
            |row| topo::db::sql_types::get_text(row, 0),
        )
        .expect("newest key_request event_id");
    event_id_from_base64(&event_id_b64).expect("key_request event id")
}

fn source_event_ids_in_dependency_order(
    source_db_path: &str,
    event_ids: &[EventId],
) -> Vec<EventId> {
    fn recursive_dep_field_values(
        parsed: &topo::event_modules::ParsedEvent,
    ) -> Vec<(&'static str, EventId)> {
        let mut deps = parsed.dep_field_values();
        if let topo::event_modules::ParsedEvent::Signed(signed) = parsed {
            if let Ok(inner) = topo::event_modules::parse_event(&signed.payload) {
                deps.extend(recursive_dep_field_values(&inner));
            }
        }
        deps
    }

    fn visit(
        conn: &rusqlite::Connection,
        event_id: EventId,
        visited: &mut BTreeSet<EventId>,
        ordered: &mut Vec<EventId>,
    ) {
        if !visited.insert(event_id) {
            return;
        }
        let event_id_b64 = event_id_to_base64(&event_id);
        let blob = conn
            .query_row(
                "SELECT blob FROM events WHERE event_id = ?1",
                rusqlite::params![&event_id_b64],
                |row| topo::db::sql_types::get_blob(row, 0),
            )
            .ok();
        let Some(blob) = blob else {
            return;
        };
        let parsed = topo::event_modules::parse_event(&blob).expect("parse source event");
        for (_, dep_id) in recursive_dep_field_values(&parsed) {
            visit(conn, dep_id, visited, ordered);
        }
        ordered.push(event_id);
    }

    let conn = open_connection(source_db_path).expect("open source db for dependency closure");
    let mut visited = BTreeSet::new();
    let mut ordered = Vec::new();
    for event_id in event_ids {
        visit(&conn, *event_id, &mut visited, &mut ordered);
    }
    ordered
}

fn ingest_selected_events(
    dest_db_path: &str,
    dest_recorded_by: &str,
    source_tag: &str,
    event_ids: &[EventId],
    source_db_path: &str,
) {
    let now_ms = current_timestamp_ms();
    let batch = source_event_ids_in_dependency_order(source_db_path, event_ids)
        .into_iter()
        .map(|event_id| {
            (
                event_id,
                event_blob_by_id(source_db_path, &event_id),
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
        message_count: 0,
        network_age: None,
    });
    assert!(created.ok, "workspace creation failed: {:?}", created.error);

    for (daemon, username) in [
        (&bob, "bob"),
        (&carol, "carol"),
        (&dave, "dave"),
        (&erin, "erin"),
    ] {
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
    finish_bootstrap_until_authoring_ready(&db_paths, &[&bob, &carol, &dave, &erin]);

    let alice_peer = active_peer_id(&alice);
    let key_bytes = [0xAB; 32];
    let alice_key = seed_shared_holder_rotation(&alice, &[&alice, &bob], key_bytes);

    let content = "fresh-key repair path";
    let encrypted_event_id =
        create_encrypted_message_with_key(&db_paths[0], &alice_peer, &alice_key, content)
            .expect("create encrypted message with fresh key");
    let encrypted_event_id_b64 = event_id_to_base64(&encrypted_event_id);
    let key_event_id_b64 = event_id_to_base64(&alice_key);

    let mut delivery_rounds = 0usize;
    while ![&bob, &carol, &dave, &erin]
        .into_iter()
        .all(|daemon| has_event(daemon, &encrypted_event_id_b64) && has_event(daemon, &key_event_id_b64))
    {
        let report = run_fake_star_round(&fake_star_db_paths, "message propagation round");
        assert_eq!(report.rounds[0].unique_pairs, 4);
        delivery_rounds = delivery_rounds.saturating_add(1);
        assert!(
            delivery_rounds <= 8,
            "encrypted message or referenced key_rotation did not reach all peers within bounded planner rounds"
        );
    }
    assert_has_event(&bob, &encrypted_event_id_b64);
    assert!(!snapshot_has_message_content(&carol, content));
    assert!(!snapshot_has_message_content(&dave, content));
    assert!(!snapshot_has_message_content(&erin, content));

    let mut benchmark = RepairBenchmark::default();
    let mut converged = false;
    for round_idx in 0..12 {
        let _requests = emit_key_requests_for_dbs(&db_paths).expect("emit key requests");
        let _responses = emit_key_shared_responses_for_dbs(&db_paths, policy)
            .expect("emit key shared responses");
        let report = run_fake_star_round(
            &fake_star_db_paths,
            &format!("repair propagation round {}", round_idx + 1),
        );
        accumulate_round_transfers(&mut benchmark, &report);
        benchmark.repair_rounds = benchmark.repair_rounds.saturating_add(1);
        if snapshot_has_message_content(&carol, content)
            && snapshot_has_message_content(&dave, content)
            && snapshot_has_message_content(&erin, content)
        {
            converged = true;
            break;
        }
    }
    assert!(
        converged,
        "repair path did not converge within bounded rounds: requests={} responses={} carol={} dave={} erin={} || {} || {} || {}",
        distinct_key_request_events(&db_paths, &encrypted_event_id_b64),
        distinct_key_shared_events_for_key(&db_paths, &key_event_id_b64),
        snapshot_has_message_content(&carol, content),
        snapshot_has_message_content(&dave, content),
        snapshot_has_message_content(&erin, content),
        repair_readiness_snapshot(&carol, &encrypted_event_id, &alice_key),
        repair_readiness_snapshot(&dave, &encrypted_event_id, &alice_key),
        repair_readiness_snapshot(&erin, &encrypted_event_id, &alice_key),
    );

    let _follow_up_requests =
        emit_key_requests_for_dbs(&db_paths).expect("emit follow-up requests");
    let _follow_up_responses =
        emit_key_shared_responses_for_dbs(&db_paths, policy).expect("emit follow-up responses");
    let follow_up_round = run_fake_star_round(&fake_star_db_paths, "follow-up suppression round");
    benchmark.follow_up_transferred_key_request_events = benchmark
        .follow_up_transferred_key_request_events
        .saturating_add(
            follow_up_round
                .rounds
                .iter()
                .flat_map(|round| round.pairs.iter())
                .map(|pair| {
                    pair.stats.left_to_right.transferred_key_request_events
                        + pair.stats.right_to_left.transferred_key_request_events
                })
                .sum::<usize>(),
        );
    benchmark.suppressed_key_request_events =
        benchmark.suppressed_key_request_events.saturating_add(
            follow_up_round
                .rounds
                .iter()
                .flat_map(|round| round.pairs.iter())
                .map(|pair| {
                    pair.stats.left_to_right.suppressed_key_request_events
                        + pair.stats.right_to_left.suppressed_key_request_events
                })
                .sum::<usize>(),
        );
    benchmark.suppressed_key_shared_events = benchmark.suppressed_key_shared_events.saturating_add(
        follow_up_round
            .rounds
            .iter()
            .flat_map(|round| round.pairs.iter())
            .map(|pair| {
                pair.stats.left_to_right.suppressed_key_shared_events
                    + pair.stats.right_to_left.suppressed_key_shared_events
            })
            .sum::<usize>(),
    );

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
        message_count: 0,
        network_age: None,
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
    finish_bootstrap_until_authoring_ready(&db_paths, &[&bob, &carol, &dave]);

    let alice_peer = active_peer_id(&alice);
    let (carol_recipient_event_id, _) = local_repair_recipient_material(&carol);
    let (dave_recipient_event_id, _) = local_repair_recipient_material(&dave);

    let key_bytes = [0xCD; 32];
    let alice_key = seed_shared_holder_rotation(&alice, &[&alice, &bob], key_bytes);

    let removal_event_id = create_removal(&db_paths[0], &alice_peer, &dave_recipient_event_id, &[])
        .expect("create removal");
    let rotation_event_id =
        create_key_rotation(&db_paths[0], &alice_peer, &alice_key, &[removal_event_id])
            .expect("create key rotation");

    let content = "post-removal frontier repair";
    let encrypted_event_id =
        create_encrypted_message_with_key(&db_paths[0], &alice_peer, &rotation_event_id, content)
            .expect("create encrypted message with rotated key");
    let encrypted_event_id_b64 = event_id_to_base64(&encrypted_event_id);
    let rotation_event_id_b64 = event_id_to_base64(&rotation_event_id);

    let mut propagation_rounds = 0usize;
    while ![&bob, &carol, &dave]
        .into_iter()
        .all(|daemon| {
            has_event(daemon, &encrypted_event_id_b64)
                && has_event(daemon, &rotation_event_id_b64)
        })
    {
        let report = run_fake_star_round(
            &fake_star_db_paths,
            &format!("frontier propagation round {}", propagation_rounds + 1),
        );
        assert_eq!(report.rounds[0].unique_pairs, 3);
        propagation_rounds = propagation_rounds.saturating_add(1);
        assert!(
            propagation_rounds <= 8,
            "encrypted event or referenced frontier rotation did not reach all peers within bounded planner rounds"
        );
    }

    assert_has_event(&bob, &encrypted_event_id_b64);
    assert_has_event(&carol, &encrypted_event_id_b64);
    assert_has_event(&dave, &encrypted_event_id_b64);
    assert!(!snapshot_has_message_content(&carol, content));
    assert!(!snapshot_has_message_content(&dave, content));
    let mut request_stats = None;
    for _ in 0..8 {
        let stats = emit_key_requests_for_dbs(&db_paths).expect("emit key requests");
        if stats.emitted_requests == 2 {
            request_stats = Some(stats);
            break;
        }
        let report = run_fake_star_round(&fake_star_db_paths, "request frontier propagation round");
        assert_eq!(report.rounds[0].unique_pairs, 3);
    }
    let request_stats =
        request_stats.expect("blocked non-holders never learned enough frontier to request");
    assert_eq!(
        request_stats.emitted_requests, 2,
        "only the two blocked non-holders should request"
    );

    let mut saw_allowed_response = false;
    for round_idx in 0..12 {
        let response_stats =
            emit_key_shared_responses_for_dbs(&db_paths, KeyResponsePolicy::AllEligible)
                .expect("emit key shared responses");
        saw_allowed_response |= response_stats.emitted_responses > 0;
        let report = run_fake_star_round(
            &fake_star_db_paths,
            &format!("request/response propagation round {}", round_idx + 1),
        );
        assert_eq!(report.rounds[0].unique_pairs, 3);
        if snapshot_has_message_content(&carol, content) {
            break;
        }
    }

    assert!(
        saw_allowed_response,
        "allowed recipient never observed a key_shared response"
    );

    assert!(snapshot_has_message_content(&carol, content));
    assert!(
        !snapshot_has_message_content(&dave, content),
        "removed peer must remain unable to decrypt"
    );

    let key_event_id_b64 = event_id_to_base64(&rotation_event_id);
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

    let rerequest_stats =
        emit_key_requests_for_dbs(&db_paths).expect("emit follow-up key requests");
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
    assert!(
        follow_up_response_stats.emitted_responses <= 1,
        "follow-up rounds may still emit at most one duplicate response for the allowed requester: {follow_up_response_stats:?}"
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
fn request_closure_delivers_rotation_frontier_before_response() {
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
        message_count: 0,
        network_age: None,
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
    finish_bootstrap_until_authoring_ready(&db_paths, &[&bob, &carol, &dave]);

    let alice_peer = active_peer_id(&alice);
    let bob_peer = active_peer_id(&bob);
    let carol_peer = active_peer_id(&carol);
    let (dave_recipient_event_id, _) = local_repair_recipient_material(&dave);

    let key_bytes = [0xEF; 32];
    let alice_key = seed_shared_holder_rotation(&alice, &[&alice, &bob], key_bytes);

    let removal_event_id = create_removal(&db_paths[0], &alice_peer, &dave_recipient_event_id, &[])
        .expect("create removal");
    let rotation_event_id =
        create_key_rotation(&db_paths[0], &alice_peer, &alice_key, &[removal_event_id])
            .expect("create key rotation");
    let encrypted_event_id = create_encrypted_message_with_key(
        &db_paths[0],
        &alice_peer,
        &rotation_event_id,
        "request-before-removal",
    )
    .expect("create encrypted message");
    let encrypted_event_id_b64 = event_id_to_base64(&encrypted_event_id);
    let rotation_event_id_b64 = event_id_to_base64(&rotation_event_id);

    let request_event_id = {
        let mut request_event_id = None;
        for round_idx in 0..8 {
            let alice_to_carol = PlannerSimulation::with_explicit_fake_pairs(
                db_paths.clone(),
                vec![(alice_peer.clone(), carol_peer.clone())],
            )
            .tick()
            .unwrap_or_else(|err| {
                panic!("alice->carol propagation round {}: {err}", round_idx + 1)
            });
            assert_eq!(alice_to_carol.unique_pairs, 1);
            assert_has_event(&carol, &encrypted_event_id_b64);
            assert_has_event(&carol, &rotation_event_id_b64);
            assert!(
                !snapshot_has_message_content(&carol, "request-before-removal"),
                "carol should have the encrypted message but still be blocked before repair"
            );

            let request_stats = emit_key_requests_for_dbs(&db_paths).expect("emit key requests");
            if request_stats.emitted_requests == 1 {
                request_event_id = Some(newest_key_request_event_id(
                    &db_paths[2],
                    &carol_peer,
                    &rotation_event_id,
                ));
                break;
            }
        }
        request_event_id.expect("carol never emitted a request after bounded propagation rounds")
    };

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

    let bob_removal_count: i64 = bob_conn
        .query_row(
            "SELECT COUNT(*) FROM removals WHERE recorded_by = ?1",
            rusqlite::params![&bob_peer],
            |row| row.get(0),
        )
        .expect("bob removal count after request import");
    let bob_rotation_count: i64 = bob_conn
        .query_row(
            "SELECT COUNT(*) FROM key_rotations WHERE recorded_by = ?1 AND key_event_id = ?2",
            rusqlite::params![&bob_peer, &event_id_to_base64(&rotation_event_id)],
            |row| row.get(0),
        )
        .expect("bob key_rotation count after request import");
    assert_eq!(
        bob_removal_count, 1,
        "request closure should carry the removal frontier to the holder"
    );
    assert_eq!(
        bob_rotation_count, 1,
        "request closure should carry the referenced key_rotation to the holder"
    );

    let response_stats =
        emit_key_shared_responses_for_dbs(&[db_paths[1].clone()], KeyResponsePolicy::AllEligible)
            .expect("emit responses after request closure");
    assert_eq!(
        response_stats.emitted_responses, 1,
        "once the request closure delivers the frontier-bound rotation locally the holder can answer"
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
