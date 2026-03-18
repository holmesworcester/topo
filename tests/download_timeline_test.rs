use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use topo::crypto::event_id_to_base64;
use topo::db::{open_connection, timeline::EventTimeline};
use topo::testutil::{sync_until_converged, Peer, ScenarioHarness};

fn assert_non_decreasing(label: &str, earlier: Option<i64>, later: Option<i64>) {
    let earlier = earlier.unwrap_or_else(|| panic!("{label}: missing earlier timestamp"));
    let later = later.unwrap_or_else(|| panic!("{label}: missing later timestamp"));
    assert!(earlier <= later, "{label}: expected {earlier} <= {later}");
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_millis() as i64
}

#[tokio::test]
async fn requested_download_records_pipeline_timestamps_on_source_and_sink() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    let marker = alice.create_message("download timeline marker");
    let marker_b64 = event_id_to_base64(&marker);

    let _metrics = sync_until_converged(
        &alice,
        &bob,
        || bob.has_event(&marker_b64),
        Duration::from_secs(30),
    )
    .await;

    let sink_conn = open_connection(&bob.db_path).expect("open sink db");
    let sink_timeline = EventTimeline::new(&sink_conn)
        .load(&marker_b64)
        .expect("load sink timeline")
        .expect("sink timeline row");
    assert!(
        sink_timeline.discovery_round_started_at.is_some(),
        "sink should record discovery round start"
    );
    assert!(
        sink_timeline.wanted_discovered_at.is_some(),
        "sink should record wanted discovery"
    );
    assert!(
        sink_timeline.request_selected_at.is_some(),
        "sink should record request selection"
    );
    assert!(
        sink_timeline.request_sent_at.is_some(),
        "sink should record request emission"
    );
    assert!(
        sink_timeline.response_received_at.is_some(),
        "sink should record data receipt"
    );
    assert!(
        sink_timeline.persisted_at.is_some(),
        "sink should record durable persist"
    );
    assert!(
        sink_timeline.projected_at.is_some(),
        "sink should record projection"
    );
    assert_non_decreasing(
        "sink wanted->selected",
        sink_timeline.wanted_discovered_at,
        sink_timeline.request_selected_at,
    );
    if sink_timeline.discovery_round_completed_at.is_some() {
        assert_non_decreasing(
            "sink discover->complete",
            sink_timeline.discovery_round_started_at,
            sink_timeline.discovery_round_completed_at,
        );
    }
    assert_non_decreasing(
        "sink selected->request",
        sink_timeline.request_selected_at,
        sink_timeline.request_sent_at,
    );
    assert_non_decreasing(
        "sink discover->wanted",
        sink_timeline.discovery_round_started_at,
        sink_timeline.wanted_discovered_at,
    );
    assert_non_decreasing(
        "sink wanted->request",
        sink_timeline.wanted_discovered_at,
        sink_timeline.request_sent_at,
    );
    assert_non_decreasing(
        "sink request->receive",
        sink_timeline.request_sent_at,
        sink_timeline.response_received_at,
    );
    assert_non_decreasing(
        "sink receive->persist",
        sink_timeline.response_received_at,
        sink_timeline.persisted_at,
    );
    assert_non_decreasing(
        "sink persist->project",
        sink_timeline.persisted_at,
        sink_timeline.projected_at,
    );

    let source_conn = open_connection(&alice.db_path).expect("open source db");
    let source_timeline = EventTimeline::new(&source_conn)
        .load(&marker_b64)
        .expect("load source timeline")
        .expect("source timeline row");
    assert!(
        source_timeline.request_received_at.is_some(),
        "source should record request receipt"
    );
    assert!(
        source_timeline.response_sent_at.is_some(),
        "source should record response send"
    );
    if let Some(need_sent_at) = source_timeline.need_list_sent_at {
        assert!(
            sink_timeline.need_list_received_at.is_some(),
            "source recorded discovery-hint send but sink missed discovery-hint receipt"
        );
        assert_non_decreasing(
            "needlist send->recv",
            Some(need_sent_at),
            sink_timeline.need_list_received_at,
        );
    }
    assert_non_decreasing(
        "source request->response",
        source_timeline.request_received_at,
        source_timeline.response_sent_at,
    );

    harness.finish();
}

#[tokio::test]
async fn bidirectional_sync_receives_only_requested_event_data() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

    let phase_start_ms = current_timestamp_ms();
    let alice_msgs: Vec<String> = (0..3)
        .map(|idx| event_id_to_base64(&alice.create_message(&format!("alice msg {idx}"))))
        .collect();
    let bob_msgs: Vec<String> = (0..3)
        .map(|idx| event_id_to_base64(&bob.create_message(&format!("bob msg {idx}"))))
        .collect();

    let _metrics = sync_until_converged(
        &alice,
        &bob,
        || {
            alice_msgs.iter().all(|eid| bob.has_event(eid))
                && bob_msgs.iter().all(|eid| alice.has_event(eid))
        },
        Duration::from_secs(30),
    )
    .await;

    let alice_conn = open_connection(&alice.db_path).expect("open alice db");
    let alice_timeline = EventTimeline::new(&alice_conn);
    for eid in &bob_msgs {
        let row = alice_timeline
            .load(eid)
            .expect("load alice sink timeline")
            .expect("alice sink timeline row");
        assert!(
            row.request_sent_at.is_some(),
            "alice received remote event {eid} without a request timestamp after {phase_start_ms}"
        );
        assert!(
            row.response_received_at.is_some(),
            "alice missing receive timestamp for remote event {eid}"
        );
    }

    let bob_conn = open_connection(&bob.db_path).expect("open bob db");
    let bob_timeline = EventTimeline::new(&bob_conn);
    for eid in &alice_msgs {
        let row = bob_timeline
            .load(eid)
            .expect("load bob sink timeline")
            .expect("bob sink timeline row");
        assert!(
            row.request_sent_at.is_some(),
            "bob received remote event {eid} without a request timestamp after {phase_start_ms}"
        );
        assert!(
            row.response_received_at.is_some(),
            "bob missing receive timestamp for remote event {eid}"
        );
    }

    harness.finish();
}
