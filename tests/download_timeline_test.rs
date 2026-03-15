use std::time::Duration;

use topo::crypto::event_id_to_base64;
use topo::db::{open_connection, timeline::EventTimeline};
use topo::testutil::{sync_until_converged, Peer, ScenarioHarness};

fn assert_non_decreasing(label: &str, earlier: Option<i64>, later: Option<i64>) {
    let earlier = earlier.unwrap_or_else(|| panic!("{label}: missing earlier timestamp"));
    let later = later.unwrap_or_else(|| panic!("{label}: missing later timestamp"));
    assert!(earlier <= later, "{label}: expected {earlier} <= {later}");
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
    assert_non_decreasing(
        "source request->response",
        source_timeline.request_received_at,
        source_timeline.response_sent_at,
    );

    harness.finish();
}
