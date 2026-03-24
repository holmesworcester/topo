use std::time::Duration;

use topo::crypto::event_id_to_base64;
use topo::db::{open_connection, timeline::EventTimeline};
use topo::testutil::{sync_until_converged, Peer, ScenarioHarness};

fn assert_non_decreasing(label: &str, earlier: Option<i64>, later: Option<i64>) {
    let earlier = earlier.unwrap_or_else(|| panic!("{label}: missing earlier timestamp"));
    let later = later.unwrap_or_else(|| panic!("{label}: missing later timestamp"));
    assert!(earlier <= later, "{label}: expected {earlier} <= {later}");
}

fn assert_sink_delivery_timeline(
    timeline: &EventTimeline<'_>,
    event_id_b64: &str,
    sink_name: &str,
) {
    let row = timeline
        .load(event_id_b64)
        .expect("load sink timeline")
        .unwrap_or_else(|| {
            panic!("missing sink timeline row for {sink_name} event {event_id_b64}")
        });
    assert!(
        row.first_received_at.is_some(),
        "{sink_name} should record receive time for {event_id_b64}"
    );
    assert!(
        row.first_stored_at.is_some(),
        "{sink_name} should record first store time for {event_id_b64}"
    );
    assert!(
        row.projected_at.is_some(),
        "{sink_name} should record projection time for {event_id_b64}"
    );
    assert_non_decreasing(
        &format!("{sink_name} receive->store"),
        row.first_received_at,
        row.first_stored_at,
    );
    assert_non_decreasing(
        &format!("{sink_name} store->project"),
        row.first_stored_at,
        row.projected_at,
    );
}

#[tokio::test]
async fn synced_event_records_receive_store_and_projection_on_sink() {
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
    let sink_timeline = EventTimeline::new(&sink_conn);
    assert_sink_delivery_timeline(&sink_timeline, &marker_b64, "bob");

    harness.finish();
}

#[tokio::test]
async fn bidirectional_sync_records_delivery_timeline_for_remote_events() {
    let alice = Peer::new_with_identity("alice");
    let bob = Peer::new_in_workspace("bob", &alice).await;
    let harness = ScenarioHarness::new();
    harness.track(&alice);
    harness.track(&bob);

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
        assert_sink_delivery_timeline(&alice_timeline, eid, "alice");
    }

    let bob_conn = open_connection(&bob.db_path).expect("open bob db");
    let bob_timeline = EventTimeline::new(&bob_conn);
    for eid in &alice_msgs {
        assert_sink_delivery_timeline(&bob_timeline, eid, "bob");
    }

    harness.finish();
}
