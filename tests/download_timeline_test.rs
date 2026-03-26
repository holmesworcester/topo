//! Real-daemon delivery timeline tests.
//!
//! These tests use the CLI/daemon harness rather than the in-process `Peer`
//! bootstrap helper so they validate the product path:
//! workspace create -> invite -> accept -> daemon autodial/live sync -> send.

mod cli_harness;

use std::time::Duration;

use cli_harness::*;
use topo::crypto::{event_id_from_hex, event_id_to_base64};
use topo::db::{open_connection, timeline::EventTimeline};

const TIMELINE_TIMEOUT_MS: u64 = 60_000;

struct TimelineEnvGuard {
    prev: Option<String>,
}

impl TimelineEnvGuard {
    fn enable() -> Self {
        let prev = std::env::var("TOPO_EVENT_TIMELINE").ok();
        std::env::set_var("TOPO_EVENT_TIMELINE", "1");
        Self { prev }
    }
}

impl Drop for TimelineEnvGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(value) => std::env::set_var("TOPO_EVENT_TIMELINE", value),
            None => std::env::remove_var("TOPO_EVENT_TIMELINE"),
        }
    }
}

struct StartedCliPeer {
    db: String,
    _daemon: HarnessDaemon,
}

struct StartedCliPeers {
    alice: StartedCliPeer,
    bob: StartedCliPeer,
    _timeline_env: TimelineEnvGuard,
}

struct SentEventIds {
    hex: String,
    b64: String,
}

fn send_message_ids(db: &str, content: &str) -> SentEventIds {
    let hex = send_message(db, content);
    let eid = event_id_from_hex(&hex).unwrap_or_else(|| panic!("invalid hex event id: {hex}"));
    SentEventIds {
        b64: event_id_to_base64(&eid),
        hex,
    }
}

fn start_two_cli_peers(tmpdir: &tempfile::TempDir) -> StartedCliPeers {
    hold_network_test_lock_for_binary();
    let timeline_env = TimelineEnvGuard::enable();

    let alice_db = tmpdir.path().join("alice.db").to_str().unwrap().to_string();
    let bob_db = tmpdir.path().join("bob.db").to_str().unwrap().to_string();

    create_workspace_with_details(&alice_db, "timeline-repro", "alice", "alice-box");
    let alice_daemon = start_daemon(&alice_db);
    wait_for_active_tenant_ready(&alice_db, Duration::from_secs(60));

    let invite_link = create_invite_with_spki(
        &alice_db,
        &daemon_listen_addr(&alice_db),
        Some(&daemon_identity_fingerprint(&alice_db)),
    );

    let bob_daemon = start_daemon(&bob_db);
    accept_invite_with_identity_on_running_daemon(
        &bob_db,
        &invite_link,
        "bob",
        "bob-box",
        Duration::from_secs(30),
    );
    wait_for_active_tenant_ready(&bob_db, Duration::from_secs(60));
    wait_for_live_sync_session(&alice_db, Duration::from_secs(60));
    wait_for_live_sync_session(&bob_db, Duration::from_secs(60));

    StartedCliPeers {
        alice: StartedCliPeer {
            db: alice_db,
            _daemon: alice_daemon,
        },
        bob: StartedCliPeer {
            db: bob_db,
            _daemon: bob_daemon,
        },
        _timeline_env: timeline_env,
    }
}

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

#[test]
fn synced_event_records_receive_store_and_projection_on_sink() {
    let tmpdir = tempfile::tempdir().unwrap();
    let peers = start_two_cli_peers(&tmpdir);

    let marker = send_message_ids(&peers.alice.db, "download timeline marker");
    assert_eventually(
        &peers.bob.db,
        &format!("has_event:{} >= 1", marker.hex),
        TIMELINE_TIMEOUT_MS,
    );

    let sink_conn = open_connection(&peers.bob.db).expect("open sink db");
    let sink_timeline = EventTimeline::new(&sink_conn);
    assert_sink_delivery_timeline(&sink_timeline, &marker.b64, "bob");
}

#[test]
fn bidirectional_sync_records_delivery_timeline_for_remote_events() {
    let tmpdir = tempfile::tempdir().unwrap();
    let peers = start_two_cli_peers(&tmpdir);

    let alice_msgs: Vec<SentEventIds> = (0..3)
        .map(|idx| send_message_ids(&peers.alice.db, &format!("alice msg {idx}")))
        .collect();
    let bob_msgs: Vec<SentEventIds> = (0..3)
        .map(|idx| send_message_ids(&peers.bob.db, &format!("bob msg {idx}")))
        .collect();

    for sent in &alice_msgs {
        assert_eventually(
            &peers.bob.db,
            &format!("has_event:{} >= 1", sent.hex),
            TIMELINE_TIMEOUT_MS,
        );
    }
    for sent in &bob_msgs {
        assert_eventually(
            &peers.alice.db,
            &format!("has_event:{} >= 1", sent.hex),
            TIMELINE_TIMEOUT_MS,
        );
    }

    let alice_conn = open_connection(&peers.alice.db).expect("open alice db");
    let alice_timeline = EventTimeline::new(&alice_conn);
    for sent in &bob_msgs {
        assert_sink_delivery_timeline(&alice_timeline, &sent.b64, "alice");
    }

    let bob_conn = open_connection(&peers.bob.db).expect("open bob db");
    let bob_timeline = EventTimeline::new(&bob_conn);
    for sent in &alice_msgs {
        assert_sink_delivery_timeline(&bob_timeline, &sent.b64, "bob");
    }
}
