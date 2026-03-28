use topo::sim::{
    exact_matrix_bytes, ActivityProfile, IngestPolicy, MessageAuthoring, PeerId, PeerSpec,
    Scenario, Simulation, SparseKnowledge, SyncPolicy, Topology,
};

#[test]
fn tiny_star_scenario_produces_summary_metrics() {
    let scenario = topo::sim::Scenario::tiny_demo(Topology::Star {
        hub: topo::sim::PeerId(0),
    });
    let summary = Simulation::new(scenario)
        .expect("build star simulation")
        .run();

    assert!(summary.published_messages > 0);
    assert!(summary.sync_events > 0);
    assert!(summary.delivered_messages > 0);
    assert!(summary.ingested_messages > 0);
    assert!(summary.range_bytes > 0);
    assert!(summary.key_need_events > 0);
    assert!(summary.key_repair_events > 0);
    assert_eq!(summary.key_need_events, summary.key_repair_events);
    assert!(summary.total_bytes >= summary.range_bytes);
    assert_eq!(
        summary.exact_matrix_bytes_estimate,
        exact_matrix_bytes(4, 8)
    );
}

#[test]
fn tiny_graph_scenario_runs_with_sparse_peer_knowledge() {
    let scenario = topo::sim::Scenario::tiny_demo(Topology::Graph { degree: 2 });
    let summary = Simulation::new(scenario)
        .expect("build graph simulation")
        .run();

    assert!(summary.published_messages > 0);
    assert!(summary.simulated_time_ms > 0);
    assert!(summary.online_peer_samples > 0);
}

#[test]
fn exact_matrix_estimate_matches_100k_square_discussion() {
    assert_eq!(exact_matrix_bytes(100_000, 100_000), 1_250_000_000);
}

#[test]
fn sparse_knowledge_merge_can_learn_large_prefix_without_per_event_queries() {
    let mut left = SparseKnowledge::new();
    let mut right = SparseKnowledge::new();

    assert_eq!(left.mark_range_known(0, 100_000), 100_000);
    let learned = right.merge_from(&left);

    assert_eq!(learned, 100_000);
    assert_eq!(right.known_contiguous_prefix(), 100_000);
    assert_eq!(right.sparse_tail_count(), 0);
}

#[test]
fn hot_window_ingest_can_deliver_more_than_it_projects() {
    let scenario = Scenario {
        peers: vec![
            PeerSpec {
                id: PeerId(0),
                activity: ActivityProfile::AlwaysOnline,
            },
            PeerSpec {
                id: PeerId(1),
                activity: ActivityProfile::AlwaysOnline,
            },
        ],
        topology: Topology::Star { hub: PeerId(0) },
        message_count: 10,
        message_interval_ms: 0,
        message_bytes: 512,
        key_need_bytes: 160,
        key_repair_bytes: 170,
        repair_ttl_ms: 1_000,
        ingest: IngestPolicy::HotMessageWindow {
            recent_message_count: 2,
        },
        sync_rounds: 1,
        authoring: MessageAuthoring::Fixed { peer_id: PeerId(0) },
        sync: SyncPolicy {
            interval_ms: 1,
            link_rtt_ms: 1,
            bandwidth_bytes_per_ms: 1024,
        },
    };

    let summary = Simulation::new(scenario)
        .expect("build hot-window simulation")
        .run();

    assert_eq!(summary.delivered_messages, 10);
    assert_eq!(summary.ingested_messages, 2);
    assert_eq!(summary.delivered_without_ingest, 8);
    assert_eq!(summary.key_need_events, 2);
    assert_eq!(summary.key_repair_events, 2);
}

#[test]
fn without_sync_rounds_no_events_replicate_beyond_the_author() {
    let scenario = Scenario {
        peers: vec![
            PeerSpec {
                id: PeerId(0),
                activity: ActivityProfile::AlwaysOnline,
            },
            PeerSpec {
                id: PeerId(1),
                activity: ActivityProfile::AlwaysOnline,
            },
            PeerSpec {
                id: PeerId(2),
                activity: ActivityProfile::AlwaysOnline,
            },
        ],
        topology: Topology::Graph { degree: 1 },
        message_count: 3,
        message_interval_ms: 0,
        message_bytes: 512,
        key_need_bytes: 160,
        key_repair_bytes: 170,
        repair_ttl_ms: 1_000,
        ingest: IngestPolicy::EagerAll,
        sync_rounds: 0,
        authoring: MessageAuthoring::Fixed { peer_id: PeerId(0) },
        sync: SyncPolicy {
            interval_ms: 1,
            link_rtt_ms: 1,
            bandwidth_bytes_per_ms: 1024,
        },
    };

    let report = Simulation::new(scenario)
        .expect("build no-sync simulation")
        .run_detailed();

    assert_eq!(report.summary.sync_events, 0);
    assert_eq!(report.summary.delivered_messages, 0);
    assert_eq!(report.peers[0].known_contiguous_prefix, 3);
    assert_eq!(report.peers[1].known_contiguous_prefix, 0);
    assert_eq!(report.peers[2].known_contiguous_prefix, 0);
}

#[test]
fn path_propagation_follows_scheduled_pair_edges_only() {
    let topology = Topology::Star { hub: PeerId(1) };
    assert_eq!(topology.neighbors(3, PeerId(0)), vec![PeerId(1)]);
    assert_eq!(topology.neighbors(3, PeerId(2)), vec![PeerId(1)]);

    let scenario = Scenario {
        peers: vec![
            PeerSpec {
                id: PeerId(0),
                activity: ActivityProfile::AlwaysOnline,
            },
            PeerSpec {
                id: PeerId(1),
                activity: ActivityProfile::AlwaysOnline,
            },
            PeerSpec {
                id: PeerId(2),
                activity: ActivityProfile::AlwaysOnline,
            },
        ],
        topology,
        message_count: 1,
        message_interval_ms: 0,
        message_bytes: 512,
        key_need_bytes: 160,
        key_repair_bytes: 170,
        repair_ttl_ms: 1_000,
        ingest: IngestPolicy::EagerAll,
        sync_rounds: 2,
        authoring: MessageAuthoring::Fixed { peer_id: PeerId(0) },
        sync: SyncPolicy {
            interval_ms: 1,
            link_rtt_ms: 1,
            bandwidth_bytes_per_ms: 1024,
        },
    };

    let report = Simulation::new(scenario)
        .expect("build path simulation")
        .run_detailed();

    assert_eq!(report.summary.sync_events, 4);
    assert_eq!(report.peers[0].known_contiguous_prefix, 1);
    assert_eq!(report.peers[1].known_contiguous_prefix, 1);
    assert_eq!(
        report.peers[2].known_contiguous_prefix, 1,
        "sink peer should learn the message only through the hub's pairwise sync edge"
    );
}

#[test]
fn star_leaf_does_not_receive_without_a_live_hub_pair() {
    let scenario = Scenario {
        peers: vec![
            PeerSpec {
                id: PeerId(0),
                activity: ActivityProfile::AlwaysOnline,
            },
            PeerSpec {
                id: PeerId(1),
                activity: ActivityProfile::Offline,
            },
            PeerSpec {
                id: PeerId(2),
                activity: ActivityProfile::AlwaysOnline,
            },
        ],
        topology: Topology::Star { hub: PeerId(1) },
        message_count: 1,
        message_interval_ms: 0,
        message_bytes: 512,
        key_need_bytes: 160,
        key_repair_bytes: 170,
        repair_ttl_ms: 1_000,
        ingest: IngestPolicy::EagerAll,
        sync_rounds: 3,
        authoring: MessageAuthoring::Fixed { peer_id: PeerId(0) },
        sync: SyncPolicy {
            interval_ms: 1,
            link_rtt_ms: 1,
            bandwidth_bytes_per_ms: 1024,
        },
    };

    let report = Simulation::new(scenario)
        .expect("build disconnected-star simulation")
        .run_detailed();

    assert_eq!(report.summary.delivered_messages, 0);
    assert_eq!(report.peers[0].known_contiguous_prefix, 1);
    assert_eq!(report.peers[1].known_contiguous_prefix, 0);
    assert_eq!(
        report.peers[2].known_contiguous_prefix, 0,
        "leaf peers should not learn events without a live hub sync pair"
    );
}
