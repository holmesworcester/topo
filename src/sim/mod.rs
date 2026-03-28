pub mod clock;
pub mod hash_graph;
pub mod key_repair;
pub mod knowledge;
pub mod large_graph_sample;
pub mod node_behavior;
pub mod pair_sync;
#[allow(dead_code)]
mod peer_db_bridge;
pub mod planner_runner;
pub mod query_snapshot;
pub mod runner;
pub mod scenario;
pub mod topology;
pub mod virtual_daemon;

pub use clock::SimTime;
pub use key_repair::{
    create_encrypted_message_with_key, create_key_rotation, create_removal,
    emit_key_requests_for_dbs, emit_key_requests_for_peers, emit_key_shared_responses_for_dbs,
    emit_key_shared_responses_for_peers, seed_deterministic_key_secret, KeyRepairEmitStats,
    KeyResponsePolicy,
};
pub use knowledge::{exact_matrix_bytes, SparseKnowledge};
pub use large_graph_sample::{
    run_large_graph_sampled_decrypt_trial, LargeGraphSampleDecryptConfig,
    LargeGraphSampleDecryptPeerReport, LargeGraphSampleDecryptReport,
};
pub use node_behavior::{
    sqlite_behavior_summary, BehaviorRow, BehaviorValue, EventProjectionFilter, NodeBehaviorEngine,
    NodeBehaviorSummary,
};
pub use pair_sync::{
    plan_pair_sync_intents, run_pair_sync_session, PairSyncDirectionStats, PairSyncIntent,
    PairSyncSessionStats, SimPeerNode,
};
pub use planner_runner::{
    FakeTopologyPreference, PlannedPairSession, PlannerImportedNode, PlannerMode,
    PlannerRoundReport, PlannerRunReport, PlannerSimulation,
};
pub use query_snapshot::{
    import_local_tenants_from_db, import_peer_state, snapshot_messages_via_rpc,
    snapshot_replayed_peer, snapshot_replayed_peer_to_path, ImportedBootstrapContextRow,
    ImportedBootstrapTarget, ImportedConnectTarget, ImportedKnownEvent, ImportedObservedTarget,
    ImportedPeerState, QuerySnapshot,
};
pub use runner::{PeerSimulationState, Simulation, SimulationReport, SimulationSummary};
pub use scenario::{
    ActivityProfile, IngestPolicy, MessageAuthoring, PeerId, PeerSpec, Scenario, SyncPolicy,
};
pub use topology::Topology;
pub use virtual_daemon::VirtualDaemon;
