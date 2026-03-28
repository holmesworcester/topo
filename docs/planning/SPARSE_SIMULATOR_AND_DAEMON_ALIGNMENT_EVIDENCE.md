# Sparse Simulator + Daemon Alignment Evidence

Date: 2026-03-27
Branch: `sparse-sim-plan`
Worktree: `/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan`

## Scope delivered on this branch

Initial roadmap pieces delivered:

1. a comprehensive execution plan with explicit rules, phases, SCs, and
   validation expectations,
2. dependency-session calibration metrics for the direct dependency lane,
3. a sparse in-memory simulator scaffold with scenario, topology, sparse
   knowledge, simulation clock, runner, smoke entrypoint, and a
   virtual-daemon RPC harness that calls the real server dispatch path
   in-process.
4. a first reusable projection/apply seam that lifts `project_one_step` and
   the dep/signer/apply flow behind a backend interface while keeping the
   current SQLite path as the default implementation.
5. a selected-peer SQLite snapshot bridge that lets the sparse simulator run a
   real in-process `Messages` RPC query against a temporary peer view without
   making SQLite the simulator's primary state model.

## Success criteria mapping

### SC1. Calibration metrics exist for both lanes

Partial pass for this branch slice.

Evidence:

1. [runtime.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/runtime/sync_engine/runtime.rs)
   now defines `DependencySessionStats`.
2. [dependency_session.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/runtime/sync_engine/session/dependency_session.rs)
   now records control/data bytes and request/response counters through the
   dependency-session loops.
3. Targeted tests:
   - `request_id_stats_track_control_bytes_and_counts`
   - `response_event_stats_track_wire_and_payload_bytes`

Remaining gap:

1. dependency-session stats are not yet persisted into `sync_runs` or a
   unified calibration surface alongside range sessions.

### SC2. Shared policy seam is explicit

Partial pass for this branch slice.

Evidence:

1. The plan explicitly defines the daemon/simulator/shared-core split in
   [SPARSE_SIMULATOR_AND_DAEMON_ALIGNMENT_EXECUTION_PLAN.md](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/docs/planning/SPARSE_SIMULATOR_AND_DAEMON_ALIGNMENT_EXECUTION_PLAN.md).
2. The plan explicitly fixes incoming connections as accepted outbound dials,
   not a separate planner.

Remaining gap:

1. No code extraction of `ConnectivityAdequacy` / `ConnectivityPlan` has landed
   yet.
2. Read/query reuse is only partially solved:
   - selected-peer `Messages` reads can use a SQLite snapshot bridge,
   - general read-model abstraction is not extracted yet.

### SC2a. Shared projection/apply seam is explicit

Partial pass for this branch slice.

Evidence:

1. New backend module:
   - [backend.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/state/projection/apply/backend.rs)
2. [project_one.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/state/projection/apply/project_one.rs)
   now exposes `project_one_step_with_backend(...)`.
3. [stages.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/state/projection/apply/stages.rs)
   now exposes:
   - `run_dep_and_projection_stages_with_backend(...)`
   - `apply_projection_with_backend(...)`
4. Targeted tests prove the generic seam can project a valid event and reject
   a missing blob without going through the old direct-SQL call shape:
   - `project_one_step_can_run_against_generic_backend_for_valid_event`
   - `project_one_step_can_reject_missing_blob_against_generic_backend`
   - `sqlite_backend_loads_empty_context_via_registry_loader`

Remaining gap:

1. Event-module context loaders still take `&rusqlite::Connection`; the backend
   seam currently wraps them rather than replacing that signature.
2. Read/query code is not generally trait-backed yet, but selected-peer
   snapshots now cover representative real RPC reads and writes through the
   real daemon dispatcher.

### SC2b. Selected-peer real RPC inspection and per-peer DB export/import are possible without making SQLite the simulator hot path

Pass for the selected-peer replay/export slice.

Evidence:

1. New snapshot/export bridge:
   - [query_snapshot.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/query_snapshot.rs)
   - [peer_db_bridge.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/peer_db_bridge.rs)
2. The bridge materializes a fresh selected-peer SQLite DB and then drives the real in-process RPC path through
   [virtual_daemon.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/virtual_daemon.rs).
3. Export uses the selected peer's `recorded_events` corpus plus local replay
   inputs such as `shared_event_index`, bootstrap context, secrets, local
   client ops, observed endpoints, and daemon transport identity before replay.
4. Import uses real tenant/runtime connectivity readers:
   - `discover_local_tenants`
   - `resolve_tenant_transport_target`
   - `load_bootstrap_targets`
   - `load_observed_endpoint_targets`
   - `list_authorized_transport_rows`
5. Targeted tests:
   - `replayed_peer_snapshot_supports_real_rpc_queries_and_local_writes`
   - `exported_peer_db_supports_same_db_join_and_reimported_bootstrap_connectivity`
   - `imported_peer_state_derives_bootstrap_targets_from_real_invite_flow`
   - `replayed_peer_snapshot_supports_real_rpc_commands_and_queries`

Remaining gap:

1. Selected-peer export/import exists, but the simulator hot path still does not
   ingest received events through the shared non-SQL projection backend.
2. There is not yet a CLI-facing `topo-sim import/export` command surface; the
   bridge exists as library code plus tests.

### SC3. Sparse simulator scaffold runs locally

Pass for the scaffold slice.

Evidence:

1. New module export in [lib.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/lib.rs).
2. New simulator modules:
   - [mod.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/mod.rs)
   - [clock.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/clock.rs)
   - [knowledge.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/knowledge.rs)
   - [scenario.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/scenario.rs)
   - [topology.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/topology.rs)
   - [runner.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/runner.rs)
3. Smoke entrypoint:
   - [sim_smoke.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/bin/sim_smoke.rs)
4. Virtual-daemon RPC harness:
   - [virtual_daemon.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/virtual_daemon.rs)
4. Targeted test:
   - [sim_scaffold_test.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/tests/sim_scaffold_test.rs)

### SC4. `100k` users / `100k` messages is explicitly supported by the model

Pass for the current star-topology slice.

Evidence:

1. [knowledge.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/knowledge.rs)
   includes a sparse `prefix + sparse tail` knowledge structure and an
   `exact_matrix_bytes` helper to make the memory story explicit.
2. The execution plan explicitly requires `100k/100k` support without
   per-peer SQL read-model tables.
3. [sim_rpc_large_run.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/bin/sim_rpc_large_run.rs)
   completed a `100,000 users / 100,000 messages` run in star topology while
   using the real in-process daemon RPC path to create and observe the message
   corpus.
4. Completed run summary:
   - daemon `message_count = 100000`
   - simulator `sync_events = 99999`
   - simulator `delivered_messages = 9999900000`
   - simulator `exact_matrix_bytes_estimate = 1250000000`
   - run timing:
     - `generate_ms = 57464`
     - `simulation_ms = 11952`
     - `total_ms = 69535`

### SC5. Small daemon-vs-simulator comparison exists

Partial pass for this branch slice.

Evidence:

1. The new in-process RPC harness exercises the real dispatch path against a
   daemon state without Unix sockets.
2. The targeted test
   [virtual_daemon_rpc_test.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/tests/virtual_daemon_rpc_test.rs)
   proves `CreateWorkspace -> Send -> Generate -> Messages -> Stats` works
   through that path.

Remaining gap:

1. no side-by-side comparison between the real daemon and sparse simulator on
   the same large scenario has landed yet.

### SC6. End-to-end validation is present

Partial pass for the delivered pieces.

Evidence:

1. simulator scaffold smoke test passes,
2. simulator smoke binary runs and emits JSON summary metrics,
3. in-process RPC path test passes,
4. dependency-session stats unit tests pass.

## Files changed

1. [SPARSE_SIMULATOR_AND_DAEMON_ALIGNMENT_EXECUTION_PLAN.md](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/docs/planning/SPARSE_SIMULATOR_AND_DAEMON_ALIGNMENT_EXECUTION_PLAN.md)
2. [SPARSE_SIMULATOR_AND_DAEMON_ALIGNMENT_EVIDENCE.md](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/docs/planning/SPARSE_SIMULATOR_AND_DAEMON_ALIGNMENT_EVIDENCE.md)
3. [lib.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/lib.rs)
4. [mod.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/runtime/mod.rs)
5. [runtime.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/runtime/sync_engine/runtime.rs)
6. [dependency_session.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/runtime/sync_engine/session/dependency_session.rs)
7. [mod.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/mod.rs)
8. [clock.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/clock.rs)
9. [knowledge.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/knowledge.rs)
10. [scenario.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/scenario.rs)
11. [topology.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/topology.rs)
12. [runner.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/runner.rs)
13. [sim_smoke.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/bin/sim_smoke.rs)
14. [virtual_daemon.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/virtual_daemon.rs)
15. [sim_scaffold_test.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/tests/sim_scaffold_test.rs)
16. [virtual_daemon_rpc_test.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/tests/virtual_daemon_rpc_test.rs)
17. [sim_rpc_large_run.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/bin/sim_rpc_large_run.rs)
18. [virtual_daemon_smoke.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/bin/virtual_daemon_smoke.rs)
19. [backend.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/state/projection/apply/backend.rs)
20. [project_one.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/state/projection/apply/project_one.rs)
21. [stages.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/state/projection/apply/stages.rs)
22. [mod.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/state/projection/apply/mod.rs)
23. [query_snapshot.rs](/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan/src/sim/query_snapshot.rs)

## Tests and checks run

1. `cargo fmt`
2. `cargo test -q --test sim_scaffold_test`
3. `cargo test -q --test virtual_daemon_rpc_test`
4. `cargo test -q request_id_stats_track_control_bytes_and_counts`
5. `cargo test -q response_event_stats_track_wire_and_payload_bytes`
6. `cargo run -q --bin sim_smoke -- graph`
7. `cargo run -q --bin virtual_daemon_smoke`
8. `cargo run -q --bin sim_rpc_large_run -- --users 100000 --messages 100000 --topology star --sync-rounds 1`
9. `cargo test -q project_one_step_can_run_against_generic_backend_for_valid_event`
10. `cargo test -q project_one_step_can_reject_missing_blob_against_generic_backend`
11. `cargo test -q sqlite_backend_loads_empty_context_via_registry_loader`
12. `cargo test -q snapshot_message_prefix_supports_real_messages_rpc_query`

## Remaining gaps

1. unify dependency-session calibration with the persisted sync-log / `sync_runs`
   surface,
2. extract code-level `ConnectivityAdequacy` / `ConnectivityPlan` seam from the
   peering runtime,
3. add a side-by-side daemon-vs-simulator comparison scenario,
4. replace the current simulator's synthetic range/dependency execution with
   real shared projection/apply code over a non-SQL backend,
5. scale from one in-process virtual daemon with real RPC corpus control to
   many virtual daemons sharing simulated sync transport,
6. extend the SQLite snapshot adapter beyond `Messages` and make it selective
   enough to support other real RPC reads on chosen virtual peers,
7. add import/export of peer DB state so real `topo` databases can seed or
   inspect simulated peers directly.
