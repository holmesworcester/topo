# Sparse Simulator + Daemon Alignment Execution Plan

Date: 2026-03-27
Branch: `sparse-sim-plan`
Worktree: `/home/holmes/poc-7/.codex-worktrees/sparse-sim-plan`

## Objective

Build a sparse, in-memory large-community simulator that stays behaviorally
aligned with the real daemon instead of inventing a parallel protocol.

The simulator target is not a simplified parallel app. It is an in-process
host for many virtual daemons that reuse the real daemon's command, event
creation, ingest, projection, and query code wherever those paths can be
backed by an in-memory state model instead of SQLite and real transport.

The simulator must be able to model at least:

1. `100,000` users
2. `100,000` messages/events in the shared corpus
3. connection target selection
4. incoming connections as acceptance of other peers' outbound dials
5. range-sync scheduling
6. dependency fetch
7. repair-lane traffic such as `KeyNeed` / `KeyRepair`
8. simulation time rather than wall-clock waiting

The real daemon remains the authority for:

1. wire shapes
2. projector semantics
3. signer/dep validation
4. connection/session behavior at small and medium scale

## Why this plan exists

The current repo can already run real-daemon sync perf at large event counts,
including `100k`/`200k`/`500k` one-way sync, but it cannot reasonably run
`100k` daemon processes or materialize full per-peer SQL read models for
`100k` peers.

The problem to solve is therefore:

1. keep the daemon honest and measurable,
2. extract the reusable policy/semantic core,
3. give the simulator a sparse backend instead of full per-peer SQL
   materialization,
4. calibrate the simulator against small real-daemon runs before trusting
   large sweeps.

## Enforced system model

There are three layers, and docs/code/tests must match them:

1. `Real daemon runtime`
   - SQL-backed projection/read models
   - QUIC transport
   - Tokio wall-clock loops
   - used for correctness and calibration
2. `Shared semantic/policy core`
   - event metadata and semantic type codes
   - command/event creation logic
   - dependency and signer rules
   - projector semantics
   - query/service semantics where the daemon already exposes them behind
     non-CLI handlers
   - connectivity adequacy policy
   - sync-window policy
3. `Sparse simulator runtime`
   - one process hosting many virtual daemons
   - shared in-memory event/state backend plus sparse per-peer knowledge state
   - simulation clock
   - synthetic reachability/latency/session outcomes
   - same command/event/projection/query core as the daemon
   - temporary SQLite snapshots for selected-peer real RPC read observability
     when a query still requires SQL-backed projection tables

The simulator is not allowed to become a second protocol definition.

## Non-negotiable design rules

### R1. Daemon is the authority

1. The real daemon remains the source of truth for protocol behavior.
2. The simulator must reuse daemon semantics rather than fork them.
3. The simulator should call the same non-CLI command/event creation and
   projection paths the daemon uses today, not reimplement them in
   simulator-only logic.

### R2. No full per-peer SQL read-model simulation

1. The simulator must not materialize `messages/users/reactions/files/...`
   tables per peer as the primary state model.
2. The simulator must use sparse in-memory state such as:
   - exact bitsets,
   - `none except`,
   - `all/prefix except gaps`,
   - intervals,
   - roaring-style compressed sets.
3. The simulator may keep a shared in-memory state representation plus sparse
   peer knowledge overlays, but not one SQLite tenant/read-model per peer.

### R2a. Reuse daemon services, not CLI parsing

1. The simulator should not treat `clap` parsing in
   `runtime/control/cli.rs` as the reusable surface.
2. It should invoke the same underlying RPC/service/command handlers the CLI
   and daemon use after parsing.
3. If current daemon code is too tied to SQLite or sockets, extract a backend
   seam rather than duplicating the business logic in simulator code.

### R2b. Real read RPCs may use selected-peer snapshots

1. The simulator hot path must stay sparse and in memory.
2. For observability or selected peer inspection, the simulator may
   materialize a fresh SQLite DB for one virtual peer and run the
   real in-process RPC read/query path against it.
3. These snapshots are an adaptation layer, not the simulator's primary state
   model.
4. Export should replay one selected peer's known event corpus plus the local
   replay inputs needed for auth/bootstrap/tenant continuity, rather than
   cloning unrelated tenants.
5. Import/export of peer DB state should build on the same seam so `topo` and
   `topo-sim` can interoperate at the database boundary.

### R3. Incoming connections are derived, not planned separately

1. Outbound dial policy is explicit.
2. Incoming connections are the acceptance result of another peer's outbound
   dial intent.
3. The simulator must not invent a separate inbound connection planner.

### R4. Connectivity is modeled by adequacy, not raw sockets

1. The reusable abstraction is "ensure adequate connection state", not
   transport-packet emulation.
2. The policy layer must be able to answer:
   - bootstrap reachability adequacy,
   - steady-state live-session adequacy,
   - hot-window sync adequacy,
   - backfill opportunity adequacy.

### R5. Range sync and dependency fetch remain distinct lanes

1. Range sync remains the bulk anti-entropy path.
2. Dependency fetch remains the targeted repair/fill path.
3. Repair events may travel over those existing mechanisms; the simulator must
   attribute their bytes separately by semantic type and lane.

### R6. Simulation time is a first-class input

1. Simulator timing must not be local wall-clock waiting.
2. Session duration must derive from:
   - RTT,
   - bandwidth,
   - event count / projection cost,
   - policy cadence,
   - retry/backoff,
   - TTL expiry.

## Deliverables

### D1. Execution plan and evidence contract

1. This plan file.
2. A matching evidence file on the branch once code lands.

### D2. Runtime calibration instrumentation

1. Existing range-sync metrics remain intact.
2. Dependency-fetch/session metrics become first-class and queryable.
3. Sync logs can attribute bytes by lane and, where practical, by semantic
   type.

### D3. Reusable policy seam

1. Sync-window selection is reusable by simulator and daemon.
2. Connection adequacy / dial-target policy is extracted into a shape that can
   be backed by SQL+Tokio or by sparse simulated state.
3. Command execution, ingest/projection, and read/query paths needed for the
   experiment are callable against both the real daemon backend and an
   in-memory simulation backend, either directly or through a selected-peer
   SQLite snapshot bridge.

### D4. Sparse simulator scaffold

1. Scenario input format.
2. Simulation clock and event queue.
3. Sparse peer knowledge model.
4. Topology / reachability model.
5. Initial metrics output.

### D5. Calibration and conformance tests

1. Small matching scenarios run both against the daemon and the simulator.
2. The simulator is rejected if it drifts materially from daemon behavior on
   those scenarios.

## Required phases

### Phase 1. Instrument the real daemon for calibration

Purpose:

1. measure what the daemon actually does today,
2. remove unknowns before simulator extrapolation.

Required work:

1. expose dependency-session bytes/events/timing in a way comparable to range
   sync metrics,
2. preserve current `sync_runs` and sync-log behavior,
3. add tests proving the counters move on a pass case and stay zero on a
   no-op/break case where appropriate.

### Phase 2. Extract reusable connectivity and sync policy

Purpose:

1. avoid simulator-specific policy drift,
2. narrow the daemon/simulator seam.

Required work:

1. define a pure-ish connectivity adequacy model,
2. keep incoming connections as derived acceptance of outbound dials,
3. reuse current sync-window ladder and partition logic,
4. keep transport execution in daemon-only code.

### Phase 3. Build sparse simulator kernel

Purpose:

1. run large peer-count experiments locally,
2. avoid per-peer SQL read-model explosion.

Required work:

1. host many virtual daemons in one process,
2. use dense event IDs / metadata plus a shared in-memory event/state backend,
3. implement sparse peer knowledge representation,
4. route local command execution through real daemon command/event paths,
5. route range sync and dependency fetch through simulated transport/session
   operations instead of QUIC/socket loops,
6. support at least star and graph topologies,
7. support online/offline schedules and simulation time.

### Phase 4. Add calibration scenarios

Purpose:

1. establish trust in the simulator,
2. constrain future refactors.

Required work:

1. one or more small scenarios that both real daemon and simulator can run,
2. compare:
   - connection counts,
   - sync windows chosen,
   - bytes by lane,
   - time-to-delivery / time-to-decrypt,
   - hub ingress/egress in star topology.

### Phase 5. Run large sparse scenarios

Purpose:

1. answer the original `100k users / 100k messages` question,
2. make protocol design tradeoffs measurable.

Required work:

1. baseline `100k/100k`,
2. report memory footprint,
3. report range vs dependency bytes,
4. report repair amplification,
5. report time-to-read/decrypt percentiles under chosen assumptions.

## Success criteria

### SC1. Calibration metrics exist for both lanes

1. Range-sync metrics remain available.
2. Dependency-fetch/session metrics are emitted and queryable.
3. Tests prove the new metrics move when dependency traffic exists.

### SC2. Shared policy seam is explicit

1. There is a reusable representation of connection adequacy and dial/sync
   planning.
2. The simulator does not invent an unrelated target-selection policy.
3. Incoming connections are modeled as accepted outbound dials, not a second
   planner.

### SC3. Sparse simulator scaffold runs locally

1. A simulator entrypoint exists on the branch.
2. It can ingest scenario parameters and run with simulation time.
3. It does not require per-peer SQL projection tables.
4. The intended end state is a virtual-daemon harness, not a simulator-only
   message propagation implementation.
5. At least one real RPC read path can inspect a selected simulated peer
   without requiring the simulator to maintain full per-peer SQL state.

### SC4. `100k` users / `100k` messages is explicitly supported by the model

1. The simulator can represent at least `100k` peers and `100k` shared events.
2. The reported state model and memory story do not depend on full per-peer SQL
   read-model rows.

### SC5. Small daemon-vs-simulator comparison exists

1. At least one scenario is executable both ways.
2. The comparison reports daemon and simulator outputs side by side.
3. The branch documents any remaining mismatch rather than hiding it.

### SC6. End-to-end validation is present

1. The branch has targeted tests/checks for new instrumentation and simulator
   pieces.
2. At least one end-to-end comparison or scenario run proves the delivered
   functionality actually works, not just unit-level fragments.

## Required checks for code on this branch

At minimum, run the checks that match the delivered code:

```bash
cargo test -q --test daemon_realistic_network_perf_test -- --ignored --nocapture
cargo test -q --test daemon_multi_source_tiered_window_perf_test -- --ignored --nocapture
cargo test -q --test daemon_perf_test
cargo test -q --lib
```

If new simulator code lands with dedicated tests, also run those targeted tests.

If TLA/runtime mappings are touched, also run:

```bash
python3 scripts/check_projector_tla_conformance.py
python3 scripts/check_projector_tla_bijection.py
```

## Initial branch scope

This branch does not need to finish the whole roadmap.

The minimum acceptable implemented subset is:

1. the plan,
2. at least one calibration/instrumentation improvement,
3. at least one sparse simulator scaffold piece,
4. targeted validation for those pieces.

## Evidence artifact required on this branch

Create:

- `docs/planning/SPARSE_SIMULATOR_AND_DAEMON_ALIGNMENT_EVIDENCE.md`

It must map delivered work to:

1. SC1-SC6
2. exact files changed
3. tests/checks run
4. known remaining gaps

## Merge discipline

Do not claim the simulator is authoritative until:

1. daemon calibration exists,
2. small daemon-vs-simulator comparison exists,
3. evidence file states the remaining mismatch budget explicitly.
