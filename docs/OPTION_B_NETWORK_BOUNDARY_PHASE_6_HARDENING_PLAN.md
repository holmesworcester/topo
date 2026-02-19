# Option B Phase 6 Hardening Plan (Boundary Narrowing + Readability)

## Scope Note

This document is **Option B network-boundary Phase 6** and is separate from the unrelated `Phase 6` in `docs/PLAN.md`.

## Objective

Finish the boundary carve-out so networking and replication can be reasoned about and tested in isolation without losing realism.

## Outcomes Required

1. Newcomer can trace runtime flow from `node::run_node` to one sync session in under 15 minutes.
2. Network layer depends on contracts, not event-runtime internals.
3. Replication session handler no longer downcasts to QUIC concrete types.
4. Core networking/replication files are split into role-focused modules (target <= 400 lines each).
5. Boundary violations fail fast via automated gate.
6. Replication can be tested with a deterministic fake transport harness that is hard to cheat.

## Current State Snapshot (after Option B Phase 5)

1. Composition root is clear: `src/node.rs` delegates to `src/network/runtime.rs`.
2. Network orchestration and replication protocol moved out of `sync/engine.rs`.
3. Boundary script exists: `scripts/check_boundary_imports.sh` and is exercised via `src/lib.rs` test.
4. Remaining coupling and readability gaps:
   - `src/network/loops.rs` imports `event_runtime::{batch_writer, drain_project_queue, IngestItem}`.
   - `src/replication/session.rs` directly spawns `batch_writer` fallback path.
   - `src/replication/session_handler.rs` downcasts `Box<dyn SessionIo>` into concrete QUIC session IO.
   - Large files (`network/runtime.rs`, `network/loops.rs`, `replication/session.rs`) are still > 750 lines each.

## Non-Goals

1. No wire-format changes.
2. No trust semantic changes.
3. No DB schema changes unless absolutely required for test harness realism.
4. No interactive/CLI UX redesign.

## Execution Order

1. Workstream A: Event ingest boundary contract.
2. Workstream B: Remove SessionIo downcast and QUIC concretions from replication handler path.
3. Workstream C: Split large modules by role.
4. Workstream D: Strengthen architecture gates and CI wiring.
5. Workstream E: Add realistic isolated replication tests with anti-cheat constraints.

---

## Workstream A: Event Ingest Boundary Contract

### Goal

Networking and replication should publish ingest intents through a contract, not by calling event-runtime internals.

### Changes

1. Extend `src/contracts/event_runtime_contract.rs`:
   - Define an ingest runtime trait that covers:
     - enqueue incoming event blob,
     - optional queue drain kick,
     - shared writer acquisition/handle abstraction.
   - Keep typed errors (`IngestError`, `StoreError`) only.
2. Add concrete adapter(s) in `src/event_runtime/sqlite_adapters.rs`.
3. Refactor `src/network/loops.rs` to use contract traits instead of:
   - `batch_writer`,
   - `drain_project_queue`,
   - direct `IngestItem` channel shape.
4. Refactor `src/replication/session.rs` ingest fallback path to depend on the same contract.

### Acceptance Criteria

1. `rg "event_runtime::(batch_writer|drain_project_queue|IngestItem)" src/network src/replication` returns zero matches.
2. Network and replication compile against contract interfaces.
3. Existing integration tests still pass.

### Suggested PR slices

1. Introduce trait + adapter without behavior change.
2. Switch network path.
3. Switch replication path.

---

## Workstream B: Remove SessionIo Downcast

### Goal

`SessionHandler` remains truly polymorphic and transport-agnostic.

### Changes

1. Remove `into_any` downcast dependency from `SessionIo` contract usage path.
2. Introduce an adapter layer where QUIC framing/encoding is handled in transport module.
3. Update `ReplicationSessionHandler` to use only trait methods and typed IO errors.
4. Keep stream materialization marker behavior centralized and tested.

### Acceptance Criteria

1. `rg "into_any|downcast::<|SyncSessionIo<|quinn::" src/replication` returns zero matches.
2. Replication handler behavior unchanged for inbound/outbound role checks.
3. Holepunch + scenario sync tests remain green.

### Suggested PR slices

1. Add trait methods needed to avoid downcast.
2. Migrate session handler.
3. Remove obsolete contract members/adapters.

---

## Workstream C: Readability Split of Large Modules

### Goal

Reduce local cognitive load and improve navigability for newcomers and assistants.

### Target module layout

1. `src/network/`
   - `runtime/mod.rs` (public entry)
   - `runtime/startup.rs`
   - `runtime/discovery.rs`
   - `runtime/autodial.rs`
   - `runtime/peer_dispatch.rs`
   - `loops/mod.rs`
   - `loops/accept.rs`
   - `loops/connect.rs`
   - `loops/download.rs`
   - `loops/tenant_resolution.rs`
2. `src/replication/`
   - `session/mod.rs`
   - `session/initiator.rs`
   - `session/responder.rs`
   - `session/receiver.rs`
   - `session/coordinator.rs`

### Rules

1. Preserve existing public API from `network/mod.rs` and `replication/mod.rs`.
2. Keep behavior-preserving extraction commits; avoid semantic edits in same commit as moves.
3. Each extracted file should include a short module-level doc comment with ownership scope.

### Acceptance Criteria

1. No file in `src/network/` or `src/replication/` exceeds 400 lines (soft cap).
2. `node.rs` remains composition root only.
3. Tests and boundary script remain green.

---

## Workstream D: Architecture Gate Hardening

### Goal

Prevent regression of dependency direction by default.

### Changes

1. Extend `scripts/check_boundary_imports.sh` with explicit forbidden edges:
   - `network -> event_runtime internals`,
   - `replication -> transport concrete types`,
   - `event_runtime -> network/replication/sync`.
2. Add optional positive checks (required edges only through contracts).
3. Add CI workflow job (fast path) invoking boundary script directly.
4. Keep `src/lib.rs` boundary test, but ensure script is also run independently in CI.

### Acceptance Criteria

1. Boundary script fails on intentional violation.
2. CI contains explicit boundary check job.
3. Local and CI behavior match.

---

## Workstream E: Realistic Isolation Test Harness (Hard-to-Cheat)

### Goal

Test replication/session correctness in isolation from QUIC, while preserving realistic failure modes.

### Contract for harness

1. Build `FakeSessionIo` implementing `SessionIo`.
2. Harness must model:
   - frame fragmentation,
   - delayed delivery,
   - out-of-order control/data arrivals,
   - half-close and abrupt close,
   - frame-size violations,
   - deterministic peer-protocol violations.
3. Harness should expose scriptable scenarios with deterministic seed.

### Anti-cheat constraints

1. Tests must assert exact frame-level events (not just final DB state).
2. No direct invocation of internal helper functions that bypass `SessionHandler` entrypoint.
3. Include at least one mutation test target:
   - disable marker send,
   - swap done/done-ack ordering,
   - skip cancellation watch signal,
   and verify tests fail.

### Test suite additions

1. `tests/replication_contract_tests/`
   - `initiator_protocol_ordering.rs`
   - `responder_protocol_ordering.rs`
   - `cancellation_semantics.rs`
   - `error_mapping.rs`
2. Keep existing QUIC integration tests as conformance layer; do not replace them.

### Acceptance Criteria

1. Replication contract tests run without QUIC endpoint startup.
2. At least one anti-cheat mutation case fails as expected.
3. Existing integration tests remain green.

---

## Implementation Tracking

Update this table in each PR/commit.

| Workstream | Status | Commit | Notes |
|---|---|---|---|
| A Ingest Contract | Done | — | Added `IngestItem`, `BatchWriterFn`, `DrainQueueFn` to contracts; threaded fn pointers through network/replication; zero forbidden imports remain |
| B SessionIo De-concretion | Done | — | Added `ControlIo`/`DataSendIo`/`DataRecvIo` sub-traits + `split()` method; adapter pattern in session_handler; zero downcast/QUIC refs in replication |
| C Module Splits | Done | — | `runtime.rs` → 5 files (max 240 lines); `loops.rs` → 4 files (max 316 lines); `session.rs` → 5 files (max 366 lines) |
| D Boundary Gates | Done | — | Hardened `check_boundary_imports.sh` with forbidden edges + positive contract checks; added `.github/workflows/boundary-check.yml` CI gate |
| E Isolation Harness | Done | — | `FakeSessionIo` + 14 tests in `tests/replication_contract_tests/`: protocol ordering, cancellation semantics, error mapping, 3 anti-cheat mutation targets |

## Required Validation Commands (minimum)

1. `bash scripts/check_boundary_imports.sh`
2. `cargo test --lib test_boundary_imports_enforced -q`
3. `cargo test --test holepunch_test -q`
4. `cargo test --test scenario_test test_mdns_two_peers_discover_and_sync -q`
5. `cargo test --test scenario_test test_run_node_multitenant_outbound_isolation -q`
6. `cargo test --test scenario_test test_tenant_scoped_outbound_trust_rejects_untrusted_server -q`

## Handoff Notes for Next Assistant

1. Start with Workstream A and keep each commit behavior-preserving.
2. Do not mix module moves with semantic changes in same commit.
3. After each slice:
   - run validation commands,
   - update tracking table,
   - append short "what changed / why" note.
4. If a boundary change requires contract expansion, update tests first (red->green) before implementation changes.
