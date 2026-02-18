# Option B Detailed Plan: Network Runtime vs Replication Engine Boundary

## Objective

Implement Option B as a staged refactor that improves:

1. newcomer understanding of runtime flow,
2. code readability and local reasoning,
3. ease and safety of LLM-assisted implementation,
4. realistic, hard-to-cheat isolation testing for networking.

The refactor preserves current wire protocol and behavior while tightening ownership boundaries.

## Goals (Priority Order)

1. **Newcomer comprehension**
   - Trace one sync session in 10-15 minutes.
   - Find where to change trust, dialing, session protocol, and projection without broad search.
2. **Code readability**
   - Shrink `src/sync/engine.rs` and `src/node.rs` into role-focused modules.
   - Reduce hidden side effects and mixed responsibilities.
3. **LLM-assisted implementation**
   - Small PR slices with explicit contracts and typed failures.
   - Localized breakage when boundaries are violated.
4. **Isolation testing realism**
   - Real QUIC+mTLS and process boundaries for integration/conformance.
   - Strong anti-bypass rules to prevent "fake green" tests.

## Non-Goals

1. Changing event wire format or event schemas.
2. Replacing QUIC.
3. Changing trust semantics.
4. DB schema migration for this refactor itself.

## Current Pain Points

1. `src/sync/engine.rs` mixes protocol logic, queue management, ingest writer, and projection triggering.
2. `src/node.rs` mixes endpoint setup, routing, discovery, autodial, and lifecycle orchestration.
3. Networking and event runtime still couple through direct DB/projection calls.

## Target Architecture

1. **Network runtime**
   - QUIC+mTLS endpoints, accept/connect lifecycle, discovery, intro/holepunch.
2. **Replication engine**
   - Session behavior: reconciliation, control/data frame sequencing, completion semantics.
3. **Event runtime**
   - Ingest persistence, queue progression, projection scheduling and replay safety.

## Contracts to Freeze Early

Define all boundary contracts in phase 1 (not incrementally) to avoid throwaway adapters.

### Network contract (typed and bounded)

```rust
pub struct TenantId(pub String);
pub struct PeerFingerprint([u8; 32]);

pub enum SessionDirection {
    Inbound,
    Outbound,
}

pub struct SessionMeta {
    pub session_id: u64,
    pub tenant: TenantId,
    pub peer: PeerFingerprint,
    pub remote_addr: std::net::SocketAddr,
    pub direction: SessionDirection,
}

pub enum TrustDecision {
    Allow,
    Deny,
}

pub enum TrustError {
    StoreUnavailable,
    Internal(String),
}

pub enum SessionIoError {
    ConnectionLost,
    FrameTooLarge { len: usize, max: usize },
    PeerViolation(String),
    Timeout,
    Internal(String),
}

#[async_trait::async_trait]
pub trait TrustOracle: Send + Sync {
    async fn check(&self, tenant: &TenantId, peer: &PeerFingerprint)
        -> Result<TrustDecision, TrustError>;
}

#[async_trait::async_trait]
pub trait SessionIo: Send {
    fn session_id(&self) -> u64;
    fn max_frame_size(&self) -> usize;
    async fn poll_send_ready(&mut self) -> Result<(), SessionIoError>;
    async fn recv_control(&mut self) -> Result<Vec<u8>, SessionIoError>;
    async fn send_control(&mut self, frame: &[u8]) -> Result<(), SessionIoError>;
    async fn recv_data(&mut self) -> Result<Vec<u8>, SessionIoError>;
    async fn send_data(&mut self, frame: &[u8]) -> Result<(), SessionIoError>;
    async fn close_session(&mut self, code: u32, reason: &[u8]) -> Result<(), SessionIoError>;
}

#[async_trait::async_trait]
pub trait SessionHandler: Send + Sync {
    async fn on_session(
        &self,
        meta: SessionMeta,
        io: Box<dyn SessionIo>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> Result<(), String>;
}
```

### Event-runtime contract

```rust
pub trait IngestSink {
    fn ingest_event(&self, tenant: &TenantId, event_id: [u8; 32], blob: Vec<u8>)
        -> Result<(), IngestError>;
}

pub trait ReplicationStore {
    fn enqueue_outbound(&self, peer: &PeerFingerprint, ids: &[[u8; 32]])
        -> Result<(), StoreError>;
    fn claim_outbound(&self, peer: &PeerFingerprint, limit: usize)
        -> Result<Vec<[u8; 32]>, StoreError>;
    fn load_shared_blob(&self, id: &[u8; 32])
        -> Result<Option<Vec<u8>>, StoreError>;
}
```

### Contract invariants

1. `SessionHandler::on_session` is invoked only after mTLS success and peer fingerprint extraction.
2. `PeerFingerprint` is binary type-level identity, not unchecked hex string.
3. Backpressure is explicit through `poll_send_ready`.
4. Cancellation is explicit through `CancellationToken`.
5. Error classes are typed at boundary; no `anyhow::Result` across boundaries.

## Module Layout Target

1. `src/contracts/`
   - `network_contract.rs`, `replication_contract.rs`, `event_runtime_contract.rs`
2. `src/network/`
   - `runtime.rs`, `quic_adapter.rs`, `tenant_router.rs`, `discovery.rs`, `intro.rs`, `punch.rs`
3. `src/replication/`
   - `session.rs`, `coordinator.rs`, `engine.rs`
4. `src/event_runtime/`
   - `ingest_writer.rs`, `replication_store_sqlite.rs`, `project_queue_driver.rs`

## Revised Phase Plan (Risk-Adjusted)

## Phase 0: Baseline, Trace Oracle, and Guardrails

1. Freeze baseline tests:
   - `tests/two_process_test.rs`
   - `tests/holepunch_test.rs`
   - `tests/rpc_test.rs`
   - `tests/cli_test.rs`
2. Add structured tracing spans for a canonical session flow to compare behavior before/after extraction.

Done when baseline tests pass and trace output is captured for one canonical run.

## Phase 1: Define All Contracts + Thin Adapters (No Behavior Change)

1. Add network + event-runtime contracts together.
2. Add thin adapters over current QUIC/session and store APIs.
3. Add typed boundary errors.

Done when contracts compile and are exercised by existing integration paths.

## Phase 2: Extract Event Runtime First

1. Move ingest writer and project queue drive to `src/event_runtime/*`.
2. Implement `IngestSink` and `ReplicationStore` SQL adapters.

Why first: this stabilizes lower boundary and avoids temporary adapters in replication extraction.

Done when network/replication no longer call projection internals directly.

## Phase 3: Extract Replication Session Logic

1. Move initiator/responder loops to `src/replication/session.rs`.
2. Keep wire semantics unchanged.

Done when `sync/engine.rs` is orchestration glue only.

## Phase 4: Extract Network Runtime

1. Move accept/connect/discovery/intro/holepunch orchestration to `src/network/runtime.rs`.
2. Keep trust policy backed by existing SQL trust semantics.
3. Add active-session revocation behavior through cancellation.

Done when `src/node.rs` is composition root and routing semantics match baseline.

## Phase 5: Boundary Enforcement + Adversity Suite

1. Enforce dependency direction in CI:
   - network must not import projection/event-runtime internals,
   - replication must depend on contracts, not concrete QUIC types.
2. Add dedicated privileged CI job for netns/netem adversity tests.

Done when dependency checks and adversity CI are stable and mandatory.

## Realistic, Hard-to-Cheat Test Strategy

## Test tiers

1. **Tier 1 (fast):** unit/property tests for parsers/state transitions.
2. **Tier 2 (medium):** in-process real QUIC+mTLS integration tests.
3. **Tier 3 (slow):** multi-process conformance tests.
4. **Tier 4 (CI privileged):** netns + `tc netem` adversity tests.

If privileged CI is unavailable, Tier 4 must run in a scheduled external runner and be required before release tags.

## Conformance matrix

1. Handshake trust
   - trusted accepted,
   - untrusted rejected,
   - removed peer denied,
   - active session terminated after revocation.
2. Session integrity
   - control/data completion semantics unchanged,
   - malformed/oversized frame rejection.
3. Runtime lifecycle
   - reconnect behavior,
   - endpoint observation behavior,
   - intro/holepunch path.
4. Idempotency and crash safety
   - re-delivery does not duplicate,
   - crash between ingest and projection is recoverable.
5. Concurrent session interleaving
   - multiple sessions for same tenant against shared outbound queue,
   - no double-claim, no loss, no deadlock.

## Anti-bypass controls

1. Integration tests must use production trust oracle implementation (SQL-backed).
2. Explicit "untrusted cert rejected" test catches permissive trust shortcuts.
3. No test-only permissive verifier flags in integration binaries.
4. Same runtime path in prod and tests for transport handshake/session flow.

## LLM-Assisted Implementation Rules

1. PR size: one phase sub-step, <= 3 conceptual areas.
2. Prompt requirements:
   - include boundary contracts and invariants,
   - explicit "no behavior change" scope for extraction-only PRs,
   - required test evidence.
3. Merge gate:
   - boundary checks pass,
   - baseline conformance tests pass,
   - no forbidden imports introduced.

Phase 1 must include a short spike + checkpoint: validate contract against one real extraction slice before freezing final signatures.

## Updated Acceptance Checklist

1. Boundary contracts use typed errors (no `anyhow` at boundary).
2. `SessionMeta` includes `session_id` and `direction`.
3. Backpressure and max frame sizing are enforced at `SessionIo`.
4. Cancellation behavior is explicit and tested.
5. Existing behavior validated by baseline tests and trace-structure comparison.
6. Dependency direction checks added as soon as each boundary is extracted (not only final phase).
7. Tiered tests documented and wired in CI.
8. Privileged Tier 4 execution path is concrete (not aspirational).

## Success Criteria

1. Newcomer can trace one sync session touching <= 4 files.
2. `src/sync/engine.rs` and `src/node.rs` are significantly smaller and role-focused.
3. Network stack is testable in isolation with real QUIC+mTLS and process boundaries.
4. LLM implementation throughput improves because boundaries and acceptance rules are explicit.

## Claude Opus 4.6 Feedback Summary

Feedback was gathered via CLI (`claude -p --model claude-opus-4-6`) and the plan was updated accordingly.

High-impact points incorporated:

1. Added explicit backpressure and frame bound handling in `SessionIo`.
2. Added typed boundary errors; removed boundary-level `anyhow`.
3. Added explicit cancellation contract.
4. Reordered migration: extract event runtime before replication extraction.
5. Added tiered testing model and privileged adversity CI strategy.
6. Added explicit concurrent-session interleaving test requirement.

Raw review artifact: `docs/reviews/OPTION_B_PLAN_OPUS46_FEEDBACK.md`.

## Branch Status (2026-02-18)

This branch implements a substantial **Phase 1 contract + adapter slice** with runtime wiring, while keeping behavior and wire protocol intact.

Completed in code:

1. Added explicit network/event contracts in `src/contracts/`.
2. Added QUIC session adapter (`SyncSessionIo`) with typed boundary errors and frame bound checks.
3. Added SQL-backed trust adapter (`SqliteTrustOracle`) implementing contract trust checks.
4. Added `LegacySyncSessionHandler` bridge and routed major session entry points through `SessionHandler`:
   - accept loop,
   - connect loop,
   - invite bootstrap sync,
   - hole-punch sync,
   - coordinated multi-source download.
5. Added explicit cancellation token flow for sessions and active-session revocation cancellation watch.
6. Replaced several direct trust checks with contract-backed trust oracle checks.

Validation snapshot:

1. `cargo test` passes end-to-end on this branch.
2. Existing realism/integration suites still pass (no wire/protocol behavior regression observed in current tests).

Still remaining for full Option B completion:

1. Phase 2 completion: remove compatibility shims and fully stop direct projection internals from replication/network paths.
2. Phase 3 extraction of replication session logic into dedicated replication module.
3. Phase 4 extraction of network runtime orchestration out of `node.rs`/`sync` glue.
4. Phase 5 dependency-direction enforcement and privileged adversity CI hardening.

## Phase 2 Progress (2026-02-18, follow-up)

A follow-up extraction slice was completed after the Phase 1 checkpoint:

1. Moved ingest runtime implementation (`IngestItem`, `batch_writer`) into `src/event_runtime/ingest_runtime.rs`.
2. Added SQL-backed event-runtime adapters in `src/event_runtime/sqlite_adapters.rs`:
   - `SqliteIngestSink` implementing `IngestSink`
   - `SqliteReplicationStore` implementing `ReplicationStore`
3. Kept compatibility for existing callers via `sync::engine` re-export of `batch_writer` and `IngestItem`.
4. Preserved behavior in sync loops while narrowing ownership of ingest/projection queue flow toward the event-runtime module.

Validation performed for this slice:

1. `cargo test --lib --no-run`
2. `cargo test --test scenario_test --no-run`
3. `cargo test --test two_process_test -q`
4. `cargo test --test holepunch_test -q`
5. `cargo test --test rpc_test -q`
6. `cargo test --test cli_test -q`

## Current Branch Snapshot (Rebased)

1. Branch: `exec/option-b-network-boundary`
2. Base: `master` at `241094b` (plus earlier master history)
3. Option B commits on top:
   - `efca1a0` - Phase 1 contracts/adapters/session-handler wiring
   - `933fa9f` - Phase 2 event-runtime ingest slice
   - `e51fd33` - Strengthen plan with phase tracking and handoff context
4. Worktree status expectation before starting new work: `git status -sb` should be clean.

## Phase Status Tracker

| Phase | Status | What is complete | Remaining to close phase |
|---|---|---|---|
| Phase 0 | Complete | Baseline behavior/test gates established | None |
| Phase 1 | Complete | Contracts + adapters + session handler wiring landed | None |
| Phase 2 | Complete | Ingest runtime + SQL adapters + `drain_project_queue` boundary; shims removed; `project_one` no longer imported from sync/node | None |
| Phase 3 | Not Started | N/A | Extract replication session logic to `src/replication/*` |
| Phase 4 | Not Started | N/A | Extract network runtime orchestration to `src/network/*` |
| Phase 5 | Not Started | N/A | Enforce dependency direction + privileged adversity CI |

## Progress Tracking Rules

1. Every implementation checkpoint must update this doc in-place with:
   - commit hash,
   - date,
   - completed checklist items,
   - commands run and pass/fail outcome.
2. Do not mark a phase complete without both code movement and listed test gate evidence.
3. Keep all extraction PRs "no behavior change" unless explicitly scoped otherwise.

## Next Task (Phase 2 Completion) - Concrete Checklist

Phase 2 is in-progress. The remaining work removes compatibility shims and finishes decoupling
projection internals from replication/network paths.

### 2a. Remove `project_one` calls from `sync/engine.rs`

Current state: `src/sync/engine.rs` line 37 imports `projection::pipeline::project_one` and calls
it directly at lines ~1021 and ~1262 during project-queue drain in `accept_loop_with_ingest` and
`connect_loop`.

Steps:
1. Add a `ProjectionDriver` trait (or extend `IngestSink`) in `src/contracts/event_runtime_contract.rs`
   that abstracts the project-queue drain loop (receive event IDs, call project, return decision).
2. Implement the trait in `src/event_runtime/sqlite_adapters.rs` wrapping the existing
   `project_one` call and queue drain logic.
3. Thread the trait object through `accept_loop_with_ingest` and `connect_loop` parameters.
4. Remove `use crate::projection::pipeline::project_one` from `sync/engine.rs`.

### 2b. Encapsulate `project_one` inside event-runtime boundary

Current state: `src/event_runtime/ingest_runtime.rs` line 16 imports `project_one` directly.
This is acceptable since `event_runtime` owns projection scheduling, but the import should be
internal-only (not re-exported).

Steps:
1. Confirm `project_one` is not re-exported from `event_runtime/mod.rs` (it is not currently).
2. Move the project-queue drain loop from `batch_writer` into a helper that uses the contract
   trait, so `batch_writer` receives a trait object rather than calling `project_one` directly.
   This allows the same `batch_writer` to work with test stubs.
3. If `project_one` remains called only inside `event_runtime/`, that is within-boundary and
   acceptable for Phase 2 closure. Full contract-only access is a Phase 5 hardening item.

### 2c. Remove re-export shims in `sync/engine.rs`

Current state: `src/sync/engine.rs` line 47 has `pub use crate::event_runtime::{batch_writer, IngestItem};`.
`src/node.rs` line 76 imports these re-exports via `crate::sync::engine::{..., batch_writer, IngestItem}`.

Steps:
1. Update `src/node.rs` to import `batch_writer` and `IngestItem` directly from `crate::event_runtime`.
2. Remove the `pub use` re-export line from `sync/engine.rs`.
3. Grep for any other callers of `sync::engine::batch_writer` or `sync::engine::IngestItem` and
   redirect them to `event_runtime`.

### 2d. Validate Phase 2 completion

1. Run Fast Gate tests.
2. Confirm: `rg 'projection::pipeline' src/sync/ src/node.rs` returns zero matches.
3. Confirm: `rg 'sync::engine::.*(batch_writer|IngestItem)' src/` returns zero matches outside
   `sync/engine.rs` itself.
4. Update Phase Status Tracker to mark Phase 2 complete with commit hash and date.

---

## Planned Task (Phase 3) - Concrete Checklist

### 3a. Create `src/replication/` module structure

1. Create `src/replication/mod.rs` with `pub mod session;`.
2. Create `src/replication/session.rs`.
3. Add `pub mod replication;` to `src/lib.rs`.

### 3b. Move session functions to `src/replication/session.rs`

Move the following from `src/sync/engine.rs`:

1. **`run_sync_initiator_dual`** (lines ~413-735, ~323 lines)
   - Initiator-side bidirectional sync: negentropy reconciliation, data streaming, shutdown
     protocol (DataDone/Done/DoneAck), optional multi-peer coordination via `PeerCoord`.
2. **`run_sync_responder_dual`** (lines ~742-950, ~209 lines)
   - Responder-side bidirectional sync: responds to negentropy, streams egress events, waits
     for peer DataDone before DoneAck.
3. **`spawn_data_receiver`** (lines ~202-400, ~200 lines)
   - Blocking task that receives events from data stream, sends through ingest channel,
     tracks received byte count, signals when peer's DataDone is received.
4. **`spawn_peer_removal_cancellation_watch`** — do NOT move this to replication.
   - This function (lines ~77-97) monitors trust tables and cancels session tokens.
   - Ownership decision: **network runtime owns cancellation orchestration** (Phase 4).
     Replication sessions receive a `CancellationToken` but do not decide when to cancel.
   - In Phase 3, keep this function in `sync/engine.rs` (it stays with orchestration glue).
   - In Phase 4, move it to `src/network/runtime.rs` alongside `PeerDispatcher`.
5. **Session-local constants** used only by the above:
   - `NEGENTROPY_FRAME_SIZE`, `CONTROL_POLL_TIMEOUT`, `NEED_CHUNK`, `ENQUEUE_BATCH`,
     `HAVE_CHUNK`, `EGRESS_CLAIM_COUNT`, `EGRESS_CLAIM_LEASE_MS`, `DATA_DRAIN_TIMEOUT`.
6. **`SyncStats`** return type (if defined locally in engine.rs and used only by session functions).

### 3c. Keep compatibility via re-exports

1. Add temporary re-exports in `src/sync/engine.rs`:
   `pub use crate::replication::session::{run_sync_initiator_dual, run_sync_responder_dual};`
   so existing call sites (`accept_loop_with_ingest`, `connect_loop`, `download_from_sources`)
   compile without modification.
2. Mark re-exports with `// TRANSITIONAL: remove when orchestration moves to network runtime`.

### 3d. Verify `sync/engine.rs` reduction

After extraction, `src/sync/engine.rs` should contain only orchestration glue (~700-800 lines):
- `accept_loop` (~37 lines)
- `accept_loop_with_ingest` (~213 lines) - orchestration wrapper
- `resolve_tenant_for_peer` (~21 lines) - tenant resolution helper
- `connect_loop` (~226 lines) - outbound connection orchestration
- `download_from_sources` (~174 lines) - multi-source coordination
- Temporary re-exports pointing to `replication::session`

### 3e. Validate Phase 3 completion

1. Run Fast Gate tests.
2. Run Phase 3 Gate tests (including `scenario_test` and `sync_graph_test`).
3. Confirm: `wc -l src/sync/engine.rs` is under 900 lines.
4. Confirm: `run_sync_initiator_dual` and `run_sync_responder_dual` are defined in
   `src/replication/session.rs`, not in `src/sync/engine.rs`.
5. Update Phase Status Tracker with commit hash, date, and test evidence.

## Planned Task (Phase 4) - Concrete Checklist

### 4a. Create `src/network/` module structure

1. Create `src/network/mod.rs` with `pub mod runtime;`.
2. Create `src/network/runtime.rs`.
3. Add `pub mod network;` to `src/lib.rs`.

### 4b. Move network orchestration from `src/node.rs` to `src/network/runtime.rs`

`src/node.rs` is currently ~748 lines. Move the following:

1. **`PeerDispatcher` struct** (lines ~37-70, ~34 lines)
   - Manages peer deduplication with `DiscoveryAction` enum (Skip/Connect/Reconnect).
   - Tracks `(peer_id, addr, cancellation_token)` per discovered peer.
2. **`run_node` main body** (lines ~251-629, ~379 lines)
   - Loads tenant identities from DB.
   - Creates QUIC endpoint with `WorkspaceCertResolver`.
   - Per-tenant: spawns `accept_loop_with_ingest` (inbound), `connect_loop_to_auto_peers`
     (outbound), auto-discovery refresh.
   - Creates shared `batch_writer` channel for inbound events.
3. **Discovery functions** (lines ~138-250, ~113 lines)
   - `load_placeholder_invite_autodial_targets` - load bootstrap peers from DB.
   - `collect_placeholder_invite_autodial_targets` - transform discovery list.
   - `build_tenant_client_config` - create per-tenant QUIC client config.
   - `spawn_placeholder_autodial_refresher` - background discovery refresh task.
   - `spawn_connect_loop_thread` - wrapper to spawn outbound connect_loop.
4. **Utility functions** (lines ~84-137, ~54 lines)
   - `normalize_discovered_addr_for_local_bind` - handle loopback binding.

### 4c. Move remaining network-lifecycle from `src/sync/engine.rs`

After Phase 3 leaves engine.rs as orchestration glue, move:
- `accept_loop` and `accept_loop_with_ingest` - accept-side orchestration.
- `connect_loop` - outbound connection orchestration.
- `resolve_tenant_for_peer` - tenant resolution for inbound peers.
- `download_from_sources` - multi-source coordinated download.
- Active-session cancellation watch hooks.

### 4d. Move discovery/intro/punch orchestration

- Discovery/autodial entrypoints currently called by `node.rs`.
- Intro/holepunch orchestration entrypoints currently in `src/sync/punch.rs`.
- These become `src/network/discovery.rs`, `src/network/intro.rs`, `src/network/punch.rs`.

### 4e. Reduce `src/node.rs` to composition root

After extraction, `src/node.rs` should be ~100-150 lines containing only:
- Main entry point that delegates to `network::runtime`.
- Error handling for startup.
- Shutdown coordination.
- No accept/connect/discovery/intro/punch logic.

### 4f. Wiring constraints

1. Keep session execution routed through `SessionHandler` contract (no direct protocol loop
   coupling in network runtime).
2. Keep trust decisions routed through `TrustOracle` adapter; avoid reintroducing direct trust
   SQL calls inside network runtime.
3. Move `spawn_peer_removal_cancellation_watch` here from `sync/engine.rs` (ownership decision
   from Phase 3: network runtime owns cancellation orchestration). Integrate it with
   `PeerDispatcher` so that when `TrustOracle::check` returns `Deny` for a previously trusted
   peer, the dispatcher cancels that peer's `CancellationToken`.

### 4g. Validate Phase 4 completion

1. Run Fast Gate tests.
2. Run Phase 4 Gate tests (below).
3. Confirm: `wc -l src/node.rs` is under 200 lines.
4. Confirm: `PeerDispatcher` and `run_node` body are defined in `src/network/runtime.rs`.
5. Confirm no function *definitions* for network-lifecycle logic remain in `src/node.rs`:
   `rg '^\s*(pub\s+)?(async\s+)?fn\s+(accept_loop|connect_loop|.*discovery.*)' src/node.rs`
   returns zero matches. Calls/imports/delegations to `network::runtime` are expected and OK.
6. Update Phase Status Tracker with commit hash, date, and test evidence.

## Planned Task (Phase 5) - Concrete Checklist

### 5a. Enforce dependency direction in code

Target dependency graph (arrows = "may depend on"):
```
contracts/  <--  network/      (network depends on contracts)
contracts/  <--  replication/   (replication depends on contracts)
contracts/  <--  event_runtime/ (event_runtime depends on contracts)
event_runtime/ contracts  <--  replication/  (replication uses event_runtime via contracts)
contracts/  <--  transport/     (transport depends on contracts)
```

### 5b. Add CI dependency-direction check

Create `scripts/check_boundary_imports.sh` (or equivalent build-script/test) that runs the
following forbidden-import patterns and exits non-zero on any match:

```bash
# Check both `use crate::` imports AND fully-qualified path usage (crate::mod::...)
# to prevent bypass via inline paths, type aliases, or re-exports.

check_no_match() {
  local pattern="$1"
  local path="$2"
  if rg -n "$pattern" "$path"; then
    echo "boundary violation: pattern '$pattern' matched in $path" >&2
    exit 1
  fi
}

# network must not reach into projection or event_runtime internals or sync
check_no_match 'crate::projection' src/network/
check_no_match 'crate::event_runtime::ingest_runtime' src/network/
check_no_match 'crate::sync' src/network/

# replication must not reach into projection directly
check_no_match 'crate::projection' src/replication/

# replication must not use concrete QUIC types
check_no_match 'quinn::' src/replication/

# event_runtime must not reach into network, replication, or sync
check_no_match 'crate::network' src/event_runtime/
check_no_match 'crate::replication' src/event_runtime/
check_no_match 'crate::sync' src/event_runtime/
```

Note: these patterns catch both `use crate::` imports and inline fully-qualified paths
(`crate::projection::pipeline::project_one(...)`). If Rust AST-level checking becomes
feasible (e.g. via a custom lint or `cargo-depcheck`), prefer that over regex.

Wire this into CI as a required check (same tier as `cargo test --lib`).

### 5c. Add/confirm anti-bypass tests

1. Untrusted cert rejection enforced through production `PinnedCertVerifier` path.
2. Trust-oracle integration path remains SQL-backed in integration tests.
3. Removed-peer active session cancellation path is covered.
4. No test-only permissive verifier flags exist in integration binaries.

### 5d. Remove transitional compatibility debt from Phases 1-4

1. Remove `LegacySyncSessionHandler` downcast-dependent bridge — replace with direct
   `SessionHandler` dispatch now that session logic lives in `replication/session.rs`.
2. Remove all `sync::engine` re-exports pointing to `replication::session` and `event_runtime`.
3. Remove any `// TRANSITIONAL` markers and the shims they annotate.
4. Grep for remaining `anyhow::Result` at boundary traits — replace with typed errors.
5. Remove any network-path direct dependency on sync internals.

### 5e. Add Tier 4 adversity test infrastructure

1. Create `tests/adversity/` directory with netns+netem test harness.
2. Minimum adversity scenarios:
   - **Partition-heal**: two nodes syncing, partition for 10s, heal, verify convergence.
   - **Asymmetric loss**: 20% packet loss on one direction, verify eventual consistency.
   - **Latency spike**: inject 500ms latency mid-session, verify no timeout false-positives
     (session timeout is configurable, default 60s).
   - **Reorder**: packet reordering on QUIC streams, verify frame reassembly.
3. CI integration:
   - Privileged CI job (`needs: [unit, integration]`) runs adversity tests.
   - If privileged runners are unavailable, document a scheduled external runner path
     and require adversity pass before release tags.

### 5f. Validate Phase 5 completion

1. Run Full Gate: `cargo test`.
2. Run boundary-check script: `scripts/check_boundary_imports.sh` exits 0.
3. Confirm: `rg 'TRANSITIONAL' src/` returns zero matches.
4. Confirm: `LegacySyncSessionHandler` is removed or replaced with direct dispatch.
5. Confirm: adversity test harness runs at least the partition-heal scenario successfully.
6. Update Phase Status Tracker with commit hash, date, and test evidence.

## Non-Negotiable Runtime Invariants

1. Do not change DataDone/Done/DoneAck semantics.
2. Keep stream materialization markers used by current connect/session bootstrap paths.
3. Preserve cancellation-on-peer-removal behavior for active sessions.
4. Preserve trust check semantics (SQL-backed trust sources).
5. No event wire format changes and no DB schema changes for this refactor track.

## Test Gates by Stage

### Fast Gate (required for every extraction commit)

1. `cargo test --lib --no-run`
2. `cargo test --test two_process_test -q`
3. `cargo test --test holepunch_test -q`
4. `cargo test --test rpc_test -q`
5. `cargo test --test cli_test -q`

### Phase 3 Gate (before marking Phase 3 complete)

1. Fast Gate commands above
2. `cargo test --test scenario_test --no-run`
3. At least one representative sync-graph smoke:
   - `cargo test --test sync_graph_test multi_source_coordinated_2x_5k -q`

### Phase 4 Gate (before marking Phase 4 complete)

1. Fast Gate commands above
2. `cargo test --test scenario_test test_mdns_two_peers_discover_and_sync -q`
3. `cargo test --test scenario_test test_run_node_multitenant_outbound_isolation -q`
4. `cargo test --test scenario_test test_tenant_scoped_outbound_trust_rejects_untrusted_server -q`
5. `cargo test --test holepunch_test -q`

### Phase 5 Gate (before marking Phase 5 complete)

1. Full Gate command below (`cargo test`)
2. `cargo test --test cheat_proof_realism_test -q`
3. Dependency-direction check command/script passes (CI and local).
4. Privileged adversity run passes (CI or approved external runner):
   - `tests/netns_cheat_proof_realism_test.sh`
   - if local privileges unavailable, attach CI/external-run evidence link in this doc.

### Full Gate (periodic / pre-merge to shared branch)

1. `cargo test`

## Transitional Debt to Remove

| # | Debt item | Introduced | Remove after | Current location |
|---|-----------|-----------|-------------|-----------------|
| 1 | `LegacySyncSessionHandler` downcast bridge | Phase 1 | Phase 5 | `src/sync/session_handler.rs` |
| 2 | `sync::engine` re-export of `batch_writer`/`IngestItem` | Phase 2 | Phase 2 completion | `src/sync/engine.rs` line 47 |
| 3 | Direct `projection::pipeline::project_one` in `sync/engine.rs` | Pre-refactor | Phase 2 completion | `src/sync/engine.rs` lines ~37, ~1021, ~1262 |
| 4 | `sync::engine` re-export of `run_sync_initiator_dual`/`run_sync_responder_dual` | Phase 3 (planned) | Phase 4 | To be added in Phase 3 |
| 5 | Direct runtime orchestration in `src/node.rs` | Pre-refactor | Phase 4 | `src/node.rs` lines ~251-629 |
| 6 | Network-path direct dependency on `sync` internals | Pre-refactor | Phase 4 | `src/node.rs` imports from `sync::engine` |
| 7 | Any remaining `anyhow::Result` at boundary traits | Various | Phase 5 | Grep `anyhow` in `src/contracts/` |

## Cross-Boundary Import Audit (2026-02-18)

Current problematic imports that violate the target dependency graph. Each must be resolved
by the phase indicated.

| Import | File | Line | Violation | Resolve by |
|--------|------|------|-----------|-----------|
| `use crate::projection::pipeline::project_one` | `src/sync/engine.rs` | ~37 | sync→projection direct | Phase 2 |
| `project_one(...)` call in accept path | `src/sync/engine.rs` | ~1021 | sync→projection direct | Phase 2 |
| `project_one(...)` call in connect path | `src/sync/engine.rs` | ~1262 | sync→projection direct | Phase 2 |
| `pub use crate::event_runtime::{batch_writer, IngestItem}` | `src/sync/engine.rs` | ~47 | sync re-exports event_runtime | Phase 2 |
| `use crate::sync::engine::{..., batch_writer, IngestItem}` | `src/node.rs` | ~76 | node→sync for event_runtime symbols | Phase 2 |
| `use crate::projection::pipeline::project_one` | `src/event_runtime/ingest_runtime.rs` | ~16 | event_runtime→projection direct (within-boundary, but tight coupling) | Phase 5 (optional) |
| `use crate::projection::pipeline::project_one` | `src/service.rs` | ~24 | service→projection direct (OK: service is not a boundary module) | N/A |

## Module Size Targets

| Module | Current lines | Target after extraction | Phase |
|--------|--------------|----------------------|-------|
| `src/sync/engine.rs` | ~1639 | ~700-800 (orchestration glue) | Phase 3 |
| `src/sync/engine.rs` | ~700-800 | ~0 (absorbed by network + replication) | Phase 4 |
| `src/node.rs` | ~748 | ~100-150 (composition root) | Phase 4 |
| `src/replication/session.rs` | N/A (new) | ~730 (initiator + responder + helpers) | Phase 3 |
| `src/network/runtime.rs` | N/A (new) | ~580 (run_node + discovery + orchestration) | Phase 4 |

## Assistant Handoff Notes

1. Update this doc first when starting work, then implement, then update with evidence.
2. Favor small extraction commits with explicit no-behavior-change scope.
3. If conflicts with newer `master` changes appear, rebase before starting a new phase slice.
