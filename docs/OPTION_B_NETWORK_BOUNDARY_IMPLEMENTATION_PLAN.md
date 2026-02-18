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
    async fn recv_control(&mut self) -> Result<bytes::Bytes, SessionIoError>;
    async fn send_control(&mut self, frame: &[u8]) -> Result<(), SessionIoError>;
    async fn recv_data(&mut self) -> Result<bytes::Bytes, SessionIoError>;
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

1. Phase 2 extraction of event runtime modules (`event_runtime/*`) behind contracts.
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
