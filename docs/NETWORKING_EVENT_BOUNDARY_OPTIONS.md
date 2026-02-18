# Networking/Event Boundary Options for `poc-7`

## Context

Current behavior is coherent but concentrated in a few large modules:

1. `src/node.rs` orchestrates tenant discovery, endpoint setup, accept loop startup, discovery, and autodial.
2. `src/sync/engine.rs` mixes protocol/session logic with persistence queueing and projection triggering.
3. Event-layer convergence is good: both local create and network ingest eventually go through `project_one`.

The question is not "is it broken?" but "should the networking contract be narrower and cleaner?"

## What We Want

1. A clearer contract between transport runtime and event replication/runtime.
2. Better testability of replication behavior independent of QUIC specifics.
3. Preserve flexibility for mDNS, invite bootstrap, hole punching, and future control messages.
4. Avoid a destabilizing rewrite.

## Option A: Minimal Refactor (Stabilize Current Shape)

### Idea

Keep current architecture, but extract explicit interfaces around the heaviest mixed responsibilities in `sync/engine.rs`.

### Changes

1. Introduce `ReplicationStore` trait for DB-backed responsibilities now embedded in engine loops.
2. Introduce `IngestSink` trait for `(event_id, blob, recorded_by)` writes + projection enqueue.
3. Keep QUIC, mTLS, and stream/message primitives exactly where they are.
4. Split `sync/engine.rs` into smaller files:
   - `sync/session.rs` (initiator/responder loop)
   - `sync/ingest_writer.rs` (batch writer)
   - `sync/coordination.rs` (multi-source coordinator)
   - `sync/peer_runtime.rs` (accept/connect loop orchestration)

### Pros

1. Lowest risk and quickest to land.
2. Immediate readability and test improvements.
3. Preserves all current flexibility.

### Cons

1. Network and replication are still in same subsystem boundary.
2. Contract is cleaner but not strongly enforced at process/runtime boundary.

### When to pick

Pick when you want cleaner code soon, with minimal behavior change risk.

## Option B: Medium Refactor (Explicit Network Runtime vs Replication Engine)

### Idea

Create a harder seam between:

1. `network runtime` (QUIC, mTLS, discovery, intro/hole punch, session lifecycle),
2. `replication engine` (negentropy/state sync protocol, event send/receive decisions),
3. `event runtime` (ingest persistence + projection progression).

### Proposed Contract

1. Network layer exposes `SessionEndpoint` and `SessionHandle` (open/accept sessions, stream frames, peer identity metadata).
2. Replication engine operates on a transport-agnostic session interface (send/recv control/data frames).
3. Event runtime offers `ReplicationStore` + `IngestSink`.

### Module Direction

1. `src/network/` for transport runtime and peer lifecycle orchestration.
2. `src/replication/` for protocol/session logic (today in `sync/engine.rs`).
3. `src/event_runtime/` for ingestion batching and projection queue draining.

### Pros

1. Much cleaner ownership model.
2. Easier future transports/relay strategies without touching replication logic heavily.
3. Easier to test replication deterministically with fake sessions.

### Cons

1. Medium migration effort.
2. Requires careful phased extraction to avoid regressions in bootstrap/invite flows.

### When to pick

Pick when you want significant long-term maintainability gains without a full rewrite.

## Option C: Full Refactor (Protocol-First Core, Transport Plugins)

### Idea

Build a strict "core replication kernel" that is transport-agnostic and state-machine driven, with QUIC as one adapter.

### Changes

1. Move sync protocol machine into pure core package with no DB or QUIC types.
2. Use adapters:
   - QUIC adapter,
   - DB adapter,
   - runtime orchestration adapter.
3. Promote intro/hole-punch and discovery to explicit control-plane services with evented coordination.

### Pros

1. Maximum clarity and portability.
2. Strongest testability and future extensibility.

### Cons

1. Highest engineering cost.
2. Highest integration risk.
3. Slower to deliver direct user-visible value.

### When to pick

Pick only if this project is becoming a long-lived platform with multiple transport backends.

## Option D: No Structural Refactor (Document + Guardrails Only)

### Idea

Keep current code structure, but formalize boundaries through docs, ownership rules, and tests.

### Changes

1. Add architecture docs with approved call paths.
2. Add tests that lock current boundary assumptions.
3. Add lint/CI checks around module dependencies.

### Pros

1. Very low churn.
2. No migration risk.

### Cons

1. Complexity keeps accumulating in current hot modules.
2. Design debt continues, just documented better.

### When to pick

Pick only if team bandwidth is very constrained.

## Recommended Path

Recommend **Option B**, delivered in **Option A-style phases**.

### Why

1. Option A alone improves readability but does not sufficiently narrow the runtime contract.
2. Option C is likely too heavy for current scope.
3. Option B gives real boundary clarity while keeping migration risk manageable.

## Suggested Phased Plan (for Option B)

### Phase 1: Carve Interface Seams

1. Define `ReplicationStore`, `IngestSink`, and `SessionIo` traits.
2. Keep existing behavior and DB schema unchanged.
3. Add fake implementations for deterministic unit tests.

### Phase 2: Extract Replication Engine Module

1. Move initiator/responder session loops behind `replication::engine`.
2. Keep `node.rs` and QUIC orchestration unchanged initially.
3. Validate with existing integration tests.

### Phase 3: Move Network Orchestration

1. Create `network::runtime` for accept/connect/discovery/intro orchestration.
2. Keep trust checks in existing DB-backed policy provider.
3. Keep current bootstrap and invite flows behavior-identical.

### Phase 4: Isolate Event Runtime

1. Move batch writer/project queue handling into `event_runtime`.
2. Keep `project_one` contract unchanged.
3. Verify recovery/replay semantics.

### Phase 5: Tighten Contracts

1. Remove remaining direct DB calls from network module.
2. Restrict cross-module imports (enforce dependency direction).
3. Add architecture tests for seam compliance.

## Risk Controls

1. Preserve wire protocol and DB schema during refactor phases.
2. Run two-process invite/bootstrap sync tests on each phase.
3. Gate rollout by behavior checks:
   - invite accept + push-back,
   - peer removal teardown,
   - hole-punch intro path,
   - multi-tenant routing by `recorded_by`.

## Decision Summary

1. If you want minimal disruption now: Option A.
2. If you want cleaner long-term architecture with acceptable risk: Option B (recommended).
3. If you want framework-grade modularity: Option C.
4. If you cannot absorb refactor work now: Option D.
