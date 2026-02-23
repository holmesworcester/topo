# Transport Encapsulation Boundary Execution Plan

Date: 2026-02-23
Branch: `exec/transport-encapsulation-boundary-plan`
Worktree: `/home/holmes/poc-7-transport-encapsulation-plan`

## Objective

Make transport boundaries obvious and make runtime data-flow diagrams easy to understand at a glance.

Primary outcomes:

1. Transport is a clearly isolated capsule with a narrow contract.
2. Peering/runtime orchestration no longer touches QUIC stream wiring details.
3. Diagrams show contract-level flow, not concrete type plumbing.

## Scope lock (transport only)

In scope:

1. `src/transport/**`, `src/peering/**`, `src/contracts/**`, runtime composition wiring.
2. Diagram/docs updates for transport and runtime flow.
3. Boundary checks and tests for transport encapsulation.

Out of scope:

1. Event module reorganizations.
2. Service/event-locality changes.
3. Event schema or projection semantics changes.

## Recommended simplification model

Best simplification: **one opaque transport capsule** with two session-entry verbs and one trust verb.

Conceptual contract surface:

1. `accept_next_session(tenant_set) -> SessionEnvelope`
2. `dial_next_session(tenant_id, target) -> SessionEnvelope`
3. `check_trust(tenant_id, peer_fp) -> Allow|Deny`

`SessionEnvelope` carries:

1. `SessionMeta` (tenant, peer, remote_addr, direction)
2. `TransportSessionIo` (already split/ready for sync handler)

This keeps peering in charge of orchestration (when to dial/accept), while transport owns all QUIC stream/cert/wiring details.

## Diagram simplification rules (non-negotiable)

Use only 3 canonical diagrams:

1. **L0 Runtime Loop** (5-6 boxes max): planner -> peering supervisor -> transport capsule -> sync session -> ingest/projection.
2. **L1 Transport Boundary** (inside capsule): endpoint, trust oracle, session factory, intro listener hooks.
3. **L2 Session Data Flow** (single session): control/data frames and ingest output only.

Diagram rules:

1. Show only contract names across boundaries, never concrete Rust types.
2. No arrows directly from peering to `quinn::*` concepts in L0/L2.
3. Keep one arrow vocabulary:
   - solid arrow = data path
   - dashed arrow = control/orchestration
4. Max one level of detail per diagram; deep internals stay in file references.

## Target boundary ownership

1. `transport/*` owns endpoint management, mTLS verification, stream opening, and conversion to `TransportSessionIo`.
2. `peering/*` owns target planning, loop lifecycle, retries, cancellation, and session scheduling.
3. `sync/*` owns protocol state machine over `TransportSessionIo`.
4. `event_pipeline.rs` owns ingest persistence/projection.

## Required refactor phases

### Phase 0: Baseline and map current leaks

1. Capture current boundary leaks (where peering imports QUIC-concrete constructs).
2. Confirm compile/tests baseline.

### Phase 1: Introduce transport runtime seam

1. Add a transport-facing contract module (or extend `contracts/peering_contract.rs`) for session acquisition.
2. Define a `SessionEnvelope` style payload so peering receives ready-to-run session IO + metadata.
3. Keep existing behavior identical.

### Phase 2: Move QUIC session wiring behind transport seam

1. Move `DualConnection` + `QuicTransportSessionIo` construction out of peering loop helpers.
2. Peering loops call transport seam methods to get `SessionEnvelope`.
3. Keep session timeout/cancellation semantics unchanged.

### Phase 3: Thin peering loops to orchestration-only

1. `accept`/`connect` loops keep retry/backoff/planning.
2. Remove direct stream-open/wire code from loops.
3. Keep intro/holepunch lifecycle orchestration in peering, but transport details behind seam.

### Phase 4: Update docs + canonical diagrams

1. Rewrite `docs/CURRENT_RUNTIME_DIAGRAM.md` to the 3-diagram model above.
2. Update `docs/DESIGN.md` transport/runtime section to match code ownership.
3. Keep diagram language aligned with actual file/module names.

### Phase 5: Boundary checks + tests

1. Extend `scripts/check_boundary_imports.sh`:
   - peering must not depend on QUIC-concrete wiring types.
   - transport remains the only QUIC stream-wiring owner.
2. Add seam-focused tests:
   - unit tests for transport seam adapters.
   - peering loop tests using seam fakes to verify orchestration behavior.

## Hard success criteria

1. `src/peering/**` has no direct construction of `DualConnection` / `QuicTransportSessionIo`.
2. QUIC stream open/accept wiring is owned in `src/transport/**`.
3. Peering loop code reads as orchestration only (plan, dial, accept, retry, cancel).
4. Runtime diagrams fit within the 3-diagram model and reference only boundary contracts.
5. Core tests and boundary script pass.

## Verification commands

```bash
rg -n "DualConnection::new|QuicTransportSessionIo::new|open_bi\(|accept_bi\(" src/peering src/transport
rg -n "quinn::SendStream|quinn::RecvStream|quinn::Connection" src/peering
bash scripts/check_boundary_imports.sh
cargo check
cargo test --lib -q
cargo test --test holepunch_test -q
cargo test --test sync_contract_tests -q
```

Expected interpretation:

1. Peering grep should show orchestration-level usage only; stream wiring should move to transport.
2. Boundary script passes with stricter transport encapsulation rules.
3. Tests show no behavior regression.

## Suggested implementation order for assistant

1. Add seam contract + adapter types first.
2. Migrate one path (`connect_loop`) to seam.
3. Migrate `accept_loop` to seam.
4. Remove old wiring helpers from peering.
5. Update diagrams/docs and boundary checks last.

## Evidence artifact required

Create:

- `docs/planning/TRANSPORT_ENCAPSULATION_BOUNDARY_EVIDENCE.md`

Map each success criterion to concrete file/test command evidence.
