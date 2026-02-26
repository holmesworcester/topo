# Connect/Accept Collapse Execution Plan

Date: 2026-02-24
Branch: `exec/connect-accept-collapse-plan`
Worktree: `/home/holmes/poc-7-connect-accept-collapse-plan`

## Objective

Collapse duplicated `connect` and `accept` loop orchestration into one explicit owner path while preserving current runtime behavior.

Primary collapse goal:

1. One owner for connection/session supervision logic.
2. One owner for shared preflight DB recovery logic.
3. One runtime-faithful outbound path (coordinated multi-source semantics remain default).
4. No regression to bellwether perf and coordinated multi-source tests.

## Scope

In scope:

- `src/peering/loops/{mod.rs,connect.rs,accept.rs}`
- new shared supervisor module under `src/peering/loops/*`
- `src/peering/runtime/{mod.rs,target_planner.rs,discovery.rs}` as needed
- `src/peering/workflows/punch.rs` if required to remove runtime non-coordinated initiator usage
- `src/testutil/mod.rs` and tests that depend on loop APIs
- `docs/CURRENT_RUNTIME_DIAGRAM.md` update after refactor lands

Out of scope:

- Changing sync protocol semantics
- Reworking trust model or transport crypto identity model
- Broad transport trait redesign

## Non-Negotiable Requirements

### R1. Single supervision owner for accept/connect session lifecycle

1. Connection/session orchestration logic must have one implementation owner (for both inbound and outbound).
2. `accept.rs` and `connect.rs` may remain as thin mode wrappers only.
3. Duplicated orchestration blocks (preflight recovery, session loop cadence, session dispatch, peer-removal guard) must not exist in two separate loop files.

### R2. Single preflight/recovery owner

1. Startup preflight currently repeated in both paths must be centralized:
   - `create_tables`
   - `purge_expired_endpoints`
   - `project_queue.recover_expired`
   - initial `drain_project_queue`
2. The shared preflight path must preserve existing tenant scoping rules.

### R3. Coordinated multi-source remains default runtime behavior

1. Runtime outbound supervision must continue using coordination.
2. No production runtime path should silently downgrade to uncoordinated `need_ids -> HaveList(all)` behavior.
3. If a non-coordinated helper remains, it must be test-only or clearly non-runtime.

### R4. Runtime behavior invariants preserved

1. Trust gate and peer identity extraction behavior unchanged.
2. Endpoint observation recording and transport binding recording unchanged.
3. Intro listener behavior unchanged.
4. Cancellation semantics (peer removal, shutdown, connection drop) unchanged.

### R5. Collapse quality bar is strict

1. Wrapper files must be visibly thinner after collapse.
2. All invariants are proven by targeted tests and grep evidence.
3. Runtime diagram must reflect collapsed ownership after code changes land.

## Mandatory Implementation Phases

### Phase 1: Introduce unified supervision core

1. Create a shared loop supervisor module in `src/peering/loops` (for example `supervisor.rs`).
2. Move common orchestration there:
   - preflight recovery
   - shared ingest/writer wiring (when applicable)
   - repeated session run loop
   - common cancellation/watch hooks
3. Encode mode differences via explicit mode/config input instead of copy-paste branches.

### Phase 2: Convert `accept` and `connect` to thin wrappers

1. `accept.rs` should primarily:
   - resolve inbound provider/tenant routing specifics
   - call unified supervisor
2. `connect.rs` should primarily:
   - resolve outbound provider/dial specifics
   - call unified supervisor
3. Keep public API compatibility where practical; if APIs change, update all call sites in one pass.

### Phase 3: Enforce coordinated runtime outbound path

1. Ensure runtime call paths (`runtime/mod.rs`, discovery, target planner) are coordinated only.
2. Audit production paths for `SyncSessionHandler::initiator(...)` and either:
   - replace with coordinated path, or
   - move to clearly test-only ownership.

### Phase 4: Tests and evidence hardening

1. Add/adjust focused loop tests that prove both modes run through the same supervision core.
2. Keep multi-source coordinated tests passing without special setup.
3. Keep perf bellwethers within acceptable drift.

### Phase 5: Docs and topology update

1. Update `docs/CURRENT_RUNTIME_DIAGRAM.md` to show collapsed connect/accept ownership.
2. Keep topology artifact detailed but with new simplified ownership boundaries.

## Hard Success Criteria (all required)

### SC1. One supervision owner exists

1. Exactly one shared implementation owns session supervision for both modes.
2. `accept.rs` and `connect.rs` are wrappers, not duplicate orchestrators.

### SC2. Duplicate preflight code removed

1. Preflight recovery sequence is centralized once.
2. No duplicated preflight block remains in both wrappers.

### SC3. Runtime outbound path is coordinated-only

1. Runtime targets (autodial/discovery) use coordinated supervision path.
2. No production runtime downgrade to uncoordinated fetch-all mode.

### SC4. No behavior regressions on core sync paths

1. Existing peering/sync contract tests pass.
2. Coordinated multi-source tests pass.

### SC5. Bellwether perf unaffected

1. `perf_sync_50k` and `perf_sync_10k` run before/after.
2. Throughput/events-per-second/wall-time drift beyond 10 percent requires explicit justification and approval.

### SC6. Diagram and docs reflect collapsed reality

1. Runtime topology diagram shows collapsed connect/accept ownership.
2. Wording matches actual code ownership after refactor.

## Required Verification Commands

Run and include outputs in evidence:

```bash
cargo check

rg -n "create_tables\\(|purge_expired_endpoints\\(|recover_expired\\(|drain_project_queue\\(" src/peering/loops
rg -n "connect_loop_with_coordination|accept_loop_with_ingest|run_session\\(" src/peering/loops src/peering/runtime
rg -n "SyncSessionHandler::initiator\\(" src/peering src/node src/main

cargo test -q --test sync_contract_tests
cargo test -q --test scenario_test
cargo test -q --test sync_graph_test catchup_2x_5k

cargo test --release -q --test perf_test perf_sync_50k -- --nocapture
cargo test --release -q --test perf_test perf_sync_10k -- --nocapture
```

Interpretation requirements:

1. Grep output must show centralized ownership, not duplicated loop bodies.
2. Runtime grep for direct `SyncSessionHandler::initiator(` should be empty or explicitly test-only.
3. Multi-source and perf gates must pass.

## Required Evidence Artifact

Create:

- `docs/planning/CONNECT_ACCEPT_COLLAPSE_EVIDENCE.md`

Evidence file must map SC1-SC6 to:

1. file-level proof,
2. grep output proof,
3. test/perf command proof.

## Mandatory Working Rules

1. Work only in `/home/holmes/poc-7-connect-accept-collapse-plan`.
2. Do not implement this in any other worktree.
3. Rebase on latest `master` before final review:
   - `git fetch origin`
   - `git rebase origin/master`
4. Run Codex feedback loop until acceptance:
   - mid-implementation review in `feedback.md`
   - final audit in `codex_final_audit.md` with explicit PASS/FAIL for SC1-SC6.

## Merge Checklist

All must be true:

1. SC1-SC6 all PASS in evidence.
2. No unresolved High/Medium feedback items.
3. Final audit concludes `READY_TO_MERGE`.
4. Branch rebased on current `master`.
