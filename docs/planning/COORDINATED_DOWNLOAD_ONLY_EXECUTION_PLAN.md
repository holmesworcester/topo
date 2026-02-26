# Coordinated Download Only: Remove All Non-Coordinated Initiator Paths

Date: 2026-02-24
Branch: `exec/noncoordinated-download-removal-plan`
Status: active plan

## Goal

Enforce one canonical outbound download behavior across runtime, workflows, and tests:

1. Every initiator sync session is coordinator-backed.
2. `need_ids` are always assigned through coordinator flow.
3. No direct/non-coordinated `HaveList(all need_ids)` path remains in code.

## Current Evidence (master)

Non-coordinated paths still exist in active code:

1. `run_sync_initiator(..., coordination: Option<&PeerCoord>, ...)` supports `None` path.
2. `dispatch_need_ids_after_reconcile(..., coordination_enabled: bool, ...)` still has direct request branch.
3. `SyncSessionHandler::initiator(...)` stores `coordination: None`.
4. `testutil/bootstrap.rs` creates initiator sessions without coordination.
5. `peering/workflows/punch.rs` creates initiator sessions without coordination.
6. `testutil::connect_sync_once` calls `run_sync_initiator(..., None, ...)` directly.
7. Docs still mention legacy non-coordinated helper/test path in `docs/CURRENT_RUNTIME_DIAGRAM.md`.

## Target State

1. Initiator API is coordination-required (no `Option`).
2. Session handler outbound constructor requires coordination and cannot be created without it.
3. Control-plane need dispatch has no non-coordinated branch.
4. Bootstrap/punch/test helpers all use coordinator-backed initiator path (single-peer coordinator allowed).
5. Runtime/docs describe only coordinated pull assignment.

## Required Refactor

### Step 1: API hardening (compile-time enforcement)

1. Change `run_sync_initiator` signature to require coordinator (no `Option`).
2. Change `SyncSessionHandler` initiator constructor to require coordinator (single constructor for outbound).
3. Remove `coordination: Option<Arc<PeerCoord>>` from `SyncSessionHandler`; make it required for initiator role.
4. Remove non-coordinated control-plane API (`coordination_enabled: bool`).

### Step 2: Remove non-coordinated behavior

1. Delete direct need dispatch branch (`HaveList(all need_ids)` bypass).
2. If coordinator assignment cannot be obtained (disconnect/failed channel), fail the session explicitly; do not silently degrade.
3. Remove comments and fallback notes that claim non-coordinated recovery.

### Step 3: Update all call sites

Required call-site updates:

1. `src/peering/workflows/punch.rs`: create/register coordinator and pass it to initiator handler.
2. `src/testutil/bootstrap.rs`: bootstrap initiator path must also be coordinator-backed.
3. `src/testutil/mod.rs` (`connect_sync_once` and similar direct initiator helpers): use coordinator-backed handler/session path.
4. `tests/sync_contract_tests/*`: adjust constructors/fixtures to pass coordinator.

### Step 4: Remove stale helper naming and docs

1. Rename/remove helper names and comments that imply non-coordinated mode.
2. Update `docs/CURRENT_RUNTIME_DIAGRAM.md` to remove mention of legacy non-coordinated path.
3. Ensure `docs/DESIGN.md` and `docs/PLAN.md` do not describe optional/non-coordinated initiator pull mode.

## No-Cheat Enforcement

Add and enforce boundary checks in `scripts/check_boundary_imports.sh`:

1. Fail if any code declares `coordination: Option<&PeerCoord>` or `Option<Arc<PeerCoord>>` for initiator sync flow.
2. Fail if `SyncSessionHandler::initiator(` exists (old non-coordinated constructor name/signature).
3. Fail if `run_sync_initiator` is called with `None` in source or tests.
4. Fail if control-plane function retains `coordination_enabled` boolean branch.
5. Fail if docs mention non-coordinated helper/runtime download path in active docs.

Required grep gates (must be included in PR summary):

1. `rg -n "coordination:\s*Option<(&|Arc<)PeerCoord" src tests`
   - must return no matches.
2. `rg -n "SyncSessionHandler::initiator\(" src tests`
   - must return no matches.
3. `rg -n -U "run_sync_initiator\([\s\S]{0,240}None" src tests`
   - must return no matches.
4. `rg -n "coordination_enabled" src/sync/session`
   - must return no matches.
5. `rg -n "non-coordinated|legacy helper/test path" docs/CURRENT_RUNTIME_DIAGRAM.md docs/DESIGN.md docs/PLAN.md`
   - must return no matches in active docs.

## Tests (required)

Minimum required test run after refactor:

1. `cargo check`
2. `bash scripts/check_boundary_imports.sh`
3. `cargo test --test sync_contract_tests -q`
4. `cargo test --test sync_graph_test catchup_2x_5k -q`
5. `cargo test --test holepunch_test -q`
6. `cargo test --test cli_test -q`

If any are flaky, rerun with evidence and include both failing and passing output counts in PR notes.

## Acceptance Criteria (all required)

1. Non-coordinated initiator API is impossible to call at compile time.
2. No runtime or test helper can route `need_ids` without coordinator assignment.
3. Coordinator loss results in explicit session failure/retry path, not silent bypass.
4. Boundary script fails when reintroducing a non-coordinated path.
5. Required tests pass.
6. Active docs describe only coordinated download behavior.

## Reviewer Checklist

1. Can any call site construct initiator sync without coordinator? (must be no)
2. Can `need_ids` still flow directly to `HaveList` without assignment? (must be no)
3. Does punch/bootstrap now use the same coordinator-backed path as runtime connect loops? (must be yes)
4. Do grep gates and boundary script prove the restriction automatically? (must be yes)
5. Do tests cover contract + integration paths touched by this change? (must be yes)

