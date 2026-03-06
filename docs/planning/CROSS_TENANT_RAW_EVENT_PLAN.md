# Cross-Tenant Raw Event Plan

## Problem

Shared-DB multitenancy currently has two different notions of "an event belongs to a tenant":

1. `recorded_events` means the tenant observed or ingested the blob.
2. `valid_events` and scoped projection tables mean the tenant accepted the event into its workspace state.

Those two notions diverge in real network cases.

In the current implementation:

- the batch writer inserts into `recorded_events` before projection
- projection later rejects foreign-workspace events into `rejected_events`
- the replay harness in [`src/testutil/mod.rs`](../../src/testutil/mod.rs) still treats any cross-workspace `recorded_events` overlap as leakage

That mismatch is why the real-network shared-DB isolation test in
[`tests/scenario_tests/shared_db.rs`](../../tests/scenario_tests/shared_db.rs) currently needs a `ScenarioHarness::skip(...)`.

## Current Findings

### Observed behavior

- `events` is a global content-addressed blob store for the whole SQLite DB.
- `recorded_events(peer_id, event_id, ...)` is written during ingest before `project_one`.
- `project_one` writes terminal acceptance to `valid_events(peer_id, event_id)`.
- `project_one` writes terminal rejection to `rejected_events(peer_id, event_id, reason, ...)`.
- In a shared-DB node, a tenant from workspace B can observe a raw event from workspace A in `recorded_events`, then reject it during projection.

### Relevant code

- Ingest persists `recorded_events` before projection in [`src/state/pipeline/mod.rs`](../../src/state/pipeline/mod.rs) and [`src/state/db/store.rs`](../../src/state/db/store.rs).
- Rejections are terminal and durable in [`src/state/projection/apply/project_one.rs`](../../src/state/projection/apply/project_one.rs) and [`src/state/projection/apply/stages.rs`](../../src/state/projection/apply/stages.rs).
- The current leakage invariant is enforced in [`src/testutil/mod.rs`](../../src/testutil/mod.rs).

## Recommendation

Treat `recorded_events` as a tenant-scoped raw ingress log, not as accepted workspace state.

That means:

- Cross-workspace overlap in `recorded_events` is allowed.
- Cross-workspace overlap in `valid_events` is not allowed.
- Cross-workspace projection into scoped tables is not allowed.
- `rejected_events` is the proof that a tenant observed a foreign event and correctly refused to admit it into workspace state.

This keeps the ingest pipeline honest and avoids deleting useful dedupe/frontier state just to satisfy a too-strict test invariant.

## Proposed Invariants

### Invariant A: Raw ingress is not leakage

For tenants on different workspaces, the same `event_id` may appear in both tenants' `recorded_events`.

Allowed only if the foreign tenant does not also treat that event as valid state.

### Invariant B: Valid state remains workspace-scoped

For tenants on different workspaces, the same `event_id` must never appear in both tenants' `valid_events` unless the event is an intentionally shared local/system artifact that we explicitly whitelist.

Initial implementation assumption:

- no whitelist
- any cross-workspace `valid_events` overlap is a failure

### Invariant C: Projection tables are the hard isolation boundary

For tenants on different workspaces, foreign events must not materialize rows in scoped tables such as:

- `messages`
- `reactions`
- `deleted_messages`
- `key_secrets`
- identity/workspace tables scoped by `recorded_by`

### Invariant D: Foreign observed events should converge to a terminal explanation

For a cross-workspace raw event that was ingested by the wrong tenant, the stable end state should be:

- present in `recorded_events`
- absent from `valid_events`
- present in `rejected_events`

## Workstreams

### 1. Redefine the replay invariant

Replace the current pairwise "different workspaces must have disjoint `recorded_events`" rule in
[`src/testutil/mod.rs`](../../src/testutil/mod.rs) with a classification rule:

- same-workspace overlap in `recorded_events` is expected
- different-workspace overlap in `recorded_events` is allowed only when the overlapping event is not valid for the foreign tenant
- different-workspace overlap in `valid_events` remains forbidden

### 2. Add explicit harness helpers

Add helpers that classify overlapping event IDs into:

- shared-and-valid
- shared-and-rejected
- shared-and-pending

The harness should fail only on the categories that imply workspace leakage.

Initial policy recommendation:

- `shared-and-valid` across different workspaces: fail
- `shared-and-pending` at end-of-test: fail unless the test opted into an in-flight state
- `shared-and-rejected`: allow

### 3. Add direct regression tests for the invariant itself

Create focused tests for `assert_no_cross_tenant_leakage(...)` using synthetic shared-DB fixtures:

- overlap in `recorded_events` plus matching `rejected_events` should pass
- overlap in `recorded_events` plus matching `valid_events` should fail
- overlap in `valid_events` alone should fail
- same-workspace overlap in `recorded_events` and `valid_events` should pass

### 4. Remove the current scenario skip

Update the real-network cross-workspace shared-DB scenario in
[`tests/scenario_tests/shared_db.rs`](../../tests/scenario_tests/shared_db.rs)
to use `ScenarioHarness::new()` instead of `ScenarioHarness::skip(...)`.

That test should become the end-to-end proof that the new invariant matches reality.

### 5. Improve operator visibility

Add a small introspection surface for debugging multitenant overlap:

- either a helper query in `testutil`
- or a lightweight debug/status query showing per-tenant counts for:
  - `recorded_events`
  - `valid_events`
  - `rejected_events`
  - cross-workspace raw overlaps

This is primarily for investigation, not for the first semantic fix.

## Success Criteria

### SC1

Shared-DB tenants in different workspaces may share raw observed event IDs without the harness treating that as leakage.

Checks:

- a synthetic harness test with overlapping `recorded_events` and matching `rejected_events` passes
- the real-network cross-workspace shared-DB scenario no longer needs `ScenarioHarness::skip(...)`

### SC2

Shared-DB tenants in different workspaces still cannot share accepted event state.

Checks:

- a synthetic harness test with overlapping `valid_events` across workspaces fails
- the real-network cross-workspace scenario proves foreign events do not become valid or project into scoped content tables

### SC3

The invariant distinguishes "observed and rejected" from true workspace leakage.

Checks:

- a harness/unit test reports `shared-and-rejected` as acceptable
- a harness/unit test reports `shared-and-valid` as a failure

### SC4

The solution keeps same-workspace shared-DB convergence fully supported.

Checks:

- existing same-workspace shared-DB scenarios still pass
- same-workspace overlap in `recorded_events` and `valid_events` remains explicitly allowed

## Validation Plan

Targeted validation for the eventual implementation:

1. `cargo test --test scenario_tests test_shared_db_three_peer_same_workspace_real_network_direct_sync -- --nocapture`
2. `cargo test --test scenario_tests test_shared_db_three_peer_cross_workspace_real_network_isolation -- --nocapture`
3. `cargo test --test scenario_tests shared_db:: -- --nocapture`
4. `cargo test assert_no_cross_tenant_leakage -- --nocapture`
5. `cargo test --test scenario_tests identity_sync::test_foreign_workspace_rejected_via_sync -- --nocapture`

End-to-end validation expectation:

- same-workspace shared-DB sync continues to converge directly
- different-workspace shared-DB sync can still ingest foreign raw blobs
- those foreign blobs remain rejected and never leak into accepted scoped state

## Decisions Deferred

### Should we prune foreign raw events after rejection?

Recommendation: no, not in the first pass.

Reason:

- `recorded_events` is currently the ingress/dedupe frontier
- deleting rejected rows risks re-request churn and makes debugging worse

### Should we add `workspace_id` directly to `recorded_events`?

Recommendation: no, not initially.

Reason:

- the immediate mismatch is the invariant, not missing data
- we already have enough information from `recorded_events`, `valid_events`, and `rejected_events` to classify the stable outcome

### Should the global `events` table become tenant-scoped?

Recommendation: no.

Reason:

- that is a much larger storage and transport design change
- the current bug is about interpreting global blob presence as workspace acceptance

## First Implementation Slice

Do this first, in order:

1. Add harness/unit tests for the new classification-based invariant.
2. Rewrite `assert_no_cross_tenant_leakage(...)` to allow cross-workspace raw overlap only when foreign tenants reject the overlap.
3. Remove the `ScenarioHarness::skip(...)` from the real-network cross-workspace shared-DB scenario.
4. Re-run the shared-DB scenario matrix and the foreign-workspace sync scenarios.

If that slice passes cleanly, we can decide whether better debugging surfaces are still needed.
