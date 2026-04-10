# Single-Node Formal Coverage Execution Plan

Goal: complete basic single-node coverage for the
`RawRows -> DecisionContext -> Plan -> executor` pattern across runtime seams,
projector families, and single-node composition checks without expanding into
multi-node temporal proof work.

This plan treats "complete coverage" as:

1. every proof-bearing runtime/state seam is inventoried,
2. every inventoried seam has explicit success criteria and executable checks,
3. every covered seam has runtime query tests, Verus planner proofs, and
   executor-conformance checks,
4. projector and composition coverage close the remaining single-node gaps,
5. hot-path refactors stay within the existing performance envelope.

## 1. Coverage Inventory And Gate Completeness

Success Criteria:

1. Every `src/runtime/**` and `src/state/**` file that exposes a
   `DecisionContext`/`Plan` seam is indexed in
   `docs/planning/FORMAL_SEAM_COVERAGE.md`.
2. Every non-module Verus source in `verus-proofs/src/**` is indexed either as a
   covered seam or a supporting proof module.
3. Every covered-seam row references existing runtime path(s), existing Verus
   mirror path(s), known invariant keys, and real `cargo test --lib <filter>`
   targets.
4. Every covered-seam row has non-empty `Requires`, `Provides`, and
   `Targeted Checks`, and every row names `cargo-verus verify`.

Required Checks:

1. `python3 scripts/check_formal_seam_coverage.py`
2. `cargo test -j1 --lib formal_seam_coverage -- --nocapture`

End-to-End Validation:

1. Add a new uncovered seam file or Verus module and confirm the coverage gate
   fails until the map is updated.
2. Break a runtime path, Verus path, or lib-test filter in the coverage map and
   confirm the gate fails on the live repo state.

## 2. Seam-Local Proof Completeness

Success Criteria:

1. Every covered seam exposes explicit `RawRows`, `DecisionContext`, `Plan`,
   `normalize_*`, `decide_*`, and executor boundaries in the owning runtime
   module.
2. Every covered seam has a mirrored Verus module that proves:
   - fail-closed behavior for missing/ambiguous/malformed context,
   - noninterference for irrelevant fields,
   - planner determinism,
   - the seam-specific safety property tied to its `Provides` invariants.
3. Every covered seam names at least one repo-wide invariant in `Provides`.

Required Checks:

1. `scripts/run_verus_proofs.sh`
2. All row-specific targeted checks in
   `docs/planning/FORMAL_SEAM_COVERAGE.md`

End-to-End Validation:

1. For each seam, at least one runtime pass case reaches the intended plan.
2. For each seam, at least one runtime break case proves the planner skips,
   rejects, or suppresses the action when the context is invalid.

## 3. Query Correctness Coverage

Success Criteria:

1. Every covered seam has runtime tests that exercise the actual SQLite query
   path that produces its `RawRows`.
2. Each seam has both pass and break raw-row tests.
3. Break tests cover the seam-relevant invalid states such as missing rows,
   ambiguity, duplicate conflicting rows, wrong tenant/workspace, stale or
   removed authority, and malformed values where applicable.

Required Checks:

1. Run the seam-specific `cargo test -j1 --lib <filter> -- --nocapture` checks
   listed in the coverage map for the touched seam.

End-to-End Validation:

1. Build representative DB state through runtime helpers or projection, run the
   real query, and prove the resulting plan authorizes only the valid path.
2. Mutate the DB state into an invalid form and prove the same runtime entry
   point now rejects or suppresses the action.

## 4. Executor Conformance Coverage

Success Criteria:

1. Every `Plan` variant has a runtime test proving the executor performs only
   the named effects.
2. Reject/skip plans prove minimal side effects.
3. Executors do not widen scope by performing new authority discovery after the
   planner has chosen a plan.

Required Checks:

1. Row-specific runtime suites for the touched seam.
2. Any seam-level end-to-end tests that enter through the public runtime entry
   point and inspect the resulting DB/network effects.

End-to-End Validation:

1. Start from the public entry point for the seam, produce each reachable plan
   variant, and assert the resulting side effects are exact.
2. Prove that a reject/skip plan does not emit broader writes, fanout, auth, or
   network actions.

## 5. Projector Event-Family Coverage

Success Criteria:

1. Every registered event family in `src/event_modules/mod.rs` is represented in
   the projector proof inventory.
2. Every event family has pass and break projector tests for its local semantic
   rules.
3. Context loaders reject malformed or mismatched context before projector
   execution.

Required Checks:

1. `cargo test -j1 --lib registry_formal_projector_coverage -- --nocapture`
2. Event-family projector test suites
3. `python3 scripts/check_projector_tla_conformance.py`
4. `python3 scripts/check_projector_tla_bijection.py`

End-to-End Validation:

1. A valid event projects through the real context loader and projector.
2. An invalid event or malformed context is rejected or blocked before it can
   widen state.

## 6. Typed Raw-Row And Normalizer Discipline

Success Criteria:

1. Security-sensitive SQL-to-planner boundaries use typed `RawRows` structs
   rather than ad hoc tuples, booleans, or interleaved SQL/planner logic.
2. Normalizers collapse contradictory or redundant raw states into explicit
   `DecisionContext` variants.
3. Planners consume only `DecisionContext`, not follow-on authority queries.

Required Checks:

1. Seam-local code review against the shape rules above.
2. Row-specific runtime and Verus checks for every touched seam.

End-to-End Validation:

1. A runtime seam can be described as one query boundary, one normalizer, one
   planner, and one executor without hidden authority reads.
2. Contradictory raw states normalize to explicit rejection, ambiguity, or
   absence instead of silent authorization.

## 7. Single-Node Composition Invariants

Success Criteria:

1. Each repo-wide invariant key (`UCA`, `ALB`, `WC`, `AMF`, `ECP`) has at least
   one concrete runtime composition test and one Verus composition fact.
2. Known security bugs are mapped to both a seam-local proof and a
   cross-seam/runtime composition check.
3. Representative single-node flows cover `persist -> project -> query -> plan
   -> execute` rather than isolated planner calls only.

Required Checks:

1. `scripts/run_verus_proofs.sh`
2. Existing composition-oriented runtime suites such as tenant/workspace
   isolation and already-local bootstrap suppression
3. Any new end-to-end runtime tests added to instantiate uncovered invariants

End-to-End Validation:

1. Start from a real command or projected event, drive the full single-node
   path, and confirm the invariant survives across the seam boundaries.
2. Include a corresponding break case that demonstrates the action is blocked
   when the invariant would otherwise be violated.

## 8. Hot-Path Performance Guard

Success Criteria:

1. Sync/auth planner refactors do not move decisions into per-message or
   per-entry hot loops.
2. Every hot-path coverage refactor names the guarded benchmark and metric in
   the change description or evidence note.
3. Warm-path sync and 10k catchup stay within the current acceptable envelope.

Required Checks:

1. The relevant warm-path benchmark or perf script for the touched seam
2. Existing release/perf commands already used for warm sync and 10k catchup

End-to-End Validation:

1. Run the guarded benchmark before and after the refactor when the touched seam
   is on a hot path.
2. Reject merges that improve proof shape while regressing the guarded warm-path
   metric.

## Execution Order

1. Land inventory/test-target gates first so missing work turns into explicit
   failures.
2. Close any gaps the gates expose in `FORMAL_SEAM_COVERAGE.md`.
3. Deepen projector event-family pass/break coverage.
4. Expand seam-level query and executor-conformance tests where rows are still
   thin.
5. Add the remaining single-node composition tests per invariant key.
6. Keep hot-path perf evidence current for auth/sync changes throughout.
