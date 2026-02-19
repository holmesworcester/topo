# Stream 5: Docs and Archive Hygiene

## Goal

Make active docs accurate and compact; move branch-review/prototype artifacts into archive so contributors use one mature source of truth.

## Scope

1. Archive root feedback artifacts and stale planning docs that are no longer active guidance.
2. Correct active docs that contradict current code.
3. Remove machine-local path references from active docs.

## Owned Files

1. `FEEDBACK.md`
2. `feedback.md`
3. `docs/PLAN.md`
4. `docs/DESIGN.md`
5. `docs/PERF.md`
6. `docs/LOW_MEM_PERF_ANALYSIS.md`
7. `docs/PHASE_7_LOGIC_FIXES.md`
8. `docs/QUIC_HOLEPUNCH_PLAN.md`
9. `docs/SYNC_GRAPH_PERF_PLAN.md`
10. archive destinations under `docs/archive/`

## Non-Goals

1. No runtime behavior changes.
2. No schema/migration changes.
3. No event-type changes.

## Work Items

1. Move root-level `FEEDBACK.md` / `feedback.md` into `docs/archive/` (or consolidate into one archived summary).
2. Add a short index in `docs/` that distinguishes:
   - active specs/plans
   - historical/archive docs
3. Fix known stale statements in active docs, including:
   - missing file references (for example `src/wire/mod.rs` references).
   - outdated transport security notes that contradict current `PinnedCertVerifier` implementation.
   - machine-local references (`/tmp/...`, `/home/holmes/...`) in active guidance.
4. Keep historical details but relocate them under `docs/archive/`.

## Acceptance Criteria

1. No root-level feedback docs remain outside `docs/`.
2. Active docs do not reference non-existent code paths as current-state facts.
3. Active docs do not include machine-local absolute paths.
4. Archive contents remain accessible for historical context.

## Validation Commands

```bash
rg -n "/tmp/|/home/holmes/|src/wire/mod.rs|SkipServerVerification" docs/*.md docs/**/*.md
rg -n "FEEDBACK.md|feedback.md" .
```

## Risks

1. Over-pruning docs and losing useful historical context.
2. Conflicts with concurrent feature docs updates.

## Mitigations

1. Archive rather than delete.
2. Keep each doc header marked as `Active` or `Archived`.

