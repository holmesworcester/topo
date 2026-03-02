# Perf Tail Profile + Tuning Execution Plan

Date: 2026-03-01
Branch: `exec/perf-tail-profile-tuning`
Worktree: `/home/holmes/poc-7-perf-tail-profile-tuning`

## Goal

Diagnose and improve the 500k one-way sync tail slowdown using a profiling-first workflow, then apply the highest-value fix with measurable benefit and bounded regression risk.

## Non-Negotiable Requirements

1. Profile first; do not tune blind.
2. Use serial perf execution to avoid cross-test interference.
3. Keep completion assertions count/data-based (no marker timing gates).
4. Update `docs/PLAN.md` and `docs/DESIGN.md` to reflect implemented behavior and operational guidance.
5. Run review in this same worktree/branch and iterate until explicitly accepted.
6. Final step requirement: commit completed work on this same worktree branch before handoff or review.

## Scope

In scope:
1. 500k tail profiling and root-cause evidence capture.
2. One prioritized optimization pass based on profiling evidence.
3. Validation on 50k and 500k serial perf runs.
4. Architecture/documentation sync in PLAN/DESIGN.

Out of scope:
1. Multi-source fairness changes (tracked in separate worktree).
2. Cross-epoch compatibility shims.
3. Broad unrelated perf rewrites.

## Phase 0: Baseline Capture

1. Run baseline serial suite:
   - `scripts/run_perf_serial.sh core`
2. Run tail benchmark:
   - `cargo test --release --test perf_test perf_sync_500k -- --ignored --nocapture --test-threads=1`
3. Save baseline numbers and environment details in:
   - `docs/planning/PERF_TAIL_PROFILE_TUNING_EVIDENCE.md`

Success criteria:
1. Baseline 50k + 500k numbers are captured with command lines and run date.
2. Any baseline instability is documented before tuning begins.

## Phase 1: Tail Profiling (Required Before Tuning)

1. Produce actionable tail profile data (CPU + SQLite/WAL + writer-path timing) focused on the 250k->500k segment.
2. Add minimal instrumentation/scripts if needed to make profile runs repeatable.
3. Record evidence and root-cause ranking in `PERF_TAIL_PROFILE_TUNING_EVIDENCE.md`.

Success criteria:
1. Evidence identifies the dominant bottleneck with concrete measurements.
2. At least one lower-priority bottleneck is also documented for follow-up.

## Phase 2: Implement Highest-Value Fix

Apply only the top-ranked fix from Phase 1 (for example: writer batch byte/page budgeting, WAL checkpoint policy adjustments, or index/query-path corrections).

Rules:
1. Keep the change minimal and attributable to measured bottleneck.
2. If fix requires additional guardrails, include them in tests/scripts.

Success criteria:
1. 500k tail throughput or wall time improves meaningfully versus baseline.
2. 50k run does not regress materially (document threshold/rationale in evidence file).

## Phase 3: Verification

Run and capture:
1. `cargo check`
2. `scripts/run_perf_serial.sh core`
3. `cargo test --release --test perf_test perf_sync_500k -- --ignored --nocapture --test-threads=1`

Success criteria:
1. All required checks pass.
2. Before/after comparison is explicit and reproducible.

## Phase 4: Documentation Sync (Mandatory)

Update:
1. `docs/PLAN.md`
2. `docs/DESIGN.md`

Must include:
1. Profiling-first perf workflow for tail regressions.
2. Implemented tuning behavior and decision boundary.
3. Any new operational constraints for serial perf measurement.

Note: full benchmark table refresh in `docs/PERF.md` is intentionally deferred to the final consolidation step on master.

Success criteria:
1. PLAN and DESIGN align with implemented code and scripts.
2. No stale architecture/perf guidance remains.

## Phase 5: Review + Iterate Until Accepted

1. Request branch review against this plan.
2. Record findings in `feedback.md`.
3. Fix all High/Medium findings; resolve or explicitly justify Low findings.
4. Re-run required verification after each fix iteration.
5. Repeat until explicit acceptance is recorded.

Success criteria:
1. Reviewer marks branch accepted.
2. No unresolved High/Medium findings remain.

## Deliverables

1. Tail profiling evidence artifact.
2. Implemented and validated top-priority tail fix.
3. Updated PLAN/DESIGN docs.
4. Review artifact with accepted status.

## Final Checklist

1. All success criteria above are met.
2. Evidence file contains baseline, profiling, and post-fix comparison.
3. Required checks are passing.
4. PLAN and DESIGN are updated to latest behavior.
5. Review is complete and accepted.
6. Commit completed work on this same worktree branch before handoff or review.
