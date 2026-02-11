# Feedback: Stream 2 Identity Compatibility Cleanup Plan

## Decision
Approved with merged changes.

## Merged Improvements
1. Added explicit dependency coordination with Stream 1 for alias callers in:
   - `tests/cli_test.rs`
   - `tests/netns_nat_test.sh`
2. Split alias cleanup into two phases:
   - Phase A: wording/help normalization
   - Phase B: alias retirement only after dependent caller updates merge
3. Strengthened acceptance criteria so alias outcome must be explicit:
   - aliases removed with caller updates in the same wave, or
   - aliases retained with a documented follow-up owner
4. Added validation command to detect residual alias consumers:
   - `rg -n 'arg\("identity"\)|\bidentity --db\b|backfill-identity' tests src docs`

## Remaining Expectations
1. Stream 1 and Stream 2 must agree on ownership for caller updates before Phase B.
2. If Stream 2 ships only Phase A, track Phase B with a named owner and follow-up item.

## Merge Readiness
Plan is merge-ready with the updates now in `docs/cleanup/02_identity_compat_cleanup_plan.md`.
