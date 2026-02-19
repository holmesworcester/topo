# Phase 2.5 Feedback-Fix Review (`de1f135`, `d494552`)

> **Historical feedback; file paths may not match the current source tree.**

Assumption for this review:
- Baseline issues from `PHASE_2_5_FEEDBACK.md` are the target (hard-error signer paths, non-durable rejects, tenant-scope ambiguity).
- Review is scoped to the fix commits on branch `phase-2.5-feedback-fixes` and checked against the signer/dependency intent in `PLAN.md` (Phase 2.5/2.6 ordering and invariants).

Scope reviewed:
- Commit `de1f135` (`Fix Phase 2.5 signer substrate: tenant-scoped resolution and data-error handling`)
- Commit `d494552` (`Fix O(n²) unblock_dependents scan during batch event creation`)
- Files:
  - `src/projection/signer.rs`
  - `src/projection/pipeline.rs`

## Findings (severity ordered)

No blocking findings for the Phase 2.5 feedback-fix scope.

## What is fixed correctly

1. Signer data errors no longer bubble as hard projection errors.
- `resolve_signer_key` now returns structured `SignerResolution` (`Found` / `NotFound` / `Invalid`) and reserves `Err` for DB/infrastructure failures.
- `apply_projection` maps `Invalid`/`NotFound` to deterministic `Reject` decisions.
- This addresses the prior reliability issue where malformed signer data caused repeated warning-only retries.

2. Signer resolution is tenant-scoped.
- Signer lookup now joins through `valid_events` for the current `recorded_by` tenant.
- This aligns with the Phase 2.6 scoped-projection gate and avoids cross-tenant signer satisfaction.

3. Test coverage for signer edge cases is improved.
- Added/validated tests for unsupported signer type, wrong signer event type, and tenant-scoped signer lookup.
- Targeted scenario and unit tests pass for these paths.

4. Cascade performance guard is reasonable.
- `unblock_dependents` skips expensive candidate scans when `DELETE ... blocker_event_id` removes zero rows.
- This is a practical mitigation for repeated no-op scans during high-volume creation.

## Residual notes (non-blocking)

1. This branch is aligned for Phase 2.5/2.6 signer behavior.
- Encrypted-wrapper signer is introduced in Phase 3, so signed-encrypted parity from `PLAN.md` Phase 2.5 definition-of-done is only fully testable once Phase 3 code is included.

## Tests run for this review

1. `cargo test projection::signer::tests:: -- --nocapture`
2. `cargo test test_cross_tenant_signer_isolation -- --nocapture`
3. `cargo test test_unsupported_signer_type_rejects -- --nocapture`
4. `cargo test test_invalid_signature_rejected_after_sync -- --nocapture`

All targeted tests passed.
