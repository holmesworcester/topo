# Phase 2.5 Feedback (`3732a48`)

Scope reviewed:
- Commit `3732a48` (`Implement Phase 2.5: shared signer substrate with Ed25519 verification`)
- Files:
  - `src/events/mod.rs`
  - `src/events/peer_key.rs`
  - `src/events/signed_memo.rs`
  - `src/projection/signer.rs`
  - `src/projection/pipeline.rs`
  - `src/projection/create.rs`
  - `src/projection/projectors.rs`
  - `src/db/migrations.rs`
  - `src/testutil.rs`
  - `tests/scenario_test.rs`

## Findings (severity ordered)

1. High: unsupported/invalid signer paths return hard errors instead of terminal reject/block state.
- Evidence:
  - `resolve_signer_key` returns `Err` for unsupported `signer_type` and wrong signer event type (`src/projection/signer.rs`).
  - `apply_projection` propagates that error (`src/projection/pipeline.rs`), so `project_one` returns `Err` instead of `ProjectionDecision::Reject`.
  - Caller paths (notably batch ingest) log and continue, leaving the event neither valid nor blocked.
- Impact:
  - malformed signed events can repeatedly retry without terminal state and generate recurring warning churn.
  - this is a practical reliability/DoS risk when fed adversarial blobs.
- Action:
  - convert signer-resolution failures caused by event data into `ProjectionDecision::Reject { reason }`.
  - reserve `Err` only for infrastructure failures (DB/query/runtime), not invalid event content.

2. Medium: signed-event rejection is still non-durable even though `rejected_events` exists.
- Evidence:
  - invalid signatures return `ProjectionDecision::Reject` from projection (`src/projection/pipeline.rs`) but are not persisted to `rejected_events`.
  - `rejected_events` table exists in migrations (`src/db/migrations.rs`) but is not written in projector paths.
- Impact:
  - no durable audit trail for bad-signature/malformed-signer events.
  - rejected items can be retried on replay/reproject cycles with no terminal marker.
- Action:
  - on reject, write `(peer_id, event_id, reason, rejected_at)` idempotently.
  - exclude rejected rows from unblock/reproject candidate scans.

3. Medium: dependency and signer key resolution are still global (`events`) rather than tenant-scoped.
- Evidence:
  - dep checks use `SELECT ... FROM events WHERE event_id = ?` (`src/projection/pipeline.rs`).
  - signer key lookup also reads global `events` (`src/projection/signer.rs`).
- Impact:
  - in a multi-tenant DB, signed events can be considered satisfiable by blobs that were never recorded/valid for the current `recorded_by` scope.
  - this weakens workspace-scoped causality guarantees.
- Action:
  - define canonical rule: dep/signer satisfied by global existence vs per-tenant recorded/valid state.
  - implement and test whichever rule is intended before identity/encryption phases depend on it.

## Test gaps to close

1. Add a test for invalid `signer_type` (e.g. `255`) and assert terminal reject behavior (not propagated hard error).
2. Add a test that verifies `rejected_events` rows are written for invalid signatures and parse failures.
3. Add a tenant-isolation signer test:
- signer blob exists globally but not in this tenant's recorded/valid scope,
- assert expected behavior per chosen dependency semantics.

## What is good and should be preserved

1. Signer substrate is cleanly separated (`projection/signer.rs`) and reused by create + pipeline paths.
2. Signed event creation API (`create_signed_event_sync`) preserves canonical sign-bytes flow with explicit signature overwrite.
3. Out-of-order blocking/unblocking behavior for signer dependencies is covered by integration tests.
4. New event types and registry metadata are consistent and keep type-level behavior centralized.

## Tests run for this review

1. `cargo test signed_event -- --nocapture`
2. `cargo test invalid_signature_rejected_after_sync -- --nocapture`

All passed; findings above are semantic/reliability gaps not currently enforced by tests.
