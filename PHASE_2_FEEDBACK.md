# Phase 2 Feedback (`23c60f6`)

Scope reviewed:
- Commit `23c60f6` (`Implement Phase 2: projector core with dependency blocking and cascade unblocking`)
- Files:
  - `src/projection/pipeline.rs`
  - `src/projection/create.rs`
  - `src/projection/projectors.rs`
  - `src/sync/engine.rs`
  - `src/db/migrations.rs`
  - `src/events/mod.rs`
  - `src/testutil.rs`
  - `tests/scenario_test.rs`

## Findings (severity ordered)

1. High: dependency checks are global and do not enforce tenant/terminal-state semantics.
- Evidence:
  - `project_one` checks deps with `SELECT COUNT(*) > 0 FROM events WHERE event_id = ?` (`src/projection/pipeline.rs`).
  - `unblock_dependents` uses the same global-existence check for deps (`src/projection/pipeline.rs`).
- Impact:
  - A dependent event can project because a blocker exists in global blob storage even if the blocker was never recorded/projected for the current `recorded_by` peer scope.
  - This risks violating workspace-scoped projection semantics.
- Action:
  - decide and codify dependency semantics explicitly:
    - if tenant-scoped: require blocker presence in `recorded_events` and/or `valid_events` for the same `peer_id`.
    - if global-existence is intended: document that decision and add tests proving this is safe for future identity/encryption phases.

2. Medium: ingest path can silently lose events without a durable reject trail.
- Evidence:
  - `wanted.remove(event_id)` is called before durable event persistence in `batch_writer` (`src/sync/engine.rs`).
  - key DB writes in the ingest loop ignore errors (`let _ = ...`) for `neg_items`, `events`, and `recorded_events` (`src/sync/engine.rs`).
- Impact:
  - transient DB or parsing/type-path failures can drop events from wanted tracking and skip durable recording/projection.
  - replay may recover later, but local observability and determinism degrade.
- Action:
  - move `wanted.remove` after confirmed durable event insert.
  - stop swallowing write errors; route failures to structured rejection handling.
  - ensure rejected/malformed events have explicit terminal recording for diagnostics.

3. Medium: `rejected_events` terminal table exists but is not used by projector paths.
- Evidence:
  - `rejected_events` migration exists (`src/db/migrations.rs`).
  - `project_one` returns `ProjectionDecision::Reject` on parse/missing-blob paths but does not insert into `rejected_events` (`src/projection/pipeline.rs`).
  - cascade path silently skips parse failures (`if let Ok(parsed) = ...`) without terminal record (`src/projection/pipeline.rs`).
- Impact:
  - malformed events may be retried repeatedly with no durable rejection reason.
  - operator/debug visibility is weaker than intended schema design.
- Action:
  - on reject, write `(peer_id, event_id, reason, rejected_at)` to `rejected_events` idempotently.
  - align cascade behavior with the same reject path rather than silent skip.

## Test gaps to close

1. Dependency scoping test:
- event B depends on A where A exists in global `events` but is not recorded/valid for this `peer_id`.
- assert expected behavior explicitly (blocked vs valid) per chosen semantics.

2. Malformed/unknown-type ingest test:
- assert malformed blobs become durable rejects (not silent drops).

3. Ingest durability test:
- force a failure between receive and projection; verify event is either retained for retry or durably rejected.

## Tests run for this review

1. `cargo test projection::pipeline::tests:: -- --nocapture`
2. `cargo test test_out_of_order_reaction_sync -- --nocapture`
3. `cargo test test_cross_workspace_isolation -- --nocapture`

All passed. Current issues are semantic/reliability gaps not covered by existing assertions.
