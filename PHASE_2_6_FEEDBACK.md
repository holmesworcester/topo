# Phase 2.6 Feedback (`f7b1a6f`)

Scope reviewed:
- Commit `f7b1a6f` (`Implement Phase 2.6: multitenancy scoped projection and ingest durability`)
- Files:
  - `src/projection/pipeline.rs`
  - `src/sync/engine.rs`
  - `src/testutil.rs`
  - `tests/scenario_test.rs`

What Phase 2.6 did well:
- Dependency checks now require tenant-scoped `valid_events`, which aligns projection with `recorded_by` semantics.
- Rejections are persisted to `rejected_events` and excluded from replay/unblock loops.
- Replay logic is now tenant-scoped to `recorded_events`.
- Added solid unit/integration coverage for tenant-scoped deps and durable rejection behavior.

## Findings (severity ordered)

1. High: COMMIT/transaction failure path in `batch_writer` can drop batches and stall ingestion.
- Evidence:
  - On COMMIT error, code logs and `continue`s without rollback (`src/sync/engine.rs`).
  - If a transaction remains open, next loop `BEGIN` can fail; the code then skips processing while still draining channel batches.
- Impact:
  - under DB pressure/failure, events can be consumed from ingest channel but never persisted/projected.
  - writer can enter a degraded loop where data is silently lost.
- Action:
  - explicitly `ROLLBACK` on COMMIT failure (or handle `BEGIN`/txn state with `Transaction` API).
  - if `BEGIN` fails, do not silently accept/drain batch; retry with backoff and preserve items.

2. Medium: `wanted.remove` still runs for every batch item after COMMIT, even for items that were not successfully persisted.
- Evidence:
  - `event_ids_to_remove` is populated before per-item validation/write success (`src/sync/engine.rs`).
  - rows skipped due parse/type/insert failures are still removed from `wanted` after COMMIT.
- Impact:
  - missing deps can be prematurely forgotten and may not be re-requested.
  - weakens the intended ingest-durability guarantee.
- Action:
  - only enqueue IDs for wanted-removal after successful `events` + `recorded_events` persistence.
  - keep failed items wanted (or write durable reject state) so recovery is explicit.

3. Medium: signer-resolution content errors still propagate as hard projector errors instead of terminal reject state.
- Evidence:
  - `resolve_signer_key` returns `Err` for unsupported signer type/wrong signer event kind (`src/projection/signer.rs`).
  - `apply_projection` uses `?`, so `project_one` returns `Err` rather than `ProjectionDecision::Reject` (`src/projection/pipeline.rs`).
- Impact:
  - malformed signed events can repeatedly trigger warnings without terminal classification.
  - behavior diverges from the new durable reject model added in this phase.
- Action:
  - map signer content failures to `ProjectionDecision::Reject` and persist to `rejected_events`.
  - reserve hard `Err` for infrastructure failures only.

## Test gaps to close

1. DB failure-path test for `batch_writer`:
- simulate COMMIT/BEGIN failure and assert no event loss + clean recovery.

2. Wanted-retention test:
- an item that fails persistence should remain wanted (or be durably rejected) and not be silently dropped.

3. Invalid signer-type test:
- assert terminal reject + durable `rejected_events` row (not repeated hard errors).

## Tests run for this review

1. `cargo test projection::pipeline::tests:: -- --nocapture`
2. `cargo test test_cross_tenant_dep_scoping_after_sync -- --nocapture`

All passed. Findings above are reliability hardening gaps not yet covered by existing assertions.
