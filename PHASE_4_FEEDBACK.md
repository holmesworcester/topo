# Phase 4 Feedback (`8c77bf3`)

Scope reviewed:
- Commit `8c77bf3` (`Implement Phase 4: durable queue architecture with crash recovery`)
- Files:
  - `src/db/egress_queue.rs`
  - `src/db/project_queue.rs`
  - `src/db/queue.rs`
  - `src/db/migrations.rs`
  - `src/sync/engine.rs`
  - `tests/scenario_test.rs`

## Findings (severity ordered)

1. High: `wanted_events` can be cleared for items that were never durably persisted.
- Evidence:
  - Batch writer pushes every incoming ID into `event_ids_to_remove` before any persistence checks (`src/sync/engine.rs:138`, `src/sync/engine.rs:140`).
  - On COMMIT success it removes all IDs in that list from wanted (`src/sync/engine.rs:195`).
  - Persistence path has multiple early `continue` branches before event storage/recording/enqueue (`src/sync/engine.rs:145`, `src/sync/engine.rs:155`, `src/sync/engine.rs:171`).
- Impact:
  - failed/partial items can be dropped from wanted despite never being recorded/projected.
  - this weakens durability and can produce silent projection gaps until a later full re-sync.
- Action:
  - track only successfully persisted/enqueued IDs and remove only those from wanted.

2. High: `project_queue::drain` deletes claimed rows even when projection fails.
- Evidence:
  - `drain` callback has no success/failure return channel (`src/db/project_queue.rs:167`).
  - It processes a batch, then unconditionally deletes all rows (`src/db/project_queue.rs:176`, `src/db/project_queue.rs:180`).
  - Caller swallows `project_one` errors and continues (`src/sync/engine.rs:203`).
- Impact:
  - transient DB/projection infra failures can permanently drop queue work without valid/rejected/blocked terminal state.
- Action:
  - make callback return result and keep/retry failed items (`mark_retry`) instead of unconditional delete.

3. High: local-only events are still admitted to sync circulation paths.
- Evidence:
  - `neg_items` insertion is unconditional once `created_at` is present (`src/sync/engine.rs:145`).
  - Send loops stream any blob from store without share-scope gate (`src/sync/engine.rs:461`, `src/sync/engine.rs:648`).
- Impact:
  - local-only event types (e.g., secret material) can be advertised/sent.
- Action:
  - gate `neg_items` and send-path by `share_scope == shared` as defense in depth.

4. Medium: transaction failure handling in ingest path is not robust enough for queue durability claims.
- Evidence:
  - `BEGIN` failures are ignored with no retry/backoff path (`src/sync/engine.rs:136`).
  - `COMMIT` failure path logs and continues without explicit rollback/recovery action (`src/sync/engine.rs:212`).
- Impact:
  - increased chance of dropped ingest batches under lock pressure and weaker crash/lock resilience.
- Action:
  - add bounded BEGIN retry/backoff and explicit rollback on commit failure.

## Test gaps

1. No test that simulates partial persistence in a batch and verifies wanted retention for failed items.
2. No test that forces projection callback error during `project_queue::drain` and asserts item remains queued/retriable.
3. No test asserting local-only events are excluded from `neg_items` and from send loops.

## Tests run for this review

Commands attempted:
1. `cargo test -q --manifest-path /home/holmes/poc-7/Cargo.toml test_project_queue_crash_recovery -- --nocapture`
2. `cargo test -q --manifest-path /home/holmes/poc-7/Cargo.toml test_egress_queue_lifecycle -- --nocapture`

Both commands failed before test execution due current compile errors in `src/events/message_deletion.rs` (unresolved `EVENT_TYPE_MESSAGE_DELETION` / missing `ParsedEvent::MessageDeletion`).
