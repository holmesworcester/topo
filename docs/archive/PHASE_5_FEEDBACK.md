# Phase 5 Feedback

> **Historical feedback; file paths may not match the current source tree.**

Reviewed commit: `2aae603` (`Implement Phase 5: message deletion with cascade/tombstone and fix O(N²) unblock_dependents`)

## Overall

Phase 5 adds the right core pieces (message deletion event, tombstones, cascade delete, and unblock perf fix), but there are correctness issues to resolve before calling this phase complete.

## Findings

### 1. High: deterministic emit can skip tenant projection when event already exists globally

- Evidence:
  - `src/projection/emit.rs:25` checks global `events` existence.
  - `src/projection/emit.rs:32` returns early if present.
- Impact:
  - For a second tenant (`recorded_by`), this can skip `recorded_events` insertion and skip `project_one(...)`.
  - Breaks tenant isomorphism and replay/projection expectations.
- Required fix:
  - Remove early-return behavior that bypasses per-tenant recording/projection.
  - Always ensure tenant-scoped side effects (`recorded_events`, projector terminal state) are applied even if canonical blob already exists.

### 2. High: emitted events are inserted into `neg_items` unconditionally

- Evidence:
  - `src/projection/emit.rs:60` inserts into `neg_items` without share-scope guard.
- Impact:
  - Local-only emitted events may be advertised for sync.
  - Violates share-scope policy and local-only guarantees.
- Required fix:
  - Gate `neg_items` insert by event metadata:
    - only insert when `meta.share_scope == ShareScope::Shared`.

### 3. Medium: deletion auth can be bypassed after tombstone exists

- Evidence:
  - `src/projection/projectors.rs:142` checks tombstone first.
  - `src/projection/projectors.rs:149` returns `AlreadyProcessed` immediately.
  - `src/projection/pipeline.rs:195` marks non-reject/non-block as valid.
- Impact:
  - Later wrong-author deletion events can be treated as valid no-op after first delete.
  - This may not match intended authorization semantics.
- Required decision + fix:
  - Choose policy explicitly:
    - Option A: strict authorization even after tombstone -> wrong-author should `Reject`.
    - Option B: idempotent no-op after tombstone regardless of author.
  - Implement consistently and test explicitly.

## Missing Tests To Add

1. Deterministic emit for an event that already exists globally, but for a different tenant:
   - verify tenant still gets `recorded_events` and projected/terminal state.
2. Local-share deterministic emitted event:
   - verify no `neg_items` row is written.
3. Post-tombstone wrong-author deletion:
   - verify behavior matches chosen policy (`Reject` vs idempotent valid no-op).

## Exit Criteria For Phase 5 Signoff

- Fixes for findings 1 and 2 are merged.
- Finding 3 policy is explicitly decided and implemented.
- All three missing tests are added and passing.
