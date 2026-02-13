# Issue 8: Savepoint Rollback Destroys Cascade State

## Summary

The savepoint-based atomicity change in `src/db/project_queue.rs` (commit `aa6eab1`,
merged to master in `8e3490d`) introduced a race condition that breaks the
`blocked_event_deps` cascade-unblock mechanism. Under concurrent write contention,
`ROLLBACK TO project_item` destroys `blocked_event_deps` rows that `project_one`
wrote, preventing dependent events from ever being unblocked and projected.

## Severity: High

Affects all identity-derived trust paths (TransportKey projection) and any
multi-peer sync scenario where events arrive out of dependency order across
concurrent batch_writers.

## Root Cause

### Before (`71af06e`, passing)

`drain_with_limit` ran each `project_fn` call in autocommit mode (no enclosing
savepoint). Projection side-effects — including `blocked_event_deps` and
`blocked_events` rows written by `project_one` when a dependency is missing —
persisted immediately. If `project_fn` later errored (e.g. from SQLite `BUSY`
during the `unblock_dependents` cascade), those blocked-dep rows survived. When
the missing dependency arrived in a later batch, `unblock_dependents` could find
and cascade-project the blocked event.

### After (`aa6eab1`, failing)

`drain_with_limit` wraps each `project_fn` call in `SAVEPOINT project_item`.
On error:

```rust
Err(_) => {
    let _ = self.conn.execute_batch(
        "ROLLBACK TO project_item; RELEASE project_item"
    );
    let _ = self.mark_retry(peer_id, event_id_b64);
}
```

This rolls back **all** writes from `project_one`, including:
- `blocked_event_deps` rows (the cascade-unblock index)
- `blocked_events` header rows (the deps-remaining counter)
- Any `valid_events` rows written during partial cascade

The event is marked for retry via `mark_retry`, but the blocked-dep tracking is
lost. When the missing dependency arrives later and `unblock_dependents` runs,
it finds no `blocked_event_deps` rows to cascade through — the dependent event
is silently orphaned.

### Why errors occur

SQLite `BUSY` errors arise from concurrent batch_writers sharing a database.
In the holepunch test, the introducer (I) has two concurrent sync sessions
(I↔A and I↔B), each with its own batch_writer thread. When both attempt
writes simultaneously, one gets `BUSY`. The `unblock_dependents` savepoint
(`SAVEPOINT unblock_cascade`) propagates this error up through `project_one`,
which propagates it through `project_fn`, triggering the rollback of the
enclosing `SAVEPOINT project_item`.

## Reproduction

```bash
cd /home/holmes/poc-7

# Fails ~80% of runs on clean master (race condition):
cargo test --test holepunch_test test_three_peer_intro_happy_path

# Run 5x to see both passes and failures:
for i in 1 2 3 4 5; do
  cargo test --test holepunch_test test_three_peer_intro_happy_path 2>&1 \
    | grep -E 'ok|FAILED|trust'
done
```

The failing assertion varies per run ("A should trust B", "B should trust A",
"B should trust I") — confirming it is a race, not a deterministic logic error.

## Bisect Evidence

| Commit | Result | Note |
|--------|--------|------|
| `71af06e` | PASS | Pre-merge master |
| `aa6eab1` | FAIL | Savepoint change (on branch) |
| `8e3490d` | FAIL | Merge to master |
| `c04b4e9` | FAIL | Current master HEAD |

**Confirmed isolation**: reverting only `src/db/project_queue.rs` to the
`71af06e` version on current master makes the test pass reliably.

## Fix

Remove the savepoint wrapping from `drain_with_limit`. Projection side-effects
(especially `blocked_event_deps`) must persist even when `project_fn` errors,
because the cascade-unblock mechanism depends on them. The item is still marked
for retry via `mark_retry`, so the queue's own consistency is maintained.

```rust
// Fix: no savepoint around project_fn
match project_fn(self.conn, event_id_b64) {
    Ok(()) => {
        self.conn.execute(
            "DELETE FROM project_queue WHERE peer_id = ?1 AND event_id = ?2",
            params![peer_id, event_id_b64],
        )?;
        succeeded += 1;
    }
    Err(_) => {
        let _ = self.mark_retry(peer_id, event_id_b64);
    }
}
```

The `test_drain_rollback_on_projector_failure` unit test must be updated to
reflect this: partial projection writes now persist on error (which is the
correct behavior for cascade correctness).

## Files

- `src/db/project_queue.rs` — `drain_with_limit` method and associated tests
- `src/projection/pipeline.rs` — `unblock_dependents` (nested savepoint victim)

## Related

- Commit `aa6eab1`: "Fix queue drain atomicity gap and INSERT OR REPLACE policy violation"
- Commit `8e3490d`: "Merge fix/issue-7-atomicity-upsert-policy into master"
- `FEEDBACK.md`: issue 7 feedback (noted "residual risk around higher-concurrency
  write contention patterns" — this is that risk materialized)
