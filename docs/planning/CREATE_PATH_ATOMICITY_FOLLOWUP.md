# Create-Path Atomicity Follow-Up

Date: 2026-03-11
Branch: `codex/hot-cold-sync-plan`
Worktree: `/tmp/poc-7-hot-cold-sync`
Status: proposed cleanup after review of the implemented branch

## Goal

Reduce the number of special create-side paths and make the create contract
principled:

1. one atomic durable-store phase,
2. one projection-attempt phase,
3. one recovery story,
4. one live-sync wakeup story,
5. no local-create-only fast path that later hops do not share.

## Universals

### U1. Durable local store is atomic

For any locally-created shared event, the following rows must be committed in
one transaction or not at all:

1. `events`
2. `neg_items` when the event is shared
3. `recorded_events`
4. origin-tenant `project_queue`
5. pending same-workspace sibling fanout row, when applicable

This closes the fatal crash window where the canonical event exists but no
generic recovery row exists to re-attempt projection.

### U2. Synchronous create returns `Ok(event_id)` only after projection succeeds

`create_event_synchronous`, `create_signed_event_synchronous`, and
`create_encrypted_event_synchronous` should continue to return `Ok(event_id)`
only when the inline projection attempt reaches `Valid` or
`AlreadyProcessed`.

This preserves chaining: later synchronous creates may rely on projector-owned
context being visible before the prior call returns.

### U3. Blocked is durable before return

If a synchronous create returns `Err(Blocked { event_id, missing })`, the
blocked state must already be durable before the function returns:

1. `blocked_event_deps`
2. `blocked_events`
3. any projector-specific guard-block state

The caller may choose to tolerate this through `event_id_or_blocked`, but that
should only be possible once the recovery state is committed.

### U4. Recovery rows are for repair, not latency shortcuts

The create path should not directly enqueue newly-valid local shared events to
peer egress queues as a special first-hop bypass.

That shortcut improves only the origin hop. It does not apply to later hops in
a graph, so it can hide poor hot-sync tuning and make local-origin latency look
better than transit latency.

### U5. Live propagation uses the same mechanism on every hop

When a shared event becomes valid, whether from:

1. local create,
2. wire ingest,
3. replay, or
4. cascade-unblock,

the runtime should use the same peer-dirty / hot-sync wakeup mechanism to move
it onward. The chain case should not depend on a local-create-only shortcut.

## Proposed Create-Side Shape

## Phase A. Atomic durable store

Wrap the durable store in `with_immediate_tx(...)` and commit:

1. canonical event row,
2. negentropy row,
3. recorded row,
4. origin recovery row in `project_queue`,
5. pending sibling fanout row.

This phase does not decide success vs blocked. Its job is only to make the
event and its repair path durable.

## Phase B. Projection attempt

After Phase A commits, attempt inline projection.

Possible results:

1. `Valid` or `AlreadyProcessed`
   - remove the origin recovery row,
   - run same-workspace fanout,
   - mark the relevant peer slots dirty so hot sync runs promptly,
   - return `Ok(event_id)`.

2. `Blocked`
   - ensure blocked state is durably recorded before return,
   - keep the origin recovery row,
   - return `Err(Blocked { event_id, missing })`.

3. `Rejected`
   - ensure rejection state is durable before return,
   - remove or keep the origin recovery row according to retry policy,
   - return `Err(Rejected { event_id, reason })`.

## Why this is smaller and cleaner

This removes the ad hoc distinction between:

1. local create gets direct egress enqueue,
2. remote ingest waits for hot/cold reconciliation.

Instead:

1. all ingestion sources share one projection/recovery model,
2. all newly-valid shared events use one onward-propagation trigger,
3. sync responsiveness is solved in sync scheduling, not by a first-hop bypass.

## Concrete Changes To Make

1. Wrap `store_blob_only(...)` in an explicit transaction using
   `with_immediate_tx(...)`.
2. Treat `project_queue` insert and pending sibling-fanout insert as part of
   that transaction.
3. Add an explicit projection-attempt boundary so the blocked path can commit
   its own durable bookkeeping before returning.
4. Keep `Ok(event_id)` only for successfully projected synchronous creates.
5. Keep blocked-tolerant chaining only behind `event_id_or_blocked(...)`.
6. Remove the local-create direct-to-egress enqueue in
   `projection/create.rs`.
7. Add a uniform peer-dirty / hot-session wakeup path for any newly-valid
   shared event, regardless of source.

## Required Tests

1. crash-safety unit/integration test:
   a locally-created shared event must never be durable without either an
   origin `project_queue` row or terminal projection state.
2. blocked-return test:
   synchronous create returning `Err(Blocked { event_id, .. })` must already
   have durable blocked rows before the return is observed.
3. chaining contract test:
   synchronous `Ok(event_id)` must imply the subsequent dependent create can
   observe the required projector context immediately.
4. chain-latency test:
   live events should advance across a multi-hop chain because each hop's hot
   sync reacts to newly-valid shared events, not because the first hop used a
   special shortcut.

## Non-Goals

1. Do not introduce a separate event universe for "live" traffic.
2. Do not add a local-create-only push plane.
3. Do not weaken the blocked-event contract by returning success before
   projector-owned context exists.
