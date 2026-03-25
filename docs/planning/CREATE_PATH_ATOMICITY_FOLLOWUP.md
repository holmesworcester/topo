# Create-Path Atomicity Follow-Up

Date: 2026-03-12
Branch: `codex/hot-cold-sync-plan`
Worktree: `/tmp/poc-7-hot-cold-sync`
Status: implemented atomicity baseline plus remaining API cleanup

## Goal

Reduce the number of special create-side paths and make the create contract
principled:

1. one atomic durable-store phase,
2. one projection-attempt phase,
3. one blocked/rejected durability story,
4. one explicit event-id-dependent context hook,
5. no create-side origin recovery rows.

## Universals

### U1. Durable local store is atomic

For any locally-created shared event, the following rows must be committed in
one transaction or not at all:

1. `events`
2. `shared_event_index` when the event is shared
3. `recorded_events`

Local create no longer relies on create-side origin `project_queue` rows or
create-side pending sibling fanout rows. Crash safety comes from making the
store and first projection attempt one transaction boundary, not from writing
extra create-specific recovery rows.

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

### U4. Explicit context injection is a narrow second mode

Some flows genuinely need the event id before projection can succeed. The only
principled exception is:

1. store event atomically,
2. write event-id-dependent context,
3. project in the same transaction,
4. return only after the projection outcome commits.

This is now exposed as an explicit helper (`store_signed_event_then_project`)
instead of each caller open-coding its own create transaction.

## Proposed Create-Side Shape

## Phase A. Atomic durable store + first projection attempt

Wrap the durable store and the first projection attempt in
`with_immediate_tx_result(...)` and commit one terminal outcome:

1. canonical event row,
2. negentropy row,
3. recorded row,
4. projection side effects for one attempt (`valid`, `blocked`, or `rejected`).

Possible results:

1. `Valid` or `AlreadyProcessed`
   - run same-workspace fanout,
   - return `Ok(event_id)`.

2. `Blocked`
   - ensure blocked state is durably recorded before return,
   - return `Err(Blocked { event_id, missing })`.

3. `Rejected`
   - ensure rejection state is durable before return,
   - return `Err(Rejected { event_id, reason })`.

For rare bootstrap-context flows, the transaction shape is:

1. store canonical rows,
2. write event-id-dependent context,
3. attempt projection,
4. commit the resulting outcome.

## Why this is smaller and cleaner

This removes the ad hoc distinction between:

1. normal local create needing create-specific recovery rows,
2. special bootstrap flows open-coding their own storage/projection contract.

Instead:

1. strict synchronous create is the default,
2. event-id-dependent context injection is the only explicit exception,
3. blocked state is the durable repair path for blocked events.

## Concrete Changes To Make

Done on this branch:

1. local synchronous create commits canonical store plus first projection
   attempt in one transaction,
2. local create no longer writes origin `project_queue` rows,
3. local create no longer writes create-side pending sibling fanout rows,
4. blocked synchronous create returns only after blocked rows are durable,
5. bootstrap-context invite creation now uses a shared
   `store_signed_event_then_project(...)` helper.

Still worth cleaning up before/after merge:

1. narrow generic staged helpers so product code prefers strict synchronous
   create or the explicit `store_*_then_project(...)` path,
2. remove stale documentation that still describes create-side recovery rows as
   the local-create safety mechanism,
3. keep pressure on chain-latency tests so direct first-hop enqueue is not
   mistaken for the long-term solution.

## Required Tests

1. synchronous create leaves no origin `project_queue` or create-side pending
   fanout rows,
2. blocked synchronous create commits blocked rows before return,
3. bootstrap-context invite creation works via the explicit
   `store -> context -> project` path without origin recovery rows,
4. chaining contract still holds for strict synchronous create.

## Non-Goals

1. Do not introduce a separate event universe for "live" traffic.
2. Do not weaken the blocked-event contract by returning success before
   projector-owned context exists.
