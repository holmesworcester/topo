# Subscriptions Event Feeds Execution Plan

Branch/worktree context:
- Branch: `subscriptions-event-feeds`
- Worktree: `/home/holmes/poc-7-subscriptions`
- Base: `master`

## Problem

We need backend-managed subscriptions that can match arbitrary event classes and event properties, with low latency under active SQLite churn from syncing/projection.

Needed examples:
1. new messages,
2. new messages since timestamp,
3. new messages since event id/cursor,
4. either detailed item delivery (ids/full items) or coarse `has_changed` notifications.

Constraints:
- Keep logic in backend.
- Keep filter ownership local to event modules.
- Expose a simple API that can prototype a React-like data flow using CLI/RPC.

## High-level approach (recommended)

Implement a **local subscription engine** with:
1. local subscription definitions in SQLite,
2. event-module-owned filter matchers,
3. projection-time trigger hook for low latency,
4. pull-based feed API (`poll`) plus optional `has_changed` mode.

This keeps concurrency simple:
- one canonical projection path,
- deterministic subscription side effects in DB,
- UI/CLI only consumes feed state.

## Hook point in pipeline

Use successful projection path where we already have `(recorded_by, event_id, parsed_event)`:
- `src/state/projection/apply/project_one.rs`
- after valid terminal state write (or immediately before, but consistently one place)

Call a backend hook such as:
- `event_modules::subscriptions::on_projected_event(conn, recorded_by, event_id_b64, &parsed)`

Rationale:
- only fires for events that actually project as valid,
- naturally ordered with projection,
- no extra polling latency.

## Module locality design

Add new event module namespace:
- `src/event_modules/subscriptions/`

And keep event-specific filters local by adding per-module matcher files, for example:
- `src/event_modules/message/subscriptions.rs`
- `src/event_modules/reaction/subscriptions.rs`
- `src/event_modules/message_attachment/subscriptions.rs`

Central subscription module does generic orchestration only:
1. load candidate subscriptions for event type,
2. invoke event-module matcher,
3. append/coalesce feed output.

## Data model (local-only, non-replicated)

```sql
CREATE TABLE IF NOT EXISTS local_subscriptions (
  recorded_by TEXT NOT NULL,
  subscription_id TEXT NOT NULL,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  event_type TEXT NOT NULL,            -- "message", "reaction", etc
  delivery_mode TEXT NOT NULL,         -- "full" | "id" | "has_changed"
  spec_json TEXT NOT NULL,             -- validated backend spec
  cursor_created_at_ms INTEGER NOT NULL DEFAULT 0,
  cursor_event_id TEXT NOT NULL DEFAULT '',
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (recorded_by, subscription_id)
);

CREATE INDEX IF NOT EXISTS idx_local_subscriptions_active
  ON local_subscriptions(recorded_by, enabled, event_type);

CREATE TABLE IF NOT EXISTS local_subscription_feed (
  recorded_by TEXT NOT NULL,
  subscription_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  event_id TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  payload_json TEXT NOT NULL,
  emitted_at_ms INTEGER NOT NULL,
  PRIMARY KEY (recorded_by, subscription_id, seq)
);

CREATE TABLE IF NOT EXISTS local_subscription_state (
  recorded_by TEXT NOT NULL,
  subscription_id TEXT NOT NULL,
  next_seq INTEGER NOT NULL DEFAULT 1,
  pending_count INTEGER NOT NULL DEFAULT 0,
  dirty INTEGER NOT NULL DEFAULT 0,
  latest_event_id TEXT NOT NULL DEFAULT '',
  latest_created_at_ms INTEGER NOT NULL DEFAULT 0,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (recorded_by, subscription_id)
);
```

Notes:
- `local_subscription_feed` stores itemized matches for `full`/`id`.
- `has_changed` mode can avoid item rows and only update `local_subscription_state`.

## Subscription spec shape (simple but extensible)

Backend accepts a JSON spec with fixed operators:

```json
{
  "event_type": "message",
  "since": {
    "created_at_ms": 1730419200000,
    "event_id": ""
  },
  "filters": [
    { "field": "author_id", "op": "eq", "value": "<b64 or hex>" },
    { "field": "created_at_ms", "op": "gte", "value": 1730419200000 }
  ]
}
```

Rules:
1. `event_type` required.
2. `filters.field` must be declared by the owning event module.
3. unsupported field/operator combinations are rejected by backend.
4. no arbitrary SQL or expression language in phase 1.

## Delivery modes

1. `full`
   - feed row includes minimal render payload (for message: id/author/content/created_at).
2. `id`
   - feed row includes only identifiers and timestamps.
3. `has_changed`
   - no per-item rows required; only mark dirty/pending count and latest cursor in state table.

This directly supports "by id" and "has changed" requirements.

## RPC + CLI prototype API

Add RPC methods:
1. `SubscribeCreate { name, event_type, delivery_mode, spec_json }`
2. `SubscribeList`
3. `SubscribeDisable { subscription_id }`
4. `SubscribeEnable { subscription_id }`
5. `SubscribePoll { subscription_id, after_seq: Option<i64>, limit: usize }`
6. `SubscribeAck { subscription_id, through_seq: i64 }`
7. `SubscribeState { subscription_id }` (for has_changed counters/cursor)

CLI commands mirroring RPC (React-isomorphic pull model):
1. `topo sub-create --name inbox --event-type message --delivery full --since-ms <ms>`
2. `topo sub-create --name changed --event-type message --delivery has_changed --since-event-id <id>`
3. `topo sub-list`
4. `topo sub-poll --sub <id> --limit 50 --json`
5. `topo sub-state --sub <id> --json`
6. `topo sub-ack --sub <id> --through-seq <n>`
7. `topo sub-disable --sub <id>` / `topo sub-enable --sub <id>`

React mapping:
- frontend keeps local cursor per subscription,
- polls for deltas,
- merges with existing timeline state via `event_id`.

## Event-module matcher contract

Define trait-like contract in subscription module:

```rust
pub trait SubscriptionMatcher {
    fn event_type_name() -> &'static str;
    fn allowed_fields() -> &'static [AllowedField];
    fn matches(spec: &CompiledSpec, parsed: &ParsedEvent, event_id_b64: &str) -> bool;
    fn feed_payload(parsed: &ParsedEvent, event_id_b64: &str, mode: DeliveryMode) -> serde_json::Value;
}
```

Each event module owns:
1. field extraction semantics,
2. operator support,
3. payload shaping for `full` mode.

## Concurrency and performance notes

1. Trigger in projection transaction to preserve ordering.
2. Keep subscription lookup indexed by `(recorded_by, enabled, event_type)`.
3. For high volume event types, cap per-call processed subscriptions (configurable safety ceiling) and log drops.
4. `has_changed` mode should be O(1) update.
5. `full` mode payload must remain compact to avoid hot-path bloat.

## Realistic test plan

Add integration test file:
- `tests/subscriptions_test.rs`

Scenarios:
1. `subscribe_new_messages_since_time`
   - create subscription with `since_ms`,
   - send messages before/after threshold,
   - poll verifies only expected matches.

2. `subscribe_since_event_id`
   - seed messages, capture cursor event id,
   - create subscription from cursor,
   - verify only newer events appear.

3. `subscribe_has_changed_mode`
   - create `has_changed` subscription,
   - send many messages under sync churn,
   - verify state flips dirty and increments pending count without item explosion.

4. `subscription_filter_by_property`
   - filter by author_id or created_at range,
   - verify event-module-local matcher semantics.

5. `subscription_feed_order_and_dedupe`
   - under reorder/replay conditions,
   - verify deterministic seq ordering and no duplicates by `(subscription_id, seq)` and event id semantics.

6. `subscription_persists_across_daemon_restart`
   - create subscription,
   - restart daemon,
   - verify definitions/state/feed remain consistent.

7. `subscription_with_active_sync_load`
   - 2-3 peers syncing while subscription polling runs,
   - assert no deadlocks/timeouts and expected latency bound for new message visibility.

## Daemon log output for subscription matches

When the daemon has active subscriptions, the projection hook emits `tracing::info!`
lines for every subscription match — giving real-time visibility into the subscription
engine directly in `topo start` output.

Format:
```
INFO topo::subscriptions: [sub "inbox"] message by @alice (event abc1…) — full delivery, seq 47
INFO topo::subscriptions: [sub "changed"] message — has_changed, pending: 12
```

This fires at the same point the feed row / state update is written, so the log shows
exactly what a polling consumer would see, with no additional overhead. For `full`/`id`
modes the log includes event type, subscription name, short event ID, and seq number.
For `has_changed` mode it shows the updated pending count.

Implementation: a single `tracing::info!` call in the subscription hook's match-dispatch
path, immediately after the feed/state write. No extra machinery required.

## Alternative designs (if needed)

### Option B: Poll-only scanner (no projection hook)

Implement by scanning `recorded_events/events` since cursor on `sub-poll`.

Pros:
- simpler integration,
- zero hot-path projection overhead.

Cons:
- higher query latency,
- more expensive polling,
- less "instant" behavior.

Use if projection hook risk is unacceptable in first pass.

### Option C: In-memory pub/sub in daemon only

Daemon keeps subscriptions in memory and emits to RPC clients.

Pros:
- very low latency.

Cons:
- lost on restart,
- not available in non-daemon paths,
- weak isomorphism with real app persistence.

Not recommended for primary implementation.

## Suggested implementation order

1. Add schema + `event_modules/subscriptions` storage/query helpers.
2. Add subscription spec parser/validator.
3. Add module-local matcher implementations for `message` first.
4. Integrate projection hook in `project_one` valid path.
5. Add RPC/CLI commands for create/list/poll/state/ack/enable/disable.
6. Extend matchers to `reaction` and `message_attachment`.
7. Add integration tests above.
8. Document commands in README and design references.

## Acceptance criteria

1. Backend can store and evaluate subscriptions for event type + property filters.
2. `new messages` and `new messages since time/event id` work end-to-end.
3. `id` and `has_changed` delivery modes both work.
4. Subscription logic is backend-contained and event-module-local for filter semantics.
5. CLI can show subscription feed/state and behaves like a thin frontend client.
6. Tests pass under normal and sync-churn conditions.
7. Daemon logs subscription matches in real time via `tracing::info!` during `topo start`.

## Final step

1. Commit all completed work on this same branch/worktree before handoff or review.
