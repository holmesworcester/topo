# Download Pipeline Timestamps

We now have enough separation between discovery, request selection, request
transport, data receipt, and projection to record useful per-event timing in
the DB and surface it in test diagnostics.

## Current status

Implemented on the branch:

- durable `event_timeline(event_id, ...)` rows in infra schema
- discovery / wanted observation timestamps
- request sent / request received timestamps
- response sent / response received timestamps
- persisted / blocked / unblocked / projected timestamps
- `assert-eventually has_event:...` timeout output now includes any available
  event timeline summary
- one realistic sync test proves source-side and sink-side rows populate across
  a real requested download

Current defaults:

- enabled automatically in debug/test builds
- enabled in release only when `TOPO_EVENT_TIMELINE=1`

## Goal

When a sync assertion times out, report where time was actually spent for the
relevant event(s) instead of only saying "has_event == 0".

This should let us distinguish:

- discovery delay,
- request-planning delay,
- request transport latency,
- source response delay,
- receive/persist delay,
- projection delay,
- blocked-dependency delay.

## Implemented timestamps

For each `event_id`, record nullable timestamps such as:

- `discovery_round_started_at`
- `wanted_discovered_at`
- `request_sent_at`
- `request_received_at`
- `response_sent_at`
- `response_received_at`
- `persisted_at`
- `projected_at`

- `blocked_at`
- `unblocked_at`

## Design constraints

- Do not add unbounded in-memory observability state.
- Prefer piggybacking on writes that already happen in the same transaction.
- Keep this opt-in or cheap enough that it does not distort perf numbers.
- Make it easy for test helpers to print the timeline for:
  - one specific `event_id`,
  - the first and last event in a count-based assertion,
  - derived spans such as `request_latency_ms`, `receive_to_project_ms`, or
    `blocked_duration_ms`.

## Test/reporting follow-up

- `assert_eventually` now prints any available timeline row for timed-out
  `has_event:...` assertions.
- still missing:
  - count-based assertions reporting first/last-event timelines
  - aggregate perf/debug dumps over many rows
  - optional blocker-specific filtering so guard/dependency waits can be
    separated from pure receive/project latency
  - explicit projection-attempt timestamps if we want to distinguish
    "first try blocked" from "first successful project"

That should make sync bottlenecks explainable without guessing from ad hoc
daemon logs.
