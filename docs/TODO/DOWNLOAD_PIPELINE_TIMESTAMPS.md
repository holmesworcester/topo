# Download Pipeline Timestamps

We now have enough separation between discovery, request selection, request
transport, data receipt, and projection to record useful per-event timing in
the DB and surface it in test diagnostics.

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

## Candidate timestamps

For each `event_id`, record nullable timestamps such as:

- `discovery_round_started_at`
- `wanted_discovered_at`
- `request_sent_at`
- `request_received_at`
- `response_started_at` or `response_first_byte_at`
- `response_completed_at` or `data_received_at`
- `persisted_at`
- `projected_at`

Optional blocked/projection-specific fields:

- `blocked_at`
- `unblocked_at`
- `project_attempted_at`
- `project_succeeded_at`

## Design constraints

- Do not add unbounded in-memory observability state.
- Prefer piggybacking on writes that already happen in the same transaction.
- Keep this opt-in or cheap enough that it does not distort perf numbers.
- Make it easy for test helpers to print the timeline for:
  - one specific `event_id`,
  - the first and last event in a count-based assertion,
  - derived spans such as `request_latency_ms`, `receive_to_project_ms`, or
    `blocked_duration_ms`.

## Likely shape

The most direct implementation is a small DB table keyed by `event_id`, for
example:

- `event_timeline(event_id PRIMARY KEY, ...nullable timestamps...)`

Each stage does an upsert only when it is already touching durable state:

- discovery updates when `wanted` / `wanted_sources` are written,
- request timestamps update when requests are emitted or received,
- receipt timestamps update in the ingest/persist path,
- projection timestamps update when projector state commits.

This avoids storing large queues in memory and keeps observability aligned with
the durable truth the runtime already uses.

## Test/reporting follow-up

Once the timeline exists:

- `assert_eventually` should print any available timeline rows for the asserted
  event on timeout,
- count-based assertions should print timeline info for the earliest and latest
  matched event,
- perf/debug helpers should be able to dump aggregated stage latencies.

That should make sync bottlenecks explainable without guessing from ad hoc
daemon logs.
