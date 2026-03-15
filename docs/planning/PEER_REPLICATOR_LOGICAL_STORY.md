# Peer Replicator Logical Story

This is the clean causal split the runtime is moving toward.

## 1. Discovery / Observation

Negentropy is the observer.

Its job is only to answer:

- what shared events does the remote peer appear to be missing from us,
- what shared events do we appear to be missing from the remote peer,
- which peer appears to be a candidate supplier for each missing event.

Outputs from observation:

- peer egress demand for push traffic,
- sink `wanted` demand for pull traffic,
- sink `wanted_sources` candidate-source rows for pull traffic.

Negentropy does **not** decide final balancing policy.

## 2. Request Selection

The sink-side request scheduler is the actuator for pull traffic.

Its job is only to answer:

- which wanted IDs should this peer be asked for next,
- how much source-advertised request credit should be filled for this peer right now.

SQL truth:

- `wanted_events`: global demand, one row per missing event,
- `wanted_sources`: candidate suppliers per event/peer.

Memory-only control state:

- per-peer request credit,
- per-peer in-flight requested IDs,
- optional short-lived retry / timeout bookkeeping.

This is where balancing lives:

- the sink can prefer not to duplicate requests, but duplicate pulls are allowed when spare peer credit exists,
- multiple peers can be kept busy because a shared tenant-scoped coordinator plans requests across the current peer-credit snapshot,
- a slow or dead peer does not own work forever because in-flight request suppression is bounded memory state rather than durable ownership.

## 3. Send / Response

The source-side responder is the actuator for push traffic.

Its job is only to answer:

- for the IDs this peer requested, stream the corresponding canonical blobs,
- for the IDs discovered as outbound `have_ids`, push them through peer egress.

This side should not decide multi-source balancing either.

It just drains:

- `egress_queue` for push traffic,
- `HaveList` requests for pull responses.

## 4. Why The Split Matters

This separates three concerns cleanly:

1. **Discovery** is expensive and low-rate.
   - Negentropy, snapshots, candidate-source updates.
2. **Request selection** is cheap and high-rate.
   - Fill source-advertised request credit from `wanted + wanted_sources`.
3. **Data send** is cheap and high-rate.
   - Drain leased push windows or bounded in-memory pull-response queues and
     keep QUIC streams fed.

Without this split, the wire ends up paced by SQLite claim cadence or by fresh
negentropy rounds instead of by transport availability.

## 5. Invariants

The intended invariants are:

- at most one steady-state live authenticated peer slot per peer,
- at most one sender owner drains a peer slot's push egress at a time,
- wanted demand is recorded once per event, independent of how many peers may satisfy it,
- candidate source membership is recorded separately from demand,
- pull balancing is sink-driven, not embedded in negentropy,
- per-peer pull in-flight state is bounded in memory and does not scale with total workspace size,
- once persisted locally, an event cannot become wanted again from stale observation,
- later sync rounds can rediscover supply without changing the balancing story,
- low-memory mode keeps many leased IDs possible while blob residency stays small.

## 6. Current Incremental Shape

The current code is an incremental form of this model rather than the final
`PeerReplicator` actor:

- initiator session still contains both the observer and request-refill loops,
- request selection itself is already shared tenant-scoped coordinator state rather than per-session local SQL selection,
- sync handlers are now scoped to authenticated connection lifetime, which is
  where future connection-scoped request/response state belongs,
- pull credit, in-flight request suppression, and pending responses still reset
  with each discovery round because requests still ride per-round control streams,
- responder session now serves pull responses from a bounded in-memory queue
  rather than SQLite egress,
- `wanted` + `wanted_sources` are already the durable sink-side discovery truth,
- request credit and in-flight request suppression are already memory-only.

That is enough to make the sink-driven scheduler real before the larger actor
refactor.
