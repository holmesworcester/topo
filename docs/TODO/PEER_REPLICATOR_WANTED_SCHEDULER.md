# Peer Replicator And Wanted Scheduler

Story 2 is now the design truth:

- one authenticated `PeerReplicator` per peer slot,
- low-rate observer loop for negentropy discovery,
- high-rate sender/request loop for transport fill,
- sink-driven `wanted` + `wanted_sources` scheduling for multi-source balancing.

Implementation follow-up:

1. Add durable sink demand state:
   - `wanted(event_id, ...)`
   - `wanted_sources(event_id, peer_id, first_seen_at, last_seen_at, priority_lane, priority_ts)`
2. Move the remaining multi-source pull balancing out of session control flow and into a fully connection-scoped request scheduler.
3. Keep one sender owner per peer slot with leased push windows and batch completion acks.
4. Keep blob residency low-memory-friendly by leasing IDs more aggressively than blobs.
5. Replace local-create first-hop shortcuts with `dirty_hot` wakeups so every hop uses the same propagation rule.
6. Preserve connection-level idempotency:
   - many hint sources may call `ensure_connected(peer)`,
   - at most one steady-state live peer slot survives after authentication.
7. Add/keep realistic proof tests:
   - multi-source fairness,
   - large file plus live-message latency,
   - chain propagation,
   - low-memory catchup and low-memory file delta,
   - duplicate-send regression.
8. Feed causal blockers into the same demand graph:
   - when projection blocks on missing deps, insert those missing event IDs into `wanted`,
   - once candidate suppliers are observed, let the same request scheduler prioritize them,
   - preserve a way to rank blockers above ordinary catchup once the lane/priority story is implemented end-to-end.
9. Keep the first request scheduler simple:
   - durable truth is only `wanted + wanted_sources`,
   - per-peer request credit and in-flight suppression stay in memory,
   - tenant-scoped shared coordination across active peers is already implemented,
   - duplicate pulls are allowed aggressively when spare peer credit exists.
10. Future follow-ups:
   - split encrypted wrapper types into explicit outer types such as
     `encrypted_message`, `encrypted_reaction`, `encrypted_file_slice` so
     discovery can carry only `event_id + timestamp + type_code`,
   - derive size class / byte-credit mapping from the registry rather than
     from ad hoc SQL priority metadata,
   - keep hot/cold observer cadences, where hot runs frequently on the newer
     range and cold runs less frequently on the older range over the same event
     universe,
   - add richer prioritization for auth / blockers / dependency discovery once
     the initial credit-driven request loop is settled.
11. Add first-class perf instrumentation for the request-credit design:
   - exact sender QUIC idle time / idle percentage, not just sampled `SendIdle`
     diagnostics,
   - duplicate-request accounting on the sink, especially "duplicate request
     issued before every currently eligible wanted ID has been requested at
     least once",
   - durable-receipt completion metrics separate from projection completion, so
     network/request performance can be optimized independently from projector
     cost,
   - end-to-end file transfer and catchup benchmarks that report request
     utilization, durable receive completion, and projection lag separately.
12. Finish the structural split implied by the credit model:
   - keep session semantics only for Negentropy discovery rounds,
   - sync handlers are already scoped to authenticated connection lifetime, but sink request credit, in-flight suppression, and source pending responses still need real connection-scoped request lanes instead of riding per-round session streams,
   - remove remaining sync-time dependence on durable SQLite egress where credit
     already bounds memory,
   - extend the current tenant-scoped shared coordinator to a true global sink
     scheduler over authenticated `(tenant, peer)` slots, so multi-workspace /
     multi-tenant demand can be allocated across all credited peers in one
     testable planning step.
