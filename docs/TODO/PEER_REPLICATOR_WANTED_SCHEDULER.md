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
2. Move multi-source pull balancing out of negentropy/session control code and into a peer-scoped request scheduler.
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
9. If the initial lease-based scheduler still needs better fairness under source stalls, add explicit per-peer backoff / retry metadata on top of the current `wanted` lease fields rather than moving balancing back into negentropy.
