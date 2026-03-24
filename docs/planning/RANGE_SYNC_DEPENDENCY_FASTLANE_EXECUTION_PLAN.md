# Range-Owned Sync + Dependency Fast Lane Plan

Date: 2026-03-21
Branch: `codex/dependency-ingest-fastlane`
Worktree: `/home/holmes/poc-7/.codex-worktrees/dependency-ingest-fastlane`

## Goal

Keep the sync hot path small and readable:

1. bulk catchup is range-owned,
2. bulk receive is append-only and durable-first,
3. dependency repair is direct and latency-first,
4. projection stays on the normal canonical path,
5. the coordinator schedules ranges instead of balancing per-event requests.

## Current Implemented Shape

### Connection and session model

1. There is one authenticated QUIC connection per peer.
2. The transport opens two session classes on that connection:
   - `Range`
   - `Dependency`
3. A `RangeSession` uses a control stream plus a data stream, but semantically
   it is one range-owned job with two strict phases:
   - reconcile the selected range with negentropy,
   - exchange all missing event blobs for that range.
4. A dependency session stays alive alongside range sessions and uses:
   - control for `RequestIds`,
   - data for dependency `Event` replies.

### Range scheduler

1. The scheduler is intentionally simple.
2. Outbound range selection round-robins over:
   - `LastDay`
   - `LastWeek`
   - `LastTwelveWeeks`
   - `Full`
3. `TOPO_SYNC_TIER_MODE` is gone.
4. The active scheduler is the disjoint ladder above; nested mode is gone.
5. This is the current bootstrap scheduler, not the final arbitrary-range
   coordinator.

### Multi-source strategy

1. `LastDay` is duplicated across all live peers.
2. `week`, `12 weeks`, and `full` are partitioned across the live peer set
   by sorted peer rank.
3. The partition is recomputed every time a new range session starts.
4. This is the simplest robust rule for peer churn:
   - no durable ownership table,
   - no per-event planner,
   - no rebalance state to repair after a peer disappears.
5. When a peer drops, the next round sees a smaller live set and the remaining
   peers automatically widen their historical slices.

### Bulk receive path

1. The range receiver appends blobs to one `ReceiveLog`.
2. `ReceiveLog` has a single embedded header in the `.bin` file; new logs do
   not use a `.meta` sidecar.
3. Each append stamps:
   - `first_received_at`
   - `first_stored_at`
4. `first_stored_at` is the first-store timestamp used by perf tests.
5. On connection close or idle timeout, the log is finalized and replayed into
   canonical ingest.
6. On startup, leftover logs are ingested and deleted.
7. Replay parses valid frames to EOF and ignores a truncated tail.

### Dependency fast path

1. Projection blocking emits dependency fetches keyed by source peer.
2. Dependency requests go directly to the live dependency session for that
   `(db_path, tenant, peer)`.
3. Replies are ingested immediately with `ingest_now`.
4. If several replies are already buffered, the receiver drains a tiny
   no-wait micro-batch (`16` max today).
5. Dependency replies do not wait behind range receive logs.

### What is gone

1. Durable `wanted` rows are not part of the bulk path.
2. Request-credit scheduling is not part of the bulk path.
3. `ResponseCredit` is not part of the live protocol.
4. The old shared-ingest wrapper layer is gone from connect/accept runtime
   orchestration.
5. The node runtime no longer spins up a shared batch-writer worker for sync
   sessions.

## Design Rules

1. Prefer human readability and minimum mechanism count.
2. Keep the wire hot path free of per-event SQLite work when doing bulk sync.
3. Use the vendored `negentropy` library as directly as practical.
4. Keep dependency repair separate from bulk catchup.
5. Track `durable` and `projected` as separate concepts, but derive them from
   existing tables and timestamps rather than adding counters.

## Current Gaps

### Coordinator

1. The current scheduler is still the fixed `LastDay/LastWeek/LastTwelveWeeks/Full`
   ladder.
2. Arbitrary coordinator-chosen ranges are future work.
3. The current multi-source rule is fixed:
   - duplicate hot ranges,
   - partition cold ranges by live peer rank.
4. Smarter balancing by measured peer throughput is future work.

### Dependency path

1. The first source for a blocker is still the source peer of the blocking
   event.
2. More advanced fallback source selection is future work.
3. The dependency session registry is routing state, not a fully general
   duplicate-request suppression layer.

### Transport priority

1. The runtime separates range sessions from dependency sessions.
2. Explicit measured transport-priority guarantees between dependency and bulk
   work still need more dedicated perf coverage.

## Success Criteria

Satisfied on this branch:

1. Bulk catchup is range-owned.
2. Bulk receive is append-only and tolerant of interrupted files.
3. Dependency replies are ingested immediately.
4. The old request-credit hot path is gone.
5. The scheduler is simpler and always range-based.
6. The runtime no longer carries dead shared-ingest wrappers.
7. Multi-source historical ranges repartition automatically when peers drop.
8. The graph test binary no longer needs manual `--test-threads=1`.

Still open:

1. Arbitrary coordinator-chosen ranges.
2. Smarter multi-peer range assignment.
3. More direct perf evidence for dependency-vs-range prioritization.

## Validation

Core validation used on this branch:

1. `cargo test -q range_scheduler_round_robins_windows --lib`
2. `cargo test -q receive_log_ --lib`
3. `cargo test -q --test sync_contract_tests`
4. `cargo test -q --test download_timeline_test`
5. `cargo test --test sync_graph_test`
6. `cargo test --test holepunch_test -- --test-threads=1`
7. `cargo test -q --tests --no-run`

Preserved CLI / e2e validation used on this branch:

1. `cargo test --test cli_test -- --test-threads=1`
2. `cargo test --test sync_control_cli_tests -- --test-threads=1`
3. `cargo test --test cli_invite_discovery_empty_bootstrap_test -- --test-threads=1`
4. `cargo test --test cli_invite_discovery_wrong_bootstrap_test -- --test-threads=1`
5. `cargo test --test cli_device_link_discovery_test -- --test-threads=1`
6. `cargo test --test cli_reused_invite_reload_test -- --test-threads=1`
7. `cargo test --test cli_live_file_sync_test -- --test-threads=1`

Representative multi-source proof on this branch:

1. `catchup_4x_240_spread_uses_multiple_sources_efficiently`
2. Result on current head:
   - 240 useful unique messages,
   - 243 received `Event` frames,
   - 4 active sources,
   - 98.8% delivery efficiency,
   - peer-dropout recovery still passes in `catchup_dead_peer_dropout`.

## Naming

The branch now uses this minimal vocabulary:

1. `Range`
2. `RangeSession`
3. `ReceiveLog`
4. `DependencyFetch`
5. `ingest_event_log`
6. `ingest_one`
7. `durable`
8. `projected`

The words we intentionally retired from the active bulk design are:

1. `wanted`
2. `credit`
3. `request-credit`
4. `shared_ingest`
