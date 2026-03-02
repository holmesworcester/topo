# Low-Latency Coordinated Download Plan (Streaming Ownership + Fallback)

Date: 2026-03-01
Branch: `exec/multisource-file-fix`
Status: **completed**

## Summary

Implemented deterministic per-event ownership for multi-source download with
threshold-based claim-all fallback for source-unique events.

### Key design decisions

1. **Streaming ownership dispatch**: during reconciliation, each `need_id` is
   routed through `is_event_owned(event_id, peer_idx, total_peers)` using
   `hash(event_id[0..8]) % total_peers == peer_idx`. Owned events get
   `HaveList` immediately (no barrier).

2. **Threshold-based claim-all**: when `need_ids.len() <= total_peers *
   FALLBACK_THRESHOLD_FACTOR` (currently 20), the session claims ALL need_ids
   regardless of ownership. This handles source-unique events (identity chains,
   markers) that only exist at one specific source and cannot be downloaded by
   their deterministic "owner" peer.

3. **Pre-registration of peers**: all `PeerCoord` handles are registered before
   spawning connect loop threads, ensuring `total_peers` is correct from the
   first session. Eliminates the race where early threads see `total_peers=1`.

4. **Shared batch_writer**: a single ingest channel + writer thread serves all
   connect loops for one sink, providing fair source attribution via
   `recorded_events.source`.

5. **clone_events_to workspace_id fix**: test helper now inserts neg_items with
   the target peer's workspace_id (not default ''), preventing duplicate
   neg_items that inflated negentropy counts.

### Files changed

- `src/runtime/sync_engine/session/control_plane.rs` — ownership dispatch with threshold
- `src/runtime/sync_engine/session/initiator.rs` — streaming ownership integration
- `src/runtime/sync_engine/session/coordinator.rs` — PeerCoord struct
- `src/runtime/peering/loops/connect.rs` — `connect_loop_with_shared_ingest`
- `src/testutil/mod.rs` — `start_sink_download` pre-registration, `clone_events_to` fix
- `src/event_modules/file_slice/projection_context.rs` — source attribution queries
- `tests/sync_graph_test.rs` — Family C multi-source file tests

### Test evidence (release mode)

4x1024 slices (3 consecutive passes):
- Run 1: 1245ms, 23.7%/23.3%/25.8%/27.1% split
- Run 2: 636ms, 22.6%/23.1%/27.8%/26.5% split
- Run 3: 638ms, 25.9%/25.5%/23.5%/25.1% split

8x1024 slices:
- 1292ms, 10.2%-14.2% per source (all 8 contributing)

Chain 10-hop 10k: passes, no regression.

Contract tests: 21/21 passing.

## Acceptance Criteria (all met)

1. No mandatory reconcile->assign->dispatch barrier in initiator flow.
2. Chain test has no multi-minute stall from coordinator wait.
3. Multi-source large-file tests pass with >=5% per-source contribution floor.
4. Ownership logic is deterministic and documented (threshold fallback for source-unique events).
5. Execution plan updated with evidence.
