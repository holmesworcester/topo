# Refactoring Plan: Simplicity & Performance

**Guiding Principles:**
1. **Simplicity first** - Less code, clearer intent, easier maintenance
2. **Performance** - Eliminate waste, batch operations, reduce allocations
3. **Correctness preserved** - All changes must maintain sync correctness

---

## Phase 1: Code Simplification (Do First)

### 1.1 Extract Shared Utilities
- [ ] Create `src/util.rs` with `current_timestamp_ms()`
- [ ] Remove duplicates from `store.rs`, `outgoing.rs`, `wanted.rs`

### 1.2 Remove Dead Code
- [ ] Remove `incoming_queue` table from schema (unused in dual-stream)
- [ ] Fix double COMMIT bug at main.rs:713-714
- [ ] Remove any unused imports

### 1.3 Unify Sync Functions
- [ ] Create `SyncRole` enum (Initiator, Responder)
- [ ] Merge `run_sync_initiator_dual` and `run_sync_responder_dual` into single `run_sync_dual(role, ...)`
- [ ] Extract common setup into helper functions

### 1.4 Refactor batch_writer
- [ ] Extract common event processing into `process_event_batch()`
- [ ] Make dependency strategy a parameter/enum instead of 3 separate code paths
- [ ] Reduce branch duplication from ~230 lines to ~80 lines

---

## Phase 2: High-Impact Performance (Do Second)

### 2.1 Eliminate Busy-Wait Polling
**Current:** 1ms timeout polling burns CPU
```rust
match tokio::time::timeout(Duration::from_millis(1), conn.control.recv()).await
```
**Target:** True async multiplexing with `tokio::select!`
- [ ] Replace polling loops with `tokio::select!` in main sync loop
- [ ] Handle control, data receive, and send readiness concurrently

### 2.2 Batch Blob Fetching for Sends
**Current:** One `store.get()` per event sent
**Target:** Single query for batch of blobs
- [ ] Add `Store::get_batch(&[EventId]) -> Vec<(EventId, Vec<u8>)>`
- [ ] Use batch fetch in send loop

### 2.3 Incremental Block Index Rebuild
**Current:** Full O(N) rebuild on every sync start (~260ms for 100k)
**Target:** Skip rebuild if no new items
- [ ] Track `last_item_count` in `neg_meta` table
- [ ] Compare current count; skip rebuild if unchanged
- [ ] (Future) Incremental append for new items only

---

## Phase 3: Medium-Impact Performance (Do Third)

### 3.1 Consistent ID Storage Format
**Current:** Mixed base64 TEXT and raw BLOB across tables
**Target:** Raw BLOB everywhere (faster, smaller)
- [ ] Migrate `store.id` from TEXT to BLOB
- [ ] Migrate `shareable_events.id` from TEXT to BLOB
- [ ] Migrate `messages.message_id` from TEXT to BLOB
- [ ] Remove `event_id_to_base64()` from hot paths

### 3.2 Batch neg_items Inserts
**Current:** Individual INSERT per event in batch_writer
**Target:** Multi-row INSERT
- [ ] Accumulate neg_items inserts within transaction
- [ ] Use single INSERT with multiple VALUE tuples

### 3.3 Optimize Negentropy OFFSET Queries
**Current:** `OFFSET ?` is O(N) for large offsets
**Options:**
- [ ] Reduce BLOCK_SIZE from 4096 to 1024 (limits max offset)
- [ ] OR: Use cursor-based iteration instead of OFFSET

---

## Phase 4: Lower-Impact Optimizations (Optional)

### 4.1 Pre-allocate Vectors
- [ ] `Vec::with_capacity()` in batch collection loops
- [ ] Reuse buffers where possible

### 4.2 Reduce Flush Frequency
- [ ] Flush data stream less often when queue has more items
- [ ] Adaptive flush based on pending bytes

### 4.3 Larger HaveList Chunks
- [ ] Increase from 1000 to 5000 IDs per message
- [ ] Reduces control stream round trips

---

## Implementation Order

1. **Phase 1.1-1.2** - Quick wins, low risk
2. **Phase 1.3-1.4** - Bigger refactor, high code reduction
3. **Phase 2.1** - Select! loop (biggest perf win)
4. **Phase 2.2-2.3** - Batch operations
5. **Phase 3** - As time permits
6. **Phase 4** - Polish

---

## Testing Strategy

- Run `cargo test` after each phase
- Run `cargo run --release -- sim --events 10000` to verify sync still works
- Compare throughput/memory before and after Phase 2

### Real QUIC Integration Test
- [ ] Add `tests/quic_integration.rs` with actual QUIC transport test
- [ ] Spawn server and client in separate tasks (not threads)
- [ ] Test with 1000+ events each direction over localhost
- [ ] Verify both peers have all events after sync
- [ ] Test connection error handling (server down, timeout)
- [ ] Ensure test runs in CI without flakiness

---

## Notes

- Keep commits atomic and reviewable
- Preserve all existing CLI commands and behavior
- Don't change wire protocol (maintain compatibility)
