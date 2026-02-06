# Sync Round Design (Snapshot Negentropy + 1-Hop Gossip)

This document formalizes the sync design for SQLite-backed negentropy with QUIC dual streams, optimized for correctness, low memory, and continuous operation.

## Core Invariants
1. **Negentropy runs on a stable snapshot** of `neg_items` for the duration of a round.
2. **Only one round per peer** at a time.
3. **Fast-path for locally created events** (1-hop gossip).
4. **Negentropy repairs everything else.**

## Per-Peer State (Minimal)
- `last_sync_epoch: u64` — local epoch fully reconciled with this peer.
- `snapshot_epoch: u64` — epoch captured at round start.
- `round_in_flight: bool`
- `pending_round: bool` — set if local epoch advanced during round.
- `last_round_end: Instant`

## Local State (Minimal)
- `local_epoch: AtomicU64` — increment on every successful `neg_items` insert.
- `heartbeat_interval`
- `round_time_budget`
- `round_idle_budget`

## Round Lifecycle
1. **Start**
   Trigger on:
   - New connection
   - `local_epoch > last_sync_epoch`
   - Heartbeat timeout
2. **Snapshot**
   - Open dedicated SQLite connection for negentropy.
   - `BEGIN` a read transaction (snapshot consistency).
   - `snapshot_epoch = local_epoch`.
3. **Reconcile**
   - Run negentropy control loop over the snapshot.
4. **End**
   - End on completion, time budget, or idle budget.
   - `COMMIT` read transaction.
   - `last_sync_epoch = snapshot_epoch`.
   - If `local_epoch > last_sync_epoch`, set `pending_round = true`.

## State Machine (Per Peer)
```
Idle -> Reconciling: peer_connected OR dirty OR heartbeat
Reconciling -> Cooldown: round_complete OR time_budget OR idle_budget
Cooldown -> Reconciling: pending_round OR local_epoch > last_sync_epoch
Cooldown -> Idle: clean AND no pending_round
```

## Task Responsibilities

### Round Manager (per peer)
- Starts rounds on dirty/connect/heartbeat.
- Opens snapshot connection and `BEGIN`.
- Runs negentropy until complete or budget.
- `COMMIT` snapshot; updates `last_sync_epoch`.
- If `local_epoch` advanced, schedules another round.

### Control Sender
- Sends negentropy control messages (NegOpen/NegMsg/HaveList).
- Loops until stream blocks; flushes when needed.

### Control Receiver
- Receives control messages and feeds the negentropy state machine.
- Produces have/need IDs when reconciliation ends.

### Data Sender (per peer)
- **Pulls from DB on-demand**, **pushes to stream**.
- While stream is writeable and queue not empty:
  - pop ID
  - fetch blob from DB
  - send on stream
- Stops only when stream blocks or queue empties.

### Data Receiver
- Reads data stream.
- Sends `(id, blob)` into bounded ingest channel with `send().await`.
- Backpressures only when ingest is saturated.

### Ingest Worker
- Drains ingest channel in batches.
- Writes `store`, `shareable_events`, `neg_items`.
- Increments `local_epoch`.
- Marks peers dirty.

### Projection Worker (optional)
- Consumes `incoming_queue` asynchronously.
- Never blocks ingest or receive.

## Fast-Path Gossip (Newest Events)
- **Locally created events:** send immediately to direct peers on data stream.
- **Received events:** do not re-gossip; mark peers dirty so negentropy can pull.
- This avoids floods while keeping newest data fast.

## Backpressure Strategy
- Backpressure only applies at the **ingest channel** (receive side).
- Control and data streams are separate, so large data writes never block reconciliation.
- `send().await` avoids drops and ensures pacing under load.

## Why This Is Simple
- No new tables required.
- No in-flight rounds per peer.
- No blob prefetch.
- Clear correctness boundary: **negentropy sees a stable snapshot**.

## Simplicity Optimizations (Minimal LOC / Conceptual Overhead)

If you want the smallest possible implementation while keeping correctness, use this pared-down variant:

### Minimal State
Per peer:
- `round_in_flight: bool`
- `pending_round: bool`
- `last_sync_epoch: u64` (or just `dirty: bool` + heartbeat)

Local:
- `local_epoch: AtomicU64` (or incrementing counter in memory)

### Minimal State Machine
```
Idle -> Reconciling: peer_connected OR dirty OR heartbeat
Reconciling -> Idle: round_complete OR time_budget
Reconciling -> Reconciling: pending_round (immediately restart)
```
No cooldown state, no idle budget. Just a time budget + completion.

### Minimal Correctness Guarantee
- Use **one dedicated read transaction** per round for a stable snapshot.
- Keep writers on a separate connection.
- Rebuild `neg_blocks` before each round (simple and safe).

### Minimal Backpressure Design
- One bounded ingest channel.
- Data receiver uses `send().await` into ingest channel.
- Projection remains async and never blocks ingest.

### Minimal Throughput Design
- One data sender loop per peer that **writes until blocked**.
- The sender **pulls from DB on-demand**; no prefetch.

### Minimal Dirty Tracking
Two options:
1. **Epoch-based (preferred):** increment on each `neg_items` insert.
2. **Dirty flag + heartbeat:** set dirty on insert; reconcile on interval to catch false clean.

This keeps the design small, correct, and fast without extra tables, queues, or complex coordination.

## Simplified Plan With Added Requirements/Goals

### Requirements/Goals
1. Minimal in-memory state; prefer DB-backed state.
2. No large `have_ids`/`need_ids` vectors in memory.
3. Send queue must not balloon under backpressure.
4. Always send as fast as the QUIC stream allows.
5. Maintain correctness with a stable snapshot per round.

### Simplest Plan That Satisfies All Goals
1. **Snapshot per round**  
   Open a dedicated SQLite connection for negentropy and `BEGIN` a read transaction before reconciliation. Commit at round end.

2. **One round per peer**  
   Track `round_in_flight`, `pending_round`, and `last_sync_epoch` (or `dirty` + heartbeat).

3. **Bounded ingest backpressure**  
   Receiver uses `send().await` into a bounded ingest channel. Projection remains async and never blocks ingest.

4. **Stream-until-blocked sender**  
   Data sender loops while the stream is writeable, pulling blobs from DB on demand and writing to QUIC until blocked.

5. **DB-spooled outgoing queue**  
   Replace in-memory send queues with a SQLite table keyed by peer. Sender reads and deletes rows as it sends. This caps RAM use regardless of backlog size.

6. **Chunked have/need processing**  
   Do not hold full `have_ids`/`need_ids` in memory. Either:\n
   - spill IDs into DB as they are produced, or\n
   - process in small fixed-size chunks (windowed HaveList / Have processing).

7. **Fast path for local events only**  
   Locally created events are pushed 1 hop immediately. Received events are not re-gossiped; they mark peers dirty for the next round.

### Minimal Implementation Path
1. Add snapshot read transaction around reconciliation using a dedicated connection.
2. Add per-peer `round_in_flight`, `pending_round`, and `last_sync_epoch` (or `dirty`).
3. Add a SQLite table for outgoing IDs (per peer) and switch sender to read from it.
4. Change `have/need` handling to chunked processing or DB spill.
5. Keep existing bounded ingest channel and async projection.

## Sketch: DB-Spool Queue + Chunked Have/Need

### SQLite Schema (Outgoing Queue)
```
CREATE TABLE IF NOT EXISTS outgoing_queue (
  peer_id TEXT NOT NULL,
  event_id BLOB NOT NULL,
  enqueued_at INTEGER NOT NULL,
  PRIMARY KEY (peer_id, event_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_outgoing_peer
  ON outgoing_queue(peer_id, enqueued_at);
```

### Enqueue Have IDs (Spill to DB)
```
fn enqueue_have_ids(conn: &Connection, peer_id: &str, have_ids: &mut Vec<Id>) -> Result<()> {
    let now = now_ms();
    let tx = conn.transaction()?;
    let mut stmt = tx.prepare(
        "INSERT OR IGNORE INTO outgoing_queue (peer_id, event_id, enqueued_at)
         VALUES (?1, ?2, ?3)"
    )?;
    for id in have_ids.drain(..) {
        stmt.execute(rusqlite::params![peer_id, id.as_bytes(), now])?;
    }
    tx.commit()?;
    Ok(())
}
```

### Send Need IDs Immediately (Chunked)
```
fn flush_need_ids(conn: &mut DualConnection, need_ids: &mut Vec<Id>) -> Result<()> {
    const NEED_CHUNK: usize = 1000;
    while need_ids.len() >= NEED_CHUNK {
        let chunk: Vec<EventId> = need_ids
            .drain(..NEED_CHUNK)
            .map(|id| neg_id_to_event_id(&id))
            .collect();
        conn.send_control(&SyncMessage::HaveList { ids: chunk })?;
    }
    Ok(())
}

fn flush_need_ids_final(conn: &mut DualConnection, need_ids: &mut Vec<Id>) -> Result<()> {
    if !need_ids.is_empty() {
        let chunk: Vec<EventId> = need_ids
            .drain(..)
            .map(|id| neg_id_to_event_id(&id))
            .collect();
        conn.send_control(&SyncMessage::HaveList { ids: chunk })?;
    }
    Ok(())
}
```

### Sender: Batch Pull From DB and Stream Until Blocked
```
fn fetch_outgoing_batch(conn: &Connection, peer_id: &str, limit: usize) -> Result<Vec<(i64, Vec<u8>)>> {
    let mut stmt = conn.prepare(
        "SELECT rowid, event_id FROM outgoing_queue
         WHERE peer_id = ?1 ORDER BY enqueued_at LIMIT ?2"
    )?;
    let rows = stmt.query_map(rusqlite::params![peer_id, limit as i64], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
    })?;
    Ok(rows.flatten().collect())
}

fn delete_sent_batch(conn: &Connection, rowids: &[i64]) -> Result<()> {
    if rowids.is_empty() {
        return Ok(());
    }
    let placeholders = std::iter::repeat("?")
        .take(rowids.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!("DELETE FROM outgoing_queue WHERE rowid IN ({})", placeholders);
    let tx = conn.transaction()?;
    let params: Vec<&dyn rusqlite::ToSql> = rowids.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
    tx.execute(&sql, params.as_slice())?;
    tx.commit()?;
    Ok(())
}
```

### Integration Points (Minimal Changes)
1. After each `reconcile_with_ids`, call `enqueue_have_ids` if `have_ids` is large or on completion.
2. After each `reconcile_with_ids`, call `flush_need_ids` to send requests in chunks.
3. At reconciliation end, call `flush_need_ids_final`.
4. Sender loop pulls batches from `outgoing_queue` and streams until blocked, deleting only sent rowids.
