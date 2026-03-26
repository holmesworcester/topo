# Operational Runtime Pattern Findings

## What Works

### 1. SQLite as the coordination substrate

The strongest pattern in this experiment: **replace in-memory coordination state
with projected SQLite queries**. The runtime becomes a reconciler that reads
desired state and converges actual state toward it.

Concrete wins:
- `check_stale_dial_state` replaces an in-memory counter with a SQL query
  against `outbound_connection_history`. The stale-dial policy survives restart.
- `desired_runtime_action` replaces inline status-matching in main.rs with a
  single function that reads `client_runtime_history`. A reader can understand
  the reconciler's decision in one place.
- `load_due_effects` already drove the target dispatcher from SQLite. Extending
  this with `load_active_connections` and `is_connection_live` means the
  reconciler can derive worker liveness from projected state instead of a
  process-local HashMap.

The key insight: **the event pipeline is a serialization point**. Events go in,
projections come out, and the projected tables are the coordination substrate.
Concurrent runtime tasks don't need to coordinate with each other directly —
they just read/write through SQLite. WAL mode handles the concurrency.

### 2. Thin handle maps for mechanical lifecycle

The one thing SQLite can't hold: OS handles (CancellationToken, JoinHandle).
The `ConnectionReconciler` pattern separates this cleanly:
- **Policy** (which connections should be active, precedence, cadence): SQLite
- **Handles** (cancel, join): thin process-local map with no policy fields

The old `ActiveConnectWorker` carried `source_kind` — a policy field that
was used for precedence decisions. The reconciler's `WorkerHandle` has only
`cancel` and `join`. Precedence is decided by `should_activate_plan` in the
event family module, not by the handle map.

### 3. FieldSpec eliminates wire ceremony

The `FieldSpec` codec reduced ~1,100 lines of per-event parse/encode
boilerplate. Every event now declares its wire format as a `&[FieldSpec]`
array. This makes the event-owned architecture viable — without it, each
operational event cost 600-900 lines of ceremony, which was the biggest
barrier to adoption.

### 4. Typed outcomes eliminate hardcoded strings

`SessionOutcome` (Shutdown, ConnectionDropped, BuildMismatch) replaces
hardcoded `"session_ended"` strings. Small change, clear value: the close
reason is now type-checked and the event family decides what to record.

## What Doesn't Work (Yet)

### 1. The event pipeline as a concurrency barrier is expensive

Every "observation → event → projection → query" cycle opens a SQLite
connection, writes a blob, enqueues for projection, and then the caller
opens another connection to read the result. For high-frequency operations
(stale-dial checks on every connection attempt), this is measurably more
expensive than incrementing an in-memory counter.

The mitigation: batch observations and amortize the SQLite cost over
multiple events. The `ingest_now` path already does this for canonical
events. Operational events should follow the same pattern.

### 2. The live_connection_slots problem

Connection liveness is inherently process-local — a connection exists in
the QUIC transport layer, not in SQLite. The `live_connection_slots` HashMap
tracks which peer has an active connection to prevent duplicates. This
can't be fully SQLite-ified because:
- If the process crashes, SQLite would still show the connection as "live"
- Cleanup-on-crash requires either startup recovery or TTL-based expiry

The practical answer: keep `live_connection_slots` as an in-memory
coordination mechanism for duplicate prevention, but don't pretend it's
durable. Accept that this is process-local state that is legitimately
in-memory. The event system records observations after the fact.

### 3. Multi-client replay requires solving clock and causality

The `replay_multi_client` function works for projecting events into an
in-memory database, but it doesn't solve the hard problems:
- Two clients' local events have independent clocks
- Causal ordering across clients requires the bilateral episode IDs
- Conflict resolution between divergent local histories isn't defined

This needs a separate design — it's not a straightforward extension of
the event pipeline.

### 4. Boilerplate reduction has diminishing returns

After FieldSpec, the remaining per-event boilerplate is:
- Struct definition (~10 lines)
- Validate function (~10 lines)
- Projector function (~20-40 lines)
- Authoring helper (~10 lines)
- ParsedEvent variant + match arms (~15 lines across mod.rs)

That's ~70-90 lines per event. A macro could reduce this further but
would trade readability for brevity. The current level feels right.

## The Pattern That Emerges

The successful pattern for the runtime is:

```
1. External thing happens (dial result, session end, timer fires)
2. Runtime records an observation event
3. Event pipeline projects it into a table
4. Next reconciliation cycle queries the table
5. Reconciler spawns/cancels workers to converge
```

The runtime loop becomes:
```
loop {
    reap_finished_workers()
    desired = query_projected_state()
    actual = handle_map.keys()
    cancel(actual - desired)
    spawn(desired - actual)
    sleep_until(next_due_or_wake)
}
```

This is the "embarrassingly small runtime" the plan described.
The complexity lives in the event families (which define the projected
tables and the policy queries) and in the projectors (which maintain
the invariants). The runtime is just a reconciliation loop.

## Recommendations

1. **Land FieldSpec on master** — done
2. **Extract the reconciler pattern** as a standalone improvement
3. **Keep live_connection_slots in memory** — it's legitimate process state
4. **Batch operational event authoring** — don't open a connection per event
5. **Don't pursue multi-client replay** until bilateral IDs are integrated
   into the transport layer
6. **The operational event types are correct in shape** but should be rebuilt
   on current master rather than trying to rebase this branch
