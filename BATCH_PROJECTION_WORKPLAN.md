# Batch Projection Refactor

## Baseline

- Current: ~1,900 msgs/s (10k bidirectional sync, daemon, warm)
- Note: `02cbebe` (forward-on-have) halved throughput from ~4K — separate regression
- Target: 5-10x improvement on the projection phase

## Architecture

### Current model (autocommit-per-event)

```
for event in batch:
    context = read_from_db(conn, event)    // 1+ queries per event
    project_one(conn, tenant, event)       // autocommit writes
```

### New model (batch pure-function projection)

```
1. context = batch_read_context(db, tenant)     // 1 query per table
2. ops = batch.map(|e| project(e, &context))    // pure functions, no DB
3. partition ops → succeeded WriteOps + blocked
4. commit all succeeded WriteOps in one transaction
5. cascade-unblock blocked events until stable
6. commit newly-unblocked WriteOps
```

## Implementation Plan

### Phase 1: Define WriteOp and ProjectionContext types
- `WriteOp` enum covering all projector outputs (insert, update, delete, block)
- `ProjectionContext` struct with pre-read tenant state
- Context reader function that batch-reads small identity tables

### Phase 2: Convert message projector (most common type)
- Messages have zero deps — simplest projector
- Returns `Vec<WriteOp>` instead of writing to DB directly
- Keep old `project_one` path for all other types

### Phase 3: Convert identity projectors
- User, PeerShared, PeerSecret, InviteAccepted, etc.
- These have dependency chains — blocking becomes `WriteOp::Block`
- Cascade-unblock at end of batch

### Phase 4: Batch commit executor
- Takes `Vec<WriteOp>` and executes in one transaction
- Groups by table for efficient multi-row INSERT

### Phase 5: Wire into batch_writer
- Replace `drain_project_queue_on_connection` with new batch path
- Measure, iterate

## Success Criteria

- All existing tests pass
- perf_sync_10k throughput >= 2x improvement over baseline
- Projectors are testable without a database connection
