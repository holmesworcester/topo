# Parallel Cleanup Plan Index

> **Historical plan; file paths may not match the current source tree.** `src/events/` is now `src/event_modules/`; `src/projection/pipeline.rs` is now `src/projection/apply/`.

This index splits cleanup work into parallelizable streams with explicit file ownership and dependency edges so multiple assistants can work safely at the same time.

## Stream List

1. `01_transport_trust_test_plan.md`
2. `02_identity_compat_cleanup_plan.md`
3. `03_db_surface_prune_plan.md`
4. `04_event_legacy_prune_plan.md`
5. `05_docs_archive_hygiene_plan.md`

## Parallel Execution Model

### Wave 1 (can run in parallel)

1. Stream 1: transport trust test modernization
2. Stream 2: identity compatibility cleanup
3. Stream 3: DB surface pruning
4. Stream 5: docs/archive hygiene

### Wave 2 (run after Wave 1 merges)

1. Stream 4: event legacy pruning (`peer_key`, `bench_dep`)

Wave 2 is intentionally sequenced after Wave 1 because it has broader protocol/test surface impact and higher merge/conflict risk.

## File Ownership Matrix

### Stream 1 owns

1. `src/testutil.rs`
2. `tests/cli_test.rs`
3. `tests/holepunch_test.rs`
4. `tests/netns_nat_test.sh`

### Stream 2 owns

1. `src/identity.rs`
2. `src/lib.rs`
3. `src/main.rs`
4. `docs/IDENTITY_RENAME_PLAN.md`

### Stream 3 owns

1. `src/db/mod.rs`
2. `src/db/schema.rs`
3. `src/db/outgoing.rs`
4. `src/db/shareable.rs`
5. `src/db/tenant.rs`

### Stream 4 owns

1. `src/events/peer_key.rs`
2. `src/events/bench_dep.rs`
3. `src/events/mod.rs`
4. `src/projection/signer.rs`
5. `src/projection/projectors.rs`
6. `src/projection/pipeline.rs`
7. `src/projection/encrypted.rs`
8. `tests/scenario_test.rs`
9. `tests/topo_cascade_test.rs`
10. `tests/file_throughput.rs`

### Stream 5 owns

1. `FEEDBACK.md`
2. `feedback.md`
3. `docs/PLAN.md`
4. `docs/DESIGN.md`
5. `docs/PERF.md`
6. `docs/LOW_MEM_PERF_ANALYSIS.md`
7. `docs/PHASE_7_LOGIC_FIXES.md`
8. `docs/QUIC_HOLEPUNCH_PLAN.md`
9. `docs/SYNC_GRAPH_PERF_PLAN.md`
10. new docs under `docs/archive/` or `docs/cleanup/`

## Cross-Stream Rules

1. Do not modify another stream's owned files unless a blocker requires a handoff.
2. If a blocker appears, open a small follow-up patch in the owning stream instead of broadening scope.
3. Keep commits stream-local and rebase before merge.
4. Run `cargo check --all-targets` before opening PRs.

## Suggested Branch Names

1. `cleanup/transport-trust-tests`
2. `cleanup/identity-compat`
3. `cleanup/db-surface-prune`
4. `cleanup/event-legacy-prune`
5. `cleanup/docs-hygiene`

