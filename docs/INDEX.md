# Documentation Index

## Active Documents

These are current specs, plans, and reference material.

| Document | Description |
|----------|-------------|
| [PLAN.md](PLAN.md) | Authoritative implementation plan for all phases |
| [DESIGN.md](DESIGN.md) | Target protocol design (post-PLAN end state) |
| [CURRENT_RUNTIME_DIAGRAM.md](CURRENT_RUNTIME_DIAGRAM.md) | Engineer-facing runtime diagrams (node, sync session, ingest/projection flow) |
| [../TODO.md](../TODO.md) | Current discrepancy/remediation backlog and execution ordering |
| [PERF.md](PERF.md) | Benchmark results and testing guide |
| [LOW_MEM_PERF_ANALYSIS.md](LOW_MEM_PERF_ANALYSIS.md) | Scaling analysis and memory-constrained architecture guidance |
| [tla/projector_spec.md](tla/projector_spec.md) | Runtime-to-model mapping for projector semantics |
| [planning/DISCREPANCY-MATRIX.md](planning/DISCREPANCY-MATRIX.md) | Current design/plan/code discrepancy matrix |

## Canonical Module Vocabulary

These are the current source module names. Active docs should use these names exclusively.

| Module | Path | Description |
|--------|------|-------------|
| `peering` | `src/peering/` | Transport runtime, peer lifecycle, accept/connect loops, NAT traversal, mDNS discovery |
| `sync` | `src/sync/` | Negentropy reconciliation, sync session handler |
| `protocol` | `src/protocol/` | Wire frame encoding/decoding (`wire.rs`) |
| `event_modules` | `src/event_modules/` | Per-event-type wire format, projectors, commands, queries |
| `event_pipeline` | `src/event_pipeline/` | Ingest runtime (`batch_writer`), projection queue draining, SQLite adapters |
| `projection/apply` | `src/projection/apply/` | Projection pipeline: `project_one`, cascade, context, dispatch, stages |
| `projection` | `src/projection/` | Projection create, encrypted, signer, decision, emit helpers |
| `identity` | `src/identity/` | Transport identity, identity ops (bootstrap, invite, accept) |
| `transport` | `src/transport/` | Cert generation, mTLS, trust oracle, multi-workspace cert resolver |
| `db` | `src/db/` | Schema, migrations, queues, trust, removal watch |

### Superseded names (do not use in active docs)

| Old name | Current name |
|----------|-------------|
| `src/network/` | `src/peering/` |
| `src/replication/` | `src/sync/` |
| `src/event_runtime/` | `src/event_pipeline/` |
| `src/events/` | `src/event_modules/` |
| `src/sync/protocol.rs` | `src/protocol/wire.rs` |
| `src/projection/pipeline.rs` | `src/projection/apply/` |
| `src/projection/projectors.rs` | deleted; projectors live in `src/event_modules/<type>/projector.rs` |
| `src/projection/identity.rs` | deleted; identity projectors live in event modules |
| `src/sync/engine.rs` | split into `src/peering/loops/` and `src/peering/runtime/` |
| `src/identity_ops.rs` | `src/identity/ops.rs` |
| `src/transport_identity.rs` | `src/identity/transport.rs` |
| `src/discovery.rs` | `src/peering/discovery.rs` |
| `event_runtime_contract.rs` | `event_pipeline_contract.rs` |
| `network_contract.rs` | `peering_contract.rs` |
| `ReplicationStore` | `SyncStore` |
| `SqliteReplicationStore` | `SqliteSyncStore` |
| `ReplicationSessionHandler` | `SyncSessionHandler` |
| `tests/replication_contract_tests/` | `tests/sync_contract_tests/` |

## Maintenance Note

Archived docs (`docs/archive/`) may contain historically inaccurate module names and file paths. They are retained for context but should **not** be used as implementation source of truth. Only active documents (listed above) reflect the current source tree.

## Archive

Historical feedback artifacts, completed execution plans, and superseded planning docs. Retained for context, not active guidance.

| Document | Description |
|----------|-------------|
| [archive/CLI_BOOTSTRAP_TEST_REALISM_EXECUTION_PLAN.md](archive/CLI_BOOTSTRAP_TEST_REALISM_EXECUTION_PLAN.md) | Completed: CLI bootstrap test realism |
| [archive/CREATE_EVENT_SYNC_SEMANTICS_EXECUTION_PLAN.md](archive/CREATE_EVENT_SYNC_SEMANTICS_EXECUTION_PLAN.md) | Completed: create_event_sync semantics investigation |
| [archive/CREATE_EVENT_SYNC_SEMANTICS_FINDINGS.md](archive/CREATE_EVENT_SYNC_SEMANTICS_FINDINGS.md) | Completed: create_event_sync semantics findings |
| [archive/FIXED_LENGTH_FIELDS_EXECUTION_PLAN.md](archive/FIXED_LENGTH_FIELDS_EXECUTION_PLAN.md) | Completed: fixed-length event fields |
| [archive/HOLEPUNCH_TEST_REALISM_EXECUTION_PLAN.md](archive/HOLEPUNCH_TEST_REALISM_EXECUTION_PLAN.md) | Completed: hole-punch test realism |
| [archive/IDENTITY_RENAME_PLAN.md](archive/IDENTITY_RENAME_PLAN.md) | Completed: transport identity rename |
| [archive/ISSUE_8_SAVEPOINT_CASCADE_REGRESSION.md](archive/ISSUE_8_SAVEPOINT_CASCADE_REGRESSION.md) | Historical: savepoint cascade regression |
| [archive/NETWORKING_EVENT_BOUNDARY_OPTIONS.md](archive/NETWORKING_EVENT_BOUNDARY_OPTIONS.md) | Historical: networking/event boundary options |
| [archive/OPTION_B_NETWORK_BOUNDARY_IMPLEMENTATION_PLAN.md](archive/OPTION_B_NETWORK_BOUNDARY_IMPLEMENTATION_PLAN.md) | Completed: Option B network boundary implementation |
| [archive/OPTION_B_NETWORK_BOUNDARY_PHASE_6_HARDENING_PLAN.md](archive/OPTION_B_NETWORK_BOUNDARY_PHASE_6_HARDENING_PLAN.md) | Historical: Option B Phase 6 hardening |
| [archive/PEER_NEW_IN_WORKSPACE_EXECUTION_PLAN.md](archive/PEER_NEW_IN_WORKSPACE_EXECUTION_PLAN.md) | Completed: Peer::new_in_workspace realism |
| [archive/PLAN-collapse-single-tenant.md](archive/PLAN-collapse-single-tenant.md) | Completed: collapse single-tenant mode |
| [archive/QUIC_HOLEPUNCH_PLAN.md](archive/QUIC_HOLEPUNCH_PLAN.md) | Historical: QUIC hole punch plan |
| [archive/SYNC_GRAPH_PERF_PLAN.md](archive/SYNC_GRAPH_PERF_PLAN.md) | Historical: sync graph performance plan |
| [archive/QUIC_HOLEPUNCH_FEEDBACK.md](archive/QUIC_HOLEPUNCH_FEEDBACK.md) | Branch review: `quic-holepunch` |
| [archive/FILES_SYNC_MERGE_FEEDBACK.md](archive/FILES_SYNC_MERGE_FEEDBACK.md) | Branch review: file-sync merge (post-revert) |
| [archive/MASTER_9bbbc47_FEEDBACK.md](archive/MASTER_9bbbc47_FEEDBACK.md) | Master snapshot feedback |
| [archive/PHASE_0_FEEDBACK.md](archive/PHASE_0_FEEDBACK.md) | Phase 0 review |
| [archive/PHASE_0_5_FEEDBACK.md](archive/PHASE_0_5_FEEDBACK.md) | Phase 0.5 review |
| [archive/PHASE_2_5_FIXES_FEEDBACK.md](archive/PHASE_2_5_FIXES_FEEDBACK.md) | Phase 2.5 fixes review |
| [archive/PHASE_5_FEEDBACK.md](archive/PHASE_5_FEEDBACK.md) | Phase 5 review |
| [archive/PHASE_6_FEEDBACK.md](archive/PHASE_6_FEEDBACK.md) | Phase 6 review |
| [archive/PHASE_7_FEEDBACK.md](archive/PHASE_7_FEEDBACK.md) | Phase 7 review |
| [archive/PHASE_7_LOGIC_FIXES.md](archive/PHASE_7_LOGIC_FIXES.md) | Historical: Phase 7 guard-placement fix plan |
| [archive/TRANSPORT_TRUST_HARDENING_FEEDBACK.md](archive/TRANSPORT_TRUST_HARDENING_FEEDBACK.md) | Transport trust hardening review |
| [archive/NEGENTROPY_SQLITE_PLAN.md](archive/NEGENTROPY_SQLITE_PLAN.md) | Historical: negentropy/SQLite plan |
| [archive/SYNC_ROUND_DESIGN.md](archive/SYNC_ROUND_DESIGN.md) | Historical: sync round design |
| [archive/OPTION_B_PLAN_OPUS46_FEEDBACK.md](archive/OPTION_B_PLAN_OPUS46_FEEDBACK.md) | Option B plan review |
| [archive/STREAM2_IDENTITY_COMPAT_PLAN_FEEDBACK.md](archive/STREAM2_IDENTITY_COMPAT_PLAN_FEEDBACK.md) | Stream 2 identity compat feedback |
| [archive/STREAM_5_DOCS_HYGIENE_FEEDBACK.md](archive/STREAM_5_DOCS_HYGIENE_FEEDBACK.md) | Stream 5 docs hygiene feedback |
| [archive/PARALLEL_CLEANUP_INDEX.md](archive/PARALLEL_CLEANUP_INDEX.md) | Historical: parallel cleanup plan index |
| [archive/01_transport_trust_test_plan.md](archive/01_transport_trust_test_plan.md) | Historical: transport trust test modernization |
| [archive/02_identity_compat_cleanup_plan.md](archive/02_identity_compat_cleanup_plan.md) | Historical: identity compat cleanup |
| [archive/03_db_surface_prune_plan.md](archive/03_db_surface_prune_plan.md) | Historical: DB surface pruning |
| [archive/04_event_legacy_prune_plan.md](archive/04_event_legacy_prune_plan.md) | Historical: legacy event surface pruning |
| [archive/05_docs_archive_hygiene_plan.md](archive/05_docs_archive_hygiene_plan.md) | Historical: docs archive hygiene |
| [archive/06_misplaced_and_superfluous_cleanup_handoff.md](archive/06_misplaced_and_superfluous_cleanup_handoff.md) | Historical: misplaced cleanup handoff |

## Other Directories

| Directory | Description |
|-----------|-------------|
| `planning/` | Execution plans and discrepancy tracking for active workstreams |
| `tla/` | TLA+ formal models and configs (BootstrapGraph, EventGraphSchema, transport lifecycle) |
| `archive/` | Historical plans, feedback docs, and superseded material |
