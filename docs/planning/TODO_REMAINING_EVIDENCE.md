# TODO Remaining Evidence Matrix

Branch: `exec/todo-remaining-non-event-locality-instructions`
Date: 2026-02-20

Maps each TODO section/item to file/test proof of completion.

## Stage 1: Rename/vocabulary closure

| Item | Evidence |
|------|----------|
| `network` → `peering` | Zero `crate::network` hits in `src/` and `tests/`; `src/peering/` is canonical |
| `replication` → `sync` | Zero `crate::replication` hits; `src/sync/` is canonical |
| `events` → `event_modules` | Zero `crate::events` (bare) hits; `src/event_modules/` is canonical |
| `event_runtime` → `event_pipeline` | Zero `crate::event_runtime` hits; `src/event_pipeline/` is canonical |
| `event_runtime_contract.rs` → `event_pipeline_contract.rs` | `src/contracts/event_pipeline_contract.rs` |
| `network_contract.rs` → `peering_contract.rs` | `src/contracts/peering_contract.rs` |
| `ReplicationStore` → `SyncStore` | `src/contracts/event_pipeline_contract.rs:65` |
| `SqliteReplicationStore` → `SqliteSyncStore` | `src/event_pipeline/sqlite_adapters.rs:93` |
| `ReplicationSessionHandler` → `SyncSessionHandler` | `src/sync/session_handler.rs:109`, `src/sync/mod.rs:7` |
| `tests/replication_contract_tests/` → `tests/sync_contract_tests/` | `tests/sync_contract_tests/main.rs` |
| Boundary script updated | `scripts/check_boundary_imports.sh` uses `event_pipeline_contract`, `peering_contract` |
| Active docs vocabulary | `docs/INDEX.md` superseded table updated; `docs/DESIGN.md` `Frame::Event` (was `SyncMessage::Event`) |

## Stage 2: `invite_accepted` semantics + model/doc closure

| Item | Evidence |
|------|----------|
| Prerequisite-free projection | `INVITE_ACCEPTED_META.dep_fields: &[]`, `signer_required: false` (`src/event_modules/invite_accepted.rs:155-158`) |
| Force-valid workspace command emission | `EmitCommand::RetryWorkspaceEvent { workspace_id }` emitted (`src/event_modules/invite_accepted.rs:132`) |
| Standard apply + unblock cascade | `RetryWorkspaceEvent` handled via `project_one()` in `src/projection/apply/write_exec.rs:80-96` |
| No service-triggered bootstrap hacks | Service layer uses `bootstrap_sync_from_invite()` (real QUIC sync), not event copies |
| TLA conformance | `docs/tla/EventGraphSchema.tla`: `InviteAccepted` in `LocalRoots`, invariants `InvTrustAnchorImmutable`, `InvTrustAnchorSource`, `InvInviteAcceptedRecorded`, `InvBootstrapTrustSource` |
| TLA conformance (bootstrap) | `docs/tla/BootstrapGraph.tla`: concrete bootstrap sequence modeled |
| Projector tests (pass/break) | `src/event_modules/invite_accepted_projector_tests.rs`: 5 tests covering SPEC_ANCHOR_IMMUTABLE, SPEC_ANCHOR_SOURCE, SPEC_BOOTSTRAP_TRUST |
| Integration test | `src/projection/apply/tests/mod.rs:3872`: `test_invite_accepted_guard_retry_on_workspace` |
| Runtime check catalog | `docs/tla/runtime_check_catalog.md`: CHK_IA_TRUST_ANCHOR_WRITE, CHK_IA_TRUST_ANCHOR_CONFLICT, CHK_IA_RETRY_GUARDS, CHK_IA_BOOTSTRAP_TRUST, CHK_IA_INVITE_RECORDED, CHK_IA_ANCHOR_SOURCE |

## Stage 3: Identity <-> transport boundary closure

| Item | Evidence |
|------|----------|
| Contract definition | `src/contracts/transport_identity_contract.rs`: `TransportIdentityIntent` enum + `TransportIdentityAdapter` trait |
| Sole materialization point | `src/transport/identity_adapter.rs`: `ConcreteTransportIdentityAdapter` — only code calling raw install functions |
| Event module usage | `src/event_modules/local_signer_secret.rs:139-144`: emits `ApplyTransportIdentityIntent` |
| Projection routing | `src/projection/apply/write_exec.rs:187-193`: routes through adapter |
| Service usage | `src/service.rs:1527-1535, 1683-1691`: uses adapter, not raw calls |
| No raw install leaks | `scripts/check_boundary_imports.sh:56-62`: enforces no raw calls in service/event_modules/projection |
| Bootstrap sync contracts-only | `src/peering/workflows/bootstrap.rs`: imports only contracts + transport, no event_module internals |
| Tests | `tests/identity_transport_contract_tests/`: 11 passing tests (intent, projection path, fake adapter) |
| DESIGN.md updated | §2.2 "Transport identity materialization boundary" added |
| PLAN.md updated | §17.1.4.1 "Transport identity materialization contract" added |

## Stage 4: Docs consistency + TODO closure

| Item | Evidence |
|------|----------|
| Active docs vocabulary | Zero stale module paths/symbols in active docs (verified by grep checks) |
| Archive disclaimers | All 34 archive docs have historical disclaimer blockquotes |
| `docs/INDEX.md` superseded table | Updated with contract file renames and symbol renames |
| TODO.md items 1-22 | All marked DONE with evidence (items verified before this branch) |
| TODO.md items 23-26 | Verified: `user_event_id` in PeerShared, `finish()` panic, `svc_bootstrap_workspace_conn`, `start_peers_pinned` |
| This evidence matrix | `docs/planning/TODO_REMAINING_EVIDENCE.md` |

## Quality gates

| Gate | Status |
|------|--------|
| `cargo check` | PASS |
| `bash scripts/check_boundary_imports.sh` | PASS |
| Mandatory grep check 1 (old crate paths in src/tests) | Zero hits |
| Mandatory grep check 2 (old paths in active docs) | Only INDEX.md superseded table (intended) |
| Mandatory grep check 3 (old symbols in src/docs) | Zero hits in src; DESIGN.md:283 "network layer" is generic networking term, not module reference |
