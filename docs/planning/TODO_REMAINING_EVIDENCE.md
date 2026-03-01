# TODO Remaining Evidence Matrix

Branch: `exec/todo-remaining-non-event-locality-instructions`
Date: 2026-02-20

Maps each TODO section/item to file/test proof of completion.

## Stage 1: Rename/vocabulary closure

| Item | Evidence |
|------|----------|
| `network` → `peering` | Zero `crate::network` hits in `src/` and `tests/`; `src/peering/` is canonical |
| `replication` → `sync` | Zero `crate::replication` hits; `src/sync/` is canonical; zero "replication" in src/ comments |
| `events` → `event_modules` | Zero `crate::events` (bare) hits; `src/event_modules/` is canonical |
<<<<<<< HEAD
| `event_runtime` → `event_pipeline` | Zero `crate::event_runtime` hits; `src/event_pipeline.rs` is canonical; straggler comments fixed |
| `event_runtime_contract.rs` → `event_pipeline_contract.rs` | `src/contracts/event_pipeline_contract.rs` |
| `network_contract.rs` → `peering_contract.rs` | `src/contracts/peering_contract.rs` |
| `ReplicationStore` → `SyncStore` | `src/contracts/event_pipeline_contract.rs:65` |
| `SqliteReplicationStore` → `SqliteSyncStore` | Zero symbol hits in `src/` (legacy names removed from active code) |
| `ReplicationSessionHandler` → `SyncSessionHandler` | `src/sync/session_handler.rs:109`, `src/sync/mod.rs:7` |
| `tests/replication_contract_tests/` → `tests/sync_contract_tests/` | `tests/sync_contract_tests/main.rs` |
| Boundary script updated | `scripts/check_boundary_imports.sh` uses `event_pipeline_contract`, `peering_contract` |
| Active docs vocabulary | `docs/INDEX.md` superseded table updated; `docs/DESIGN.md` `Frame::Event` (was `SyncMessage::Event`) |
| Straggler comments cleaned | `sync/session/mod.rs`, `sync/session/receiver.rs`, `peering/loops/mod.rs`, `event_pipeline/ingest_runtime.rs` |
| Completed planning docs archived | `docs/archive/TODO4_DOCS_CONSISTENCY_INSTRUCTIONS.md` (with historical disclaimer) |

## Stage 2: `invite_accepted` semantics + model/doc closure

| Item | Evidence |
|------|----------|
| Prerequisite-free projection | `INVITE_ACCEPTED_META.dep_fields: &[]`, `signer_required: false` (`src/event_modules/invite_accepted.rs:155-158`) |
| Force-valid workspace command emission | `EmitCommand::RetryWorkspaceEvent { workspace_id }` emitted (`src/event_modules/invite_accepted.rs:132`) |
| Standard apply + unblock cascade | `RetryWorkspaceEvent` handled via `project_one()` in `src/projection/apply/write_exec.rs:80-96` |
| No service-triggered bootstrap hacks | Service layer uses `bootstrap_sync_from_invite()` (real QUIC sync), not event copies |
| TLA conformance | `docs/tla/EventGraphSchema.tla`: `InviteAccepted` in `LocalRoots`, invariants `InvTrustAnchorImmutable`, `InvTrustAnchorSource`, `InvBootstrapTrustSource` |
| TLA conformance (bootstrap) | `docs/tla/EventGraphSchema.tla` + `docs/tla/event_graph_schema_bootstrap.cfg`: concrete bootstrap sequence modeled |
| Projector tests (pass/break) | `src/event_modules/invite_accepted_projector_tests.rs`: 5 tests covering SPEC_ANCHOR_IMMUTABLE, SPEC_ANCHOR_SOURCE, SPEC_BOOTSTRAP_TRUST |
| Integration test | `src/projection/apply/tests/mod.rs:3872`: `test_invite_accepted_guard_retry_on_workspace` |
| Runtime check catalog | `docs/tla/runtime_check_catalog.md`: CHK_IA_TRUST_ANCHOR_WRITE, CHK_IA_TRUST_ANCHOR_CONFLICT, CHK_IA_RETRY_GUARDS, CHK_IA_BOOTSTRAP_TRUST, CHK_IA_ANCHOR_SOURCE |
| Bootstrap/join tests | `two_process_test` and `cheat_proof_realism_test` failures are pre-existing on master (same QUIC connection-lost error), not regressions from this branch |

## Stage 3: Identity <-> transport boundary closure

| Item | Evidence |
|------|----------|
| Contract definition | `src/contracts/transport_identity_contract.rs`: `TransportIdentityIntent` enum + `TransportIdentityAdapter` trait |
| Sole materialization point | `src/transport/identity_adapter.rs`: `ConcreteTransportIdentityAdapter` — only code calling raw install functions |
| Event module usage | `src/event_modules/local_signer_secret.rs:139-144`: emits `ApplyTransportIdentityIntent` |
| Projection routing | `src/projection/apply/write_exec.rs:187-193`: routes through adapter |
| Service usage | `src/service.rs:1329-1337, 1466-1474`: uses adapter for identity intents, not raw calls |
| No raw install leaks | `scripts/check_boundary_imports.sh:56-62`: enforces no raw calls in service/event_modules/projection |
| Bootstrap sync contracts-only | `src/peering/workflows/bootstrap.rs`: imports only contracts + transport, no event_module internals |
| `svc_bootstrap_workspace_conn` | `src/service.rs:409-424`: thin wrapper over `identity::ops::bootstrap_workspace` (genesis operation, correctly in identity ops) |
| Tests | `tests/identity_transport_contract_tests/`: 11 passing tests (intent, projection path, fake adapter) |
| DESIGN.md updated | §2.2 "Transport identity materialization boundary" added |
| PLAN.md updated | §17.1.4.1 "Transport identity materialization contract" added |

## Stage 4: Docs consistency + TODO closure

| Item | Evidence |
|------|----------|
| Active docs vocabulary | Zero stale module paths/symbols in active docs (grep checks clean excluding archive) |
| Archive disclaimers | All archive docs have historical disclaimer blockquotes (35 docs including newly archived TODO4) |
| `docs/INDEX.md` superseded table | Updated with contract file renames and symbol renames |
| TODO.md items 1-22 | All marked DONE with evidence (items verified before this branch) |
| TODO.md items 23-26 | Verified: `user_event_id` in PeerShared, `finish()` panic, `svc_bootstrap_workspace_conn`, `start_peers_pinned` |
| This evidence matrix | `docs/planning/TODO_REMAINING_EVIDENCE.md` |
| Feedback doc | `feedback.md`: reviewed against instructions, 4 straggler comments fixed |
| Final audit | `codex_final_audit.md`: codex CLI review with corrected assessment |

## Quality gates

| Gate | Status |
|------|--------|
| `cargo check` | PASS |
| `bash scripts/check_boundary_imports.sh` | PASS |
| `cargo test --lib -q` | PASS (443 tests) |
| `cargo test --test sync_contract_tests -q` | PASS (21 tests) |
| `cargo test --test holepunch_test -q` | PASS (4 tests) |
| `cargo test --test identity_transport_contract_tests -q` | PASS (11 tests) |
| Mandatory grep check 1 (old crate paths in src/tests) | Zero hits |
| Mandatory grep check 2 (old paths in active docs) | Zero hits excluding archive; INDEX.md superseded table is reference material |
| Mandatory grep check 3 (old symbols in src/docs) | Zero hits in src; DESIGN.md "network layer" is generic networking term |

## Pre-existing issues (not regressions from this branch)

| Issue | Evidence |
|------|----------|
| `tests/cli_test.rs` compile error (`bind_port`) | Same error on master; pre-existing breakage |
| `test_two_process_invite_and_sync` QUIC connection lost | Same failure on master; pre-existing issue |
| `cheat_proof_realism_test` invite tests fail | Same failures on master; pre-existing issue |
| Instructions doc references `replication_contract_tests` | Test already renamed to `sync_contract_tests`; instructions doc is self-referential |
