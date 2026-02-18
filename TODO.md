# TODO: Design/Plan/Code Alignment Backlog (topo/master)

Date: 2026-02-15

Goal: track and close high-impact discrepancies between `docs/DESIGN.md`, `docs/PLAN.md`, TLA mappings, tests, and runtime code, while keeping behavior realistic and simplifying where possible.

## Cross-cutting rule: TLA/model alignment

For any TODO that changes protocol semantics, trust-source semantics, dependency/guard rules, or identity/key lifecycle behavior:

1. Update relevant TLA modules under `docs/tla/` (for example `EventGraphSchema.tla`, `TransportCredentialLifecycle.tla`, `BootstrapGraph.tla`) before Rust implementation changes.
2. Run TLC/model checks and confirm expected invariants/counterexamples before coding the semantic change.
3. Implement Rust changes to match the validated model.
4. Update `docs/tla/projector_spec.md` mapping rows and any DESIGN/PLAN invariant lists.
5. Add or adjust model-check CI/test invocation for the changed model scope.

## Cross-cutting rule: POC replacement policy (no backward compatibility)

This repository is a POC. For protocol/runtime simplification work:

1. Do not carry dual-read, dual-write, compatibility windows, or legacy shadow paths.
2. Each round ends with old behavior/code paths removed, not just deprecated.
3. Update tests/docs/TLA mappings in the same round so one canonical behavior remains.
4. If old persisted state cannot be represented after a change, fail fast and require recreation rather than adding compatibility layers.

## Cross-cutting rule: test gate and coverage requirements

For every stage of work in this TODO:

1. The stage is not complete until tests pass on the branch (`cargo test` and required scenario/integration suites for touched areas).
2. Any behavior change, bug fix, or semantic change must include new or updated tests in the same stage.
3. Pure refactors may skip new tests only when existing coverage already exercises the changed paths and all tests remain green.
4. Do not defer required tests to a later TODO item.

## Recommended execution order (dependency-driven)

Realism-first rule for ordering: finish test-fidelity items up front (copying events, direct DB seeding, static pinning overlays, and optional invariant checks) so downstream refactors are validated by realistic tests.

1. ~~`P0: Remove copy_event_chain from interactive invite acceptance`~~ **DONE**: `copy_event_chain` deleted; interactive and CLI invite acceptance now use real QUIC bootstrap sync via `svc_accept_invite` / `bootstrap_sync_from_invite`. Two-process integration test validates end-to-end. See PLAN.md §2.2 "CLI Isomorphism Principle".
2. ~~`P1: Replace prerequisite event copy in Peer::new_in_workspace`~~ **DONE**: `new_in_workspace` now uses real QUIC bootstrap sync via `svc_accept_invite` + temp sync endpoint. No direct `insert_event`/`insert_recorded_event` calls remain in the join path. Joiner DB starts empty (no transport identity); invite-derived identity installed by service layer. Holepunch and scenario tests pass with realistic bootstrap.
3. ~~`P1: Stop direct SQL trust seeding in CLI invite-bootstrap test`~~ **DONE**: CLI bootstrap tests now use production invite create/accept flow; direct trust-row seed helpers were removed from active CLI test paths.
4. ~~`P1: Remove manual endpoint observation writes in hole-punch integration test`~~ **DONE**: hole-punch integration now derives endpoint observations from organic sync traffic (no manual endpoint DB seeding in the test flow).
5. ~~`P2: Align test transport setup with production dynamic trust lookup`~~ **DONE**: realism-sensitive suites use dynamic DB trust lookup helpers; remaining static pinning cases are explicitly annotated as pinning-boundary tests in scenario/hole-punch coverage.
6. ~~`P1: Deprecate --pin-peer from product code and design after invite-trust maturity`~~ **DONE**: `--pin-peer` removed from product sync CLI/runtime trust authority; residual references are test-plan/archival artifacts only.
7. ~~`P0: Make scenario replay invariants mandatory by default (opt-out only)`~~ **DONE**: scenario tests now go through mandatory `ScenarioHarness` replay checks unless explicitly skipped.
8. ~~`P0: Bring scenario invariant harness fully in line with PLAN (fingerprints + full invariant set)`~~ **DONE**: deterministic full-state fingerprint replay checks are now active for forward/idempotent/reverse/shuffled replay paths, with mandatory ScenarioHarness replay verification by default.
9. ~~`P1: Investigate and decide create_event_sync service semantics before implementation changes`~~ **DONE**: strict `create_event_sync` and bootstrap-only `create_event_staged` semantics are explicitly captured in PLAN §6.4 and covered by contract tests (`test_create_event_sync_contract_valid_only`, `test_create_event_sync_contract_blocked_returns_err_with_event_id`).
10. ~~`P1: Investigate simplification of project_one/project_one_core split to better match one-path intent`~~ **DONE**: Investigated and resolved. Decision: keep two-layer model (`project_one` public entrypoint + `project_one_step` internal non-cascading step) as justified cascade optimization. Renamed `project_one_core` → `project_one_step` with clear doc comments. Added 7 source-isomorphism invariance tests proving direct/cascade/reverse-order convergence. Updated DESIGN.md §4.1, PLAN.md §5/§15.1, and TLA projector_spec.md to explicitly document the internal split.
11. ~~`P0: Unify transport identity architecture (single event-derived peer identity, no rotation sidecar)`~~ **DONE**: single event-derived identity authority is canonical. `transport_key` removed as trust authority; transport allow/deny now uses PeerShared-derived SPKIs + bootstrap trust only. No rotation sidecar, no silent regeneration. TLA models (`EventGraphSchema`, `TransportCredentialLifecycle`) rewritten and verified. DESIGN/PLAN/projector_spec aligned.
12. ~~`P2: Resolve disjoint trust sets docs/code mismatch`~~ **DONE**: docs now match code semantics (tenant-scoped trust checks with permitted cross-tenant SPKI overlap).
13. ~~`P0: Enforce removal policy at transport runtime (deny + disconnect active sessions)`~~ **DONE**: runtime now checks removal state in sync loops and closes active sessions for removed peers.
14. ~~`P0: Unify bootstrap key distribution via invite-key wrap/unwrap (keep local secret_key dep)`~~ **DONE**: invite create/accept uses canonical wrap→unwrap flow (`secret_shared` targeted to invite key + deterministic local `secret_key` materialization). Out-of-order bootstrap tests cover SecretShared signer blocking, encrypted key-dep blocking/unblocking, deterministic key event ID convergence, and full wrap→unwrap→encrypt convergence. TLA model, projector_spec, DESIGN, and PLAN all updated to describe unified bootstrap/runtime wrap path. No raw PSK bootstrap input remains.
15. ~~`P1: Collapse encrypted-inner projection onto the same dependency/signer engine stages`~~ **DONE**: encrypted-inner and cleartext share one dep/signer/dispatch stage helper (`run_dep_and_projection_stages`), and DESIGN/PLAN/TLA mapping docs now explicitly record the decrypted-inner dep-type-check exception rationale.
16. ~~`P0: Re-impose fixed-length event fields + langsec parser model`~~ **DONE**: canonical event parsers now enforce fixed wire sizes (including encrypted-size-by-inner-type), no canonical parser uses in-event length/count fields, and fixed-layout/no-length guard suites are green (`fixed_layout_tests`, `wire_no_length_fields_guard_test`).
17. ~~`P1: Remove duplicated command/business logic between CLI (main.rs) and service layer (service.rs)`~~ **DONE**: core CLI command flows route through service-layer APIs; remaining REPL-specific cleanup is tracked separately in item 21.
18. ~~`P1: Eliminate direct SQL access in CLI command paths where module APIs already exist`~~ **DONE (CLI)**: direct SQL was removed from standard CLI command paths; remaining REPL/internal helper SQL cleanup is tracked under item 21.
19. ~~`P1: Reconcile TLA/spec mapping docs with PLAN and implemented projector semantics`~~ **DONE**: event-registry/dependency mapping rows refreshed; transport-credential lifecycle naming/model terms unified with item 11 architecture. TLC checks green for all models. No known stale mapping rows remain.
20. ~~`P2: Remove residual compatibility cruft from active schema/docs/runtime surfaces`~~ **DONE**: `ingress_queue` removed from DESIGN queue listing, removed from `rename_peer` loop, and dropped from schema in migration 28 (unused, no runtime path); migration 12 no-op comment removed; migration 20 duplicate name fixed; `legacy_cli_*` tests renamed to `cli_direct_*`; "backward compat parsing" comment removed from scenario test; PLAN.md references updated.
21. ~~`P1: CLI isomorphism — route remaining interactive commands through service layer`~~ **DONE**: all interactive REPL commands now route through service-layer APIs. Zero direct SQL (`rusqlite::prepare`/`query_row`/`execute`) remains in interactive.rs. New service functions: `svc_message_event_id_by_num_conn`, `svc_deleted_message_ids_conn`, `svc_reactions_for_message_conn`, `svc_remove_user_conn`, `svc_create_invite_conn`, `svc_create_device_link_invite_conn`. REPL retains only UX affordances (numeric aliases, author name display, channel labels).
22. ~~`P2: Single-port multi-tenant endpoint — share one UDP port across tenants on the same device`~~ **DONE**: node now runs a single shared QUIC endpoint with multi-workspace cert resolution and per-tenant outbound isolation checks.

## Newly opened follow-up items (2026-02-18)

23. `P0: Enforce user_removed transitive transport deny + disconnect` **DONE**: Added `user_event_id: [u8; 32]` to PeerShared events (170B wire format), migration 29, transitive user removal in trust queries and removal watch.
24. `P1: Close ScenarioHarness implicit bypass (new-without-track)` **DONE**: `finish()` now panics on zero tracked subjects; two tests switched to `ScenarioHarness::skip()`.
25. `P1: Route interactive new-workspace through service layer` **DONE**: Added `svc_bootstrap_workspace_conn` to service.rs; `cmd_new_workspace` now routes through it.
26. `P2: Remove residual trust-bootstrap shortcuts from realism helpers` **DONE**: `start_peers` renamed to `start_peers_pinned` (annotated as PINNING BOUNDARY); new `start_peers` for same-workspace peers without CLI pin seeding; mDNS tests use `new_in_workspace` for invite-based trust instead of `import_cli_pins_to_sql`.

## ~~P0: Re-impose fixed-length event fields + langsec parser model~~ DONE

Evidence: current docs explicitly allow variable event payloads (`docs/DESIGN.md:60`, `docs/DESIGN.md:61`, `docs/PLAN.md:305`, `docs/PLAN.md:314`), and these event types currently parse variable-length payloads:

1. `message` (`content_len`): `src/events/message.rs:20`, `src/events/message.rs:50`
2. `reaction` (`emoji_len`): `src/events/reaction.rs:20`, `src/events/reaction.rs:48`
3. `signed_memo` (`content_len`): `src/events/signed_memo.rs:18`, `src/events/signed_memo.rs:43`
4. `encrypted` (`ciphertext_len`): `src/events/encrypted.rs:20`, `src/events/encrypted.rs:48`
5. `file_slice` (`ciphertext_len`): `src/events/file_slice.rs:25`, `src/events/file_slice.rs:54`
6. `message_attachment` (`filename_len` + `mime_len`): `src/events/message_attachment.rs:31`, `src/events/message_attachment.rs:90`
7. `bench_dep` (`dep_count`-driven variable list): `src/events/bench_dep.rs:14`, `src/events/bench_dep.rs:34`

Problem: variable-length canonical parsing increases grammar complexity and parser state, expands edge-case surface (length-prefix inconsistencies, truncation/tail ambiguities), and conflicts with a strict langsec posture for canonical event parsing.

Fix:

1. Update spec to require fixed-length canonical event fields:
   - `docs/DESIGN.md`: replace variable-field guidance with fixed-size schema requirement for canonical events.
   - `docs/PLAN.md`: remove `var_bytes`/`var_string` as canonical field kinds; keep fixed transport frame delimiter only.
2. Define fixed-layout replacements for all variable event types above (new type codes / versioned layouts), with explicit per-field byte budgets and deterministic padding/canonicalization rules.
3. Parser simplification (langsec-first):
   - table-driven fixed offsets and exact total-size checks,
   - no parser control flow driven by untrusted length prefixes for canonical event body layout,
   - strict zero-padding and canonical UTF-8 constraints where text is represented in fixed byte slots.
4. POC cutover plan:
   - land fixed-layout schemas/parsers/emitters,
   - remove variable-layout canonical parser/emitter paths in the same round,
   - update fixtures/tests to only the new canonical layouts.
5. Verification hardening:
   - add per-type fixed-size golden-byte tests,
   - add negative tests for truncation, trailing bytes, non-zero padding, and malformed text slots,
   - add parser fuzz/property tests that enforce single canonical decode per blob.
6. TLA/model alignment:
   - update model/docs boundaries to explicitly reflect what is modeled (event-graph semantics) vs parser-wire canonicalization checks,
   - update `docs/tla/projector_spec.md` and DESIGN/PLAN invariants/boundaries so parser hardening requirements are not left implicit.

Acceptance:

1. `docs/DESIGN.md` and `docs/PLAN.md` explicitly require fixed-length canonical event fields.
2. No canonical event parser in `src/events/` computes body boundaries from variable length prefixes.
3. All currently variable canonical event types have fixed-layout successors with tests.
4. Parser test suite demonstrates strict reject behavior for non-canonical encodings and malformed padding.
5. TLA/projector mapping docs are updated to match the new canonical-format assumptions and boundaries.

## ~~P1: Collapse encrypted-inner projection onto the same dependency/signer engine stages~~ DONE

Completed:

1. Cleartext and decrypted-inner events now run through one shared stage helper:
   - `src/projection/pipeline.rs`: `run_dep_and_projection_stages(...)`
   - `src/projection/encrypted.rs`: wrapper-specific decrypt/admissibility only, then shared stage call.
2. Block/reject semantics remain outer-event anchored for encrypted wrappers.
3. Docs now explicitly describe the shared-stage model and decrypted-inner dep-type-check exception rationale:
   - `docs/tla/projector_spec.md`
   - `docs/DESIGN.md` §6.2
   - `docs/PLAN.md` §7.4

Verification:

1. Projection pipeline tests remain green after refactor.
2. Fixed-layout/no-length guard suites remain green.

## ~~P0: Unify bootstrap key distribution via invite-key wrap/unwrap (keep local `secret_key` dep)~~ DONE

Completed:

1. Local-only `secret_key` dependency model retained for encrypted payload decryption (type-6 local dep unchanged).
2. No raw PSK bootstrap input paths remain in runtime code (CLI/service/invite-link).
3. Invite create/accept uses canonical `secret_shared` wrap→unwrap flow:
   - inviter wraps content key to invite public key (X25519 DH + BLAKE2b-256 + XOR),
   - joiner unwraps with invite private key and materializes local `secret_key` events.
4. Deterministic key event IDs: BLAKE2b of key bytes → `created_at_ms`, ensuring both parties derive identical `key_event_id` values.
5. Out-of-order bootstrap tests in `tests/scenario_test.rs`:
   - `test_secret_shared_blocks_until_signer_valid`: SecretShared blocks on missing signer dep, unblocks after identity cascade.
   - `test_encrypted_blocks_then_unblocks_on_key_materialization`: encrypted blocks on key dep, key-dep resolves after deterministic key materialization.
   - `test_deterministic_key_event_id_matches_across_peers`: deterministic key event IDs match across inviter/joiner.
   - `test_wrap_unwrap_encrypted_convergence`: full wrap→unwrap→encrypt flow with key convergence verification.
6. TLA model updated: `EventGraphSchema.tla` comments clarify bootstrap vs runtime SecretShared usage. TLC verified (177007 states, no errors).
7. Docs updated: DESIGN.md §9.4.1 (bootstrap key distribution), §2.4.1 (accept key unwrap); PLAN.md §7.6 (test strategy), §11.4.1 (bootstrap flow), §11.5 (sender-keys model); projector_spec.md (SecretShared wire format notes, bootstrap key materialization section).

## ~~P0: Unify transport identity architecture (single event-derived peer identity, no rotation sidecar)~~ DONE

Completed:

1. TLA models rewritten:
   - `TransportCredentialLifecycle.tla`: rotation/revocation removed; 4 variables, 7 actions, 6 invariants for single-credential model.
   - `EventGraphSchema.tla`: `transportKeyCarriedPeer`/`transportKeyTrustPeer` → `peerSharedDerivedPeer`/`peerSharedTrustPeer`; all invariants renamed; `InvPendingBootstrapTrustConsumedByPeerShared` added.
   - TLC verified: EventGraphSchema (177007 states), TransportCredentialLifecycle (3450001 states), no errors.
2. Runtime trust authority unified:
   - `transport_key` removed as trust source from `allowed_peers_from_db`, `is_peer_allowed`, `trusted_peer_count`, `has_any_trusted_peer`.
   - Trust union: PeerShared-derived SPKIs ∪ invite_bootstrap_trust ∪ pending_invite_bootstrap_trust.
   - Bootstrap supersession uses PeerShared-derived SPKI matching.
3. Identity bootstrap simplified:
   - `transport_key_event_id` removed from `IdentityChain`/`JoinChain`/`LinkChain`.
   - `create_transport_key_if_possible` and `ensure_transport_key_event` removed entirely.
4. Docs updated: DESIGN.md, PLAN.md, projector_spec.md all aligned to single-authority model.
5. All tests green (61 scenario, 21 transport_trust, 18 interactive, 2 low_mem).

## ~~P0: Remove `copy_event_chain` from interactive invite acceptance~~ DONE

Evidence: `src/interactive.rs:905`, `src/interactive.rs:1049`, `src/interactive.rs:1629`.

Problem: `accept-invite` and `accept-link` currently copy shared events directly between DBs before acceptance. This bypasses network sync and can leak all already-shared workspace state instantly.

Fix:

1. Delete `copy_event_chain` usage from invite acceptance paths.
2. Add a real bootstrap sync step in interactive mode (from invite link `bootstrap_addr` + bootstrap trust rows) before calling `accept_user_invite`/`accept_device_link`.
3. If prerequisite invite/workspace events are still missing, fail with a clear "sync first" error.

Acceptance:

1. No direct event-copy call remains in interactive invite acceptance paths.
2. `tests/interactive_test.rs` no longer validates copied-event behavior (`test_copy_event_chain_shared_only` should be removed/replaced).

## ~~P1: Stop direct SQL trust seeding in CLI invite-bootstrap test~~ DONE

Evidence: `tests/cli_test.rs:134`, `tests/cli_test.rs:160`, `tests/cli_test.rs:404`.

Problem: the CLI bootstrap trust test inserts `invite_bootstrap_trust` and `pending_invite_bootstrap_trust` rows directly, skipping the real invite flow.

Fix:

1. Replace `seed_invite_bootstrap_trust`/`seed_pending_invite_bootstrap_trust` with a real flow that creates and accepts an invite link.
2. If needed, add non-interactive CLI commands for invite create/accept so tests can stay process-based without direct DB writes.

Acceptance:

1. `tests/cli_test.rs` no longer calls direct trust-row seed helpers.
2. Invite-bootstrap sync test passes through production invite APIs or CLI commands only.

## ~~P1: Replace prerequisite event copy in `Peer::new_in_workspace`~~ DONE

Evidence: `src/testutil.rs:140`, `src/testutil.rs:157`, `src/testutil.rs:169`.

Problem: `Peer::new_in_workspace` currently copies workspace/invite events DB-to-DB before `accept_user_invite`, which is not a real network join.

Fix:

1. Update `new_in_workspace` to fetch prerequisite events through a real sync session.
2. Keep identity operations (`create_user_invite`, `accept_user_invite`) but remove direct event insertion and projection from this path.

Acceptance:

1. `new_in_workspace` contains no `insert_event`/`insert_recorded_event` calls.
2. Hole-punch and other same-workspace integration tests still pass with real sync bootstrap.

## ~~P0: Make scenario replay invariants mandatory by default (opt-out only)~~ DONE

Evidence:

1. Replay invariant helpers already exist (`src/testutil.rs:951`, `src/testutil.rs:956`, `src/testutil.rs:1047`) and cover:
   - simple replay,
   - replay idempotency (double replay),
   - reverse-order replay (reordering stress).
2. `tests/scenario_test.rs` invokes replay checks manually/optionally instead of through one mandatory harness path.
3. Plan text calls replay checks a required baseline and warns against optional/manual usage (`docs/PLAN.md:439`, `docs/PLAN.md:1188`, `docs/PLAN.md:1323`).

Problem: replay correctness checks are not guaranteed to run for every scenario test, so determinism and ordering/idempotency regressions can slip through depending on test author discipline.

Fix:

1. Move replay checks into the shared scenario harness so they run automatically for scenario tests by default.
2. Required default replay suite per scenario:
   - one-pass replay from canonical event order,
   - second-pass replay on the same stream (idempotency),
   - reverse-order replay (reordering robustness).
3. Add explicit per-test opt-out only, with a required short rationale string (for example unsupported fixture shape or intentionally partial graph).
4. Remove duplicated manual replay-check calls from scenario tests once harness default is in place.
5. Add a guard test/check that fails when new scenario tests bypass replay invariants without explicit opt-out.

Acceptance:

1. Scenario tests run replay invariants by default without per-test boilerplate.
2. Any omitted replay coverage is explicit and justified in the test definition.
3. `tests/scenario_test.rs` no longer relies on ad-hoc optional replay calls for baseline coverage.

## ~~P1: Remove manual endpoint observation writes in hole-punch integration test~~ DONE

Evidence: `tests/holepunch_test.rs:296`, `tests/holepunch_test.rs:303`, `tests/holepunch_test.rs:307`.

Problem: test injects `peer_endpoint_observations` directly to make intro runnable on new endpoint addresses.

Fix:

1. Capture endpoint observations via real accepted connections instead of writing DB rows directly.
2. Ensure introducer sends intro based on observed addresses from runtime traffic only.

Acceptance:

1. No direct `record_endpoint_observation` calls in `tests/holepunch_test.rs`.
2. Intro happy-path still passes end-to-end.

## ~~P2: Align test transport setup with production dynamic trust lookup~~ DONE

Completed:

1. Shared test helpers now use production-matching dynamic trust (`is_peer_allowed`) for common sync topologies:
   - `src/testutil.rs` dynamic endpoint helpers (`create_dual_endpoint_dynamic` / tenant-scoped lookup).
2. Realism-sensitive suites run through dynamic trust paths by default.
3. Residual static pinning coverage is explicitly marked as intentional policy-boundary testing:
   - `tests/holepunch_test.rs` (stale/untrusted intro boundary cases),
   - `tests/scenario_test.rs` (tenant cert presentation and tenant-scoped outbound rejection).

## ~~P1: Deprecate `--pin-peer` from product code and design after invite-trust maturity~~ DONE

Evidence: `--pin-peer` remains a first-class CLI surface (`src/main.rs:53`, `src/main.rs:184`, `src/main.rs (daemon start)`), runtime guidance still points users to it (`src/main.rs:984`, `src/service.rs:1002`), and design still documents it as an overlay (`docs/DESIGN.md:117`).

Problem: retaining `--pin-peer` as a normal operational path undermines the event-derived trust model and keeps manual transport trust bootstrapping in the critical path after invite/bootstrap workflows are available.

Fix:

1. Define ordering gate:
   - keep `--pin-peer` only until invite create/accept + first sync are reliable end-to-end.
2. Once gate is met, remove from steady-state code path in the same round:
   - stop merging CLI pins into transport trust resolution by default,
   - make SQL/event-derived trust the sole default authority.
3. Final removal:
   - remove `--pin-peer` flags from primary commands and daemon entrypoints,
   - keep any explicit pinning behavior only in narrow transport-policy test utilities or a clearly scoped debug-only command.
4. Design/doc update:
   - update `docs/DESIGN.md` and `docs/PLAN.md` to state invite/event-derived trust is normative and manual pin overlays are non-normative bootstrap-only paths removed from steady-state product behavior.
5. TLA/model alignment:
   - if CLI pinning is removed from normative runtime semantics, update model boundary notes and mapping docs to reflect that (including any prior "modeled only in Rust" caveats).

Acceptance:

1. Main user/daemon sync flows no longer require or advertise `--pin-peer`.
2. Invite bootstrap and post-invite sync tests pass without CLI pin overlays.
3. `docs/DESIGN.md` and `docs/PLAN.md` no longer present `--pin-peer` as a normal steady-state mechanism.
4. TLA/model boundary/mapping docs reflect the post-deprecation trust-source story.

## ~~P2: Resolve "disjoint trust sets" docs/code mismatch~~ DONE

Evidence:

1. `docs/DESIGN.md:300` states: tenants in different workspaces have disjoint trust sets.
2. Runtime trust lookup is tenant-scoped by `recorded_by`, not globally disjoint by fingerprint value:
   - `src/db/transport_trust.rs:221` (`allowed_peers_from_db`)
   - `src/db/transport_trust.rs:256` (`is_peer_allowed`)
3. DB schema allows same SPKI in multiple tenants' trust rows (keys/indexes are scoped by `recorded_by`):
   - `src/db/migrations.rs:268` (`transport_keys`)
   - `src/db/migrations.rs:392` (`invite_bootstrap_trust`)
   - `src/db/migrations.rs:410` (`pending_invite_bootstrap_trust`)

Problem: design text currently claims a stronger property than the implementation guarantees. This can mislead reviewers and future hardening work.

Fix:

1. Decide intended policy:
   - `A` (likely): tenant trust checks are isolated by `recorded_by`, but trust-set value overlap across tenants is allowed.
   - `B`: strict value-level disjointness across different-workspace tenants is required.
2. If `A`: update `docs/DESIGN.md` wording at section 3.2.1 to remove "disjoint trust sets" claim and describe scoped-lookup semantics precisely.
3. If `B`: add enforcement + tests:
   - schema and/or projector constraints preventing SPKI overlap across different-workspace tenants,
   - invariant tests that fail on cross-workspace trust-set overlap.
4. TLA/model alignment:
   - if policy `B` is chosen, add explicit disjointness invariants in trust models;
   - if policy `A` is chosen, ensure model/docs explicitly state overlap-allowed + tenant-scoped authorization semantics.

Acceptance:

1. Docs match implemented semantics exactly (or implementation is upgraded to match docs).
2. A test exists for the chosen policy (overlap-allowed behavior or strict-disjoint rejection behavior).
3. TLA invariants and mapping docs encode the chosen policy unambiguously.

## ~~P0: Enforce removal policy at transport runtime (deny + disconnect active sessions)~~ DONE

Evidence:

1. Design/plan require removal to affect trust runtime semantics:
   - `docs/DESIGN.md:770` ("peer_removed cascades trust removal"),
   - `docs/PLAN.md:1131` (transport lifecycle includes trust removal).
2. Runtime transport allow checks currently read trust tables only:
   - `src/db/transport_trust.rs:221` (`allowed_peers_from_db`),
   - `src/db/transport_trust.rs:256` (`is_peer_allowed`).
3. Identity projector currently records removals but does not perform trust/source/session teardown:
   - `src/projection/identity.rs:221` (`user_removed` -> `removed_entities`),
   - `src/projection/identity.rs:236` (`peer_removed` -> `removed_entities`).

Problem: after a removal event projects, removed peers/users may remain transport-authorized by existing trust rows and active sessions can continue, violating expected removal enforcement semantics.

Fix:

1. Define and implement removal closure per tenant:
   - direct peer target for `peer_removed`,
   - user target expansion for `user_removed` (all currently authorized peer identities linked to removed user identity).
2. Apply closure to transport trust runtime:
   - supersede/remove matching entries from `transport_keys`, `invite_bootstrap_trust`, and `pending_invite_bootstrap_trust` (or enforce an equivalent deny overlay in lookup path).
3. Enforce immediate runtime behavior:
   - deny new handshakes for removed peers from first post-removal check,
   - disconnect existing active sessions for removed peers,
   - cancel/deny related intro/hole-punch attempts.
4. Add integration tests:
   - "allowed before removal, denied after removal",
   - "active sync session is terminated after removal is observed",
   - same checks for `user_removed` transitive peer closure.
5. TLA/model alignment:
   - extend/update transport lifecycle model and mapping rows so removal semantics include both trust-source exclusion and runtime deny behavior.

Acceptance:

1. Removed peers cannot authenticate after removal projection for that tenant.
2. Existing sessions with removed peers are torn down promptly.
3. Removal semantics are covered for both `peer_removed` and `user_removed`.
4. TLA/model docs match runtime behavior.

## ~~P0: Bring scenario invariant harness fully in line with PLAN (fingerprints + full invariant set)~~ DONE

Evidence:

1. PLAN requires deterministic table-state fingerprints and full replay/reproject/reorder checks:
   - `docs/PLAN.md:439`,
   - `docs/PLAN.md:451`,
   - `docs/PLAN.md:1188`,
   - `docs/PLAN.md:1200`.
2. Current helper checks only selected table counts:
   - `src/testutil.rs:1047` (`verify_projection_invariants`),
   - count-based comparisons at `src/testutil.rs:1051`-`src/testutil.rs:1114`.

Problem: count-only checks can miss state regressions where row contents differ but aggregate counts stay equal; harness also does not yet encode the full PLAN 12.4 invariant set in one standard path.

Fix:

1. Add deterministic tenant-scoped table-state fingerprinting helper(s) for canonical projected state (excluding operational queues).
2. Upgrade scenario invariants to compare fingerprints for:
   - replay once,
   - replay twice (idempotency),
   - reverse-order replay,
   - reproject from canonical store,
   - reorder/out-of-order ingest convergence.
3. Fold into the default scenario harness path (paired with explicit opt-out mechanism from the existing replay-default TODO).
4. Add failing-then-passing regression tests proving fingerprint checks catch state-content divergence missed by count-only checks.

Acceptance:

1. Scenario invariants use deterministic state fingerprints, not count-only comparisons.
2. Standard harness covers PLAN 12.4 checks in default flow.
3. Per-test opt-out remains explicit and justified.

## ~~P1: Investigate and decide `create_event_sync` service semantics before implementation changes~~ DONE

Decision and closure:

1. Keep two explicit create APIs with distinct contracts:
   - `create_event_sync`: strict user-facing contract, success only on `Valid`/`AlreadyProcessed`.
   - `create_event_staged`: bootstrap-only helper that preserves blocked event ids.
2. PLAN now captures this split explicitly (`docs/PLAN.md` §6.4).
3. Contract tests are present and green:
   - `src/projection/create.rs`: `test_create_event_sync_contract_valid_only`
   - `src/projection/create.rs`: `test_create_event_sync_contract_blocked_returns_err_with_event_id`

## ~~P1: Reconcile TLA/spec mapping docs with PLAN and implemented projector semantics~~ DONE

Completed:

1. Event-registry and dependency mapping rows refreshed to match runtime semantics.
2. Shared encrypted-inner pipeline mapping and rationale documented.
3. Transport-credential lifecycle naming/model terms unified with item-11 architecture:
   - `InvBootstrapTrustConsumedByTransportKey` → `InvBootstrapTrustConsumedByPeerShared`
   - `InvTransportKeyTrustSource` → `InvPeerSharedTrustSource`
   - `InvTransportKeyTrustMatchesCarried` → `InvPeerSharedTrustMatchesCarried`
   - Added `InvPendingBootstrapTrustConsumedByPeerShared`
   - Removed stale rotation/revocation invariants from projector_spec.md
4. TLC checks green for all models (EventGraphSchema + TransportCredentialLifecycle).
5. DESIGN.md / PLAN.md references updated where mapping names changed.

Acceptance met:
1. No known stale rows remain in mappings. ✓
2. TLC/model checks pass. ✓
3. Transport lifecycle naming unified with item-11 architecture. ✓

## ~~P1: Remove duplicated command/business logic between CLI (`main.rs`) and service layer (`service.rs`)~~ DONE

Evidence:

1. Command/business flows are implemented in both places (for example identity bootstrap, send/react/delete/status/assert paths):
   - `src/main.rs`
   - `src/service.rs`
2. This duplication has already produced behavior-shape divergence risks (for example create semantics wrappers and differing helper patterns).

Problem: maintaining parallel command logic increases drift risk, review overhead, and bug-fix fanout. It also weakens confidence that CLI and daemon/control-plane behavior are identical.

Fix:

1. Define one canonical command/business layer (service/application module) as the only owner of command semantics.
2. Make CLI entrypoints thin adapters:
   - parse args,
   - apply CLI-only frontend affordances (for example number-alias resolution for message/invite references and other UX shorthands),
   - call canonical service functions for business semantics,
   - render output.
3. Remove duplicated business logic from `main.rs` once parity tests pass.
4. Add parity tests ensuring CLI command behavior matches service API behavior for key flows while preserving CLI affordances.

Acceptance:

1. No duplicated command semantics remain between `src/main.rs` and `src/service.rs`.
2. CLI path and service/API path share one business implementation per command, with CLI affordances limited to input/output adaptation.
3. Regression tests cover CLI/service parity for core commands.

## ~~P1: Eliminate direct SQL access in CLI command paths where module APIs already exist~~ DONE

Evidence:

1. CLI/service command handlers still perform direct DB queries/updates for business behavior in multiple places instead of consistently routing through dedicated domain modules (identity/projection/trust/query helpers).
2. Existing architecture intent favors command/query helpers and event/projection modules as semantic boundaries.

Problem: direct SQL in command handlers bypasses domain boundaries, duplicates query semantics, and makes future schema/projection changes harder and riskier.

Fix:

1. Audit CLI/service command handlers for direct SQL that can be replaced by existing APIs in:
   - `src/identity_ops.rs`,
   - `src/projection/*`,
   - `src/db/*` query helpers,
   - service-layer command/query helpers.
2. Introduce missing command/query helpers where needed, then migrate command handlers to use them.
3. Reserve inline SQL in CLI/service only for narrow glue/telemetry cases with explicit justification.
4. Add lint/check or code-review guardrails to prevent reintroduction of ad-hoc command-layer SQL.
5. Keep CLI convenience affordances (for example numeric aliases) by resolving them through owned query helpers rather than ad-hoc SQL in command handlers.

Acceptance:

1. Command paths do not embed business-critical SQL when an owned module API exists.
2. Query semantics used by CLI (including convenience alias resolution) are centralized in reusable helpers/modules.
3. Future schema updates require changes in one query owner, not N command handlers.

## ~~P2: Remove residual compatibility cruft from active schema/docs/runtime surfaces~~ DONE

Completed:

1. `ingress_queue` removed from DESIGN.md operational queue listing.
2. `ingress_queue` removed from `rename_peer` loop in `src/db/mod.rs` and from `excluded_tables` in testutil.rs.
3. `ingress_queue` dropped from active schema via migration 28 (`drop_unused_ingress_queue`).
4. Migration 12 no-op comment ("Historical no-op kept to preserve migration numbering") removed.
5. Migration 20 name fixed from duplicate `add_intro_attempts` to `add_intro_attempts_index`.
6. `legacy_cli_send_and_status` / `legacy_cli_assert_now` renamed to `cli_direct_send_and_status` / `cli_direct_assert_now` with section header updated to "Direct CLI commands".
7. "backward compat parsing" comment removed from `test_transport_key_projects_without_auto_binding`.
8. PLAN.md references updated to remove active `ingress_queue` usage and note removal.
9. Earlier round: `drop_retired_compat_tables` → `drop_retired_tables`, cert-resolver fallback comments updated, `test_legacy_peer_key_blob_rejected` → `test_retired_type3_peer_key_blob_rejected`.

## ~~P1: Investigate simplification of `project_one`/`project_one_core` split to better match one-path intent~~ DONE

Investigation completed. Decision: keep two-layer model with documentation alignment.

Findings:
1. `project_one` (pub) is the sole public entrypoint — all external callers use it.
2. `project_one_core` (now renamed `project_one_step`, private) is only used within `cascade_unblocked_inner` Phase 1 (Kahn worklist).
3. The split is a justified cascade optimization: Phase 1 uses `project_one_step` to avoid redundant recursive cascade (it manages its own worklist); Phase 2 guard retries use `project_one` for proper recursive cascade.
4. No semantic divergence exists — all projection stages (dep check, type check, signer verify, projector dispatch) are shared.

Resolution:
- Renamed `project_one_core` → `project_one_step` with clear doc comments explaining the relationship.
- Added 7 source-isomorphism invariance tests proving direct/cascade/reverse-order convergence for message, reaction, encrypted, deletion, and multi-event chains.
- Updated DESIGN.md §4.1, PLAN.md §5/§15.1, and TLA projector_spec.md to document the internal two-layer model as a justified optimization.

All acceptance criteria met:
1. Investigation note captures rationale and options. ✓
2. Chosen direction is explicit: documented boundary (not refactor). ✓
3. Docs and code are aligned after implementation. ✓

## P0: Enforce `user_removed` transitive transport deny + disconnect

Evidence:

1. `user_removed` projection currently only records `removed_entities` (`src/projection/identity.rs:221`).
2. Trust checks exclude removed peers by `target_event_id = peers_shared.event_id` only (`src/db/transport_trust.rs:225`).
3. Active-session teardown checks also resolve only removed peer identities (`src/db/removal_watch.rs:20`, `src/sync/engine.rs:1256`, `src/sync/engine.rs:1465`).

Problem: removal enforcement is complete for direct `peer_removed`, but not for `user_removed` transitive closure across linked peer identities.

Fix:

1. Define user-removal closure in runtime terms: if a `user_removed` target is present, all corresponding active/trusted peer identities for that user become denied.
2. Apply closure in both trust lookup and active-session teardown paths.
3. Add integration coverage:
   - allowed before removal, denied after `user_removed`,
   - active sync session terminated after `user_removed`,
   - both single-tenant and shared-endpoint multi-tenant routing paths.
4. Update TLA and mapping docs before Rust semantics changes:
   - `docs/tla/EventGraphSchema.tla`,
   - `docs/tla/TransportCredentialLifecycle.tla`,
   - `docs/tla/projector_spec.md`,
   - matching DESIGN/PLAN invariant text.

Acceptance:

1. `user_removed` denies new transport auth for all covered peer identities.
2. Existing sessions for covered peers are closed promptly.
3. Tests prove both direct and transitive removal behavior.
4. TLA/model/docs and runtime behavior are aligned.

## P1: Close ScenarioHarness implicit bypass (`new()` without `track`)

Evidence:

1. Replay checks run only for tracked peers/nodes (`src/testutil.rs:2287`).
2. Some tests use `ScenarioHarness::new()` with no `track(...)`, so replay checks are skipped implicitly (`tests/scenario_test.rs:3777`, `tests/scenario_test.rs:3874`).

Problem: this bypasses the "mandatory by default (opt-out only)" requirement without explicit skip rationale.

Fix:

1. Enforce harness contract: `ScenarioHarness::new()` must fail on `finish()` when no subjects were tracked.
2. Keep `ScenarioHarness::skip(reason)` as the only explicit opt-out.
3. Extend the scenario guard test to catch `new()`-without-track usage.
4. Update PLAN/DESIGN testing text if any wording currently implies weaker guarantees.

Acceptance:

1. `ScenarioHarness::new()` cannot complete silently with zero tracked subjects.
2. Every scenario test either tracks subjects or uses `skip(reason)`.
3. Guard test fails on implicit bypass patterns.

## P1: Route interactive `new-workspace` through service layer

Evidence:

1. Interactive `cmd_new_workspace` currently calls `identity_ops::bootstrap_workspace` directly (`src/interactive.rs:494`).
2. TODO goal states interactive command semantics should route through service APIs (item 21).

Problem: one interactive command path still bypasses the intended service-layer boundary.

Fix:

1. Add or use a service-layer command for workspace bootstrap.
2. Migrate `cmd_new_workspace` to call service-layer API only.
3. Keep interactive-only UX shaping (labels, defaults) in `interactive.rs`.
4. Add regression coverage for parity with non-interactive flows.

Acceptance:

1. No direct `identity_ops::bootstrap_workspace` call remains in interactive command flow.
2. Service layer owns workspace bootstrap command semantics.
3. Interactive behavior remains UX-equivalent.

## P2: Remove residual trust-bootstrap shortcuts from realism helpers

Evidence:

1. `start_peers` auto-imports CLI pin rows (`src/testutil.rs:1336`).
2. mDNS realism tests seed trust with `import_cli_pins_to_sql` (`tests/scenario_test.rs:3493`, `tests/scenario_test.rs:3610`).

Problem: these helpers still shortcut trust bootstrap and can mask invite/bootstrap/discovery trust integration failures.

Fix:

1. For realism-sensitive suites, replace direct pin-import setup with invite/bootstrap/discovery or event-derived trust setup flows.
2. Keep pin-import usage only in tests explicitly labeled as pinning-policy boundary tests.
3. Update helper naming/documentation to distinguish realism helpers from policy-boundary fixtures.
4. Add/adjust tests so realism suites fail if trust bootstrap is not acquired through runtime paths.

Acceptance:

1. Realism suites do not rely on `import_cli_pins_to_sql` for baseline connectivity.
2. Remaining pin-import tests are explicitly scope-labeled as policy-boundary tests.
3. Documentation reflects the boundary clearly.
