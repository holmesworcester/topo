# TODO: Design/Plan/Code Alignment Backlog (poc-7/master)

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
3. `P1: Stop direct SQL trust seeding in CLI invite-bootstrap test` (partially addressed: `test_two_process_invite_and_sync` uses production invite flow; existing `test_cli_sync_bootstrap_from_accepted_invite_data` still seeds directly)
4. `P1: Remove manual endpoint observation writes in hole-punch integration test`
5. `P2: Align test transport setup with production dynamic trust lookup`
6. `P1: Deprecate --pin-peer from product code and design after invite-trust maturity`
7. `P0: Make scenario replay invariants mandatory by default (opt-out only)`
8. `P0: Bring scenario invariant harness fully in line with PLAN (fingerprints + full invariant set)`
9. `P1: Investigate and decide create_event_sync service semantics before implementation changes`
10. ~~`P1: Investigate simplification of project_one/project_one_core split to better match one-path intent`~~ **DONE**: Investigated and resolved. Decision: keep two-layer model (`project_one` public entrypoint + `project_one_step` internal non-cascading step) as justified cascade optimization. Renamed `project_one_core` → `project_one_step` with clear doc comments. Added 7 source-isomorphism invariance tests proving direct/cascade/reverse-order convergence. Updated DESIGN.md §4.1, PLAN.md §5/§15.1, and TLA projector_spec.md to explicitly document the internal split.
11. `P0: Unify transport identity architecture (single event-derived peer identity, no rotation sidecar)`
12. `P2: Resolve disjoint trust sets docs/code mismatch`
13. `P0: Enforce removal policy at transport runtime (deny + disconnect active sessions)`
14. `P0: Unify bootstrap key distribution via invite-key wrap/unwrap (keep local secret_key dep)`
15. `P1: Collapse encrypted-inner projection onto the same dependency/signer engine stages`
16. `P0: Re-impose fixed-length event fields + langsec parser model`
17. `P1: Remove duplicated command/business logic between CLI (main.rs) and service layer (service.rs)` (partially addressed: invite create/accept now routes through service layer; remaining: send, messages, status, react, delete, users, keys)
18. `P1: Eliminate direct SQL access in CLI command paths where module APIs already exist`
19. `P1: Reconcile TLA/spec mapping docs with PLAN and implemented projector semantics`
20. `P2: Remove residual compatibility cruft from active schema/docs/runtime surfaces`
21. `P1: CLI isomorphism — route remaining interactive commands through service layer` (send, messages, status, react, delete, users, keys — interactive REPL should be a thin adapter over service functions per PLAN §2.2)
22. `P2: Single-port multi-tenant endpoint — share one UDP port across tenants on the same device` (currently per-tenant ports; see PLAN §2.3)

## P0: Re-impose fixed-length event fields + langsec parser model

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

## P1: Collapse encrypted-inner projection onto the same dependency/signer engine stages

Evidence:

1. Plan requires one dependency engine and one projection entry pipeline (`docs/PLAN.md:95`, `docs/PLAN.md:96`, `docs/PLAN.md:550`).
2. Signer refs are already modeled as dependencies in event metadata (`docs/PLAN.md:546`) and in code (`src/events/mod.rs:138`).
3. Current encrypted path re-implements core stages for inner plaintext:
   - inner dep check/block row writes: `src/projection/encrypted.rs:91`
   - inner signer verification: `src/projection/encrypted.rs:126`
   - inner projector dispatch switch: `src/projection/encrypted.rs:163`
4. Generic non-encrypted flow already has shared stages:
   - dep check/type check: `src/projection/pipeline.rs:222`, `src/projection/pipeline.rs:257`
   - signer verify + dispatch: `src/projection/pipeline.rs:61`

Problem: logic drift risk. Two implementations of the same semantic stages can diverge (error reasons, blocker writes, signer handling, event-type admission policy).

Fix:

1. Keep the current model that signer refs are deps (for blocking) plus a distinct signature-verification stage after deps are available.
2. Refactor pipeline into explicit reusable stages callable for both:
   - canonical outer event path (today’s `project_one_core`),
   - decrypted inner event path (encrypted wrapper).
3. Minimize `projection/encrypted.rs` to wrapper-specific concerns only:
   - key resolve / decrypt / `inner_type_code` checks / no-nested-encrypted policy,
   - then call shared dep/type/signer/dispatch stage with outer `event_id` context.
4. Ensure blocker/reject semantics remain anchored to outer event_id for encrypted wrappers.
5. Add regression tests proving parity between direct event projection and encrypted-inner projection for the same inner type.
6. TLA/model alignment:
   - update `docs/tla/projector_spec.md` to reflect single staged engine semantics (including encrypted-inner reuse path),
   - update model notes if any guard/dependency staging language changes.

Acceptance:

1. No duplicated dep/signer/dispatch logic remains between `projection/pipeline.rs` and `projection/encrypted.rs`.
2. Signed inner events block on signer deps and verify signatures through the same shared stage as cleartext events.
3. New parity tests pass for at least message/reaction/deletion/file-slice inner event families.
4. TLA/projector mapping docs describe one staged dependency/signer engine path.

## P0: Unify bootstrap key distribution via invite-key wrap/unwrap (keep local `secret_key` dep)

Evidence:

1. Plan requires one key-wrap model across PSK bootstrap and identity phases (`docs/PLAN.md:101`, `docs/PLAN.md:102`, `docs/PLAN.md:1080`).
2. Current encrypted path correctly depends on local `secret_key` event (type 6, local scope):
   - encrypted dep metadata: `src/events/encrypted.rs:108`
   - type-6 dep constraint: `src/events/encrypted.rs:109`
   - local scope: `src/events/secret_key.rs:62`
3. Current create/project encrypted flow resolves key bytes directly from local `secret_keys` table:
   - create path: `src/projection/create.rs:180`
   - projection path: `src/projection/encrypted.rs:22`
4. `secret_shared` key-wrap event/projector path already exists (`src/events/secret_shared.rs:76`, `src/projection/identity.rs:251`) but is not the canonical bootstrap flow for obtaining local decrypt keys.

Problem: bootstrap still relies on simplified PSK-style assumptions, not a realistic invite-key wrap/unwrap bootstrap path, so the architecture remains bifurcated in practice.

Fix:

1. Keep local-only `secret_key` dependency model for encrypted payload decryption (do NOT remove type-6 local dependency).
2. Remove raw PSK bootstrap input paths (invite-link/CLI bootstrap secret inputs) from normative flow.
3. At invite creation, produce wrapped bootstrap/content key material to invite public key derived from invite secret (prefer reusing `secret_shared` event path rather than adding a second wrap model).
4. At invite acceptance, unwrap with invite private key and materialize local `secret_key` event/state for the accepting tenant.
5. Ensure out-of-order behavior is realistic:
   - encrypted events block/reject until local unwrapped key material exists,
   - unwrap arrival enables normal unblock/project flow.
6. Explicitly keep key-layer simplicity in this POC:
   - no rotation tree, no advanced key-history backfill, no removal-driven rekeying beyond baseline trust/removal logic.
7. TLA/model alignment:
   - update key-material and wrap/unwrap modeling in `docs/tla/EventGraphSchema.tla` (or split module) so invite bootstrap and steady-state use one key-wrap semantic path,
   - refresh invariant mapping in `docs/tla/projector_spec.md`.

Acceptance:

1. No raw PSK bootstrap secret is required in invite links or bootstrap CLI paths for normal flow.
2. End-to-end invite bootstrap demonstrates wrap -> unwrap -> local `secret_key` availability -> encrypted event projection.
3. `encrypted` continues to depend on local type-6 key material; only key acquisition path changes.
4. Tests cover bootstrap wrap/unwrap ordering (in-order and out-of-order arrival) without introducing rotation complexity.
5. TLA model and mapping docs cover the new bootstrap wrap/unwrap flow.

## P0: Unify transport identity architecture (single event-derived peer identity, no rotation sidecar)

Evidence:

1. Current runtime still has split transport/event identity authority:
   - transport identity and sidecar storage in `local_transport_creds`,
   - event-graph identity and trust logic in identity projection + trust tables.
2. Current split permits drift/rebuild hazards (for example silent local transport regeneration when sidecar state is missing).
3. Existing design/plan complexity around transport credential lifecycle and bridge events (`transport_key`) increases surface area.

Problem: duplicated identity authority (`peer` identity in event graph vs transport sidecar identity state) creates drift risk, replay/rebuild ambiguity, and unnecessary lifecycle machinery.

Target intent for this POC (preferred):

1. Device identity is the event-layer peer key (`peer_shared` lineage); `peer_id` is permanent and bound to that identity.
2. TLS cert/key material is derived/materialized from event-layer identity as a thin transport adapter, not an independent authority.
3. No transport identity rotation machinery in this POC model.
4. Security posture:
   - TLS 1.3 provides forward secrecy for sessions,
   - identity key capture permits active impersonation of that device identity (accepted tradeoff for this POC),
   - no additional transport-key-history revocation machinery is required.

Fix (direct cutover):

1. Lock the chosen model in DESIGN/PLAN/TLA first (TLA-first rule).
2. Remove `transport_key` as normative trust authority if this model is selected.
3. Remove/neutralize sidecar authority semantics (`local_transport_creds`) so canonical identity authority is event-derived.
4. Eliminate silent transport identity regeneration paths tied to missing sidecar rows.
5. Update transport allow/deny logic and tenant discovery to the chosen single-identity model.
6. Remove old split/rotation code paths in the same round (no dual mode).
7. TLA/model alignment:
   - rewrite/remove transport lifecycle invariants that assume rotating sidecar credential history,
   - align `docs/tla/projector_spec.md` mappings and DESIGN/PLAN invariant text to the chosen single-identity semantics.

Acceptance:

1. One canonical identity authority remains (event-layer peer identity).
2. Replay/rebuild does not depend on independent mutable transport sidecar state for identity continuity.
3. Runtime no longer has transport identity rotation behavior for this POC.
4. DESIGN/PLAN/TLA mapping and runtime behavior match.

## P0: Remove `copy_event_chain` from interactive invite acceptance

Evidence: `src/interactive.rs:905`, `src/interactive.rs:1049`, `src/interactive.rs:1629`.

Problem: `accept-invite` and `accept-link` currently copy shared events directly between DBs before acceptance. This bypasses network sync and can leak all already-shared workspace state instantly.

Fix:

1. Delete `copy_event_chain` usage from invite acceptance paths.
2. Add a real bootstrap sync step in interactive mode (from invite link `bootstrap_addr` + bootstrap trust rows) before calling `accept_user_invite`/`accept_device_link`.
3. If prerequisite invite/workspace events are still missing, fail with a clear "sync first" error.

Acceptance:

1. No direct event-copy call remains in interactive invite acceptance paths.
2. `tests/interactive_test.rs` no longer validates copied-event behavior (`test_copy_event_chain_shared_only` should be removed/replaced).

## P1: Stop direct SQL trust seeding in CLI invite-bootstrap test

Evidence: `tests/cli_test.rs:134`, `tests/cli_test.rs:160`, `tests/cli_test.rs:404`.

Problem: the CLI bootstrap trust test inserts `invite_bootstrap_trust` and `pending_invite_bootstrap_trust` rows directly, skipping the real invite flow.

Fix:

1. Replace `seed_invite_bootstrap_trust`/`seed_pending_invite_bootstrap_trust` with a real flow that creates and accepts an invite link.
2. If needed, add non-interactive CLI commands for invite create/accept so tests can stay process-based without direct DB writes.

Acceptance:

1. `tests/cli_test.rs` no longer calls direct trust-row seed helpers.
2. Invite-bootstrap sync test passes through production invite APIs or CLI commands only.

## P1: Replace prerequisite event copy in `Peer::new_in_workspace`

Evidence: `src/testutil.rs:140`, `src/testutil.rs:157`, `src/testutil.rs:169`.

Problem: `Peer::new_in_workspace` currently copies workspace/invite events DB-to-DB before `accept_user_invite`, which is not a real network join.

Fix:

1. Update `new_in_workspace` to fetch prerequisite events through a real sync session.
2. Keep identity operations (`create_user_invite`, `accept_user_invite`) but remove direct event insertion and projection from this path.

Acceptance:

1. `new_in_workspace` contains no `insert_event`/`insert_recorded_event` calls.
2. Hole-punch and other same-workspace integration tests still pass with real sync bootstrap.

## P0: Make scenario replay invariants mandatory by default (opt-out only)

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

## P1: Remove manual endpoint observation writes in hole-punch integration test

Evidence: `tests/holepunch_test.rs:296`, `tests/holepunch_test.rs:303`, `tests/holepunch_test.rs:307`.

Problem: test injects `peer_endpoint_observations` directly to make intro runnable on new endpoint addresses.

Fix:

1. Capture endpoint observations via real accepted connections instead of writing DB rows directly.
2. Ensure introducer sends intro based on observed addresses from runtime traffic only.

Acceptance:

1. No direct `record_endpoint_observation` calls in `tests/holepunch_test.rs`.
2. Intro happy-path still passes end-to-end.

## P2: Align test transport setup with production dynamic trust lookup

Evidence: production dynamic trust is in `src/main.rs:993`-`src/main.rs:997`; test helpers often use static allowlists in `src/testutil.rs:1131` and `tests/holepunch_test.rs:66`.

Problem: many integration helpers construct endpoints with static `AllowedPeers` snapshots, while production sync checks trust from SQL at handshake time.

Fix:

1. Add a test helper endpoint mode that uses dynamic DB trust lookup (`is_peer_allowed`) like `run_sync`.
2. Migrate realism-sensitive integration tests to this mode.
3. Keep static pin mode only for explicit pinning-policy tests.

Acceptance:

1. At least one main integration suite (CLI or hole-punch) runs through dynamic trust helper.
2. Static pin helper remains only where pinning policy itself is the thing under test.

## P1: Deprecate `--pin-peer` from product code and design after invite-trust maturity

Evidence: `--pin-peer` remains a first-class CLI surface (`src/main.rs:53`, `src/main.rs:184`, `src/bin/p7d.rs:38`), runtime guidance still points users to it (`src/main.rs:984`, `src/service.rs:1002`), and design still documents it as an overlay (`docs/DESIGN.md:117`).

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

## P2: Resolve "disjoint trust sets" docs/code mismatch

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

## P0: Enforce removal policy at transport runtime (deny + disconnect active sessions)

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

## P0: Bring scenario invariant harness fully in line with PLAN (fingerprints + full invariant set)

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

## P1: Investigate and decide `create_event_sync` service semantics before implementation changes

Evidence:

1. PLAN contract says synchronous create success implies `valid` terminal state:
   - `docs/PLAN.md:600`-`docs/PLAN.md:603`.
2. Service currently treats `Blocked` as success via wrapper:
   - `src/service.rs:88`-`src/service.rs:96`,
   - used in user-facing commands (`src/service.rs:607`, `src/service.rs:773`, `src/service.rs:801`).

Problem: docs/plan contract and service API behavior are currently misaligned; changing behavior affects CLI/service UX and orchestration assumptions.

Required process for this TODO (approval gate):

1. Initial investigation only (no behavior changes):
   - enumerate all call sites and current caller expectations,
   - catalog where `Blocked`-as-success is relied on today.
2. Planning and explanation:
   - write options with tradeoffs (for example strict valid-only vs explicit terminal-status response),
   - include test impact, caller behavior impact, and rollback risk.
3. Decision checkpoint:
   - present recommendation and wait for explicit approval before any implementation patch.
4. Implementation starts only after approval is recorded on this TODO item.

Acceptance:

1. Investigation note + option analysis is committed/recorded first.
2. No runtime behavior change lands before explicit approval.
3. Post-approval implementation and tests follow the selected option.

## P1: Reconcile TLA/spec mapping docs with PLAN and implemented projector semantics

Evidence:

1. PLAN requires projector/TLA divergence to be treated as spec bug (`docs/PLAN.md:1118`).
2. `docs/tla/projector_spec.md` currently contains stale rows versus current schema/runtime in several places (for example signer-required/signer-type rows and invite-related invariants).

Problem: stale mapping docs weaken reviewability and can hide real model/runtime divergence.

Fix:

1. Perform a row-by-row audit:
   - event registry metadata vs projector-spec table,
   - guard/invariant mapping vs implemented guards/projectors.
2. Update `docs/tla/projector_spec.md` to match current code and PLAN semantics:
   - signer requirements/types,
   - invite-accepted trust-anchor semantics,
   - transport trust/removal mapping rows.
3. Reconcile/trim stale invariants that no longer reflect normative behavior; add missing ones that now are normative.
4. Re-run relevant TLC/model checks and record results/artifacts.
5. Update `docs/DESIGN.md` / `docs/PLAN.md` references where mapping names changed.

Acceptance:

1. Mapping doc has no known stale rows against current runtime semantics.
2. TLC/model checks pass for updated invariants.
3. DESIGN/PLAN/TLA mapping terminology is consistent.

## P1: Remove duplicated command/business logic between CLI (`main.rs`) and service layer (`service.rs`)

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

## P1: Eliminate direct SQL access in CLI command paths where module APIs already exist

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

## P2: Remove residual compatibility cruft from active schema/docs/runtime surfaces

Evidence:

1. Active DESIGN still references compatibility-staging queue behavior:
   - `docs/DESIGN.md:538` (`ingress_queue` "reserved compatibility/diagnostic staging").
2. Migrations retain historical compatibility-only artifacts:
   - `src/db/migrations.rs:296` (version-12 no-op retained for ordering compatibility),
   - `src/db/migrations.rs:480` (`drop_retired_compat_tables` naming/history trail).
3. Runtime/test surface still carries legacy terminology artifacts:
   - `src/projection/pipeline.rs:1288` (`test_legacy_peer_key_blob_rejected` naming).

Problem: these leftovers keep old-era compatibility context alive in active surfaces, increasing cognitive load and conflicting with the POC single-path replacement policy.

Fix:

1. Prune/rename compatibility artifacts from active docs and code where they no longer serve runtime correctness.
2. Remove unused compatibility-only schema elements (for example `ingress_queue`) if no active runtime path depends on them.
3. Collapse compatibility-only migration/history clutter via epoch-forward schema cleanup (POC recreate-db model).
4. Keep archival context only under `docs/archive/`, not in normative active docs.

Acceptance:

1. Active DESIGN/PLAN text has no compatibility-shim framing for non-runtime features.
2. Active schema/runtime does not include unused compatibility-only tables/paths.
3. Legacy/compat wording in active tests/code is minimized to intentional hardening cases only.

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
