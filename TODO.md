# TODO: Test Realism Gaps (poc-7/master)

Date: 2026-02-15

Goal: make invite/join/sync tests exercise the same trust and transport paths as production `sync`, with minimal test-only shortcuts.

## Cross-cutting rule: TLA/model alignment

For any TODO that changes protocol semantics, trust-source semantics, dependency/guard rules, or identity/key lifecycle behavior:

1. Update relevant TLA modules under `docs/tla/` (for example `EventGraphSchema.tla`, `TransportCredentialLifecycle.tla`, `BootstrapGraph.tla`).
2. Update TLC configs if state/events/invariants changed.
3. Update `docs/tla/projector_spec.md` mapping rows and any DESIGN/PLAN invariant lists.
4. Add or adjust model-check CI/test invocation for the changed model scope.

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
4. Migration plan:
   - dual-read old/new types during transition,
   - write new fixed-layout types only once rollout gate is enabled,
   - retire old variable-layout emitters after compatibility window.
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

## P0: Event-source local transport credential lifecycle (no silent regen)

Evidence: `src/transport_identity.rs:47` generates new cert/key when `local_transport_creds` is missing; bootstrap trust is TTL-bound (`src/db/transport_trust.rs:9`, `src/db/transport_trust.rs:12`); trust authority is event-derived `transport_keys`.

Problem: a DB rebuild from canonical events that loses `local_transport_creds` can silently generate a new transport identity (`peer_id`), making previously shared `transport_key` bindings unusable and potentially stranding the node once bootstrap rows expire.

Fix:

1. Add local transport-identity lifecycle events (local share scope) for:
   - initial local cert/key install,
   - rotation/replacement.
2. Project those local events into `local_transport_creds` so replay/rebuild restores the same local transport identity.
3. Change `ensure_transport_cert*` behavior to avoid silent regen when identity already has trust history:
   - fail closed (explicit recovery action required), or
   - require an explicit `rotate-transport-identity` command that emits the local lifecycle event and follow-up `TransportKey` publication.
4. Ensure rotation path automatically publishes a new `TransportKey` event and provides a controlled overlap/grace policy for old/new SPKIs.
5. TLA/model alignment:
   - update `docs/tla/TransportCredentialLifecycle.tla` invariants/actions if lifecycle authority changes (event-backed local creds, no silent regen),
   - update `docs/tla/projector_spec.md` transport-lifecycle mapping rows accordingly.

Acceptance:

1. Local transport credential state is reconstructible from event replay (including local events), not only mutable SQL side state.
2. Restart/replay with intact event history does not change `peer_id` unexpectedly.
3. Silent transport identity regeneration is removed from default sync startup path.
4. Transport-credential TLA invariants and mapping docs match implemented lifecycle behavior.

## P1: Simplify identity model (reduce transport/event key split complexity)

Evidence: current design keeps separate transport SPKI identity and event-graph signer identity, bridged by `transport_key` events (`docs/DESIGN.md:102`, `docs/DESIGN.md:105`, `docs/DESIGN.md:144`).

Problem: operational complexity is high (extra binding events, local credential side-state, rebuild edge cases).

Fix (design + migration track):

1. Write a design decision comparing:
   - current split model (`peer_shared` + `transport_key` bridge),
   - simplified model where transport identity is deterministically derived from event identity (single logical identity authority).
2. If simplified model is chosen:
   - remove `transport_key` as required steady-state trust authority,
   - derive transport trust from projected identity graph directly,
   - reduce or eliminate mutable local transport credential side-state,
   - simplify transport credential lifecycle model by removing local credential history/revocation semantics (`InvActiveCredInHistory`, `InvRevokedSubsetHistory`, related invariants) from normative design and runtime requirements.
3. Provide a migration path with compatibility window (dual-read/dual-validate), then remove legacy path.
4. TLS forward-secrecy posture for simplification:
   - treat QUIC/TLS session confidentiality as provided by TLS 1.3 ephemeral handshake,
   - keep app-layer trust model focused on peer authorization and key distribution,
   - avoid adding protocol-level historical transport-credential revocation machinery unless we need active compromise response semantics beyond trust-set removal.
5. TLA/model alignment:
   - remove or rewrite transport lifecycle invariants that are no longer normative (`InvActiveCredInHistory`, `InvRevokedSubsetHistory`, etc.),
   - keep only invariants that remain part of the chosen simplified semantics.

Acceptance:

1. Decision doc committed with explicit tradeoffs and chosen direction.
2. If simplification is adopted, one end-to-end flow (invite -> sync) works without publishing `transport_key` events.
3. Replay/rebuild no longer depends on non-event local credential state for connectivity continuity.
4. `docs/DESIGN.md` and `docs/PLAN.md` no longer require credential-history/revocation invariants as normative behavior for transport lifecycle.
5. TLA modules/configs and `docs/tla/projector_spec.md` are updated to the simplified model.

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
   - keep `--pin-peer` only as an explicit bootstrap aid while invite-derived trust paths are still being stabilized,
   - once invite create/accept + first sync are reliable end-to-end, switch to deprecation mode.
2. Deprecation mode:
   - mark CLI `--pin-peer` as deprecated in help text and docs,
   - emit runtime warnings when used,
   - remove it from "happy path" examples and test defaults.
3. Remove from steady-state code path:
   - stop merging CLI pins into transport trust resolution by default,
   - make SQL/event-derived trust the sole default authority.
4. Final removal:
   - remove `--pin-peer` flags from primary commands and daemon entrypoints,
   - keep any explicit pinning behavior only in narrow transport-policy test utilities or a clearly scoped debug-only command.
5. Design/doc update:
   - update `docs/DESIGN.md` and `docs/PLAN.md` to state invite/event-derived trust is normative and manual pin overlays are transitional/deprecated (or removed).
6. TLA/model alignment:
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
