# ENCRYPTION REALITY INSTRUCTIONS

## Branch + Worktree
- Branch: `feat/encryption-rigor-plan`
- Worktree: `/home/holmes/poc-7/.worktrees/encryption-plan`

## Objective
Make encryption fully real across the content surface and eliminate all "fake encryption" behavior.

Required product rule:
- All content must be encrypted, including reactions.
- Auth/identity naming fields may remain plaintext placeholders for now (workspace/user/device/invite naming), to keep encrypted auth naming out of scope.

Required protocol rule:
- Key dependencies are normal event dependencies.
- Secret keys are materialized from unwrapped `secret_shared` events and must unblock anything blocked on `key_event_id`.

Required scope constraint:
- Group key agreement is out of scope.
- Message/reaction/deletion content uses one shared workspace content key in this POC, distributed via invite-link wrapping so all joiners can unwrap it.
- Each file attachment uses its own unique attachment key (`message_attachment.key_event_id`), and file slices are encrypted only with that attachment key.

Required documentation discipline:
- Any protocol/behavior change in this plan must update `docs/DESIGN.md` and `docs/PLAN.md` in the same change set.
- No implementation-only encryption behavior drift is allowed; design, plan, TLA mapping docs, and code must stay aligned.

## What Counts As "Fake" (Must Be Removed)
Any of the following is a failure:
1. Content command path creates plaintext `message`/`reaction`/`message_deletion`/`message_attachment`/`file_slice` as the canonical shared payload instead of `encrypted` wrapper flow.
2. `file_slice.ciphertext` carries raw file bytes without real encryption semantics.
3. Key availability is simulated by manually creating matching `secret_key` events on receivers instead of real `secret_shared` unwrap.
4. Encrypted content succeeds without a real key dependency chain (`encrypted -> key_event_id -> secret_key`).
5. Tests claim encrypted behavior but bypass real wrap/unwrap/decrypt/unblock flow.
6. TLA specs omit unwrap/materialization/unblock invariants or are not model-checked after updates.
7. File payload encryption reuses non-attachment keys, or attachment keys are reused across distinct attachments.
8. Message deletion leaves attachment decryptability unchanged (no crypto-shred semantics).

## Current Known Gaps To Fix
1. Command-layer plaintext content creation is still present in:
   - `src/event_modules/message/commands.rs`
   - `src/event_modules/reaction/commands.rs`
   - `src/event_modules/message_deletion/commands.rs`
   - file send/generation paths in `src/event_modules/message/commands.rs`
2. Invite bootstrap unwrap exists, but generalized runtime `secret_shared` -> local `secret_key` materialization is incomplete/non-authoritative.
3. Device-link invite flow does not guarantee equivalent content-key wrap distribution for joiners.
4. Existing tests still include synthetic/manual key materialization shortcuts.
5. Existing TLA coverage includes `InvEncryptedKey`, but does not fully model unwrap/materialization/unblock lifecycle at the granularity needed to prevent regressions.

## Target End-State
1. All content writes go through one encryption pipeline.
2. All content reads decrypt through one verified path.
3. `secret_shared` is the only shared key transport.
4. Local `secret_key` materialization is deterministic and auditable.
5. Missing key blocks are normal dependency blocks; key materialization causes normal cascade unblocking.
6. No plaintext-content fallback remains in production command paths.
7. TLA invariants for encryption/unwrap are present and TLC-checked.

## Implementation Plan

### Phase 0: Freeze + Audit
1. Produce a coverage matrix of every write path for content event types and mark each as `real`, `fake`, or `mixed`.
2. Add temporary failing tests that assert current fake behavior is disallowed (tests may fail initially; keep as guardrails).
3. Add static grep guard in CI to forbid command-layer direct creation of raw content types except in explicitly allowed test helpers.

### Phase 1: Centralize Content Encryption Writes
1. Introduce a single command helper (event-module local) that:
   - resolves the workspace content key event id,
   - signs the inner content event,
   - wraps it as `encrypted` (type 5),
   - stores/projects synchronously.
2. Migrate command callers:
   - send message
   - react
   - delete message
   - send-file metadata + slices
   - synthetic generators used by runtime commands
3. Remove/forbid direct command-layer calls that emit raw content events as shared canonical payloads.

### Phase 2: Make Key Distribution Real (No Simulation)
1. Keep one workspace content key for message/reaction/deletion content (no key agreement/rotation in this scope).
2. Ensure workspace content key wrapping occurs for all join paths:
   - user invites
   - device-link invites
3. Ensure joiners can always unwrap invite-wrapped content key and materialize deterministic `secret_key` event IDs.
4. For file attachments, emit a fresh attachment key per attachment and wrap that key to recipients via `secret_shared` events (same dependency machinery).

### Phase 3: Generalize `secret_shared` Unwrap Materialization
1. Implement authoritative materialization flow driven by projected `secret_shared`:
   - detect locally-eligible recipient key material (`peer_shared` local signer key or pending invite key),
   - unwrap with sender public key,
   - verify deterministic `key_event_id` match,
   - create local `secret_key` event idempotently.
2. Emit retry path for late prerequisites (signer key, recipient key material, or secret_shared arrival order).
3. Keep this in normal projection/cascade semantics, not a side channel.

### Phase 4: File Encryption Correctness
1. Eliminate fake "ciphertext" writes.
2. Enforce file key model:
   - each new attachment gets a fresh `secret_key` event (attachment key),
   - `message_attachment.key_event_id` points to that attachment key,
   - attachment keys are never reused across different attachments.
3. Encrypt each `file_slice` directly with its attachment key (no fallback plaintext path); document and test deterministic nonce/AAD derivation.
4. Ensure attachment key distribution uses `secret_shared` wraps to eligible recipients/invitees (event-driven, retryable).
5. Enforce crypto-shred semantics on message deletion:
   - deleted message attachments must become undecryptable in normal read paths,
   - attachment-key availability for deleted content is removed/quarantined in projection/read policy,
   - no new wraps for deleted-message attachment keys.
6. Ensure receiver reconstruction path performs real decrypt, validates integrity, and truncates by `blob_bytes`.
7. Ensure filename/mime/content metadata follows the "content is encrypted" rule.

### Phase 5: Dependency + Unblock Correctness
1. Verify blocked rows for missing `key_event_id` are produced only by dependency checks.
2. Verify key materialization resolves blockers and triggers cascade unblocking.
3. Ensure no reject-path shortcut is used where block/unblock is required.

### Phase 6: Remove Fake Test Patterns
1. Replace tests that create matching secret keys on both peers by hand when they are intended to test network key sharing.
2. Add end-to-end tests requiring real flow:
   - invite wrap -> accept -> unwrap -> key materialize -> encrypted content decrypt
   - out-of-order `encrypted` before key, then unblock after unwrap/materialization
   - reactions encrypted end-to-end
   - file attachment end-to-end encrypt/decrypt integrity
3. Keep a small set of low-level crypto unit tests for pure primitives only.

### Phase 7: TLA Modeling + Model Checking (Required)
Update TLA so encryption/unwrap invariants are modeled and checked, not just described.

0. Preflight:
   - ensure `docs/tla/tla2tools.jar` is present (or CI provides equivalent classpath),
   - pin the TLC version + checksum in repo docs so checks are reproducible.
1. Extend model set (preferred: add dedicated `EncryptionLifecycle.tla` + cfg files; alternatively extend `EventGraphSchema.tla` if state-space remains tractable).
2. Add invariants (minimum):
   - `InvEncryptedDependsOnMaterializedKey`:
     encrypted validity requires corresponding local secret key validity.
   - `InvUnwrapOnlyForLocalRecipient`:
     unwrap/materialization allowed only if recipient identity belongs to local tenant context.
   - `InvDeterministicKeyIdFromUnwrap`:
     materialized secret_key event id must match deterministic derivation from unwrapped bytes and `key_event_id` hint.
   - `InvNoPhantomSecretKey`:
     non-local secret_key materialization must be causally explainable by valid secret_shared unwrap path.
   - `InvBlockedEncryptedUnblocksAfterKey` (safety + progress):
     if encrypted is blocked only on key and matching key becomes valid, encrypted eventually leaves key-blocked state.
   - `InvContentWritesAreEncrypted`:
     content-visible valid events originate from encrypted wrapper path (except explicitly local-only test fixtures).
3. Update mapping docs:
   - `docs/tla/projector_spec.md`
   - `docs/tla/runtime_check_catalog.md`
4. Run and record TLC checks (must pass):
   - `cd docs/tla && ./tlc event_graph_schema_fast.cfg`
   - `cd docs/tla && ./tlc TransportCredentialLifecycle transport_credential_lifecycle_fast.cfg`
   - `cd docs/tla && ./tlc UnifiedBridge unified_bridge_progress_fast.cfg`
   - `cd docs/tla && ./tlc EncryptionLifecycle encryption_lifecycle_fast.cfg` (new)
5. Run deeper cfg for encryption model before merge (`*_expanded` or dedicated deep cfg).

### Phase 8: Enforcement Before Merge
1. Add CI gates:
   - unit/integration tests for encryption flow,
   - TLA fast checks,
   - static anti-fake guard (no plaintext content command writes).
2. Require an evidence doc with:
   - changed code paths,
   - test outputs,
   - TLC pass outputs,
   - explicit statement of what remains intentionally out of scope.

### Phase 9: Design/Plan Alignment Gate (Required)
1. Update `docs/DESIGN.md` to match implemented encryption semantics:
   - message-content key policy,
   - per-attachment file key policy,
   - crypto-shred-on-message-deletion behavior,
   - wrap/unwrap and unblock lifecycle.
2. Update `docs/PLAN.md` phase text/checklists to match the same semantics and rollout order.
3. Update TLA mapping docs (`docs/tla/projector_spec.md`, `docs/tla/runtime_check_catalog.md`) so invariant names/check bindings match final behavior.
4. Add a CI/doc check that fails if implementation PR changes encryption behavior without touching DESIGN/PLAN/TLA mapping docs.

## Acceptance Criteria (Strict)
All must be true:
1. Content commands never emit raw shared plaintext content events in production flow.
2. Real decrypt is required to access message/reaction/deletion/attachment/slice content.
3. Key unwrapping is event-driven (`secret_shared`) and deterministic.
4. Key dependency blocks/unblocks occur via normal dependency engine.
5. Invite joiners (user + device-link) can unwrap distributed workspace content key.
6. TLA invariants for unwrap/materialization/unblock are present and TLC-checked.
7. No tests rely on fake key simulation where the scenario intent is real key distribution.
8. Every file attachment has a unique attachment key, and file slices are encrypted only under that key.
9. Message deletion enforces crypto-shred semantics for associated file attachments.
10. `docs/DESIGN.md` and `docs/PLAN.md` are updated and consistent with the shipped encryption behavior.

## Rigorous Success Criteria (SC)
`SC-1` Content write-path purity:
- In command-layer integration tests, canonical shared writes for content produce `event_type='encrypted'` wrappers; no raw shared `message/reaction/message_deletion/message_attachment/file_slice` command writes.

`SC-2` Dependency correctness:
- For an encrypted content event `E` referencing `key_event_id=K`, projecting `E` without valid `K` yields `Block` with blocker `K` (not `Reject`).

`SC-3` Unblock correctness:
- After deterministic materialization of `K`, previously key-blocked `E` leaves key-blocked state via normal cascade.

`SC-4` SecretShared materialization causality:
- Non-local secret key materialization has a traceable valid `secret_shared` cause and recipient ownership proof.

`SC-5` Deterministic ID consistency:
- For the same plaintext key bytes, inviter and joiner derive identical `secret_key` event IDs; mismatch paths are rejected/skipped.

`SC-6` Invite coverage:
- Both user-invite and device-link join paths receive equivalent content-key wrap coverage enabling decrypt for post-join content.

`SC-7` File reality:
- File payload reconstruction verifies real decrypt round-trip; ciphertext-at-rest differs from plaintext source bytes.

`SC-8` Fake test removal:
- Scenario/integration tests that previously used manual receiver-side key synthesis for distribution scenarios are migrated to real wrap/unwrap setup.

`SC-9` Static anti-fake guard:
- CI fails if command modules directly create raw shared content events outside approved low-level/test fixtures.

`SC-10` TLA invariant presence:
- Encryption/unwrap/materialization/unblock invariants are explicitly declared in TLA spec(s) and mapped in `projector_spec.md` + `runtime_check_catalog.md`.

`SC-11` TLA check gate:
- Fast TLC configs for EventGraphSchema, TransportCredentialLifecycle, UnifiedBridge, and the encryption lifecycle model pass in CI.

`SC-12` Evidence completeness:
- Evidence document includes command-path diff matrix, test pass output, TLC pass output, and explicit out-of-scope remainder list.

`SC-13` Attachment key uniqueness + scope:
- For any two distinct attachment IDs, `message_attachment.key_event_id` values differ; each attachment's slices decrypt only with its own key.

`SC-14` Crypto-shred on message deletion:
- After message deletion projects, attachment payload for that message is no longer decryptable through normal query/read APIs, and no further key-wrap distribution occurs for its attachment keys.

`SC-15` DESIGN/PLAN alignment:
- Encryption behavior changes are accompanied by matching updates in `docs/DESIGN.md`, `docs/PLAN.md`, and TLA mapping docs in the same PR.

## Explicit Out-of-Scope (for this execution)
1. TreeKEM/DCKGA or any advanced group key agreement.
2. Historical key rotation and history re-encryption policy.
3. Encrypting auth/identity naming fields.

## Suggested Execution Order
1. Phase 0 + Phase 1 (stop plaintext writes first).
2. Phase 2 + Phase 3 (make key distribution/materialization authoritative).
3. Phase 4 + Phase 5 (file correctness + unblock rigor).
4. Phase 6 (remove fake tests).
5. Phase 7 + Phase 8 (formal checks + CI enforcement + evidence).
6. Phase 9 (DESIGN/PLAN/TLA mapping alignment gate before merge).
