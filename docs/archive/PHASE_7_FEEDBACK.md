# Phase 7 Feedback

> **Historical feedback; file paths may not match the current source tree.**

Reviewed commit: `78cdf82` (`Implement Phase 7: TLA-first minimal identity layer`)

Scope note:
- This review covers only Phase 7 commit `78cdf82` and excludes later plan/doc edits.

Test check:
- `cargo test -q --test scenario_test` passed (`37 passed`).

## Findings

### 1. Critical: pre-projection invite-network binding path should be removed under the corrected model

- Evidence:
  - capture happens before `project_one` in local create path: `src/projection/create.rs:83`.
  - capture happens before projection in sync ingest path: `src/sync/engine.rs:216`.
  - capture logic trusts raw blob type/offset and does `INSERT OR IGNORE` first-write-wins: `src/projection/identity.rs:272`, `src/projection/identity.rs:282`, `src/projection/identity.rs:287`.
- Impact:
  - malformed or signature-invalid `user_invite_boot` blobs can still set `invite_network_bindings`.
  - because first write wins, a poisoned early binding can persist and affect trust-anchor decisions later.
- Recommended fix:
  - remove `invite_network_bindings` capture from recording path (`src/projection/create.rs:83`, `src/sync/engine.rs:216`) and remove the table if no longer needed.
  - bind trust anchor directly from `invite_accepted` semantics (local acceptance), then keep guard logic on `network` events only.
  - this matches the clarified protocol intent: invite flows from network/signer chain; `invite_accepted` should not implement invite-presence guarding.

### 2. High: `InviteAccepted` currently enforces `HasRecordedInvite`, but model should not guard here

- Evidence:
  - `project_invite_accepted` runs `HasRecordedInvite` query and blocks when none found: `src/projection/identity.rs:90`, `src/projection/identity.rs:99`.
- Impact:
  - adds an unnecessary guard edge and ordering constraint at the wrong place in the causal chain.
  - couples trust-anchor binding to generic recorded invite presence instead of explicit local accept semantics.
- Recommended fix:
  - remove `HasRecordedInvite` guard from `invite_accepted`.
  - keep/strengthen guarding on `network` (`TrustAnchorMatch`) only.
  - if `invite_event_id` linkage is still required for auditability, model it as a normal dependency/reference check, not a global invite-presence guard.

### 3. High: trust anchor and network signer root are not immutable/unique

- Evidence:
  - trust anchor uses `INSERT OR REPLACE`: `src/projection/identity.rs:126`.
  - `networks` table allows multiple rows per peer (PK is `(recorded_by, event_id)` only): `src/db/migrations.rs:193`.
  - projector spec states invariant `InvSingleNetwork` (“At most one network row per peer”): `docs/tla/projector_spec.md:144`.
- Impact:
  - trust anchor can be overwritten by later local events.
  - multiple valid network signer rows can coexist for one peer, conflicting with documented invariant and making signer-root semantics ambiguous.
- Recommended fix:
  - make trust-anchor write immutable (`INSERT OR IGNORE` + reject on mismatch).
  - add schema constraint for single-network semantics (or update spec/invariants if plurality is intended).

### 4. Medium: “out-of-order identity” scenario test is not actually out-of-order

- Evidence:
  - test comment says UserBoot is recorded before UserInviteBoot: `tests/scenario_test.rs:1809`.
  - implementation records `UserInviteBoot` before `UserBoot`: `tests/scenario_test.rs:1833`, `tests/scenario_test.rs:1846`.
- Impact:
  - true out-of-order unblock path for this chain is not tested.
- Recommended fix:
  - build/store `UserBoot` first via raw insert helper (or explicit helper that allows missing dep), then project invite path and assert unblock.

### 5. Low: TLA projector spec updates required (plus existing `Encrypted` scope mismatch)

- Evidence:
  - spec says `Encrypted` share scope is `Local`: `docs/tla/projector_spec.md:13`.
  - runtime metadata is `ShareScope::Shared`: `src/events/encrypted.rs:101`.
- Impact:
  - assistant/maintainer confusion and incorrect assumptions when following frozen mapping docs.
- Recommended fix:
  - align `docs/tla/projector_spec.md` with runtime behavior (or change runtime if doc is canonical).
  - update TLA/model mapping for the corrected guard design:
    - remove `HasRecordedInvite` as an `InviteAccepted` guard from spec and model.
    - keep `TrustAnchorMatch` as the guard on `Network`.
    - remove invite-binding capture mechanism assumptions (`invite_network_bindings`) if trust anchor is set directly by `invite_accepted`.
    - regenerate/update invariants and mapping rows that depended on `HasRecordedInvite` / invite-binding path.

## Required model-sync note

Given the clarified intent, Phase 7 should include a focused TLA/spec revision before further projector changes:
- adjust the causal chain so `invite_accepted` is local trust-anchor binding without invite-presence guard,
- ensure only `network` is trust-guarded by the anchor,
- re-freeze `docs/tla/projector_spec.md` after model re-check.

## Open question (plan conformance)

- `create_event_synchronous` currently returns success for `Block` (`src/projection/create.rs:94`).
- In Phase 7, guard-blocked identity events make this path common.
- If the intended contract is “sync create returns only when terminal valid,” this now diverges and should be made explicit (or fixed).
