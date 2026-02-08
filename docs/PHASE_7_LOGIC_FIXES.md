# Phase 7 Logic Fixes Plan

This plan aligns runtime, tests, and TLA artifacts with the corrected Phase 7 semantics:

1. `invite_accepted` is local trust-anchor binding.
2. Trust-anchor guard applies to root `network/workspace` event validity.
3. No `HasRecordedInvite`-style global guard on `invite_accepted`.
4. No pre-projection raw-blob trust-binding capture authority.
5. TLA scope gap for transport credential lifecycle is explicit and tracked.

---

## 1. Target behavior (authoritative)

### 1.1 Guard placement

- `invite_accepted`: local anchor-binding step.
- `network/workspace` root event: guard with trust-anchor match.
- Foreign root ids must reject (or remain non-valid) under anchor mismatch.

### 1.2 Trust binding source

- Trust anchor binds from validated `invite_accepted` event fields.
- Do not bind from out-of-band pre-projection capture tables.

### 1.3 TLA scope

- Identity/event causality remains modeled in existing TLA modules.
- Transport credential lifecycle modeling (event-backed TLS credential/trust state transitions) must be added as a tracked follow-up artifact.
- TLS handshake/session-key derivation may remain abstracted.

---

## 2. Code changes

## 2.1 Projection logic

Files:
- `src/projection/identity.rs`
- `src/projection/pipeline.rs` (only if guard retry behavior needs adjustment)

Required edits:
1. Remove `HasRecordedInvite` guard behavior from `project_invite_accepted`.
2. Remove `invite_network_bindings` fallback path from `project_invite_accepted`.
3. Bind trust anchor directly from `InviteAcceptedEvent` fields.
4. Make trust-anchor write semantics deterministic and safe:
   - prefer immutable first-write semantics (`INSERT OR IGNORE`) plus mismatch handling,
   - avoid silent overwrite (`INSERT OR REPLACE`) unless explicitly intended and proven safe.
5. Keep/reconfirm guard-cascade reproject behavior for network events after `invite_accepted`.

## 2.2 Recording-path cleanup

Files:
- `src/projection/identity.rs`
- `src/projection/create.rs`
- `src/sync/engine.rs`

Required edits:
1. Remove `capture_invite_network_binding(...)` API and call sites.
2. Ensure no trust-binding state is derived from unvalidated ingress/local blobs.

## 2.3 Schema/migrations cleanup

File:
- `src/db/migrations.rs`

Required edits:
1. Add a migration to retire `invite_network_bindings` from active logic.
2. Keep backward-compatible read behavior if old DBs contain the table.
3. If retained for compatibility, mark as deprecated and unused by runtime logic.

Optional hardening (if adopted in same PR):
1. enforce single active root network row semantics per tenant (or explicitly document plurality).
2. enforce trust-anchor immutability policy at schema/query level.

---

## 3. TLA/spec changes

Files:
- `docs/tla/BootstrapGraph.tla`
- `docs/tla/EventGraphSchema.tla`
- `docs/tla/projector_spec.md`
- related `.cfg` files as needed

Required edits:
1. Remove/replace `HasRecordedInvite` guard for `invite_accepted`.
2. Remove/replace invite-binding capture assumptions (for example `inviteNet` capture path as authority).
3. Model anchor binding as direct consequence of validated `invite_accepted` semantics.
4. Keep trust-anchor guard on root network/workspace events.
5. Re-freeze projector mapping doc to match runtime after changes.

Transport scope follow-up artifact:
1. Add a dedicated TLA note/module for transport credential lifecycle modeling:
   - event-backed local TLS credential state,
   - projected SPKI trust mapping transitions,
   - rotation/revocation transition shape.
2. Link this artifact from `PLAN.md` and `projector_spec.md` scope notes.

---

## 4. Test plan

Files:
- `tests/scenario_test.rs`
- unit tests under `src/projection/*` and `src/events/*` as needed

Required tests:
1. `invite_accepted` does not depend on global invite-presence guard.
2. root network/workspace guard enforces trust-anchor match.
3. no pre-projection blob capture influence:
   - malformed/invalid invite-like blob cannot alter trust binding.
4. true out-of-order identity chain test (actually records dependent before dependency).
5. replay/idempotency/reverse-order invariants still pass.

Regression checks:
1. existing Phase 7 scenario set passes.
2. tenant isolation checks remain intact.

---

## 5. PR slicing

Recommended sequence:
1. `PR-1`: TLA/spec guard correction + projector spec update (no runtime change).
2. `PR-2`: runtime guard-placement fix in projection logic.
3. `PR-3`: recording-path capture removal + migration cleanup.
4. `PR-4`: scenario/unit tests for corrected semantics and out-of-order coverage.
5. `PR-5`: transport-credential TLA scope artifact (explicit follow-up model).

Each PR should include at least one failing test made to pass.

---

## 6. Done criteria

Phase-7 logic fix effort is done when:
1. No `HasRecordedInvite` runtime guard remains for `invite_accepted`.
2. No pre-projection trust-binding capture path is used by runtime authority.
3. Network/workspace root trust guard behavior is explicit and tested.
4. TLA/spec artifacts match runtime behavior.
5. Transport credential TLA scope gap is either closed or explicitly tracked with linked artifact and acceptance notes.
