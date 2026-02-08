# Phase 3 Feedback (`8a38321`)

Scope reviewed:
- Commit `8a38321` (`Implement Phase 3: encrypted events with PSK-based AES-256-GCM`)
- Files:
  - `src/events/encrypted.rs`
  - `src/events/secret_key.rs`
  - `src/events/mod.rs`
  - `src/projection/encrypted.rs`
  - `src/projection/pipeline.rs`
  - `src/projection/create.rs`
  - `src/projection/projectors.rs`
  - `src/testutil.rs`
  - `tests/scenario_test.rs`

Plan alignment used for this review:
- `PLAN.md` Phase 3 section (`## 7`) and encrypted-test strategy (`## 7.6`, `## 12.2`).
- Core simplification rules in `PLAN.md` (`## 2`), especially local-only event semantics and blocked-event normalcy.

## Findings (severity ordered)

1. High: local-only secret key events are still synced over the wire, which conflicts with plan semantics and leaks key material.
- Evidence:
  - `SecretKeyEvent` is marked `share_scope: Local` (`src/events/secret_key.rs`).
  - Sync path still advertises/sends all event IDs via negentropy + `store.get` with no `share_scope='shared'` gate (`src/sync/engine.rs`, `src/db/store.rs`).
  - Integration test currently expects remote peer to receive/project secret keys (`tests/scenario_test.rs::test_encrypted_event_sync`).
- Plan conflict:
  - `PLAN.md` says canonical local-only events are not shared (`## 2`, `## 5.4`).
  - Phase 3 PSK strategy expects per-instance local materialization, not secret-key replication (`## 7.6`, item 2).
- Impact:
  - secret key bytes can be replicated to remote peers despite local-only typing.
  - future sender-keys/key-wrap model will need rework because this path bakes in key replication.
- Action:
  - enforce share-scope filtering at reconciliation/egress boundary (share only `events.share_scope='shared'`).
  - adjust encrypted tests to materialize local keys per tenant instead of syncing `secret_key` events.

2. Medium: Phase 3 implementation does not yet match the planned key-wrap trajectory.
- Evidence:
  - no `secret_shared`/key-wrap event family exists in this phase; only `secret_key` + `encrypted` are added.
  - happy-path depends on remote receipt of sender key event (current tests).
- Plan conflict:
  - Plan explicitly wants Phase 3 PSK mode to lead into the same key-wrap path used later (`PLAN.md` `## 7.6`, `## 11.5`).
- Impact:
  - increases migration cost into Phase 7 identity/sender-subjective encryption.
- Action:
  - either update plan to accept temporary direct key replication, or introduce minimal key-wrap event now and keep `secret_key` strictly local.

3. Medium: signer data errors inside encrypted-inner projection can still surface as hard errors instead of terminal reject.
- Evidence:
  - `project_encrypted` calls `resolve_signer_key(...)?` and treats resolver errors as propagated errors (`src/projection/encrypted.rs`).
  - resolver still returns `Err` for unsupported signer types/wrong signer event kind on this branch (`src/projection/signer.rs`).
- Impact:
  - malformed encrypted-inner signed events can produce repeat projection errors without clean terminal reject classification.
- Action:
  - apply the `SignerResolution` pattern (already implemented in phase-2.5-fixes worktree) to this branch and map data-level signer failures to `Reject` + durable `rejected_events` rows.

## Test gaps against PLAN

1. Missing explicit test that local-only `secret_key` events are never sent to remote peers.
2. Missing Phase 3 two-set PSK isolation harness (`PSK_A` vs `PSK_B`) from `PLAN.md` `## 12.2`.
3. Missing encrypted-inner unsupported-signer test asserting durable reject (not hard projection error).

## What is good and should be preserved

1. Encrypted wrapper is integrated as a normal registry type with mandatory `inner_type_code`.
2. Materialization flow is adapter-style (decrypt -> parse inner -> normal projector), not a second projection system.
3. Key dependency blocking/unblocking semantics for encrypted events are implemented and covered by tests.
4. Wrong-key and nested-encryption rejection behavior is covered by tests.

## Tests run for this review

1. `cargo test encrypted -- --nocapture`

The suite passed; findings above are design/semantics gaps relative to the original plan and future-phase compatibility.
