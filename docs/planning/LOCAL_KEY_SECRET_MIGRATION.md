# LocalKeySecret migration plan

Date: 2026-04-22
Branch: `dep-facts-pilot`
Addresses: Finding 2 of the reviewer's notes + Recommendation #4 of
`REAL_PROOFS_SIMPLIFICATION_RECOMMENDATIONS.md`.

## Problem

`project_encrypted` (`src/state/projection/encrypted.rs:22`) looks up
the decryption key via an ambient SELECT against `key_secrets` and,
when the key is absent, returns `BlockOnMissingDeps { missing: [] }`
— a *guard block* that the standard dep cascade cannot unblock. To
wake encrypted events later, `KeyShared`, `KeyRotation`, and
`KeyHistory` each emit a bespoke `EmitCommand::RetryBlockedEncryptedByKey`
(`src/state/projection/apply/write_exec.rs:260`) that rescans the
blocked-events table and re-projects encrypted rows whose
`key_event_id` matches.

This is a parallel control channel running alongside the event
graph: not dep-derived, not Verus-friendly, not uniform with the
rest of projection.

## Target shape

Positive authority for decryption should be carried by the event
graph: `Encrypted.key_event_id` names a `KeySecret` event (type 6,
`ShareScope::Local`) whose deterministic event_id is
`hash(encode(KeySecret { key_bytes }))`. When any of the three
key-bearing events (`KeyShared`, `KeyRotation`, `KeyHistory`)
successfully unwraps key material, it **emits a deterministic
`KeySecret` event** instead of writing `key_secrets` directly. The
emitted `KeySecret` projects through the normal pipeline, populates
`key_secrets`, and triggers the standard cascade unblock for any
dep-blocked encrypted event that named this `KeySecret`.

## Concrete changes

### 1. Re-type `Encrypted.key_event_id`

`src/event_modules/encrypted.rs:197`

```diff
-    dep_field_type_codes: &[&[32], &[1]],
+    dep_field_type_codes: &[&[EVENT_TYPE_KEY_SECRET], &[EVENT_TYPE_MESSAGE]],
```

(Use named constants, not magic numbers, while here.)

### 2. Route the three writers through `EmitCommand::EmitDeterministicBlob`

Replace each `WriteOp::InsertOrIgnore { table: "key_secrets", … }`
plus `EmitCommand::RetryBlockedEncryptedByKey` pair with a single
emit:

```rust
let ks = deterministic_key_secret_event(material.key_bytes);
let blob = encode_event(&ks).expect("KeySecret encode");
commands.push(EmitCommand::EmitDeterministicBlob { blob });
```

Sites:
- `src/event_modules/key_shared.rs:232` (and :245 retry)
- `src/event_modules/key_rotation.rs:260` (and :271 retry)
- `src/event_modules/key_history.rs:222` (and :238 retry)

### 3. Change `ensure_content_key_for_peer` to return the `KeySecret` id

`src/event_modules/workspace/identity_ops.rs:1048`

Today returns the KeyRotation event's id. Change to:

- Resolve (or create) the KeyRotation as before (wire-level key
  delivery still goes through rotation events).
- Look up the rotated key's `key_bytes` (from `key_secrets` during
  transition, or via the parsed rotation blob directly).
- Compute `deterministic_key_secret_event_id(&key_bytes)` and
  *locally emit* a matching `KeySecret` event (idempotent via the
  existing `create_deterministic_key_secret_event` helper at
  `identity_ops.rs:101`).
- Return the KeySecret event id.

Callers (all tests + production `create_encrypted_event` sites)
carry through automatically; they just pass whatever
`ensure_content_key_for_peer` returned.

### 4. Retire `RetryBlockedEncryptedByKey`

- Delete the `EmitCommand::RetryBlockedEncryptedByKey` variant from
  `src/state/projection/projector.rs`.
- Delete the handler at `src/state/projection/apply/write_exec.rs:260`.
- Remove the emits in the three projectors (already dead after
  step 2).

### 5. Simplify `project_encrypted`

`src/state/projection/encrypted.rs:22`

The standard dep-resolution pipeline now blocks encrypted events
whose KeySecret hasn't arrived. When `project_encrypted` runs, the
key is guaranteed present. Replace the guard-block branch with an
unwrap/panic (or a structured invariant violation), since a missing
key at this point means the dep system let a dep-unsatisfied event
through.

Still read from `key_secrets` — no reason to dep-load the parsed
KeySecret event and re-extract bytes when the projection row is
already there.

## Blast radius estimate

- 3 projector files (key_shared, key_rotation, key_history)
- 1 decryption pipeline file (encrypted.rs projection side)
- 1 identity-ops helper (workspace/identity_ops.rs)
- 2 EmitCommand plumbing files (projector.rs, write_exec.rs)
- ~10-20 test fixtures that construct encrypted events with specific
  `key_event_id` values (need remapping via the deterministic helper)
- Mirror updates in `src/sim/` if any direct key-material flows
  exist there

Rough size: 300-500 line diff, 30-50 tests touched.

## Sequencing

One commit per step; each commit keeps `cargo test --lib` at the
pre-existing 10-failure baseline.

1. Step 1 (dep_field_type_codes rewire) + Step 3 (ensure_content_key
   change) together — the wire contract flips in lockstep.
2. Step 2 (projector emission rewire) — three projectors,
   one commit each or batched.
3. Step 4 (retire RetryBlockedEncryptedByKey) — pure deletion,
   should be clean once step 2 landed.
4. Step 5 (simplify project_encrypted guard block) — opportunistic
   cleanup after step 2+4.

Risk: step 1's rewiring breaks any caller that constructs an
Encrypted event with a hand-crafted `key_event_id`. Address by a
pre-pass that greps for `EncryptedEvent { key_event_id: …`
constructions in tests.

## Proof implications

After this migration:

- **Encrypted.Valid ⇒ KeySecret exists locally** becomes a
  structural invariant directly provable from the dep graph. No
  ambient-state lemma required.
- The **"Valid KeyShared ⇒ invited recipient"** theorem (followup
  #67) can now be phrased as a property over the KeySecret chain:
  "every locally materialized KeySecret for a workspace was emitted
  by a KeyShared whose recipient resolves to an invited user." The
  proof is purely graph-local.
- The retry signal disappearing removes a non-grounded control-flow
  surface that no refinement bridge currently covers.

## Why this isn't being done in a single turn

Each wire-contract flip ripples through all construction sites,
and `ensure_content_key_for_peer`'s return-value change cascades
through `create_encrypted_event`, test fixtures, and several test
harnesses. Doing it safely requires the full test suite passing at
each commit boundary; rushing it risks breaking the tree and
leaving a half-migrated state that blocks other work.

This plan captures the design so a focused follow-up session can
execute it in bounded, reviewable steps.
