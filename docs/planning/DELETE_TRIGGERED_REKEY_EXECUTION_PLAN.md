# Delete-Triggered Rekey Execution Plan (revised)

## Objective

Make message deletion drive key rotation so that, after a bounded grace
window, no key material on any honest peer's disk can decrypt the deleted
content. The mechanism must:

1. Handle concurrent deletes (multiple admins, multi-device authors)
   without coordination.
2. Handle Sends and rewraps that race with rotations: if peer P emitted a
   rewrap under a sibling rotation that turns out to be the loser of a
   tiebreaker, the loser key must STILL become purgeable. Otherwise the
   loser's rewrap of a (later-tombstoned) message is an FS hole.
3. Reuse the existing `key_rotation` / `key_shared` / `key_history`
   machinery; add the smallest set of new rules.

This plan is the mechanical half of the Forward Secrecy plan. FS needs
"old keys eventually become unrecoverable" plus "ciphertext copies of
deleted content eventually become unrecoverable"; this plan delivers
both.

## Scope

### In scope
- New event type **`Rewrap`** that carries new ciphertext under a new key
  but inherits the *logical id* of the original message; unsigned;
  validated by inner-signature check.
- Cascade purge of tombstoned messages enumerates by logical id, so all
  rewraps under all keys are removed by a single MessageDeletion.
- Canonical-rewrap-only invariant: per logical message, only the rewrap
  under the current canonical key is retained on disk; non-canonical
  rewraps are GC'd.
- Quiescent KeySecret purge with grace, counting **canonical** referents
  only.
- Per-file symmetric key embedded in the message descriptor, so message
  rewrap covers all attached file slices without re-encrypting slice
  bytes.
- Optional informational `triggered_by_event_ids[]` field on
  `KeyRotation` for audit / heal-loop "stuck deletion" detection.
  Non-load-bearing — no protocol-level dep.

### Out of scope
- Forward secrecy beyond what rotation-on-delete enables; see separate FS
  plan.
- Changes to `message_deletion` authorization (still author OR admin).
- Changes to the existing removal-frontier semantics of `KeyRotation`
  (those keep working unchanged).
- A protocol-level dep between `MessageDeletion` and `KeyRotation`
  (rejected after codex review — created a dep cycle and forced a
  wire-incompatible field add). The deleter's client emits both events
  atomically, but they have no protocol coupling.

## Architecture today

Relevant files on this branch (`cli-key-heal-after-removal-20260416`):

- `src/event_modules/key_rotation.rs` — `KeyRotation` (type 32) carries a
  fixed-4 removal-frontier and recipient-slot wrapped keys; signer
  required; `rotated_by == current_signer` check at lines 205-208.
- `src/event_modules/message_deletion/projector.rs:44-174` — tombstone
  only; auth at lines 61-71. Wire is fixed 41-byte layout
  (`message_deletion/wire.rs:19`); cannot grow without a new
  type/version.
- `src/event_modules/encrypted.rs` — AES-256-GCM with random 12-byte
  nonce, 16-byte tag.
- `src/event_modules/file_slice/projector.rs:83` — slice key MUST match
  descriptor's `key_event_id`; this is what makes attachments tied to
  the epoch key today.
- `src/event_modules/key_history.rs` — bulk archive bundle; immutable on
  wire, distributed at join.
- `src/state/projection/encrypted.rs:35-40` — `Encrypted` returns
  `Block` when `KeySecret` dep is missing; retry via
  `RetryBlockedEncryptedByKey`.
- `src/runtime/key_repair.rs:121-158` — periodic heal loop;
  natural home for canonical-rewrap GC and quiescent purge scans.

## Core design

### D1. New event: `Rewrap` (logical-id-inheriting, unsigned)

New event type `Rewrap` (next available id after `KeyHistory = 36`).

Wire fields:
- `original_event_id: [u8; 32]` — the logical id this rewrap inherits.
- `new_key_event_id: [u8; 32]` — the `KeySecret` the new ciphertext is
  encrypted under.
- `nonce: [u8; 12]` — derived deterministically as
  `blake3("poc7-rewrap-nonce-v1" || original_event_id ||
  new_key_event_id)[..12]`. Stored explicitly for forward-compat against
  derivation changes.
- `ciphertext: variable bytes` — AES-256-GCM ciphertext of the same
  inner plaintext as the original Encrypted, under `new_key_event_id`,
  with the derived nonce. Plus 16-byte tag.

No outer signature.

**Logical id inheritance.** The wire-level event id of a `Rewrap` is the
content hash of its bytes (standard); but at projection, the logical
identity for downstream tables is `original_event_id`. The
`messages` / `reactions` / `files` rows keyed by `original_event_id` can
have multiple ciphertext blobs associated with them (the original plus
N rewraps). The "currently-decryptable-under" pointer is recomputed as
new rewraps arrive.

**Authority.** Rewraps inherit signature authority from the original
event. Validation rule:
1. Look up `original_event_id`; require it to exist in the events table.
2. Decrypt `ciphertext` with `KeySecret(new_key_event_id)`.
3. Verify the resulting plaintext is a signed inner event from the
   original's claimed author (standard signed-inner-event verification).
4. Optionally cross-check against the original's plaintext if both keys
   are locally present (defense-in-depth, not required).

If validation fails, reject the rewrap as untrusted. Determinism (D3)
ensures honest re-emitters all produce byte-identical rewrap events, so
content-addressed event ids dedupe naturally; a forgery has a different
event id and is rejected on validation.

### D2. Cascade purge by logical id

Extend the existing tombstone cascade. When `MessageDeletion(M)` is
projected:
1. Tombstone logical id `M` (existing).
2. Cascade-purge from disk every `Encrypted` event AND every `Rewrap`
   event whose logical id is `M`. (Today's cascade only sees the
   original event; this extends the enumeration to include rewraps
   indexed by `original_event_id`.)
3. Existing reactions / message_attachment cascade rules continue
   unchanged.

Result: a single MessageDeletion removes every on-disk ciphertext copy
of M, on every honest peer that observes the tombstone. Even rewraps
emitted under sibling-loser rotations are removed.

### D3. Canonical-rewrap-only invariant

For each logical message M, retain only the rewrap (or original) under
the current **canonical key**. Canonical key = the highest-precedence
known rotation in the rotation DAG, where precedence is defined by the
sibling tiebreaker (lowest event id wins among siblings sharing a
parent).

GC pass (runs in `key_repair` heal loop on each rotation observation):
1. For each logical message M with multiple ciphertext copies (original
   plus rewraps), compute the canonical key K_canon for M's view.
2. If a non-canonical-key copy exists for M, purge it from disk.
3. Note: this is a local-only purge; rewrap events themselves are not
   retracted on the wire. The on-disk blob is removed, but the event
   may resurface during sync — projection re-applies the GC
   immediately.

Effect: loser-key rewraps of live messages become inert (no disk copy);
loser keys lose their last live referent → eligible for D5 purge.

### D4. Concurrent rotation siblings

Two concurrent `KeyRotation` events with the same parent rotation are
**siblings**. Tiebreaker: the rotation with the lowest event id is
canonical. The loser's KeySecret is distributed via `KeyShared` like
any other (the wire bandwidth is not recovered), but no peer
re-encrypts to the loser's key after observing the winner.

Pre-tiebreaker rewraps (peers that emitted under the loser before
observing the winner) are cleaned by D3.

A subsequent rotation may name both siblings as parents in its
`triggered_by_event_ids[]` (D7) for audit visibility, but is not
required for convergence.

### D5. Quiescent KeySecret purge counting canonical referents

Replace D5 from the prior draft. KeySecret K is eligible for purge
when:
1. K has been superseded by a newer rotation (recorded via
   `superseded_at_ms` local column).
2. **No live message has K as its canonical key.** (Computed from the
   per-logical-message canonical-key index — see Required
   infrastructure.)
3. Grace window has elapsed since (1).

Critically: condition (2) does not require non-canonical rewraps to be
removed from disk. A K7 rewrap of message m3 that's been demoted to
non-canonical is GC'd by D3, but even if a peer's GC hasn't yet fired,
that rewrap is not counted as a live referent of K7.

Periodic scan in `key_repair` deletes the `key_secrets` row when all
three conditions hold.

### D6. Per-file key in message descriptor

Today: file slices are encrypted under the epoch `KeySecret`
referenced by the descriptor's `key_event_id`
(`file_slice/projector.rs:83` enforces match). Slices already
*structurally* depend on the descriptor (the slice projector blocks
until the descriptor is valid), so the descriptor is the natural
carrier for slice key material.

Proposed:
- Each file gets a fresh symmetric key F_k generated at upload time.
- All slices of the file are encrypted under F_k (independent of any
  epoch key).
- The descriptor (embedded in the attaching `message` plaintext)
  carries F_k in a new field.
- `file_slice/projector.rs:83` is updated to validate slice ciphertext
  against descriptor's F_k. The existing slice→descriptor dep already
  guarantees the validator has F_k available at projection time.

When the message is rewrapped under a new epoch key, F_k travels in
the new rewrap's plaintext unchanged. Slice ciphertext stays as-is.
**No slice-byte re-encryption is ever needed**, regardless of how
many rotations occur.

When the message is tombstoned, F_k becomes unrecoverable (the
descriptor lives in the message plaintext, which is cascade-purged).
Existing slice-cascade logic continues to purge slice bytes from disk.

Migration: old descriptors without F_k continue to work via the
legacy "slice key == epoch key" path; new descriptors use F_k. New
uploads always emit F_k-bearing descriptors; rotation only rewraps
F_k-bearing messages, never touches slice bytes.

### D7. `triggered_by_event_ids[]` informational field

Add optional `triggered_by_event_ids: Vec<[u8; 32]>` to `KeyRotation`
(wire change, but additive — needs new wire version of KeyRotation or
extension via existing variable-length area).

Semantics: emitter populates with deletion / removal event ids that
prompted this rotation. Non-load-bearing: not used for current-key
selection, not used for repair authorization, no dep is created on
these ids.

Use cases:
- **Audit**: peers can see which deletes drove which rotations.
- **Stuck-deletion detection**: `key_repair` periodically scans
  recently-tombstoned messages and checks whether any rotation observed
  in the same window names them in `triggered_by_event_ids`. If a
  deletion has no covering rotation after `T_catchup`, the heal loop
  emits a catch-up rotation. Prevents a buggy/offline deleter from
  leaving old key material around indefinitely.

### D8. Decoupled `MessageDeletion` and `KeyRotation`

The deleter's client emits both events atomically (`MessageDeletion` +
`KeyRotation`), but the protocol has **no dep between them**.
`MessageDeletion` is a pure tombstone; `KeyRotation` is independent.

This avoids:
- The dep cycle codex flagged
  (`required_rotation_event_id` ↔ `frontier_refs`).
- Wire incompatibility from adding a field to the fixed-41-byte
  `MessageDeletion`.

FS guarantee comes from D1+D2+D3+D5, not from a protocol-level
binding. D7's stuck-deletion detection plus client-side
emit-both-atomically gives the operational guarantee that deletes
typically drive rotations.

## Required infrastructure (new)

### State indices
- `encrypted_transport_index` (new, per tenant): row per
  (logical_id, key_event_id) pointing at the on-disk Encrypted/Rewrap
  blob. Required for D2 enumeration (find all rewraps of a logical id)
  and D3 enumeration (find all non-canonical rewraps for a logical id).
  Replaces today's "scan raw event blobs" approach
  (`encrypted.rs:182`).
- `canonical_key_for_message` (new, per tenant): single column update
  per logical id when a new rotation makes a different key canonical.
  Used by D5 referent count.
- `key_referent_count` (derived view or maintained counter): live
  canonical referents per `KeySecret`. Drives D5.

### Triggers
- On `KeyRotation` projection: emit `RecomputeCanonicalKeys` signal →
  scan messages whose canonical key is now superseded → pick new
  canonical → emit `Rewrap` events for those whose canonical key
  differs from existing on-disk blob.
- On `Rewrap` projection: update `encrypted_transport_index`,
  recompute canonical pointer for the logical id, GC non-canonical
  on-disk blobs.
- On `MessageDeletion` projection: cascade purge using
  `encrypted_transport_index`.

## Event layer changes

- **New event**: `Rewrap` (D1).
- **`KeyRotation`**: optional `triggered_by_event_ids[]` field (D7).
  Wire bump (new sub-version) since the format changes.
- **Message descriptor**: new `file_key: [u8; 32]` field (D6).
- **`MessageDeletion`**: **no change** — wire stays 41 bytes.
- **`Encrypted`**: no change.
- **`key_secrets` table**: add `superseded_at_ms BIGINT NULL`.
- **New table**: `encrypted_transport_index`.
- **New table or column**: `canonical_key_for_message`.

## Projection changes

- New `rewrap/projector.rs`:
  - Validate (D1: lookup original, decrypt, verify inner signature).
  - Insert into `encrypted_transport_index`.
  - Recompute `canonical_key_for_message` for the logical id.
  - GC non-canonical on-disk blobs for the logical id.
- `key_rotation.rs` projector:
  - Existing logic unchanged.
  - Emit `RecomputeCanonicalKeys { affected_keys }` signal post-apply.
- `message_deletion/projector.rs`:
  - Existing tombstone logic unchanged.
  - Cascade enumerates `encrypted_transport_index` by logical id and
    purges all rewrap blobs.
- `file_slice/projector.rs`:
  - Validate slice ciphertext against descriptor's F_k (new) or fall
    back to epoch key (legacy).
- `key_repair.rs`:
  - Handle `RecomputeCanonicalKeys`: scan affected messages, emit
    `Rewrap` events under the new canonical key.
  - New periodic task: KeySecret purge per D5.
  - New periodic task (if D7 informational adopted): stuck-deletion
    detection → emit catch-up `KeyRotation`.

## Testing plan

1. Unit: derived-nonce determinism — two peers independently re-encrypt
   the same inner under the same new key; output bytes match; logical
   id derived from `original_event_id` matches.
2. Unit: rewrap with mismatched inner signature is rejected.
3. Unit: cascade purge by logical id removes all rewraps including
   under loser keys.
4. Unit: canonical-rewrap GC removes a demoted-non-canonical rewrap on
   sibling tiebreaker resolution.
5. Sim: concurrent admin + multi-device delete in same epoch → two
   sibling rotations → some peers re-encrypt under loser before
   tiebreaker resolves → after sync convergence, loser key has zero
   canonical referents and is purged.
6. Sim: late-syncing offline sender — emits Send under (now-superseded)
   K_old → upon sync, observes rotation, emits rewrap under canonical
   key → original Send remains on wire but on-disk K_old blob is GC'd
   as non-canonical.
7. Sim: delete-without-rotation (catch-up case) — `MessageDeletion`
   alone, no atomic rotation; heal loop's stuck-deletion detector
   emits catch-up rotation within `T_catchup`.
8. Sim: file with attachments — rotate epoch key → message rewrapped →
   F_k unchanged in new rewrap → slices remain decryptable; on
   tombstone → message + descriptor + slices all cascade-purged.
9. CLI end-to-end: delete → rotation → rewrap → quiescent purge
   observable in DB; on-disk inspection at T+grace shows no decryptable
   ciphertext for the deleted message.

## Open questions (for codex re-review)

1. `Rewrap` event projection model: the "logical id is `original_event_id`"
   semantics differ from every other event in the system. Is there a
   simpler refactor that achieves the same end (e.g., a separate
   `encrypted_transport` table where rows are keyed by
   (logical_id, key_id) and event ids are just transport
   identifiers)? Worried we're inventing a new identity model just for
   rewraps.
2. Validation requires the `KeySecret(new_key_event_id)` to be present
   to decrypt + verify. If a peer receives a rewrap before it has the
   key (key_shared / key_history pending), how should it handle
   validation? Block on key dep, like existing Encrypted does? Yes
   probably — proposed: identical to existing `Encrypted` block-on-key
   semantics.
3. `triggered_by_event_ids[]` requires a wire bump on `KeyRotation`.
   Acceptable, or should we introduce a separate "rotation cause"
   event that links sideways without changing the rotation wire?
4. File descriptor `file_key`: currently descriptor wire is fixed
   layout. Is adding F_k acceptable, or does it require a new
   descriptor variant (and therefore a new file event type variant)?
5. The canonical-key index needs to be recomputed on every rotation
   observation. Cost concern in workspaces with high rotation cadence
   (FS plan increases this). Worth pre-computing or caching? Sim test
   should measure.
6. Stuck-deletion detection (D7 use case) emits a catch-up rotation;
   what's the policy for who emits — any signer, designated heal
   leader, or admin only? Want to avoid every peer emitting redundant
   catch-up rotations.
7. Codex earlier flagged that `KeyHistory` bundles are immutable and
   carry raw key bytes. This plan doesn't address them; they remain a
   concern that the FS plan must handle (via short-lived wrap pubkeys
   so the bundles become unwrappable post-grace). Confirm acceptable
   to defer.

## Success criteria

- Every encrypted message is followed by a rotation within one
  projection cycle when the deleter's client behaves correctly; within
  `T_catchup` even if the deleter's client misbehaves (D7).
- No sim scenario produces an undecryptable live message after a
  rotation.
- After T+grace, no honest peer's local state contains any decryptable
  ciphertext for a deleted message — verified by a sim "compromise
  test" that dumps all on-disk keys + ciphertext.
- Loser sibling keys are purged within `grace` of the canonical winner
  being observed network-wide (counted via canonical referents per
  D5).
- Concurrent deletes never produce a logical message with multiple
  on-disk canonical ciphertexts.
- File slice bytes are not re-encrypted on epoch rotation; only the
  descriptor (containing F_k) is rewrapped via the message rewrap.

## Dependencies

- None upstream. Plan can land first; FS plan builds on top.
- Coexists with the active keyrepair work on this branch — the new
  rewrap projector and canonical-rewrap GC join the same heal loop.
- The canonical-key index and `encrypted_transport_index` are new
  state-layer infra; plan their migration alongside this work.
