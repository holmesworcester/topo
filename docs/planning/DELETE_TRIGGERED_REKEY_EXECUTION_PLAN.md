# Delete-Triggered Rekey Execution Plan

## Objective

Make message deletion drive key rotation so that a deleted message's key
can be purged after a bounded grace window. The mechanism must:

1. Handle concurrent deletes (multiple admins, or a multi-device author)
   without requiring any coordination.
2. Handle sends that race with rotations — a sender who has not yet
   delivered a concurrent rotation continues to emit under the superseded
   key, and those messages must still end up decryptable by current
   members.
3. Reuse the existing `key_rotation` / `key_shared` / `key_history`
   machinery; add the smallest set of new rules needed.

This is the mechanical half of the Forward Secrecy plan. FS needs
"old keys eventually become unrecoverable"; this plan delivers the
"old keys can be purged" property, so FS's purge grace becomes meaningful.

## Scope

### In scope
- `message_deletion` emits (or binds to) a `key_rotation` that supersedes
  the current epoch key.
- Any member with decryption access re-encrypts survivor messages under
  the new key via deterministic, content-addressed re-emission.
- Projector dedupes re-encryption output on content-address.
- Old `KeySecret` becomes eligible for purge once no live `Encrypted`
  event references it (quiescence-driven, not event-driven).
- Concurrent-delete sibling handling (tiebreaker + eventual union).
- Late-send coverage: when an owner syncs a rotation that occurred after
  its send, it (or any observer) re-encrypts the send under the new key.

### Out of scope
- Forward secrecy beyond what rotation-on-delete enables; see separate FS
  execution plan.
- Changes to `message_deletion` authorization (still author OR admin).
- Encrypted `file_slice` re-encryption; deferred to a phase-2 follow-up.
- Any change to the removal-driven rotation path (it keeps working as-is).

## Architecture today

Relevant files on this branch (`cli-key-heal-after-removal-20260416`):

- `src/event_modules/key_rotation.rs` — `KeyRotation` (type 32) binds to
  `frontier_hash = H(sorted(removal_event_ids))` and carries
  `rotated_by`. Projector validates `rotated_by == current_signer`
  (lines 205-208).
- `src/event_modules/message_deletion/projector.rs:44-174` — tombstone
  only; auth at lines 61-71 (author or admin). No rekey today.
- `src/event_modules/encrypted.rs` — AES-256-GCM with **random 12-byte
  nonce**, 16-byte tag.
- `src/state/projection/encrypted.rs:35-40` — `Encrypted` returns `Block`
  when `KeySecret` dep is missing; retry is driven by
  `RetryBlockedEncryptedByKey`.
- `src/event_modules/key_shared.rs`, `src/event_modules/key_request.rs` —
  already use deterministic `delivery_target_id = blake3(params)` so
  multiple emitters converge on identical events.
- `src/runtime/key_repair.rs:121-158` — periodic heal loop that emits
  `KeyRequest`/`KeyShared`. This is where scheduled rekey and
  re-encryption work belongs.

## Design

### D1. Extend `KeyRotation` frontier to cover deletions

Today: `frontier_hash = H(sorted(removal_event_ids))`.
Proposed: `frontier_hash = H(sorted(removal_event_ids ∪
deletion_event_ids))`.

No wire change to `KeyRotation` — `frontier_refs` is already a
variable-length list of event ids; deletion refs sit alongside removal
refs. Frontier-hash derivation extended in `key_rotation.rs`
projector.

Alternative considered: a separate `DeletionRotation` event type. Rejected
because observers would need two rotation-successor graphs and peer
logic would fork into parallel paths.

### D2. `MessageDeletion` binds to a new rotation

Add field `required_rotation_event_id: [u8; 32]` to `MessageDeletion`.

Semantics:
- The deleter's client constructs BOTH a `KeyRotation` advancing the
  frontier (with this deletion in its `frontier_refs`) AND a
  `MessageDeletion` referencing that rotation's event id.
- `message_deletion` projector blocks the deletion on
  `required_rotation_event_id` if the rotation is not yet valid (standard
  dep-blocking machinery).
- Projector rejects the deletion if the referenced rotation's
  `frontier_refs` does not contain this deletion's own event id.

The atomic pair (rotation + deletion) guarantees you never observe a
deletion in valid state without a corresponding rotation.

Migration: existing tombstones carry the zero id and are treated as
"legacy, no rotation." No back-fill.

### D3. Deterministic re-encryption rule

New handler in `key_repair.rs`, driven by a `RekeyEncryptedSuccessors
{ old_key_id, new_key_id }` signal emitted when a `KeyRotation` applies.

For every `Encrypted` event E under `old_key_id` where:
- E's inner message is not tombstoned,
- this peer has `KeySecret(old_key_id)` (can decrypt) AND
  `KeySecret(new_key_id)` (can re-encrypt),

emit `E' = re-encryption of E.inner under new_key_id`.

**Determinism: derived-nonce.**
`nonce' = first 12 bytes of blake3("poc7-rekey-nonce-v1" ||
inner_event_id || new_key_event_id)`.

Same inner plaintext + same new key ⇒ same ciphertext bytes ⇒ same outer
event id. Any number of re-emitters produce byte-identical events;
content-addressing naturally dedupes at ingest.

Alternative considered: random nonce + projector first-writer-wins on
(inner_event_id, new_key_event_id). Easier implementation (no change to
`encrypt_event_blob`), but wastes bandwidth until dedupe kicks in and
breaks the "event id is a hash of bytes" invariant elsewhere. Rejected.

### D4. Concurrent rotations: sibling handling

Two concurrent deletes each mint a `KeyRotation` rooted at the same
prior frontier. Neither dominates; both are valid in the DAG.

- A peer that observed only rotation A re-encrypts survivors to A's new
  key. A peer that observed only B re-encrypts to B's new key. A peer
  that observed both picks the **lowest event id** as the re-encryption
  target (tiebreaker), to minimize wasted work.
- A later rotation naming both A and B in its `frontier_refs` unifies
  the DAG. Observers re-encrypt forward to the union successor.
- Sibling-loser re-encryptions (if any got emitted before the winner was
  observed) become orphan `Encrypted` events whose `key_event_id` has no
  live referents going forward; they get purged when the loser's key is
  purged (D5).

No merge event is required — the next naturally-occurring rotation
(next delete or scheduled) subsumes siblings.

### D5. Quiescence-driven `KeySecret` purge

`KeySecret` K is eligible for purge when:
1. A successor `KeyRotation` exists whose frontier strictly extends K's
   frontier (K is superseded).
2. No valid `Encrypted` event references K.
3. A configurable grace window has elapsed since (1).

Implementation:
- Add local column `superseded_at_ms` to `key_secrets` (no wire impact).
- Set on projection of a superseding rotation.
- Periodic scan in `key_repair.rs`: query superseded + no-referent +
  grace-elapsed, delete.

The rotation and `KeyShared` events stay; only the raw secret material
is removed. That is the cryptographically-relevant step for FS.

### D6. Late-send coverage

Scenario: D2 sends m4 under `K_old`. Admin concurrently emits
`MessageDeletion` + `KeyRotation K_old → K_new`. D2 syncs later.

With D3 in place:
1. D2 receives the `KeyRotation` and receives `KeyShared(K_new)`
   (already handled by heal loop + key_shared distribution).
2. D2's local re-encryption scan discovers its own `Encrypted(m4,
   K_old)` and emits the derived-nonce re-encryption.
3. Any other peer with both keys produces byte-identical output;
   content-addressing dedupes.
4. Once all observers have processed, `K_old` has no live referents and
   becomes eligible for purge (D5).

The original `Encrypted(m4, K_old)` is retained as-is; it is not
retracted. Its payload is recoverable via the new event under `K_new`
until `K_old` is purged, after which only the new event remains
decryptable.

## Event layer changes

- `MessageDeletion` wire: add `required_rotation_event_id: [u8; 32]`.
  Durable `type_name` unchanged.
- `KeyRotation` wire: unchanged; `frontier_refs` contract extended to
  include deletion event ids.
- `Encrypted` wire: unchanged; nonce derivation is a sender-side detail.
- `key_secrets` table: add `superseded_at_ms BIGINT NULL`.

## Projection changes

- `message_deletion/projector.rs`:
  - Block on `required_rotation_event_id` not yet valid.
  - Reject if referenced rotation's frontier does not include this
    deletion.
  - Otherwise, existing tombstone flow.
- `key_rotation.rs` projector: on apply, emit
  `EmitCommand::RekeyEncryptedSuccessors { old_key_id, new_key_id }`
  (new variant).
- `key_repair.rs`:
  - Handle `RekeyEncryptedSuccessors`: scan encrypted events, produce
    derived-nonce re-encryption events.
  - New periodic task: `KeySecret` purge per D5.
- `encrypted.rs` (`encrypt_event_blob`): accept an optional
  "rekey source" arg that supplies (inner_event_id, new_key_event_id);
  when present, derives nonce instead of randomizing.

## Testing plan

1. Unit: derived-nonce determinism — two peers independently re-encrypt
   the same inner under the same new key; output bytes match.
2. Unit: legacy removal-only rotations still pass validation; mixed
   frontier (removal + deletion) validates.
3. Unit: `MessageDeletion` rejected when referenced rotation does not
   include the deletion in its frontier.
4. Sim: concurrent admin + multi-device delete of different messages in
   the same epoch → two sibling rotations → later observation of both →
   survivors decrypt under the winner → losers eventually purged.
5. Sim: offline sender's race — sender comes online, receives rotation,
   re-encrypts own pending send; `K_old` purged after grace with no live
   referents.
6. Sim: tombstoned message's `Encrypted` is never re-encrypted (save
   bandwidth).
7. CLI end-to-end: delete → rotation → re-encryption → purge observable
   in database.

## Open questions (for codex)

1. Should `MessageDeletion` + `KeyRotation` always be constructed
   together client-side, or is a service-level "deletion signal → heal
   loop emits rotation" decomposition acceptable? Current plan assumes
   client-constructs-both for self-containment.
2. Derived nonce vs random-nonce + projector dedupe — is there a code
   path I'm missing (e.g., non-repudiation, analytics) that relies on
   nonce randomness? Assumes none.
3. Legacy tombstones with zero `required_rotation_event_id`: accept as
   "legacy, no rotation" indefinitely, or plan a one-time migration?
4. Encrypted file slices: batch the re-encryption (O(slice count per
   message)) or defer to a follow-up plan? Leaning defer.
5. Should `RekeyEncryptedSuccessors` work recursively if a newer
   rotation overtakes the one being processed (multi-generation catch-up
   on a just-onlined peer)? Plan assumes yes via the natural iterative
   rule (re-encrypt to newest known key each pass).

## Success criteria

- Every delete of an encrypted message is followed by a rotation within
  one projection cycle; no manual operator step.
- No sim scenario produces an undecryptable live message after a
  rotation.
- `KeySecret` for an old epoch is purged within `grace` seconds of the
  last survivor being re-encrypted.
- Concurrent deletes produce exactly one canonical re-encryption per
  message per successor key (verified via content-addressed event ids).
- Bandwidth overhead of deterministic re-emission is bounded by `N *
  epoch_size` with dedupe; not `N_members * epoch_size`.

## Dependencies

- None upstream. This plan can land first; FS builds on top.
- Coexists with the active keyrepair work on this branch — the new
  re-encryption scan joins the same heal loop.
