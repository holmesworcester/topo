# Per-Message FS via Split Key Distribution Events (Plan 1 v4)

## Objective

Forward secrecy for **deleted** and **TTL-expired** messages, with no rekey
step, within the existing dep/cascade substrate.

Threat model:
- Honest-peer compromise at `T + grace` MUST NOT recover plaintext of any
  message deleted (or TTL-expired) before `T − grace`.
- Live-message FS is NOT a goal.
- Malicious peers retaining ciphertext and compromised long after the fact
  are OUT OF SCOPE.

Design goals:
- Minimal ruleset; no rewrap chains, no rotation chains, no multi-step
  rekey protocols.
- Reuse standard `BlockOnMissingDeps` and `cascade_unblocked()` for all
  key-to-message dep resolution.
- Every encrypted message has its own independent key; individual purge
  suffices for individual FS.

## Event types

### 1. `key_broadcast` (bulk fanout; retargeted `KeyRotation`)

Land as `src/event_modules/key_broadcast/`.

Fixed-shape wire event: **8192 recipient-wrap slots, 1 `K_bundle`, 0
historical slots**. Full event stays in the ~524 KB-class budget that
matches master's capped bulk key fanout.

Fields:
- `bundle_id: [u8;32]` — identifier for the delivered `K_bundle`.
- `recipient_wrap_slots: [8192]` — each populated entry is
  `(recipient_WrapPubkey_event_id, asymmetric_wrap(recipient_pubkey, K_bundle))`;
  unused slots are zero/sentinel-filled.
- Signer-required for authorization/audit only; content integrity
  comes from deterministic payload bytes.

Projection:
- No event-level dep on `WrapPubkey`.
- Each peer locally scans slots against `wrap_privkeys`. On successful
  unwrap: emit deterministic local `KeySecret(K_bundle)` with event id
  `blake3("poc7-content-key-created-at-v1" || K_bundle_bytes)`.
- This is **one of three producers** that can materialize the same
  deterministic local `KeySecret(K_bundle)` for blocked `message_key`s.

### 2. `key_history_bundle` (bootstrap fanout; retargeted `KeyHistory`)

Land as `src/event_modules/key_history_bundle/`.

Fixed-shape wire event: **1 recipient wrap, 8192 historical-bundle
slots**. Byte budget is again ~524 KB-class: one recipient wrap plus
the capped 8192 historical slots.

Fields:
- `bundle_id: [u8;32]` — the anchor/current `K_bundle` used to open
  the history payload.
- `recipient_WrapPubkey_event_id: [u8;32]`.
- `wrapped_k_bundle` — `asymmetric_wrap(recipient_pubkey, K_bundle)`.
- `historical_bundle_slots: [8192]` — each populated entry is
  `(historical_bundle_id, AEAD_encrypt(K_bundle, historical_K_bundle_bytes))`;
  unused slots are zero/sentinel-filled.

Projection:
- Recipient unwraps the anchor `K_bundle` via their `wrap_privkeys`
  privkey, emits the deterministic local `KeySecret(K_bundle)` for
  `bundle_id`, then AEAD-decrypts each populated historical slot.
- For each successfully decrypted historical slot, emit the
  deterministic local `KeySecret(historical_K_bundle)` keyed by that
  bundle's bytes.
- For any given bundle `B`, this producer must materialize the same
  local `KeySecret(B)` event id that `key_broadcast(B)` or
  `key_shared(B)` would produce.

### 3. `key_shared` (targeted heal; retargeted `KeyShared`)

Land as `src/event_modules/key_shared/`.

Fixed-shape wire event: **1 recipient wrap, 1 `K_bundle`, 0 historical
slots**. Expected wire size is small: ~150-200 bytes including the
normal signed envelope overhead.

Fields:
- `bundle_id: [u8;32]`.
- `recipient_WrapPubkey_event_id: [u8;32]`.
- `wrapped_k_bundle` — `asymmetric_wrap(recipient_pubkey, K_bundle)`.

Projection:
- Exactly the same unwrap rule as `key_broadcast`, just
  single-recipient.
- On successful unwrap, emit the **same deterministic local
  `KeySecret(K_bundle)`** event id as the bulk and bootstrap producers.

### 4. `key_request` (retargeted `KeyRequest`)

Land as `src/event_modules/key_request/`.

Small fixed-size event.

Fields:
- `bundle_id: [u8;32]` — the `K_bundle` the requester is missing.
- `requester_wrappubkey_event_id: [u8;32]` — the requester's current
  `WrapPubkey`.

Semantics:
- Fired when a peer has one or more `message_key`s blocked on local
  `KeySecret(K_bundle)` and lacks any producer path that can
  materialize it locally.
- Response is `key_shared`, **not** `message_key`, and **not** a new
  bulk `key_broadcast`.

### 5. `message_key` (per-message, carries the per-message K_m wrap)

Small fixed-size event.

**Per-device bundle lineage invariant.** Each sender device emits its
own stream of `key_broadcast` rotations — its bundles are distinct
from other devices'. When a device sends a message, it generates a
**fresh unique K_m** for that message (never reused across messages)
and wraps it under **that device's own current K_bundle** (the most
recent non-superseded `key_broadcast` the sender device emitted).
Every message is therefore bound to: (a) a K_m unique to this
message, and (b) the sender device's current bundle at send time.
Receivers track per-device bundle streams independently; unwrap paths
always resolve via the sender's bundle lineage.

Fields:
- `bundle_id: [u8;32]` — the `K_bundle` identity (sender device's
  current bundle at send time).
- `k_bundle_local_event_id: [u8;32]` — **blocking dep** on the
  deterministic local `KeySecret(K_bundle)` event id
  (`blake3("poc7-content-key-created-at-v1" || K_bundle_bytes)` style —
  see `key_secret.rs:62-84`). Stable regardless of which producer
  delivers K_bundle (`key_broadcast`, `key_history_bundle`, or
  `key_shared`).
- `owning_message_event_id: [u8;32]` — the `message` event this
  `message_key` is for. Enables tombstone-check on late arrival.
- `wrapped_k_m: [u8; ~48]` — `AEAD(K_bundle, K_m)`.
- Deterministic: same `(K_bundle, K_m, owning_message_event_id)` + fixed
  derivation nonce → byte-identical event. Any emitter produces the
  same event_id; dedupe via content-address.

**Send-time sender invariant.** When a sender device emits a
`message`, the runtime must:
1. Resolve the sender device's current `K_bundle` (its latest
   non-superseded bundle).
2. Generate a fresh random `K_m` never used by any prior message from
   this device.
3. Wrap K_m under the current K_bundle → `wrapped_k_m`.
4. Emit `message_key(bundle_id, …, wrapped_k_m)` alongside the
   `message` event.

Projection:
- Before materializing `K_m`: check `deleted_messages` for
  `owning_message_event_id` (`decision_context.rs:1272-1295`). If
  present, **self-drop terminally** (see terminal-state contract
  below).
- Additionally, check `deletion_intents` for `owning_message_event_id`,
  but only treat intents whose signer is **currently admin** (verified
  against the admin table at projection time) as authoritative. An
  admin-signed deletion is authoritative even before the target message
  exists, so message_key must self-drop when an admin intent is
  present. Non-admin intents (author-claimed, pre-message-creation) are
  NOT authoritative because we cannot yet verify author identity —
  ignore them.

  The remaining exposure window — a `message_key` arrives before the
  owning message, materializes `K_m`, then the message arrives and is
  legitimately tombstoned — is tiny: message arrival and tombstone
  happen in the same projection transaction, which also cascade-purges
  `K_m`. During the window, no ciphertext blob is on disk for
  compromise to exploit.

**Terminal-state contract for self-drop.**
Self-drop is a **new terminal projection state** (call it
`DroppedOwnerTombstoned`), NOT `Valid` and NOT `Reject`. It must:
- Record a durable marker that `already_processed()`
  (`project_one.rs:70-80`, `backend.rs:340-359`) recognizes, so replays
  of the same `message_key` blob are suppressed and never re-try
  `K_m` materialization.
- Purge the `message_key` blob (row-delete), same as other terminal
  purges.
- NOT leave a dangling zero-dep blocked row; the state is fully
  terminal.

**Symmetric check on the message side.** `encrypted/projector.rs`
(Message projection) checks `deleted_messages` for its **own event_id**
BEFORE blocking on `message_key_event_id` or attempting decrypt. If the
message is itself tombstoned, message self-drops terminally (same
state). This covers the arrival order where the message arrives AFTER
having been tombstoned by a concurrent `MessageDeletion` — message
doesn't uselessly block on a `message_key` that will never arrive or
was itself dropped.

Combined, this closes the "deleted message, then late `message_key`,
then late message wrapper" replay case: every late arrival sees the
durable `deleted_messages` row and self-drops terminally.
- Otherwise: `BlockOnMissingDeps { missing:
  vec![k_bundle_local_event_id] }` if the local `KeySecret(K_bundle)`
  event is not yet Valid.
- When `KeySecret(K_bundle)` is Valid (materialized by ANY of
  `key_broadcast`, `key_history_bundle`, or `key_shared`): look up
  `K_bundle` bytes in `key_secrets` keyed by the local deterministic
  `k_bundle_local_event_id`. Decrypt `wrapped_k_m` → `K_m`. Insert
  `K_m` into `key_secrets` keyed by **`message_key_event_id`** (this
  event's own id). Transition to Valid. Cascade unblocks the owning
  `message`, which looks up `K_m` in `key_secrets` keyed by the same
  `message_key_event_id` from its outer header.

**Key lookup contract (explicit):**
- `key_secrets.event_id = k_bundle_local_event_id` → `K_bundle` bytes.
  Written by any successful key-distribution projector:
  `key_broadcast`, `key_history_bundle`, or `key_shared`.
- `key_secrets.event_id = message_key_event_id` → `K_m` bytes.
  Written by `message_key.project()` on successful unwrap.
- `message.project()` decrypts using `K_m` from
  `key_secrets WHERE event_id = message_key_event_id` (read from the
  outer header of the message event).
- Replaces the current overloaded
  `encrypted.key_event_id → key_secrets` contract cleanly — same
  lookup shape, just the identifier semantics change.

**Why this dep shape:** `message_key` depends only on the
deterministic local `KeySecret(K_bundle)` event id, never on a specific
wire-event id. That is the key property that keeps heal small: heal
does **not** re-wrap `message_key`; heal re-wraps `K_bundle` via
`key_shared`. Whether `K_bundle` arrived by bulk fanout
(`key_broadcast`), bootstrap history (`key_history_bundle`), or
targeted heal (`key_shared`), projection materializes the same local
`KeySecret(K_bundle)` event id, and cascade unblocks every waiting
`message_key` automatically.

### 6. `message` (Encrypted)

Existing Encrypted event shape, with one outer-header change:
- `message_key_event_id: [u8;32]` exposed **pre-decrypt** in the outer
  header so dep blocking can happen before the decryption stage.

Projection:
- `BlockOnMissingDeps { missing: vec![message_key_event_id] }` until
  `message_key` is Valid (i.e., until `KeySecret(K_m)` is locally
  materialized).
- On unblock: decrypt ciphertext with `K_m`, project inner as today.

### 7. `WrapPubkey` (short-lived, self-tombstoning)

Fields:
- `pubkey: [u8;32]` — curve25519.
- `valid_until_ms: u64`.
- Signer-required (signed by emitting peer's identity).

Semantics:
- Peer emits new `WrapPubkey` per cadence `T_wrap`.
- New emission from the same peer **tombstones prior `WrapPubkey`s from
  that peer** (self-tombstoning — only the latest is live).
- "Current" / "latest" `WrapPubkey` for a peer is defined
  deterministically under out-of-order replay as the max by
  `(created_at_ms, event_id)` among that peer's non-tombstoned emissions.
- No event-level deps on anything.

Privkey storage: on `WrapPubkey` emission, the emitting peer writes
`(pubkey_event_id, privkey, valid_until_ms)` into a new local table
`wrap_privkeys` at emit time. This is local device state, NOT derived
from event projection. Privkey purged at `valid_until_ms + grace`.

**Replay and sync ordering are non-concerns:** unwrapping a recipient
wrap from `key_broadcast`, `key_history_bundle`, or `key_shared` is a
purely local operation — the peer looks up each slot's
`recipient_WrapPubkey_event_id` in their own `wrap_privkeys` table. No
dependency on the `WrapPubkey` event's projection state on their side.
The emitter of any key-distribution event naturally has the
recipient's `WrapPubkey` (they can't reference what they haven't
seen); receivers never need the other peers' `WrapPubkey` events to
project at all.

### 8. `MessageDeletion` (existing, unchanged wire)

Pure tombstone. Authorization: author or admin (existing). Cascade
mechanism extended below.

## Dep graph

```
key_broadcast      ─┐
key_history_bundle  ├─> local KeySecret(K_bundle) ← message_key ← message
key_shared         ─┘
```

`key_request` is NOT a dep edge; it is the trigger that asks another
peer to emit `key_shared`.

All edges are standard `BlockOnMissingDeps` with named event ids. No
guard-block pattern. No shape-specific retry signal. Unblocking happens
through `cascade_unblocked()` (`state/projection/apply/cascade.rs`).

When `K_bundle` materialization occurs, the local `KeySecret` event's
`Valid` transition cascades to every `message_key` that named it; each
`message_key` then materializes its own `KeySecret(K_m)`, which cascades
to the corresponding `message`. Standard walk; nothing new.

## Dep-expiry: explicitly NOT introduced

We considered a dep-expiry mechanism (blocked events time out if their
deps never arrive). Rejected:
- Deletion/TTL paths already handle cleanup. A peer blocked on a
  never-arriving bundle will, when the underlying message is deleted or
  TTL-expires, get a `MessageDeletion` tombstone → cascade purge → blocked
  row gone.
- Pure "stuck forever" is a local resource concern, not a correctness or
  FS concern.
- Adding dep-expiry would introduce shared-validity issues (different
  peers expire at different times) and risk `rejected_events`
  short-circuiting self-healing later arrival via `already_processed()`
  (`backend.rs:340`).

## Deletion cascade (extends `purge.rs` hard-purge)

`MessageDeletion(M)` → tombstone (existing `deleted_messages` durable
schema at `message_deletion/mod.rs:25-45`), then hard-purge:

1. Extend the purge manifest in `purge.rs:125-258` to include `M`'s
   `message_key` via the outer-header `message_key_event_id` field on
   the `message` event itself (read directly from the message wire,
   not via a reverse index table — no ordering hazard).
2. Purge enumeration includes:
   - `M`'s outer Encrypted row (blob + row), as today.
   - `M`'s `message_key` row (blob + row), if present.
   - Local `KeySecret(K_m)` row (if materialized).
   - Existing reactions/files/file_slices cascade unchanged.
3. `message_key.project()` checks BEFORE materializing `K_m`:
   (a) `deleted_messages` for `owning_message_event_id` (lookup
   surface `decision_context.rs:1272-1295`); self-drop if present.
   (b) `deletion_intents` for `owning_message_event_id`, filtered to
   admin-signed intents only (verified against admin table at
   projection time); self-drop if any admin intent present. Non-admin
   intents are ignored here (they cannot be authoritative before the
   target message exists). `deleted_messages` is durable and persists
   after hard purge (`message_deletion/mod.rs:25-32`;
   `purge.rs:346-470` does not touch it).

No reverse index table is needed. The bidirectional linking (`message`
→ `message_key_event_id` in outer header; `message_key` →
`owning_message_event_id` field) provides lookup in both directions
without any auxiliary state.

## TTL expiry drives deletion path

Messages carry TTL (via existing disappearing-messages settings). TTL
expiry locally emits a self-tombstone (local-only `MessageDeletion`-style
event with `ShareScope::Local` or equivalent) → same cascade as explicit
delete. No new mechanism; TTL-FS and delete-FS share one purge path.

## Bundle retention

`K_bundle` is local material (not a wire event). Retain locally until:
- All pointing `message_key`s are tombstoned, AND
- `max(grace, longest_remaining_TTL_of_any_pointing_message)` has
  elapsed.

Once both conditions hold, purge `K_bundle` from local key storage. Any
late-arriving `message_key` pointing at this bundle will fail to decrypt
and self-drop without materializing `K_m` — acceptable.

## `key_request` heal path (small, targeted)

Fires when: peer has one or more `message_key`s blocked on local
`KeySecret(K_bundle)` for `bundle_id` and does not currently have a
valid local producer path for that bundle.

Response: another peer who has `KeySecret(K_bundle)` locally AND
observes the requester's current `WrapPubkey` emits
`key_shared(bundle_id, requester_wrappubkey_event_id,
asymmetric_wrap(requester_pubkey, K_bundle))` — ~150-200 bytes on the
wire. `key_shared.project()` on the requester materializes the
deterministic local `KeySecret(K_bundle)` → cascade unblocks all
pending `message_key`s.

Existing `key_repair.rs:373-420, 709-757` heal-loop structure carries
over with minor changes — the heal target is now "missing
`KeySecret(K_bundle)`" rather than "blocked encrypted by
`key_event_id`". Request dedupe/ranking is retained from the current
capped-rotation repair machinery.

## Per-file key in descriptor (unchanged from prior)

Clean-replace the `File` wire format to include `file_key: [u8;32]`.
Slices encrypted under `file_key`, not the epoch key.
`file_slice/projector.rs:83` validates against descriptor's `file_key`.
Message rewrap / delete cascades naturally; slice bytes never
re-encrypted. See prior D6.

## Purge semantics (no storage split)

Keep `events.blob NOT NULL`. Purge is row-delete (existing pattern).
Services that load blobs by event_id must handle `NotFound`:

- `signer.rs:36` — cache `signature_valid` on events row at projection
  time; subsequent reads use cache.
- `backend.rs:362` — retries that reference purged rows return a
  "skip / dead" status.
- `key_repair.rs:641` — skip purged rows during heal scans.
- Sync (`range_session.rs:915-959`) — respond "blob unavailable" for
  purged rows; requester tries another peer or drops.
- `runtime/control/service.rs:297-316` — control / inspection paths
  assume the current `key_event_id` contract and need updates when the
  encrypted outer header shifts to `message_key_event_id`.
- `src/event_modules/layout/common.rs:33-46` and
  `verus-proofs/src/event_modules/encrypted.rs:20-69` — wire layout and
  formal seams that assume the current encrypted header contract.
- `src/event_modules/file_slice/projector.rs:83-89` — slice validation
  currently references the transport key id; must be retargeted at the
  descriptor's `file_key` under D6.
- `src/runtime/key_repair.rs:561-564` — the old encrypted-heal path
  (shape-specific retry) goes away along with
  `RetryBlockedEncryptedByKey`.

The touch surface is real; enumeration of impacted sites is part of
implementation scoping.

## Out of scope

- `events` / `event_blobs` table split (not needed for FS; row-delete
  works).
- Generic downward reference counting (direct outer-header field read
  suffices).
- Tree-structured bundles for per-leaf blank (future work; wire format
  should be future-proof).
- Rewrap transport / logical-id inheritance (no rekey primitive; not
  needed).
- Strong-FS-on-removal (removed peers keep what they locally
  materialized; `WrapPubkey` expiry cuts off further access).
- Classical ratchet / per-message ephemeral-key derivation.

## Infra summary (new state)

- New/retargeted key-distribution event types:
  - `key_broadcast`: 8192 recipient-wrap slots, 1 K_bundle. ~524
    KB-class bulk fanout. Retargets master's `KeyRotation`.
  - `key_history_bundle`: 1 recipient wrap + 8192 historical-bundle
    slots. ~524 KB-class bootstrap. Retargets master's `KeyHistory`.
  - `key_shared`: 1 recipient wrap, 1 K_bundle. ~150-200 bytes
    targeted heal. Retargets master's `KeyShared`.
  - `key_request`: small request signaling missing K_bundle.
    Retargets master's `KeyRequest`.
- New event types:
  - `message_key`: per-message K_m wrap, deterministic-unsigned.
  - `WrapPubkey`: short-lived, self-tombstoning, used for ALL wraps.
- New local table: `wrap_privkeys`. (No reverse index table — the
  bidirectional linking via outer-header fields on `message` and
  `message_key` covers both directions.)
- Existing `key_secrets` continues to hold materialized K_bundle +
  K_m values. Three distinct producer projectors can materialize the
  same deterministic local `KeySecret(K_bundle)` row.
- Cached `signature_valid` column on `events` row.
- Removed: `RetryBlockedEncryptedByKey` emit variant and its handler
  (cascade-normalized under D8).

## Projection changes summary

- New `key_broadcast/projector.rs`: bulk recipient-slot unwrap,
  materialize deterministic local `KeySecret(K_bundle)`.
- New `key_history_bundle/projector.rs`: unwrap anchor bundle for one
  recipient, then materialize deterministic local `KeySecret(...)` for
  each historical slot.
- New `key_shared/projector.rs`: targeted single-recipient unwrap,
  materialize the same deterministic local `KeySecret(K_bundle)` as
  the other producer paths.
- New `message_key/projector.rs`: pre-check `deleted_messages` AND
  admin-signed `deletion_intents` for `owning_message_event_id` —
  terminal-drop if either present. Non-admin intents are ignored (not
  authoritative pre-message-creation). Otherwise block-on deterministic
  `k_bundle_local_event_id`. On unblock, decrypt `wrapped_k_m` against
  local `KeySecret(K_bundle)`, insert `K_m` into `key_secrets` keyed
  by this event's `message_key_event_id`, transition to Valid.
- `encrypted/projector.rs` (Message): block-on `message_key_event_id`
  (via outer-header field); existing decrypt path otherwise.
- `message_deletion/projector.rs`: extended purge manifest covers
  `message_key` + `KeySecret(K_m)`.
- `key_repair.rs`: simplified. Scans for peers missing `K_bundle` for
  bundles they should have access to; emits `key_request`. Response
  handler emits targeted `key_shared`.

## Testing plan

1. Unit: `key_broadcast` bulk fanout with N recipients; each
   authorized peer materializes the same deterministic local
   `KeySecret(K_bundle)`.
2. Unit: `key_history_bundle` bootstrap path; recipient unwraps anchor
   bundle and materializes deterministic local `KeySecret(...)` rows
   for populated historical slots.
3. Unit: `key_shared` targeted heal path produces the same local
   `KeySecret(K_bundle)` event id that `key_broadcast` would produce
   for the same bytes.
4. Unit: `message_key` deterministic (two peers produce byte-identical
   events for same `(K_bundle, K_m, owning_message_event_id)`).
5. Unit: `message_key` self-drops if owning message already tombstoned.
6. Unit: cascade — each producer path (`key_broadcast`,
   `key_history_bundle`, `key_shared`) unblocks `message_key` and then
   `message` through the same deterministic local key id.
7. Sim: peer missing initial distribution emits `key_request` →
   another peer emits `key_shared` → requester decrypts.
8. Sim: delete message → `message_key` + `K_m` + Message blob all
   purged on every honest peer; compromise-at-T+grace dump shows no
   decryptable state for that message.
9. Sim: TTL expiry of a message produces same purged state as explicit
   delete.
10. Sim: bootstrap — new joiner receives a `key_history_bundle`
    targeting their new `WrapPubkey`. Can decrypt historical
    `message_key`s + `message`s.
11. Sim: `WrapPubkey` rotation — old privkey purge after grace leaves
    any wrap targeted at the old pubkey unrecoverable (no new key
    material arrives at that peer unless re-wrapped).
12. CLI: end-to-end send + delete + bundle-retention-window + verify
    local key state is empty for deleted message past grace.
13. **Required** late-replay test (closes the terminal-state blocker):
    (a) emit `MessageDeletion`, (b) then emit `message_key`, (c) then
    emit the `message` wrapper. Expected: all three arrivals produce
    terminal drops, no `K_m` row ever materializes, no zero-dep
    blocked row remains. Then replay the three events in every other
    order and assert the same end state.

## Success criteria

- Honest-peer compromise at `T + grace` cannot recover any message
  deleted (or TTL-expired) before `T − grace`. Verified via sim
  compromise test.
- No multi-step rekey protocol and no `message_key`-level heal
  primitive. Every message has its own key; delete = purge + cascade;
  heal is a small `key_shared` re-wrap of `K_bundle` only.
- Dep/cascade substrate unchanged (standard `BlockOnMissingDeps`); only
  the hard-purge manifest extends to enumerate `message_key`.
- Bandwidth: per-message overhead ≈ 100 bytes (`message_key`); bulk
  distribution remains 1 × `key_broadcast` (~524 KB-class); bootstrap
  is 1 × `key_history_bundle` (~524 KB-class) only for joiners; heal
  is 1 × `key_shared` (~150-200 bytes). For a 10-peer workspace with
  10k messages: ~14 MB total, comparable to a shared-epoch-key scheme.

## Resolved design calls

1. **`message_key` signature: deterministic-unsigned.** Heal does NOT
   re-wrap `message_key`; heal re-wraps `K_bundle` via `key_shared`.
   Unsigned `message_key` remains correct for three reasons: (a) the
   signed owning `message` already binds `message_key_event_id` via
   its outer header; (b) deterministic unsigned bytes preserve
   multi-device author dedupe; (c) a recipient who legitimately
   learned `K_m` can deterministically re-emit the same `message_key`
   bytes to fill a narrow gap without introducing a new
   author-signature rule.
2. **Local `KeySecret` events (`K_bundle` + `K_m`): emit as full local
   events (`ShareScope::Local`).** Enables standard cascade semantics
   via `Valid` transition on a deterministic event id.
3. **`WrapPubkey` ordering: no event dep, no replay rule.** Unwrap is
   purely local against `wrap_privkeys`. Sync/replay ordering doesn't
   matter because receivers never need a peer's `WrapPubkey` event to
   project — the emitter of any key-distribution event
   (`key_broadcast`, `key_history_bundle`, `key_shared`) is
   responsible for using a `WrapPubkey` they've already observed.

## Heal authorization (must preserve)

Current repair checks frontier/removal authorization before responding
(`key_repair.rs:798-815, 842-884`). The new `key_request` heal path
MUST preserve this property: a responder emits a targeted `key_shared`
only if the requester is currently entitled to the bundle (not
removed, membership-current, `WrapPubkey` current). Without this
check, removal safety regresses — removed peers could re-request
K_bundles they lost access to. Implementation reuses the existing
authorization surface; only the "which bundle" parameter changes.

## Dependencies

- None upstream. This plan supersedes all prior versions of Plan 1.
- Forward Secrecy (Plan 2) folds entirely into this — the short-lived
  `WrapPubkey` + local privkey purge + bundle retention rule _are_ the
  FS mechanism. Plan 2 as a separate document may be redundant after
  this lands.
