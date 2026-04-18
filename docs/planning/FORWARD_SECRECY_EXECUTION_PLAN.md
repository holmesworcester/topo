# Forward Secrecy Execution Plan

## Objective

Provide forward secrecy for messages that are **deleted** or **TTL-expired**
past a bounded grace window. Concretely: if a device is compromised at time
T, the adversary MUST NOT be able to recover the plaintext of any message
that was deleted (or expired by its event TTL) before T − grace.

Live messages (not deleted, not expired) remain readable by current members.
This is **not** classical ratchet FS — a compromise at T can still decrypt
live content. The protection surface is deleted/expired content past grace.

This plan composes three primitives:

1. **Short-lived KEM pubkeys** so wrapping uses keys that expire and whose
   private material is purged on schedule.
2. **Preface rotation triggered on (a) key-TTL thresholds and (b) membership
   change** — the membership-change half already exists (removal).
3. **Deleter-initiated rotation + deterministic re-encryption + quiescent
   purge** — covered by the Delete-Triggered Rekey Execution Plan
   (prerequisite).

## Threat model

Adversary:
- Can eventually compromise any device's persistent state, recovering every
  key present on disk at compromise time.
- Does NOT have capability to recover memory-only ephemeral keys from before
  compromise.
- Sees all network traffic, including durable historical sync.

Goal: after compromise at time T, adversary cannot decrypt any message M
where:
- M was deleted before T − grace, OR
- M's event TTL expired before T − grace.

Non-goals:
- Live-message FS (compromise reveals live plaintext).
- Group-membership confidentiality.
- Metadata / timing confidentiality.
- Recovery from backups that were themselves compromised.

## Scope

### In scope
- Short-lived wrap pubkeys; default cadence shorter than grace.
- TTL-driven `KeyRotation` emission (scheduled trigger in key_repair loop).
- Deletion-triggered rotation (inherits Delete-Triggered Rekey plan).
- Quiescent `KeySecret` purge with grace.
- Retention policy for wrap private keys: purge at expiry + grace.

### Out of scope
- Per-message ephemeral keys / double ratchet.
- Rotation of signing keys (long-lived `peer_shared` identity); separate
  concern handled by existing identity plan.
- Backup / recovery of past keys.

## Architecture today

Relevant on this branch:

- `src/event_modules/peer_shared/` — long-lived peer public keys
  (identity + wrap, currently conflated).
- `src/event_modules/invite_secret.rs` — invite-scoped keypair,
  TTL-bounded by invite lifetime.
- `src/event_modules/key_shared.rs` — wraps `KeySecret` to a recipient
  using `unwrap_key_from_sender`; recipient pubkey derived from
  `peer_shared` or `invite_secret`.
- `src/event_modules/key_rotation.rs` — manual trigger today; binds to
  removal frontier.
- `src/runtime/key_repair.rs:121-158` — periodic loop; natural home for
  scheduled FS triggers.

Gaps for FS:
- Wrap pubkey is long-lived. Compromise of `peer_shared` private material
  retroactively unwraps all historical `KeyShared` events.
- No TTL-driven rotation — a `KeySecret` can protect arbitrarily old
  ciphertext.
- No `KeySecret` purge — deleted messages' keys persist indefinitely.

## Design

### D1. `WrapPubkey` event (short-lived)

New event type `WrapPubkey` (next available type id after
`KeyHistory = 36`):

Fields:
- `pubkey: [u8; 32]` — curve25519 wrap public key.
- `valid_until_ms: u64` — expiry.
- `signer_event_id: [u8; 32]` — emitter's identity event.

Signer required; shared scope.

Semantics:
- Each peer emits a `WrapPubkey` periodically (cadence configurable,
  default 1 hour).
- `key_shared.rs` selects the **latest non-expired** `WrapPubkey` for the
  recipient at wrap time; falls back to the recipient's `peer_shared`
  pubkey only when no `WrapPubkey` is known (bootstrap compat).
- The corresponding private key is generated locally and persisted in a
  new local-only table.

### D2. `wrap_privkeys` local table

Schema (local, not sync'd):
```
CREATE TABLE wrap_privkeys (
  pubkey BLOB PRIMARY KEY,
  privkey BLOB NOT NULL,
  valid_until_ms INTEGER NOT NULL,
  created_at_ms INTEGER NOT NULL
);
```

Retention:
- Row retained until `valid_until_ms + grace_ms < now`.
- Purge in the `key_repair` periodic loop.
- Edge case: a peer offline when a `KeyShared` targeting its (now
  purged) `WrapPubkey` was sent cannot recover the wrapped key.
  Acceptable: peer was offline past grace; recoverable only via a fresh
  pubkey + re-wrap.

### D3. TTL-driven rotation

Scheduled trigger in `key_repair`:
- For each active `KeySecret` K, compute `age = now - K.created_at_ms`.
- If `age > key_rotation_max_age_ms` (config, default 1h), emit a
  `KeyRotation` superseding K. Frontier extends the prior frontier with no
  new removal or deletion refs; it's a pure time-driven rotation.

Refinement (optional, phase 2): rotate when
`age > min(event_ttl under K) - grace`. Start with simple max-age.

### D4. Deletion-triggered rotation

Inherited from Delete-Triggered Rekey Execution Plan. No additional work
here.

### D5. Quiescent purge with grace

Extends Delete-Triggered Rekey D5 with a grace parameter:

`KeySecret` K eligible for purge when:
1. K has been superseded by a `KeyRotation`.
2. No valid `Encrypted` event references K.
3. `K.superseded_at_ms + grace_ms < now`.

Grace accounts for offline observers still re-encrypting late sends under
K. Default grace: 24 hours; configurable via workspace-level setting.

The `KeyRotation` event itself remains for dep integrity; only the raw
secret material is erased.

### D6. Wrap-pubkey retention

Already covered in D2. Summary: wrap-pubkey private material purged
`valid_until + grace` after emission, independent of whether any
ciphertext still exists under it. (Ciphertext that can't be wrapped via a
purged pubkey is recoverable only via a new `KeyShared` from someone who
still has the corresponding `KeySecret`.)

## Event layer changes

- New event `WrapPubkey` in registry; signer required.
- `KeySecret` (local state): add `superseded_at_ms` (already called out in
  Delete plan; explicit here for clarity).
- New local table `wrap_privkeys`.
- No wire change to existing events.

## Projection changes

- `wrap_pubkey/projector.rs` (new): insert row in `wrap_pubkeys` (new
  local table) indexed by `(signer_peer_id, valid_until_ms)`.
- `key_shared.rs` sender-side path: selection query prefers latest
  non-expired `WrapPubkey` for recipient; fallback to `peer_shared`
  pubkey only if none known.
- `key_repair.rs`:
  - Schedule periodic `WrapPubkey` emission per this peer.
  - Schedule TTL-driven `KeyRotation` per D3.
  - Schedule `KeySecret` purge per D5 (coordinates with Delete plan).
  - Schedule `wrap_privkeys` GC per D2.
- No change to `peer_shared` projector.

## Interaction with keyrepair work on this branch

- The "heal after removal" loop continues to operate unchanged in its core
  logic. It now runs against faster-rotating epochs, but the mechanics
  (authorization-gated `KeyRequest`/`KeyShared`) are the same.
- `KeyHistory` bundles for late joiners still work, but the bundle's
  contents are subject to the same quiescent purge once supersession +
  grace elapses. A joiner who arrives post-purge cannot recover pre-purge
  plaintext — acceptable (that's the FS property).
- The new `WrapPubkey` layer slots in alongside `peer_shared`. Consider
  whether bootstrap events (invite acceptance) should also emit an
  initial `WrapPubkey` so first-contact sends use a short-lived key.

## Testing plan

1. Unit: `WrapPubkey` selection prefers latest non-expired; falls back
   only when no entry exists.
2. Unit: `wrap_privkeys` GC removes expired rows; `KeyShared` wrapped
   against a purged pubkey is unrecoverable by the original recipient.
3. Sim: TTL-driven rotation fires on schedule; superseded `KeySecret`
   purged after grace; compromise-at-T test cannot recover a message
   deleted before T − grace.
4. Sim: offline recipient past grace — peers stop successfully wrapping
   for them; recoverable once a fresh `WrapPubkey` is published.
5. Sim: end-to-end — send, delete, wait grace, dump on-disk state,
   verify ciphertext is not decryptable under any key material present.
6. Sim: compromise-at-T test for an expired-by-TTL message (no explicit
   delete) — same property.

## Open questions (for codex)

1. Grace duration: 24h default reasonable? Too long, exposed window is
   large. Too short, offline peers lose recovery ability.
2. `WrapPubkey` cadence: 1h default OK? Bandwidth cost in a steady-state
   4-peer workspace should be minimal; larger groups might need tuning.
3. Bootstrap: how does a joiner learn the inviter's current
   `WrapPubkey`? Options: (a) extend `KeyHistory` bundle to carry recent
   `WrapPubkey` refs, (b) inviter always emits a fresh `WrapPubkey`
   right before sending the invite.
4. Offline-peer DOS: a peer offline past grace loses ability to
   decrypt messages sent during its offline window. Acceptable, or do we
   want an opt-in extended retention (per-recipient, at sender's
   discretion)?
5. Should signing vs wrap separation be formalized now (two distinct
   long-lived and short-lived pubkeys) or lazy-migrate? Leaning
   formalize: `peer_shared` remains the signing identity; `WrapPubkey`
   is the wrap pubkey.
6. Event TTL source: events don't currently carry TTL in their payload.
   Is TTL derived from `channel` settings (disappearing-messages), from
   workspace-level defaults, or explicit per-event? Affects D3
   refinement.

## Dependencies

- **Blocks on**: Delete-Triggered Rekey Execution Plan. The deletion-
  triggered rotation and quiescent purge are prerequisites.
- **Coexists with**: the active keyrepair work on this branch.

## Success criteria

- Compromise test (dump all keys at time T) cannot recover plaintext of
  any message deleted before T − 24h.
- Compromise test at time T cannot recover plaintext of any message whose
  event TTL expired before T − 24h.
- Live-message readability unchanged — current members read current
  content across rotation boundaries without interruption.
- Steady-state network bandwidth for `WrapPubkey` rotations in a 4-peer
  workspace is < 5% of baseline sync traffic.
- Compromise test at T recovers only content that is either live at T, or
  deleted/expired within the trailing grace window.
