# Alternate FS Design: Convergent Wrap Events + Unified Frontier Advance

Status: proposal (not implemented). Sibling / successor to the Per-Message
FS design currently on the `per-message-fs` branch.

This document describes an alternate forward-secrecy design for poc-7
that unifies key distribution into one mechanism (convergent wrap
events driven by signed ephemeral pubkey requests + deterministic
preemptive emits), collapses today's `removal` + `key_rotation`
events into a single `frontier_advance`, and optionally derives per-
message `K_m` from `K_bundle` via HKDF to drop the per-message
`message_key` event entirely.

The FS guarantee is unchanged: honest-peer compromise at `T + grace`
cannot recover plaintext of any message deleted/TTL-expired before
`T − grace`. The lever remains delete-triggered K_bundle retirement.
Only the *distribution* mechanism changes; the purge cascade and
`retired_bundles` / `retired_keys` gates are preserved.

---

## 1. Motivation

### 1.1 What the current design on `per-message-fs` does

- Three distinct K_bundle distribution events:
  - `key_rotation` — bulk fanout, up to 8192 recipient slots
  - `key_history_bundle` — bootstrap fanout for late joiners (one
    recipient + 8192 historical K_bundle slots + 4096 K_m slots)
  - `key_shared` — 1×1 targeted heal
- Per-message `message_key` event (~133 B) carries `wrapped_k_m =
  AEAD(K_bundle, K_m)`; one event per message.
- Membership change: `removal` event advances the frontier; a separate
  `key_rotation` then rotates K_bundle for the new frontier. Ordering
  is enforced by dependency-blocking but the pairing is not atomic.
- Post-invite delivery: the rotation's 8192 recipient_slots now also
  include active invite pubkeys (landed in commit `7e668b01`), so a
  joiner holding an invite privkey can unwrap rotations created after
  the invite. This closes the gap but is a special case in the
  rotation projector.

### 1.2 Gaps and costs

- **Recipient cap.** 8192 slots is a hard ceiling. Workspaces with
  more active peers+invites than that cannot rotate.
- **Three producers, one meaning.** `key_rotation`, `key_history_bundle`,
  and `key_shared` all deliver K_bundle. Each has its own wire shape,
  projector, context loader, and test surface. The deterministic local
  `KeySecret(K_bundle)` emit dance exists specifically so all three
  converge on a single id.
- **Per-message storage tax.** Every message produces a `message_key`
  event (~133 B), a `message_keys` row, a `key_secrets` row for K_m,
  and a `messages_to_message_keys` row. For a 100k-message workspace:
  ~13 MB wire + ~300k SQL rows per peer.
- **Coupled but non-atomic membership change.** Removal and rotation
  are two events. A rotation missing after a removal is a real bug
  class; the code has guards but the pairing is convention, not
  structure.
- **Post-invite delivery is a special case.** The rotation projector
  has an invite-pubkey fallback path. Works, but is a special case
  specifically to work around the "predict future recipients" problem
  inherent in the broadcast shape.

### 1.3 What this design proposes

Three orthogonal moves:

1. **Collapse distribution.** Replace `(key_rotation,
   key_history_bundle, key_shared)` with one `wrap_event` shape plus
   signed `eph_pubkey_request` events. Wraps are emitted either in
   response to requests OR preemptively on two deterministic triggers.
   Same shape covers steady-state, post-invite, bootstrap, and heal.
2. **Collapse membership+rotation.** Replace `(removal,
   key_rotation)` with a single admin-signed `frontier_advance` event
   that declares both the new frontier and the new `bundle_id`.
   Atomic by construction.
3. **(Optional) KDF `K_m`.** Derive `K_m = HKDF(K_bundle, peer_id ‖
   nonce_12B)` on demand; cache on first derive. Drops the
   `message_key` event entirely. Orthogonal to (1) and (2).

Each is independently useful. (1) is the biggest distribution win.
(2) is a structural cleanup. (3) is the biggest per-message-storage
win.

---

## 2. Events

### 2.1 `frontier_advance` (replaces `removal` + `key_rotation`)

Admin-signed. Declares a new frontier and pins a new K_bundle for it.

Fields:
- `prev_frontier_ref` — event_id of the prior `frontier_advance` (or
  workspace bootstrap event), making the frontier chain explicit.
- `frontier_delta` — added / removed member references. Empty for
  non-membership rotations (delete-triggered strong-FS rotation,
  scheduled rotation, etc).
- `bundle_id` — `blake3(K_bundle_bytes)`. Content-addressed.
- `created_at_ms` — timestamp.

`bundle_id` is the canonical name for this frontier's K_bundle.
Every `wrap_event` referencing this bundle uses this id.

**Why merged:** every bundle rotation is a frontier advance (even
for "same members, new bundle" the frontier reference is carried),
and every removal demands a bundle rotation. Making them one event
removes an entire bug class and one wire type.

### 2.2 `eph_pubkey_request`

Member-signed. A standing or one-shot request for some key.

Fields:
- `target_key_id` — either a `bundle_id` (frontier-scoped request) or
  a `k_m_id = blake3(K_m_bytes)` (per-message-K_m request).
- `pubkey` — one-shot ephemeral Ed25519 pubkey. Requester holds the
  matching privkey in a local `eph_privkeys` table, shredded on
  first successful unwrap or on `valid_until_ms` expiry.
- `valid_until_ms` — short-lived (minutes to hours). After expiry,
  responders may ignore.
- `supersedes_eph_pubkey_event_id` (optional) — references a prior
  request from the same member for the same target. Tells responders
  "my prior pubkey is void; emit a fresh wrap."
- `created_at_ms`, signature.

**Why signed:** binds the request to an admitted member. Spam blast
radius = member count, same as any other admitted-member event.
Signatures give an audit trail for ban-on-abuse.

**Why ephemeral pubkey:** one-shot + shredded-after-unwrap means the
request channel itself has FS. Retaining the privkey past its single
use has no benefit. Determinism is not only unnecessary but harmful:
it would let multiple wraps on the same pubkey be recovered from one
stored privkey.

**Invite pubkeys are implicit standing requests.** When a new invite
lands, its pubkey is treated as an eph_pubkey_request for "anything
I'm entitled to under my frontier" with no expiry (or with expiry
= invite's own `valid_until_ms`). Holders react via preemptive
triggers (§3.2).

### 2.3 `wrap_event`

Unsigned, deterministic-content-addressed. A single (recipient,
target_key) binding.

Fields:
- `target_key_id` — the `bundle_id` or `k_m_id` being wrapped.
- `recipient_pubkey` — matches some `eph_pubkey_request.pubkey` (or
  a member's `peer_shared.public_key`, or an invite's public_key).
- `ciphertext` — `AEAD(K_recipient_shared, target_key_bytes)` or
  `asymmetric_wrap(recipient_pubkey, target_key_bytes)`.
- `nonce`, `auth_tag`, `created_at_ms`.

**Deterministic event id.** `nonce = blake3(target_key_id ‖
recipient_pubkey ‖ sender_identity)`. Multiple holders emitting
independently for the same target+recipient produce byte-identical
`wrap_event`s that dedupe on the wire. Convergence is structural.

**No signature.** Validity is proven by successful AEAD decryption
at the recipient. Forgery requires knowing the target key, which
the forger doesn't have.

### 2.4 Retained events

- `message` — unchanged in (1)+(2). Under (3), gains a ~12B nonce
  field in its header.
- `message_deletion` — unchanged. Drives the purge cascade.
- Identity events (`user`, `user_invite`, `device_invite`,
  `peer_shared`, etc.) — unchanged.

### 2.5 Removed events (under full adoption)

- `key_rotation`, `key_history_bundle`, `key_shared` — replaced by
  `wrap_event`.
- `removal` — merged into `frontier_advance`.
- `message_key` — replaced by KDF derivation if (3) is adopted.

---

## 3. Distribution mechanics

### 3.1 Explicit request path

Steady-state heal. A member needs `target_key_id X` but doesn't have it.

```
requester                          holder
  |                                  |
  |-- eph_pubkey_request(X, pk) -----|-- (project; check entitlement)
  |                                  |   (match: key_secrets for X)
  |<-- wrap_event(X, pk, ct) --------|-- (emit per pattern b)
  | (AEAD decrypt; shred privkey)    |
  | (cache key in key_secrets)       |
```

Idempotency key on holder side: `(eph_pubkey_event_id, target_key_id)`.
Never `(member_id, target_key_id)` — so re-requests after privkey
shred get fresh wraps.

If the wrap never arrives (holder offline, crashed), requester re-
publishes a fresh signed eph_pubkey with optional `supersedes_`
reference.

### 3.2 Preemptive triggers (no explicit request needed)

Two deterministic holder-side triggers fire on projection of
member/invite/bundle events:

**Trigger A: "new invite for my frontier."**
- On projecting a `user_invite` or `device_invite` whose frontier I
  am a member of:
- For each `bundle_id` in my local `key_secrets` whose frontier_ref
  the invite is entitled to (see §4 for entitlement predicate):
- Emit `wrap_event(bundle_id, invite.pubkey, wrapped)` deterministically.

This replaces `key_history_bundle`. Invite pubkey acts as an implicit
standing request for "every bundle I'm entitled to"; holders fulfill
it per-bundle.

**Trigger B: "new bundle for a frontier with active invites."**
- On projecting a `frontier_advance`:
- For each active invite pubkey on that frontier:
- Emit `wrap_event(new_bundle_id, invite.pubkey, wrapped)`.

This replaces the current invite-pubkey slot fallback in
`key_rotation.recipient_slots`.

Both triggers emit deterministic wraps — independent holders produce
byte-identical events and dedupe on the wire. No coordination needed.

### 3.3 On-the-wire optimization

If sync knows recipient Q is the counterparty of this transfer AND
Q appears as a member of the current frontier AND Q doesn't yet have
its own wrap of `bundle_id X`, the sender emits just that one wrap
targeted at Q. Once Q unwraps, Q has K_bundle and can derive every
K_m under that bundle. Saves wire vs shipping every wrap_event.

Fully optional optimization — doesn't affect correctness. Convergence
still holds: if the targeted wrap doesn't arrive, the broader flood
eventually will.

### 3.4 Request scoping

Two valid `target_key_id` shapes:

- **`bundle_id`** — "give me this specific bundle." Used for heal
  when a member sees a `wrap_event` or `message_key`-equivalent
  referencing a `bundle_id` they don't have.
- **`frontier_ref`** — "give me whatever bundle is currently active
  for this frontier." Used for bootstrap / first-contact. Responder
  picks the current `bundle_id` from their local state.

Both use the same `eph_pubkey_request` shape; the `target_key_id`
field tells the responder which semantics apply.

---

## 4. FS lifecycle

### 4.1 K_bundle retirement (strong-FS lever, unchanged)

On `message_deletion` for any message under `bundle_id B`:
1. Walk `messages_to_message_keys` (or KDF-equivalent index) to
   enumerate K_m ids and ciphertexts under B.
2. Shred K_bundle's `key_secrets` row keyed by `bundle_id B`
   (content-addressed) and by any other aliases (see §4.4).
3. Zero-overwrite via `secure_shred_blob`.
4. Insert `(recorded_by, bundle_id)` into `retired_bundles`.
5. `execute_write_ops` gate refuses future `key_secrets` inserts for
   retired bundles.

This is the current design's cascade, unchanged.

### 4.2 Per-K_m cache granularity

Cache-on-first-derive:
- On receiving a message encrypted under `K_m = HKDF(K_bundle,
  peer_id ‖ nonce)`, derive K_m and store in `key_secrets` keyed by
  `k_m_id = blake3(K_m_bytes)`.
- On `message_deletion` for this message, shred the `key_secrets`
  row for `k_m_id`.
- Insert `(recorded_by, k_m_id)` into `retired_keys`.
- Gate refuses future inserts for retired keys (stops in-flight
  wraps that arrive after delete from rehydrating).

After K_bundle retirement, any remaining cached K_m row is the only
copy in existence (re-derivation impossible). Shred → terminal.

### 4.3 In-flight wrap at delete time

A `wrap_event` for `k_m_id X` may be emitted before a deletion
arrives at the holder. Three cases:

- **Wrap reaches requester before the delete reaches either.**
  Requester unwraps, caches, then receives delete → normal per-K_m
  shred cascade applies. Message decrypted in that window counts
  as "saw it" — same weak-FS edge as today.
- **Wrap reaches requester after the delete reaches requester.**
  Requester's `retired_keys` gate refuses the `key_secrets` insert.
  Wrap is inert.
- **Wrap reaches requester, but not yet the delete.** Requester has
  a brief window where they can decrypt. Delete arrives, cascade
  shreds. Same FS-grace window we already accept.

Bounded by deletion propagation latency — the canonical FS grace.

### 4.4 One-name-for-K_bundle

Under this design, the `bundle_id` is `blake3(K_bundle_bytes)` —
ONE canonical content-addressed id. Today's double-naming
(`k_bundle_local_event_id` vs `key_rotation` event_id, shredded
together) disappears. The `frontier_advance` event carries
`bundle_id` directly; no translation layer.

This simplifies the purge cascade: one name to find and shred, not
two.

---

## 5. Optional: KDF K_m

Derive per-message K_m from K_bundle rather than sampling random K_m
and wrapping it. Orthogonal to §2–§4.

### 5.1 Derivation

```
K_m = HKDF-Extract-and-Expand(
    salt    = bundle_id,
    ikm     = K_bundle,
    info    = peer_id || nonce_12B,
    L       = 32
)
```

- `peer_id`: the sender's `peer_shared` event_id (32 B).
- `nonce_12B`: random per message, carried in the message header.
- Collision: 2^48 messages per peer per bundle before birthday bound.
  Effectively zero at any realistic scale.

### 5.2 Header change

`Encrypted` message's outer header gains a `kdf_nonce [12 B]` field.
Everything else on the Encrypted event is unchanged (bundle_id still
pins which K_bundle to use, sender identity is carried by the
existing signature).

### 5.3 Dropped events / rows

- `message_key` event (~133 B) — gone.
- `message_keys` row — gone.
- `key_secrets` row for K_m — **optional cache** (see §4.2); exists
  only if caching is enabled.
- `messages_to_message_keys` reverse index — gone; replaced by a
  direct `bundle_id → messages` index walked at delete time.

### 5.4 Why FS is unchanged

Pre-compromise: attacker on the wire who retained the Encrypted
event has the nonce but not K_bundle. Cannot derive K_m. Cannot
decrypt. Same as today.

Post-compromise without retention: attacker has K_bundle locally
but no ciphertext (it was purged on delete). Can derive K_m for
deleted message in principle — but has no blob to apply it to.
Same as today.

Post-compromise with retention (weak-FS edge): attacker retained the
Encrypted blob + has K_bundle → can decrypt. Same weak-FS as today.

The strong-FS lever is "ciphertext is purged + K_bundle retired before
compromise." KDF derivation preserves both.

### 5.5 Caching policy decision

Cache-on-first-derive gives today's per-K_m purge granularity "for
free" (§4.2). Don't-cache gives the maximum storage win. Either is
valid; default to cache-on-first-derive for symmetry with today's
cascade.

---

## 6. Edge cases and hardening

### 6.1 DoS: flooded requests

Signed requests bound blast radius to admitted members. Two soft
mitigations deferred to future work:

- **Rate-limit per member.** Responders track `(member_id,
  target_key_id)` and suppress if a prior non-expired request exists.
  The `supersedes_eph_pubkey_event_id` field lets honest re-requesters
  bypass.
- **Ban-on-abuse.** Signatures give audit trail; admins can publish a
  removal via `frontier_advance` if a member floods.

Both are additive; neither affects correctness.

### 6.2 Out-of-order wrap / request

If a wrap arrives before its matching request projection, the wrap
either matches a local eph_privkey (use it) or doesn't (ignore).
No buffer table needed. Late-arriving request with an earlier-arriving
wrap: the requester always emits the request first locally (they
authored it), so this case only arises for third parties who don't
need either.

### 6.3 Retired request pubkey

A member shreds their eph_privkey after first unwrap. If they need
the same bundle again (e.g., state loss on one device of a multi-
device account), they publish a fresh signed eph_pubkey with an
optional `supersedes_` ref. Responders re-emit.

### 6.4 Entitlement predicate

"Should I respond to a request for bundle B from member M?" The
predicate is: M is a member of B's frontier AND M is not removed.
Both are projected state: M appears in `peers_shared` / `users` /
`device_invites` / `user_invites` for the workspace, and not in
any removal tombstone.

Responders check before emitting. Requester-side: receiving a wrap
whose decryption fails is a soft error (ignore; the responder was
wrong or the wrap is malformed).

### 6.5 Frontier advance without rotation reason

Permitted: `frontier_advance` with empty `frontier_delta` and a new
`bundle_id`. This is the delete-triggered strong-FS rotation path
and scheduled-rotation path. No membership change, but K_bundle
refreshes.

### 6.6 Multiple admins racing to frontier_advance

Conflict resolution: frontier_advance references `prev_frontier_ref`;
if two advances reference the same prior, treat them as concurrent
and deterministically pick one (lex order on event_id) as
authoritative. The loser's `bundle_id` is retired immediately via
the same `retired_bundles` gate.

Same mechanism as current two-rotations-with-same-frontier case.

---

## 7. Comparison with current per-message-fs branch design

### 7.1 Wire shape

| Axis | Current (per-message-fs) | Proposed |
|---|---|---|
| K_bundle delivery events | 3 (`key_rotation`, `key_history_bundle`, `key_shared`) | 1 (`wrap_event`) |
| Per-message K_m event | `message_key` (~133 B) | None (KDF header ~12 B) |
| Removal + rotation | 2 events (`removal` + `key_rotation`) | 1 (`frontier_advance`) |
| Recipient cap | 8192 slots/rotation | None (flood) |
| Deterministic event id convergence | All 3 producers emit canonical `KeySecret(K_bundle)` | All emitters produce byte-identical `wrap_event`s |

### 7.2 Per-peer storage (100k-message workspace)

| | Current | Proposed (KDF cache-on-derive) | Proposed (no cache) |
|---|---|---|---|
| `message_keys` rows | 100k | 0 | 0 |
| `key_secrets` rows for K_m | 100k | up to 100k (only for read msgs) | 0 |
| `messages_to_message_keys` rows | 100k | 0 (inline in bundle index) | 0 |
| Wire cost of K_m delivery | ~133 B × 100k ≈ 13 MB | 12 B × 100k ≈ 1.2 MB (header only) | same |

Dominant storage and wire cost drops ~10×.

### 7.3 FS guarantee

| Property | Current | Proposed |
|---|---|---|
| Delete-triggered K_bundle retirement | yes | yes (unchanged) |
| Per-message K_m purge | yes (via `message_key` cascade) | yes (cache-on-derive) or N/A (no cache) |
| Weak-FS edge for attacker with wire-retained ciphertext + retained K_bundle | present | present (unchanged) |
| Forward secrecy for deleted messages against no-retention attacker | yes | yes (unchanged) |

**Identical FS in practice.** The per-message-K_m purge granularity in
the current design is cosmetic against retention attackers (they
already have K_m before the delete). Against no-retention attackers,
the ciphertext-shred does the work in both designs.

### 7.4 Protocol complexity

| Axis | Current | Proposed |
|---|---|---|
| Projector files | 6 for K_bundle paths + 1 for `message_key` + 1 for `removal` | 1 for `wrap_event` + 1 for `eph_pubkey_request` + 1 for `frontier_advance` |
| Dep-blocking chains | `message → message_key → KeySecret(K_bundle)` | `message` only (KDF); or `message → wrap_event → key_secrets` (no-KDF variant) |
| Post-invite delivery | Special-case in `load_key_rotation_context` | Just another preemptive wrap trigger |
| Recipient slot accounting | 8192-slot packing, deterministic ordering | None |

### 7.5 Implementation scope

Rough estimate from current branch state:

- (1) Convergent wrap + eph_pubkey_request: replaces ~3 event modules,
  rewrites `key_repair.rs` heal loop, rewrites
  `active_rotation_recipients_for_frontier` preemptive emit. Probably
  equivalent to current per-message-fs impl size (3–4 weeks).
- (2) `frontier_advance` merger: modest. Renames/merges 2 events,
  updates ~10 callsites. 2–3 days.
- (3) KDF K_m: wire-format change to `Encrypted`'s header (add nonce
  field). Drops `message_key` event and its projector/cascade. Adds
  HKDF derivation helper. 1 week.

Migration is not in scope for this doc — this is a greenfield design.
Landing it would be a coordinated wire-format break with a defined
cutover.

### 7.6 When to prefer the current design

- **Shorter wire-format lifespan for the Encrypted event.** Current
  design leaves `Encrypted` exactly as-is and adds `message_key` as a
  side event. Proposed (with KDF) adds a header field to Encrypted.
- **Bounded-sized rotations.** If the 8192-recipient cap isn't a real
  constraint (workspaces < 8192 active members+invites), the current
  design's single large broadcast is simpler to reason about than a
  flood of deterministic wraps.
- **Per-K_m granularity is user-visible.** Some auditing or compliance
  contexts may want the explicit `message_key` row as a user-visible
  deletion artifact.

### 7.7 When to prefer the proposed design

- **Large workspaces.** No recipient cap; per-message cost drops ~10×.
- **Simpler protocol surface.** Fewer event types, fewer projectors,
  no special-case for post-invite delivery, no double-naming of
  K_bundle.
- **Atomic membership + rotation.** `frontier_advance` makes the
  "removal without rotation" bug class unrepresentable.
- **Greenfield.** If we're going to break wire format anyway (we are,
  for per-message FS), do it once.

---

## 8. Open questions / deferred

- **DoS rate-limiting spec.** Soft rate-limit rule is sketched in
  §6.1 but not fully specified. Ban-on-abuse via `frontier_advance`
  covers the worst case.
- **Entitlement predicate precise definition.** §6.4 sketches; needs
  a formal TLA+ or executable spec tied to the workspace identity
  model.
- **Multi-device request coalescing.** Two devices of the same user
  may independently publish requests. Soft dedupe via `(user_id,
  target_key_id)` could collapse them; same mechanism as §6.1.
- **Migration from current design.** If we decided to adopt this
  after landing the current per-message-fs branch, a migration plan
  is a separate execution plan. This doc is the *design*, not the
  migration.

---

## 9. Relation to other docs

- `docs/DESIGN.md` §9.6 — current FS design with delete-triggered
  K_bundle purge. The FS guarantee there carries over unchanged.
- `docs/PLAN.md` §22 — per-message FS execution plan on the
  `per-message-fs` branch.
- `docs/planning/DELETE_TRIGGERED_REKEY_EXECUTION_PLAN.md` — the
  approved Plan 1 v4 execution plan. This alternate design
  *supersedes* that plan structurally but preserves its FS
  invariants.
- `docs/tla/` — identity / event graph models. The `frontier_advance`
  merger would simplify the identity model (fewer event types); TLA+
  updates are scoped to the adoption execution plan, not this design.
