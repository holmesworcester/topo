# FS Alt Design — Revised Plan (v2)

Revised after codex review of `FS_ALT_CONVERGENT_WRAP_DESIGN.md` and
subsequent design iteration. This doc is a **decisions summary with
enough concrete detail to scope an execution plan**. The v1 design
doc and codex review remain for context; this supersedes their
conclusions where they conflict.

Status: proposal; supersedes v1's specific constructions. Branch
`design-fs-alt-convergent-wrap`.

---

## Core design (decisions)

### 1. Reuse the existing `key_shared` event as THE distribution event

**What:** Make `key_shared` (already on the branch, 1 recipient × 1
target-key shape at `src/event_modules/key_shared.rs`) the sole
K_bundle distribution event. Drop `key_rotation` (8192 recipient
slots) and `key_history_bundle` (1 recipient × 4096 bundle slots +
4096 K_m slots).

**Wire shape (existing, reused):**
```
key_shared {
    target_key_id: [u8; 32],      // = bundle_id (canonical K_bundle id)
    recipient_pubkey: [u8; 32],
    ephemeral_sender_pubkey: [u8; 32],
    ciphertext: [u8; 32],          // wrapped K_bundle
    auth_tag: [u8; 16],
    nonce: [u8; 12],
    created_at_ms: u64,
}
```

**Why this works:** every broadcast / history / heal case decomposes
into one `(recipient_pubkey, target_key_id)` emission. 8192-recipient
rotation = 8192 `key_shared` events. History bundle = one per
(historical_bundle, invite_pubkey). Heal = one. No dedicated variant
per case.

**What drops from the branch:**
- `src/event_modules/key_rotation.rs` (~340 LOC)
- `src/event_modules/key_history_bundle.rs` (~380 LOC)
- `active_rotation_recipients_for_frontier` special-case for invites
  in `workspace/identity_ops.rs:469-536`
- `load_key_rotation_context` invite-secret fallback in
  `decision_context.rs:2416-2449`
- `load_key_history_context` in `decision_context.rs`

**What remains:**
- `key_shared` projector preserved; only change is it must emit the
  canonical deterministic `KeySecret(K_bundle)` on successful unwrap
  (decision 4) — `key_broadcast` already does this at
  `event_modules/key_broadcast.rs:210-219`; copy the pattern.

**Size consequence:** rotation event (≈524 KB at 8192 slots) becomes
a flood of 8192 × ~155-byte `key_shared` events (≈1.2 MB total in the
worst case). BUT most recipients are inactive or already have
K_bundle → trigger A/B emit only for the ones that need it. In
practice the flood is sparse.

---

### 2. Add `key_request`

**What:** A new member-signed event that publishes an ephemeral public
key as a standing request for some target key. The request exists for
two reasons: to let a member re-request after shredding an earlier
privkey, and to let responders confirm a specific pubkey is
authorized.

**Wire shape (new):**
```
key_request {
    target_key_id:   [u8; 32],                   // opaque 32-B id
    target_kind:     u8,                         // see table below
    pubkey:          [u8; 32],                   // ephemeral X25519 pubkey
    valid_until_ms:  u64,
    supersedes_key_request_event_id: [u8; 32],   // zero if not superseding
    created_at_ms:   u64,
    // + signer envelope + signature (standard)
}
```

**`target_kind` enumeration:**

| kind | `target_key_id` means | responder lookup | response wraps |
|---|---|---|---|
| 0 | `bundle_id` | `key_secrets.event_id = bundle_id` | K_bundle |
| 1 | `frontier_ref` | current K_bundle for that frontier | K_bundle |
| 2 | `message_event_id` | K_m cached for that message | K_m |
| 3 | `message_key_event_id` | K_m cached via its message_key (no-KDF variant) | K_m |

`target_kind=0` and `=1` are bundle-level requests (joiners, fresh
members, heal after K_bundle loss). `=2` and `=3` are per-K_m
requests for existing members who lost per-message cache state
(multi-device sync, local DB corruption, etc.) — see
§"Per-K_m recovery for existing members" below.

All kinds use the same `key_request` / `key_shared` event pair. The
responder's behavior differs only in which table they look up the
target in.

**Local table (new):**
```sql
CREATE TABLE eph_privkeys (
    recorded_by TEXT NOT NULL,
    key_request_event_id TEXT NOT NULL,
    privkey BLOB NOT NULL,
    created_at_ms INTEGER NOT NULL,
    valid_until_ms INTEGER NOT NULL,
    PRIMARY KEY (recorded_by, key_request_event_id)
);
```

**Lifecycle:**
- Requester publishes the event + persists the privkey locally.
- On receiving a `key_shared` whose `recipient_pubkey` matches a row:
  unwrap, cache K_bundle, `secure_shred_blob` the privkey row.
- Expired rows (by `valid_until_ms + grace`): sweep + shred.
- `supersedes_` ref: when projecting a new request, shred the
  superseded row's privkey.

**Why signed:** binds request to an admitted member. DoS blast
radius = member count. Ban-on-abuse is an out-of-band admin action
(a future `frontier_advance` with this member removed).

**Invite pubkeys are implicit standing requests.** When projecting
any `user_invite` / `device_invite`, the invite's pubkey is treated as
a permanent request bound to the invite's `valid_until_ms`. No
separate `key_request` needed for invites. Holders react via
trigger A (decision 5).

---

### 3. Deterministic `key_shared` construction for convergence

**The problem v1 had:** `key_shared` ciphertext depends on the
sender's ephemeral key choice; independent holders emit different
ciphertexts. No on-wire dedupe. Codex flagged this at
`FS_ALT_CONVERGENT_WRAP_DESIGN.md:152-159`.

**Fix:** derive the ephemeral sender keypair deterministically from
the (target, recipient) pair. Any holder that has K_bundle for
`target_key_id` can emit the same sealed box:

```
ephemeral_seed   = blake3("fs-wrap-v1" ‖ target_key_id ‖ recipient_pubkey)
ephemeral_sk     = clamp_to_x25519(ephemeral_seed)
ephemeral_pk     = X25519_pubkey(ephemeral_sk)
shared_secret    = X25519(ephemeral_sk, recipient_pubkey)
kdf_key          = HKDF(shared_secret, salt=target_key_id, info="fs-wrap-v1")
nonce            = first_12B(blake3("fs-wrap-nonce-v1" ‖ target_key_id ‖ recipient_pubkey))
(ciphertext, tag) = AES-GCM-encrypt(kdf_key, nonce, K_bundle)
created_at_ms    = 0  // NOT holder-dependent — see below
```

Every field is a function of (`target_key_id`, `recipient_pubkey`,
K_bundle). Different holders with the same K_bundle emit byte-
identical `key_shared` events. Content-addressed event id is
identical across holders → standard dedupe on the wire.

**`created_at_ms` handling:** must NOT be holder-current-time.
Either:
- Set to 0 (or a fixed sentinel), since the event's timing isn't
  semantically meaningful (it's a convergent idempotent emission).
- OR set to the request/invite's `created_at_ms` (whichever triggered
  the emission). This is deterministic as long as all holders react
  to the same trigger event.
- Pick the simpler: 0. Ordering isn't load-bearing for `key_shared`.

**Signer:** `key_shared` today is signed; under this scheme,
signatures also break convergence. Drop the signature; rely on AEAD
decryption at the recipient as validity proof. A forged `key_shared`
has no real K_bundle to wrap; it fails AEAD at the recipient and is
discarded. Responder identity is carried by who propagated the event,
not who "signed" it.

This lines `key_shared` up structurally with `message_key` on the
current branch: both are deterministic, unsigned, content-addressed.

---

### 4. Preserve `k_bundle_local_event_id` as the canonical dep key

**The problem v1 had:** by pitching `wrap_event` as the dep target,
v1 forced a many-to-one dep chain that doesn't work cleanly (one
message_key blocks on which `wrap_event`?). Codex flagged this at
`FS_ALT_CONVERGENT_WRAP_DESIGN.md:490-491`.

**Fix:** keep the current dep chain unchanged:
```
message  -blocks on->  message_key
message_key  -blocks on->  KeySecret(K_bundle) [deterministic local id]
```

`key_shared`'s projector, on successful unwrap, uses the existing
helper to emit a canonical `KeySecret(K_bundle)` local event:
```rust
// In key_shared::project_pure, after successful unwrap:
let k_bundle_plaintext: [u8; 32] = unwrap_key_from_sender(...);
emit_commands.push(
    key_broadcast::emit_deterministic_key_secret_command(&k_bundle_plaintext)
);
```

Pattern lifted verbatim from `src/event_modules/key_broadcast.rs:210-219`.
No new mechanism invented. `k_bundle_local_event_id =
deterministic_key_secret_event_id(K_bundle)` continues to work as
today.

**Deps in the `key_shared` projector:** target bundle presence isn't
a dep — the whole point of `key_shared` is to materialize K_bundle.
But the sender-envelope (signer) is validated via the standard
signer chain. And the requesting `key_request` should be a dep so
`key_shared` can't arrive before the request it answers to a peer
that hasn't seen the request yet.

Actually — no. `key_shared` is unsigned under decision 3. Signer
envelope disappears. Request also isn't a strict dep: an invite's
pubkey counts as a standing request, and invites project via their
own dep chain. If `key_shared` arrives before its matching request
OR invite, it has no local privkey to unwrap and is quietly ignored
(decision 2's shredding rule; recipient-side behavior).

Cascade unblocks: standard `blocked_event_deps` + `cascade_unblocked`
in `apply/cascade.rs`.

---

### 5. Preemptive emit triggers

Two deterministic holder-side emission paths replace today's
`key_history_bundle` bootstrap and today's invite-slot fanout in
`key_rotation`.

**Trigger A: "new invite for a frontier I have keys on."**

Fires on: projection of `user_invite` or `device_invite`.

Projector iterates EVERY `key_secrets` row the invite is entitled
to — both K_bundle rows AND cached per-message K_m rows — and emits
one `key_shared` per row targeting the invite pubkey:

```
for each row in key_secrets where frontier_entitles(invite, row):
   if row is a K_bundle:
       emit key_shared(target=bundle_id,
                       recipient=invite.pubkey)
   else if row is a K_m:           // surviving msg in retired bundle
       emit key_shared(target=message_event_id (or mkey_event_id),
                       recipient=invite.pubkey)
   via the deterministic construction from decision 3.
```

Entitlement check = decision 8's SQL query.

Replaces `key_history_bundle` AND seeds joiners with surviving K_m's
for messages under retired bundles. K_m rows whose bundle is retired
still exist on members who decrypted before the retirement; trigger
A enumerates them and forwards to the joiner's invite pubkey. The
joiner receives per-K_m `key_shared` events, unwraps, caches, and
can decrypt the surviving messages directly.

This means joiners **DO** see surviving messages in retired bundles.
That improves on the current branch's
`joiner_after_bundle_retirement_sees_undeleted_tail_as_history_lost`
test, which would become obsolete under v2 — it'd be replaced by
`joiner_sees_surviving_messages_in_retired_bundles`.

Cost: N per-K_m `key_shared` events per new invite for a retired
bundle with N surviving messages. Each event is ~155 bytes. 1k
survivors × 5 invites = 5k events = ~775 KB wire. Deterministic
construction → every holder emits the same event → on-wire dedupe
reduces this by the number of holders emitting, so effective wire
cost is ~155 KB × 1k = 155 KB for that joiner set, not 5k × 155 B.

**Trigger B: "new bundle, I should seed it to active invites."**

Fires on: projection of `KeySecret(K_bundle)` (or
`frontier_advance`, since the advance pins a new bundle_id).

Projector side-effect:
```
for each active invite_pubkey in this frontier's invite tables where
      frontier_entitles(invite, new_bundle_id):
   emit key_shared(target=new_bundle_id, recipient=invite.pubkey).
```

Replaces `active_rotation_recipients_for_frontier`'s current invite-
slot special case.

**Trigger C (implicit): response to explicit `key_request`.**

Fires on: projection of `key_request`.

Projector side-effect:
```
if frontier_entitles(request.requester, request.target_key_id) AND
   local key_secrets has K_bundle for target:
   emit key_shared(target=request.target_key_id,
                   recipient=request.pubkey).
```

All three triggers use the same deterministic `key_shared`
construction, so output dedupes across holders.

**Idempotency:** two identical `key_shared` events from independent
holders are one event after content-addressing. No holder-side
"already responded" tracking needed for the A/B/C triggers.

---

#### Per-K_m recovery for existing members

The question: after `bundle B` is retired due to deletion of one
message, `B`'s `K_bundle` is gone everywhere. Surviving messages
under B still have their K_m's cached on members who decrypted
them. But what about a member who lost state (device wipe, DB
corruption, multi-device out-of-sync) and never cached K_m for
surviving message M?

They can't re-derive K_m (K_bundle is retired globally). So they
need a peer who has K_m cached to wrap it directly.

**Mechanism:** same `key_request` event (decision 2), `target_kind=2`
(`message_event_id`) or `=3` (`message_key_event_id`). Trigger C
answers from any holder whose `key_secrets` table has a row keyed
by the requested id.

```
member with state loss                  holder with K_m cached
  |                                       |
  |-- key_request(kind=2,                 |
  |       target=msg_event_id,            |
  |       pubkey=pk) ------------------->-|-- trigger C fires
  |                                       |   check entitlement
  |                                       |   look up K_m by msg id
  |<-- key_shared(target=msg_event_id, ---|-- deterministic wrap
  |       recipient=pk, ct) --------------|
  | unwrap; insert into key_secrets       |
  | shred eph_privkey                     |
```

**Responder entitlement (decision 8):** holder checks that the
requester is still a member of the frontier under which M was
sent. If yes, respond. If removed, drop silently.

**Gate interaction:** `retired_keys` (decision 7) is NOT consulted
here. Retired keys correspond to *deleted* messages. A surviving
message's K_m is never in `retired_keys` — its `event_id` / K_m id
has never been retired. So inserts proceed normally.

**Convergence:** multiple holders may respond. Deterministic
`key_shared` construction (decision 3) means their events are
byte-identical → one event on the wire. Same story as bundle-level
recovery.

**No new trigger needed.** Trigger C already handles explicit
requests; we just broaden `target_kind` to include K_m ids.

**Joiner case is covered by trigger A, not by key_request.**

New joiners don't need to publish explicit `key_request`s for
surviving K_m's — trigger A (decision 5) iterates every
`key_secrets` row and emits per-K_m `key_shared` events targeted
at the invite pubkey. So joiners DO see surviving messages in
retired bundles.

The explicit `key_request` path here (target_kind = 2 or 3) is for
established members who already unwrapped once but lost local
cache state (device wipe, DB corruption, multi-device sync gap).
Trigger A doesn't fire for them because they're not a new invite;
they need the request/response path.

---

### 6. Self-contained `MessageDeletion`

**What:** `MessageDeletion` carries the ids needed to perform its
entire cascade directly, without reverse-index lookups.

**Wire shape (revised):**
```
MessageDeletion {
    message_event_id:     [u8; 32],    // target message
    message_key_event_id: [u8; 32],    // that message's K_m event
    bundle_id:            [u8; 32],    // K_bundle under which msg was sent
    created_at_ms: u64,
    // + signer envelope (author) + signature
}
```

**Cascade becomes straight-line:**
```
BEGIN;
  DELETE FROM messages           WHERE event_id = message_event_id;
  DELETE FROM events             WHERE event_id = message_event_id;
  DELETE FROM message_keys       WHERE event_id = message_key_event_id;
  DELETE FROM events             WHERE event_id = message_key_event_id;
  DELETE FROM key_secrets        WHERE event_id IN (
       message_key_event_id,   -- K_m
       bundle_id,              -- K_bundle (rotation alias)
       deterministic_k_bundle_local_id_for(bundle_id)  -- if we can
                                                       -- derive it
  );
  secure_shred_blob(message_event_id);
  secure_shred_blob(message_key_event_id);
  -- bundle blob only shredded if this is the last message under it
  INSERT INTO retired_bundles(bundle_id);
  INSERT INTO retired_keys(message_key_event_id);
  -- deleted_messages tombstone as today
  INSERT INTO deleted_messages(message_event_id, ...);
COMMIT;
```

**Drops:** `messages_to_message_keys` reverse-index table entirely.
Purge walker at `src/state/projection/purge.rs:163-238` becomes a
direct executor — no joins, no reverse-lookups, no late-index
race.

**Late-replay (strictly better than today):**
- MessageDeletion arriving before `message` / `message_key` / rotation:
  ids are known directly → insert into `retired_bundles` +
  `retired_keys` immediately. The retirement gate (decision 7)
  refuses subsequent `key_secrets` inserts for those ids. When the
  message/message_key/rotation events finally arrive, they project
  the row headers but produce no decryption material → inert.

**Validation:** author signed the deletion. If the `message_key`
event later arrives and its `bundle_id` doesn't match the deletion's
claim, the author is malicious. The gate is still safe (it only
refuses, never fabricates), but we can also reject the tampered
message_key at projection. Byzantine authors are treated as today.

**`bundle_id` derivation bookkeeping:** today the deterministic
K_bundle local id isn't always recoverable from the rotation
bundle_id alone — it requires the K_bundle bytes. So on cascade we
must also look up the `k_bundle_local_event_id` from the message_key
row we're about to delete (`message_keys.k_bundle_local_event_id`)
and add that to the shred set. Single-row lookup, no index required.

---

### 7. `retired_keys` table and gate

**Schema (new):**
```sql
CREATE TABLE retired_keys (
    recorded_by TEXT NOT NULL,
    message_key_event_id TEXT NOT NULL,
    retired_at_ms INTEGER NOT NULL,
    PRIMARY KEY (recorded_by, message_key_event_id)
);
CREATE INDEX idx_retired_keys_by_mkey
    ON retired_keys (recorded_by, message_key_event_id);
```

**Gate point:** `src/state/projection/apply/write_exec.rs` in
`execute_write_ops`, alongside the existing `retired_bundles` gate
at `:122-153`. Two additional checks:

```rust
// 1. Refuse key_secrets insert whose event_id matches a retired key.
if is_key_secrets_insert(op)
   && row_in_retired_keys(conn, recorded_by, insert_event_id)? {
    return Ok(WriteOpOutcome::RefusedByGate);
}

// 2. Refuse message_keys row insert with that event_id.
if is_message_keys_insert(op)
   && row_in_retired_keys(conn, recorded_by, insert_event_id)? {
    return Ok(WriteOpOutcome::RefusedByGate);
}
```

**Populated by:** `MessageDeletion`'s cascade (decision 6). One
`retired_keys` row per deletion.

**What it protects:** late-arriving `message_key` events whose
target message was already deleted (stops K_m rehydration); late-
arriving `key_shared` targeted at a retired K_m (inert — decrypted
bytes can't be re-cached).

**Interaction with `retired_bundles`:** orthogonal. `retired_bundles`
protects K_bundle rehydration; `retired_keys` protects K_m
rehydration. Both gates consulted on every `key_secrets` insert.

**Tests to add:**
- Late `message_key` for already-deleted message → refused; no K_m row.
- Late `key_shared` for retired K_m → refused; no K_m row.
- Deletion of message X doesn't retire K_m's for messages Y, Z under
  same bundle.
- Per-device bundle isolation: deletion in bundle B1 retires
  bundle_id_B1 only; B2's K_m rows untouched. (resolves codex's
  `per_device_bundle_isolation` regression concern)

---

### 8. Entitlement predicate as SQL query

**The problem v1 had:** predicate was "present in invite tables and
not tombstoned." Codex flagged this at
`FS_ALT_CONVERGENT_WRAP_DESIGN.md:420-424` as weaker than today's
walk-the-frontier-and-removal-lineage check at
`identity_ops.rs:419-467` and `key_repair.rs:799-887`.

**Fix:** materialize a flat set at projection time, query it with a
single-row lookup.

**Schema (new):**
```sql
CREATE TABLE frontier_removed_peers (
    recorded_by TEXT NOT NULL,
    frontier_ref TEXT NOT NULL,       -- frontier_advance event_id
    peer_ref TEXT NOT NULL,           -- peer/user/invite event_id
    removed_at_ms INTEGER NOT NULL,
    PRIMARY KEY (recorded_by, frontier_ref, peer_ref)
);
CREATE INDEX idx_frontier_removed_by_peer
    ON frontier_removed_peers (recorded_by, peer_ref, frontier_ref);
```

**Populator:** `frontier_advance` projector (decision 9). For each
`removed_peer_ref` in the event's `frontier_delta`, insert a row.
Multi-parent frontier advances each populate independently; the set
is the union.

**Predicate (reused throughout):**
```sql
-- "is peer_ref removed at frontier_ref?"
SELECT 1 FROM frontier_removed_peers
 WHERE recorded_by = ?1 AND frontier_ref = ?2 AND peer_ref = ?3
 LIMIT 1;
```

**Definitive negative:** because projection is complete before any
query runs (standard projector invariant), absence of the row is
proof of non-removal at that frontier. No lineage walk required.

**Consulted by:**
- `key_shared` responder side (trigger C) — check requester_peer_ref
  against the bundle's frontier_ref.
- Trigger A/B preemptive emits — check each candidate recipient
  pubkey's binding peer_ref against the bundle's frontier_ref.
- `key_repair.rs` heal responder (replaces the current lineage walk
  at `:799-887`).

**Frontier resolution helper (unchanged from TLA+ `ResolveNet`):** a
bundle's frontier_ref is read from its `frontier_advance` event
(decision 9), OR from the current branch's `key_rotations`/
`removal`-chain join during the transition period.

---

### 9. `frontier_advance` merges `removal` + `key_rotation`

**What:** one admin-signed event that declares a new frontier and
pins a new K_bundle atomically.

**Wire shape (new):**
```
frontier_advance {
    prev_frontier_refs: Vec<[u8; 32]>,   // multi-parent: Vec, not one
    frontier_hash: [u8; 32],              // hash of sorted parent set
    added_peers:   Vec<[u8; 32]>,         // user/device/invite event_ids
    removed_peers: Vec<[u8; 32]>,         // same
    bundle_id:     [u8; 32],              // new K_bundle content-addr id
    created_at_ms: u64,
    // + admin signer envelope + signature
}
```

(Vec encoded with the existing FieldSpec layout pattern; length-
prefixed, capped.)

**Semantics:**
- `added_peers` — new members. Triggers trigger A equivalents for
  their pubkeys over historical bundles (if they're entitled).
- `removed_peers` — populates `frontier_removed_peers` (decision 8).
- `bundle_id` — new K_bundle's content-addressed id. Declares the
  canonical name for the fresh bundle.

**Atomicity:** impossible to have a `frontier_advance` without a new
bundle, or a removal without rotation. The
`workspace/commands.rs:971-1015` two-step sequence becomes one step.

**Multi-parent:** `prev_frontier_refs` is a set (vec of sorted
event_ids). Two concurrent advances referencing the same parent
produce two siblings; both populate `frontier_removed_peers`; queries
read the union. No linearization required — codex's gap at
`FS_ALT_CONVERGENT_WRAP_DESIGN.md:614-620` is addressed structurally.

**Deps:** each `prev_frontier_ref` is a blocking dep. Standard
dep-machinery cascade. Matches how `removal` + `key_rotation`'s
`frontier_ref_*` slots work today.

**Bundle materialization:** admin emits the event + emits a local
`KeySecret(K_bundle)` for the new bundle (same deterministic pattern
as today's rotation path). Trigger B immediately fires for active
invites. Other members receive K_bundle via trigger C after
publishing their own key_request (or they materialize it on
the next message send if they're not admin).

**Retires:** `key_rotation` + `removal` events. Their projectors +
schemas + tests migrate/retire in lockstep.

**Tests to migrate:** `src/state/projection/apply/tests/removal_rotation.rs`
is primarily rewritten rather than retained — the event set
changes. But the multi-parent convergence invariants at
`:309-483` transfer directly: same property expressed over
`frontier_advance` siblings.

---

### 10. KDF `K_m` with per-peer sequence + lazy pre-derive on retirement

**What:** derive K_m from K_bundle via HKDF, namespaced by
`(sender_peer_id, seq)`. Each peer owns their own seq counter per
bundle with a **per-peer send quota of N** enforced by the send
path (seq = N triggers mandatory rotation via `frontier_advance`).
During normal operation, K_m's are derived on demand per message
(cache-on-first-derive). **Only when a peer processes a
`MessageDeletion` that retires K_bundle do they pre-derive the
remaining allotment** for every OTHER peer on the frontier — then
shred K_bundle. Drops the `message_key` event entirely.

**K_bundle lifetime is the bundle's natural lifetime** (same as
today), ending at delete-triggered retirement via the self-
contained MessageDeletion from decision 6 + gate from decision 7.
Lazy pre-derive occurs as the last step BEFORE the shred, within
the same transaction as the retirement cascade. Eager pre-derive
at provisioning was considered and rejected: it pays P × N
derivations on every bundle rotation regardless of whether any
delete ever happens. Lazy pre-derive pays that cost only for
bundles that actually get a deletion, and only for the uncached
portion of the allotment.

**Derivation:**
```
K_m(peer_id, seq) = HKDF-Extract-and-Expand(
    salt = bundle_id,
    ikm  = K_bundle,
    info = "fs-per-message-v1" ‖ peer_id ‖ seq,
    L    = 32
)
```

**Encrypted message header gains:**
```
sender_peer_id: [u8; 32]    // (carried via signer envelope, implicit)
seq:            u32         // monotonic per (sender, bundle)
```

No random salt needed — (peer_id, seq) gives uniqueness by
construction. No collisions possible; sender's seq is monotonic
in their own slot.

**Why pre-derive the full allotment (not a rolling buffer).**

Scenario that motivates this: Alice deletes M1 at T. Her cascade
retires K_bundle locally. Bob and Carol are in a long network
partition. At T+ε, Bob and Carol continue sending under the same
bundle — Bob sends msgs with seq = 47, 48, …, 312 before the
partition heals. When the messages finally reach Alice, her
K_bundle is gone — she cannot derive `K_m(Bob, S)` for any S she
hasn't already cached.

A rolling buffer ("next 64 K_m's per sender") wouldn't cover this:
by the time Alice saw seq=47, she'd only have 47..111 derived.
Bob's 312 is outside the window.

**Full allotment fixes this.** Each peer has a send quota of N
per bundle, enforced at send time (seq ≥ N → must rotate). So
Bob's seq is *necessarily* in [0, N) for this bundle — any send
beyond that forces Bob to publish a `frontier_advance` and switch
to a new K_bundle. If Bob sent more than N under a given bundle,
that's a protocol violation.

If we pre-derive all N slots per peer at provisioning, Alice
covers every possible sender seq under the current bundle
regardless of partition length. No UX gap.

Today's branch drops these in-flight messages on the floor. This
fixes it.

**Lazy pre-derive on retirement:**

During normal operation:
- Sender: when sending a new message, derive `K_m(self, seq)`
  from K_bundle, use it, cache it keyed by `k_m_id`. Advance
  `local_next_seq`. If `local_next_seq == N`, rotate (emit
  `frontier_advance`) instead of sending.
- Recipient: when receiving a message with header `(sender, seq)`,
  derive `K_m(sender, seq)` from K_bundle if not already cached
  (cache-on-first-derive).

At `MessageDeletion` retirement (the cascade from decision 6):
1. For each OTHER peer P on the frontier:
   - Compute `observed_max_seq[P]` = highest seq received from P.
   - For `seq ∈ [observed_max_seq[P] + 1, N)`:
       - Derive `K_m(P, seq)`, cache keyed by `k_m_id`.
2. `secure_shred_blob` K_bundle from `key_secrets`.
3. Insert into `retired_bundles`.

Self doesn't need pre-derive: after this peer retires K_bundle,
they rotate on next send (won't derive more K_m's under the
retired bundle).

Pre-derive cost per retirement: `P × (N - observed_max_seq_avg)`.
In typical usage (delete arrives mid-bundle), that's roughly
`P × N / 2`. At P=10, N=1000 → ~5k derivations, ~160 KB
cache added. Paid once per retired-bundle-per-peer, not per
bundle.

**Why lazy beats eager:**
- Bundles that never see a deletion cost zero pre-derive.
- Bundles that do see a deletion cost only the uncached remainder,
  not the full allotment.
- Pre-derive happens atomically with the retirement cascade — no
  window where K_bundle is shredded but cache isn't populated.

**N as a policy parameter tied to rotation cadence.** If the
workspace rotates per frontier_advance (membership change), N
can be generous (1000 or higher — bundles typically span
membership-stable periods). If more frequent rotation is
desired, N is smaller. Workspace-configurable.

**Send path enforces the quota.** Send path checks `next_seq < N`;
if `next_seq == N`, sender emits `frontier_advance` before
proceeding. This bounds the pre-derive size and makes recipients'
allotments definitive.

**Mid-bundle peer addition (via `frontier_advance`):**

Under lazy pre-derive, a new peer joining mid-bundle is
straightforward while K_bundle is still alive:
- Trigger A fires (decision 5), emitting per-K_m `key_shared` for
  each cached row to the new invite pubkey.
- Other peers derive K_m's for the new peer's future sends on
  demand as those messages arrive.

If the new peer arrives AFTER the bundle's retirement: K_bundle
is gone, but pre-derived allotments for the retired bundle exist.
Trigger A still emits per-K_m `key_shared` for all cached K_m
rows — including the pre-derived ones — to the new invite
pubkey. New peer can decrypt any message under the retired
bundle, including late ones.

**Caching identifier.**

`K_m(peer_id, seq)` for bundle B needs a stable id:

`k_m_id = blake3("fs-km-v1" ‖ bundle_id ‖ peer_id ‖ seq)`

Stored in `key_secrets` keyed by this content-addressed id. Fits
the existing schema. `MessageDeletion.message_key_event_id` (field
from decision 6) IS `k_m_id`. Cascade + `retired_keys` gate
unchanged.

**Why per-peer namespacing (not shared seq).**

- **No coordination needed.** Each peer advances their own seq
  without consulting others. Concurrent sends can't collide.
- **Pre-derive is per-(peer, bundle) independent.** Alice's buffer
  for Bob is populated by Alice alone; no need to sync with Bob.
- **Per-peer revocation is implicit.** When Bob is removed from
  the frontier, Alice simply stops refreshing Bob's buffer.
  Already-cached entries get purged at retirement / bundle change.

**FS story — same as today, not strictly stronger.**

- K_bundle lives for the full bundle lifetime. Attacker compromise
  during that window = K_bundle leak = any K_m recoverable.
  Same as today's weak-FS edge.
- Delete-triggered retirement shreds K_bundle. Attacker compromise
  post-delete = no K_bundle. Same as today.
- Per-message granularity via `retired_keys` gate + ciphertext
  shred. Same as decision 6/7.
- Pre-derive buffer is NOT a FS weakener: it caches only K_m's
  that K_bundle could already derive. An attacker who had K_bundle
  (before delete) already has these. After delete, buffer survives
  but only covers a bounded window; messages outside that window
  are unrecoverable.

**What pre-derive ACTUALLY buys** is UX, not FS:
- No messages lost during delete propagation.
- Clean recovery from transient bundle-state-loss (e.g., DB
  corruption on one peer while others still hold K_bundle — the
  affected peer's pre-derive buffer can be re-seeded via
  `key_request`).

**What drops from the branch:**
- `src/event_modules/message_key.rs` entirely (~400 LOC)
- `message_keys` table
- `messages_to_message_keys` reverse index
- `message_key`'s dep chain; `message` deps directly on a single
  `KeySecret` row keyed by `k_m_id`.

**Per-peer storage delta (100k messages, 10 peers, N=1000):**
- Drops ~300k SQL rows + ~13 MB wire for `message_key` events.
- Adds: for every deletion-retired bundle, ~P × N/2 K_m rows
  pre-derived on retirement. At typical usage (delete mid-bundle),
  that's ~5k rows = ~160 KB per retired bundle.
- Bundles never retired cost zero pre-derive.
- Observed K_m rows already cached are shared between the
  normal-operation cache and the pre-derive cache (same key).
- Net: storage strictly better than today for bundles without
  deletions, and comparable-or-better for retired bundles, while
  gaining arbitrary-partition late-decrypt.

**Adoption optionality:**

Decision 10 is a large structural change but orthogonal to 1–9.
Ship phases 1–9 first (conservative), then 10. Or ship together if
the team is comfortable with the wire break.

**Differs from the HKDF path the branch previously rejected:**

Previous rejection was for bolting HKDF onto `message_key`. This
shape:
- Drops `message_key` entirely.
- Namespaces derivation by `(peer_id, seq)`.
- Adds a rolling pre-derive buffer to close the "messages lost in
  flight at delete time" UX gap.
- Pairs with decision 6's ids-in-deletion so per-message purge
  granularity is preserved without `message_key`.

Structurally different from the rejected path.

**Open questions:**

- **Default allotment N (per-peer send quota).** Workspace-
  configurable. Tradeoff:
  - Larger N → longer bundle lifetime, larger pre-derive cost at
    retirement, less rotation churn.
  - Smaller N → more frequent rotations, smaller pre-derive cost,
    more `frontier_advance` events on the wire.
  Pick based on expected message cadence. 1000 is a reasonable
  default for "one bundle ≈ one day of active chat."
- **Proactive K_bundle shred for stronger FS.** Lazy pre-derive
  keeps K_bundle alive for the bundle's full natural lifetime.
  An alternative is to proactively pre-derive + shred K_bundle at
  some point before retirement (e.g., after N/2 messages
  observed). This shortens K_bundle's attack window but costs
  eager pre-derive. Held as a follow-up once lazy-pre-derive
  lands — orthogonal to correctness.
- **Pre-derive cache lifetime after retirement.** Retain until
  the next `frontier_advance` or until explicit purge. Individual
  K_m rows are wiped via `retired_keys` on their own message
  deletes. Full-bundle cache cleanup is natural at frontier
  advance (new bundle supersedes old).
- **Seq overflow.** u32 seq = 4B messages per peer per bundle,
  but the quota N caps this well below overflow. Non-issue.
- **Cross-quota violation by byzantine peer.** A malicious peer
  could send seq ≥ N anyway, producing messages with no
  pre-derived K_m. These fail to decrypt; recipients log the
  protocol violation. Byzantine handling is out of scope for FS
  but worth noting for the spec.
- **Pre-derive atomicity.** Must happen in the same transaction
  as the retirement cascade. If the tx fails mid-derive, retry
  from scratch. Non-atomic = FS gap (K_bundle shred without
  full pre-derive = unrecoverable late messages).

---

## FS guarantees

- Delete-triggered K_bundle retirement: `retired_bundles` gate
  refuses rehydration post-delete.
- Per-K_m purge: `retired_keys` gate at per-message granularity.
- Weak-FS edge for retain-then-compromise attacker: accepted, same
  as today.
- Strong-FS for no-retention attacker: holds at message granularity.
  Deletion of message X retires `X.K_m` via `retired_keys` and
  purges X's ciphertext; an attacker compromising a peer post-delete
  finds no ciphertext for X, no cached K_m, and — if K_bundle was
  retired OR shredded post-pre-derive (decision 10) — no derivation
  path. X is unrecoverable.
- **Arbitrary-partition late-decrypt under decision 10:** K_bundle
  is shredded only at delete-triggered retirement (same as today).
  But at bundle provisioning, peers pre-derive the full allotment
  of N K_m's per (peer, bundle) — the rotation-policy cap on how
  many messages a peer can send before forced rotation. This
  allotment cache survives K_bundle retirement, covering
  decryption of any in-flight message sent under the pre-delete
  bundle regardless of partition length (bounded by N per peer).
  Today's branch drops these messages on the floor.
- **Improvement over the current branch's bundle-granularity
  tradeoff for joiners.** Under v2, new joiners receive
  surviving-message K_m's via trigger A even when K_bundle is
  retired. So the joiner-facing FS boundary is per-deleted-message,
  not per-bundle. Deleted messages stay invisible to joiners;
  surviving messages become visible. Today's branch drops both.

---

## What codex flagged that v2 addresses

| Codex gap | v2 resolution |
|---|---|
| `wrap_event` convergence broken (nonce + ciphertext emitter-dependent) | Decision 3: deterministic ephemeral sender keypair → byte-identical sealed box |
| No canonical dep key | Decision 4: preserve `k_bundle_local_event_id` via existing deterministic KeySecret emit |
| `retired_keys` is fiction | Decision 7: full schema + gate point + populator specified |
| Trigger A dead-end for retired bundles | Decision 5: trigger A iterates ALL `key_secrets` rows (K_bundle AND per-message K_m), so joiners DO receive surviving K_m's under retired bundles. Fully resolves the gap AND *improves* on today's branch, which drops surviving messages for joiners. Obsoletes `joiner_after_bundle_retirement_sees_undeleted_tail_as_history_lost`; replace with `joiner_sees_surviving_messages_in_retired_bundles`. |
| Entitlement predicate too weak | Decision 8: SQL-table query against materialized `frontier_removed_peers` |
| `frontier_advance` linearization breaks multi-parent | Decision 9: `prev_frontier_refs: Vec`, flat set in `frontier_removed_peers`, union queries |
| Factual errors about current branch (§1.1/§7.1/§7.4) | Acknowledged; the v1 doc's §1/§7 will be rewritten when this plan is executed |
| "Already litigated" HKDF rejection | Decision 10: paired with self-contained deletion, different shape from the rejected variant |

---

## Deferred / out of scope

- **DoS rate-limiting spec for `key_request`.** Soft rate-
  limit via `valid_until_ms`; ban-on-abuse via signed audit trail
  (admin publishes `frontier_advance` with offender in
  `removed_peers`).
- **Multi-device request coalescing.** Two devices of one user may
  independently publish requests. Both get answered. Future
  optimization.
- **Migration plan from current `per-message-fs` branch.** This doc
  is a design; the execution plan is separate. Migration is a
  coordinated wire-format break with defined cutover.
- **TLA+ updates.** Scope of the adoption execution plan.
- **On-the-wire targeted delivery optimization.** Mentioned in v1
  §3.3; a transport-layer optimization independent of the event
  model.

---

## Open questions

- Exactly how does `frontier_advance`'s `prev_frontier_refs` cap
  size? Current `key_rotation` uses 4 slots + overflow mechanism.
  Reuse the same cap.
- Should `frontier_removed_peers` also carry
  `added_at_frontier_ref` to express membership windows, or is
  removal alone sufficient? Depends on whether we want to query
  "when was this peer added." For the entitlement predicate, only
  the removal set matters.
- `key_request` `valid_until_ms` — what's the default?
  Hours for explicit heal requests; invite's own `valid_until_ms`
  for invite-implicit requests. Pick concrete defaults at
  implementation time.
- Should `key_shared` under decision 3 still carry a `created_at_ms`
  of 0 (pure determinism) or match the triggering event's timestamp
  (deterministic given the trigger)? Pick 0 unless ordering becomes
  load-bearing elsewhere.

---

## Adoption sequencing

Follow-on execution plan after `per-message-fs` lands on master.

**Phase 1 — dep-chain refactor (1 week):**
- Make `key_shared` projector emit deterministic `KeySecret(K_bundle)`
  on unwrap (decision 4). Net change: one `emit_commands.push()`
  line in the projector. Verifies the dep chain works without any
  other changes.

**Phase 2 — deterministic `key_shared` construction (1 week):**
- Switch `key_shared` emission to the deterministic ephemeral
  keypair construction (decision 3). Drop signature. Update tests.

**Phase 3 — `key_request` + trigger C (1–2 weeks):**
- Add `key_request` event + `eph_privkeys` table (decision 2).
  Retargets / replaces today's `key_request.rs` and
  `key_bundle_request.rs` events.
- Add trigger C response path (decision 5).
- Support all four `target_kind` values from the start so per-K_m
  recovery for existing members (§"Per-K_m recovery…") works from
  day one.
- Rewrites the heal loop in `runtime/key_repair.rs` to emit
  `key_request` events instead of today's bespoke heal protocol.

**Phase 4 — triggers A/B (1 week):**
- Add `user_invite` / `device_invite` projection side-effect:
  enumerate entitled bundles, emit `key_shared` for each.
- Add `KeySecret(K_bundle)` projection side-effect: enumerate
  active invites, emit `key_shared` for each (trigger B).
- Drop `key_history_bundle` entirely.

**Phase 5 — `retired_keys` + self-contained deletion (1–2 weeks):**
- Add `retired_keys` table + gate (decision 7).
- Extend `MessageDeletion` wire shape with three id fields
  (decision 6). Backfill on re-projection of existing tombstones.
- Drop `messages_to_message_keys` reverse index.

**Phase 6 — entitlement materialization (1 week):**
- Add `frontier_removed_peers` table + projector population
  (decision 8).
- Replace lineage walks in `key_repair.rs` with SQL-query calls.

**Phase 7 — `frontier_advance` (2–3 weeks):**
- Add `frontier_advance` event (decision 9). Migrate emitters
  (removal, scheduled rotation, delete-triggered rotation).
- Retire `removal` + `key_rotation` event types. Migrate tests.

**Phase 8 — optional KDF K_m (1 week):**
- Add `kdf_salt_12B` to `Encrypted` header. Switch send/receive
  paths to HKDF derivation with cache-on-first-derive. Drop
  `message_key` event entirely.
- Gated behind a version bump; can be deferred indefinitely.

Each phase is independently landable and testable.

---

## Relation to v1 and the codex review

- `FS_ALT_CONVERGENT_WRAP_DESIGN.md` (v1) — original proposal.
  Retained for context. Its §2 event shapes and §3 distribution
  mechanics remain mostly valid with the renames/corrections in
  decisions 1, 3, 4; §4 `retired_keys` was underspecified (fixed
  in decision 7); §5 KDF now pairs with decision 6 (fixed).
- `FS_ALT_CONVERGENT_WRAP_DESIGN_CODEX_REVIEW.md` — codex's
  review of v1. Decisions above directly map to each flagged gap
  (see the mapping table). The "don't adopt as written" verdict
  applies to v1; v2 addresses every concrete gap it raised.
