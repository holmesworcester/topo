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

### 10. KDF `K_m` with per-peer sequence + rolling pre-derive buffer

**What:** derive K_m from K_bundle via HKDF, namespaced by
`(sender_peer_id, seq)`. Each peer owns their own seq counter per
bundle. Peers maintain a rolling pre-derive buffer of the next N
K_m's per (peer, bundle), refreshed as seq advances. Drops the
`message_key` event entirely.

**K_bundle is NOT shredded proactively.** It lives for the full
bundle lifetime, exactly as today. Delete-triggered retirement is
the shred trigger (decision 7 via self-contained MessageDeletion
from decision 6). The pre-derive buffer exists for a specific UX
reason, not an FS reason — see "Why pre-derive" below.

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

**Why pre-derive (the late-decrypt grace window).**

Scenario that motivates this: Alice deletes M1 at T. Her cascade
retires K_bundle locally. Bob hasn't synced the delete yet; at
T+ε he sends M2 under the same bundle, with `seq=S`. When Alice
receives M2, her K_bundle is gone — she cannot derive
`K_m(Bob, S)` from K_bundle. She can't decrypt M2 and M2 appears
"lost" to her.

Under today's branch this happens too, and it's a real UX
problem. The `retired_bundles` gate refuses re-hydration of
K_bundle, so even if a late `key_rotation` arrives, Alice's local
state stays retired. Messages in flight at delete time are
dropped on the floor.

**Pre-derive fixes this.** Before the delete, Alice's rolling
buffer already contained `K_m(Bob, S)` for S in Bob's expected
range. When K_bundle is shredded on delete, the buffer survives.
Alice decrypts M2 from her cached K_m row. No gap.

**Rolling buffer maintenance:**

At any moment, a peer maintains for each (other_peer, bundle):
- Cached K_m's for observed seqs up to `observed_max_seq`
- A pre-derived buffer for seqs `(observed_max_seq, observed_max_seq + N]`

When a message arrives with seq > observed_max_seq:
- Consume from the buffer.
- Derive `observed_max_seq + N + 1` from K_bundle (still live) and
  cache.
- Advance observed_max_seq.

Buffer size N: tune based on how large a "in flight at delete
time" window you want to protect. N = 64 covers ~most practical
delete-race cases; N = 256 is paranoid. Per-peer cost: N × 32 B ×
active peer count. At N=64, 10 peers → 20 KB per bundle. Cheap.

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

**Per-peer storage delta (100k messages, 10 peers):**
- Drops ~300k SQL rows + ~13 MB wire for `message_key` events.
- Adds ~20 KB pre-derive buffer per peer per active bundle.
- Net win is still large.

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

- Default buffer size N. 64 is my guess; depends on worst-case
  propagation latency for deletes + peer send rate.
- Should the pre-derive buffer be wiped at delete-triggered
  retirement, or retained? Retaining = longer grace window.
  Wiping = tighter FS bound. Recommend retaining for a configurable
  window (e.g., retain until buffer is fully consumed or
  `retire_at_ms + grace` elapses).
- Seq overflow. u32 seq = 4B messages per peer per bundle. Bundles
  rotate on frontier_advance long before that. Non-issue.

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
- **Late-decrypt grace under decision 10:** K_bundle is NOT
  shredded proactively (same as today). Delete-triggered
  retirement still shreds K_bundle. But a rolling pre-derive
  buffer of K_m's (per (peer, bundle)) survives K_bundle
  retirement, so messages in flight from peers who didn't know
  about the delete can still be decrypted. This is a UX improvement,
  not an FS change — FS story is the same as today.
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
