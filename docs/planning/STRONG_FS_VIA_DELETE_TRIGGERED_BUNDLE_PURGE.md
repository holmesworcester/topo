# Strong FS via Delete-Triggered K_bundle Purge

**Status:** design doc, not yet implemented.
**Supersedes:** the "weak-FS accepted" framing in
`DELETE_TRIGGERED_REKEY_EXECUTION_PLAN.md` (Plan 1 v4).
**Depends on:** Option C wire (landed as commit `db0f7440`) + send-time
emission (landed as commit `e0e8eb40`).

## Why

Option C gives per-message FS against an adversary that compromises
only an honest peer's local state at `T + grace`, provided the message
was deleted before `T - grace`. It does NOT protect against a
realistic relay/helper adversary that retains wire copies of
`message_key` and Encrypted events indefinitely: once such an
adversary later obtains K_bundle from any peer's `key_secrets`, they
can unwrap K_m from the retained `message_key` wire and decrypt the
retained Encrypted ciphertext — regardless of local deletion cascades
on honest peers.

`K_bundle` is therefore an **FS-sensitive long-lived key** in the
current design. Strong FS requires `K_bundle` to become unreachable
on every honest peer as soon as any message under it is deleted.

## Design — single lever, tied to deletion

**A K_bundle survives locally only until the first MessageDeletion
projects for any message that was encrypted under one of its K_m
values. On that deletion, every honest peer purges the K_bundle
plaintext from `key_secrets` in the same transaction that runs the
existing per-message FS cascade.**

This is the tightest possible FS window: the K_bundle's dangerous
lifetime ends at the propagation-speed of the deletion event, not at
the WrapPrivkey grace window (hours to days).

### Why K_m values survive the purge

Option C already decrypts K_m from `message_key.wrapped_k_m` at
`message_key` projection time (`src/event_modules/message_key.rs`
`project_pure` — the AEAD unwrap runs in the projector, and K_m lands
in `key_secrets` keyed by the message_key event id). By the time a
deletion triggers K_bundle purge, every peer has already cached K_m
for every message_key they've seen under that bundle. Purging
K_bundle does not affect those cached K_m rows. Undeleted messages
remain decryptable.

### Why history stays efficient

A K_bundle delivered via `key_broadcast` / `key_history_bundle` to a
new joiner covers every message in that bundle in a single
asymmetric wrap. A late joiner arriving during the bundle's active
life decrypts all `message_key` events they receive and pre-derives
all K_m values locally. **Bundle-level delivery, not per-message
delivery, carries history to new members — as long as no deletion
has retired the bundle yet.**

If a bundle has been retired (some message under it was deleted),
the joiner cannot get K_bundle — nobody has it any more. They fall
back to individually-wrapped K_m delivery via `key_bundle_share`
for the un-deleted messages they need. That path exists already
(Phase 6 of Plan 1 v4) and was always the "retired bundle" cold
path.

## Purge ordering

Canonical lifecycle of a K_bundle on an honest peer:

```
T_emit       Creator device emits `key_broadcast(K_bundle)`.
             Every recipient's projector unwraps and writes
             K_bundle into `key_secrets`.

T_m1 … T_mN  Under this K_bundle, the creator sends messages m1..mN.
             Each `message_key` event carries `AEAD(K_bundle, K_m_i)`
             plus a deterministic nonce. On projection each peer
             decrypts K_m_i and writes it into `key_secrets` keyed
             by the message_key event id.

T_delete     Any peer emits `MessageDeletion` for some m_j in this
             bundle. On every honest peer, the deletion cascade now
             does (in one transaction):
               1. Purge the target message (as today):
                  - Encrypted blob row
                  - message_key row
                  - K_m_j row in key_secrets
                  - messages_to_message_keys reverse index row
               2. NEW: purge the K_bundle plaintext:
                  - K_bundle row in key_secrets
                  - Leaves all other K_m rows (for m1..m_N except m_j)
                    intact — undeleted messages stay decryptable.

T_delete+ε   If the creator next calls `ensure_content_key_for_peer`
             (i.e., sends another message), it sees no
             `key_rotations JOIN key_secrets` match for the current
             frontier (K_bundle row was purged from their own state
             too) and rotates to a fresh K_bundle automatically. No
             explicit "force rotate" hook needed. If the creator
             never sends again, no rotation happens — the bundle is
             quietly retired. Symmetric purge + existing rotation
             logic does the whole job.
```

At `T_delete`, on every honest peer, it becomes cryptographically
impossible to recover K_m for any message whose message_key event
arrives after `T_delete` and references the retired K_bundle. Such
message_key events project as blocked on a `k_bundle_local_event_id`
that no longer exists in any honest peer's state. Those messages are
effectively lost — but in practice the creator's next send rotates
to a fresh bundle before any such lost-in-flight case can occur, so
this is a consistency property rather than a correctness hazard.

## Invariants

1. **K_bundle is purged on the first `MessageDeletion` for any of
   its messages, on every honest peer.** Atomic with the existing
   per-message cascade. No per-deletion bundle-enumeration join is
   needed: the reverse index `messages_to_message_keys` already maps
   `message_event_id → message_key_event_id`, and the message_key
   row records `k_bundle_local_event_id`.

2. **K_m values survive K_bundle purge.** They live in `key_secrets`
   keyed by their own `message_key_event_id`, not by
   `k_bundle_local_event_id`. The purge is a single-row delete
   (the K_bundle's row), not a cascade over all K_m's.

3. **Rotation on next send emerges naturally — no explicit
   "force rotate" machinery.** The K_bundle purge is symmetric: the
   creator's own `key_secrets` row is shredded along with every
   other honest peer's. `latest_content_key_for_frontier`
   inner-joins `key_rotations JOIN key_secrets`, so a KeyRotation
   row that no longer has a matching `key_secrets` row returns None,
   and `ensure_content_key_for_peer_at` rotates automatically on
   the creator's next send. If the creator never sends again, no
   rotation happens — the bundle is quietly retired.

   Math: rotation costs ~524 KB per `key_broadcast` emission;
   retired-bundle cold-path history delivery (individually-wrapped
   K_m per un-deleted message at ~200B each) is cheaper than
   rotation for any bundle with fewer than ~2620 messages. For
   typical chat workloads, not rotating on delete is the cheaper
   choice.

4. **Per-device K_bundle lineage.** Each sender device has its own
   K_bundle stream. Another device's deletion cascade does NOT purge
   this device's K_bundle. Without per-device lineage, one deletion
   would retire every concurrent sender's bundle simultaneously, which
   would amplify the rotation storm.

5. **WrapPrivkey purge is independent hygiene, not the FS lever.**
   Strict shred of WrapPrivkey bytes at `valid_until_ms + grace`
   prevents resurrection of K_bundle from retained `key_broadcast`
   wire in scenarios where a peer failed to purge proactively
   (disk backup, forensic image). This is a defense in depth; FS
   correctness does not require it when deletion-triggered purge is
   timely.

## What stays the same (Option C is still correct)

- `message_key` wire event and its AEAD-wrapped K_m payload.
- Per-message Encrypted wrapper keyed by `message_key.event_id`.
- `messages_to_message_keys` reverse index.
- Three-way producer fanout (`key_broadcast`, `key_history_bundle`,
  `key_bundle_share`) materializing one canonical K_bundle.
- Existing per-message FS cascade (delete → purge K_m + ciphertext +
  message_key + reverse index row).

The ONLY delta to projection is one extra row-delete in the deletion
cascade: `DELETE FROM key_secrets WHERE event_id =
<k_bundle_local_event_id of the target message's message_key>`.

## Implementation plan

### Phase A — Add K_bundle purge to deletion cascade

Touch: `src/state/projection/purge.rs`
(`collect_projection_dependents`).

After the existing lookup that walks `messages_to_message_keys` to
enumerate the message_key row(s), ALSO enumerate the
`k_bundle_local_event_id` referenced by each message_key row and add
it to the purge manifest as an event id to remove from `key_secrets`.

```sql
-- collect K_bundle event ids (one per message_key row already in
-- the manifest):
SELECT DISTINCT k_bundle_local_event_id
FROM message_keys
WHERE recorded_by = ?1 AND event_id IN (<manifest>)
```

In the subsequent row-delete pass (`delete_tenant_rows`), add the
K_bundle event ids to `key_secrets` delete targets alongside the
K_m event ids that are already being deleted.

### Phase B — Secure shred for K_bundle bytes

Same shred helper from the earlier plan, but applied once at bundle
purge time:

```rust
pub fn secure_zero(bytes: &mut [u8]);

pub fn secure_shred_blob(
    conn: &Connection,
    table: &'static str,
    blob_col: &'static str,
    where_col: &'static str,
    where_val: &str,
) -> rusqlite::Result<()>;
```

`delete_tenant_rows` routes K_bundle deletions through
`secure_shred_blob` (overwrite key_bytes column with zeros before
DELETE). Existing K_m deletes can optionally also use it — K_m is
already gone-on-delete in Option C, but shredding hardens against
SQLite page-reuse leakage.

### Phase C — (NOT NEEDED)

No explicit code. Rotation on next-send emerges for free from the
symmetric purge in Phase A + the existing `JOIN key_secrets` in
`latest_content_key_for_frontier`. Briefly delayed first-send
after a deletion is acceptable (happens serially on one device).

### Phase D — Pattern-(b) polish on heal path

Already pending from the Phase-8 sim test matrix. The `key_bundle_share`
cold-path (individually-wrapped K_m delivery for a joiner arriving
after bundle retirement) already exists architecturally; needs pattern-(b)
refactor + a dedicated test that exercises "joiner arrives after a
deletion retired the bundle."

### Phase E — WrapPrivkey hygiene (defense in depth)

Separate track, lower priority now that the primary FS trigger is
deletion-driven. When done:
- `secure_zero` + `secure_shred_blob` for WrapPrivkey rows.
- Background sweep that shreds WrapPrivkey rows at `valid_until_ms + grace`.
- Does NOT cascade to K_bundle — those are already gone (purged on
  deletion) or harmless (no deletions ⇒ no FS risk for the bundle).

### Phase F — Tests

1. **Delete triggers K_bundle purge.** Send 3 messages under one
   K_bundle, delete message 2. Assert K_bundle row gone from
   key_secrets; K_m rows for messages 1 and 3 still present;
   messages 1 and 3 still decryptable via `messages` table listing.
2. **K_m survives K_bundle purge.** Same setup; explicitly dump
   key_secrets and check by event id.
3. **Retained wire + post-purge compromise fails.** Construct a
   scenario: peer A has K_bundle; a retained `message_key` wire
   blob is kept in a test buffer; delete triggers purge; assert
   there is no mechanism (projection retry, orphan recovery, etc.)
   that re-materializes K_bundle from the retained blob.
4. **Creator forced-rotation.** Peer A authors msg1..5 under
   bundle B. Someone deletes msg3. Peer A's next send rotates to
   bundle B'. Verify on wire: new `key_broadcast` emitted; next
   `message_key` references B' not B.
5. **Late-arrival message_key on retired bundle.** Peer A sends
   msg6 concurrent with the deletion of msg3. msg6's message_key
   arrives at peer B after the deletion. Assert msg6's message_key
   stays blocked (k_bundle_local_event_id missing); msg6 is not
   decrypted. (Expected outcome — the creator MUST rotate.)
6. **Joiner after bundle retirement.** Peer C joins after peer A's
   bundle B has been retired. The `key_history_bundle` path cannot
   deliver B (nobody has it). Peer C receives individually-wrapped
   K_m values for un-deleted messages via `key_bundle_share` and
   decrypts them.
7. **Per-device isolation.** Two sender devices concurrently use
   their own K_bundles. Delete a message from device 1's bundle.
   Assert device 2's bundle is unaffected.

## Threat model — what we claim

After `T_delete + propagation_delay` on any honest peer:

- Adversary with only retained wire (no peer state): recovers
  nothing. K_bundle plaintext is gone on every honest peer; K_m for
  the deleted message is gone on every honest peer; K_m for the
  retained `message_key` blob can only be unwrapped if they have
  K_bundle, which they don't.
- Adversary with retained wire AND peer state compromised after
  `T_delete + propagation_delay`: same as above. The compromised
  peer's `key_secrets` has K_m for un-deleted messages, NOT the
  deleted one, and NOT K_bundle. Attacker can decrypt un-deleted
  messages (as expected — those messages are not deleted) but
  cannot recover the deleted one.
- Adversary with retained wire AND peer state compromised BEFORE
  `T_delete + propagation_delay`: recovers K_bundle + K_m's present
  at compromise time. This is the tight window our design bounds to
  "time between deletion emit and deletion arrival at each honest
  peer" — typically seconds to a few minutes under normal sync.

What we do NOT claim:

- FS within the propagation window. A message deleted at T_d is
  still at risk on peers that have not yet received the deletion.
  The bound is the sync-latency of `MessageDeletion` events.
- FS against hardware-level SSD forensics (wear-leveling, bad-block
  remap, TRIM timing). `secure_zero` addresses RAM; filesystem-level
  residues require OS/hardware primitives outside this plan.
- FS against peers who refuse to purge. An honest-but-hoarding peer
  remains a decryption oracle for everything they saw. This is a
  social-contract matter, not a cryptographic one.

## Not in scope (explicitly rejected)

- **`purged_bundles` terminal-state table / bundle-expiry wire
  metadata.** Codex raised this as a Medium concern against the
  earlier "WrapPrivkey-expiry gates everything" design. Under
  deletion-triggered purge it is unnecessary: the local purge IS
  the terminal state; no replay of old `key_broadcast` can
  resurrect a K_bundle whose plaintext has been shredded
  everywhere.
- **MessageDeletion as bundle-expiry marker.** The deletion
  triggers the purge; it does not NEED to be the marker. The local
  purge itself is terminal.
- **Deterministic K_m index-based pre-derive (HKDF chain).**
  Keeping Option C's `message_key` wire event is strictly simpler:
  per-message wrapped K_m values continue to materialize on
  projection, and the delete cascade targets them individually via
  the existing reverse index. No wire-shape rewrite needed.
- **Message re-encryption on delete** (the original "rekey" idea
  from Plan 1 v1/v2). Fully replaced by delete → bundle-purge lever.

## Open questions

1. **Creator rotation latency.** Between the moment a deletion
   projects on the creator and the moment they next send, their
   next message could still try to use the retired bundle. The
   `dirty_bundles` table approach serializes this correctly via
   the `ensure_content_key_for_peer` check, but if rotation takes
   time (generating a new wrap, emitting a new key_broadcast to
   all recipients), the send could be briefly delayed. Measure.

2. **Amplification on high-deletion workspaces.** A workspace that
   deletes messages frequently will force K_bundle rotations
   frequently, each costing ~260 KB per device for the new
   `key_broadcast`. In the limit, one deletion per message = one
   rotation per send = bandwidth collapses. Accept or mitigate:
   - Accept: for typical chat workloads, deletions are rare.
   - Mitigate: rate-limit rotations. If a new deletion arrives
     within N seconds of the last rotation, treat the current
     bundle as already-dirty and don't rotate again until N
     passes. Creates a brief window where the "just-rotated"
     bundle is FS-sensitive — tune N to taste.

3. **Delete-before-create interaction.** An author-delete-intent
   can arrive before the message itself. Option C handles this via
   `deletion_intents` + `HardPurgeMessageGraph` on the message's
   later arrival. Need to verify the K_bundle purge path fires in
   this ordering too (the reverse index is populated at Encrypted
   projection, which happens at create time — so the join works
   symmetrically).

4. **Joiner-after-retirement cold path cost.** If a bundle had N
   messages and was retired, a new joiner now gets N individually-
   wrapped K_m deliveries instead of one K_bundle delivery. For a
   bundle with 1000 messages, that's 1000 × (~150 B per wrap) =
   ~150 KB — compared to 1 × (~260 KB for one K_bundle delivery
   via key_history_bundle). Still a win bandwidth-wise, but the
   join latency may grow. Measure.

5. **Offline-peer decision point.** A peer offline for a long time
   comes back, sees a batch of deletions + a batch of message_key
   events for the retired bundle. They purge K_bundle AT THE
   MOMENT the deletion projects. Some message_key events may
   arrive AFTER the deletion in their local replay order, making
   them unprojectable. Need to decide: do we reorder replay to
   project all message_keys before deletions? Or accept that some
   messages may be blocked-forever after late sync? The latter is
   cleaner and matches how "rotation on deletion" is supposed to
   work — the creator should have rotated long before this peer
   came back online.

## Incremental landing checklist

- [ ] Phase A — extend `purge.rs` deletion cascade to include
       K_bundle row in `key_secrets`
- [ ] Phase B — `secure_zero` + `secure_shred_blob` helpers for
       K_bundle rows (and optionally K_m)
- [x] Phase C — dropped; natural rotation via existing
       `ensure_content_key_for_peer` inner-join suffices
- [ ] Phase D — pattern-(b) polish on `key_bundle_share` heal path
       and a retired-bundle joiner test
- [ ] Phase E — WrapPrivkey hygiene (shred + grace sweep) on its
       own track
- [ ] Phase F — 7 tests listed above
- [ ] Doc — update `DELETE_TRIGGERED_REKEY_EXECUTION_PLAN.md` to
       cross-reference this plan and mark "weak FS" as superseded
       once this lands
- [ ] Doc — refresh `MEMORY.md` to reflect deletion-triggered
       bundle purge as the primary FS lever

## Artifacts

- Threat model + design discussion: this file.
- Codex feedback on earlier redesign attempts:
  `/tmp/codex_grace_feedback.txt`.
- Option C wire reference: `SEND_TIME_MESSAGE_KEY_INTEGRATION.md`.
- Original plan (pre-superseded): `DELETE_TRIGGERED_REKEY_EXECUTION_PLAN.md`.
