# Strong FS via WrapPrivkey-Gated K_bundle Purge

**Status:** design doc, not yet implemented.
**Supersedes:** the "weak-FS accepted" framing in
`DELETE_TRIGGERED_REKEY_EXECUTION_PLAN.md` (Plan 1 v4).
**Depends on:** Option C wire (landed as commit `db0f7440`) + send-time
emission (landed as commit `e0e8eb40`).

## Why

Option C gives per-message FS against an adversary that compromises
only an honest peer's local state at `T + grace`, provided the
message was deleted before `T - grace`. It does NOT protect against a
realistic relay/helper adversary that retains wire copies of
`message_key` and Encrypted events indefinitely: once such an
adversary later obtains K_bundle from any peer's `key_secrets`, they
can unwrap K_m from the retained `message_key` wire and decrypt the
retained Encrypted ciphertext — regardless of local deletion cascades
on honest peers.

`K_bundle` is therefore an **FS-sensitive long-lived key** in the
current design. For strong FS against retention-plus-compromise, we
need `K_bundle` itself to become unreachable across the entire
honest population at a bounded time.

## Design — single lever

**`WrapPrivkey` purge is the only FS trigger we need.**

An honest peer's `K_bundle` has exactly two sources:

1. The local plaintext row in `key_secrets`, materialized when the
   peer's projector unwrapped a `key_broadcast` / `key_history_bundle` /
   `key_bundle_share` for that bundle.
2. Re-deriving the plaintext from the retained wire event by
   unwrapping the asymmetric wrap with their corresponding
   `WrapPrivkey`.

Both sources die on the same event: the peer's `WrapPrivkey` is
purged. At that moment:

- Source (2) is cryptographically impossible — the retained wire can
  never be unwrapped again, by this peer or by anyone with a retained
  copy of this peer's state that postdates the purge.
- Source (1) is immediately redundant — local state can safely purge
  the `K_bundle` plaintext too, because there is no way to re-derive
  it if someone deletes it by accident.

Therefore: **when a peer purges a `WrapPrivkey`, they also purge
every `K_bundle` that was wrapped to the corresponding `WrapPubkey`,
in the same transaction.** That is the entire FS story.

## Invariants

1. `WrapPrivkey` purge MUST be cryptographic shred, not a filesystem
   delete. The bytes are overwritten in-place before the row is
   removed. This is the load-bearing assumption; without it the
   single-lever story collapses to codex's original "add a
   `purged_bundles` replay-suppression table" design.
2. `WrapPrivkey` purge is atomic with the purge of every `K_bundle`
   that was derived from a `WrapPrivkey`→`WrapPubkey` asymmetric
   unwrap. No intermediate state where the privkey is gone but the
   `K_bundle` plaintext survives.
3. Senders do NOT keep `WrapPrivkey` past `valid_until_ms + grace`.
   The grace window bounds the FS-sensitive lifetime of any message
   sent under that bundle.
4. Per-device K_bundle lineage: each sender device emits its own
   `key_broadcast` stream, so one peer's K_bundle hoard (if any)
   cannot compromise another device's messages.
5. Before a sender purges their own `WrapPrivkey`, they must have
   either (a) delivered every `message_key` they intend to author
   under the corresponding K_bundle, or (b) accepted that retained
   un-derived K_m values are unrecoverable. In practice this means
   the creator should rotate to a new bundle well before their
   WrapPrivkey's `valid_until_ms`.

## Purge ordering

The canonical lifecycle for a `WrapPubkey` → `WrapPrivkey` → `K_bundle`
triple:

```
T_create      WrapPubkey published; WrapPrivkey stored locally.
T_create +   `key_broadcast(K_bundle_1, …, K_bundle_N)` wrapped to
   rotation  this pubkey; peer unwraps, writes K_bundles into
              key_secrets.
T_rotate     Peer rotates to a new WrapPubkey. Prior WrapPubkey is
              self-tombstoned on wire (already implemented in
              Phase 1, commit 223a0d47). The old WrapPrivkey is
              marked for purge at `valid_until_ms + grace`.
T_valid      `valid_until_ms` elapses. WrapPrivkey is still present
              (in grace window).
T_valid + G  GRACE elapses. Purge runs:
              1. Enumerate every K_bundle row whose unwrap_pubkey
                 points at this WrapPubkey_event_id.
              2. Shred each K_bundle row in key_secrets.
              3. Shred the WrapPrivkey row.
              4. All in one transaction.
```

At `T_valid + G`, on every honest peer:
- No `K_bundle` plaintext exists for any bundle delivered via this
  WrapPubkey.
- The WrapPrivkey cannot unwrap any retained wire copy.
- Retained `message_key` + Encrypted events are now inert.

Messages deleted before `T_valid + G` are recoverable from retained
wire only during the `T_send → T_valid + G` window. After that,
they are unrecoverable by any adversary, including relay-retention
adversaries.

## What stays the same (Option C is still correct)

- Per-message `message_key` event + Encrypted wrapper keyed by
  `message_key.event_id`.
- Per-message K_m; delete cascade purges K_m + ciphertext + reverse
  index immediately on `MessageDeletion`.
- `messages_to_message_keys` reverse index.
- Three-way producer fanout (`key_broadcast`, `key_history_bundle`,
  `key_bundle_share`) materializing one canonical K_bundle.
- Per-device bundle lineage invariant (send time — pending).

The only new behavior: `K_bundle`'s lifetime is now explicitly bounded
by the wrap privkey that delivered it.

## Implementation plan

### Phase A — Secure shred helper

New module: `src/shared/crypto/secure_shred.rs` (or add to existing
crypto module).

```rust
/// Overwrite a byte slice with zeros in-place using volatile writes
/// and a memory barrier so the compiler cannot elide the overwrite.
/// For in-memory scrubbing only; does not address filesystem block
/// retention on SSDs (separate issue).
pub fn secure_zero(bytes: &mut [u8]) { … }

/// Overwrite a BLOB column in SQLite to zeros BEFORE deleting the row.
/// Callers pass the exact key (recorded_by, event_id) + column name.
pub fn secure_shred_blob(
    conn: &Connection,
    table: &'static str,
    blob_col: &'static str,
    where_col: &'static str,
    where_val: &str,
) -> rusqlite::Result<()> { … }
```

All WrapPrivkey and K_bundle purge paths route through these helpers.

### Phase B — Cascade WrapPrivkey purge → K_bundle purge

1. Add a `wrap_privkey_grace_ms` constant. Default: 72 hours (tune
   with input from the WrapPubkey rotation cadence; the smaller this
   is, the stronger FS becomes but the less tolerant to offline
   peers).
2. Add a background sweep (or on-demand check) that runs:
   ```
   SELECT pubkey_event_id, privkey
   FROM wrap_privkeys
   WHERE valid_until_ms + ?grace_ms <= ?now_ms
   ```
   For each row returned, enumerate:
   ```
   SELECT k.event_id, k.key_bytes
   FROM key_secrets k
   JOIN key_broadcasts kb
     ON kb.k_bundle_local_event_id = k.event_id  -- or similar
   WHERE kb.recipient_pubkey = ?pubkey_event_id
   ```
   and call `secure_shred_blob` on each. Then shred the privkey row.
   All within one transaction.

3. Same pattern for `key_history_bundle` and `key_bundle_share`
   wrap-pubkey references.

4. The sweep runs at daemon startup + periodically (every few
   minutes). On-demand triggers on any `wrap_privkey_expiry` event
   projection — so a newly-received rotation event forces the old
   privkey to be reevaluated for purge.

### Phase C — Per-device K_bundle lineage enforcement at send time

(Already carried over from the pending per-message-fs work.)

- Send path resolves the CURRENT device's K_bundle, not a
  workspace-shared content key.
- Counter `i` in `(device_id, bundle_id, i)` is per-device durable.
- `rotate_content_key_for_peer` becomes `rotate_device_bundle_for_peer`.

### Phase D — Creator rotation on deletion awareness (opportunistic)

When the creator's device projects a `MessageDeletion` for one of
its own messages (or receives authorization that a peer-author
deletion was valid), it MAY proactively rotate to a new K_bundle on
its next send. This does not affect FS correctness — WrapPrivkey
purge still bounds everything — but it shortens the window where
retained-wire attacks work for future deleted messages.

This is policy, not protocol. Implement as a config flag.

### Phase E — Tests

1. **Pre-grace retention attack fails the expected way.**
   - Peer A sends a message; relay retains wire. Peer A deletes
     locally.
   - Attacker compromises peer B's state at T+30m (within grace).
     They recover K_bundle from key_secrets, unwrap K_m from the
     retained `message_key` wire, decrypt retained Encrypted wire.
     Test asserts this succeeds (not a security bug — weak FS
     window is by design and bounded).
2. **Post-grace retention attack fails.**
   - Same setup, but attacker compromises peer B at T + grace + 1h.
     Test asserts K_bundle is gone from key_secrets, retained wire
     can't be unwrapped, no plaintext recoverable.
3. **Secure shred test** — create a WrapPrivkey, run purge,
   hex-dump the SQLite page, assert no residual privkey bytes.
4. **K_bundle cascade test** — purge one WrapPrivkey, assert every
   K_bundle delivered via its WrapPubkey is gone from key_secrets.
5. **Grace boundary test** — purge runs at
   `valid_until_ms + grace - 1` (no action) vs
   `valid_until_ms + grace` (purge fires).
6. **Multi-device test** — device A's WrapPrivkey purge does not
   affect device B's K_bundle rows.

## Threat model — what we claim

After purge at `T_valid + G`:

- Adversary with only retained wire: recovers nothing (retained wire
  is unwrappable only by the WrapPrivkey that is now gone on all
  honest peers).
- Adversary who compromised peer state BEFORE `T_valid + G`:
  recovers everything the peer had at compromise time. This is
  unchanged from the current design and is not in scope for FS — the
  peer was a legitimate decryption oracle at that moment.
- Adversary with retained wire AND peer state compromised after
  `T_valid + G`: recovers nothing NEW. If the compromised peer had
  already purged (the honest case), no K_bundle plaintext is in
  their state. If the peer hoarded past `T_valid`, the attacker
  gets whatever the peer had — but that peer was trusted with
  K_bundle, so no new leak beyond the peer's own membership window.

What we do NOT claim:

- FS within the `T_send → T_valid + G` window. A message deleted
  during this window is still recoverable via retained-wire +
  concurrent compromise.
- FS against hardware-level disk forensics after a shred.
  `secure_zero` addresses in-memory; SSD wear-leveling is a
  separate question needing OS / hardware primitives we don't have
  here.
- FS against peers who refuse to purge. An honest-but-storage-
  hoarding peer remains a decryption oracle for anything they saw.

## Not in scope (explicitly rejected)

- **`purged_bundles` terminal-state table** (codex's Medium finding).
  Not needed because WrapPrivkey purge is strict-shred and
  irreversible; replay of old `key_broadcast` cannot resurrect
  K_bundle.
- **Bundle-expiry wire metadata** (codex's suggestion for
  sender-committed expiry). Expiry is already implied by the
  WrapPrivkey's `valid_until_ms` — no new wire field.
- **`MessageDeletion` acting as bundle-expiry marker**. Per-message
  tombstone is per-message; bundle expiry is per-bundle. Conflating
  them would require a join that runs on every `key_broadcast`
  projection and would be semantically muddy (a single deletion
  doesn't end the bundle for other messages).
- **Deterministic K_m index-based pre-derive** (earlier idea from
  chat). Keep Option C's per-message `message_key` wire event;
  close the relay hole with WrapPrivkey purge instead of rewriting
  the send/decrypt shape. The 133-byte-per-message win is separable
  and doesn't belong on this track.
- **Message re-encryption on delete** (the original "rekey" idea
  from Plan 1 v1/v2). Fully replaced by per-message K_m + bundle-
  expiry lever.

## Open questions

1. **Grace duration `G`.** Trade: shorter G = stronger FS and faster
   protection, but strands offline peers who miss history delivery
   in the window. Start value 72h; revisit with user feedback.
2. **WrapPubkey rotation cadence.** The more often you rotate, the
   shorter each K_bundle's FS-sensitive lifetime. But rotation
   costs bandwidth (a new `key_broadcast` per peer on each rotation).
   Currently tied to `wrap_pubkey.valid_until_ms` — a product
   decision, not a protocol one.
3. **Secure-shred on SSDs.** `secure_zero` overwrites RAM; the
   SQLite on-disk page may remain in an old location due to COW /
   wear-leveling. Addressing this requires either `fstrim` +
   `BLKDISCARD` (OS-level) or running on encrypted filesystems with
   per-file key shredding. Out of scope for this plan; document as
   a known residual attack surface.
4. **Offline peer recovery after grace.** A peer offline longer
   than `G` misses any K_bundle they needed (by design — the whole
   point is everyone purges). History delivery for them requires
   other peers to ship individually-wrapped K_m values via
   `key_bundle_share` — already supported architecturally, needs
   the pattern (b) polish on the heal path.
5. **Per-device lineage at send.** Separate from this FS track but a
   hard prerequisite. Currently the send path uses a workspace-
   shared content key as bundle_id (see
   `create_encrypted_event_with_message_key_via_rotation`); need to
   swap that for a per-device bundle resolver.

## Incremental landing checklist

- [ ] Phase A — `secure_zero` + `secure_shred_blob` helpers + tests
- [ ] Phase B — WrapPrivkey purge sweep wired to grace window
- [ ] Phase B — K_bundle cascade purge on WrapPrivkey shred
- [ ] Phase C — send path resolves per-device bundle
- [ ] Phase D — creator-rotates-on-deletion flag (optional)
- [ ] Phase E — test suite: six tests listed above
- [ ] Doc — update `DELETE_TRIGGERED_REKEY_EXECUTION_PLAN.md` to
       cross-reference this plan and mark "weak FS" as superseded
       once this lands
- [ ] Doc — refresh `MEMORY.md` to reflect the single-lever story

## Artifacts

- Threat model + design discussion: this file.
- Codex feedback on original redesign: `/tmp/codex_grace_feedback.txt`.
- Option C wire reference: `SEND_TIME_MESSAGE_KEY_INTEGRATION.md`.
- Original plan (pre-superseded): `DELETE_TRIGGERED_REKEY_EXECUTION_PLAN.md`.
