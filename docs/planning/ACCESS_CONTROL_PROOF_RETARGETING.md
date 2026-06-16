# Access-Control Proof Retargeting

Date: 2026-04-22
Branch: `remove-fake-proof-and-try-real`
Status: **Course correction. PR #6 not to merge.**

## What the previous proof was aiming at (wrong)

PR #6 builds a chain proving:

> *"Our runtime's Encrypted-event projector does not produce plaintext
> for a non-invited peer."*

Concretely: every arrow from "non-invited peer" to "no plaintext" goes
through our projectors, our SQL writes, our decryption call. Phase 3
pinned the SQL template for `key_secrets`; Phase 1 pinned the sole
executor; the per-projector decision cores pinned per-layer acceptance.

## Why that's the wrong target

**If a peer holds the content key, they can decrypt without using our
code.** The runtime rejecting decryption does not prevent the peer from
writing their own AES-GCM call. The proof says our projector doesn't
hand out plaintext; it says nothing about whether the key ever reaches
someone who shouldn't have it.

The security property is about the distribution of key material, not
about whether our projector runs decryption. Once key material leaks,
the game is over regardless of our code.

## The correct target

> *"Content-key material is shared only to invited peers."*

Concretely: for every Valid `KeyShared` event `K` in any peer's state,
`K`'s recipient is a peer whose user has a valid `InviteAccepted`
chain for `K`'s workspace.

Combined with the cryptographic property that only the recipient's
private key can unwrap `K`'s wrapped_key (AES-GCM / Ed25519
unforgeability — trusted primitive), this gives: *the only peers who
can extract the content key are invited peers*. No runtime decryption
gate needed.

## Why this shape is cleaner

1. **It's an event-graph invariant, not an ambient-state invariant.**
   The claim is about what events exist and to whom they're addressed,
   not about what's in what SQL table at a given moment.

2. **It composes with the recommendations doc's dep-fact direction.**
   Under `REAL_PROOFS_SIMPLIFICATION_RECOMMENDATIONS.md` recommendation
   #1, the KeyShared projector's acceptance would be `(event, DepFacts,
   GuardFacts) -> Result`. The `DepFacts` bundle would include the
   recipient's PeerShared resolution and its user-authority chain. The
   invariant becomes structural: "Valid KeyShared ⟹ recipient dep is
   itself valid and user-admin-chained."

3. **It leaves decryption entirely out of the proof.** Decryption is an
   arithmetic operation over bytes the recipient either has or doesn't.
   If they have the bytes, they decrypt. If they don't have the bytes,
   they can't. The recipient's possession of the bytes is what matters;
   that's what the key-sharing invariant controls.

4. **It reflects how secure protocols are actually proven.** TLS 1.3,
   Signal, MLS, all prove analogous properties: "session key material
   only reaches authenticated endpoints." They do not prove "the
   decryption library refuses to run." Because the decryption library
   is the attacker's library when the attacker holds the key.

## What PR #6 still contributes

Not wasted. Most pieces carry over:

- **InviteAccepted gate** — unchanged target, proves the invite chain's
  structural integrity. Load-bearing under the new proof.

- **PeerShared gate** — proves a Valid PeerShared's user is in the
  admin/user chain. Directly load-bearing: the new proof needs
  "recipient.peer_shared.user is authority-chained."

- **KeyShared structural acceptance (frontier refs, hash, delivery target)** —
  still needed. Adds nothing to the security claim but is a
  well-formedness precondition.

- **KeyShared access-control gate** — incomplete for the new target.
  Currently proves "this peer's unwrap succeeded ⟹ key_secrets row
  emitted." The new target needs "Valid KeyShared ⟹ RECIPIENT is
  invited," which is different. The current gate checks the unwrap
  recipient (local peer); the new gate needs to check the INTENDED
  recipient (the PeerShared the wrapper targets).

- **WriteCapability (Phase 1)** — applies to any write; still good.

- **Typed SQL template (Phase 3)** — **for `key_secrets`, abandoned**
  under the key-as-dep model. The `key_secrets` table is replaced by
  a `LocalKeySecret` local event that the dep graph handles
  uniformly. Phase 3's pattern stays reusable for any ambient table
  that survives (peers_shared, removed_entities, etc.) but the
  specific `KEY_SECRETS_*` constants and variants are deleted.

- **Fake-proof deletions, no-fake-proofs lint, write-site CI gate** —
  all orthogonal to the proof target, still good.

- **Verified decision-core pattern** (primitive flags, `decide_*_core`,
  structural proofs, runtime delegation) — the machinery carries over
  directly. The new proof re-uses this pattern for a different set of
  gates.

## What the new proof needs

Delta from current state:

### 1. Extend KeyShared acceptance flags

Add recipient-side flags to `KeySharedAcceptanceFlags` (in
`verus-proofs/src/event_modules/key_shared.rs`):

- `recipient_peer_shared_valid: bool` — the event's `via_peer_shared`
  points to a Valid `peers_shared` row. Supplied by the runtime via
  the decision_context layer.
- `recipient_user_authority_ok: bool` — that row's `user_event_id` is
  in the workspace's admin/user chain (uses the existing
  `decide_peer_shared_authority_plan` verified core).

### 2. New verified theorem

```rust
pub proof fn valid_key_shared_has_invited_recipient(
    flags: KeySharedAcceptanceFlags,
)
    ensures
        key_shared_accepts_spec(flags) == KeySharedAcceptanceCore::Valid
            ==> flags.recipient_peer_shared_valid
                && flags.recipient_user_authority_ok,
{
}
```

Combined with the existing `decide_peer_shared_authority_plan` proof
(which pins `user_authority_ok` to "user is admin-chained"), this
gives: `Valid KeyShared ⟹ recipient user is admin-chained in the
workspace`.

### 3. Runtime extraction of the flags

The KeyShared projector's decision_context (currently in
`src/state/projection/decision_context.rs`) must compute the two new
primitive flags and pass them through `KeySharedAcceptanceFlags`. The
existing context-load path already reads the recipient's peer_shared —
it just needs to expose the structural facts as booleans.

### 4. Retire the Encrypted-decryption gate as a security claim

`decide_encrypted_decryption_core` and `no_key_means_block` stay in
the codebase as **operational correctness**: our runtime blocks on
missing key material rather than crashing or emitting garbage. But
they are no longer cited as security properties. The access-control
claim routes through KeyShared acceptance only.

### 5. Replace Phase 3 with the key-as-dependency model

Phase 3's approach — pin the SQL template `KEY_SECRETS_INSERT_SQL` as a
Verus constant, prove the typed `InsertKeySecret*` variants route to
the `key_secrets` table — is **abandoned under the new direction**.
Under recommendation #4 in
`REAL_PROOFS_SIMPLIFICATION_RECOMMENDATIONS.md`, there IS no
`key_secrets` ambient table to pin a write to; local key possession
becomes a first-class event dep. The new shape:

**New event type: `LocalKeySecret` (local share-scope).**

- Wire representation: `(created_at_ms, key_event_id, key_bytes)`.
- Share scope: `Local` (never transmitted to other peers).
- Signer: none (emit-only-by-local-projection).
- Projector: noop — its mere existence/validity is the fact
  downstream events depend on.
- Emitted by: the KeyShared projector's Valid+Unwrap branch (and
  analogously KeyRotation / KeyHistory when their unwrap succeeds),
  and the KeySecret projector (local peer's own key plant).

**Dep-graph change:**

- `Encrypted` events gain a dep on `LocalKeySecret` via their
  `key_event_id` field. The dep resolver handles the missing case via
  the existing cascade/unblock machinery — no special SQL lookup in
  `project_encrypted`.
- When `LocalKeySecret` becomes Valid (emitted by one of the wrap-key
  projectors or the local KeySecret projector), cascade unblocks any
  waiting `Encrypted` events exactly like any other dep.

**Proof story under the new model:**

- Old: "key_secrets row exists ⟹ unwrap succeeded" (my Phase 3).
- New: "Valid LocalKeySecret for peer P ⟹ emitted by P's KeyShared /
  KeyRotation / KeyHistory / KeySecret projector ⟹ for non-local
  variants, P's unwrap succeeded." This falls out uniformly from the
  existing projector-gate pattern — no custom SQL mapping, no special
  ambient-table gate, no special typed write variant.

**What gets deleted:**

- `KeySecretsRow` typed-row struct.
- `WriteOp::InsertKeySecretFromUnwrap` / `InsertKeySecretLocal`
  dedicated enum variants.
- `KEY_SECRETS_TABLE` constant and its `KEY_SECRETS_COLUMNS` mapping.
- `KEY_SECRETS_INSERT_SQL` Verus-pinned template.
- `key_secrets_insert_sql_template()` runtime fn and its cross-check
  test.
- `typed_variants_target_key_secrets` / `generic_variants_target_is_runtime_supplied`
  theorems for this table.
- CI gate pass 3's `VARIANT_ALLOW` entries for all the key_secrets
  variant-spellings (`WriteOp::InsertKeySecret*`, `to_write_op_from_unwrap`,
  `to_write_op_local`, etc.).
- CI gate pass 2's `key_secrets` DSL pattern.
- `key_secrets` membership in pass 1's `TABLES` set.

**What gets added:**

- `LocalKeySecret` event type with `share_scope: ShareScope::Local`
  in the registry.
- Wire codec for `LocalKeySecret`.
- Projector dispatch for `LocalKeySecret` (accepts trivially; its
  validity IS the fact).
- Dep-field declaration on `Encrypted` to depend on its
  `key_event_id` (resolving to a LocalKeySecret).
- Migration: existing `key_secrets`-row readers replaced with
  "query LocalKeySecret validity via standard dep resolution."

**What stays useful from Phase 3:**

- The verified-SQL-template pattern applied to `peers_shared` (which
  recommendation #4 does NOT eliminate — peers_shared is a projected
  identity binding, not an ambient key store).
- The general approach of pinning a runtime constant via a Verus
  `ensures` + runtime cross-check test.

**The upshot:**

Phase 3 was correct in shape (pin the SQL, prove variant-table
discipline) but pointed at a table that shouldn't exist under the
target architecture. Abandoning Phase 3 for `key_secrets` is the right
move. Retaining the Phase 3 pattern for `peers_shared` and other
remaining ambient tables is still correct.

### 6. Keep the pattern for tables that remain ambient

The tables surviving the key-as-dep refactor need the old
Phase-1/Phase-3 treatment:

- `peers_shared` — projected identity binding. Stays ambient.
- `removed_entities` — revocation state. Stays ambient.
- `invite_bootstrap_trust` / `pending_invite_bootstrap_trust` —
  transport-trust cache. Stays ambient (has TTL semantics).

For these, the decision cores + write-op typing + capability tokens
from PR #6 carry forward unchanged. The CI gate simplifies to just
these tables.

## Status of PR #6

**Do not merge.**

The commits represent real work, but they prove the wrong theorem.
Leave the branch open; use it as reference for the decision-core
pattern and the infrastructure (fake-proof lint, write-site gate,
WriteCapability token, Verus SQL-template pinning). Start a new
branch for the corrected proof.

Phase 2 as previously planned (introduce `DbReader`/`DbWriter`
newtypes) is **abandoned**. The recommendations doc's Priority 1
(dep-fact standardization) replaces it. That refactor inherently
narrows Connection access — when projector context loaders become
`(event, DepFacts, GuardFacts) -> Result` pure functions, they no
longer hold `&Connection` and the type-boundary question resolves.

## Next cycle

1. **Land recommendations-doc Priority 1** — typed `DepFacts` from a
   generic dep resolver. Pick one projector as pilot; prove the
   pattern works; fan out.

2. **Introduce the `LocalKeySecret` event type.** Share scope Local,
   no signer, trivial projector-acceptance (valid iff the event is
   well-formed). Migrate the four writers of the old `key_secrets`
   table (KeyShared, KeyRotation, KeyHistory, KeySecret projectors)
   to emit `LocalKeySecret` events instead.

3. **Migrate `Encrypted` to depend on `LocalKeySecret`.** Replace
   the direct SQL read with a standard dep declaration. The existing
   cascade/unblock machinery handles missing-key-blocked events
   without any custom logic in `project_encrypted`.

4. **Delete the `key_secrets` ambient table** once no projector writes
   to it and no reader queries it. Delete `KeySecretsRow`, the typed
   `WriteOp::InsertKeySecret*` variants, the Phase-3 SQL template
   pinning, and the CI gate rules specific to this table.

5. **Build the corrected access-control proof** on top of `DepFacts`.
   The `KeyShared` acceptance gate's new primitive flags come from
   dep-fact extraction: `recipient_peer_shared_valid`,
   `recipient_user_authority_ok`. The verified core proves
   `Valid KeyShared ⟹ recipient peer is admin-chained in the
   workspace`, composing with the existing PeerShared and
   InviteAccepted gates.

6. **Compose the top-level theorem**:
   `valid_key_shared_has_invited_recipient`
     + `cryptographic_unforgeability_of_unwrap` (trusted primitive)
     ⟹ *content-key material reaches only invited peers*.

7. **Retain the Phase-1/Phase-3 pattern for surviving ambient tables**
   — `peers_shared`, `removed_entities`, `invite_bootstrap_trust`,
   `pending_invite_bootstrap_trust`. Capability tokens + verified
   SQL templates + variant-table discipline stay useful for writes
   to these tables.

## Honest framing for the PR description

Updating PR #6's body to:

- Strike the "non-invited peer cannot decrypt" framing.
- Strike Phase 2 planning.
- Note this doc as the corrected target.
- List the pieces that carry forward (InviteAccepted, PeerShared,
  KeyShared structural, WriteCapability, CI gates, fake-proof lint).
- Mark the branch as "reference for patterns, not for the theorem."
