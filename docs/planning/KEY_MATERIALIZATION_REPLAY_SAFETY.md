# Key Materialization Replay Safety

## Problem Statement

The dep-driven key materialization flow has a replay-safety gap: the DH unwrap
in `secret_shared`'s context_loader depends on projection state
(`local_signer_material`) that may not yet exist when the event projects.

### Current flow

1. Join/link command creates a `LocalSignerSecret` event (signer_kind=4 for
   invite keys, signer_kind=3 for PeerShared keys) storing the private key.
2. `LocalSignerSecret` projects → populates `local_signer_material` table.
3. `SecretShared` events arrive via sync with `recipient_event_id` pointing to
   the invite or PeerShared event.
4. `SecretShared`'s context_loader reads `local_signer_material` for a private
   key matching `recipient_event_id`.
5. If found → DH unwrap → projector emits `MaterializeSecretKey` → handler
   creates deterministic `secret_key` event → cascade unblocks encrypted content.

### The gap

`LocalSignerSecret` is **not** a declared dependency of `SecretShared`. The dep
engine only knows about `recipient_event_id` (the invite/PeerShared event
itself) and `signed_by`. It has no knowledge of `local_signer_material`.

On replay (re-project all events from a clean projection state), if
`SecretShared` projects before `LocalSignerSecret`:

1. Context_loader reads `local_signer_material` → **empty**
2. No unwrap, no `MaterializeSecretKey`, event goes Valid without key
   materialization
3. `LocalSignerSecret` projects later → populates `local_signer_material`
4. **Nothing re-triggers `SecretShared`** → key never materializes → encrypted
   content stays blocked forever

This applies to both:
- **Invite keys** (signer_kind=4): workspace content key unwrap on join
- **PeerShared keys** (signer_kind=3): per-attachment key unwrap at runtime

### Why the old approach masked this

The removed `retry_pending_invite_content_key_unwraps` post-drain hook
imperatively scanned all pending invite keys and all `secret_shared` events on
every projection drain, retrying unwrap regardless of projection order. This was
the band-aid.

## Design Options

### Option A: Derived dependency events

Model "private key available for recipient X" as a first-class event in the dep
graph.

1. Add a `RecipientKeyReady` local event type emitted when `LocalSignerSecret`
   projection materializes a non-zero private key.
2. `SecretShared` projection emits a derived `UnwrapSecretShared` local event
   that depends on both `SecretShared` itself and `RecipientKeyReady` for the
   same `recipient_event_id`.
3. `UnwrapSecretShared`'s projector does the DH unwrap and emits
   `MaterializeSecretKey`.

**Pros:**
- Fully order-independent — the dep engine handles sequencing
- No imperative scanning or special-case re-projection
- Clean fit with the existing architecture

**Cons:**
- Two new local event types
- `SecretShared` events targeting non-local recipients (the common case — most
  peers aren't us) would either not emit `UnwrapSecretShared` at all (decided at
  projection time based on context) or emit it and let it block indefinitely
  (blocking is not an error — it's the normal state for events whose deps
  haven't arrived)

**Open question:** Should `SecretShared` always emit `UnwrapSecretShared`
(letting non-local ones block harmlessly) or only emit it when the recipient is
provably local? The former is simpler and more deterministic; the latter avoids
accumulating permanently-blocked events.

### Option B: LocalSignerSecret emits re-project commands

When `LocalSignerSecret` projects with a non-zero private key, its projector
emits an `EmitCommand` to re-project all `SecretShared` events targeting that
`signer_event_id` as `recipient_event_id`.

**Pros:**
- No new event types
- Targeted — only re-evaluates relevant events

**Cons:**
- Requires `LocalSignerSecret` projector to know about `SecretShared` (coupling)
- Re-projection of already-Valid events needs careful handling (must re-run
  context_loader and MaterializeSecretKey emission)
- Feels like a scan in disguise — looking up secret_shared rows by recipient

### Option C: Post-projection hook (restore the old approach, cleaner)

Restore a targeted post-drain hook that only runs when `LocalSignerSecret`
events were projected in the current drain cycle, scanning `secret_shared` for
that specific recipient.

**Pros:**
- Minimal code change
- Known to work

**Cons:**
- Imperative scanning — the approach we explicitly moved away from
- Not dep-driven — violates the architectural principle

## Recommendation

**Option A** (derived dependency events) is the cleanest fit. It makes the
implicit dependency explicit in the event graph, works regardless of projection
order, and requires no special-case scanning or re-projection logic.

The blocking-forever concern for non-local recipients is a non-issue: blocked
events are a normal, expected state in the system (any event whose deps haven't
synced yet is blocked). The dep engine handles this gracefully.

## Context

- Branch: `feat/encryption-rigor-plan`
- Related code:
  - `src/event_modules/secret_shared.rs` — context_loader + projector
  - `src/state/projection/apply/write_exec.rs` — MaterializeSecretKey handler
  - `src/event_modules/workspace/identity_ops.rs` — key storage helpers
  - `src/state/projection/contract.rs` — EmitCommand, ContextSnapshot
- Related docs:
  - `docs/DESIGN.md` §9.4 — encryption semantics
  - `docs/ENCRYPTION_EVIDENCE.md` — key distribution evidence
