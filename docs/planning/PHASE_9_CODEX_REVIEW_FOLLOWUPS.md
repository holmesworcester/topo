# Phase 9 — Codex Deliverable Review: Follow-ups

## Status

Codex review run on commits `4be39735..28663fd1`. Full output at
`/tmp/codex_deliverable_out.txt`. One High-severity fix already
addressed in follow-up commit `f4be369c` (message_key
`k_bundle_local_event_id` field). Remaining findings tracked below.

## Addressed in f4be369c

- **High #2**: `message_key` wire missing `k_bundle_local_event_id`.
  ✓ Added; now blocks on the deterministic local `KeySecret(K_bundle)`
  id as the plan specified.

## Remaining follow-ups (not blocking the scaffold)

### Critical — actual producer unwrap + K_m materialization

Codex finding #1: the four producer modules
(`key_broadcast`, `key_history_bundle`, `key_bundle_share`,
`message_key`) all register `load_empty_context` as their
`context_loader`, so the new `ProjectorDecisionContext` fields
(`owning_message_tombstoned`, `decrypted_k_m_bytes`,
`unwrapped_k_bundle`) are never populated. Without that wiring, the
conditional `key_secrets` writes never fire.

**What's required:**
1. Write bespoke `build_projector_context` functions for each of the
   four producers that:
   - For `key_broadcast` / `key_history_bundle` / `key_bundle_share`:
     query `wrap_privkeys`, scan recipient slots for own pubkey,
     call `unwrap_key_from_sender` (`src/shared/crypto/mod.rs:178`)
     on match, populate `ctx.unwrapped_k_bundle`.
   - For `message_key`: query `deleted_messages` for
     `owning_message_event_id` → populate
     `ctx.owning_message_tombstoned`; query `key_secrets` for the
     deterministic K_bundle id → if present, AEAD-decrypt
     `wrapped_k_m` under K_bundle → populate
     `ctx.decrypted_k_m_bytes`.
2. Replace `load_empty_context` in each producer's `*_META` with the
   new loader.

Reference pattern: existing custom context loaders live in
`src/state/projection/decision_context.rs` with
`define_query_context_loader!` macros (~2.8k lines). New loaders
follow the same shape.

### High — `key_history_bundle` wire size target

Codex finding #3: `key_history_bundle` came in at 655_477 B
(80-byte historical slots = 32 B bundle_id + 48 B GCM ciphertext).
Plan called for ~524 KB-class.

**Fix:** reduce historical slots to 64 bytes. Options:
- Store raw K_bundle bytes (32 B) AEAD-encrypted without including
  the tag (rely on content-address verification) — risky.
- Split: one field for N × 32 B bundle_ids, one field for N × 32 B
  encrypted K_bundle bytes, one field for N × 16 B tags (still 80
  B per slot total but cache-friendlier).
- Redefine cap: 8192 × 64 B = 524_288 → adjust slot format or
  use pure encrypted bundle without explicit tag.

Preferable: recompute plan to account for 16 B tag overhead (~655 KB
is within a capped-event class; not technically wrong, just larger
than original estimate). Update plan doc if we accept 655 KB.

### Medium — Terminal-drop contract inconsistency

Codex finding #4: `message_key` self-drop uses
`ProjectorResult::valid(vec![])` (Valid + no writes), not a distinct
terminal-drop state as the plan's "Terminal-state contract for
self-drop" section requires. However, an earlier nit in the plan
says "don't introduce a new public `DroppedOwnerTombstoned`
decision state."

**Fix:** align plan language with what the code does. The code
approach (`Valid` + no writes, durable `deleted_messages` row is the
terminal marker) is consistent with the earlier nit but not with
the later "new terminal state" paragraph. Recommend keeping code
as-is and editing plan to remove the `DroppedOwnerTombstoned`
reference.

### Medium — Admin `deletion_intents` tombstone check

Codex finding #4 also notes the `message_key` projector's pre-check
comment still says it checks admin-signed `deletion_intents` in
addition to `deleted_messages`. The actual implementation only
reads `ctx.owning_message_tombstoned.unwrap_or(false)`, which is
populated by the (deferred) context_loader. The loader's correct
logic needs to query BOTH `deleted_messages` AND admin-authorized
`deletion_intents`, or just the former — the plan is ambiguous (see
Medium #4 above).

**Fix:** decide between strict `deleted_messages`-only vs
`deleted_messages + admin deletion_intents`, then update both plan
text and the eventual context_loader to match.

### Low — nonce derivation helper

Codex finding under "Cryptographic sanity" notes there's no
`deterministic_message_key_nonce` helper. The current integration
test passes because both emitters hardcode the same nonce.

**Fix:** add
`deterministic_message_key_nonce(bundle_id, owning_message_event_id,
k_m)` that returns a 12-byte nonce via `blake3(...)[..12]`. Wire the
sender side of `message_key` emission to use this helper so
multi-device authors producing the same (K_bundle, K_m,
owning_message) produce byte-identical events end-to-end.

### Non-blocking — test suite run

Codex couldn't run `cargo test` under its read-only sandbox. The
branch should retain the prior ~10 pre-existing failures baseline
observed on master. Verified locally by this session (no new
regressions beyond the pre-existing set).

## Summary

Scaffolding is structurally complete and matches the plan's event
model (all 6 new types, wire shapes, registry wiring, cascade
normalization, purge extension). Cornerstone invariants (three-
producer uniformity, content-address dedupe, wire sizes) are tested.

The remaining work is the **context-loader layer** that actually
runs `asymmetric_unwrap` and the tombstone query — concentrated in
`src/state/projection/decision_context.rs` — and **integration into
`key_repair.rs`** for heal emission. Neither is a redesign; both
are conventional per-module context-loader writing.
