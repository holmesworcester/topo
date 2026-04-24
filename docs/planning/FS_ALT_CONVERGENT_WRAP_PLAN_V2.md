# FS Alt Design — Revised Plan (v2)

Revised after codex review of `FS_ALT_CONVERGENT_WRAP_DESIGN.md` and
subsequent design iteration. This doc is a **decisions summary**, not
a full spec. The v1 design doc and codex review remain for context;
this supersedes their conclusions where they conflict.

Status: proposal; supersedes v1's specific constructions. Branch
`design-fs-alt-convergent-wrap`.

---

## Core design (decisions)

1. **Reuse the existing `key_shared` event as THE distribution event.**
   Drop `key_rotation` and `key_history_bundle`. `key_shared` is
   already a 1×1 (one recipient × one target key) shape. No new event
   type for the wrap.

2. **Add `eph_pubkey_request`.** Member-signed, one-shot, short
   `valid_until_ms`, optional `supersedes_eph_pubkey_event_id`.
   Carries `target_key_id` (either `bundle_id` or a future key id
   shape) + ephemeral pubkey. Privkey stored in local
   `eph_privkeys`, shredded on first successful unwrap.

3. **Deterministic `key_shared` construction for convergence.**
   Ephemeral sender keypair derived from
   `blake3("fs-wrap-v1" ‖ target_key_id ‖ recipient_pubkey)` →
   sealed-box ciphertext is byte-identical across independent
   holders. Multiple holders react to the same request/invite →
   emit the same event → dedupe on the wire.
   Resolves codex gap #1.

4. **Preserve `k_bundle_local_event_id` as the canonical dep key.**
   `key_shared` projector, on successful unwrap, emits the
   deterministic `KeySecret(K_bundle)` local event — same pattern
   `key_broadcast` and `key_rotation` use today. `message_key`
   continues to dep on `k_bundle_local_event_id`. No hand-waving
   "message → wrap_event → key_secrets" chain.
   Resolves codex gap #2.

5. **Preemptive emit triggers.** Two deterministic holder-side
   triggers replace the `key_history_bundle` + invite-slot fanout:
   - **Trigger A** (learn of new invite): emit `key_shared` for
     every `bundle_id` in local `key_secrets` the invite is
     entitled to.
   - **Trigger B** (learn of new bundle): emit `key_shared` for
     every still-active invite pubkey entitled on that bundle's
     frontier.
   Works with the existing `retired_bundles` gate — retired bundles
   are absent from `key_secrets`, so trigger A naturally skips them.

6. **Self-contained `MessageDeletion` carries all ids.**
   New fields: `message_event_id`, `message_key_event_id`,
   `bundle_id`. Cascade becomes straight-line DELETEs + retired-set
   inserts. Drops the `messages_to_message_keys` reverse index.
   Late-replay works: deletion arriving before any of
   message/message_key/rotation inserts its ids into
   `retired_bundles` + `retired_keys` immediately; subsequent
   arrivals fail to rehydrate.
   Resolves codex gap about `messages_to_message_keys` and
   cascade lookup complexity.

7. **Add `retired_keys` table and gate.** New per-`message_key_event_id`
   gate alongside existing `retired_bundles`. Spec:
   ```
   CREATE TABLE retired_keys (
       recorded_by TEXT NOT NULL,
       message_key_event_id TEXT NOT NULL,
       retired_at_ms INTEGER NOT NULL,
       PRIMARY KEY (recorded_by, message_key_event_id)
   );
   ```
   `execute_write_ops` refuses `key_secrets` insert whose `event_id`
   matches a retired key, AND refuses `message_keys` row insert with
   that event_id. Populated by the self-contained `MessageDeletion`
   projector from (6).
   Resolves codex gap #3.

8. **Entitlement predicate is a SQL query, not a lineage walk.**
   Materialize a `frontier_removed_peers(recorded_by, frontier_ref,
   peer_ref)` table at projection time. Predicate:
   ```sql
   SELECT 1 FROM frontier_removed_peers
    WHERE recorded_by = ?1 AND frontier_ref = ?2 AND peer_ref = ?3
    LIMIT 1;
   ```
   0 rows = entitled. Index on `(recorded_by, frontier_ref,
   peer_ref)` → O(log n). "Definitive negative" holds because
   projection is complete before the query runs.
   Consulted by: `key_shared` responder side, Trigger A/B
   recipient filter.
   Resolves codex gap #5.

9. **`frontier_advance` merges `removal` + `key_rotation`.**
   Admin-signed. Carries frontier delta + new `bundle_id`. Atomic
   by construction.
   Multi-parent frontier support preserved via the flat
   `frontier_removed_peers` set (from 8): two concurrent advances
   each contribute rows independently; queries read the union. No
   linearization required.
   Resolves codex gap #6.

10. **KDF `K_m` with random salt per message (optional but
    preferred).** `K_m = HKDF(K_bundle, salt=random_12B,
    info="fs-per-message-v1")`. Drops the `message_key` event
    entirely. Message header gains `kdf_salt_12B`.
    - Collision bound: 2^48 messages per bundle. Irrelevant.
    - Back-derivation: infeasible (HKDF is a PRF via HMAC-SHA256).
    - Cache-on-first-derive: store K_m in `key_secrets` keyed by
      message_event_id (or the deletion-carried
      `message_key_event_id` surrogate when present). Preserves
      per-message purge granularity.
    - Drops `message_keys`, `messages_to_message_keys`, and the
      `message_key` event's projector + dep-chain entirely.
   Supersedes codex's point that the branch's plan "rejected HKDF":
   that rejection was for a different shape. This shape pairs KDF
   with the self-contained `MessageDeletion` from (6) so
   per-message granularity isn't lost.

---

## FS guarantees (unchanged from v1)

- Delete-triggered K_bundle retirement: `retired_bundles` gate
  refuses rehydration post-delete.
- Per-K_m purge: `retired_keys` gate at per-message granularity.
- Weak-FS edge for retain-then-compromise attacker: accepted, same
  as today.
- Strong-FS for no-retention attacker: holds at bundle granularity;
  at message granularity when the delete cascade shreds the cached
  K_m row before compromise.

---

## What codex flagged that v2 addresses

| Codex gap | v2 resolution |
|---|---|
| `wrap_event` convergence broken (nonce + ciphertext emitter-dependent) | Decision 3: deterministic ephemeral sender keypair → byte-identical sealed box |
| No canonical dep key | Decision 4: preserve `k_bundle_local_event_id` via existing deterministic KeySecret emit |
| `retired_keys` is fiction | Decision 7: specified (schema + gate point + populator) |
| Trigger A dead-end for retired bundles | Expected behavior per v1 (retired bundles absent from `key_secrets` intentionally); matches existing `joiner_after_bundle_retirement_sees_undeleted_tail_as_history_lost` test |
| Entitlement predicate too weak | Decision 8: SQL-table query against materialized removal set |
| `frontier_advance` linearization breaks multi-parent | Decision 9: flat set in `frontier_removed_peers`, union queries |
| Factual errors about current branch (§1.1/§7.1/§7.4) | Acknowledged; rewrite v1 doc when this plan is executed |
| "Already litigated" HKDF rejection | Decision 10: paired with self-contained deletion, different shape from the rejected variant |

---

## Deferred / out of scope

- DoS rate-limiting spec for `eph_pubkey_request`. Soft rate-limit
  via `valid_until_ms`; ban-on-abuse via signed audit trail.
- Multi-device request coalescing.
- Migration plan from current per-message-fs branch. This doc is a
  design, not an execution plan.
- TLA+ updates. Scope of the adoption execution plan.

---

## Open questions

- Is decision 10 (KDF K_m) required for the design to be a win, or
  can we ship (1)–(9) without it and treat KDF as a later
  orthogonal simplification? v1 estimated KDF as a ~1-week lift,
  but interaction with decision 6 changes that — per-message
  granularity is carried by the deletion event now, not the
  `message_key` event, so KDF is more tractable.
- Exactly which event carries `frontier_advance`'s multi-parent
  reference field(s)? Needs alignment with the existing removal
  frontier reference mechanism.
- Should `frontier_removed_peers` also carry `added_at_frontier_ref`
  to express membership windows, or is removal alone sufficient?

---

## Relation to v1 and the codex review

- `FS_ALT_CONVERGENT_WRAP_DESIGN.md` (v1) — original proposal.
  Retained for context. Its §2 event shapes and §3 distribution
  mechanics remain mostly valid; §4 retired_keys was
  underspecified (fixed in decision 7); §5 KDF variant now
  pairs with decision 6 (fixed).
- `FS_ALT_CONVERGENT_WRAP_DESIGN_CODEX_REVIEW.md` — codex's
  review of v1. Decisions above directly map to its flagged gaps.
  The "don't adopt as written" verdict applies to v1; v2
  addresses every concrete gap it raised.

---

## Adoption sequencing (preliminary)

This would be a follow-on execution plan after `per-message-fs`
lands on master. Rough sequencing:

1. Add `eph_pubkey_request` event + `eph_privkeys` table (decision 2).
2. Make `key_shared` projector deterministic + emit canonical
   `KeySecret(K_bundle)` on unwrap (decisions 3, 4).
3. Add preemptive Trigger A/B emission paths (decision 5).
4. Self-contained `MessageDeletion` with ids (decision 6) +
   `retired_keys` table/gate (decision 7).
5. `frontier_removed_peers` table + entitlement predicate
   (decision 8).
6. `frontier_advance` event merging removal + rotation (decision 9).
7. Retire `key_rotation`, `key_history_bundle`, `removal` events
   (rely on decisions 1, 9).
8. (Optional) KDF K_m + drop `message_key` event (decision 10).

Each step is independently testable against existing invariants.
