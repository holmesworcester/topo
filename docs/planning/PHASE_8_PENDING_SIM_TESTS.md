# Phase 8 — Additional Sim Tests (pending)

## Status

**Scaffolded.** Producer-uniformity + wire-size tests are in place at
`tests/per_message_fs_producer_uniformity.rs`. The full end-to-end sim
matrix is documented here and pending.

## Delivered this pass

- 3 integration tests:
  1. `three_producers_produce_identical_keysecret_event_ids` —
     validates the cornerstone invariant that key_broadcast,
     key_history_bundle, and key_bundle_share all emit the same
     deterministic local KeySecret(K_bundle) for identical K_bundle
     bytes. Cascade unblocks uniformly.
  2. `message_key_event_id_determinism_across_emitters` — two devices
     emitting a message_key for the same (K_bundle, K_m, owning_message)
     produce byte-identical blobs. Content-addressed dedupe.
  3. `wire_sizes_follow_plan_targets` — all 6 new event types match
     the wire-size budget from the approved plan.

- 13 unit tests across wrap_pubkey, key_broadcast, key_history_bundle,
  message_key, key_bundle_request, key_bundle_share (wire roundtrip +
  deterministic helpers).

## Remaining Phase 8 sim tests (follow-up)

Each requires a multi-peer sim harness based on
`tests/sim_scaffold_test.rs` and `tests/sim_pair_sync_test.rs`.

1. **Compromise test** — peer A sends M, peer A deletes M. Wait past
   grace. Dump all on-disk state for peer B. Assert no `key_secrets`
   row for M's K_m, no message blob for M. Verified FS.

2. **TTL expiry test** — send M with 24h TTL. Simulate 24h + grace.
   Assert same purged state as explicit delete. Requires TTL-driven
   self-tombstone hook (also pending; noted as follow-up in
   message_deletion).

3. **Bootstrap test** — new joiner receives
   `key_history_bundle` targeting their fresh `WrapPubkey`.
   Successfully decrypts historical messages. Verifies the anchor
   unwrap → AEAD-decrypt-historical-slots → emit deterministic
   KeySecret path.

4. **Heal test** — peer P isn't in initial `key_broadcast` recipient
   slots. P emits `key_bundle_request`. Another peer (with K_bundle
   and authority) emits `key_bundle_share` targeted at P. P unwraps,
   materializes KeySecret(K_bundle), cascade unblocks pending
   `message_key`s.

5. **Late-replay ordering test** — emit MessageDeletion, message_key,
   message in all 6 orderings. Expected: every ordering produces
   identical empty end state. No K_m row ever persists, no zero-dep
   blocked row remains.

6. **Concurrent-send/rotate race** — peer D1 sends M1 under K_bundle_N.
   Peer D2 emits rotation to K_bundle_N+1. D1's send arrives after
   D2's rotation. M1's K_m still unwraps because K_bundle_N is
   still alive (no premature purge).

7. **WrapPubkey rotation** — peer P rotates WrapPubkey. Old privkey
   purged at `valid_until_ms + grace`. New wraps targeting P go to
   the new pubkey (derived by `(created_at_ms, event_id)` tie-break).

8. **Per-device bundle lineage** — two devices D1, D2 each emit
   independent key_broadcast streams. Messages from D1 use D1's
   current bundle; messages from D2 use D2's. Recipients track both
   lineages.

9. **Entitlement gate preservation** — removed peer emits
   `key_bundle_request`. Current members' heal loop MUST NOT respond
   with `key_bundle_share`. Verifies the authority gate in
   `key_repair.rs:798-815, 842-884` carries over.

10. **CLI end-to-end** — use `send`, `delete`, `messages`,
    `assert-eventually` to verify delete → local state empty past
    grace.

## Why these are follow-up

These tests need:
- Multi-peer sim scaffolding beyond the current projector-level unit
  tests.
- The `context_loader` that runs `asymmetric_unwrap` against
  `wrap_privkeys` and populates `ctx.unwrapped_k_bundle` (wire scaffold
  is in place; loader is the glue).
- `key_repair.rs` heal-loop wiring to EMIT `key_bundle_request` and
  to RESPOND with `key_bundle_share` while preserving the entitlement
  gate. Legacy KeyRequest/KeyShared paths remain alongside during the
  migration.
- TTL-driven self-tombstone emission hook (test #2 specifically).

None of these block the current Per-Message FS shape from landing;
they exercise the integration boundaries that wire the event layer
to the runtime.
