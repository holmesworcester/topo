# Codex review of FS_ALT_CONVERGENT_WRAP_DESIGN.md

Source: `codex exec --sandbox read-only` run against
`per-message-fs` branch at commit `7e668b01` on 2026-04-23.
Full transcript preserved at `/tmp/codex_fs_alt_review.log`.

Codex model: `gpt-5.4`, reasoning effort `xhigh`, source review
only (no suite execution).

---

**A**

The proposal does not preserve full parity with the branch as it exists today.

- Delete-triggered bundle retirement is load-bearing in the current code because purge walks `message -> message_key -> both bundle aliases`, shreds both bundle rows, and records `retired_bundles`; the executor then blocks only future `key_secrets` inserts for those bundle ids while still allowing surviving per-message K_m rows to exist and rehydrate (`src/state/projection/purge.rs:163-238`, `src/state/projection/purge.rs:538-584`, `src/state/projection/apply/write_exec.rs:122-153`, `src/state/projection/apply/tests/new_joiner_history.rs:496-650`). The proposal says this is “unchanged”, but it does not re-specify the exact gate semantics, alias handling, or insertion point for its new `retired_keys` concept. Current code has `retired_bundles` only (`src/event_modules/key_secret.rs:105-127`).

- Late-arrival inertness is only partially reestablished. Current branch has three separate protections: late `message_key` with no live bundle yields no K_m (`src/state/projection/decision_context.rs:2528-2541`, `src/event_modules/message_key.rs:245-272`, `src/state/projection/apply/tests/per_message_fs.rs:539-595`); stale bundle reinsert via history/heal is refused by the retired-bundle gate (`src/state/projection/apply/write_exec.rs:122-153`, `src/state/projection/apply/tests/per_message_fs.rs:733-797`, `src/state/projection/apply/tests/new_joiner_history.rs:618-650`); and purge retires both the deterministic bundle id and the rotation alias (`src/state/projection/purge.rs:200-238`, `src/state/projection/purge.rs:559-583`). The proposal only clearly covers the second, and only if `wrap_event -> key_secrets` is wired through the same narrow gate. Its KDF path has no equivalent of the current late-`message_key` inertness proof.

- The weak-FS edge is the same. Current branch explicitly accepts the pre-propagation compromise window and rejects only post-delete compromise with retained wire (`docs/DESIGN.md:1908-1918`). The proposal keeps the same “retained ciphertext + retained K_bundle” weak edge (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:371-375`).

- The KDF cache-on-first-derive story in §4.2 is not sound as written. Current branch eagerly materializes a per-message K_m row keyed by the `message_key` event id at projection time (`src/event_modules/message_key.rs:245-272`), and purge removes that exact row while preserving other messages’ K_m rows (`src/state/projection/purge.rs:163-238`, `src/state/projection/purge.rs:496-584`, `src/state/projection/apply/tests/per_message_fs.rs:313-456`). The proposal switches to `k_m_id = blake3(K_m)` plus `retired_keys` (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:279-287`) but never defines the executor/query surface for that gate, contradicts itself on whether caching happens on receive or only for read messages (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:279-282` vs `FS_ALT_CONVERGENT_WRAP_DESIGN.md:463-467`), and drops the current message-identity key that makes selective purge precise.

- Test scenarios currently covered:
  - `cli_send_emits_message_key_and_delete_purges_it`, `fs_preserved_for_deleted_message`, and `fs_preserved_for_ttl_expired_message` do not survive the proposal’s KDF variant as-is because `message_key`, `message_keys`, and `messages_to_message_keys` are removed (`tests/cli_per_message_fs_test.rs:73-134`, `src/state/projection/apply/tests/per_message_fs.rs:192-311`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:173-178`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:351-358`).
  - `history_preserved_after_deletion`, `sequential_deletes_preserve_non_target_history`, and `joiner_keeps_undeleted_keys_when_delete_happens_after_invite_received` only remain true if the proposal keeps eager per-message caches for all relevant messages; they fail in the no-cache variant and are not proven in the “read-msgs only” cache variant (`src/state/projection/apply/tests/per_message_fs.rs:313-456`, `src/state/projection/apply/tests/new_joiner_history.rs:496-650`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:463-467`).
  - `retained_wire_plus_post_purge_compromise_recovers_nothing` is plausibly preserved at the bundle level if the bundle gate is made equivalent (`src/state/projection/apply/tests/per_message_fs.rs:465-537`).
  - `joiner_after_bundle_retirement_sees_undeleted_tail_as_history_lost` is probably still the effective behavior, because the proposal’s Trigger A iterates bundle ids still present in `key_secrets`, while retired bundles are intentionally removed from `key_secrets` (`src/state/projection/apply/tests/per_message_fs.rs:597-658`, `src/state/projection/purge.rs:538-584`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:212-217`).
  - `cli_joiner_sees_messages_encrypted_under_post_invite_bundle` is the one scenario the proposal likely does preserve, because both designs target the same user-visible outcome and current code already achieves it via active-invite recipients plus invite-secret unwrap fallback (`tests/cli_post_invite_bundle_delivery_test.rs:10-21`, `tests/cli_post_invite_bundle_delivery_test.rs:104-117`, `src/event_modules/workspace/identity_ops.rs:469-536`, `src/state/projection/decision_context.rs:2416-2449`).
  - `per_device_bundle_isolation_delete_in_b1_does_not_purge_b2` is not expressible if the proposal literally means one bundle per frontier; current test expects separate bundles to survive independent deletes (`src/state/projection/apply/tests/per_message_fs.rs:660-731`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:89-103`).

**B**

The proposal has several concrete gaps.

- Its convergence claim for `wrap_event` does not follow from its own fields. It says byte-identical wraps dedupe across holders, but its nonce includes `sender_identity`, and its ciphertext is emitter-dependent (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:152-159`). Current branch gets convergence from deterministic local `KeySecret(K_bundle)` ids instead (`src/state/projection/create.rs:531-540`, `src/event_modules/key_rotation.rs:279-294`, `src/event_modules/key_broadcast.rs:202-218`).

- It never reestablishes a single canonical dependency key equivalent to current `k_bundle_local_event_id`. Current dep blocking is `message -> message_key -> canonical KeySecret(K_bundle)` (`src/event_modules/message_key.rs:52-57`, `src/event_modules/message_key.rs:287-302`). The proposal’s “`message -> wrap_event -> key_secrets`” chain is hand-wavy because `wrap_event` is recipient-specific and many-to-one (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:490-491`).

- Its entitlement predicate is too weak. Current authorization walks the frontier and removal lineage, not just “is present in tables and not tombstoned” (`src/event_modules/workspace/identity_ops.rs:419-467`, `src/runtime/key_repair.rs:799-887`). The proposal’s predicate at `FS_ALT_CONVERGENT_WRAP_DESIGN.md:420-424` does not reconstruct that.

- `retired_keys` is treated as already-existing infrastructure, but the branch has no such table or gate; only `retired_bundles` exists (`src/event_modules/key_secret.rs:105-127`).

- Trigger A cannot recover retired-bundle history as written. It iterates bundle ids still in holder `key_secrets` (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:214-217`), but retired bundles are deleted from `key_secrets` by the current FS lever (`src/state/projection/purge.rs:538-584`).

- `frontier_advance` replaces a multi-parent frontier model with a linear predecessor chain, but the proposal never re-specifies how current concurrent frontier behavior maps. The current branch explicitly tests multi-parent frontier convergence and blocking for both `removal` and `key_rotation` (`src/state/projection/apply/tests/removal_rotation.rs:309-483`).

**C**

If adopted exactly as written, many current tests would need rewriting, and some invariants disappear.

- Retain largely as-is: `tests/cli_post_invite_bundle_delivery_test.rs:1-121`. It is already outcome-based and mechanism-agnostic.

- Retain in spirit but rewrite internals/assertions: the CLI delete/history tests in `tests/cli_per_message_fs_test.rs:73-299` and the state-level retention test in `src/state/projection/apply/tests/per_message_fs.rs:465-537`. They can still assert “deleted message gone, survivors remain,” but not `message_key`/`message_keys`/reverse-index details under KDF.

- Rewrite completely: every `message_key`-centric or `key_history_bundle`-slot test, including `src/state/projection/apply/tests/per_message_fs.rs:192-456` and `src/state/projection/apply/tests/new_joiner_history.rs:157-650`.

- Rewrite completely: the frontier/removal/rotation tests in `src/state/projection/apply/tests/removal_rotation.rs:107-533`, because `frontier_advance` changes the frontier model itself.

- Not expressible if proposal is literal: per-device bundle isolation (`src/state/projection/apply/tests/per_message_fs.rs:660-731`) and the current narrow “bundle retired, undeleted per-message K_m rows still survive” invariant (`src/state/projection/apply/tests/new_joiner_history.rs:496-650`).

**D**

The proposal’s description of the current branch is cleaner than the code actually is.

- `§1.1` / `§7.1` say the current branch has three K_bundle delivery events: `key_rotation`, `key_history_bundle`, and `key_shared` (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:26-32`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:455-459`). The branch is messier. The per-message-FS dep chain and purge logic explicitly treat `key_broadcast`, `key_history_bundle`, and `key_bundle_share` as the producer family for canonical `KeySecret(K_bundle)` materialization (`src/event_modules/message_key.rs:52-57`, `src/event_modules/message_key.rs:287-302`, `src/event_modules/key_bundle_share.rs:1-9`), while legacy/bootstrap/repair paths still use `key_shared` (`src/event_modules/key_shared.rs:1-29`, `src/runtime/key_repair.rs:710-758`).

- `§7.4` says post-invite delivery is a special case in `load_key_rotation_context` (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:490-493`). That is incomplete. Current branch also changed sender-side recipient selection in `active_rotation_recipients_for_frontier` (`src/event_modules/workspace/identity_ops.rs:469-536`); the loader fallback is only the recipient-side half (`src/state/projection/decision_context.rs:2416-2449`).

- The proposal repeatedly speaks as if `retired_bundles / retired_keys` are both “preserved” (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:18`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:285-287`). Current code only has `retired_bundles` (`src/event_modules/key_secret.rs:105-127`).

- The branch still has `remove_member` as two sequential event creations, not a structural atomic pair: it emits `removal` first and only then rotates (`src/event_modules/workspace/commands.rs:971-1015`). So the proposal is right that the current pairing is non-atomic, but its scope estimate for replacing it is optimistic given the amount of frontier-, auth-, repair-, and test-surface tied to the current split (`src/runtime/key_repair.rs:799-887`, `src/state/projection/apply/tests/removal_rotation.rs:107-533`).

**E**

Don’t adopt this design as written.

The only part that looks worth revisiting later is the narrower “make removal+rotation structurally atomic” idea, because the current command really does emit them sequentially (`src/event_modules/workspace/commands.rs:971-1015`). The convergent-wrap and KDF parts do not reestablish the exact gate/cascade contracts the current FS implementation depends on (`src/state/projection/purge.rs:163-238`, `src/state/projection/purge.rs:538-584`, `src/state/projection/apply/write_exec.rs:122-153`), and the branch’s active plan has already explicitly rejected the HKDF/no-`message_key` path for now (`docs/PLAN.md:2030-2034`).

If this gets revisited after `per-message-fs` lands, the proposal needs four concrete fixes before it is credible: a real canonical dep key replacing current `k_bundle_local_event_id`, a cryptographically coherent convergence story for `wrap_event`, an exact `retired_*` executor/query spec, and explicit tests for delete-after-invite, retired-bundle late joiners, and per-device isolation. Source review only; I did not run the suite.
tokens used
214,720
**A**

The proposal does not preserve full parity with the branch as it exists today.

- Delete-triggered bundle retirement is load-bearing in the current code because purge walks `message -> message_key -> both bundle aliases`, shreds both bundle rows, and records `retired_bundles`; the executor then blocks only future `key_secrets` inserts for those bundle ids while still allowing surviving per-message K_m rows to exist and rehydrate (`src/state/projection/purge.rs:163-238`, `src/state/projection/purge.rs:538-584`, `src/state/projection/apply/write_exec.rs:122-153`, `src/state/projection/apply/tests/new_joiner_history.rs:496-650`). The proposal says this is “unchanged”, but it does not re-specify the exact gate semantics, alias handling, or insertion point for its new `retired_keys` concept. Current code has `retired_bundles` only (`src/event_modules/key_secret.rs:105-127`).

- Late-arrival inertness is only partially reestablished. Current branch has three separate protections: late `message_key` with no live bundle yields no K_m (`src/state/projection/decision_context.rs:2528-2541`, `src/event_modules/message_key.rs:245-272`, `src/state/projection/apply/tests/per_message_fs.rs:539-595`); stale bundle reinsert via history/heal is refused by the retired-bundle gate (`src/state/projection/apply/write_exec.rs:122-153`, `src/state/projection/apply/tests/per_message_fs.rs:733-797`, `src/state/projection/apply/tests/new_joiner_history.rs:618-650`); and purge retires both the deterministic bundle id and the rotation alias (`src/state/projection/purge.rs:200-238`, `src/state/projection/purge.rs:559-583`). The proposal only clearly covers the second, and only if `wrap_event -> key_secrets` is wired through the same narrow gate. Its KDF path has no equivalent of the current late-`message_key` inertness proof.

- The weak-FS edge is the same. Current branch explicitly accepts the pre-propagation compromise window and rejects only post-delete compromise with retained wire (`docs/DESIGN.md:1908-1918`). The proposal keeps the same “retained ciphertext + retained K_bundle” weak edge (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:371-375`).

- The KDF cache-on-first-derive story in §4.2 is not sound as written. Current branch eagerly materializes a per-message K_m row keyed by the `message_key` event id at projection time (`src/event_modules/message_key.rs:245-272`), and purge removes that exact row while preserving other messages’ K_m rows (`src/state/projection/purge.rs:163-238`, `src/state/projection/purge.rs:496-584`, `src/state/projection/apply/tests/per_message_fs.rs:313-456`). The proposal switches to `k_m_id = blake3(K_m)` plus `retired_keys` (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:279-287`) but never defines the executor/query surface for that gate, contradicts itself on whether caching happens on receive or only for read messages (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:279-282` vs `FS_ALT_CONVERGENT_WRAP_DESIGN.md:463-467`), and drops the current message-identity key that makes selective purge precise.

- Test scenarios currently covered:
  - `cli_send_emits_message_key_and_delete_purges_it`, `fs_preserved_for_deleted_message`, and `fs_preserved_for_ttl_expired_message` do not survive the proposal’s KDF variant as-is because `message_key`, `message_keys`, and `messages_to_message_keys` are removed (`tests/cli_per_message_fs_test.rs:73-134`, `src/state/projection/apply/tests/per_message_fs.rs:192-311`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:173-178`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:351-358`).
  - `history_preserved_after_deletion`, `sequential_deletes_preserve_non_target_history`, and `joiner_keeps_undeleted_keys_when_delete_happens_after_invite_received` only remain true if the proposal keeps eager per-message caches for all relevant messages; they fail in the no-cache variant and are not proven in the “read-msgs only” cache variant (`src/state/projection/apply/tests/per_message_fs.rs:313-456`, `src/state/projection/apply/tests/new_joiner_history.rs:496-650`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:463-467`).
  - `retained_wire_plus_post_purge_compromise_recovers_nothing` is plausibly preserved at the bundle level if the bundle gate is made equivalent (`src/state/projection/apply/tests/per_message_fs.rs:465-537`).
  - `joiner_after_bundle_retirement_sees_undeleted_tail_as_history_lost` is probably still the effective behavior, because the proposal’s Trigger A iterates bundle ids still present in `key_secrets`, while retired bundles are intentionally removed from `key_secrets` (`src/state/projection/apply/tests/per_message_fs.rs:597-658`, `src/state/projection/purge.rs:538-584`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:212-217`).
  - `cli_joiner_sees_messages_encrypted_under_post_invite_bundle` is the one scenario the proposal likely does preserve, because both designs target the same user-visible outcome and current code already achieves it via active-invite recipients plus invite-secret unwrap fallback (`tests/cli_post_invite_bundle_delivery_test.rs:10-21`, `tests/cli_post_invite_bundle_delivery_test.rs:104-117`, `src/event_modules/workspace/identity_ops.rs:469-536`, `src/state/projection/decision_context.rs:2416-2449`).
  - `per_device_bundle_isolation_delete_in_b1_does_not_purge_b2` is not expressible if the proposal literally means one bundle per frontier; current test expects separate bundles to survive independent deletes (`src/state/projection/apply/tests/per_message_fs.rs:660-731`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:89-103`).

**B**

The proposal has several concrete gaps.

- Its convergence claim for `wrap_event` does not follow from its own fields. It says byte-identical wraps dedupe across holders, but its nonce includes `sender_identity`, and its ciphertext is emitter-dependent (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:152-159`). Current branch gets convergence from deterministic local `KeySecret(K_bundle)` ids instead (`src/state/projection/create.rs:531-540`, `src/event_modules/key_rotation.rs:279-294`, `src/event_modules/key_broadcast.rs:202-218`).

- It never reestablishes a single canonical dependency key equivalent to current `k_bundle_local_event_id`. Current dep blocking is `message -> message_key -> canonical KeySecret(K_bundle)` (`src/event_modules/message_key.rs:52-57`, `src/event_modules/message_key.rs:287-302`). The proposal’s “`message -> wrap_event -> key_secrets`” chain is hand-wavy because `wrap_event` is recipient-specific and many-to-one (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:490-491`).

- Its entitlement predicate is too weak. Current authorization walks the frontier and removal lineage, not just “is present in tables and not tombstoned” (`src/event_modules/workspace/identity_ops.rs:419-467`, `src/runtime/key_repair.rs:799-887`). The proposal’s predicate at `FS_ALT_CONVERGENT_WRAP_DESIGN.md:420-424` does not reconstruct that.

- `retired_keys` is treated as already-existing infrastructure, but the branch has no such table or gate; only `retired_bundles` exists (`src/event_modules/key_secret.rs:105-127`).

- Trigger A cannot recover retired-bundle history as written. It iterates bundle ids still in holder `key_secrets` (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:214-217`), but retired bundles are deleted from `key_secrets` by the current FS lever (`src/state/projection/purge.rs:538-584`).

- `frontier_advance` replaces a multi-parent frontier model with a linear predecessor chain, but the proposal never re-specifies how current concurrent frontier behavior maps. The current branch explicitly tests multi-parent frontier convergence and blocking for both `removal` and `key_rotation` (`src/state/projection/apply/tests/removal_rotation.rs:309-483`).

**C**

If adopted exactly as written, many current tests would need rewriting, and some invariants disappear.

- Retain largely as-is: `tests/cli_post_invite_bundle_delivery_test.rs:1-121`. It is already outcome-based and mechanism-agnostic.

- Retain in spirit but rewrite internals/assertions: the CLI delete/history tests in `tests/cli_per_message_fs_test.rs:73-299` and the state-level retention test in `src/state/projection/apply/tests/per_message_fs.rs:465-537`. They can still assert “deleted message gone, survivors remain,” but not `message_key`/`message_keys`/reverse-index details under KDF.

- Rewrite completely: every `message_key`-centric or `key_history_bundle`-slot test, including `src/state/projection/apply/tests/per_message_fs.rs:192-456` and `src/state/projection/apply/tests/new_joiner_history.rs:157-650`.

- Rewrite completely: the frontier/removal/rotation tests in `src/state/projection/apply/tests/removal_rotation.rs:107-533`, because `frontier_advance` changes the frontier model itself.

- Not expressible if proposal is literal: per-device bundle isolation (`src/state/projection/apply/tests/per_message_fs.rs:660-731`) and the current narrow “bundle retired, undeleted per-message K_m rows still survive” invariant (`src/state/projection/apply/tests/new_joiner_history.rs:496-650`).

**D**

The proposal’s description of the current branch is cleaner than the code actually is.

- `§1.1` / `§7.1` say the current branch has three K_bundle delivery events: `key_rotation`, `key_history_bundle`, and `key_shared` (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:26-32`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:455-459`). The branch is messier. The per-message-FS dep chain and purge logic explicitly treat `key_broadcast`, `key_history_bundle`, and `key_bundle_share` as the producer family for canonical `KeySecret(K_bundle)` materialization (`src/event_modules/message_key.rs:52-57`, `src/event_modules/message_key.rs:287-302`, `src/event_modules/key_bundle_share.rs:1-9`), while legacy/bootstrap/repair paths still use `key_shared` (`src/event_modules/key_shared.rs:1-29`, `src/runtime/key_repair.rs:710-758`).

- `§7.4` says post-invite delivery is a special case in `load_key_rotation_context` (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:490-493`). That is incomplete. Current branch also changed sender-side recipient selection in `active_rotation_recipients_for_frontier` (`src/event_modules/workspace/identity_ops.rs:469-536`); the loader fallback is only the recipient-side half (`src/state/projection/decision_context.rs:2416-2449`).

- The proposal repeatedly speaks as if `retired_bundles / retired_keys` are both “preserved” (`FS_ALT_CONVERGENT_WRAP_DESIGN.md:18`, `FS_ALT_CONVERGENT_WRAP_DESIGN.md:285-287`). Current code only has `retired_bundles` (`src/event_modules/key_secret.rs:105-127`).

- The branch still has `remove_member` as two sequential event creations, not a structural atomic pair: it emits `removal` first and only then rotates (`src/event_modules/workspace/commands.rs:971-1015`). So the proposal is right that the current pairing is non-atomic, but its scope estimate for replacing it is optimistic given the amount of frontier-, auth-, repair-, and test-surface tied to the current split (`src/runtime/key_repair.rs:799-887`, `src/state/projection/apply/tests/removal_rotation.rs:107-533`).

**E**

Don’t adopt this design as written.

The only part that looks worth revisiting later is the narrower “make removal+rotation structurally atomic” idea, because the current command really does emit them sequentially (`src/event_modules/workspace/commands.rs:971-1015`). The convergent-wrap and KDF parts do not reestablish the exact gate/cascade contracts the current FS implementation depends on (`src/state/projection/purge.rs:163-238`, `src/state/projection/purge.rs:538-584`, `src/state/projection/apply/write_exec.rs:122-153`), and the branch’s active plan has already explicitly rejected the HKDF/no-`message_key` path for now (`docs/PLAN.md:2030-2034`).

If this gets revisited after `per-message-fs` lands, the proposal needs four concrete fixes before it is credible: a real canonical dep key replacing current `k_bundle_local_event_id`, a cryptographically coherent convergence story for `wrap_event`, an exact `retired_*` executor/query spec, and explicit tests for delete-after-invite, retired-bundle late joiners, and per-device isolation. Source review only; I did not run the suite.
