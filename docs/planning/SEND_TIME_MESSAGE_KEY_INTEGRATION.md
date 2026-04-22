# Send-Time Message Key Integration (pending)

## Status

**Option C wire/projection landed** in commit `db0f7440`. The
`owning_message_event_id` field is dropped from the `message_key`
wire; linkage is established at Encrypted-projection time by writing
`(message_event_id, message_key_event_id)` into a new
`messages_to_message_keys` reverse index. Purge cascade now reads the
reverse index to enumerate the per-message K_m row to remove.

**Remaining scope** — wire the SEND path (`message::commands::create`)
to actually emit a `message_key` alongside each outgoing message and
encrypt under a fresh K_m instead of K_epoch. The current send flow
still uses the legacy `KeyRotation` content key (which is why the
existing FS CLI tests exercise blob-level purge, not K_m-level purge).
Upgrading to per-message K_m tightens the FS granularity but does not
add a new property — blob purge already covers the deleted message's
ciphertext.

## Current send flow (legacy, still functional)

```
message::commands::send
  → message::commands::create
    → workspace::identity_ops::ensure_content_key_for_peer(db, recorded_by)
          → returns KeyRotation's event_id + K_epoch in key_secrets
    → create::create_encrypted_event(db, recorded_by, &K_rotation_evid, &msg, signer)
          → SELECT key_bytes FROM key_secrets WHERE event_id = K_rotation_evid
          → encrypts msg under K_epoch with random nonce
          → builds Encrypted wrapper with key_event_id = K_rotation_evid
          → signs + emits
```

Every message under the current rotation uses the SAME K_epoch.
Delete-purge is scoped to the message's blob only; K_epoch persists
(shared across other live messages in the rotation). That's the FS
property the CLI tests prove.

## Target send flow (Per-Message FS)

```
send → create_with_message_key:
  K_bundle_evid, K_bundle_bytes <- lookup sender's current bundle
  K_m <- fresh random 32 bytes
  encrypt inner under K_m, random nonce → (nonce_inner, ct_inner, tag_inner)
  wrapped_k_m <- AEAD(K_bundle, K_m) with deterministic nonce
  build message_key event:
    { bundle_id, k_bundle_local_event_id: K_bundle_evid,
      owning_message_event_id: ???,  ← the circular bit
      wrapped_k_m, nonce: ... }
  mkey_evid <- content-address hash of message_key bytes
  build Encrypted wrapper with key_event_id = mkey_evid
  msg_evid <- content-address hash of Encrypted wrapper
  emit message_key; emit Encrypted(+ signed envelope)
```

## The chicken-and-egg

poc-7's invariant: **outer event_id = logical message id**. A
message's `message_id` is derived from the hash of its encoded outer
(Encrypted or Signed(Encrypted)) bytes.

message_key carries `owning_message_event_id` so the purge cascade
can enumerate "all message_keys bound to this deleted message"
(`purge.rs` extension). Under content-addressing, message_key's own
event_id derives from its bytes, which include
`owning_message_event_id`. So:

- To compute `mkey_evid`, we need `owning_message_event_id`.
- To compute `msg_evid`, we need `mkey_evid` (because the Encrypted
  wrapper carries `key_event_id = mkey_evid` in its bytes).
- To compute `owning_message_event_id` (= `msg_evid`), we need
  `msg_evid`.

A cycle. The current wire format can't be built in one pass.

## Three resolution options

**Option A — Use a sender-chosen logical id (NOT the outer hash).**
Break the "outer event_id = logical id" invariant. The sender
picks a fresh random/deterministic id M_id for the logical message
(e.g., `blake3(author_signing_key || counter)`). The Encrypted
wrapper carries M_id as a NEW outer-header field distinct from
event_id. message_key's `owning_message_event_id = M_id`. Purge
enumerates by M_id.

Pros: clean. No cycle. FS guarantees hold identically.
Cons: big invariant change. Affects every module that uses outer
event_id as the logical ref (message, reaction, file, file_slice,
purge, etc.). Multi-commit refactor.

**Option B — Two-phase emission with a reverse-index.**
Emit Encrypted wrapper first with `key_event_id = 0` (or a
placeholder derived from K_m). On projection, Encrypted blocks
normally on a dep that the subsequent message_key emission
satisfies. message_key emitted second with `owning_message_event_id
= msg_evid`. Purge uses the `message_keys` reverse index
(`owning_message_event_id → event_id`) which is now populated.

Pros: no invariant change.
Cons: two network events per message in strict emission order.
Encrypted's `enc.key_event_id` field needs a different meaning —
something like "the event id that will SAT my dep," not a direct
`message_key` reference. Awkward.

**Option C — Don't carry `owning_message_event_id` in message_key
wire; infer from message on projection.**
message_key wire drops the field. When the Encrypted message
projects and unwraps via its message_key, the projection writes
`(message_event_id, message_key_event_id)` into a new
`messages_to_message_keys` reverse index table. Purge enumerates
via that table.

Pros: simplest wire change. No chicken-and-egg.
Cons: reverse index is per-tenant derived state. If message_key
arrives with no owning message, it sits as a K_m row without being
bound to any message — a leak if the message never arrives. Need a
GC rule for orphan message_keys.

## Recommendation

**Option C** is the smallest surgical change. Drop
`owning_message_event_id` from the message_key wire. On Encrypted
projection that unwraps K_m via a specific message_key, write
`(msg_evid, mkey_evid)` into a new `messages_to_message_keys`
table. Purge consults that table for cascade enumeration.

The FS property is preserved: delete flows through
`MessageDeletion(msg_evid)` → cascade reads
`messages_to_message_keys` → purges `message_keys.event_id =
mkey_evid` + `key_secrets.event_id = mkey_evid`. K_m is gone as
an on-disk row AND as a wire artifact.

GC for orphan message_keys (no message ever materialized): a
time-bounded TTL on the `message_keys` row — if no owning message
has arrived within grace, drop the K_m row. This is a correctness
concern for peer crashes during send, not a security concern.

## Scope of implementation under Option C

Files to touch:

- `src/event_modules/message_key.rs` — drop
  `owning_message_event_id` field from MESSAGE_KEY_FIELDS,
  MessageKeyEvent struct, parse, encode, determinism helper.
  Wire size shrinks from 165 B to 133 B.
- `src/state/projection/apply/stages.rs` or
  `src/state/projection/encrypted.rs` — on successful decrypt of an
  Encrypted via a specific message_key_id, write
  `(message_evid, message_key_evid)` into
  `messages_to_message_keys`.
- `src/state/projection/purge.rs` — change the enumeration query
  from `WHERE owning_message_event_id = ?` to JOIN against
  `messages_to_message_keys`.
- `src/event_modules/message/commands.rs` — new
  `create_with_message_key` helper invoked from `create()`.
- `src/state/projection/create.rs` — supporting `create_encrypted_event`
  variant that emits a message_key alongside.
- Update existing tests that asserted the old
  `owning_message_event_id` field.

Estimated: ~8 files, ~200 LOC changes, plus test updates.

## Why defer

Chicken-and-egg resolution + reverse-index introduction +
send-path refactor is a coherent unit that deserves its own commit
and review pass. Half-implementing it would destabilize the current
working state.

The existing CLI FS tests (`cli_fs_deleted_message_removes_key_preserves_history`
etc.) prove the FS property is achieved via blob-level purge
through the legacy KeyRotation flow. Upgrading to per-message K_m
tightens the FS model but isn't a new property — it's a finer
granularity of the same cascade.

Phase 8 sim tests that depend on send-time message_key emission
(e.g., "compromise test: send, delete, dump local state — no K_m
for deleted message") are also blocked on this same design
decision.

## Recommended next session

1. Implement Option C (drop owning_message_event_id, add reverse
   index, send-time emission).
2. Run CLI FS tests — they should continue to pass with tighter
   guarantees (K_m specifically purged, not just blob).
3. Add sim tests for the remaining Phase 8 matrix (bootstrap,
   heal, WrapPubkey rotation, per-device lineage, etc.).
