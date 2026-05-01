# Event-Centered Encryption and Auth Plan

This plan extends poc-8's event-centered design with deterministic encryption
availability. It should be read beside `plan.md`, but it is not an addendum to
that file. The same core constraints apply: canonical event bytes define event
identity, projectors are deterministic transforms over facts, queue-like work is
module-owned table state, and physical purge must not erase the only semantic
evidence of deletion, removal, revocation, supersession, or receipt.

The core idea is:

```
public events + projected facts + local secret rows
  -> deterministic derived obligations
  -> bounded generated events
  -> eventual availability
```

Public rows and labels are append-only semantic facts. Local secret rows are
private inputs that may be inserted, punctured, or purged. The absence of local
secret material is never the only public proof of a semantic change.

## Ownership

Auth/encryption owns durable authorization facts, device pubkeys, group-key
epochs, group-key wrap events, wrap receipt events, deletion facts, retained
history-tree nodes, and invite history grants.

Auth/encryption does not own connection transit encryption, TCP IO, private key
custody outside local secret tables, sync scheduling, or the global control
loop. Those stay in the existing `connection`, `transport`, `sync`, `state`, and
`control_loop` boundaries.

There are two distinct meanings of "wrap":

- `key_wrap` is a durable canonical event. It encrypts a group root or
  history-tree node to one recipient pubkey and has a normal event id,
  dependencies, labels, signatures, and sync behavior.
- `connection.wrap` is an opaque transit envelope. It carries canonical event
  bytes over TCP and is not itself an event.

## Vocabulary

```
recipient        = device recipient or invite recipient
device_pubkey    = canonical event that binds one pubkey to one recipient
active_pubkey    = latest non-superseded pubkey for a non-removed recipient
key_epoch        = group-key epoch created by workspace creation or removal
removal_frontier = deterministic auth frontier named by a key_epoch
key_wrap         = canonical event encrypting an epoch root or tree node to one pubkey
key_wrap_receipt = canonical event proving the recipient received/decrypted that wrap
history_tree     = KDF tree rooted in an epoch root; leaves cover `(unix_minute, event_id)`
history_delete   = delete or expiry event naming deleted history coordinates or ranges
```

Suggested event modules:

```
src/event_modules/auth/
  invite/
  key/
  key_epoch/
  key_wrap/
  history_tree/
  removal/
```

Suggested durable shared events:

```
device_pubkey
key_epoch
key_wrap
key_wrap_receipt
history_delete
invite_history_grant
```

Suggested local-only secret state:

```
key_secret
invite_secret
local_epoch_root
local_history_node_secret
local_device_private_key
local_invite_private_key
```

## State Shape

Minimal public tables:

```
recipients(recipient_id, workspace_id, kind)
device_pubkeys(pubkey_event_id, recipient_id, pubkey, prev_pubkey_event_id)
key_epochs(epoch_id, workspace_id, prev_epoch_id, removal_event_id, removal_frontier, root_commitment)
key_wraps(wrap_event_id, epoch_id, pubkey_event_id, node_prefix, ciphertext_commitment)
key_wrap_receipts(receipt_event_id, epoch_id, pubkey_event_id, wrap_event_id)
history_nodes(epoch_id, node_prefix, node_commitment, source_event_id)
history_deletes(delete_event_id, epoch_id, deleted_cover, retained_cover_commitment)
invite_history_grants(grant_event_id, invite_recipient_id, epoch_id, cover_commitment)
```

Minimal local secret tables:

```
local_epoch_roots(epoch_id, root_secret)
local_history_node_secrets(epoch_id, node_prefix, node_secret)
local_device_private_keys(pubkey_event_id, private_key)
local_invite_private_keys(invite_recipient_id, private_key)
```

Durable labels:

```
removed:recipient_id
superseded:pubkey_id
wrap_receipted:epoch_id:pubkey_id
deleted:message_id
deleted_coord:epoch_id:minute:event_id
expired_coord_range:epoch_id:range
```

Projectors may physically purge rows, event bytes, wraps, or local secrets only
after an equivalent surviving label, summary, or retained tree node preserves
the semantic fact.

## Deterministic Closure

The encryption facts should behave like a Datalog or Differential Dataflow
closure. Base events and local secret rows produce derived obligations. Derived
obligations produce generated canonical events when the local peer has the
required secret material.

Core derivations:

```
active_pubkey(recipient, pubkey, frontier)
  = latest pubkey for recipient at frontier
    - superseded pubkeys
    - pubkeys for removed recipients

wrap_obligation(epoch, pubkey, node_prefix)
  = active_pubkey(recipient, pubkey, epoch.removal_frontier)
    + local secret for (epoch, node_prefix)
    - key_wrap_receipt(epoch, pubkey)

pending_wrap(epoch, pubkey, node_prefix)
  = wrap_obligation(epoch, pubkey, node_prefix)
    - existing key_wrap(epoch, pubkey, node_prefix)
```

Duplicate outputs collapse by canonical bytes. A `key_wrap` event is
deterministic over:

```
workspace_id
epoch_id
pubkey_event_id
node_prefix
plaintext node secret
recipient pubkey
crypto suite
```

The exact crypto construction must be domain separated, recipient-bound, and
test-vectored before any security claim depends on it. Deterministic wrapping
intentionally leaks equality of the wrap target and content. The delivery server
sees encrypted data and `key_wrap` events, but is not a recipient.

## Phase One: O(n) Broadcast With Relaxed Forward Secrecy

Phase one optimizes for deterministic eventual availability, ideally on first
sync, with minimal jobs and loops. Most work is triggered by user actions or by
receipt of other events:

- a user creates a workspace, invite, message, delete, pubkey rotation, or
  removal,
- a peer receives a `key_epoch`, `device_pubkey`, `key_wrap`, or
  `key_wrap_receipt`,
- a peer decrypts a wrap and emits a receipt,
- negentropy discovers missing canonical events and outbox delivers them.

Rules:

1. Workspace creation creates the initial `key_epoch`.
2. Every removal creates exactly one successor `key_epoch` with a fresh root
   commitment and a removal frontier.
3. A `key_epoch` creates `O(n)` `key_wrap` obligations for active pubkeys at
   that frontier.
4. The removed recipient and superseded pubkeys are excluded from those
   obligations.
5. A `device_pubkey` event tombstones the previous pubkey for the same
   recipient by dependency, then creates wrap obligations for every unreceipted
   epoch where that recipient is active.
6. A `key_wrap_receipt(epoch_id, pubkey_event_id)` stops future wrap obligations
   for that epoch/pubkey pair.
7. A receipt does not need to delete the historical `key_wrap` event. Production
   may physically purge the wrap after the receipt and any required audit
   window, but the receipt label remains.
8. If a recipient was unknown to the remover, or rotates its pubkey after the
   remover created the epoch, any peer that later knows both the epoch root and
   the active pubkey derives the same missing `key_wrap` event.
9. Offline devices weaken forward secrecy until they acknowledge receipt and
   purge old key material.
10. The operator enforces a forward-secrecy limit by removing the offline
    device. Removal creates a new epoch that excludes that device from all
    future wraps.
11. Deleted and expired messages are not recoverable from live devices after the
    delete or expiry is delivered and local history material is purged, assuming
    the delivery server did not suppress the delete or expiry event. Phase one
    records deletion facts, but does not require tree puncturing for old epochs.

Implementation shape:

```
Project(key_epoch | device_pubkey | key_wrap_receipt | removal)
  -> write durable rows/labels
  -> insert key_wrap_obligations with deterministic keys
  -> emit at most fuel-limited key_wrap events for obligations this peer can satisfy

Project(key_wrap)
  -> if local private key can decrypt:
       write local_epoch_roots / local_history_node_secrets as appropriate
       emit key_wrap_receipt
       derive newly satisfiable obligations
```

Large `O(n)` expansion must not be an unbounded projector loop. Use a
module-owned `key_wrap_obligations` table keyed by:

```
(epoch_id, pubkey_event_id, node_prefix)
```

Process that table with bounded fuel. Startup and crash recovery may regenerate
obligations from canonical facts; duplicate rows collapse. This keeps work
proportional to input deltas and affected arrangements instead of total state.

Phase-one success criteria:

- Replaying the same event set in any order produces identical active pubkeys,
  key epochs, wrap obligations, pending wraps, receipts, and deletion labels.
- A removal with `N` active recipient pubkeys creates exactly `N` wrap
  obligations, excluding removed recipients and superseded pubkeys.
- Duplicate removals, duplicate pubkey events, duplicate wraps, duplicate
  receipts, and duplicate outbox sends collapse by deterministic keys.
- Pubkey rotation prevents future wraps to the old pubkey after the supersession
  frontier and provokes missing wraps to the new pubkey.
- Clearing memory `outbox` or restarting during obligation expansion does not
  lose availability; pending wrap work is rebuilt from canonical facts and local
  secrets.
- Receipt acknowledgement stops retry/projection for that epoch/pubkey without
  erasing the semantic receipt fact.

Phase-one validation checks:

- Property-test randomized event DAGs with permutations, duplicates, delayed
  dependencies, and replay from empty state.
- Compare incremental projections against a simple reference model for active
  pubkeys, wrap obligations, pending wraps, and receipts.
- Run a large-recipient removal with very low expansion fuel and verify final
  projected state matches an unbounded reference run.
- Simulate restart with memory `outbox` cleared and prove pending wraps are
  regenerated.
- Add deterministic wrap test vectors for event id stability, domain separation,
  recipient binding, wrong-recipient decrypt failure, and no nonce reuse within
  the chosen crypto suite.

## Phase Two: History-Tree Forward Secrecy

Phase two adds forward secrecy for deleted and expired content by making the
group root the root of a puncturable history tree.

History coordinates:

```
history_coord = (unix_minute, event_id)
leaf_secret   = KDF(epoch_root, "leaf", unix_minute, event_id)
node_secret   = KDF(parent_secret, "left" | "right", node_prefix)
```

Use BLAKE3-256 for event ids, tree commitments, and set hashes, with
domain-separated inputs for each use. The goal is not only speed. The tree
relies on collision resistance so an attacker cannot choose colliding event ids
to control deletion collateral damage.

Rules:

1. Message encryption uses the leaf secret for `(unix_minute, event_id)`.
2. Tree leaves do not have duplicate messages because canonical event ids are
   BLAKE3-256 over canonical bytes.
3. A delete or expiry event names a message id, coordinate, or coordinate range.
4. Projection treats deletes as a set union. Order does not matter.
5. Applying deletes computes a deterministic retained cover: purge roots or
   secrets that cover deleted coordinates and keep the minimal sibling nodes
   needed to derive every possible undeleted coordinate.
6. The retained cover is public as commitments and local as secret rows.
7. Production may purge deleted ciphertext, deleted leaf secrets, and covered
   parent secrets after retained siblings and delete summaries are durable.
8. `key_wrap` can wrap a retained tree node, not only the epoch root.
9. New recipients receive enough retained roots and siblings to cover authorized
   history.
10. A new pubkey tombstones the old pubkey and expands wrap obligations for the
    removal frontier. Every epoch or retained node for which the recipient is
    active and unreceipted gets a deterministic wrap to the new pubkey.
11. A removed recipient is excluded from future epochs and future retained-node
    wraps.
12. Old unacknowledged wraps remain the relaxed-FS exposure until the old device
    is removed and all live devices purge acknowledged old private material.

Deletion is commutative by definition:

```
deleted_set'       = deleted_set union incoming_delete_cover
retained_cover'    = canonical_minimal_cover(all_history - deleted_set')
purge_cover'       = canonical_minimal_cover(deleted_set')
history_summary_id = Hset("history-delete-summary", deleted_set', retained_cover')
```

Invites behave as single-pubkey recipients. The default phase-two policy is a
full-history invite grant: include enough retained roots and siblings to cover
all known undeleted history and all not-known-deleted coordinate space needed
for concurrency. This is availability-friendly and may be large.

Later policies may choose current-only, since-range, or selected-range grants,
but those are explicit tradeoffs. A full-history invite is a forward-secrecy
leak if its private material persists or is intercepted. Clients must surface
that risk and prefer out-of-band delivery over trusted channels such as Signal.

Phase-two success criteria:

- Delete and expiry events commute for overlapping, adjacent, duplicate, and
  reordered ranges.
- The same delete set yields the same retained cover, purge cover, history
  summary id, and local secret rows independent of event order.
- Deleted or expired messages cannot be decrypted from live devices after delete
  delivery, retained-cover projection, local puncture, and private-key purge.
- A newcomer with an authorized full-history invite can derive every undeleted
  message that the grant policy covers and cannot derive deleted coordinates.
- A new pubkey expands deterministic wraps for every eligible frontier node and
  no superseded pubkey receives new wraps.
- Production purge never removes the only public evidence of deletion, removal,
  pubkey supersession, receipt, or retained history coverage.

Phase-two validation checks:

- Property-test history-tree deletion with randomized message coordinates,
  delete ranges, reorderings, and duplicate delete events.
- Compare incremental retained-cover projection against a simple functional
  tree-cover implementation.
- Test invite grants against generated histories with concurrent late-arriving
  undeleted messages and known-deleted gaps.
- Test puncture behavior by asserting deleted leaf secrets and covered parent
  secrets are unavailable after projection while sibling-derived undeleted leaves
  remain available.
- Test pubkey tombstone expansion across multiple epochs and retained nodes,
  including offline recipients and later removal.
- Run purge-mode tests: audit mode keeps facts; production mode can purge
  ciphertext/secrets only after labels, summaries, receipts, and retained node
  commitments survive.

## Worktree Instructions

1. Add canonical phase-one event schemas and pure projector/reference-model tests.
2. Add bounded `key_wrap_obligations` expansion before optimizing sync cadence
   or jobs.
3. Add phase-two history-tree projection only after phase-one deterministic
   replay and restart tests pass.
4. Commit the completed work on that same worktree branch before handoff or
   review.
