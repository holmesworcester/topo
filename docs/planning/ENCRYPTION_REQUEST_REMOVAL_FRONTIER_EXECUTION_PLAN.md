# Encryption Request + Removal Frontier Execution Plan

## Objective

Design and implement the next encryption PoC around these primitives:

1. removal events form a DAG,
2. key rotations point at a removal frontier,
3. the remover performs a constant-capped proactive first send,
4. missing recipients recover keys via signed request/response repair,
5. every invite carries a constant-capped recent history as separate wrapped deliveries,
6. key delivery authorization depends on the removal frontier,
7. non-expired invite-event public keys are subscribed to future proactive sharing.

The primary goal is not cryptographic novelty. The goal is a coherent event and
projection model that is:

- async-share-friendly in small groups,
- operationally bounded in large groups,
- partition-tolerant when any online eligible holders exist,
- explicit about what removed users may and may not recover.

This document is an implementation plan, not a final protocol spec. It
deliberately includes success criteria, checks, and end-to-end validation cases.

## Scope

### In scope

- Durable removal and rotation events.
- Durable or TTL-bounded request/response events for key repair.
- Frontier-bound authorization for proactive shares and repair responses.
- Invite-targeted historical `key_shared` deliveries for a capped recent key window.
- Projection and unblock behavior for encrypted events that arrive before keys.
- Partition-healing behavior, including invites unknown to one partition.
- Simulation and CLI-driven tests that show proactive coverage, repair propagation,
  and denial after removal.

### Out of scope

- Perfect forward secrecy beyond removal-triggered rotation.
- Arbitrary background rotation unrelated to removal.
- TreeKEM / MLS interoperability.
- UX-level policy for moderator approval or appeals.
- Final byte layout tuning beyond “bounded and measurable”.

## Core Model

### 1. Removal DAG

Add a durable `Removal` event:

- fields:
  - `removed_member_ref`
  - `parents[]` as the prior removal frontier
  - `removed_by`
  - `signed_by`
- semantics:
  - removals form a DAG, not a single chain
  - multiple independent removals may coexist until compacted by a later frontier

### 2. Removal Frontier

Define a canonical `frontier_hash = H(sorted(frontier removal ids))`.

This frontier hash is the authorization boundary for key delivery:

- every `KeyRotation` binds to exactly one `frontier_hash`
- every proactive share produced from that rotation binds to that same `frontier_hash`
- every `KeyRequest` names the same `frontier_hash`
- every `KeyResponse` / `KeyShared` must match that `frontier_hash`

This is the key rule that prevents a removed user from requesting or receiving a
key for an epoch from which they are excluded.

### 3. Rotation by Remover

Add a durable `KeyRotation` event:

- fields:
  - `key_event_id`
  - `frontier_hash`
  - `removal_frontier[]` or resolvable frontier refs
  - `rotated_by`
  - `signed_by`
- semantics:
  - created only after a removal frontier change
  - introduces a new group key epoch
  - does not itself contain all wrapped deliveries

The remover then performs a proactive first send with a hard cap:

- proactive targets:
  - all non-expired invite-event public keys in the active set
  - subject to a constant byte/count cap
- if the active invite-key set exceeds the cap:
  - prioritize the active set by recency / current-online heuristic
  - remaining recipients recover via request/response

### 4. Delivery Primitive

Use a recipient-targeted delivery object keyed by:

- `delivery_target = { key_event_id, frontier_hash, recipient_key_ref }`
- `delivery_target_id = H(delivery_target)`

Where `recipient_key_ref` is the active invite-event pubkey ref or other active
unwrap-key ref for the intended recipient.

The actual wrapped-key share can stay close to the existing `key_shared`
semantics:

- `wrapped_key`
- `key_event_id`
- `recipient_key_ref`
- `unwrap_key_event_id`
- `frontier_hash` or `delivery_target_id`
- `signed_by`

The exact event type can remain `key_shared` or be split into a more explicit
`key_response`/`key_delivery` event later. For the PoC, semantic correctness is
more important than the final name.

### 5. Request Primitive

Add or extend a durable/TTL-bounded `KeyRequest` event:

- fields:
  - `delivery_target_id`
  - `key_event_id`
  - `frontier_hash`
  - `recipient_key_ref`
  - `blocked_event_id`
  - `expires_at_ms`
  - `signed_by`
- semantics:
  - emitted when a node receives an encrypted event but lacks the matching key
  - shareable while live
  - can be recreated deterministically if still needed

### 6. Response Primitive

Response events are signed wrapped-key deliveries bound to the same target:

- fields:
  - `delivery_target_id`
  - `wrapped_key`
  - `expires_at_ms`
  - `signed_by`
- semantics:
  - valid only if signer is frontier-authorized to answer
  - valid only if recipient is eligible at the bound frontier
  - TTL matches the request TTL for the same repair episode

### 7. Invite Historical Deliveries

Every invite should carry a capped recent history as separate `KeyShared`
deliveries targeted to the invite event:

- include the most recent historical key deliveries up to a constant cap
- emit them as separate frontier-bound `KeyShared` events
- wrap them to the invite-event public key(s)
- omit older history once the cap is reached
- older missing keys are recovered later through the same `KeyRequest` path

This gives async joiners a large but bounded no-repair history window, while
keeping invite creation and sync behavior predictable.

### 8. Invite Subscription for Future Proactive Sharing

Non-expired invite-event public keys should be treated as proactive recipients
for future rotations until the invite ages out.

For the PoC, define:

- `INVITE_HISTORY_KEY_CAP = 100`
- `INVITE_ACTIVE_TTL_MS` as a shared constant
- `invite is active` iff `invite.created_at_ms + INVITE_ACTIVE_TTL_MS > now`

This predicate must be derivable from shared invite events alone. It must not
depend on local-only acceptance state.

## Projection Model

### Encrypted event projection

Encrypted events should depend semantically on `key_event_id`, not on a giant
bundle object.

Projection flow:

1. encrypted event arrives,
2. projector checks for the needed local `key_secret`,
3. if present, decrypt and continue normally,
4. if missing, block on the key and emit a `KeyRequest`,
5. when a matching delivery arrives and materializes the key, unblock.

This keeps “message before key” and “key before message” symmetric.

### KeyRequest projection

When a valid `KeyRequest` is projected:

- record it as a live repair need for `delivery_target_id`
- leave it shareable until TTL
- if the local node holds the key and frontier permits sharing, it may create a response

### KeyResponse / KeyShared projection

When a valid matching delivery is projected:

- verify signer and frontier authorization
- verify recipient eligibility against the same frontier
- if for the local recipient, unwrap and materialize `key_secret`
- mark the request satisfied locally
- suppress lower-ranked competing responses from further sharing

### Response ranking

Use deterministic ranking per target:

- `rank = H(delivery_target_id || responder_id)`
- only the best currently known valid response stays shareable
- losers remain accepted but non-shareable until TTL expiry

This keeps amplification bounded while preserving eventual convergence.

## Authorization Rules

### Frontier-bound eligibility

A node may proactively share or answer a request only if:

1. it holds the key for `key_event_id`,
2. it can prove the request/response target matches `frontier_hash`,
3. the recipient key ref is still eligible in that frontier,
4. the recipient key ref is not descended from or superseded by a removed member in that frontier.

### Removed-user denial

The key safety property for the PoC:

- a removed user must not obtain a successful response for any rotation whose
  frontier excludes them

That means frontier checks are not optional metadata. They must be part of the
response authorization predicate and part of the request target.

## Proactive Sharing Policy

### Active set

The proactive send should target:

- all non-expired invite-event public keys in the active set,
- subject to a constant cap.

The active set should be derived from:

- non-expired user invites,
- non-expired device invites,
- optional recency ordering heuristics only when the set exceeds the cap.

For this PoC, prefer a deterministic ordering:

- newest active invite first,
- tie-break by invite event id.

### Constant cap

Choose one cap for the PoC and keep it explicit:

- by total bytes, or
- by max recipient count, or
- both

The cap must be stable enough that simulation and CLI tests can reason about it.

### Expected behavior

- small groups: most or all active members get proactive shares
- large groups: a hot subset gets proactive shares, cold members repair on demand

## Invite History Policy

### Rule

Every invite includes the most recent capped historical key deliveries for that
invite’s public keys, emitted as separate `KeyShared` events at invite
creation time.

### Expected outcomes

- if a joiner syncs only recent history, invite-targeted shares are enough
- if a joiner joins after recent rotations, those keys are already proactively
  wrapped to the invite and can sync before or during join
- after join and recent sync, the invitee should already decrypt recent history
  without sending any `KeyRequest`
- if a joiner backfills beyond the cap, they emit `KeyRequest`s for older keys
- if the invite reaches one partition before the other, the joiner can still
  heal later after partitions merge

## Partition-Healing Requirements

The design must handle all of these:

### 1. Invite unknown to another partition

Scenario:

- partition A issues and accepts an invite
- partition B does not know that invite exists yet
- remover/rotator in partition B rotates while partitioned
- after healing, the new member joins the merged graph

Expected result:

- the new member may miss proactive deliveries generated during the partition
- after healing, the joiner requests missing keys
- any frontier-authorized holder with knowledge of the joiner’s invite key ref
  can answer once the invite state converges

### 2. Message before invite bundle

Scenario:

- joiner receives encrypted history before invite key bundle

Expected result:

- messages block on missing keys
- invite bundle or later repair unblocks them

### 3. Invite bundle before message

Expected result:

- local key materialization happens first
- later encrypted messages decrypt immediately

## Test Plan

Prefer validation through existing daemon control surfaces over raw DB
inspection wherever possible:

- `topo messages`
- `topo keys`
- `topo stats`
- `topo assert-now`
- `topo assert-eventually`
- matching RPC methods when JSON-level assertions are easier

## Success Criteria

### SC1. Frontier-bound delivery is explicit and executable

The event model must make it impossible to authorize a response without the
same `frontier_hash` that the rotation used.

Checks:

- projector/unit tests for `KeyRotation`, `KeyRequest`, and `KeyResponse`
- break case: mismatched frontier hash rejects
- pass case: matching frontier hash accepts

End-to-end validation:

- one encrypted event blocks, then unblocks only when a matching-frontier
  delivery arrives

### SC2. Removed users cannot recover excluded keys

A removed user must not receive a valid response for a key rotated after the
frontier that removed them.

Checks:

- unit test: responder rejects request whose recipient key ref is excluded by frontier
- scenario test: removed user emits request and receives no valid response
- break test: altered authorization path that ignores frontier must fail the suite

End-to-end validation:

- sender posts after removal-driven rotation
- removed user syncs, blocks, requests, retries, and still never decrypts

### SC3. Non-expired invite-event pubkeys receive proactive sharing

The remover’s first send must proactively wrap to non-expired invite-event
public keys, and future rotations must continue doing so while those invites
remain active.

Checks:

- scenario test with non-expired invite pubkeys under the cap
- scenario test with non-expired invite pubkeys above the cap
- scenario test with expired invite pubkeys excluded
- assert proactive share count equals all active invite keys when under cap
- assert capped selection when over cap

End-to-end validation:

- active recent joiner receives the new key without needing repair
- same invite keeps receiving proactive shares for later rotations until expiry

### SC4. Missing keys recover through request/response

Missing recipients must heal through request/response without needing a giant
shared wrap event.

Checks:

- request emitted on blocked encrypted event
- frontier-authorized responder creates response
- recipient materializes key and unblocks

End-to-end validation:

- message arrives before key
- request propagates
- response propagates
- message becomes visible

### SC5. Response amplification is bounded

Lower-ranked responses must stop sharing once a better response is known.

Checks:

- sim benchmark with all responders eligible
- sim benchmark with best-observed-only response creation
- report duplicate response count and transferred copies

End-to-end validation:

- star and graph sim runs show bounded duplicate propagation and stable winner selection

### SC6. Invite-targeted recent history works without repair and older history still recovers

Joiners must receive the most recent capped key window from the invite as
separate `KeyShared` events, decrypt recent history without repair, and repair
older history on demand.

Checks:

- scenario test: last `100` recent keys are emitted as separate invite-targeted
  `KeyShared` events
- scenario test: recent messages decrypt from invite-targeted shares alone
- scenario test: older messages beyond cap emit `KeyRequest`
- scenario test: older requests eventually resolve after repair

End-to-end validation:

- joiner joins, syncs, and views recent history immediately without repair
- joiner then backfills older history and repairs only the out-of-cap keys

### SC7. CLI / RPC observability proves proactive coverage and repair behavior

The PoC must be testable through existing daemon control surfaces wherever
possible.

Checks:

- `topo messages` or RPC `Messages` proves whether messages decrypt
- `topo keys` / RPC `Keys` proves whether recent invite-targeted keys are present
- `topo stats` / `Status` / `AssertNow` proves `key_secret_count` and message counts
- add one explicit repair enable/disable control so tests can compare
  proactive-only behavior against proactive+repair behavior

End-to-end validation:

- with repair disabled, recent joiner still reads in-cap history
- with repair disabled, out-of-cap history remains blocked
- with repair enabled again, out-of-cap history recovers

### SC8. Partitions heal correctly

Partitions with invite asymmetry must still converge after healing.

Checks:

- scenario test: invite created in partition A only
- scenario test: rotation happens in partition B while invite unknown there
- healing test: after frontier/invite convergence, joiner requests and receives missing keys

End-to-end validation:

- joiner can read messages after both partitions resync, without replaying the whole room from scratch

## Concrete Test Matrix

### Projector/unit tests

- `key_rotation_valid_with_matching_frontier`
- `key_rotation_rejects_missing_frontier`
- `key_request_valid_with_matching_target`
- `key_request_rejects_missing_key_event_id`
- `key_response_valid_for_matching_frontier`
- `key_response_rejects_frontier_mismatch`
- `key_response_rejects_removed_recipient`
- `invite_history_delivery_compacts_to_cap`
- `invite_history_delivery_skips_expired_invites_for_future_rotations`

### Projection-path integration tests

- blocked encrypted event emits `KeyRequest`
- matching `KeyResponse` materializes `key_secret`
- mismatched frontier response does not unblock
- removed recipient response remains blocked forever

### CLI / daemon scenario tests

- removal rotates once and proactively shares under cap
- active invite pubkey under cap receives proactive share
- over-cap cold peer repairs by request
- invite-targeted recent `KeyShared` events provide recent history without repair
- older history requires request/response
- removed user cannot decrypt post-removal message
- repair-disabled mode proves recent history still decrypts from proactive invite shares
- repair-disabled mode proves older out-of-cap history remains blocked
- repair-enabled mode then proves the same older history recovers

### topo-sim tests

- fake star: requests propagate to holders in one round through hub
- fake graph: requests/responses reach all eligible peers in bounded rounds
- graph benchmark at `1k / 10k / 100k`
- report:
  - avg request bytes/peer
  - avg response bytes/peer
  - duplicate response creation
  - duplicate response propagation
  - multiplier over proactive share

## End-to-End Validation Scenarios

### E2E 1. Removal and proactive share

1. create group with active and inactive invite pubkeys
2. remove one member
3. remover emits `Removal`
4. remover emits `KeyRotation`
5. remover proactively shares to active invite pubkeys up to cap
6. active recipients decrypt next message without repair
7. existing non-expired invites stay subscribed for later rotations until expiry

### E2E 2. Repair after missing proactive share

1. same setup, but recipient is outside proactive cap
2. recipient receives encrypted message
3. recipient blocks and emits `KeyRequest`
4. best responder emits `KeyResponse`
5. recipient decrypts and unblocks

### E2E 2a. Join without requesting for recent history

1. create more than one recent rotation before invite acceptance
2. create a new invite
3. emit the last `100` invite-targeted `KeyShared` deliveries as separate events
4. sync the invite and those recent `KeyShared` events to the invitee before or during join
5. join the invitee
6. verify via `topo keys`, `topo messages`, and `topo stats` that recent history decrypts with no `KeyRequest`

### E2E 3. Removed user denial

1. member is removed in frontier `F`
2. remover rotates to key `K(F)`
3. removed user receives encrypted message and emits request
4. all eligible responders reject or ignore the request
5. removed user remains blocked and cannot decrypt

### E2E 4. Partition-healing with unknown invite

1. partition A creates invite and accepts joiner
2. partition B remains unaware of that invite
3. partition B rotates after removal
4. partitions heal
5. invite and frontier state converge
6. joiner repairs missing keys and decrypts allowed history

### E2E 5. CLI-visible proactive vs repair comparison

1. create a room with more than `100` historical rotations
2. create a fresh invite and join it
3. run with repair disabled
4. verify recent history decrypts and older history does not
5. re-enable repair
6. verify older history becomes readable after request/response

## Implementation Phases

### Phase 1. Frontier and rotation events

- add `Removal`
- add `KeyRotation`
- add frontier hash derivation and validation

Exit criteria:

- frontier hash is stable and test-covered
- rotations cannot exist without a frontier

### Phase 2. Frontier-bound request/response

- extend `KeyRequest`
- bind `key_shared` or new `KeyResponse` to `delivery_target_id`
- add authorization checks for frontier and removed-recipient denial

Exit criteria:

- requests and responses project correctly
- removed-recipient denial case is executable

### Phase 3. Proactive share and active invite pubkeys

- define active invite-key selection from shared non-expired invite events
- implement capped proactive delivery generation
- add stats/metrics for proactive hit rate
- add repair enable/disable control for CLI/scenario tests

Exit criteria:

- under-cap active invite keys all covered
- over-cap selection is deterministic and measurable
- expired invites stop receiving future proactive shares

### Phase 4. Invite bundle history window

- replace one-key invite wrap with capped recent invite-targeted `KeyShared` history
- add join-path projection and lazy backfill

Exit criteria:

- recent in-cap history works without repair
- older history repairs correctly
- invitee can sync the recent invite-targeted key history before or during join

### Phase 5. Partition and scale validation

- extend topo-sim scenarios for invite asymmetry
- add star/graph amplification measurements
- add removal denial and healing scenarios
- add CLI-shaped E2E scenarios that use `topo messages`, `topo keys`, `topo stats`,
  and `topo assert-*` for verification

Exit criteria:

- partition-healing scenario passes
- removed-user denial scenario passes
- `1k / 10k / 100k` graph/star numbers are published

## Deliverables

1. Runtime event schemas and projectors for removal, rotation, request, and response.
2. Updated TLA/runtime mapping rows for any modeled checks touched by the change.
3. Scenario and topo-sim tests for:
   - proactive share,
   - repair,
   - partition healing,
   - removed-user denial.
4. Benchmark output comparing repair traffic against proactive-only sharing.
5. CLI-visible proof that recent invite-targeted shares decrypt on join without repair.

## Recommended First Slice

Implement the minimum path in this order:

1. `Removal`
2. `KeyRotation`
3. frontier-bound `KeyRequest`
4. frontier-bound `KeyResponse` / extended `key_shared`
5. removed-recipient denial test
6. capped proactive active-invite sharing
7. invite history cap as separate invite-targeted `KeyShared` events
8. CLI / repair-toggle validation path

That yields the core correctness properties before any large-scale tuning.
