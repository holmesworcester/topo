# Quiet Rust Prototype Protocol (Post-PLAN End State)

This document describes the target protocol and runtime shape after completing all phases in `PLAN.md`.
It is intentionally practical: one coherent model, one projection path, one dependency mechanism, and operational behavior that is easy to test with real QUIC daemons.

Terminology note:
use `workspace` for the logical peer set and shared protocol context; reserve "network" for transport/networking concerns.

## Why?

The design goal is to keep protocol behavior auditable while still supporting real-time chat behavior and agent-friendly automation:

1. canonical data stays event-sourced and replayable,
2. transport and sync are real (QUIC + mTLS), not simulator paths,
3. projection logic is deterministic and convergent,
4. CLI workflows remain synchronous enough for imperative command chains.

## How?

We split concerns aggressively:

1. Canonical events are durable facts.
2. Runtime protocol traffic (sync/intros/holepunch control) is not canonical event data.
3. Projection is the only way canonical events affect application state.
4. Blocking/unblocking is uniform across normal and encrypted events.
5. Multitenancy is first-class with `recorded_by` scoping on shared tables.

---

# 1. Protocol Model

## 1.1 Event classes

1. Canonical shared events:
   - durable and shareable across peers.
2. Canonical local-only events:
   - durable and replayable, but never shared.
3. Runtime protocol messages:
   - non-canonical transport/sync frames only.

Shareability is event-type policy, not a separate storage system.

## 1.2 Event format

Events are flat and schema-defined.

Rules:
1. no universal `deps` field,
2. no universal `payload` envelope,
3. any schema field marked as `event_id` reference is a dependency source.

Field kinds are schema-driven (`fixed_bytes`, integers, bounded var-bytes/strings), and each event type has deterministic field order.
Field definitions are fixed; total event size is variable by event type.

## 1.3 Event identity and signatures

1. canonical event bytes are content-addressed (`event_id` from canonical bytes),
2. signed events carry canonical signer fields:
   - `signed_by` (event-id reference),
   - `signer_type` (`peer | user | workspace | invite`),
   - `signature`,
3. signature verification resolves signer key by (`signer_type`, `signed_by`) after dependency resolution,
4. transport security is separate and complementary to event signatures.

Deterministic emitted-event exception:
1. deterministic emitted event types are canonical but unsigned for deterministic bytes/ids,
2. those types omit `signed_by`, `signer_type`, and `signature` by schema,
3. they are validated by deterministic-derivation checks instead of signature checks.

No per-event transit wrapper is used.

## 1.4 Sync frame header (`payload_len`) rationale

Sync frames include a `payload_len` in the frame header.

Why keep it:
1. QUIC streams are byte streams; receiver needs explicit frame boundaries.
2. Non-event frame types also exist (reconciliation/control), so delimiters are needed for mixed frame streams.
3. Length-delimited framing allows safe skip/reject behavior for unknown/future frame types.

Safety rule:
1. `payload_len` is an untrusted framing delimiter, not semantic authority.
2. enforce global and per-frame-type max lengths.
3. fixed-size event types must match exact schema size.
4. variable-size event types must parse via schema and consume exactly `payload_len`.
5. any mismatch rejects the frame.

---

# 2. Transport and Session Identity

## 2.1 QUIC + mTLS

All peer transport uses QUIC with strict pinned mTLS.

Rules:
1. each daemon profile has persistent cert/private key material,
2. peer allow/deny policy is based on expected certificate SPKI pins,
3. no permissive verifier in production mode.

## 2.2 Identity binding

Peer identity is event-defined:

1. `peer_id = hash(peer_identity_event)`,
2. identity state maintains mapping `peer_id -> allowed cert SPKI`,
3. reverse lookup `SPKI -> peer_id` binds authenticated sessions.

In this prototype stage, identity public key and cert SPKI key material are aligned (long-lived identity key).
QUIC/TLS 1.3 still provides forward-secret session keys via handshake key agreement.

## 2.3 Recording identity semantics

1. `signed_by`: canonical signer event reference used for signature/policy checks.
2. `signer_type`: signer keyspace discriminator (`peer | user | workspace | invite`).
3. `recorded_by`: local tenant peer identity that recorded/projected the event.
4. `via_peer_id`: authenticated remote transport peer for ingress metadata.

`recorded_by` is derived from authenticated local daemon/profile identity, not from event payload claims.

---

# 3. Durable Storage Model

## 3.1 Canonical and state tables

Core durable tables:

1. `events(event_id, event_type, blob, share_scope, created_at, inserted_at)`.
2. `recorded_events(peer_id, event_id, recorded_at, source)` as receive/create journal.
3. `valid_events(peer_id, event_id)`.
4. `rejected_events(peer_id, event_id, reason, rejected_at)`.
5. projection tables owned by event modules.

Operational metadata table:

1. `peer_endpoint_observations(recorded_by, via_peer_id, origin_ip, origin_port, observed_at, expires_at)` (append-only + TTL).

## 3.2 Multitenancy model

Shared physical tables are used across peers.

Rules:
1. no per-tenant table fanout,
2. subjective rows include tenant scope (`peer_id` or `recorded_by`),
3. composite identity/index shape is tenant-first, typically `(peer_id, event_id)`,
4. query APIs are tenant-bound wrappers rather than raw unrestricted DB handles.

This preserves `poc-6`-style scoped reads/writes while keeping the schema ergonomic.

## 3.3 Table lifecycle and naming

1. schema creation runs through ordered migrations,
2. event modules register their projection table migrations,
3. startup performs migration + registry/schema consistency checks and fails fast on mismatch,
4. each event module declares explicit `event_type` and `projection_table`; no inferred naming heuristics.

---

# 4. Projection Model

## 4.1 Single projector entrypoint

All ingest paths converge on:

`project_one(recorded_by, event_id) -> ProjectionDecision`

This applies to:
1. local create,
2. wire receive,
3. replay/reproject,
4. unblock retries.

No alternate projection path is allowed.

## 4.2 Decision contract

Each projection attempt yields one terminal decision:

1. `Valid(effects)`,
2. `Block(missing_deps)`,
3. `Reject(reason)`.

Most event types are predicate + tenant-scoped autowrite.

Default write policy:
1. immutable and idempotent materialization uses `INSERT OR IGNORE`,
2. mutable operational metadata uses `ON CONFLICT DO UPDATE`,
3. avoid `INSERT OR REPLACE`.

Pipeline/projector split (DRY contract):
1. shared pipeline code handles:
   - event load/decode dispatch,
   - dependency extraction and blocking,
   - signer resolution and signature verification ordering,
   - queue/state transitions and terminal status writes,
   - generic effect application.
2. per-event projector code handles:
   - event-specific predicate/policy logic,
   - returning declarative effects for the shared applier.
3. per-event projectors do not implement custom dependency resolution, signature pipeline, or queue/terminal-write paths.

Endpoint observation policy:
1. observations are append-only rows with TTL (`observed_at`, `expires_at`),
2. ingest uses `INSERT OR IGNORE` (no in-place refresh),
3. derive `first_seen`/`last_seen` via `MIN(observed_at)`/`MAX(observed_at)` queries when needed.

## 4.3 Emitted-event rule

If projector `A` emits event `B`:

1. emit canonical `B` only (normal persistence/queue path),
2. allow `B` to project through `B`'s own projector/autowrite table.

Projectors should not directly write into another event type's projection table except rare, explicitly documented operational exceptions.

Deterministic emitted-event rule detail:
1. deterministic emitted event types still use the same emitted-event flow (`emit -> persist -> self-project`),
2. they use schema-marked unsigned mode for determinism (no signer fields),
3. shared pipeline applies deterministic derivation checks for those types in place of signer checks.

## 4.4 Explicit special cases

Some behavior stays explicit by design:

1. deletion/tombstone cascades (`message_deletion` and related checks),
2. trust-anchor handling in `invite_accepted`,
3. identity/removal policy checks from TLA guards.

---

# 5. Dependency Blocking and Unblocking

## 5.1 Blocked edge persistence

Blocked edges are recorded in:

`blocked_event_deps(peer_id, event_id, blocker_event_id)`

We do not require a full persisted dependency graph for baseline projection.
Dependencies are extracted per attempt from schema metadata.

## 5.2 Set-based unblock

Unblocking uses set-based SQL:

1. clear edges where blocker became valid,
2. requeue candidates with no remaining blockers.

This is Kahn-compatible with multiple blockers and avoids per-row imperative unblock loops.

## 5.3 Event creation API

Three creation entry points exist:

1. `persist_and_enqueue(event_blob, peer_id) -> event_id`,
2. `create_event_sync(...) -> event_id`,
3. `create_events_batch(events, project_now) -> Vec<event_id>`.

`create_event_sync` uses the same internal path as workers and returns success only when terminal state is `valid` for the target `recorded_by`.
This preserves imperative orchestration ergonomics:

1. create event A synchronously,
2. create dependent event B in the next line with no ad-hoc waits.

---

# 6. Encrypted Events (Same Model, No Fork)

## 6.1 Wrapper integration

Encrypted wrapper is a normal event type in the same registry.
It uses flat fields such as `key_event_id`, mandatory `inner_type_code`, `ciphertext`, and auth metadata.

Wrapper field rule:
1. `inner_type_code` is mandatory in this phase (fixed-width).
2. do not make it optional while wrapper ciphertext is variable-length.
3. if we later adopt padded/opaque envelopes, this can be revisited deliberately.

## 6.2 Materialization adapter

Projection flow:

1. parse outer encrypted wrapper,
2. resolve outer deps (including key dependency),
3. if missing deps: block on normal `blocked_event_deps`,
4. verify envelope signature/auth,
5. decrypt,
6. decode inner event using normal registry,
7. verify `inner_type_code` matches decoded inner event type (mismatch -> reject),
8. reject nested encrypted wrapper,
9. resolve inner deps via same schema dependency engine,
10. run normal inner projector,
11. mark outer event valid only if inner projection succeeds.

Materialization is an adapter step, not a second projection system.

## 6.3 Plaintext policy

1. default: no persisted plaintext queue,
2. plaintext exists in memory during projection only,
3. optional short-lived cache can be added later for performance.

---

# 7. Durable Queue and Worker Model

## 7.1 Queue tables

Operational queues:

1. `ingress_queue` for raw received transport frames,
2. `project_queue(peer_id, event_id, available_at, attempts, lease_until)`,
3. `egress_queue(connection_id, frame_type, event_id, payload, attempts, lease_until, sent_at, dedupe_key)`.

Canonical tables and queue tables stay separate.

## 7.2 Workers

1. ingress worker:
   - frame decode, canonical insert, recording metadata, append endpoint observation row, project enqueue.
2. project worker:
   - claim, project (`valid|block|reject`), dequeue.
3. egress worker:
   - claim per connection, send frame, mark sent or retry.
4. cleanup worker:
   - reclaim expired leases, purge stale/sent operational rows, TTL endpoint cleanup.

Queue claim/lease/retry/backoff logic is DRY and shared across `project_queue` and `egress_queue`.

## 7.3 Egress production

Egress rows are produced by:

1. negentropy reconciliation decisions,
2. incoming have-list responses,
3. control protocol producers,
4. optional proactive send pathways.

For canonical event transfer, egress rows carry `event_id`; canonical blob is read at send time.

## 7.4 Dedupe and purge

1. `project_queue` is transient and purged on terminal decision,
2. enqueue uses dedupe guards and skips terminal/blocked states,
3. duplicate enqueue races are safe via `INSERT OR IGNORE` plus terminal fast-drop checks,
4. `attempts` is retry bookkeeping (backoff, lease recovery, alert thresholds), not business truth.

## 7.5 Atomicity boundaries

Must be atomic:

1. canonical event insert + recorded insert + project enqueue,
2. projection state transition + project dequeue,
3. unblock update + project requeue.

Can be eventual:

1. transport send,
2. queue cleanup/purge,
3. metrics/logging.

---

# 8. CLI and Daemon Contract

## 8.1 Operational shape

1. one daemon per profile/peer,
2. local RPC control socket,
3. thin CLI (`p7ctl`) with stable JSON and strict exit codes.

## 8.2 Testing and agent ergonomics

Assertion-first commands are first-class:

1. `assert-now`,
2. `assert-eventually`,
3. optional `assert-stable`.

`assert-eventually` is preferred over ad-hoc sleeps for both deterministic tests and agent self-play loops.

---

# 9. Identity, Invites, Trust Anchor, and Removal

## 9.1 TLA-first requirement

Identity phase projector predicates are derived from an explicit TLA causal model.
Rust projector guards map 1:1 to named model guards.

## 9.2 Invite model

Use split event types:

1. `user_invite`,
2. `device_invite`,
3. `invite_accepted`.

No multimodal `invite(mode=...)` type.

Implementation uses shared invite helper logic with per-type policy tables.

## 9.3 Trust-anchor cascade

`invite_accepted` records trust-anchor intent for `workspace_id` in tenant scope.

Required semantics:
1. workspace is not valid until trust anchor exists,
2. invites are not force-valid,
3. normal signer/dependency chain still governs validity.

Self-invite bootstrap stays explicit:

1. create `workspace`,
2. create bootstrap `user_invite`,
3. locally accept invite (`invite_accepted`),
4. cascade unblocks `workspace -> user_invite -> user -> device_invite -> peer_shared`.

## 9.4 Sender-subjective encryption baseline

For each encrypted message in the prototype baseline:

1. sender creates a fresh local key event,
2. sender emits one key-wrap event per currently eligible recipient peer pubkey,
3. encrypted content references key dependency via normal event refs.

After observing `user_removed` or `peer_removed`, sender excludes removed recipients from subsequent wraps.
No historical re-encryption or key history backfill is required in this baseline.

---

# 10. Convergence and Test Invariants

The system is accepted only if these invariants hold:

1. replay invariance:
   - replaying canonical events yields the same projected state.
2. reproject invariance:
   - dropping projections and reprojection yields the same state.
3. reorder invariance:
   - out-of-order ingest converges to the same state.
4. source isomorphism:
   - `local_create`, `wire_receive`, and replay converge through the same `project_one` path.
5. tenant isolation:
   - no cross-tenant leakage under scoped queries.

Operational queue rows are excluded from end-state equality fingerprints.

---

# 11. Performance and Operational Defaults

1. use SQLite WAL mode and prepared statements,
2. batch worker operations with measured sizing,
3. keep queue purge policies explicit and predictable,
4. monitor blocked counts, queue age, retries, lease churn.

Initial event-size policy:

1. `EVENT_MAX_BLOB_BYTES = 1 MiB` soft cap,
2. `FILE_SLICE_TARGET_BYTES = 256 KiB`,
3. `FILE_SLICE_MAX_BYTES = 1 MiB` hard cap.

`file_slice` events are signed and validated like other canonical events.

---

# 12. Extensibility Path

The completed prototype is deliberately minimal but extension-friendly.

## 12.1 Richer content surface

Additional content event families (reactions, edits, richer thread semantics, moderation signals) can be added by:

1. declaring schema + projection table metadata,
2. using default autowrite where possible,
3. introducing explicit special projector logic only when policy semantics require it.

## 12.2 File attachments and large payload flows

Attachments and slice streaming fit naturally:

1. large payload events remain canonical typed events,
2. variable event sizes already support larger slices,
3. deps and signatures continue to gate integrity and ordering.

## 12.3 Proactive 1-hop gossip on send

Beyond pull/reconcile sync, send-time proactive push can be layered as an egress producer:

1. on local canonical event creation, enqueue one-hop egress to currently connected peers,
2. keep dedupe by `(connection_id, event_id)` and existing lease/retry rules,
3. preserve canonical/projector semantics unchanged (transport optimization only).

## 12.4 Subjective encryption with history provision

The baseline sender-subjective O(n) wrap model can incrementally evolve toward the `poc-6` subjective-encryption plan in `docs/group-encryption-design-aspects.md`:

1. introduce update-path style shared key structure for better asymptotics,
2. add key request/response healing for inactive peers,
3. add history-availability policy and provisioning events for newly linked devices/users,
4. eventually optimize recipient-cover selection while preserving the same canonical dependency/projection model.

This extension path is intentionally additive: it does not require a new storage or projection architecture.

---

# 13. Summary

After completing all phases in `PLAN.md`, the system is:

1. real transport and real daemon operations (no simulator dependency),
2. one canonical event model with strict replayability,
3. one projection/dependency engine for cleartext and encrypted events,
4. queue-driven operational control with explicit atomic boundaries,
5. tenant-scoped shared tables,
6. trust-anchor and identity behavior grounded in TLA guard mappings.

The result is a small protocol core with clear upgrade paths instead of a stack of exceptions.
