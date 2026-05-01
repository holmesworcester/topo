# Topo rewrite

I want to rewrite topo with clarity on:

* interfaces
* the invariants they guarantee
* decoupling
* realms of responsibility
* event-based networking

UPDATED:

- Inbound processing is a pure function chain; admission by event id happens before context loading.
- Queue-like work is just module-owned table rows at wait/dedupe/retry/schedule/IO boundaries.
- `events` stores durable, local, and endpoint-local canonical event bytes; `outbox` stores only `(connection_id, event_id)`.
- Blocking uses `blocked_by_event(blocked_by_event_id, event_id)` pair rows and same-transaction unblocking.
- Connection wrapping has two modes: endpoint-pubkey bootstrap/repair and connection-secret ordinary traffic.
- Outgoing TCP flow has one send owner per connection: `outbox` is the deduped source, a bounded hot queue keeps bytes ready, and TCP writability is the backpressure signal.
- Event modules own their canonical `codec.rs`; "wire" means transit bytes, not canonical event bytes.
- `state` materializes table definitions from event-module declarations; it owns storage mechanics, not domain schema meaning.
- Sync is an event-module family, not a separate sync engine.
- Timely Dataflow and Differential Dataflow are a proposal and source of ideas for Rust architecture and performance: deltas, arrangements, consolidation, frontiers, compaction, and bounded work should inform experiments without committing the kernel to those runtimes.
- Production may physically purge deleted or TTL-expired events and rows, but only after surviving facts, labels, summaries, or high-water marks preserve any semantic truth future projections need.

See appendix for documentation style rules and references.

# Timely / Differential Proposal

Timely Dataflow and Differential Dataflow are a proposal and source of ideas, not a settled dependency choice or required kernel architecture. They are useful local references for Rust performance work because they make deltas, indexed arrangements, logical progress, compaction, and bounded work explicit.

The design should borrow ideas that simplify this kernel. It should not import their full model unless doing so clearly reduces code and operational complexity. A good outcome is that selected projector families could later be lowered into Differential-style dataflows, while the default kernel remains small and auditable.

Ideas to test:

- Facts/events are base collections.
- Projectors are incremental transformations from input deltas and indexed context to output deltas.
- Module table declarations include the keys and indexes needed to maintain reusable arrangements.
- Dedupe is consolidation by deterministic key: event id, wire id, `(connection_id, event_id)`, or module-owned fact key.
- Joins, semijoins, antijoins, distincts, counts, and reductions should be expressed structurally in module declarations when possible, not hidden behind opaque context scans.
- Large cascades become bounded obligations with fuel/batch limits; the control loop reactivates them rather than recursively draining them.
- Logical truth and physical storage are separate: deletion, expiry, revocation, and supersession are facts; purge and merge are physical compaction of data whose semantic replacement is already represented.
- Pure deterministic work such as parse, signature verify, decrypt, hash, and canonical encode may run inline or as jobs, but its results are facts. External IO remains an effect boundary.

Performance rules from these systems:

- Do work proportional to input deltas and affected arrangements, not total stored facts.
- Maintain hot indexes incrementally; do not rebuild negentropy trees, dependency caches, or unblock state at session time.
- Batch where throughput matters, especially inbound admission, projection apply, outbox refill, and socket writes.
- Bound every unit of runtime work by records, bytes, or time.
- Keep compaction explicit and tunable so simulation can disable purge while production can merge or discard physical detail that is no longer semantically required.

# Components / Responsibility

**event_modules/** contains every protocol or domain behavior that can be expressed as events, projectors, commands, jobs, and projected tables. This includes content, identity, auth, connection, sync, and local-only behavior.

Suggested organization:

```
src/event_modules/
  content/
    message/
    reaction/
    file/
  identity/
    workspace/
    user/
    peer/
  auth/
    invite/
    key/
    removal/
  connection/
    connection/
    connection_secret/
    observed_address/
  sync/
    compare/
    have/
    need/
    negentropy_tree/
    dep_cache/
  local/
    local_secret/
    job_tick/
```

**Per-file pattern, always.** Every event module is a directory with one file per concern (`codec.rs`, `projector.rs`, `commands.rs`, `queries.rs`, `registry_meta.rs`, `mod.rs`, etc.) — even when a module is small enough that a single `.rs` file would suffice. The cost is some empty-ish files in tiny modules; the win is that this is intentional friction. In a codebase where most code is assistant-generated, uniform shape across the surface makes accumulating logic easy to spot — files that grow disproportionately, or directories that sprout extra concerns, are the audit signal that something needs simplification or splitting. No collapsed single-file event modules.

This rule is in conscious tension with "let complexity earn length" in the documentation quality bar (see appendix): that rule applies to *prose* in docs, this rule applies to *code structure* in event modules. Both stand.

**networking** All complex networking behavior including bootstrap, connection, and sync is also implemented in event modules: commands (run by jobs) initiate activity, projectors respond to activity, and transit encryption is unwrapped into contained events. Connections are between two endpoints (daemons) and sync all data in all workspaces those two endpoints share. Every workspace-scoped event carries its own `workspace_id`; endpoint-scoped events (connection, intro, observed_address, self_address, prekey events) carry endpoint identity instead. A daemon hosts at most one instance of any given workspace, so for workspace-scoped events `workspace_id` alone identifies the local processing scope and there is no separate "recorded_by". See **Event Scopes** below for the full taxonomy.

**event_pipeline** uses `event_modules` to process all Events (whether received or locally-created) such that an Event set, processed in any order, results in the same State at a given time (some event types can expire).

**control_loop** is the single-writer runtime substrate. It claims bounded batches of table rows, dispatches to the owning event module or job module, applies returned state writes atomically, and runs external effects.

**state** is the explicit table-shaped substrate that projectors and jobs observe. It is materialized from event-module table declarations and can be a database in production or an in-memory store in testing and simulation.

**network** is a TCP-only network interface that `connection`-related jobs and bootstrap jobs can use to send transmission-safe frames: endpoint-pubkey bootstrap wraps and connection-secret wraps carrying inner events.

**jobs** is a set of event-module commands that run at a regular cadence; each can query state to decide whether it runs and what other commands it calls.

The substrate pieces outside `event_modules` are deliberately narrow:

```
control_loop/   // dispatch, transactions, bounded batches, effect execution
state/          // catalog materialization, storage, migrations, snapshots
network/        // TCP bytes and socket ownership
sender/         // outbox -> connection wrap -> TCP write
```

If behavior is protocol semantics expressible as events/projectors/commands/tables, it belongs under `event_modules`. If it owns process execution, IO, storage mechanics, or scheduling, it belongs outside.

## State and Registry

State is the set of declared tables the control loop can read and update atomically:

```
State_t =
  events
  + module-owned projection tables
  + boundary/work tables
  + declared caches
```

Processing has the shape:

```
Event + Context(State_t) -> StateUpdates
State_{t+1} = apply(State_t, StateUpdates)
```

`state` does not centrally know the domain schema. Each event module declares its schema and behavior:

```
module id
event types
tables it owns
indexes
storage class: durable | memory | temp
migrations / schema version
projectors
commands / jobs
```

Those declarations form the runtime catalog:

```
event_modules/*/registry_meta.rs
  -> ModuleRegistry
  -> StateCatalog
  -> database / memory store schema
```

The event module owns semantic meaning: what a row means, which projection writes it, which indexes are required, and whether it may be rebuilt. `state` owns mechanics: creating tables, applying migrations, opening transactions, inserting NewRows, deleting Purges, querying declared indexes, resetting transient rows on startup, and choosing durable vs memory storage.

Boundary tables should follow the same rule where possible. `outbox` can be declared by the sender-facing module, `blocked_by_event` by the pipeline module, `job_schedules` by the jobs module, and sync caches by the sync modules. The fewer central special tables, the better.

## Event Pipeline

**codec** is canonical event encoding and parsing. It is not necessarily network wire. A module's `codec.rs` defines `Event <-> CanonicalEventBytes`, the event type tag, field layout, dependency field declarations, signature and signer-family rules, and deterministic id rules.

**encode** encodes an Event to `CanonicalEventBytes`, returning a BLAKE3 event id, usually used by `create` or other domain-specific functions.

**parse** consumes `CanonicalEventBytes` and returns an Event, which includes all event values, its BLAKE3 hash id, its canonical bytes, and the `workspace_id` it belongs to, or throws an error if the bytes are invalid.

**canonical-event processing** hashes the canonical bytes, checks admission before loading context, parses only newly admitted events, and then runs context/project/apply as one chained step unless the event blocks.

Typed Rust event values are the in-process semantic representation. They should not carry canonical bytes as ordinary fields. Canonical bytes and ids are boundary artifacts:

```
Event type     = semantic fields
EncodedEvent   = event_id + event_type + CanonicalEventBytes
ParsedEvent<E> = E + EncodedEvent
```

For locally created events:

```
E
  -> encode(E)
  -> EncodedEvent
  -> insert/project/outbox
```

For inbound events:

```
CanonicalEventBytes
  -> event_id = BLAKE3(CanonicalEventBytes)
  -> admit_event_id(event_id)
  -> parse(CanonicalEventBytes)
  -> ParsedEvent<E>
  -> project
```

Traits are the module API; canonical bytes are event identity. Projectors that need the id or original bytes receive them through `ParsedEvent<E>`, not because every event struct embeds them. This prevents typed values and encoded bytes from silently diverging.

**admit_event_id** consumes an event id and returns known or newly claimed. Known includes applied, blocked, rejected, and in-flight events. Duplicates record observations, call `suppress_received(id)` (see: Sync), and stop before context loading. Newly claimed ids become canonical event ids only after parse succeeds.

**get_context** consumes a newly admitted Event and returns an EventWithContext. Context for `project` is just the event's declared dependencies, its labels, and network metadata (e.g. origin ip / port) — never bespoke per-event-type SQL queries against arbitrary state. A generically sufficient EventWithContext is: 1. the Event 2. the other Events that are the consumed Event's immediate dependencies 3. every `label` for that event. If a projector "needs more state," that state must arrive as a declared dependency or a label, not as an ad-hoc query. This contract is non-negotiable; see the Forking plan section for the rationale (it is the surface this fork is rejecting from poc-7).

**labels** is a table whose rows are tuples of (event_id, label_type); adding a label can be a result of projection. Labels become part of context so there should be a bounded number of labels for a given event_id. "This event blocks others" can be a label.

**blocking** is pipeline-owned. A blocked event remains an `events` row with `status = blocked`; each missing dependency is a `blocked_by_event(blocked_by_event_id, event_id)` row.

**project** consumes an EventWithContext and returns either RejectedEvent (if known invalid), BlockedEvent, or StateUpdates.

**apply** consumes StateUpdates, applies them to State, and returns an AppliedEvent. There must be no writes (or at least no *context-relevant* writes) between the `get_context` and `apply` steps.

**StateUpdates** is [Purges, NewRows] i.e. what to delete and what rows to write to State.

**Purges** is a list of event id's for `apply` to purge.

**NewRows** is a list of tuples (table, row) for adding new rows to sorted tables in State, e.g. in SQLite with INSERT OR IGNORE. All NewRows are indexed by (event_id, workspace_id) and adding a NewRow with the same index must be idempotent.

Semantic removal is expressed by durable facts or labels, not by the absence of old rows. Examples include `deleted:message_id`, `expired:event_id`, `removed:user_id`, `revoked:key_id`, and `superseded:invite_id`. A projector may remove visible projection rows immediately, but future correctness must come from the surviving fact, label, summary, or high-water mark.

`Purges` are physical compaction. In trace, simulation, and audit modes, time-based purge should be disabled so facts remain monotonic and replayable. In app/production mode, events and projection rows may be purged for deletion or TTL once no future projector needs their bytes or rows as the only evidence of what happened.

Invariant: purging may remove physical evidence, but it must not be the only representation of a semantic change. If future behavior depends on knowing that something was deleted, expired, revoked, removed, or superseded, some surviving row must say so after purge.

Queue-like work is represented as ordinary NewRows into module-owned tables. Boundary tables are used only at wait, dedupe, retry, schedule, and IO boundaries.

## Event Scopes

All events inserted into `events` have canonical bytes from a module `codec.rs`, even if they are never sent over the network. Canonical bytes provide the event id, dedupe key, replay form, dependency reference, and projector input.

```
durable event:
  workspace_id: yes
  codec: yes
  signed: yes
  may be sent to peers: yes

endpoint-scoped event:
  workspace_id: NO  (carries endpoint identity instead)
  codec: yes
  signed: yes
  may be sent to peers: yes
  examples: connection, connection_prekey, connection_prekey_shared, intro,
            observed_address, self_address

endpoint-local event:
  workspace_id: optional (e.g. negentropy/sync events name (connection_id, workspace_id))
  codec: yes
  signed: usually no
  may be sent to one endpoint/connection: yes

local-only event:
  workspace_id: usually yes
  codec: yes, if stored/projected/deduped
  signed: usually no
  may be sent to peers: no

work item:
  codec: no, unless promoted into events
```

Examples of work items that do not need codecs are timer-fired, socket-writable, CLI-command-entered, and internal-wakeup notifications. Once something is inserted into `events`, referenced by id, deduped, blocked, replayed, or projected like an event, it needs canonical bytes.

## Control Loop

The control loop is the only always-running runtime. It owns:

- the module registry,
- boundary-table storage,
- transaction boundaries,
- clock ticks,
- resource limits,
- effect runners for TCP and local IO.

All domain behavior lives above the control loop in event modules and job modules.

Queued work is typed:

```
WorkItem =
  InboundBytes
  ReadyEvent
  OutboxWake(connection_id)
  JobTick
```

Each queue item has exactly one owning module. The control loop calls one function:

```
step(work_item, context) -> StepResult
```

`StepResult` contains:

```
StateUpdates   // includes NewRows into ordinary tables and boundary tables
Effects
```

Normal inbound processing is a pure chain inside the `InboundBytes` step:

```
InboundBytes
  -> connection.unwrap / raw frame parse
  -> CanonicalEventBytes
  -> event_id = BLAKE3(CanonicalEventBytes)
  -> admit_event_id(event_id)
  -> parse(CanonicalEventBytes)
  -> get_context(Event)
  -> project(EventWithContext)
  -> apply(StateUpdates)
```

Admission happens before parse context. Known event ids stop at `admit_event_id`. Parse failures mark the inbound bytes invalid and release the event claim. Blocked events write `blocked_by_event` rows and stop.

Boundary tables that need claim/retry ownership are ordinary module-owned tables with status metadata:

```
id primary key
status
not_before_ms
attempts
last_error
created_at_ms
updated_at_ms
```

Core boundary tables:

```
inbound_bytes       // transport ingress, dedupe by wire_id
events              // canonical event bytes plus status; ready rows are claimable
blocked_by_event    // dependency wait edges, not a job queue
outbox              // connection_id + event_id, dedupe by unique pair
job_schedules       // time enters the system
```

`events` stores every canonical event byte string that can be projected, replayed, referenced by id, or sent:

```
events:
  event_id primary key
  canonical_event_bytes
  scope        // durable | local | endpoint_local
  status       // processing | ready | blocked | applied | rejected
  created_at_ms
  expires_at_ms
```

`blocked_by_event` stores dependency wait edges:

```
blocked_by_event:
  blocked_by_event_id  // missing dep
  event_id             // blocked event
  primary key(blocked_by_event_id, event_id)
  index(event_id, blocked_by_event_id)
```

When event `D` becomes applied, the same transaction deletes `blocked_by_event_id = D` rows and marks affected blocked events `ready` when `NOT EXISTS` any remaining blocker.

Unblocking never recursively processes dependents in the same call. `events.status = ready` is the unblocked-events queue; the control loop later claims a bounded batch of ready events.

`outbox` stores only event ids to send on a connection:

```
outbox:
  connection_id
  event_id
  queued_at_ms
  primary key(connection_id, event_id)
```

`outbox` is memory by default and has no per-row claim, lease, or retry status. Each active connection has exactly one send owner:

```
ConnectionSender:
  connection_id
  hot_queue: bounded deque<event_id>
  present: set<event_id>
```

`hot_queue` is bounded by estimated bytes, not only event count. When it drops below a low-water mark, the sender refills from pending `outbox` rows for that connection, skipping ids already in `present`. It batch-loads `events.canonical_event_bytes`, wraps with `connection.wrap_bootstrap` or `connection.wrap`, and writes complete frames to TCP. After a complete frame is accepted by the socket, it deletes the corresponding `outbox` rows and removes those ids from `present`. On send failure it removes ids from `present`, leaves `outbox` rows pending, and backs off. No database transaction is held while writing to the socket.

The control loop commits `StateUpdates` in one transaction, then runs `Effects`. Effects may write new rows but do not directly project events.

The first implementation has one process-wide control-loop writer. Failed claim/retry work remains in its table with status, attempts, and last_error until its owning module marks it pending, rejected, blocked, expired, or dead. Send failure is connection-level backoff: `outbox` rows stay present. On startup, transient statuses are reset: `events.processing -> ready` and `inbound_bytes.processing -> pending`. Memory `outbox` starts empty; sync and jobs recreate missing send work.

Modules may run pure helper transforms inline until they reach a queue, state, or effect boundary. Modules do not recursively drain queues and do not perform transport IO inline.

The control loop has no sync, bootstrap, auth, connection, dependency, or event-type policy. It only knows dispatch, bounded batches, transactions, time, limits, retries, and effects. Leases are a later extension for multiple workers or long-running claim ownership.

## Network

**transport** owns TCP byte I/O between endpoints (listener on the daemon's `endpoint_id`, socket cache, `[u32 length][bytes]` framing, addresses learned from invite/`observed_address`/incoming connections). `send(remote_endpoint_id, OutboundFrame)` is the only egress; inbound bytes land on the inbound-bytes buffer with origin (remote_endpoint_id, ip, port). *Invariant: transport produces and interprets no bytes; if you can call `send` you are holding an `OutboundFrame` minted by `connection.wrap_bootstrap` or `connection.wrap`.*

**connection** is an event module. A connection event references two endpoints and carries `shared_workspaces`. Each workspace entry's authority is established by the connection event's own dependencies and signature: deps point at the capability events (workspace-membership grant, invite, peer_shared, etc.) that authorize the signer to bind that workspace to that connection, and the pipeline's standard signature/dep validation is what makes the entry trustworthy. Rotation, revocation, and expiry are further connection-related events with their own deps/sigs. The same module owns `connection_secrets`: globally-unique `connection_secret_id` → `(key, direction, connection_id, ttl)`, with separate inbound and outbound secrets per connection, each known only to the two endpoints.

The connection module also owns the transit envelope as plain functions, not as an event type (mirroring poc-6's `crypto.wrap` / `crypto.unwrap_transit`):

- `connection.wrap_bootstrap(remote_endpoint_id, inner_events) -> OutboundFrame`: encrypts to the endpoint public key. Used for connection establishment and connection-secret repair.
- `connection.wrap(connection_id, inner_events) -> OutboundFrame`: looks up the outbound secret for the connection, asserts every inner event's `workspace_id ∈ shared_workspaces(connection_id)`, pads to a size bucket, encrypts. Used for ordinary sync/control/event traffic.
- `connection.unwrap(bytes) -> Vec<CanonicalEventBytes>`: a parse-stage transform run by the pipeline on every inbound frame. Unwraps either endpoint-pubkey bootstrap frames or connection-secret frames. Connection-secret frames recover `connection_id`, drop any inner event whose `workspace_id ∉ shared_workspaces(connection_id)`, and pass the surviving canonical event bytes into canonical-event processing.

Wrapped bytes are never canonical events. They have no event id, no dependencies, and no labels — they are an opaque transit form. Only inner canonical event bytes are ids in the event store.

*Invariants: `shared_workspaces` is authoritative because the connection event's deps + signature have already been validated by the standard pipeline — the connection does not authorize itself, its dependencies do; a valid unwrap under one of our inbound secrets is by construction proof that the sender is the remote endpoint of that connection; every wrap is bound to exactly one connection; wrap and unwrap both enforce workspace ↔ connection alignment.*

**Outbox.** No event module calls `transport.send` directly. A projector that wants to send something — e.g. `needid.project` responding to a request from connection C with the requested event E — writes `outbox(connection_id=C, event_id=E)`, and only after checking *at projection time* that C is the connection the inbound trigger arrived on and that E's workspace_id is in `shared_workspaces(C)`. One `ConnectionSender` per active connection keeps a bounded byte-sized hot queue full from that connection's `outbox` rows, calls `connection.wrap`, and hands complete `OutboundFrame`s to TCP. A slow peer fills only its own hot queue and pauses only its own refill; other connection senders continue. *Invariant: every ordinary byte on the wire is the product of two independent workspace-membership checks (projector outbox write + `connection.wrap`) plus a third symmetric check on the receiving side (`connection.unwrap`).*

# Forking plan

poc-9 forks poc-7 at commit `c6f142e9` ("Simplify projection context loading", 2026-03-28) — the commit immediately before `56a9bc21` adopts iroh.

What poc-9 keeps from poc-7 (era E4–E5 substrate):

- pure-functional projectors + two-stage deletion (`b8669d31`)
- event-module locality under `event_modules/` (`bd14af95`, `7ace636d`, `26ec8c6f`)
- FieldSpec wire layout (`04bce8fc`)
- `shared_event_index`, atomic hard purge, projection context query adapters
- `runtime/state/shared` Option-D layout (`d90d083b`)

What poc-9 throws out and replaces:

- iroh (not yet in tree at fork point — bespoke QUIC + holepunch/intro/nat/upnp code physically present as deletion target / reference)
- `runtime/sync_engine/` range-owned session machinery, multi-source partition scheduler, receive/suppression plumbing
- `runtime/peering/` shared-daemon-connection orchestration
- the heavy `verus-proofs/` real-proof tree (not landed at fork point)
- per-event-type custom context-query adapters (see below)

Connection model follows poc-6's `events/network/` (`connection`, `connection_ack`, `intro`, `negentropy`, `self_address`, `sync_window`, etc. as canonical events). This is a **deliberate reversal** of poc-7's stance — poc-6's `SIMPLIFICATION_FOR_RUST_POC.md` §2 explicitly said "Connection/sync state is protocol/runtime state, not canonical events." poc-9 rejects that rule in favor of putting sync/connection facts through the same event pipeline as everything else.

**Pipeline simplicity is non-negotiable.** Preserve the pipeline shape of this document — see `get_context` in the Event Pipeline section for the strict contract. poc-7's projection-context-query adapters (one custom `context_loader` per event module) are the surface this fork is rejecting. To restate concretely, in poc-9:

- dependencies come from schema metadata on flat fields (one mechanism for all event types),
- labels are a small generic table `(event_id, label_type)` populated by projectors as the only cross-event signal,
- `get_context(event)` returns `{event, deps, labels}` and nothing else,
- if a projector "needs more state," that state must arrive as a declared dependency or a label, not as an ad-hoc query.

Note: in poc-9, labels replace custom gates for deletes, user/peer removal, and bootstrap-anchor events. poc-7 handles these with bespoke projector logic that queries side tables (deletion tombstones, removal sets, `invite_bootstrap_trust` / `pending_invite_bootstrap_trust`). poc-9 uses one uniform pattern instead:

1. on the gating event (delete X, remove user U, supersede invite I, etc.), act on all *existing* matching events in one pass — purge their rows, drop their derived state, etc.,
2. write a single label of the appropriate type (e.g. `deleted:X`, `removed_by:U`, `superseded:I`) so the gate is reified as one durable label row,
3. for any *future* incoming event that would otherwise match, the projector reads the same `labels` set already in its context and rejects / blocks / no-ops.

No per-event-type gate query, no "two-stage deletion" projector branch, no bootstrap-trust side tables consulted out-of-band — one mechanism (labels) carries every "this thing has been retired / superseded / revoked" signal, and projectors see it through the same `{event, deps, labels}` context.

This keeps one control loop, one projector contract, one dependency mechanism, and one set of correctness invariants for everything in the system — including connections and sync.

## Event types brought over

We can in principle bring over every event module from poc-7 at `c6f142e9` (`src/event_modules/`), but starting minimal is better — each event type carried forward must be re-justified under the new context-and-labels rules and the new connection-as-event model. The plan is two waves.

**Wave 1 (minimal — auth + messages, brought over from poc-7):**

- `workspace` — workspace identity / metadata root
- `user` — user identity bound to a workspace
- `peer_secret` / `peer_shared` — per-device identity (the new "endpoint identity" lives in connection events; `peer_*` stays the workspace-scoped device principal)
- `user_invite_shared` / `peer_invite_shared` — invite events for joining a workspace and linking a device
- `invite_secret` — invite local secret (issuer side)
- `invite_accepted` — accepted-workspace binding
- `key_secret` / `key_shared` — group-key material
- `encrypted` — encrypted-event wrapper
- `message` — chat message
- `reaction` — message reaction
- `message_deletion` — message delete (ported under the new label-based gate pattern; drop the two-stage-deletion branch and the deletion-tombstone side table)
- `removal` — user/peer removal (same: act on existing rows + write a `removed_by:U` label; future events check the label)

This is the smallest set that exercises all the hard cases: signed identity chains, dependency blocking, encrypted events, invites/joins, deletions, and removals — i.e. everything we need to validate the context-and-labels rules end-to-end.

**Wave 1 deferred from poc-7** (port later when the wave-1 surface is solid): `admin`, `key_request`, `key_rotation`, `tenant`, `bench_dep`, `file`, `file_slice`. `file` / `file_slice` are big enough to be their own milestone and aren't on the auth/messages critical path.

**Translation rules for any poc-7 module brought over:**

1. drop the per-module `context_loader` — declare deps as schema metadata on flat fields,
2. replace any side-table gate read (deletion tombstones, removal sets, `invite_bootstrap_trust`) with a label read on the in-context `labels` set,
3. drop any "two-stage" projector branch (e.g. message_deletion, removal) in favor of the act-on-existing + write-label + check-label pattern,
4. drop `recorded_by` in favor of the event's own `workspace_id`.

**Connection-related event types translated from poc-6:**

poc-6's `events/network/` originals: `connection_request`, `connection_prekey`, `connection_prekey_shared`, `connection_ack`, `intro`, `negentropy`, `observed_address`, `self_address`, `server_connection`, `sync_window`.

Translation note: in poc-6 these were workspace-scoped; in poc-9 connections are between two **endpoints** (daemons) and a single connection carries every workspace the two endpoints share. So:

- `connection` (new, replaces `connection_request` + `connection_ack`): two `endpoint_id`s, agreed `shared_workspaces` set signed at establishment, rotated by further `connection` events. No `workspace_id`.
- `connection_prekey` / `connection_prekey_shared`: keep the secret/shared split, but key material is per-endpoint-pair, not per-workspace.
- `intro`: keep as endpoint-pair introduction; carries no workspace identity.
- `observed_address` / `self_address`: keep as-is; both are endpoint-scoped already.
- `negentropy`: keep as the sync-compare event, but it must name `(connection_id, workspace_id)` because reconciliation is per-workspace within a shared connection.
- `sync_window`: keep as the per-workspace range/window selector; same `(connection_id, workspace_id)` scoping.
- `server_connection`: defer until we add cloud-relay / always-on server endpoints.

The transit envelope is *not* an event type in poc-9. It is `connection.wrap` / `connection.unwrap` — plain functions on the connection module, mirroring poc-6's `crypto.wrap` / `crypto.unwrap_transit`. The encrypted bytes are opaque transit form with no id, no deps, no labels; only the inner canonical event bytes are events. See the Network section above. Every connection-related event listed here travels *inside* a wrapped frame.

# Appendix: Negentropy, dependencies, and dedupe

## Plain negentropy

Negentropy is a recursive equality query over a sorted set of event ids.

For a range-tree node `v`, define:

```
R_v = locally present root events whose sync key is inside range(v)
F_v = Hset("root", R_v)
```

A sync compare event from connection `C` carries `(workspace_id, node, remote_fingerprint)`.

```
compare.project:
  if remote_fingerprint == F_v:
    emit nothing
  else if v is splittable:
    create endpoint-local compare events for each child and queue them in outbox
  else:
    create endpoint-local have-id events for the ids in R_v and queue them in outbox
```

There is no protocol session id required for correctness. Duplicate compares are harmless because the compare answer is a pure function of projected state. Jobs decide when to begin a root compare for a connection, and should avoid starting new compares while that connection has recent sync or bulk-transfer activity.

## Dep-aware negentropy

Dep-aware negentropy uses the same equality query, but the fingerprint for a root range also includes the present external dependencies required by those roots.

For every root event `r`, maintain a cached transitive dependency set:

```
D(r) = transitive event ids required by r
```

For each range-tree node `v`:

```
R_v = local root events inside range(v)
Q_v = union D(r) for r in R_v
X_v = Q_v \ R_v
P   = locally present event ids

F_v = Hset("root", R_v) + Hset("dep", X_v intersection P)
```

`X_v` is the invariant: it contains deps required by roots in `v` that are not already satisfied as roots inside `v`.

Projection maintains this incrementally. On inserting root `r` at leaf `L`:

```
add r to root membership on path L -> root

for each d in D(r):
  for v in path L -> root:
    if d is a root inside v:
      stop
    add requirement d to external deps for v
    if d is present locally:
      add d to present external dep hash for v
```

Use refcounts for `(node, dep_id)` and separate hash domains for roots and deps. A dep contributes to a node hash only when its refcount transitions `0 -> 1`, and is removed only when it transitions `1 -> 0`. This prevents duplicate dependency edges from double-counting or XOR-canceling.

When an event `d` becomes present, update the present-external-dep contribution for nodes that already require `d`. When `d` also becomes a root inside some node, it satisfies that dep for the node and all ancestors, so the external-dep contribution stops at the first satisfying node.

This is the same dep-aware comparison computed by poc-7's session code, but materialized as projected state instead of rebuilt as an on-demand session snapshot.

## Endpoint-local sync events and outbox

Sync protocol messages are endpoint-local events. They are not durable shared events and do not need signatures. The connection already authenticates the endpoint pair; the messages are only hints:

```
compare this node
I have these ids
I need these ids
send these event blobs
```

Projectors do not write to sockets. They create deterministic endpoint-local events and add their ids to `outbox`:

```
Have(id)    -> events(scope=endpoint_local), outbox(connection_id, event_id)
Need(id)    -> events(scope=endpoint_local), outbox(connection_id, event_id)
Send(id)    -> outbox(connection_id, durable_event_id)
Compare(v)  -> events(scope=endpoint_local), outbox(connection_id, event_id)
```

Duplicate projector output collapses because endpoint-local sync event bytes are deterministic and `outbox` is unique on `(connection_id, event_id)`.

Outgoing dedupe belongs at the `outbox` boundary and the per-connection hot queue, not in every projector's context. Projectors should not need `recently_sent` sets. If suppression beyond pending-buffer dedupe is needed later, keep sent rows in `outbox` with a TTL.

## Incoming buffer dedupe

Transport remains byte-only. On receive, the buffer hashes bytes before parsing:

```
wire_id = BLAKE3(bytes)

inbound_bytes:
  wire_id primary key
  bytes
  status

inbound_observations:
  wire_id
  connection_id
  remote_endpoint_id
  ip
  port
  first_seen_at
  last_seen_at
  seen_count
```

The incoming buffer is idempotent by `wire_id`. Source observations are tracked separately so address changes are diagnostics and dialing hints, not event semantics. Inner canonical event bytes unwrapped by `connection.unwrap` re-enter the same inbound processing path and dedupe again by their own canonical bytes.

Canonical-event processing only calls sync suppression after parse succeeds and the canonical event id is known. Invalid bytes may be deduped as bytes, but they are not event ids.

## Transit wrapping

Dedupe semantic work before transit wrapping.

```
outbox(connection_id, event_id)
  -> ConnectionSender.hot_queue
  -> batch-load events.canonical_event_bytes
  -> connection.wrap(connection_id, inner_events)
  -> TCP write
  -> delete sent outbox rows
```

Bootstrap and repair traffic uses `connection.wrap_bootstrap(remote_endpoint_id, inner_events)`. Ordinary sync/control/event traffic uses `connection.wrap(connection_id, inner_events)`.

If send fails, leave the `outbox` rows for retry and back off the connection sender. Dedupe remains `(connection_id, event_id)` based, not ciphertext based.

The receiver still validates inner events normally after decrypting. Network sync messages can cause work to be attempted, but they cannot make invalid durable events valid.

# Appendix: Documentation quality bar

Write this plan, implementation docs, and significant inline comments in the style of high-quality systems documentation: concrete, narrow, and audit-friendly. The model to emulate is Stellar Core's documentation:

- Overview and component map: https://github.com/stellar/stellar-core/blob/master/docs/readme.md
- Process and network architecture: https://github.com/stellar/stellar-core/blob/master/docs/architecture.md
- History system design and failure behavior: https://github.com/stellar/stellar-core/blob/master/docs/history.md
- BucketList mental model, formal model, examples, and cost analysis: https://github.com/stellar/stellar-core/blob/master/src/bucket/BucketListBase.h
- LedgerManager thread/data-flow diagram and invariant `LCL <= A <= Q <= H`: https://github.com/stellar/stellar-core/blob/master/src/ledger/LedgerManager.h
- OverlayManager responsibility and message taxonomy: https://github.com/stellar/stellar-core/blob/master/src/overlay/OverlayManager.h
- SCP/Herder separation between abstract protocol and application-specific driver: https://github.com/stellar/stellar-core/blob/master/src/scp/readme.md and https://github.com/stellar/stellar-core/blob/master/src/herder/readme.md

For every important component, document the same surface:

```
Purpose
Ownership / non-ownership
Interfaces
State
Invariants
Flow
Failure / restart behavior
Performance notes
Testing hooks
```

Style rules:

- Start with the component's responsibility, not implementation trivia.
- Say what the component does not own.
- Define vocabulary before relying on it.
- Prefer data flow and lifecycle descriptions over architecture slogans.
- State invariants explicitly, as small facts, formulas, or ordering rules.
- Explain a mechanism first with the simplest mental model, then with the precise rule.
- Use examples when a mechanism is subtle enough that the rule alone is easy to misread.
- Include operational consequences: crash, restart, retry, slow peer, invalid input, and overload behavior.
- Treat performance constraints as part of the design.
- Link prose to concrete files, functions, tables, events, or interfaces.
- Use inline comments only for non-obvious ownership, ordering, threading, safety, or performance rules.
- Keep small components brief; let complexity earn length.

Code-structure lessons from Stellar Core:

- Source directories should mark semantic subsystem boundaries, as in Stellar's `scp`, `herder`, `overlay`, `ledger`, `bucket`, `history`, `work`, and `transactions` directories. Avoid generic dumping grounds.
- Large runtime components should have a small public interface and a concrete implementation, following Stellar's `OverlayManager` / `OverlayManagerImpl`, `HistoryManager` / `HistoryManagerImpl`, and `Application` / `ApplicationImpl` pattern.
- Abstract protocol machinery should be separated from application meaning. Stellar's `scp` is protocol-generic; `herder` maps slots and values onto ledgers and transaction sets. Here, negentropy is the generic comparison mechanism; sync event modules map it onto workspace roots, deps, have/need/send events, and outbox writes.
- Managers own lifecycle, scheduling, and resource wiring. Helpers own algorithms. Do not let managers accumulate domain policy.
- Long-running work should be represented explicitly, as Stellar does with `work/`, `catchup/*Work`, and `historywork/*Work`. Hidden background behavior should become a job, table row, or effect owner.
- Data structures should encode workload assumptions. Stellar's BucketList is shaped around temporal churn, incremental hashing, and catchup. Here, dep-aware negentropy should be a projected incremental tree/cache, not a session-time rebuild.
- Canonical encoding is a hard boundary. Stellar uses XDR for hashed, historical, and peer-message forms. Here, `codec.rs` produces canonical event bytes for ids, storage, projection, replay, and dedupe; connection wrapping is a separate transit layer.
- Prefer immutable snapshots and stable ids at concurrency boundaries.
- Keep the first concurrency model legible: one control-loop writer, one sender owner per connection, bounded work at explicit boundaries.
- Failure behavior should be local: a failed send backs off one connection; a duplicate event is admitted once; a memory outbox can be regenerated; invalid bytes stop before event semantics.
