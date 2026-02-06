# Simplification Plan For Rust `poc-7`

## 1. Implementation Order (Authoritative)

This document is ordered exactly as we should build it.

1. `Phase -1`: CLI + daemon around the current simple prototype.
2. `Phase 0`: mTLS + QUIC transport baseline finalized.
3. `Phase 1`: Event schema, identity semantics, multitenant recording model.
4. `Phase 2`: Projector core and dependency blocking (without full queue complexity).
5. `Phase 3`: Encrypted events using the same dependency/projector model, tested first with per-instance PSK.
6. `Phase 4`: Durable queue architecture (`ingress`, `project`, `egress`) and workers.
7. `Phase 5`: Non-identity special-case projector logic (deletion/emitted-events).
8. `Phase 6`: Performance hardening, observability, and scaling passes.
9. `Phase 7`: TLA-first minimal identity layer for trust-anchor cascade, removal, and sender-subjective encryption.

---

## 2. Core Simplifications To Preserve

- Connection/sync state is protocol/runtime state, not canonical events.
- Canonical events are durable, replayable, and mostly projector-autowritable.
- Local-only events remain canonical events, selected by `event_type` policy.
- Event format stays flat. No universal `deps` field and no universal `payload` object.
- Any schema field that references `event_id` is a dependency source.
- Use one blocker mechanism for everything, including missing keys for encrypted events.
- No per-event transit wrapper. QUIC + mTLS secures the channel.
- Use separate tables for permanent canonical data vs operational queues.
- Use separate invite event types (`user_invite`, `device_invite`), not one multimodal invite with `mode=*`.

## 2.1 Locked design requirements (explicit)

These are required, not optional:

1. One projector entrypoint for all ingest paths.
   - `local_create`, `wire_receive`, `replay`, and unblock requeue all converge on the same `project_one(recorded_by, event_id)` path.
2. One dependency engine for all event types.
   - dependency refs come only from schema metadata on flat fields.
   - no per-type ad-hoc dependency checker.
3. Split invite types with shared implementation core.
   - keep separate event types (`user_invite`, `device_invite`) for model clarity.
   - implement with one shared invite projector helper/spec mapping.
4. One key-wrap event model across phases.
   - PSK bootstrap phase and identity sender-keys phase use the same key-wrap event/projector path.
   - only key source and wrapping algorithm differ.
5. DRY queue mechanics.
   - `project_queue` and `egress_queue` share generic claim/lease/retry/backoff helper code.
6. Isomorphism requirement.
   - once canonical event bytes are persisted, source differences disappear (`local_create == wire_receive == replay`) for projection logic.

---

## 3. Phase -1: CLI + Daemon First

Build this before queue complexity.

### Deliverables

- One daemon per profile/peer with local RPC control socket.
- Thin CLI (`p7ctl`) for non-interactive control.
- Stable JSON responses and exit codes.
- Assertion-first testing commands:
  - `assert-now <predicate>`
  - `assert-eventually <predicate> --timeout-ms <n> --interval-ms <n>`
  - optional `assert-stable <predicate> --for-ms <n>`

### Why first

- Locks in operational UX for human + agent workflows.
- Lets LLM self-play loops run through real commands instead of ad-hoc waits.
- Provides a stable harness before deeper internal refactors.

### Exit criteria

- Two daemons exchange chat events over QUIC.
- CLI can create/query/assert deterministically in scripts.
- Real-time feel is acceptable with current simple path.

---

## 4. Phase 0: mTLS + QUIC Baseline

### Deliverables

- Peer-authenticated QUIC sessions with certificate pinning/validation policy.
- Runtime protocol messages (sync/intros/holepunch negotiation) handled outside canonical events.

### Invariants

- No transit event wrapping layer in this model.
- Event-level signatures still enforce event authenticity/authorization.

### Exit criteria

- Reconnect/retry behavior is stable across daemon restarts.
- mTLS identity is plumbed into peer/session context.

---

## 5. Phase 1: Event Schema, Identity, and Multitenancy

## 5.1 Single-source event schema

Define event shape once and drive these from it:
- wire encode/decode
- signing bytes
- validation
- projector auto-row mapping metadata
- dependency extraction metadata (`is_event_ref`, `required`)

Field encoding kinds:
- `fixed_bytes(N)`
- `u8/u16/u32/u64`
- `var_bytes(len_prefix=u16|max_len=...)`
- `var_string(len_prefix=u16|max_len=..., utf8=true)`

## 5.2 Wire format direction

- Flat fields per type.
- Deterministic field order from schema.
- Fixed field definitions but variable total event sizes by type.
- Length-prefixed framing for sync transport.

This supports large events like `file_slice` while keeping deterministic signing/parsing.

## 5.3 Identity semantics (explicit)

- `author_peer_id`: canonical event author/signer.
- `recorded_by`: local tenant peer identity that recorded/projected the event.
- Both are `peer_id` typed values and intentionally separate.
- No `recorded_via` field.

## 5.4 Event classes

1. Canonical shared events: durable + shareable.
2. Canonical local-only events: durable + replayable, not shared.
3. Protocol/runtime messages: non-canonical, not in event DAG.

Shareability is by `event_type` policy, not by separate event tables.

## 5.5 Minimal durable data model

```sql
CREATE TABLE events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    blob BLOB NOT NULL,
    share_scope TEXT NOT NULL,         -- 'shared' | 'local' from event_type policy
    created_at INTEGER NOT NULL,
    inserted_at INTEGER NOT NULL
);

CREATE TABLE recorded_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id TEXT NOT NULL,             -- semantic: recorded_by
    event_id TEXT NOT NULL,
    recorded_at INTEGER NOT NULL,      -- local receive/create time for this tenant
    source TEXT NOT NULL,              -- local_create | quic_recv | import
    UNIQUE(peer_id, event_id)
);
CREATE INDEX idx_recorded_peer_order ON recorded_events(peer_id, id);
CREATE INDEX idx_recorded_peer_event ON recorded_events(peer_id, event_id);

CREATE TABLE valid_events (
    peer_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    PRIMARY KEY (peer_id, event_id)
);

CREATE TABLE rejected_events (
    peer_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    rejected_at INTEGER NOT NULL,
    PRIMARY KEY (peer_id, event_id)
);

CREATE TABLE peer_endpoint_observations (
    recorded_by TEXT NOT NULL,
    via_peer_id TEXT NOT NULL,
    origin_ip TEXT NOT NULL,
    origin_port INTEGER NOT NULL,
    first_seen_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    PRIMARY KEY (recorded_by, via_peer_id, origin_ip, origin_port)
);
CREATE INDEX idx_peer_endpoint_last_seen
    ON peer_endpoint_observations(recorded_by, via_peer_id, last_seen_at);
```

### Tenant-safety rule

- Subjective tables are keyed by tenant identity first (`peer_id`/`recorded_by`).
- Query/projection APIs should use a tenant-bound wrapper (`TenantDb { peer_id, tx }`) rather than raw DB handles.
- `recorded_events` is the per-event receive journal (`recorded_at` ~= local `received_at`).
- Endpoint/IP metadata is intentionally separate in `peer_endpoint_observations` for frequent TTL purge and intro hinting.

---

## 6. Phase 2: Projector Core Before Full Queues

Implement projection semantics before adding heavy queue machinery.

## 6.1 Projector contract

Keep projector core pure and worker orchestration imperative.
All code paths call the same projector entrypoint:
- `project_one(recorded_by, event_id) -> ProjectionDecision`

```rust
enum ProjectionDecision {
    Valid(ProjectorEffects),
    Block { missing: Vec<EventId> },
    Reject { reason: String },
}

struct ProjectorEffects {
    auto_row: Option<AutoRow>,
    extra_writes: Vec<WriteOp>,
    emit_events: Vec<NewEvent>,
    commands: Vec<Command>,
}
```

Entry-point requirement:
- `local_create`, `wire_receive`, `replay`, and unblock retries must all invoke `project_one`.
- no alternate projection code paths for specific ingestion sources.

### Default behavior

- Most event types use predicate + auto-write.
- Auto-write is typically `INSERT OR IGNORE` of flat event fields + metadata.

### Explicit exceptions

- `message_deletion` and deletion cascade rules.
- deterministic emitted-event patterns (for example key material derivations).
- identity-specific exceptions (`invite_accepted`, removal enforcement) are deferred to Phase 7.

## 6.2 Dependency handling (blocked-only first)

Start with only blocked-edge persistence.

```sql
CREATE TABLE blocked_event_deps (
    peer_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    blocker_event_id TEXT NOT NULL,
    PRIMARY KEY (peer_id, event_id, blocker_event_id)
);
CREATE INDEX idx_blocked_by_dep ON blocked_event_deps(peer_id, blocker_event_id);
```

Rules:
- Extract refs from schema-marked fields on each projection attempt.
- If required refs are present: continue projection.
- If any required refs are missing: write rows in `blocked_event_deps` and return `Block`.
- Do not persist full `event_dependencies` yet.
- Use one dependency resolver for all event families (content, identity, encrypted wrappers, invites).
- Dependency extraction is driven by event schema metadata only (`is_event_ref`, `required`, conditional requirement flags).

When full dependency table is justified later:
- reverse-edge analytics/debugging,
- heavy dependency introspection,
- or proven perf bottleneck from repeated lookups.

## 6.3 Set-based unblock (Kahn-compatible with multiple blockers)

- An event can have N blocker rows.
- It is runnable when no blocker rows remain.

Use set-based SQL when blocker `X` becomes valid:

```sql
DELETE FROM blocked_event_deps
WHERE peer_id = ? AND blocker_event_id = ?;

INSERT OR IGNORE INTO project_queue (peer_id, event_id, available_at)
SELECT DISTINCT c.peer_id, c.event_id, ?
FROM blocked_event_deps_candidates c
WHERE NOT EXISTS (
    SELECT 1
    FROM blocked_event_deps b
    WHERE b.peer_id = c.peer_id AND b.event_id = c.event_id
);
```

Set-based SQL means operating on sets of rows at once instead of per-event loops. It is helpful for unblock/requeue because one newly valid event can unblock many dependents.

## 6.4 Event creation API (simple and testable)

Use one primitive with two entry points:

- `persist_and_enqueue(event_blob, peer_id) -> event_id`
- `create_event_sync(...) -> event_id`
- `create_events_batch(events, project_now: bool) -> Vec<EventId>`

`create_event_sync` should inline projection until terminal (`valid`, `blocked`, or `rejected`) so command chains can immediately use prior event ids.

Imperative orchestration contract (poc-6 style ergonomics):
- default `create_event_sync` must return success only when the created event is `valid` for `recorded_by`.
- if terminal state is `blocked` or `rejected`, return an error containing `event_id` + terminal reason.
- this guarantees call-site sequencing:
  - `a = create_event_sync(...)`
  - `b = create_event_sync(depends_on=a, ...)`

Implementation note:
- even synchronous create uses the same internal pipeline:
  - `persist_and_enqueue` -> `project_one` loop (same code as worker mode)
- do not add a separate "local fast-path" projector.

## 6.5 Optional TLA checkpoint for blocking/unblocking (only if needed)

Usually not required at this stage, but useful if blocker behavior gets ambiguous:
- model only `valid`, `blocked_event_deps`, and unblock transitions,
- verify multi-blocker convergence and no-lost-unblock behavior,
- then map those guards directly into projector dependency checks.

---

## 7. Phase 3: Encrypted Events With The Same Model

Goal: encrypted events behave like normal events for dependencies and projection.

## 7.1 Registry integration

- Encrypted wrapper is a normal event type in the same event registry.
- It uses flat fields, for example: `key_event_id`, `ciphertext`, `nonce`, `auth_tag`, optional clear `inner_type_code`.
- No separate encryption registry.

## 7.2 Materialization model (definition)

"Materialization" means converting an encrypted wrapper into a transient normal event view:

1. parse and verify the encrypted wrapper envelope,
2. resolve/decrypt using dependency-provided key material,
3. decode plaintext into a typed flat `EventView` from the same registry,
4. pass that `EventView` into the normal projector path.

Important:
- materialization is an adapter step, not a second projection system.
- no persisted plaintext queue is required for baseline.
- after materialization, projection is isomorphic to cleartext event projection.

## 7.3 No nested encrypted events

Rule:
- If decrypted inner type resolves to encrypted wrapper type, `Reject(nested_encrypted_not_allowed)`.

## 7.4 Projection flow for encrypted wrapper

1. Parse outer encrypted event from canonical `events.blob`.
2. Extract outer deps from its flat event-ref fields (`key_event_id`, plus any other refs).
3. If outer deps missing: write `blocked_event_deps` and return `Block`.
4. Verify signature/auth over canonical encrypted bytes.
5. Decrypt ciphertext using key from `key_event_id`.
6. Decode inner event with normal registry.
7. If inner type is encrypted wrapper: reject.
8. Extract inner deps from inner schema metadata.
9. If inner deps missing: write `blocked_event_deps` using outer `event_id` and return `Block`.
10. Call the normal projector for the inner type.
11. Mark outer event `valid` only after inner projection succeeds.

## 7.5 Plaintext storage policy

- Default: no persisted plaintext queue.
- Decrypted plaintext exists in memory only for projection.
- Optional later optimization: short-lived decrypted cache with TTL.

This preserves one blocker model and one projector model.

## 7.6 Initial encrypted-event test strategy (PSK first)

Start encryption correctness with a deliberately crude harness before identity key wrapping:

1. Give each test daemon/instance a configured AES PSK (same PSK for happy-path suites; mismatched PSK for negative suites).
2. Materialize this as a local key event during test setup, and reference that key via normal `key_event_id` dependency fields.
3. Run encrypted projection through the exact same block/unblock flow as other events:
   - missing key event -> `Block`
   - key present + decrypt/auth failure -> `Reject`
   - key present + decrypt/auth success -> normal inner projector path
4. Keep all replay/reorder invariants enabled while on PSK mode.

This isolates queue/projection/dependency correctness from identity/envelope complexity.
- keep the same key-wrap event type + projector logic that will be used in Phase 7 identity sender-keys; only key source differs.

---

## 8. Phase 4: Durable Queues and Workers

Add full queue machinery after identity + projection + encryption semantics are stable.

## 8.1 Queue tables

```sql
CREATE TABLE ingress_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id TEXT NOT NULL,
    from_addr TEXT,
    received_at INTEGER NOT NULL,
    frame BLOB NOT NULL
);

CREATE TABLE project_queue (
    peer_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    available_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    lease_until INTEGER,
    PRIMARY KEY (peer_id, event_id)
);

CREATE TABLE egress_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id TEXT NOT NULL,
    frame_type TEXT NOT NULL,          -- event | neg_msg | have_list | ...
    event_id TEXT,
    payload BLOB,
    enqueued_at INTEGER NOT NULL,
    available_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    lease_until INTEGER,
    sent_at INTEGER,
    dedupe_key TEXT
);
CREATE UNIQUE INDEX idx_egress_pending_event
    ON egress_queue(connection_id, event_id)
    WHERE frame_type = 'event' AND sent_at IS NULL;
CREATE UNIQUE INDEX idx_egress_dedupe
    ON egress_queue(dedupe_key)
    WHERE dedupe_key IS NOT NULL AND sent_at IS NULL;
```

Keep canonical and queue data separate:
- permanent: `events`, `recorded_events`, projection outputs
- operational/transient: `ingress_queue`, `project_queue`, `blocked_event_deps`, `egress_queue`

## 8.2 Why not one generic jobs table

A single table sounds simple but mixes incompatible concerns:
- very different retention and purge policies,
- different dedupe keys and lease semantics,
- harder indexing and worse observability.

Separate queue tables stay simpler operationally.

## 8.3 Worker stages

1. `ingress worker`: QUIC frame -> canonical event insert -> record by tenant -> upsert endpoint observation -> enqueue project.
2. `project worker`: claim row -> project path (`valid`/`block`/`reject`) -> dequeue.
3. `egress worker`: dequeue by `connection_id` -> send frame -> mark `sent_at`/retry.
4. `cleanup worker`: purge stale ingress/sent egress rows, reclaim expired leases, TTL-purge old endpoint observations.

Queue DRY requirement:
- implement generic queue helper traits/functions once (`claim_batch`, `renew_lease`, `mark_done`, `mark_retry/backoff`).
- reuse them for both `project_queue` and `egress_queue` to avoid diverging retry/lease semantics.

## 8.4 Egress queue creation (matching working `poc-7` shape)

Create rows from:
1. Negentropy reconciliation producer (`have_ids` we can send).
2. Incoming `HaveList` request producer.
3. Local protocol producers for control frames.

For event transfer, queue `event_id` only and fetch canonical blob at send time.

## 8.5 Project queue dedupe + purge

- `project_queue` is transient, not history.
- Do not enqueue if already terminal or currently blocked.
- If duplicate enqueue races happen, worker should fast-drop after terminal check.
- On terminal decision (`valid`, `reject`, `block`), remove row from `project_queue` in the same transaction as state write.

Recommended enqueue guard:

```sql
INSERT OR IGNORE INTO project_queue (peer_id, event_id, available_at)
SELECT ?, ?, ?
WHERE NOT EXISTS (
    SELECT 1 FROM valid_events v
    WHERE v.peer_id = ? AND v.event_id = ?
)
AND NOT EXISTS (
    SELECT 1 FROM rejected_events r
    WHERE r.peer_id = ? AND r.event_id = ?
)
AND NOT EXISTS (
    SELECT 1 FROM blocked_event_deps b
    WHERE b.peer_id = ? AND b.event_id = ?
);
```

## 8.6 Role of `attempts`

`attempts` is retry bookkeeping, not business state.

Use it for:
- backoff scheduling (`available_at`),
- lease recovery after crashes/timeouts,
- dead-letter/alert threshold if needed.

If a queue is always synchronous at first, this can remain mostly zero until retry logic is enabled.

## 8.7 Atomicity boundaries

Must be atomic:
1. canonical event insert + recorded insert + project enqueue.
2. projection state transition (`valid`/`block`/`reject`) + project dequeue.
3. unblock updates + requeue.

Need not be atomic with projection:
- network send,
- cleanup/purge,
- metrics/logging.

## 8.8 Conflict policy (`INSERT OR IGNORE` vs upsert)

Use `INSERT OR IGNORE` for:
- immutable canonical events,
- idempotent projection materialization,
- queue dedupe insertions.

Use `ON CONFLICT DO UPDATE` for:
- mutable cursor/checkpoint state,
- lease/heartbeat/retry metadata,
- sync state snapshots,
- endpoint observation refresh (`last_seen_at`).

Avoid broad `INSERT OR REPLACE`.

---

## 9. Phase 5: Special Cases That Stay Explicit

These should not be forced into generic auto-write behavior.

1. `message_deletion` and cascade/tombstone semantics.
2. deterministic emitted-event flows where projection emits another event.

Deletion is special and should remain explicit.

---

## 10. Phase 6: Performance + Operational Hardening

Start simple, then tune.

- Prefer SQLite durable queues over a pure in-memory cascade pipeline.
- Tune batch sizes and indexes from measurements.
- Enable WAL and prepared statements.
- Keep queue purges explicit and predictable.
- Add invariants/metrics for blocked counts, retry growth, and queue age.

Recommended initial size policy:
- `EVENT_MAX_BLOB_BYTES = 1_048_576` (1 MiB soft cap)
- `FILE_SLICE_TARGET_BYTES = 262_144` (256 KiB)
- `FILE_SLICE_MAX_BYTES = 1_048_576` (1 MiB hard cap)

`file_slice` events can be much larger than legacy simulator limits and are signed/verified like other events.

---

## 11. Phase 7: Minimal Identity Layer + Crude Sender-Subjective Encryption

This is a final functional phase after the core projection/queue path is stable.

## 11.1 Phase gate: TLA+ causal model first

Before writing identity/removal/encryption projectors in Rust:
1. Build/update a TLA+ model of causal relationships and guards for this phase.
2. Model split invite types (`user_invite`, `device_invite`) and trust-anchor semantics.
3. Verify bootstrap/self-invite, join, device-link, and removal safety invariants.
4. Freeze a projector-spec mapping table: each projector predicate/check maps to a named TLA guard.

Projector implementations should mirror TLA conditions as directly as possible.

## 11.2 Minimal identity scope

Only include identity and policy needed for:
- trust-anchor bootstrap/join cascade
- self-invite bootstrap flow
- device linking
- removal enforcement
- recipient selection for encrypted message key wraps

## 11.3 Split invite event types (no mode switch)

Use separate types:
- `user_invite` (invites a user identity)
- `device_invite` (invites/links a peer device to a user)
- `invite_accepted` (records accepted link data + `network_id`)

Do not use one `invite` type with `mode=user|peer`.

Implementation requirement:
- keep one shared invite projector helper with per-type policy tables (signer/dependency checks).
- this keeps logical separation for TLA/model checking while avoiding duplicated Rust control flow.

## 11.4 Trust-anchor cascade requirements (from `poc-6`/TLA model)

Required behavior:
- `invite_accepted` records trust anchor intent for `network_id` (per `recorded_by` peer scope).
- `network` is not valid until corresponding trust anchor exists.
- invites are never force-valid; they validate only through signer/dependency chain.

Self-invite bootstrap sequence must stay explicit:
1. create `network` event (integrity self-sign only).
2. create bootstrap `user_invite` signed by network authority.
3. accept invite locally -> `invite_accepted(network_id=...)`.
4. normal cascade unblocks: `network -> user_invite -> user -> device_invite -> peer_shared`.

## 11.5 Crude sender-keys model (phase-1 style, no key history yet)

Use the sender-subjective O(n) baseline from `docs/group-encryption-design-aspects.md`
("Maximally simple.../Phase 1: baseline correctness and healing with O(n) key broadcast"):
- sender creates a fresh local-only `secret` key event per message,
- sender emits one `secret_shared`-style key-wrap event per perceived eligible recipient peer pubkey,
- encrypted content event references the key event id through normal dependency fields,
- each sender wraps to all perceived eligible members for each message (intentionally crude).
- use the same key-wrap event type/projector path introduced in Phase 3 PSK mode.

Not in scope yet:
- key history availability/backfill guarantees,
- optimized tree cover (TreeKEM update paths),
- advanced healing policies.

## 11.6 Minimal removal rule in this phase

- `user_removed` / `peer_removed` projection updates eligibility state.
- from first message after observing removal, sender must exclude removed peers from key wraps.
- no historical re-encryption; only forward behavior is required in this phase.

## 11.7 TLA-to-projector conformance rule

- Keep model alignment with `docs/tla/BootstrapGraph.tla` and `docs/tla/EventGraphSchema.tla`.
- Extend/adjust model events for split invites (`user_invite`, `device_invite`).
- For each identity-phase projector, include a referenced guard list in comments/docs.
- Treat divergence between projector logic and TLA guards as a spec bug that must be resolved before adding behavior.

---

## 12. Testing Plan (In Build Order)

## 12.1 CLI/daemon and agent loop tests

- CLI commands are deterministic and script-friendly.
- Prefer `assert-eventually` over ad-hoc sleeps/waits.
- `create_event_sync` chaining works for imperative orchestration:
  - event A created+projected synchronously,
  - event B created next line with dependency on A,
  - B succeeds without manual waits.

## 12.2 Encrypted-event bootstrap tests (PSK harness)

1. Happy path: all peers share PSK, encrypted events project end-to-end.
2. Missing key dep: encrypted event blocks until key event appears.
3. Wrong PSK/decrypt failure: event is rejected, not blocked.
4. Reorder: ciphertext before key events converges after unblock.
5. Replay/reproject: same final state from canonical events.

## 12.3 Projection correctness tests

- Valid/block/reject decisions per event type.
- Blocked-only dependency behavior with multiple blockers.
- Set-based unblock correctness.
- Encrypted wrapper flow, including nested-encryption rejection.
- Source-isomorphism checks: `local_create`, `wire_receive`, and `replay` converge through the same `project_one` semantics and yield identical projected state.

## 12.4 Replay/reproject/reorder invariants

1. Replay invariance: replay from canonical events yields same projected end state.
2. Reproject invariance: wipe projections and reproject yields same state.
3. Reorder invariance: out-of-order ingest converges to same state.
4. Operational queues are excluded from end-state equality checks.

Use deterministic table-state fingerprints for comparisons.

## 12.5 Multitenancy tests

1. Single-DB scoping checker test (like `poc-6`): ensure subjective queries are tenant-scoped.
2. Two-daemon integration test: separate peer identities record/project without overlap.
3. Cross-tenant leak tests: fail if rows from peer A appear in peer B scoped reads.

## 12.6 Identity and invite-cascade tests (final phase)

TLA-led acceptance:
1. Model invariants pass for split-invite causal graph before projector implementation is finalized.
2. Rust projector predicates map 1:1 to TLA guard conditions for identity/removal/encryption gate checks.

Behavior tests:
1. Self-invite bootstrap: trust anchor recorded, then normal cascade to first `peer_shared`.
2. User-join flow via `user_invite` keeps signer/dependency blocking semantics.
3. Device-link flow via `device_invite` keeps signer/dependency blocking semantics.
4. No force-valid invites: invite remains blocked until signer path is valid.
5. Removal enforcement: removed peers stop receiving new key wraps.
6. Sender-subjective baseline: each sent encrypted message yields wraps for all currently eligible recipients.

## 12.7 Real QUIC system tests

- 2-node bootstrap and sync.
- 3-node out-of-order convergence.
- reconnect/retry/backoff behavior.

---

## 13. What We Remove From `poc-6`

- Loopback/network simulator paths in production runtime.
- Connection/sync canonical event types.
- Ad-hoc bootstrap reprojection paths that bypass blocker logic.

Keep:
- local-only canonical events where replay matters,
- network-intro/holepunch related canonical events if needed,
- recorded-event model for replayability and tenant-scoped history.

---

## 14. Immediate MVP Cut

Fastest coherent milestone:

1. Finish Phase `-1`, `0`, `1`, and `2` with a small event set.
2. Add Phase `3` encrypted wrapper with PSK test harness for one core content path.
3. Add minimal Phase `4` queues.
4. Add deletion special-case behavior after baseline sync is stable.
5. Add final Phase `7` identity + invite cascade + sender-subjective key wraps.
