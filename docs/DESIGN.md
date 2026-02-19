# Topo Protocol Design (Post-PLAN End State)

> **Status: Active** — Topo target protocol design describing the post-PLAN end state.

This document describes the target protocol and runtime shape after completing all phases in `PLAN.md`.
It is intentionally practical: one coherent model, one projection path, one dependency mechanism, and operational behavior that is easy to test with real QUIC daemons.

Terminology note:
`Topo` is the project and runtime name used throughout this repository.
`workspace` is the term for the logical peer set and shared protocol context; "network" refers only to transport/networking concerns.

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
6. Policy-appropriate blocked rows after sync are normal, not failure.

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

Blocked-event normalcy rule:
1. blocked events are still canonical/shareable facts in the log,
2. some events are expected to remain blocked for a tenant (for example encrypted content or key-share events where that tenant is not a recipient),
3. post-sync blocked presence must be interpreted with policy context, not as automatic failure.

## 1.2 Event format

Events are flat and schema-defined.

Rules:
1. no universal `deps` field,
2. no universal `payload` envelope,
3. any schema field marked as `event_id` reference is a dependency source.

Field kinds are schema-driven (`fixed_bytes`, integers), and each event type has deterministic field order and fixed total wire size.
No canonical event field uses a length prefix to determine body boundaries.
Text slots use fixed-size UTF-8 with mandatory zero-padding: unused bytes after the canonical text content must be zero, and no non-zero bytes may appear after the text terminator.
Encrypted event wire size is deterministic by `inner_type_code` (inner types are fixed-size).
File slice events use a canonical fixed ciphertext size; final plaintext chunks are padded before encryption.

## 1.3 Event identity and signatures

1. canonical event bytes are content-addressed (`event_id` from canonical bytes),
2. signed events carry canonical signer fields:
   - `signed_by` (event-id reference),
   - `signer_type` (`workspace | user_invite | device_invite | user | peer_shared`),
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
3. all canonical event types have fixed wire sizes; `payload_len` must exactly match the schema-defined size for the event type (or, for encrypted events, the size determined by `inner_type_code`).
4. any mismatch rejects the frame.

---

# 2. Transport and Session Identity

Transport identity is derived from event-layer peer identity:

1. **Transport identity** (mTLS scope): cert/key material, SPKI fingerprints, `peer_id` derived from BLAKE2b-256 of X.509 SPKI. Managed by the `transport_identity` module.
2. **Event-graph identity** (identity layer scope): Ed25519 keys, signer chains, trust anchors, and identity events (types 8-22). Managed by the `projection/identity` module.

Transport certs are deterministically derived from PeerShared Ed25519 signing keys, so the two identity scopes are unified. `TransportKey` events (type 23) are retained for backward-compatible event parsing but are **not** authoritative for trust decisions. All steady-state transport trust is derived from PeerShared Ed25519 public keys via `spki_fingerprint_from_ed25519_pubkey()`.

## 2.1 QUIC + mTLS

All peer transport uses QUIC with strict pinned mTLS.

Rules:
1. each daemon profile has persistent cert/private key material,
2. peer allow/deny policy is based on SQL trust state:
   - PeerShared-derived SPKIs (steady-state; SPKI computed directly from PeerShared public key),
   - `invite_bootstrap_trust` rows written when invite links are accepted (bootstrap),
   - `pending_invite_bootstrap_trust` rows written by inviters before invitee first dial,
3. no permissive verifier in production mode.

## 2.2 Transport identity binding

Transport peer identity is SPKI-derived:

1. `peer_id = hex(BLAKE2b-256(cert_SPKI))`,
2. SPKI is computed directly from PeerShared public key (deterministic cert derivation),
3. the `peer_transport_bindings` table records observed connections,
4. `invite_bootstrap_trust` stores accepted invite-link bootstrap tuples
   (`bootstrap_addr`, inviter SPKI) used before PeerShared-derived trust appears,
5. `pending_invite_bootstrap_trust` stores inviter-side expected invitee SPKI
   until PeerShared-derived trust consumes it,
6. accepted/pending bootstrap rows are time-bounded and auto-consumed when
   matching steady-state PeerShared-derived trust is present.

Runtime rule: handshake verification queries SQL trust state per connection
creation; projected peer keys are not treated as in-memory authority.
Conceptually:
`TrustedPeerSet = PeerShared_SPKIs ∪ invite_bootstrap_trust ∪ pending_invite_bootstrap_trust`.

## 2.3 Event-graph identity binding

Event-graph identity is event-defined:

1. identity state maintains signer chains from workspace root to peer,
2. identity state directly determines transport trust — transport certs are derived from PeerShared signing keys,
3. projected identity determines which peers are allowed to sync.

### Display names (POC placeholder)

Workspace, user, and device events carry a 64-byte cleartext name text slot. This is POC convenience for human-readable CLI output. In a production system (cf. poc-6), display names would be encrypted profile fields — only visible to peers holding the workspace content key — with fallback display (truncated ID) when the key is unavailable. The cleartext approach here avoids the complexity of encrypted profile infrastructure while enabling a usable demo.

Content events (Message, Reaction, MessageDeletion) declare `author_id` as a dependency field pointing to User events (type 14/15). The dependency system blocks projection until the referenced User event exists, and the projector verifies that the signer's peer_shared `user_event_id` matches the claimed `author_id`. This enables direct `messages.author_id = users.event_id` JOINs for display name resolution.

## 2.4 NAT traversal and hole punch

Direct peer-to-peer connectivity through NAT is a transport optimization, not a canonical protocol concern.

Principles:
1. Hole punch is opportunistic — relay sync through an intermediary peer is always the fallback.
2. Introduction data (endpoint observations, IntroOffers) is runtime protocol state, not canonical events.
3. The introducer role is a behavior of any peer that has active connections to multiple other peers — it is not a special node type.
4. Punch success depends on NAT behavior (EIM = endpoint-independent mapping). Symmetric/port-dependent NATs will not work with the current approach.

### Endpoint observations

When a peer accepts or establishes a QUIC connection, it records the remote peer's observed `(ip, port)` in the `peer_endpoint_observations` table with a TTL.
After a successful hole-punched connection, it also records the punched peer's observed endpoint so that peer can be introduced to others later.

Rules:
1. Observations are append-only with `INSERT OR IGNORE`.
2. Freshness is determined by `MAX(observed_at)` query, not in-place update.
3. Observations expire via `expires_at` and are periodically purged.
4. Observations are scoped by `recorded_by` (the observer) and `via_peer_id` (the observed peer).

### Introduction protocol

An introducer sends `IntroOffer` messages to two peers so they can attempt a direct connection:

1. The introducer looks up the freshest non-expired endpoint observation for each peer.
2. It sends each peer an `IntroOffer` containing the other peer's `(peer_id, ip, port, observed_at, expires_at, attempt_window_ms)`.
3. IntroOffers are sent on uni-directional QUIC streams (not bi-directional sync streams).
4. IntroOffers are 88 bytes fixed-size and contain a 16-byte random `intro_id` for deduplication.

Receiver validation:
1. Expired offers are dropped and recorded as `expired`.
2. Offers for untrusted peers (not in `AllowedPeers`) are rejected.
3. Duplicate `intro_id` values are silently skipped.

### Hole punch dial protocol

After receiving a valid IntroOffer, the peer attempts paced QUIC connections to the introduced peer's observed address:

1. Dial attempts are paced at 200ms intervals within the `attempt_window_ms` (default 4s).
2. Each attempt uses `endpoint.connect()` on the same QUIC endpoint (sharing the UDP socket and local port).
3. On successful connection, the peer verifies the remote peer's identity matches the expected `other_peer_id`.
4. On identity match, a normal sync session runs on the punched connection.
5. The attempt lifecycle is recorded in `intro_attempts` with status transitions: `received → dialing → connected | failed | expired | rejected`.

NAT traversal relies on simultaneous open: both peers dial each other at roughly the same time, creating outgoing NAT mappings that allow the other's packets through.

### Explicit intro API

Introductions are explicit and one-shot:

1. An operator (or external job) calls `topo intro --peer-a <fpA> --peer-b <fpB>`.
2. The command looks up freshest non-expired endpoint observations for both peers.
3. It sends IntroOffers to both peers on the same QUIC endpoint socket.
4. The daemon does not run background peer-pair selection or automatic intro scheduling.

Selection logic ("who to intro, when to retry") is intentionally outside the core protocol for now.

### Testing

Test the feature with both local integration tests and Linux netns NAT simulation:

1. `cargo test --test holepunch_test`
2. `cargo test test_record_endpoint_observation`
3. `cargo build --release`
4. `sudo tests/netns_nat_test.sh --cone` (expected pass)
5. `sudo tests/netns_nat_test.sh --symmetric` (expected fail)
6. `sudo tests/netns_nat_test.sh --cleanup`

## 2.4.1 Identity bootstrap operations

High-level identity operations provide imperative APIs for workspace creation, invites, and device linking. These compose the low-level event creation primitives into correct sequences.

**Bootstrap** (`bootstrap_workspace`): creates the full 8-event chain for a new workspace owner:
Workspace → UserInviteBoot → InviteAccepted (trust anchor) → UserBoot → DeviceInviteFirst → PeerSharedFirst → AdminBoot.

**Invite** (`create_user_invite`): admin creates a UserInviteBoot event and returns portable invite data (event ID + signing key + workspace ID).

**Accept** (`accept_user_invite`): joiner consumes invite data and creates:
InviteAccepted (trust anchor) → UserBoot → DeviceInviteFirst → PeerSharedFirst.
Prerequisite: the joiner's DB must already contain the Workspace and UserInviteBoot events (copied from the inviter before or during sync).
The acceptance path also unwraps bootstrap content-key material received via `secret_shared` events (wrapped to the invite public key at creation time) and materializes local `secret_key` events so that encrypted content received during bootstrap sync can be decrypted.

**Device link** (`create_device_link_invite` / `accept_device_link`): similar to user invite but creates a shorter chain (PeerSharedFirst only, skipping user/device_invite creation).

All functions take `&Connection` and `recorded_by`, enabling multi-tenant operation where multiple identities share a single database.

## 2.5 Recording identity semantics

1. `signed_by`: canonical signer event reference used for signature/policy checks.
2. `signer_type`: signer keyspace discriminator (`workspace | user_invite | device_invite | user | peer_shared`).
3. `recorded_by`: local tenant transport peer identity that recorded/projected the event.
4. `via_peer_id`: authenticated remote transport peer for ingress metadata.

`recorded_by` is derived from authenticated local daemon/profile transport identity, not from event payload claims.

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

**Known limitation:** The `neg_items` table (negentropy reconciliation index) is global — not scoped by tenant. A remote peer connecting to the shared endpoint and routed as tenant A can see event IDs from all tenants during negentropy, including tenant B in a different workspace. This is acceptable because multi-tenant nodes are single-operator (one person with multiple workspace memberships on one device). The operator already has direct DB access, and the stronger deanonymization signal — multiple tenants sharing the same IP address and mDNS advertisements — exists at the network layer regardless. Real pseudonym isolation requires separate nodes on separate network paths.

## 3.2.1 Functional multitenancy: one node, N tenants

A single node process can host N tenant identities in one shared SQLite database, with one shared QUIC endpoint plus tenant-scoped workspace binding and trust policy.

The DB is the tenant registry. No explicit tenant registration step is required. The node discovers its tenants by joining two tables:

```sql
SELECT t.peer_id, t.workspace_id, c.cert_der, c.key_der
FROM trust_anchors t
JOIN local_transport_creds c ON t.peer_id = c.peer_id
```

`trust_anchors` is populated by `invite_accepted` (local-only, part of the identity bootstrap). `local_transport_creds` is populated during identity bootstrap (cert derived from PeerShared Ed25519 key). Any identity that has both a workspace binding and TLS material is a local tenant.

### Node daemon architecture

The node daemon (`run_node`) operates as follows:

1. Discover all local tenants from the DB.
2. Create a **single** QUIC endpoint with `WorkspaceCertResolver` for SNI-based cert selection across all tenants.
3. Create one shared `batch_writer` thread that all tenants feed into.
4. Run a single `accept_loop_with_ingest` with a union dynamic trust closure that checks across all tenants. Post-handshake, the peer's SPKI fingerprint is checked per-tenant to determine `recorded_by` routing.
5. Optionally: per-tenant mDNS advertisement and peer discovery.

### Single-port multi-tenant endpoint

All tenants on a device share a single UDP port. The server uses `WorkspaceCertResolver` to select the correct TLS cert based on the client's SNI hostname (`workspace_sni()` maps workspace_id to a DNS-safe hex label). Outbound connections use `workspace_client_config()` for per-workspace cert presentation.

### Per-tenant dynamic trust

The single QUIC endpoint uses a union trust closure that accepts connections trusted by **any** local tenant. Post-handshake, `resolve_tenant_for_peer` checks `is_peer_allowed` for each tenant to determine routing. The trust closure queries three trust sources for each tenant's `recorded_by`:
- **PeerShared-derived SPKIs** (primary steady-state; SPKI computed directly from PeerShared public key),
- `invite_bootstrap_trust` rows (accepted invite-link bootstrap, TTL-bounded),
- `pending_invite_bootstrap_trust` rows (inviter-side pre-handshake, TTL-bounded).

Trust checks are **tenant-scoped** (`recorded_by`-partitioned). Value-level trust-set overlap is allowed (the same SPKI may appear in multiple tenants' trust rows), and the union closure permits the shared endpoint to accept connections for any local tenant. (`trust_anchors` is used only for tenant discovery at startup, not for per-connection verification.)

### Removal-driven session teardown

When a `PeerRemoved` event is projected, the removed peer's SPKI is excluded from trust lookups (via `NOT EXISTS (removed_entities)` in `peer_shared_spki_fingerprints`). When a `UserRemoved` event is projected, all peers linked to that user via `peers_shared.user_event_id` are transitively denied. Additionally:
- New TLS handshakes are denied: `is_peer_allowed` returns false for removed peers and for peers whose owning user has been removed.
- Active sessions are torn down: between sync sessions, both `accept_loop` and `connect_loop` check `is_peer_removed` for the connected peer's SPKI. If the peer has been directly removed or its user has been removed, the QUIC connection is closed with error code 2 ("peer removed").

### Shared batch writer with tenant routing

All tenants share a single `batch_writer` thread to avoid SQLite write contention. Each ingested event carries a `recorded_by` field (the 3-tuple `IngestItem = (event_id, blob, recorded_by)`). The batch writer:

1. Inserts events into the shared `events` table.
2. Records each event in `recorded_events` under the correct `recorded_by`.
3. Enqueues into `project_queue` under the correct `recorded_by`.
4. Drains `project_queue` per tenant (grouping by `recorded_by`).

This eliminates write contention while preserving per-tenant projection isolation.

### TLS credential storage

Transport cert/key DER blobs live exclusively in the `local_transport_creds` SQLite table. No cert files exist on disk. Credentials are stored during identity bootstrap and loaded at endpoint creation time. This keeps all node state in one database file.

## 3.2.2 LAN peer discovery (mDNS/DNS-SD)

Multi-tenant nodes advertise each tenant on the local network under the `_topo._udp.local.` service type. Each tenant registers a separate mDNS service instance with its actual bound port and full `peer_id` in a TXT property.

Discovery rules:
1. **Self-filtering**: the browser receives the full set of local tenant peer IDs and filters them out, preventing unnecessary local connections.
2. **Trust gating**: discovered peers are only dialed if they pass the tenant's dynamic trust check.
3. **Address churn**: when a previously-discovered peer re-advertises at a different address, the old `connect_loop` is cancelled via a `watch` channel and a new one is spawned.

Out-of-scope note (current POC):
1. same-instance communication between two local tenants in the same workspace is not implemented as a special intra-daemon delivery path,
2. because self-filtering excludes local peer IDs, local tenants do not discover/connect to each other through mDNS,
3. adding explicit intra-instance delivery may be desirable future work, but it is out of scope for the current design baseline.

DNS label constraint: peer IDs (64 hex chars) are truncated to 59 chars in the mDNS instance name (62 total with `p7-` prefix, under the 63-byte DNS label limit). The full peer ID is always in the TXT property for exact matching.

Same-host daemon discovery: when two daemons run on the same machine bound to `127.0.0.1`, they advertise a routable (non-loopback) IP via mDNS because multicast DNS does not discover services advertised on loopback addresses. The browse side compensates with `normalize_discovered_addr_for_local_bind`, which rewrites discovered non-loopback addresses back to loopback when the local daemon is bound to loopback. The advertise IP is always provided explicitly by the caller (`run_node`); discovery internals perform no implicit address inference.

## 3.3 Table lifecycle and naming

1. schema creation runs through ordered migrations,
2. event modules register their projection table migrations,
3. startup performs migration + registry/schema consistency checks and fails fast on mismatch,
4. prototype schema epoch is explicit (`schema_epoch`) and enforced at startup,
5. legacy DB layouts from prior prototype epochs are intentionally rejected (no backward migration; recreate DB),
6. each event module declares explicit `event_type` and `projection_table`; no inferred naming heuristics.

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

Internal two-layer model: `project_one` is the sole public entrypoint.
Internally it delegates to `project_one_step` (the 7-step single-event
algorithm without cascade), then runs cascade-unblock if the result is
`Valid`. The Kahn cascade worklist calls `project_one_step` directly to
avoid redundant recursive cascade; Phase 2 guard retries call back into
`project_one` for proper recursive cascade. This split is a cascade
optimization, not an alternate projection path — all projection stages
(dep check, type check, signer verify, projector dispatch) are shared.

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

### Deletion cascade semantics

`message_deletion` is always an explicit special projector, not autowrite. Forcing deletion into generic autowrite logic is a known anti-pattern.

Convergence requirement:
1. deletion-before-target and target-before-deletion must produce identical final projected state,
2. this reordering invariance is the definition-of-done for deletion implementation,
3. deletion events must handle the case where the target event has not yet been projected (out-of-order arrival).

---

# 5. Dependency Blocking and Unblocking

## 5.1 Blocked dependency persistence

Blocked state uses two projection tables:

1. `blocked_event_deps(peer_id, event_id, blocker_event_id)`:
   - unique blocker edges per blocked event.
2. `blocked_events(peer_id, event_id, deps_remaining)`:
   - small header row with unresolved unique blocker count.

Rules:
1. missing deps are deduped before write,
2. blocker edges are persisted in `blocked_event_deps`,
3. `deps_remaining` is written from that deduped blocker set,
4. `blocked_event_deps` stays the canonical "currently blocked?" source for queue admission checks; `blocked_events` is a performance header for cascade scheduling.

We still do not require a full persisted dependency graph for baseline projection.
Dependencies are extracted per attempt from schema metadata.

## 5.2 Counter-based Kahn cascade unblock

Unblocking uses a counter-driven Kahn-style cascade:

1. when blocker `X` becomes valid, read candidates from `blocked_event_deps` by (`peer_id`, `blocker_event_id`),
2. decrement `blocked_events.deps_remaining` for each candidate,
3. when a candidate reaches zero remaining deps, delete its `blocked_events` header row and project it through the same canonical projection entrypoint,
4. if that candidate becomes valid, treat it as the next blocker and continue the cascade.

Implementation detail:
1. `blocked_event_deps` is read-only during per-step cascade work,
2. stale rows are bulk-cleaned only after cascade transitions occur (valid/rejected terminal rows),
3. guard retries run after this dep cleanup so guard queries see current state.

Design note:
1. a SQL-only cascade (`DELETE ... RETURNING` + zero-row checks) is simpler,
2. current branch measurements showed the counter path roughly 2x faster in the topo-cascade workload, so counter-based cascade is the default.

## 5.3 Event creation API

Three creation entry points exist:

1. `persist_and_enqueue(event_blob, peer_id) -> event_id`,
2. `create_event_sync(...) -> event_id`,
3. `create_events_batch(events, project_now) -> Vec<event_id>`.

`create_event_sync` uses the same internal path as workers and returns success only when terminal state is `valid` for the target `recorded_by`.
This preserves imperative orchestration ergonomics:

1. create event A synchronously,
2. create dependent event B in the next line with no ad-hoc waits.

## 5.4 Signer pipeline

Signer refs (`signed_by` + `signer_type`) are dependency metadata using the same blocking mechanism as other event references. Missing signer dependency writes blocker rows in `blocked_event_deps`, updates `blocked_events.deps_remaining`, and returns `Block`, identical to any other missing dep.

Ordering:
1. signer key is resolved only after all required deps (including the signer dep itself) are available,
2. signature verification runs after signer key resolution succeeds,
3. invalid signature → `Reject`, never `Block`.

One shared signer helper handles all signed event families. There is no identity-specific signer verification path; every signed event type uses the same resolve-by-(`signer_type`, `signed_by`) pipeline.

Schema-marked unsigned exemption:
1. deterministic emitted event types are schema-marked `signer_required=false`,
2. the pipeline skips signer dependency extraction and signature verification for those types,
3. validation uses deterministic-derivation checks from dependencies/context instead.

Tenant-scoped signer behavior: signer resolution and verification are scoped to the projecting tenant's `recorded_by`. Missing or invalid signer state in tenant A does not leak effects into tenant B.

---

# 6. Encrypted Events (Same Model, No Fork)

## 6.1 Wrapper integration

Encrypted wrapper is a normal event type in the same registry.
It uses flat fields such as `key_event_id`, mandatory `inner_type_code`, `ciphertext`, and auth metadata.

Wrapper field rule:
1. `inner_type_code` is mandatory (fixed-width).
2. ciphertext size is deterministic: derived from `inner_type_code` because all inner plaintext types have fixed wire sizes.
3. no `ciphertext_len` field exists in the canonical wire format; the parser computes expected ciphertext size from `inner_type_code`.
4. if we later adopt padded/opaque envelopes, this can be revisited deliberately.

## 6.2 Materialization adapter

Projection flow:

1. parse outer encrypted wrapper,
2. resolve outer deps (including key dependency),
3. if missing deps: block through normal dependency path (`blocked_event_deps` + `blocked_events`),
4. verify envelope signature/auth,
5. decrypt,
6. decode inner event using normal registry,
7. verify `inner_type_code` matches decoded inner event type (mismatch -> reject),
8. reject nested encrypted wrapper,
9. resolve inner deps via same schema dependency engine (presence check uses the same blocker tables and outer-event anchoring),
10. skip inner dep type-code enforcement for decrypted inners because inner deps may legitimately target encrypted wrapper events that carry admissible plaintext,
11. run normal inner signer + projector stages,
12. mark outer event valid only if inner projection succeeds.

Materialization is an adapter step, not a second projection system.

## 6.3 Plaintext policy

1. default: no persisted plaintext queue,
2. plaintext exists in memory during projection only,
3. optional short-lived cache can be added later for performance.

---

# 7. Durable Queue and Worker Model

## 7.1 Queue tables

Operational queues:

1. `project_queue(peer_id, event_id, available_at, attempts, lease_until)`,
2. `egress_queue(connection_id, frame_type, event_id, payload, attempts, lease_until, sent_at, dedupe_key)`.

Canonical tables and queue tables stay separate.

## 7.2 Workers

Current runtime ingest/worker shape:
1. sync ingest receiver path:
   - receive `SyncMessage::Event` blobs,
   - decode + canonical insert (`events`, `neg_items`, `recorded_events`) + `project_queue` enqueue in one transaction,
   - commit, then drain `project_queue`.
2. project worker/drain:
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

## 7.6 Multi-source download coordination

When a sink downloads from multiple sources concurrently, a coordinator thread
assigns events to peers using round-based greedy load balancing:

1. **Discovery**: each peer runs negentropy with its source, discovering need_ids
   (events the sink needs). Push (have_ids) proceeds immediately.
2. **Report**: after reconciliation, each peer sends its need_ids to the coordinator
   via a per-peer channel.
3. **Assignment**: the coordinator collects reports (short collection window after
   first report), builds an event-to-peer availability map, sorts by availability
   ascending (unique events first), and assigns each event to the least-loaded peer
   that has it.
4. **Transfer**: each peer receives its assigned subset and sends HaveList only for
   those events. Events flow into a shared batch_writer.
5. **Forget**: assignments are discarded after each round. Next round starts fresh.

Key properties:
- Events available from one peer are assigned to that peer (no choice).
- Events available from many peers are spread evenly across them.
- Slow peers' undelivered events re-appear as need_ids next round and get reassigned.
- Push path (egress streaming) continues during coordination wait.
- Per-peer channels prevent round-mixing between fast and slow peers.

### Implementation decisions

A naive negentropy implementation runs one session per peer pair: each session
has its own `batch_writer` thread for persistence, and after reconciliation it
sends HaveList for all need_ids and streams all have_ids directly. This works
for 1:1 sync but breaks down when a sink pulls from N sources concurrently:

1. N independent `batch_writer` threads all write to the same SQLite DB,
   causing WAL contention and lock timeouts.
2. Multiple sources discover the same need_ids. Without coordination each
   source sends the full set, wasting bandwidth proportional to overlap.
3. If one source is slow, its events are delayed until its session completes.
   No other source can pick up the slack.

The multi-source design addresses each of these:

**Shared batch_writer.** All concurrent sessions feed events into a single
shared `mpsc` channel consumed by one `batch_writer` thread. This eliminates
write contention entirely — only one thread ever holds the SQLite write lock.
Do not add an in-memory dedup set in front of the shared writer:
- Pre-writer dedup causes data loss if the writer transaction rolls back
  (event marked "seen" but never persisted; peer retransmissions silently dropped).
- The set grows without bound for long-running daemons (~90 bytes per EventId).
- `INSERT OR IGNORE` in `batch_writer` handles duplicates correctly and cheaply.

**Coordinator for pull, not push.** Each peer still pushes all have_ids
(events the remote needs from us) without coordination — the push path runs
at full speed. Only the pull path (need_ids — events we want) goes through
coordinator assignment. After reconciliation, each peer reports its discovered
need_ids to the coordinator thread, which assigns each event to the
least-loaded peer that has it. This eliminates redundant downloads of the same
event from multiple sources.

**Round-based reassignment.** Assignments are discarded after each round. If a
peer fails to deliver its assigned events (slow, disconnected), those events
re-appear as need_ids in the next negentropy round and get reassigned to a
different peer. No permanent affinity between events and peers.

**Short collection window (~20ms).** The coordinator waits briefly after the
first peer reports, then assigns. Stragglers report next round and get fresh
assignments. This prevents convoy effects where all peers run at the speed
of the slowest reconciliation.

**Thread-per-connection.** Each incoming connection spawns a `std::thread`
with a dedicated single-threaded tokio runtime. This isolates connection
failures, avoids `!Send` constraints from `rusqlite` leaking into the async
task graph, and allows each connection to share the `mpsc::Sender` to the
shared batch_writer.

**Incremental egress enqueue.** Have_ids from reconciliation are buffered and
drained incrementally per main loop iteration rather than enqueued in one burst.
This interleaves egress enqueue with event streaming so the data stream is not
starved while processing large reconciliation results.

**Negentropy snapshot ordering.** `BEGIN` must precede `rebuild_blocks()` so
the negentropy storage sees a consistent read snapshot of the events table.
Without this, concurrent writes from the batch_writer can produce an
inconsistent view during block rebuilding.

---

# 8. CLI and Daemon Contract

## 8.1 Operational shape

1. one daemon per profile/peer (`topo start`),
2. local RPC control socket,
3. unified CLI (`topo`) with subcommands that route through daemon when running, fall back to direct DB access otherwise.

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

Required invariants (TLC-checked):
1. `InvWorkspaceAnchor`: workspace validity requires a matching trust anchor,
2. `InvSingleWorkspace`: at most one workspace row per peer in the workspaces table,
3. `InvForeignWorkspaceExcluded`: a foreign workspace event can never become valid,
4. `InvTrustAnchorMatchesCarried`: trust anchor always matches the event-carried `workspace_id`.

Workspace binding proof: the invite determines which workspace a peer accepts; only that workspace can project. The guard mechanism checks that a workspace event's id matches the binding, structurally excluding foreign workspace events.

Invite-workspace binding: `invite_accepted` binds the trust anchor directly from its own `workspace_id` field using first-write-wins immutable semantics. No pre-projection capture authority.

Projector-spec mapping: each Rust projector predicate maps to a named TLA guard. The full mapping is maintained in `docs/tla/projector_spec.md`. Any divergence between projector logic and TLA guards is treated as a spec bug that must be resolved before adding new behavior.

## 9.2 Invite model

Use split event types:

1. `user_invite`,
2. `device_invite`,
3. `invite_accepted`.

No multimodal `invite(mode=...)` type.

Implementation uses shared invite helper logic with per-type policy tables.
Interactive CLI keeps real invite links (`quiet://invite/...`, `quiet://link/...`) in frontend state; session-local invite numbers are aliases to those links.

## 9.3 Trust-anchor cascade

`invite_accepted` records trust-anchor intent for `workspace_id` in tenant scope.

Required semantics:
1. workspace is not valid until trust anchor exists,
2. invites are not force-valid,
3. normal signer/dependency chain still governs validity,
4. accepted invite-link metadata writes bootstrap transport trust rows
   (`invite_bootstrap_trust`) keyed by local peer scope.

Self-invite bootstrap stays explicit:

1. create `workspace`,
2. create bootstrap `user_invite`,
3. locally accept invite (`invite_accepted`),
4. cascade unblocks `workspace -> user_invite -> user -> device_invite -> peer_shared`.

Guard placement rules:
1. trust-anchor guard applies to root workspace events only; foreign root ids must not become valid,
2. `invite_accepted` is a local trust-anchor binding event (no invite-presence dependency gate). In peer scope, it binds anchor from carried `workspace_id` with first-write-wins; a conflicting `workspace_id` for an already anchored peer is rejected,
3. new user/device/peer identities are still gated by normal signer/dependency validation in the same peer scope (for example `user_boot -> user_invite`, `peer_shared -> device_invite`),
4. bootstrap transport trust is persisted in SQL and queried at connection creation time; projected peer keys are not treated as in-memory-only authority.

## 9.4 Sender-subjective encryption baseline

For each encrypted message in the prototype baseline:

1. sender creates a fresh local key event,
2. sender emits one key-wrap event per currently eligible recipient peer pubkey,
3. encrypted content references key dependency via normal event refs.

After observing `user_removed` or `peer_removed`, sender excludes removed recipients from subsequent wraps.
No historical re-encryption or key history backfill is required in this baseline.

### 9.4.1 Bootstrap key distribution via invite-key wrap/unwrap

Bootstrap key acquisition uses the same `secret_shared` event type and wrap/unwrap logic as runtime sender-keys. The only difference is the recipient: at invite creation the inviter wraps content-key material to the invite public key (X25519-derived from the Ed25519 invite signing key), rather than to a peer's PeerShared public key.

Flow:
1. At invite creation, the inviter wraps current content key(s) to the invite key via `secret_shared` events (delivered during bootstrap sync, not embedded in the invite link payload).
2. At invite acceptance, the joiner unwraps using the invite private key (carried in the link) and the inviter's public key (from the `secret_shared` event's signer).
3. The joiner materializes local `secret_key` events with deterministic event IDs (BLAKE2b hash of key bytes → `created_at_ms`), ensuring both inviter and joiner derive identical `key_event_id` values.
4. Encrypted events that depend on those key IDs can then be projected normally through the standard block/unblock cascade.

This eliminates raw PSK bootstrap inputs; all key acquisition flows through the event-backed wrap/unwrap path.

## 9.5 Transport credential lifecycle model

This section covers the lifecycle state machine for the three trust sources: PeerShared-derived SPKIs (steady-state), `invite_bootstrap_trust`, and `pending_invite_bootstrap_trust`. The `transport_keys` table is populated by TransportKey event projection but is **not** consulted for trust decisions.

Supersession: when steady-state PeerShared-derived trust appears for a peer, matching `invite_bootstrap_trust` and `pending_invite_bootstrap_trust` entries are automatically consumed. Bootstrap and steady-state trust for the same peer never coexist.

TTL expiry: bootstrap trust rows are time-bounded. Unconsumed entries expire and are purged.

Removal cascade: `peer_removed` cascades trust removal across all three sources for the affected peer.

TLC-verified invariants (from `TransportCredentialLifecycle.tla`, mapped to Rust checks in `docs/tla/projector_spec.md`):
1. `InvActiveCredInHistory`,
2. `InvRevokedSubsetHistory`,
3. `InvActiveCredNotRevoked`,
4. `InvSPKIUniqueness`,
5. `InvActiveCredGloballyUnique`,
6. `InvBootstrapConsumedByPeerShared`,
7. `InvPendingConsumedByPeerShared`,
8. `InvTrustSetIsExactUnion`,
9. `InvTrustSourcesWellFormed`,
10. `InvRevokedNotInBootstrapTrust`,
11. `InvMutualAuthSymmetry`.

Abstract boundary: TLS handshake and session-key derivation remain unmodeled. The TLA spec covers trust-source state transitions but not the cryptographic session establishment that consumes them.

---

# 10. Convergence and Test Invariants

The system is accepted only if these invariants hold:

1. replay invariance:
   - replaying canonical events yields the same projected state.
2. replay idempotency:
   - replaying the same canonical set a second time (2x replay) yields no additional state changes.
3. reverse-order replay invariance:
   - replaying canonical events in reverse order yields the same projected state.
4. reproject invariance:
   - dropping projections and reprojection yields the same state.
5. reorder invariance:
   - out-of-order ingest converges to the same state.
6. source isomorphism:
   - `local_create`, `wire_receive`, and replay converge through the same `project_one` path.
7. tenant isolation:
   - no cross-tenant leakage under scoped queries.

Operational queue rows are excluded from end-state equality fingerprints.

Harness policy:
1. replay invariants (`once`, `twice`, `reverse-order`) are standard checks in the scenario harness.
2. they run after every scenario test that mutates canonical event store rows.
3. checks are computed from deterministic table-state fingerprints over event-store-derived state.

## 10.1 Application-level test assertions

Sync tests assert on application-meaningful data, never on raw event counts.

Why: the identity bootstrap chain produces a variable number of events (currently 7: Workspace, UserInviteBoot, InviteAccepted, UserBoot, DeviceInviteFirst, PeerSharedFirst, AdminBoot; plus content key events). This number has changed across development and may change again. Tests that hardcode `store_count() == 6 + N` break silently when the identity chain grows.

Rules:
1. **Convergence detection** uses `has_event(event_id)` on a specific known event, not `store_count >= N`.
2. **Assertions** use projection-level counts: `message_count()`, `reaction_count()`, `peer_shared_count()`, `user_count()`, etc.
3. **Never assert** on `store_count()`, `recorded_events_count()`, or `neg_items_count()` — these include identity overhead that varies.
4. **High-volume convergence** samples multiple events (50+) from both sides to avoid premature convergence (a single sample can pass after only partial transfer).
5. **Performance benchmarks** use the same pattern: sample event IDs from the sender, check arrival at the receiver via `has_event()`.

The `sync_until_converged` helper takes a closure for convergence detection:

```rust
sync_until_converged(&alice, &bob, || bob.has_event(&sample), timeout).await;
```

This makes tests resilient to identity chain structure changes while still verifying that the application-level data (messages, reactions, identities) converged correctly.

---

# 11. Performance and Operational Defaults

1. use SQLite WAL mode and prepared statements,
2. batch worker operations with measured sizing,
3. keep queue purge policies explicit and predictable,
4. monitor blocked counts, queue age, retries, lease churn,
5. provide `low_mem_ios` mode targeting `<= 24 MiB` steady-state RSS (iOS NSE),
6. in `low_mem_ios`, enforce strict in-flight bounds and prefer reduced throughput over memory spikes.

Initial event-size policy:

1. `EVENT_MAX_BLOB_BYTES = 1 MiB` soft cap,
2. `FILE_SLICE_TARGET_BYTES = 256 KiB`,
3. `FILE_SLICE_MAX_BYTES = 1_048_430` (`EVENT_MAX_BLOB_BYTES - 146 bytes wire overhead`).

`file_slice` events (type 25, signed) are signed and validated like other canonical events.
`message_attachment` events (type 24, signed) are file descriptors with deps on `message_id`, `key_event_id`, and `signed_by`.

### Low-memory trust and key strategy (`low_mem_ios`)

Trust and key sets use SQL indexed point lookups, not full in-memory loading. The projection tables (`trust_anchors`, identity chain tables, bootstrap trust tables) are queried on demand with indexed `(recorded_by, ...)` keys.

A bounded hot cache holds recently accessed keys to avoid redundant SQL round-trips during burst projection. The cache is size-limited and evicts LRU entries; it never grows unbounded.

Validation scale requirements: the low-memory path must remain stable at >= 1,000,000 canonical events on disk and >= 100,000 peer trust keys while staying within the 24 MiB steady-state RSS ceiling. Throughput may degrade to preserve the memory bound.

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

1. large payload events remain canonical typed events with fixed wire sizes,
2. file slices use a canonical fixed ciphertext size; final plaintext chunks are zero-padded before encryption,
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
