# Topo Protocol Design (Post-PLAN End State)

> **Status: Active** — Topo target protocol design describing the post-PLAN end state.

Topo is a draft protocol design for building full-featured local-first, peer-to-peer, end-to-end encrypted communication and collaboration tools.

This draft design focuses on the minimal necessary feature set to prove the protocol's suitability for building a viable secure replacement for Slack.

Terminology note:
`Topo` is the project and runtime name used throughout this repository.
`workspace` is the term for the logical peer set and shared protocol context; "network" refers only to transport/networking concerns.

## TODO (From design-doc-updates comment review)

These TODOs mirror the requested changes captured during design-doc review.
All listed items are resolved; this section is retained as an audit trail.

1. [x] Clarify whether "recorded" is event-sourced.
2. [x] Explain `signed_memo` purpose and usage.
3. [x] Explain why sync uses control + data streams.
7. [x] Explain SQL trust checks vs in-memory trust.
8. [x] Reconfirm boundary-enforcement abstraction.
9. [x] Reposition naming sections not transport-specific.
10. [x] Number Display names subsection.
11. [x] Number Author dependency subsection.
12. [x] Generalize freshness-by-query pattern.
16. [x] Add netns testing setup detail.
17. [x] Add note that pre-derive supports natural dependency sync during bootstrap.
18. [x] Resolve placeholder `??` comments by turning them into explicit clarification TODOs.
19. [x] Reduce implementation-specific detail in conceptual sections and use appendix references.
22. [x] Clarify known limitation wording around pseudonym isolation.
23. [x] Explain why certs matter in tenant discovery.
24. [x] Remove repetition in multitenant runtime narrative.
26. [x] Expand shared batch writer section with runtime narrative.
27. [x] Explain planner phase in plain terms.
28. [x] Replace "command derivation" with clearer phrase.
29. [x] Define "DER" once on first use.
31. [x] Mention supervisor in runtime loop sections.
32. [x] Clarify whether dial/accept loops are separate and coordinated.
33. [x] Reword "eventization boundary" toward "event-sourced authority boundary".
34. [x] Align schema lifecycle wording with epoch-only prototype policy.
36. [x] Add internal references for file-slice guard-block command.
37. [x] Explain why bootstrap trust writes are emitted commands rather than direct projector DB calls.
38. [x] Explain `WriteAcceptedBootstrapTrust` command role in same style.
39. [x] Explain `SupersedeBootstrapTrust` command role in same style.
40. [x] Clarify whether context fields include dependency snapshots.
41. [x] Add reference for "observations" concept.
42. [x] Refresh trust-anchor handling wording to current flow.
43. [x] Clarify "no full persisted dependency graph" statement.
44. [x] Clarify "dependencies extracted per attempt" statement with example.
45. [x] Add transaction/atomicity note around stale-row cleanup.
46. [x] Add measurement source for claimed counter-path speedup.
47. [x] Clarify `_sync` naming in create APIs after discussion.
48. [x] Rename "Materialization adapter" wording to projection terminology.
49. [x] Rewrite "Materialization is an adapter step" for clarity.
50. [x] Explicitly list canonically plaintext event families and scope.
51. [x] Add references for each egress producer category.
52. [x] Enumerate control protocol producers concretely.
53. [x] Define "terminal decision" in queue lifecycle text.
54. [x] Rephrase multi-source download section as default path.
55. [x] Add/link a negentropy implementation explanation section.
56. [x] Clarify unbounded-set discussion in relation to low-memory support.
57. [x] Validate/update collection window value.
58. [x] Define policy for language-specific vs implementation-specific notes in DESIGN.
59. [x] Add line that CLI/daemon shape is for operability/testing, not core protocol semantics.
60. [x] Define/document cadence for TLA conformance re-verification.
61. [x] Clarify "invite projectors" naming using concrete event names after approval.
62. [x] Recheck transport credential lifecycle section for latest identity changes.
63. [x] Add references for scenario/testing harness when invariants depend on it.
64. [x] Expand replay invariants list to include all listed checks.
65. [x] Add narrative walkthrough section after proposed format review.
66. [x] Reassess low-memory iOS claim precision and caveats after discussion.
67. [x] Reposition event-size policy with clearer section boundaries.
68. [x] Clarify fixed-size file-slice semantics vs final chunk padding.
69. [x] Verify whether bounded hot cache exists; remove inaccurate claim.
70. [x] Update "additional content event families" examples to reflect current implementation.
71. [x] Define "autowrite" where first used.
72. [x] Clarify when special projector logic is necessary.
73. [x] Reduce redundant file-spec statements with cross-references.
74. [x] Resolve missing `docs/group-encryption-design-aspects.md` reference.
75. [x] Clarify which history-availability policy pieces already exist in baseline.
76. [x] Replace awkward wording such as "Folderized events".
77. [x] Clarify "conn-level helpers" wording with concrete meaning.

### `??` Clarification TODOs

1. [x] Clarify the identity-prederive note in section 2.4.1 with a concrete bootstrap-dependency replay example.
3. [x] Clarify `neg_items` bootstrap-window leakage wording and define "pseudonym isolation" precisely for this POC.
4. [x] Replace the ambiguous "adapter step" wording in encrypted projection flow with concrete stage language.

## Requirements

1. **Encryption & Auth** - it should be straightforward to implement and validate modern, scalable, high-usability group encryption schemes with user removal (DCKGA, TreeKEM, etc.) from the ground up, so they can be tailored to product needs
1. **Deletion & Disappearing Messages** - deletion and disappearing messages should be straightforward (lots of p2p and local-first protocols make deletion hard 🤦)
1. **P2P Networking** - peer discovery, STUN-like connection across NATs, and TURN-like relay should be straightforward without additional dependencies, and adaptable to product needs
1. **Files** - multi-source file downloads (for images and attachments) should be performant (network-bound) and flexible
1. **Performance** - workspace state (messages, etc.) and files should sync quickly, up to 10GB of messages and attachments (we assume groups are using some global retention limit for security and that each workspace's data is bounded, or that users will resort to cloud hosting for long-term storage)
1. **Multi-tenancy** - It should be trivial to support many workspaces in the main client, join the same workspaces with multiple accounts in the same client, or host thousands of workspaces in a cloud node
1. **Cloud / Client Isomorphism** - Cloud nodes should not require a separate implementation.
1. **NSE / Client Isomorphism** - iOS background notification fetch (memory-constrained) should not require a separate implementation
1. **Local networking** - The protocol should be capable of zeroconf discovering and networking over LANs.
1. **Testing & Simulation** - It should be trivial to test interactions between multiple accounts on the same machine, with a toy interface that mimics the requirements of a production Slack Electron or React Native app, and to test robustness against concurrency and reordering. It should also be low-cost for an LLM to "self-QA" its work.
1. **Ergonomic Feature Development** - once complex features like auth, deletion, encryption, and forward secrecy are in place, it should be possible to build user-facing, Slack-like features (reactions, channels, threads, user profiles, etc.) with minimal friction
1. **Boring API for Frontends** - the backend should fully contain the complexity of the p2p stack and provide a boring API that keeps frontend development highly conventional (e.g., letting frontends fetch a paginated message list with attachments, reactions, usernames, and avatars should be easy)

Primary tools/stragies used:

1. **Event Sourcing** - Canonical events are durable facts. All canonical data is expressed as events, and state can be generated/restored deterministically by replaying events.
1. **Content Addressing** - All events are identified by the hash of the canonicalized event (the encrypted version if encrypted, the signed plaintext version if not)
1. **Explicit Semantic Dependency** - Rather than making events depend arbitrarily on prior events (like Automerge, OrbitDB) application developers decide what depencies are important for product needs and make them required event fields pointing to dependency event id's
1. **Dependency-agnostic Set Reconciliation** - We use a set reconciliation algorithm (Negentropy) that eventually and efficiently syncs all events we don't yet have, without using the dependency graph (as OrbitDB or Git would)
1. **Topological Sort** - Events block when dependencies are missing, and unblock with topological sort (Khan's algorithm).
1. **Keys Are Just Dependencies** - There are no special queues for events with missing signer or decryption keys: these are just declared dependencies (key material is stored in events with id's) and block/unblock accordingly.
1. **Projection** - Events are queued for validation and "projected" (materialized) into SQLite rows in atomic transactions
1. **Deterministic Query-time Winners** - Rather than applying destructive database updates that can create ordering problems, events updating a single state instead add rows using INSERT OR IGNORE; a single winner is determined at query time.
1. **Flat, Fixed-length Events** - To simplify secure parsing, all events and fields are fixed-length and canonicalized
1. **Ephemeral Protocol Messages** - Runtime protocol traffic (sync/intros/holepunch control) is not canonical event data.
1. **Conventional Networking Primitives** - All networking (including local networking) happens over QUIC with transport layer security provided by mTLS, but transport identity depends on the event-sourced auth layer for checking incoming and outgoing connections, and dropping connections.
1. **In-band Relay, Discovery, Intro** - Rather than using STUN/TURN libraries, mutually reachable (non-NAT) peers or cloud nodes can relay data through normal sync operation, and introduce NAT'ed peers by their observed addresses/ports
1. **QUIC Holepunching** - Once intro'ed by a mutually reachable peer, peers holepunch with simultaneous QUIC connections
1. **Convergence Testing** - Tests check that for all relevant scenarios, reverse reorderings of events, or duplicated event replays, yield the same state.
1. **Real Networking in Tests** - All multi-client tests are realistic as possible: real networking using CLI-controlled daemons with local peer discovery.
1. **Easy Synchronous Testing Workflows** - CLI workflows remain synchronous enough for imperative command chains (create workspace with user, invite user, join as user, etc.)
1. **Multitenancy** - Multiple user accounts/workspaces are first-class, with `recorded_by` scoping on shared tables (for example one message table, scoped to many local users). Canonical facts remain event-sourced in `events`; `recorded_events` is a local tenant ingest journal used to decide which canonical events replay for each tenant.

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
7. Freshness and winners are query-time decisions over append-only rows (for example `MAX(observed_at)`, first-write-wins trust anchors), not in-place mutable "current" rows.

---

## Documentation scope policy

1. Main sections describe protocol semantics and runtime invariants in language-agnostic terms.
2. Rust file/module paths are included only when they materially reduce ambiguity for implementers.
3. Dense implementation maps and file ownership details belong in appendices.
4. When both appear, conceptual text comes first and implementation references are cross-linked.

---

Note: the following section is written with coding agents in mind and emphasizes some aspects that might be obvious to a human reader, to avoid common agent mistakes. 

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
3. post-sync blocked presence must be interpreted with policy context, not as automatic failure; policy-appropriate blocked rows after sync can be normal operation.

## 1.2 Event format

Events are flat and schema-defined.

Rules:
1. no universal `deps` field,
2. no universal `payload` envelope,
3. any schema field marked as `event_id` reference is a dependency source.

More details:

1. Field kinds are schema-driven (`fixed_bytes`, integers), and each event type has deterministic field order and fixed total wire size.
2. No canonical event field uses a length prefix to determine body boundaries.
3. Text slots use fixed-size UTF-8 with mandatory zero-padding: unused bytes after the canonical text content must be zero, and no non-zero bytes may appear after the text terminator.
4. Encrypted event wire size is deterministic by `inner_type_code` (inner types are fixed-size).
5. File slice events use a canonical fixed ciphertext size; final plaintext chunks are padded before encryption.
6. `signed_memo` events (type 4) are currently placeholder canonical shared signed text events with a fixed 1024-byte text slot and normal signer-field verification. They project into `signed_memos` but are not part of core product flows and are candidates for removal in a later cleanup pass.
7. `bench_dep` events (type 26) are fixed-size shared benchmark events for dependency/cascade performance testing; they are non-encryptable and project no domain rows beyond validity state.

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

No per-event transit wrapper is used; transit encryption is handled by QUIC/mTLS.

## 1.4 Sync frame header (`payload_len`) rationale

Sync frames include a `payload_len` in the frame header.

Why:
1. QUIC streams are byte streams; receiver needs explicit frame boundaries.
2. Non-event frame types also exist (reconciliation/control), so delimiters are needed for mixed frame streams.
3. Length-delimited framing allows safe skip/reject behavior for unknown/future frame types.

Safety rule:
1. `payload_len` is an untrusted framing delimiter, not semantic authority.
2. enforce global and per-frame-type max lengths.
3. all canonical event types have fixed wire sizes; `payload_len` must exactly match the schema-defined size for the event type (or, for encrypted events, the size determined by `inner_type_code`).
4. any mismatch rejects the frame.

## 1.5 Dual-stream sync completion protocol

Sync sessions use one control stream and one data stream.

Why split streams:
1. keeps large event transfer (`Event` frames) from head-of-line blocking control semantics (`Done`, `DoneAck`),
2. makes completion semantics explicit (data completion vs control completion),
3. improves practical throughput and observability by separating reconciliation/control chatter from bulk payload flow.

Completion frames:
1. `Done` (control stream, initiator -> responder): initiator has finished producing outbound work for this round.
2. `DataDone` (data stream, either direction): sender has no more `Event` frames on the data stream.
3. `DoneAck` (control stream, responder -> initiator): responder confirms terminal completion.

Completion invariants:
1. responder sends `DoneAck` only after its egress is drained, it has sent its own `DataDone`, and it has observed peer `DataDone` on inbound data.
2. initiator treats the session as complete only after `DoneAck`.
3. this handshake gives explicit end-of-data semantics without relying on transport stream close timing.

---

# 2. Transport and Session Identity

Transport identity is derived from event-layer peer identity:

1. **Transport identity** (mTLS scope): cert/key material, SPKI fingerprints, `peer_id` derived from BLAKE2b-256 of X.509 SPKI. Managed by `transport/identity.rs`.
2. **Event-graph identity** (identity layer scope): Ed25519 keys, signer chains, trust anchors, and identity events (types 8-22). Managed by the `projection/identity` module.

Transport certs are deterministically derived from PeerShared Ed25519 signing keys, so the two identity scopes are unified. `TransportKey` events (type 23) are legacy, deprecated, and scheduled for removal; when present they remain parseable but are **not** authoritative for trust decisions. All steady-state transport trust is derived from PeerShared Ed25519 public keys via `spki_fingerprint_from_ed25519_pubkey()`.

## 2.1 QUIC + mTLS

All peer transport uses QUIC with strict pinned mTLS.

Rules:
1. each daemon profile has persistent cert/private key material,
2. peer allow/deny policy is based on SQL trust state:
   - PeerShared-derived SPKIs (steady-state; SPKI computed directly from PeerShared public key),
   - `invite_bootstrap_trust` rows produced by projection from `InviteAccepted` events + local `bootstrap_context`,
   - `pending_invite_bootstrap_trust` rows produced by projection from invite events (UserInviteBoot, DeviceInviteFirst) + local `bootstrap_context`,
   - trust rows are projection-owned state; the service layer writes `bootstrap_context` rows only, not trust rows directly,
3. no permissive verifier in production mode.

## 2.2 Transport identity binding

Transport peer identity is SPKI-derived:

1. `peer_id = hex(BLAKE2b-256(cert_SPKI))`,
2. SPKI is computed directly from PeerShared public key (deterministic cert derivation),
3. the `peer_transport_bindings` table is observation telemetry keyed by `(recorded_by, peer_id)`, where `recorded_by` is the local tenant key and `peer_id` is the remote transport fingerprint; `spki_fingerprint` stores the raw 32-byte SPKI for lookup/diagnostics,
4. `invite_bootstrap_trust` stores accepted invite-link bootstrap tuples
   (`bootstrap_addr`, inviter SPKI) used before PeerShared-derived trust appears,
5. `pending_invite_bootstrap_trust` stores inviter-side expected invitee SPKI
   until PeerShared-derived trust consumes it,
6. accepted/pending bootstrap rows are time-bounded and consumed at projection time
   (PeerShared projector emits `SupersedeBootstrapTrust`) when matching steady-state
   PeerShared-derived trust appears. Trust check reads are pure (no write side-effects).

Runtime rule: handshake verification queries SQL trust state per connection creation; projected peer keys are not treated as in-memory authority.

Why this is SQL-first:
1. restart-safe: no trust bootstrap gap after process restart,
2. low-memory friendly: avoids unbounded in-memory trust sets,
3. multi-tenant safe: one node can host many tenants with tenant-scoped indexed lookups.

Conceptually:
`TrustedPeerSet = PeerShared_SPKIs ∪ invite_bootstrap_trust ∪ pending_invite_bootstrap_trust`.

### Transport identity materialization boundary

Transport cert/key materialization is isolated behind a typed contract:

- **`TransportIdentityIntent`** (enum): describes *what* identity change is needed (`InstallBootstrapIdentityFromInviteKey` or `InstallPeerSharedIdentityFromSigner`).
- **`TransportIdentityAdapter`** (trait): executes the intent against the DB. The sole concrete implementation (`ConcreteTransportIdentityAdapter` in `src/runtime/transport/identity_adapter.rs`) is the **only** code that calls raw install functions (`install_invite_bootstrap_transport_identity`, `install_peer_key_transport_identity`).
- **Workspace command layer** (`accept_invite` / `accept_device_link`) installs invite-derived bootstrap identity via the adapter intent path (not raw transport calls).
- **Event modules** emit `ApplyTransportIdentityIntent` commands (e.g., `local_signer_secret` projector for PeerShared signers).
- **Projection pipeline** (`write_exec.rs`) routes intents through the adapter.
- **Downgrade guard**: bootstrap install is rejected once a PeerShared-derived identity has been installed (`BootstrapAfterPeerSharedDenied`), enforcing one-way transition.
- **Credential source tracking**: `local_transport_creds.source` records `random | bootstrap | peershared` for runtime guard checks and diagnostics.
- **Boundary enforcement**: layered controls enforce this boundary:
  1. typed intent contract (`TransportIdentityIntent`),
  2. single adapter implementation (`ConcreteTransportIdentityAdapter`),
  3. static import guard (`scripts/check_boundary_imports.sh`),
  4. contract tests (`tests/identity_transport_contract_tests/*`).

## 2.3 Event-graph identity binding

Identity is event-defined; transport identity must use event-layer identity as its source of truth:

1. identity state maintains signer chains from workspace root to peer,
2. identity state directly determines transport trust — transport certs are derived from PeerShared signing keys,
3. projected identity determines which peers are allowed to sync.
4. identity and signatures determine what events are valid (who can do what)

### 2.3.1 Display names (POC placeholder)

Encrypting workspace and event names is straightforward given group key agreement (see: poc-6), but it adds complexity and is out of the scope of this proof-of-concept design.

As a placeholder, workspace, user, and device events carry a 64-byte cleartext name text slot.

### 2.3.2 Author dependency

Content events (Message, Reaction, MessageDeletion) declare `author_id` as a dependency field pointing to User events (type 14/15). The dependency system blocks projection until the referenced User event exists, and the projector verifies that the signer's peer_shared `user_event_id` matches the claimed `author_id`. This enables direct `messages.author_id = users.event_id` JOINs for display name resolution.

## 2.4 NAT traversal and hole punch

Direct peer-to-peer connectivity through NAT is a transport optimization, not a canonical protocol concern.

Principles:
1. Hole punch is opportunistic — sync via normal-operation set reconciliation and an intermediary peer is always the fallback.
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
3. Duplicate `intro_id` values are silently skipped per `(recorded_by, intro_id)`.
4. `intro_attempts` rows currently have no TTL purge; dedupe horizon is DB-retention lifetime in this POC.

### Hole punch dial protocol

After receiving a valid IntroOffer, the peer attempts paced QUIC connections to the introduced peer's observed address:

1. Dial attempts are paced at 200ms intervals within the `attempt_window_ms` (default 4s). The 200ms pace is the current implementation default and can be promoted to a tuning knob if field data requires it.
2. Each attempt uses `endpoint.connect()` on the same QUIC endpoint (sharing the UDP socket and local port).
3. On successful connection, the peer verifies the remote peer's identity matches the expected `other_peer_id`.
4. On identity match, a normal sync session runs on the punched connection.
5. The attempt lifecycle is recorded in `intro_attempts` with status transitions: `received → dialing → connected | failed | expired | rejected`.

NAT traversal relies on simultaneous open: both peers dial each other at roughly the same time, creating outgoing NAT mappings that allow the other's packets through.

Timing uses local monotonic timers for pacing and local wall-clock checks for offer expiry. The protocol does not require GPS-grade or globally synchronized clocks; skew mainly affects whether a borderline-stale offer is attempted vs dropped.

### Explicit intro API

Introductions are explicit and one-shot:

1. An operator (or external job) calls `topo intro --peer-a <fpA> --peer-b <fpB>`.
2. The command looks up freshest non-expired endpoint observations for both peers.
3. It sends IntroOffers to both peers on the same QUIC endpoint socket.
4. The daemon does not run background peer-pair selection or automatic intro scheduling

Selection logic ("who to intro, when to retry") is intentionally out of scope for the proof-of-concept; application developers can tailor solutions to their needs.

### UPnP port mapping (operator-invoked)

UPnP/IGD mapping is an optional transport reachability aid, separate from canonical protocol state.

Rules:
1. mapping is invoked explicitly via `topo upnp` (daemon RPC `Upnp`) using the daemon's actual bound QUIC listen address.
2. result is a structured status report: `success | failed | not_attempted` with mapped external port/IP and optional gateway/error fields.
3. loopback-bound listeners produce `not_attempted`; routable mapping requires non-loopback bind (`0.0.0.0` or explicit LAN IP).
4. if mapping succeeds but the external IP is not publicly routable, runtime flags `double_nat = true` and warns.
5. UPnP outcome is informational runtime metadata (`NodeRuntimeNetInfo.upnp`) and does not modify trust/projection/signature semantics.

### Testing

Test the feature with both local integration tests and Linux netns NAT simulation:

1. `cargo test --test holepunch_test`
2. `cargo test test_record_endpoint_observation`
3. `cargo build --release`
4. `sudo tests/netns_nat_test.sh --cone` (expected pass)
5. `sudo tests/netns_nat_test.sh --symmetric` (expected fail)
6. `sudo tests/netns_nat_test.sh --cleanup`

Netns runbook notes:
1. The script creates five namespaces (`hp_i`, `hp_na`, `hp_nb`, `hp_a`, `hp_b`) and a public bridge.
2. `--cone` mode configures endpoint-independent mapping and should permit successful hole punch.
3. `--symmetric` mode configures randomized source-port NAT and should fail direct hole punch.
4. On success, temp logs are removed; on failure, logs are preserved under `/tmp/hp_nat_test.*` for diagnosis.
5. Always run `--cleanup` after interrupted runs to remove namespaces and bridge state.

## 2.4.1 Identity bootstrap operations

High-level identity operations are owned by event-module commands (`event_modules/workspace/commands.rs`). They compose low-level event creation primitives (from `event_modules/workspace/identity_ops.rs`) into correct sequences.

**Bootstrap** (`workspace::commands::create_workspace`): creates the identity chain for a new workspace owner:
Workspace → InviteAccepted (trust anchor) → UserInviteBoot → UserBoot → DeviceInviteFirst → PeerSharedFirst + LocalSignerSecret events (peer_shared, user, workspace) + content key seed.
The peer_shared LocalSignerSecret triggers `ApplyTransportIdentityIntent` on projection, installing a PeerShared-derived transport identity.

**Invite** (`workspace::commands::create_user_invite`): admin creates a UserInviteBoot event and returns portable invite data (event ID + signing key + workspace ID). Wraps content key for invitee if sender keys are available.

**Accept** (`workspace::commands::join_workspace_as_new_user`): joiner consumes invite data and creates:
InviteAccepted (trust anchor) → UserBoot → DeviceInviteFirst → PeerSharedFirst.
Prerequisite: the joiner's DB must already contain the Workspace and UserInviteBoot events (copied from the inviter before or during sync).
The acceptance path also unwraps bootstrap content-key material received via `secret_shared` events (wrapped to the invite public key at creation time) and materializes local `secret_key` events so that encrypted content received during bootstrap sync can be decrypted.
Signer secrets (LocalSignerSecret events) are NOT emitted here; `persist_join_signer_secrets` is called separately after push-back sync completes.

**Device link** (`workspace::commands::create_device_link_invite` / `add_device_to_workspace`): similar to user invite but creates a shorter chain (PeerSharedFirst only, skipping user/device_invite creation).

**Retry** (`workspace::commands::retry_pending_invite_content_key_unwraps`): retries content-key unwrap for invites where SecretShared prerequisites arrived late. Triggered via `event_modules::post_drain_hooks` from `state/pipeline/effects.rs` after each projection drain.

Identity pre-derive:

All three creation paths pre-derive `recorded_by` from the PeerShared key
(`derived_peer_id = hex(spki_fingerprint(pubkey))`) before writing any events,
so all events are written under the final peer_id from the start.

- **Workspace creation** (`create_workspace`): pre-derives PeerShared key,
  installs PeerShared-derived transport cert directly. No bootstrap sync needed.
- **Invite acceptance / device link** (`accept_invite`, `accept_device_link`):
  pre-derives PeerShared key for `recorded_by`, but installs an invite-derived
  bootstrap transport cert (needed for the initial QUIC handshake — the inviter
  expects the invite-derived SPKI). The PeerShared-derived transport identity
  replaces it later via projection cascade
  (`ApplyTransportIdentityIntent::InstallPeerSharedIdentityFromSigner`).
- **Connect loop**: identity is resolved once per QUIC connection (not per
  session). Identity transitions only happen during discrete CLI commands,
  never during active sync, so per-session re-lookup is unnecessary overhead.

Pre-derive implication:
1. because `recorded_by` is final before any event write, bootstrap does not need a special remap/finalize pass,
2. dependency blocking/unblocking behaves identically to steady-state sync,
3. replay naturally converges through normal dependency resolution for the same tenant key.

Concrete bootstrap-replay example:
1. joiner pre-derives final `recorded_by = P` from its `peer_shared` public key,
2. joiner writes `invite_accepted` and follow-on identity events under `P`,
3. if `workspace`/`user_invite` prerequisites arrive later via sync, those rows are also recorded under `P`,
4. blocked dependents unblock through the standard cascade under the same tenant key `P`,
5. no identity remap/finalize phase is required during replay.

### Identity ownership boundary

Conceptual ownership:
1. **Event commands own workflows** (workspace creation, invite creation/acceptance, device linking, retry paths).
2. **Crypto modules own cryptographic primitives** (`shared/crypto/*`, `projection/encrypted.rs` for wrap/unwrap, hash/sign/verify operations).
3. **Identity helpers own event-domain composition** (`event_modules/workspace/identity_ops.rs`: deterministic key-event materialization, invite helper assembly, bootstrap helper data shaping) and call crypto primitives rather than redefining them.
4. **Transport adapter owns cert/key/SPKI materialization** and is invoked via typed intents, not direct calls from event modules.
5. **Projection pipeline owns deterministic application order** (`write_ops` then `emit_commands`) and post-drain hooks.
6. **Service/RPC layer owns orchestration only** (routing, db open/close, error mapping), not identity policy logic.
7. **Boundary checks are automated** (import guard script + contract tests).

Concrete Rust file mapping is in Appendix A (implementation map).

All functions take `&Connection` and `recorded_by`, enabling multi-tenant operation where multiple identities share a single database.

## 2.5 Recording identity semantics

1. `signed_by`: canonical signer event reference used for signature/policy checks.
2. `signer_type`: signer keyspace discriminator (`workspace | user_invite | device_invite | user | peer_shared`).
3. `recorded_by`: local tenant scope key that recorded/projected the event; in the current implementation this key is the local transport peer fingerprint selected during bootstrap.
4. `via_peer_id`: authenticated remote transport peer for ingress metadata.

`recorded_by` is derived from authenticated local daemon/profile transport identity, not from event payload claims.
Legacy naming note: some tenant-scoped tables still use the column name `peer_id` for this same local scope key domain (for example `recorded_events.peer_id`). In this document, `recorded_by` is the canonical term.
Naming rule: `peer_id` means a transport identity fingerprint (local or remote by context). `event_id` means a canonical event hash; these domains are never interchangeable.

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
2. subjective rows include tenant scope using the same local tenant-key domain (column name is `recorded_by` in newer tables and legacy `peer_id` in older ones),
3. composite identity/index shape is tenant-first, typically `(peer_id, event_id)`,
4. query APIs are tenant-bound wrappers rather than raw unrestricted DB handles.

This preserves scoped reads/writes while keeping the schema ergonomic.

**Known limitation:** `neg_items` is one shared physical table. Negentropy reads are workspace-scoped (`workspace_id = ? OR workspace_id = ''`), so tenants do not enumerate other tenants' non-empty workspace buckets. Remaining leakage risk is limited to rows with empty `workspace_id` during bootstrap/pre-anchor windows. In this document, **pseudonym isolation** means preventing any cross-tenant metadata correlation at the node level; full pseudonym isolation still requires separate node instances on separate network paths.

## 3.2.1 Functional multitenancy: one node, N tenants

A single node process can host N tenant identities in one shared SQLite database, with one shared QUIC endpoint plus tenant-scoped workspace binding and trust policy.

The DB is the tenant registry. No explicit tenant registration step is required. The node discovers its tenants by joining two tables:

```sql
SELECT t.peer_id, t.workspace_id, c.cert_der, c.key_der
FROM trust_anchors t
JOIN local_transport_creds c ON t.peer_id = c.peer_id
``` 

`trust_anchors` is populated by `invite_accepted` (local-only, part of the identity bootstrap). `local_transport_creds` is populated during identity bootstrap: invite acceptance may install an invite-derived bootstrap cert first, then projection installs the PeerShared-derived cert.

Why certs are part of discovery:
1. event-layer identity establishes who the tenant is,
2. transport credentials establish that the tenant can actually terminate mTLS handshakes,
3. the daemon needs both to start accept/dial loops safely (identity without certs cannot serve transport; certs without anchor cannot map to workspace scope).

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

Trust checks are **tenant-scoped** (`recorded_by`-partitioned). Value-level trust-set overlap is allowed (the same SPKI may appear in multiple tenants' trust rows), and the union closure permits the shared endpoint to accept connections for any local tenant. `trust_anchors` is read during startup tenant discovery (to enumerate local tenant/workspace bindings), but per-connection authorization uses `is_peer_allowed` over PeerShared/bootstrap trust tables, not `trust_anchors`.

### Removal-driven session teardown

When a `PeerRemoved` event is projected, the removed peer's SPKI is excluded from trust lookups (via `NOT EXISTS (removed_entities)` in `peer_shared_spki_fingerprints`). When a `UserRemoved` event is projected, all peers linked to that user via `peers_shared.user_event_id` are transitively denied. Additionally:
- New TLS handshakes are denied: `is_peer_allowed` returns false for removed peers and for peers whose owning user has been removed.
- Active sessions are torn down: between sync sessions, both `accept_loop` and `connect_loop` check `is_peer_removed` for the connected peer's SPKI. If the peer has been directly removed or its user has been removed, the QUIC connection is closed with error code 2 ("peer removed").

### Shared batch writer with tenant routing

All tenants share a single `batch_writer` thread to avoid SQLite write contention.
Each ingested event carries `recorded_by` (`IngestItem = (event_id, blob, recorded_by)`), so one writer can safely persist mixed-tenant ingress without cross-tenant state confusion.

Per batch:
1. collect ingress tuples from concurrent sessions,
2. persist canonical rows once (`events`) and tenant receipt rows (`recorded_events`) in one transaction,
3. enqueue tenant-scoped projection work (`project_queue`),
4. commit,
5. run post-commit effects (queue drain, health logging, post-drain hooks).

The batch writer runs three explicit phases:

1. Persist phase (`state/pipeline/phases.rs`): inserts into `events`, `recorded_events`, and `neg_items`, and enqueues `project_queue` rows in one transaction.
2. Planner phase (`state/pipeline/planner.rs`): deterministically maps `PersistPhaseOutput` to a post-commit command list (for example drain tenant queues seen in the batch, log queue health, run post-drain hooks).
3. Effects phase (`state/pipeline/effects.rs`): executes side effects through the executor boundary (wanted removal, queue drain/projection, queue health logging, post-drain hooks).

Ownership statement: persist owns ingest SQL writes, planner owns deterministic command mapping, effects owns side-effect execution, and `batch_writer` in `state/pipeline/mod.rs` owns sequencing/retry policy.

This eliminates write contention while preserving per-tenant projection isolation.

### TLS credential storage

Transport cert/key **DER** (ASN.1 Distinguished Encoding Rules) blobs live exclusively in the `local_transport_creds` SQLite table (with `source` marker: `random | bootstrap | peershared`). No cert files exist on disk. Credentials are stored during identity bootstrap and loaded at endpoint creation time. Bootstrap identity install is one-way gated: after a PeerShared install, bootstrap install is denied. This keeps all node state in one database file.

## 3.2.2 LAN peer discovery (mDNS/DNS-SD)

Multi-tenant nodes advertise each tenant on the local network under the `_topo._udp.local.` service type. Each tenant registers a separate mDNS service instance with its actual bound port and full transport `peer_id` (SPKI-derived fingerprint) in a TXT property.

Discovery rules:
1. **Self-filtering**: the browser receives the full set of local tenant transport peer IDs and filters them out, preventing unnecessary local connections.
2. **Trust gating**: discovered peers are only dialed if they pass the tenant's dynamic trust check.
3. **Address churn**: when a previously-discovered peer re-advertises at a different address, the old `connect_loop` is cancelled via a `watch` channel and a new one is spawned.

mDNS authenticity model (POC):
1. mDNS advertisements are treated as unauthenticated discovery hints (address + claimed peer_id),
2. an attacker can spoof mDNS TXT records and cause extra dial attempts,
3. spoofed advertisements cannot bypass identity/auth: session acceptance still requires mTLS identity and tenant-scoped `is_peer_allowed` trust checks,
4. authoritative peer identity for the session is the TLS/SPKI-derived peer fingerprint observed at handshake, not the mDNS TXT claim.

Out-of-scope note (current POC):
1. same-instance communication between two local tenants in the same workspace is not implemented as a special intra-daemon delivery path,
2. because self-filtering excludes local peer IDs, local tenants do not discover/connect to each other through mDNS,
3. adding explicit intra-instance delivery may be desirable future work, but it is out of scope for the current design baseline.

DNS label constraint: peer IDs (64 hex chars) are truncated to 59 chars in the mDNS instance name (62 total with `p7-` prefix, under the 63-byte DNS label limit). The full peer ID is always in the TXT property for exact matching.

Same-host daemon discovery: when two daemons run on the same machine bound to `127.0.0.1`, they advertise a routable (non-loopback) IP via mDNS because multicast DNS does not discover services advertised on loopback addresses. The browse side compensates with `normalize_discovered_addr_for_local_bind`, which rewrites discovered non-loopback addresses back to loopback when the local daemon is bound to loopback. The advertise IP is always provided explicitly by the caller (`run_node`); discovery internals perform no implicit address inference.

## 3.2.3 Peering runtime loop model

The production peering runtime follows a single conceptual loop:

1. **Projected SQLite state**: invite_bootstrap_trust rows, PeerShared-derived trust, endpoint observations.
2. **Target planner** (`runtime::peering::target_planner`): single-owner module for all dial target planning. Collects bootstrap trust targets from SQL and mDNS discovery candidates. Routes both through `PeerDispatcher` for deduplication and reconnect management.
3. **Supervisor layer**: startup preflight + loop orchestration live in the peering supervisor.
4. **Dial/accept loops**: `connect_loop` (outbound) and `accept_loop` (inbound) are separate long-running loops coordinated by shared projected state and cancellation/watch channels. QUIC dial/accept + peer identity extraction flows through `transport::connection_lifecycle`, and stream wiring flows through `transport::session_factory`.
5. **Sync session runner** (`SyncSessionHandler`): protocol-agnostic session handler invoked via the `SessionHandler` contract.
6. **Ingest writer** (`batch_writer`): single shared thread consuming `IngestItem` tuples from all concurrent sessions.
7. **Projected SQLite state**: projection cascade updates trust rows, completing the loop.

### Module ownership

- **Target planning**: `src/runtime/peering/target_planner.rs` — the single source of truth for dial target decisions. Bootstrap autodial and mDNS discovery both route through this module.
- **Transport connection lifecycle**: `src/runtime/transport/connection_lifecycle.rs` — sole owner of QUIC `connect/accept` and TLS peer identity extraction for peering paths (`dial_peer`, `accept_peer`).
- **Transport session factory**: `src/runtime/transport/session_factory.rs` — sole owner of QUIC stream opening and `DualConnection` / `QuicTransportSessionIo` construction. Provides `open_session_io()` and `accept_session_io()` that return `(session_id, Box<dyn TransportSessionIo>)`.
- **Transport session I/O adapter**: `src/runtime/transport/transport_session_io.rs` — sole owner of frame boundary validation (`parse_frame` exact-consumption), max-frame-size enforcement, and mapping between QUIC stream errors and `TransportSessionIoError`.
- **Peering orchestration seam**: `src/runtime/peering/loops/mod.rs::run_session` — wires session metadata, peer-removal cancellation, and the session handler together. Receives pre-built `TransportSessionIo` from the transport session factory.
- **Bootstrap test helpers**: `src/testutil/bootstrap.rs` — test-only. Production runtime never depends on these; bootstrap progression is driven by the autodial loop polling projected SQL state.

### Event-sourced authority boundary (peering)

Durable trust/identity authority transitions are event-sourced (InviteAccepted, PeerShared, PeerRemoved). Transport runtime mechanics are not canonical facts: retry cadence, discovery timing, session lifecycle, and endpoint observations are ephemeral operational state managed by the peering runtime directly.

## 3.3 Table lifecycle and naming

1. schema creation runs through deterministic owner `ensure_schema` calls (no migration history playback in this POC),
2. no `schema_migrations` table or versioned migration runner is required in active startup/operation,
3. each owner module defines its own idempotent `ensure_schema(conn)` (event projection tables in `event_modules/*`, queue/infra tables in `state/db/*`),
4. central bootstrap calls owner `ensure_schema` in deterministic order,
5. prototype schema epoch is explicit (`schema_epoch`) and enforced at startup,
6. legacy DB layouts from prior prototype epochs are intentionally rejected (no backward migration; recreate DB),
7. each event module declares explicit `event_type` and `projection_table`; no inferred naming heuristics.

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
Internally it delegates to `project_one_step` (the 7-step single-event algorithm without cascade), then runs cascade-unblock if the result is `Valid`. The Kahn cascade worklist calls `project_one_step` directly to avoid redundant recursive cascade; Phase 2 guard retries call back into `project_one` for proper recursive cascade. This split isolates "single-event apply logic" from "cascade orchestration" for readability and testability while keeping one canonical ingest path. It is a cascade optimization, not an alternate projection path — all projection stages
(dep check, type check, signer verify, projector dispatch) are shared.

## 4.2 Pure functional projector contract

Projectors are **pure functions** over `(ParsedEvent, ContextSnapshot)` that return
a deterministic `ProjectorResult`. They do not execute SQL or any other side effects
directly. The apply engine executes the returned operations.

### ProjectorResult

```
ProjectorResult {
    decision: ProjectionDecision,  // Valid | Block | Reject | AlreadyProcessed
    write_ops: Vec<WriteOp>,       // deterministic state mutations
    emit_commands: Vec<EmitCommand> // follow-on actions for the command executor
}
```

- `write_ops` are only applied when `decision` is `Valid` (or `AlreadyProcessed` for
  idempotent intent writes).
- `emit_commands` are only executed when `decision` is `Valid`.

### WriteOp types

1. `InsertOrIgnore { table, columns, values }` — immutable, idempotent materialization.
2. `Delete { table, where_clause }` — explicit row removal (tombstone cascades).

### EmitCommand types

1. `RetryWorkspaceEvent { workspace_id }` — re-project the specific workspace event after trust anchor set by invite_accepted.
2. `RetryFileSliceGuards { file_id }` — re-project file_slice events after descriptor arrives.
3. `RecordFileSliceGuardBlock { file_id, event_id }` — record guard-block for pending file_slices; consumed by `RetryFileSliceGuards` after descriptor projection (see section 12.2 file attachment flow and section 5.2 cascade lifecycle).
4. `WritePendingBootstrapTrust { invite_event_id, workspace_id, expected_bootstrap_spki_fingerprint }` — materialize inviter-side pending trust from invite event + local bootstrap context. Emitted by UserInviteBoot and DeviceInviteFirst projectors.
5. `WriteAcceptedBootstrapTrust { invite_accepted_event_id, invite_event_id, workspace_id, bootstrap_addr, bootstrap_spki_fingerprint }` — materialize joiner-side accepted trust from InviteAccepted event + local bootstrap context. Emitted by InviteAccepted projector.
6. `SupersedeBootstrapTrust { peer_shared_public_key }` — supersede bootstrap trust rows whose SPKI matches a PeerShared-derived SPKI. Emitted by PeerShared projectors so trust check reads remain pure queries.

Why bootstrap trust uses emitted commands instead of direct projector SQL:
1. it preserves the pure projector contract (`event + context -> decision + write_ops + emit_commands`) and keeps trust-side effects in one executor path,
2. bootstrap trust writes are context-dependent local side effects (`bootstrap_context`, `is_local_create`), so emitting explicit commands makes this dependency visible and testable,
3. command execution centralizes idempotence and out-of-order handling (including bidirectional supersession when PeerShared and bootstrap rows arrive in either order),
4. trust-check functions (`is_peer_allowed`, `allowed_peers_from_db`) stay read-only, which keeps runtime behavior easier to reason about.

TODO (future simplification): attempt a projection-only bootstrap design where these trust rows can be expressed as plain `write_ops` (no bootstrap emit commands) while preserving purity, replay determinism, and out-of-order supersession correctness.

### ContextSnapshot

Read-model snapshot populated by the pipeline before calling the pure projector.
Projectors must not access the database directly. `ContextSnapshot` carries
query-derived read facts for projector predicates; it does not carry a generic
dependency list. Dependency IDs are extracted from parsed event fields via
schema metadata on each projection attempt.

Fields include:

- `trust_anchor_workspace_id` — trust anchor for this tenant
- `target_message_author` / `target_tombstone_author` — for deletion auth
- `deletion_intents` — pre-existing deletion intents (for delete-before-create convergence)
- `target_message_deleted` — for reaction skip-on-delete
- `recipient_removed` — for SecretShared removal exclusion
- `file_descriptors` / `existing_file_slice` — for FileSlice authorization
- `bootstrap_context` — local bootstrap context (addr + SPKI) for invite trust materialization
- `is_local_create` — whether the event was locally created (from `recorded_events.source`); gates `WritePendingBootstrapTrust` emission so only the invite creator materializes pending trust

Encrypted key resolution/decryption is handled in the encrypted-wrapper stage (`projection/encrypted.rs`), not via `ContextSnapshot`.

### Command/effect execution stage semantics

After `write_ops` are applied transactionally, `emit_commands` are executed in order
by explicit handlers in the pipeline. Commands may call `project_one` recursively
(e.g., to retry guard-blocked events), which is safe because each re-projection goes
through the same pure projector → apply engine path. Command identities are derived
from event identity for idempotence — re-running the command executor does not mutate
final state.

### Pipeline/projector split (DRY contract)

1. shared pipeline code handles:
   - event load/decode dispatch,
   - dependency extraction and blocking,
   - signer resolution and signature verification ordering,
   - building the `ContextSnapshot` from the database,
   - executing `write_ops` and `emit_commands`,
   - queue/state transitions and terminal status writes.
2. per-event projector code handles:
   - event-specific predicate/policy logic,
   - returning `ProjectorResult` with deterministic `write_ops` and `emit_commands`.
3. per-event projectors do not access the database, implement custom dependency resolution,
   signature pipeline, or queue/terminal-write paths.

### Default write policy

1. immutable and idempotent materialization uses `InsertOrIgnore`,
2. avoid `INSERT OR REPLACE`,
3. deletions are explicit `Delete` WriteOps (never hidden side effects).

Endpoint observation policy:
1. observations (runtime endpoint observations from section 2.4 "Endpoint observations") are append-only rows with TTL (`observed_at`, `expires_at`),
2. ingest uses `INSERT OR IGNORE` (no in-place refresh),
3. derive `first_seen`/`last_seen` via `MIN(observed_at)`/`MAX(observed_at)` queries when needed.

## 4.3 Emitted-event rule

If projector `A` emits event `B`:

1. emit canonical `B` only (normal persistence/queue path),
2. allow `B` to project through `B`'s own projector/autowrite table.

`autowrite` means the projector's default deterministic write path: `InsertOrIgnore` materialization into its owned projection table with no cross-module side effects.

Projectors should not directly write into another event type's projection table except rare, explicitly documented operational exceptions.

Deterministic emitted-event rule detail:
1. deterministic emitted event types still use the same emitted-event flow (`emit -> persist -> self-project`),
2. they use schema-marked unsigned mode for determinism (no signer fields),
3. shared pipeline applies deterministic derivation checks for those types in place of signer checks.

## 4.4 Explicit special cases

Some behavior stays explicit by design:

1. deletion/tombstone cascades (`message_deletion` and related checks),
2. trust-anchor handling in `invite_accepted` (first-write-wins anchor write + explicit `RetryWorkspaceEvent` replay trigger),
3. identity/removal policy checks from TLA guards.

### Deletion intent + tombstone lifecycle

Deletion uses a two-stage model so deletes stay deterministic when events arrive out of order. 

**Stage 1: deletion_intent write.**
The `MessageDeletion` projector always emits an idempotent `deletion_intent` write keyed
by `(recorded_by, target_kind="message", target_id)`. This records the intent to delete
regardless of whether the target message exists yet.

**Stage 2: tombstone + cascade.**
- If the target message exists in projected state, the projector also emits tombstone
  (`deleted_messages`) write ops and cascade deletes (`messages`, `reactions`) in the same
  apply batch.
- If the target does not exist yet, only the intent is recorded. No imperative retries.

**Delete-before-create convergence:**
Target-creation projectors (`project_message_pure`) check for matching `deletion_intent`
rows in their context snapshot and immediately tombstone on first materialization. The
tombstone row uses the original deletion event's ID and author from the intent, ensuring
identical final state regardless of arrival order.

**Monotonic deletion state:**
- `active → tombstoned` is allowed.
- `tombstoned → active` is never allowed by replay.
- Physical row removal is a separate compaction concern; projector semantics prefer tombstones.

**Cleanup fanout:**
Reaction cleanup on message delete is represented as explicit deterministic `Delete` WriteOps
in the `ProjectorResult`, not hidden side effects. Reactions arriving after their target
message is deleted (or has a deletion intent) are structurally valid but produce no row.

### Replay/reorder/idempotence deletion invariants

These invariants are enforced by tests (`test_deletion_invariant_*`):

1. **Duplicate replay:** Re-projecting a deletion event leaves state unchanged after first application.
2. **Order convergence:** Delete-before-create produces identical tombstone rows as create-before-delete.
3. **Replay invariance:** Full forward replay from event log reproduces identical tombstone state.
4. **Auth determinism:** Authorization failure paths are deterministic from projected context snapshot.
5. **Cleanup completeness:** No live reactions remain for tombstoned messages; no query can surface deleted entities.
6. **Command idempotence:** `deletion_intent` identities are stable (derived from event identity); re-running does not mutate final state.
7. **Monotonicity:** Once tombstoned, a message cannot revert to active state.

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

We do not persist a global transitive dependency graph as an always-updated materialized structure. Instead, we persist only currently-blocked edges needed for unblock scheduling (`blocked_event_deps`) plus per-event blocked headers (`blocked_events`).

Dependencies are extracted per projection attempt from schema metadata for the current event type. Example: projecting a `Reaction` reads its declared dependency fields (`target_event_id`, `author_id`, `signed_by`) from the parsed event, checks presence in `valid_events`, and writes block rows only for missing deps.

## 5.2 Counter-based Kahn cascade unblock

Unblocking uses a counter-driven Kahn-style cascade:

1. when blocker `X` becomes valid, read candidates from `blocked_event_deps` by (`peer_id`, `blocker_event_id`),
2. decrement `blocked_events.deps_remaining` for each candidate,
3. when a candidate reaches zero remaining deps, delete its `blocked_events` header row and project it through the same canonical projection entrypoint,
4. if that candidate becomes valid, treat it as the next blocker and continue the cascade.

Implementation detail:
1. `blocked_event_deps` is read-only during per-step cascade work,
2. stale rows are bulk-cleaned only after cascade transitions occur (valid/rejected terminal rows); this cleanup runs in the same projection transaction boundary as terminal-state writes so readers do not observe partial unblock state,
3. guard retries run after this dep cleanup so guard queries see current state. 

Design note:
1. a SQL-only cascade (`DELETE ... RETURNING` + zero-row checks) is simpler,
2. local benchmark runs during refactor showed the counter path materially faster in `tests/topo_cascade_test.rs` workloads (exact multiplier environment-dependent), so counter-based cascade is the default.

## 5.3 Event creation API

Three creation entry points exist:

1. `create_event_synchronous(...) -> event_id` (current Rust symbol: `create_event_sync`),
2. `create_signed_event_synchronous(...) -> event_id` (current Rust symbol: `create_signed_event_sync`),
3. `create_encrypted_event_synchronous(...) -> event_id` (current Rust symbol: `create_encrypted_event_sync`).

The `_sync` suffix in current symbols means "synchronous/blocking creation"
(not sync/reconciliation protocol semantics). The canonical semantics are
`*_synchronous`.

`create_event_synchronous` uses the same internal path as workers and returns
success only when terminal state is `valid` for the target `recorded_by`.
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

## 6.2 Projection adapter stage

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

Decryption is an adapter stage inside the same projection pipeline, not a second projection system.

## 6.3 Plaintext policy

1. default: no persisted plaintext queue,
2. plaintext exists in memory during projection only,
3. optional short-lived cache can be added later for performance.

Current canonical plaintext families:
1. identity/auth chain events (`workspace`, `invite_accepted`, `user_invite`, `device_invite`, `user`, `peer_shared`, `admin`, removals),
2. local identity/support events (`local_signer_secret`, `secret_key`, bootstrap helper events),
3. content metadata events that are intentionally cleartext in this POC (`message_attachment`, `file_slice`, `reaction`, `message_deletion`, `signed_memo`, `bench_dep`).

Encrypted wrapper events remain canonical but carry ciphertext payloads whose inner event type is validated by `inner_type_code` before inner projection.

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
   - receive `Frame::Event` blobs,
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

1. negentropy reconciliation decisions (`runtime/sync_engine/session/control_plane.rs`),
2. incoming `HaveList` responses and need buffering (`runtime/sync_engine/session/initiator.rs`),
3. control protocol producers (`Frame::NegOpen`, `Frame::NegMsg`, `Frame::HaveList`, `Frame::Done`, `Frame::DataDone`, `Frame::DoneAck`, `Frame::IntroOffer`) in `shared/protocol.rs`,
4. optional proactive send pathways (future optimization hooks in this queue model).

For canonical event transfer, egress rows carry `event_id`; canonical blob is read at send time.

## 7.4 Dedupe and purge

1. `project_queue` is transient and purged on terminal decision (`Valid`, `Reject`, or `AlreadyProcessed` for the `(peer_id, event_id)` projection target),
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

Multi-source coordinated download is the default pull path. A coordinator thread assigns events to peers using round-based greedy load balancing:

1. **Discovery**: each peer runs negentropy with its source, discovering need_ids
   (events the sink needs). Push (have_ids) proceeds immediately.
2. **Streaming pull**: during reconciliation, each peer sends HaveList frames
   immediately as need_ids are discovered (pipelining data transfer with
   reconciliation). Need_ids are also buffered for coordinator reporting.
3. **Report**: after reconciliation completes, each peer sends its full need_ids
   to the coordinator via a per-peer channel.
4. **Assignment**: the coordinator collects reports (short collection window after
   first report), builds an event-to-peer availability map, sorts by availability
   ascending (unique events first), and assigns each event to the least-loaded peer
   that has it.
5. **Transfer**: since HaveList was already streamed during reconciliation, the
   coordinator assignment is informational for the reporting peer (the `wanted`
   table deduplicates). For multi-peer scenarios, other peers receive their
   assigned subsets normally.
6. **Forget**: assignments are discarded after each round. Next round starts fresh.

**Critical invariant — streaming pull dispatch.** HaveList frames MUST be sent
during reconciliation rounds, not deferred until after reconciliation completes.
Buffering need_ids until post-reconciliation creates a pipeline stall: events
cannot flow until reconciliation finishes AND the coordinator round-trips. This
serializes ~1 second of overhead that should be pipelined. The `wanted` table
provides natural dedup so streaming dispatch is safe even with coordinator
assignment afterward.

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
- A global in-memory "seen set" grows without bound for long-running daemons (~90 bytes per EventId), which conflicts with low-memory goals.
- `INSERT OR IGNORE` in `batch_writer` handles duplicates correctly and cheaply.

**Coordinator for pull rebalancing, not gating.** Each peer still pushes all
have_ids without coordination — the push path runs at full speed. The pull
path streams HaveList during reconciliation (so events flow immediately) and
also reports need_ids to the coordinator for multi-peer load balancing. The
coordinator assigns each event to the least-loaded peer that has it, reducing
redundant downloads when multiple sources share the same events. For
single-peer sync, the coordinator degenerates to pass-through (all events
assigned to the sole peer, which already streamed them).

**Round-based reassignment.** Assignments are discarded after each round. If a
peer fails to deliver its assigned events (slow, disconnected), those events
re-appear as need_ids in the next negentropy round and get reassigned to a
different peer. No permanent affinity between events and peers.

**Short collection window (500ms default).** The coordinator waits briefly after the
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

## 7.7 Negentropy implementation notes

Baseline implementation:
1. `neg_items` stores shared-event membership tuples (`workspace_id`, timestamp, event id bytes).
2. Per-session block indexes are rebuilt into `session_blocks` for reconciliation rounds.
3. Control-plane reconciliation uses `NegOpen` and `NegMsg` frames; results drive `HaveList`.
4. Data-plane transfer streams `Event` frames while reconciliation can continue in parallel.
5. Multi-source coordination does not replace negentropy; it consumes per-peer `need_ids` discovered by negentropy.

Primary code references:
1. `src/runtime/sync_engine/negentropy_sqlite.rs`
2. `src/runtime/sync_engine/session/control_plane.rs`
3. `src/shared/protocol.rs`

---

# 8. CLI and Daemon Contract

The CLI/daemon operational shape is primarily for operability, testing, and demo workflows in this POC; it is not itself part of canonical protocol semantics.

## 8.1 Operational shape

1. one daemon per profile/peer (`topo start`),
2. local RPC control socket,
3. unified CLI (`topo`) with subcommands that route through daemon when running, fall back to direct DB access otherwise.

### RPC wire contract

1. local RPC uses a versioned envelope (`RpcRequest.version`, `RpcResponse.version`),
2. transport framing is `u32` big-endian length-prefixed JSON,
3. server rejects oversized RPC frames (>16 MiB),
4. daemon enforces a bounded concurrent RPC connection cap.

### Daemon session-local state

Daemon RPC state owns local UX/session aliases that are intentionally non-canonical:
1. active peer selection for multi-tenant DBs,
2. invite-link numeric references (session-local aliases to full `quiet://...` links),
3. channel aliases + active-channel selection per peer.

These are operator ergonomics, not protocol facts; they do not project into canonical event state.

### DB registry selector contract

CLI database selection supports a local registry (`~/.topo/db_registry.json`, overridable by `TOPO_REGISTRY_DIR`) with:
1. alias names,
2. 1-based numeric selectors,
3. default DB selection for the implicit `--db server.db` case.

Selectors resolve in priority order: existing path -> alias -> index -> passthrough path.

## 8.2 Testing and agent ergonomics

Assertion-first commands are first-class:

1. `assert-now`,
2. `assert-eventually`,

`assert-eventually` is preferred over ad-hoc sleeps for both deterministic tests and agent self-play loops.

---

# 9. Identity, Auth, Invites, Trust Anchor, and Removal

A secure Slack alternative requires a clear notion of team membership, Signal/Slack-like invite links, end-to-end encryption, and message history provision.

For reliability reasons we bias toward making key agreement a layer on top of the auth CRDT, not the same as the auth CRDT or necessary to read the auth CRDT. (Though it should be possible to build either such design with this protocol.)

We explore a simple placeholder model of this "plaintext signed auth graph as basis for group key agreement" type here.

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

### TLA conformance cadence

1. Per change (required): when modifying event schemas, projector predicates, dependency extraction, signer rules, or emitted-command semantics, run `scripts/check_projector_tla_conformance.py` and `scripts/check_projector_tla_bijection.py`.
2. Nightly/periodic full pass: run the expanded TLC configs (`docs/tla/event_graph_schema_expanded.cfg`, `docs/tla/event_graph_schema_expanded_single_peer.cfg`) and record drift.
3. Pre-merge gate for identity/trust/bootstrap changes: run full conformance + expanded TLC before merge.
4. If behavior changes, update `docs/tla/projector_spec.md` and `docs/tla/projector_conformance_matrix.md` in the same change.

### Layered conformance model

Tests are organized into three layers, each exercising a different scope of the TLA+ conformance contract:

1. **Projector unit** (`tests/projectors/*_projector_tests.rs`) — pure function contract. Each test calls `project_pure(event, ctx)` directly with a hand-built `ContextSnapshot` and asserts decision, write_ops, and emit_commands. Covers event-local predicates (trust anchor, signer mismatch, deletion author, bootstrap trust emission, file slice auth).
2. **Pipeline integration** (`src/state/projection_state/apply/tests/`) — shared pipeline stages. Tests exercise `project_one_step` end-to-end through dep presence, dep type checks, signer resolution, encrypted wrapper decrypt/dispatch, and cascade unblock. Uses a real SQLite DB with the full projection pipeline.
3. **Replay/order conformance** (`src/state/projection_state/apply/tests/`) — model-critical convergence properties. Source-isomorphism tests replay the same events in different orderings and assert identical terminal state. Covers out-of-order convergence, idempotent replay, stable terminal state, and deletion two-stage convergence.

Coverage is tracked in `docs/tla/projector_conformance_matrix.md` (spec_id → check_id → test_id with pass/break polarity) and enforced by CI gate scripts (`scripts/check_projector_tla_conformance.py`, `scripts/check_projector_tla_bijection.py`).

## 9.2 Invite model

Use split invite event types:

1. `user_invite`,
2. `device_invite`,
3. `invite_accepted`.

We do not use multimodal `invite(mode=...)` type (even though it would be DRY) because it complicates the TLA model.

Implementation uses shared invite helper logic with per-type policy tables.
Interactive CLI keeps real invite links (`quiet://invite/...`, `quiet://link/...`) in frontend state; session-local invite numbers are aliases to those links.

## 9.3 Trust-anchor cascade

`invite_accepted` records trust-anchor intent for `workspace_id` in tenant scope.

Required semantics:
1. workspace is not valid until trust anchor exists,
2. invite events and invites are not forced-valid,
3. normal signer/dependency chain still governs validity,
4. bootstrap transport trust rows (`invite_bootstrap_trust`, `pending_invite_bootstrap_trust`) are projection-owned state, produced by concrete event projectors:
   - `user_invite` projector emits `WritePendingBootstrapTrust`,
   - `device_invite` projector emits `WritePendingBootstrapTrust`,
   - `invite_accepted` projector emits `WriteAcceptedBootstrapTrust`,
   - `peer_shared` projector emits `SupersedeBootstrapTrust`.
   Projectors read local `bootstrap_context`; the service layer writes `bootstrap_context` rows only, never trust rows directly.
   This follows the same poc-6 cascade pattern where `invite_accepted` projection drives trust establishment.

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

This approach makes first-user creation and device linking isomorphic to subsequent-user additions and device linking. Auth graph logic is easy to get wrong, so this simplification is valuable. 

## 9.4 Sender-subjective encryption proof-of-concept

The proof-of-concept requires that we show that modern group key agreement schemes are possible with this approach, but we do not seek to build one, instead opting for a simple placeholder.  

For each encrypted message in the prototype:

1. sender creates a fresh local key event,
2. sender emits one key-wrap event per currently eligible recipient peer pubkey,
3. encrypted content references key dependency via normal event refs.

After observing `user_removed` or `peer_removed`, sender excludes removed recipients from subsequent wraps.
Historical re-encryption or key history request/response mechanism is out of scope for the proof-of-concept.

### 9.4.1 Bootstrap key distribution via invite-key wrap/unwrap

Bootstrap key acquisition uses the same `secret_shared` event type and wrap/unwrap logic as runtime sender-keys. The only difference is the recipient: at invite creation the inviter wraps content-key material to the invite public key (X25519-derived from the Ed25519 invite signing key), rather than to a peer's PeerShared public key.

(In this way we demonstrate that the auth graph is compatible with the goal of sharing key history (access to existing messages) with new users and devices, a potential requirement of a Slack-like workplace messenger.)

Flow:
1. At invite creation, the inviter wraps current content key(s) to the invite key via `secret_shared` events (delivered during bootstrap sync, not embedded in the invite link payload).
2. At invite acceptance, the joiner unwraps using the invite private key (carried in the link) and the inviter's public key (from the `secret_shared` event's signer).
3. The joiner materializes local `secret_key` events with deterministic event IDs (BLAKE2b hash of key bytes → `created_at_ms`), ensuring both inviter and joiner derive identical `key_event_id` values.
4. Encrypted events that depend on those key IDs can then be projected normally through the standard block/unblock cascade.

All key acquisition flows through the same event-backed wrap/unwrap path.

## 9.5 Transport credential lifecycle model

This section covers the lifecycle state machine for the three trust sources: PeerShared-derived SPKIs (steady-state), `invite_bootstrap_trust`, and `pending_invite_bootstrap_trust`. The `transport_keys` table may still be populated by legacy TransportKey event projection, but it is deprecated/scheduled for removal and is **not** consulted for trust decisions.

Credential transition model: invite acceptance may install a bootstrap transport cert first; projection later installs the PeerShared-derived cert. Runtime enforces one-way transition (no bootstrap-after-PeerShared downgrade).

Supersession: when a PeerShared event is projected, the PeerShared projector emits a `SupersedeBootstrapTrust` command that marks matching `invite_bootstrap_trust` and `pending_invite_bootstrap_trust` entries as superseded. This happens at projection time, not on trust check reads — trust check reads (`is_peer_allowed`, `allowed_peers_from_db`) are pure queries with no write side-effects.

TTL expiry: bootstrap trust rows are time-bounded. Unconsumed entries expire and are purged.

Removal cascade: `peer_removed` cascades trust removal across all three sources for the affected peer.

Invite ownership: `inviteCreator` tracks which peer created each invite SPKI. Only the invite creator (inviter) may materialize pending bootstrap trust — the joiner must not emit `WritePendingBootstrapTrust` when syncing the invite event. This is enforced by the `is_local_create` flag in `ContextSnapshot`, populated from `recorded_events.source`. The TLA+ model captures this via the `inviteCreator[s] = p` guard on `AddPendingBootstrapTrust` and the `InvPendingTrustOnlyOnInviter` invariant.

TLC-verified invariants (from `TransportCredentialLifecycle.tla`, mapped to Rust checks in `docs/tla/projector_spec.md`):
1. `InvSPKIUniqueness` — no two peers share an active SPKI,
2. `InvBootstrapConsumedByPeerShared` — bootstrap trust disjoint from PeerShared trust,
3. `InvPendingConsumedByPeerShared` — pending trust disjoint from PeerShared trust,
4. `InvTrustSetIsExactUnion` — trust set is exact union of three sources,
5. `InvTrustSourcesWellFormed` — all trust sets contain valid SPKIs,
6. `InvMutualAuthSymmetry` — mutual auth requires both peers have credentials,
7. `InvPendingTrustOnlyOnInviter` — pending trust exists only on invite creator's store,
8. `InvCredentialSourceConsistency` — credential presence and source are consistent across bootstrap→PeerShared transition.

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
1. replay invariants (`once`, `twice`, `reverse-order`, shuffled reorder, reproject-no-clear idempotency) are standard checks in the scenario harness.
2. they run after scenario tests that mutate canonical event-store rows.
3. checks are computed from deterministic table-state fingerprints over event-store-derived state.
4. implementation references: `src/testutil/mod.rs` (`verify_projection_invariants`) and scenario coverage in `tests/scenario_test.rs`.

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

## 10.2 Narrative walkthrough: invite join to steady-state sync

1. Inviter creates a `user_invite` event and shares invite data.
2. Joiner accepts via `invite_accepted`, then writes follow-on identity events (`user`, `device_invite`, `peer_shared`) under pre-derived final `recorded_by`.
3. Projectors apply deterministic rows and emit bootstrap trust commands (`WritePendingBootstrapTrust`, `WriteAcceptedBootstrapTrust`, later `SupersedeBootstrapTrust`) as dependencies become available.
4. Peering loops read trust state from SQL and establish transport sessions only for allowed peers.
5. Sync transfers missing canonical events; blocked rows unblock via the same dependency cascade used everywhere else.
6. Queries read projected rows; replaying the same canonical set converges to the same result.

---

# 11. Performance and Operational Defaults

1. use SQLite WAL mode and prepared statements,
2. batch worker operations with measured sizing,
3. keep queue purge policies explicit and predictable,
4. monitor blocked counts, queue age, retries, lease churn,
5. provide `low_mem_ios` mode targeting `<= 24 MiB` steady-state RSS for iOS-NSE-like constrained environments,
6. in `low_mem_ios`, enforce strict in-flight bounds and prefer reduced throughput over memory spikes.

Operational payload caps for this prototype (wire-format specifics in section 1.2 and file-flow details in section 12.2):

1. `EVENT_MAX_BLOB_BYTES = 1 MiB` soft cap,
2. `FILE_SLICE_TARGET_BYTES = 256 KiB`,
3. `FILE_SLICE_CIPHERTEXT_BYTES = 262_144` (fixed canonical ciphertext payload per file-slice event).

`file_slice` events (type 25, signed) are signed and validated like other canonical events.
`message_attachment` events (type 24, signed) are file descriptors with deps on `message_id`, `key_event_id`, and `signed_by`.
`signed_memo` events (type 4, signed) are placeholder fixed-size canonical memo entries projected into `signed_memos`.

### Low-memory trust and key strategy (`low_mem_ios`)

Trust and key sets use SQL indexed point lookups, not full in-memory loading. The projection tables (`trust_anchors`, identity chain tables, bootstrap trust tables) are queried on demand with indexed `(recorded_by, ...)` keys.

There is no dedicated unbounded in-memory trust/key hot cache in baseline; low-memory behavior relies on indexed SQL lookups plus statement caching (`prepare_cached`).

Runtime low-memory mode is enabled by env vars `LOW_MEM_IOS` or `LOW_MEM` (truthy except `0`/`false`). Queue/runtime tuning values are centralized in `src/tuning.rs`, including:
1. projection drain/write batch sizing,
2. shared ingest channel caps,
3. session ingest caps,
4. transport receive-buffer limits.

Validation scale requirements: the low-memory path must remain stable at >= 1,000,000 canonical events on disk and >= 100,000 peer trust keys while staying within the 24 MiB steady-state RSS ceiling. Throughput may degrade to preserve the memory bound.

Caveat: `24 MiB` is an operational target validated by representative low-memory tests and tuning profiles, not a universal guarantee across all kernels/devices/workloads. For very large message histories and trust sets, the design favors bounded memory (smaller in-flight windows and SQL point lookups) over peak throughput.

---

# 12. Extensibility Path

The completed prototype is deliberately minimal but extension-friendly.

## 12.1 Richer content surface

Current baseline already includes reactions, message deletion, attachments, and file slices. Additional families (for example edits, richer thread semantics, moderation signals) can be added by:

1. declaring schema + projection table metadata,
2. using default **autowrite** where possible (projector returns deterministic `InsertOrIgnore` writes only, no emitted commands),
3. introducing explicit special projector logic only when policy semantics require it (for example trust-anchor retries, bootstrap trust supersession, deletion intent/tombstone coupling, or guard-block retry flows).

## 12.2 File attachments and large payload flows

Attachments and slice streaming fit naturally:

1. large payload events remain canonical typed events with fixed wire sizes,
2. file slices use a canonical fixed ciphertext size; final plaintext chunks are zero-padded before encryption,
3. deps and signatures continue to gate integrity and ordering (wire/layout details in section 1.2; queue transfer behavior in section 7.6).

## 12.3 Proactive 1-hop gossip on send

Beyond pull/reconcile sync, send-time proactive push can be layered as an egress producer: 

1. on local canonical event creation, enqueue one-hop egress to currently connected peers,
2. keep dedupe by `(connection_id, event_id)` and existing lease/retry rules,
3. preserve canonical/projector semantics unchanged (transport optimization only).

## 12.4 Subjective encryption with history provision

The baseline sender-subjective O(n) wrap model can incrementally evolve toward a future group-encryption design note (not yet committed in this repository):

1. introduce update-path style shared key structure for better asymptotics,
2. add key request/response healing for inactive peers,
3. add explicit history-availability policy and provisioning events for newly linked devices/users (baseline already has invite bootstrap key distribution and pending-unwrap retry, but not full long-horizon history policy controls),
4. eventually optimize recipient-cover selection (e.g. TreeKEM) while preserving the same canonical dependency/projection model.

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
7. multitenant

The result is a small protocol core with clear upgrade paths instead of a stack of exceptions.

# 14. Event-Module Locality

For developer ergonomics it will be helpful to have event-related logic in the most important event modules, rather than spread across the codebase.

## 14.1 Enforceable locality contract

These rules are mandatory. Violations must be fixed before merge.

1. **Event-module locality rule**: Event modules (`src/event_modules/<type>/`) own all event-type-specific behavior: wire format, projector, commands, queries, and response types. No event-type-specific SQL or logic may live in `service.rs` or the projection pipeline.

2. **Service orchestration-only rule**: `service.rs` is a thin orchestrator. It handles DB open/close, auth/key loading, cross-module composition, non-event-specific logic (identity bootstrap, invite flows, predicate/assert), and error mapping. It must not contain event-type-specific SQL — it calls event-module APIs.

3. **Direct module routing rule**: Service routes event-local operations directly to event-module command/query APIs (for example: `message::send`, `reaction::list`, `workspace::name`). There is no central `EventCommand`/`EventQuery` service dispatcher.

4. **Workflow-command locality rule**: Multi-step event-domain workflows are still commands and belong in the owning event module `commands.rs` (or `commands/` when split), not in `service.rs`. Example: workspace onboarding workflows (`create_workspace`, `join_workspace_as_new_user`, `add_device_to_workspace`) live in `workspace::commands`.

5. **Module split rule**: When an event module exceeds ~300-400 LOC or mixes 3+ concerns, split into a directory module (see 14.4).

## 14.2 Layering convention

Event modules (`src/event_modules/<type>.rs` or `src/event_modules/<type>/`) own five concerns:

1. **Wire** — struct definition, parse/encode, wire layout, `EventTypeMeta`.
2. **Projector** — `project_pure()` function: the pure projector for this event type. Takes `(recorded_by, event_id_b64, &ParsedEvent, &ContextSnapshot)` and returns `ProjectorResult`. Registered in `EventTypeMeta.projector` so the pipeline dispatches via registry lookup with no central match statement.
3. **Commands** — `CreateXxxCmd` struct + `create()` function that builds the `ParsedEvent`, calls `create_signed_event_sync`, and returns `EventId`. High-level command helpers callable from service/RPC routes (for example `send`, `react`) and multi-step workflows (for example workspace onboarding) are first-class command APIs in this layer.
4. **Queries** — `list()`, `count()`, `resolve()`, `list_for_message_with_authors()`, etc. — SQL against projection tables scoped by `recorded_by`. All event-specific SQL lives here.
5. **Response types** — serializable structs for the event domain (e.g. `MessageItem`, `MessagesResponse`, `SendResponse`). Owned by the event module, re-exported by service.rs for external callers.

The projection pipeline (`src/state/projection_state/apply/`) is orchestration-only:

- Dependency presence check + block row writes
- Dependency type enforcement
- Signer verification (uniform across all signed events)
- Context snapshot construction
- Registry-driven projector dispatch: `(meta.projector)(recorded_by, event_id_b64, parsed, ctx)`
- Write-op execution and emit-command handling

The service layer (`src/service.rs`) is a thin orchestrator:

- DB open/close and connection management
- Auth/key helpers (`load_local_peer_signer_pub`, `load_local_user_key`)
- Cross-module composition is routed through RPC handlers and event-module queries (for example `workspace::view` combines workspace/message/reaction/user projections)
- Non-event-specific logic (identity bootstrap, invite flows, predicate/assert system)
- Error mapping from module results to `ServiceError`

## 14.3 Routing pattern

### Projector dispatch

`EventTypeMeta` includes a `projector` function pointer with the uniform signature:

```rust
fn(&str, &str, &ParsedEvent, &ContextSnapshot) -> ProjectorResult
```

### Service command routing

RPC command handlers (`src/runtime/control/rpc/server.rs`) call event-module command APIs directly. Example flows:

- `RpcMethod::Send` -> `message::send_for_peer`
- `RpcMethod::React` -> `reaction::react_for_peer`
- `RpcMethod::DeleteMessage` -> `message::delete_message_for_peer`
- `RpcMethod::Ban` -> `user::ban_for_peer`
- `RpcMethod::CreateWorkspace` -> `workspace::commands::create_workspace_for_db`
- `RpcMethod::AcceptInvite` -> `workspace::commands::accept_invite`
- `RpcMethod::AcceptLink` -> `workspace::commands::accept_device_link`
- `RpcMethod::CreateInvite` -> `workspace::commands::create_invite_for_db` / `workspace::commands::create_invite_with_spki`
- `RpcMethod::CreateDeviceLink` -> `workspace::commands::create_device_link_for_peer`

### Service query routing

RPC query handlers (`src/runtime/control/rpc/server.rs`) call event-module query APIs directly. Example flows:

- `RpcMethod::Messages` -> `message::list`
- `RpcMethod::Reactions` -> `reaction::list`
- `RpcMethod::Users` -> `user::list_items`
- `RpcMethod::Workspaces` -> `workspace::list_items`
- `RpcMethod::Keys` -> `workspace::keys` (which aggregates `user`, `peer_shared`, `admin`, and `transport_key` counts)

## 14.4 Module split rule

When an event module exceeds roughly 300-400 LOC or mixes 3+ concerns (wire + commands + queries + projector), split it into a directory module:

```
src/event_modules/<name>/
    mod.rs          — re-exports stable public API
    wire.rs         — event struct, parse, encode, EventTypeMeta, project_pure
    projector.rs    — project_pure + projector-local helpers (if separated from wire)
    commands.rs     — CreateXxxCmd, create(), high-level command helpers
    queries.rs      — query_list, query_count, resolve_*, response assembly
```

`mod.rs` re-exports all public items so callers continue to import from `event_modules::<name>`.

If `commands.rs` becomes long because of multiple workflows, split commands into a directory while keeping `event_modules::<name>::commands::*` stable:

```
src/event_modules/workspace/
    mod.rs
    wire.rs
    projector.rs
    queries.rs
    commands/
        mod.rs
        create_workspace.rs
        join_workspace_as_new_user.rs
        add_device_to_workspace.rs
```

This keeps workflow locality (all workspace lifecycle commands under workspace) without forcing one very large `commands.rs`.

## 14.5 Layout locality rule 

Wire layout constants (wire sizes, text-slot budgets, field offset modules) are owned by the event module that defines the event type:

1. **Single-file events** (`foo.rs`): layout constants live inline in `foo.rs`.
2. **Directory-scoped events** (`foo/`): layout constants live in `foo/layout.rs`.
3. **Shared cross-event primitives** (`COMMON_HEADER_BYTES`, `SIGNATURE_TRAILER_BYTES`, text-slot helpers, encrypted envelope helpers) live in `src/event_modules/layout/common.rs`.
4. **Event modules must not import another event module's layout constants.** Cross-event wire math (e.g. `encrypted_inner_wire_size`) belongs in `layout/common.rs` and imports the needed per-event wire sizes.

Do not reintroduce a global layout monolith. When adding a new event type, define its wire size and offsets in the owning module.

## 14.6 Explicit workspace guard retry

The `invite_accepted` projector emits `RetryWorkspaceEvent { workspace_id }` after writing the trust anchor. This explicitly targets the known workspace event for re-projection, flowing through normal `project_one` + cascade. The workspace projector guard-blocks when no trust anchor exists and unblocks when retried after the trust anchor is set by `invite_accepted`.

## 14.7 Adding a new event type

`dispatch_pure_projector` in `apply/dispatch.rs` looks up the event's type code in the registry and calls the registered projector. No central match statement is required. Each event module owns its complete projection semantics.

When adding a new event type:

1. Define the event struct, parse/encode, and `EventTypeMeta` in `src/event_modules/<type>.rs` (or `<type>/wire.rs` if split).
2. **Add `project_pure()`** — the pure projector function. Set `EventTypeMeta.projector = project_pure`. This is where all projection semantics for this event type live.
3. Add `CreateXxxCmd` + `create()` for command paths.
4. Add `query_*()` functions for any projection-table queries.
5. Add response types and service/RPC-facing convenience helpers in the event module.
6. Wire service call sites directly to the new module command/query APIs where relevant.
7. Wire service.rs to call the event module functions, mapping errors to `ServiceError`.

**Rule**: Event projection semantics MUST live in event modules, not in central projector files. The pipeline must not contain event-type-specific logic beyond context snapshot construction.

---

# 15. Appendix: Implementation Map

This appendix holds concrete Rust file/module references so conceptual sections stay readable.

## 15.1 Projection pipeline map

1. Canonical entrypoint: `src/state/projection_state/apply/project_one.rs`
2. Dependency and signer stages: `src/state/projection_state/apply/stages.rs`
3. Context snapshot builder: `src/state/projection_state/apply/context.rs`
4. Write/emit executor: `src/state/projection_state/apply/write_exec.rs`
5. Cascade scheduler: `src/state/projection_state/apply/cascade.rs`
6. Batch writer orchestration: `src/state/pipeline/mod.rs`
7. Pipeline persist/planner/effects: `src/state/pipeline/phases.rs`, `src/state/pipeline/planner.rs`, `src/state/pipeline/effects.rs`

## 15.2 Peering/runtime map

1. Peering supervisor and startup preflight: `src/runtime/peering/loops/supervisor.rs`
2. Dial loop: `src/runtime/peering/loops/connect.rs`
3. Accept loop: `src/runtime/peering/loops/accept.rs`
4. Session runner seam: `src/runtime/peering/loops/mod.rs`
5. Target planning: `src/runtime/peering/target_planner.rs`
6. QUIC dial/accept lifecycle: `src/runtime/transport/connection_lifecycle.rs`
7. Session I/O construction: `src/runtime/transport/session_factory.rs`
8. Session I/O adapter: `src/runtime/transport/transport_session_io.rs`

## 15.3 Identity and transport boundary map

1. Workspace identity workflows: `src/event_modules/workspace/commands.rs`
2. Identity helper primitives: `src/event_modules/workspace/identity_ops.rs`
3. Invite link codec: `src/event_modules/workspace/invite_link.rs`
4. Transport identity adapter contract: `src/shared/contracts/transport_identity_contract.rs`
5. Transport identity adapter implementation: `src/runtime/transport/identity_adapter.rs`
6. Transport cert/key install/load helpers: `src/runtime/transport/identity.rs`
7. Trust SQL tables + helpers: `src/state/db/transport_trust.rs`
8. Boundary guard script: `scripts/check_boundary_imports.sh`
