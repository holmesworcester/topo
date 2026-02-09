# QUIC Hole Punch Plan (Intro via Third Peer)

## Goal
Enable two peers (`A`, `B`) to establish a direct QUIC+mTLS connection using only endpoint tuples observed by a third peer (`I`) and sent as an intro message.

This is transport-layer behavior only.
- No canonical connection events.
- No network simulator.
- Real QUIC sockets only.
- Minimal-complexity first: one-shot intros from an introducer command, then optional background worker later.

## Scope and constraints
1. Use existing mTLS trust model: remote cert/SPKI must still be allowed locally.
2. Treat intro data as a hint, not authority.
3. Keep workspace/event graph semantics unchanged.
4. Keep implementation simple first: one observed `(origin_ip, origin_port)` per target peer.
5. Prefer local transport logs/tables for intros and punch attempts over canonical event types.
6. After direct connection succeeds, start existing sync protocol immediately (no special post-intro handshake).
7. Avoid new queue subsystems for intros in v1 (best-effort send on existing connections only).

## Explicit non-goals for this phase
1. No intro as canonical event.
2. No intro gossip via negentropy.
3. No projector logic for intros.
4. No requirement that hole punching succeeds for protocol correctness.

## Key design choices

### 1) Intro is a transport control message
Use the term "intro event" operationally, but implement it as a QUIC control frame, not a canonical event-store event.

Rationale:
- avoids polluting canonical history with transient network hints,
- avoids replay semantics for stale endpoint hints,
- keeps projector logic focused on content/identity.
- avoids slow/eventual delivery path for time-sensitive punch windows.

### 2) Single QUIC endpoint per daemon for accept + connect
Hole punching depends on outbound packets and inbound handshakes sharing the same UDP socket mapping.

Current code creates separate server and client endpoints in `run_sync`. For hole punching, this must become one dual-role endpoint bound once, used for:
- `accept()` loops,
- `connect()` attempts.

### 3) Keep fallback path
If direct punch fails, peers continue syncing over existing paths (for example via introducer connectivity). Hole punching is an optimization, not required for correctness.

### 4) Connect, then run normal sync immediately
After a successful direct QUIC+mTLS handshake, peers should start the normal sync initiator/responder flow (`NegOpen` and existing engine behavior) with no new transition protocol.

## Intro frame v1

Add new sync message type:
- `MSG_TYPE_INTRO_OFFER = 0x30`
- `SyncMessage::IntroOffer { ... }`

Fixed fields (v1):
1. `intro_id` `[16]` random bytes for dedupe/correlation.
2. `other_peer_id` `[32]` SPKI fingerprint bytes (raw, not hex).
3. `origin_family` `u8` (`4` or `6`).
4. `origin_ip` `[16]` (IPv4 mapped/padded, IPv6 raw).
5. `origin_port` `u16`.
6. `expires_at_ms` `u64`.

Validation on receipt:
1. drop if `now > expires_at_ms`,
2. drop if `other_peer_id` is not allowed by local trust set,
3. drop duplicate `intro_id` already processed,
4. accept otherwise and schedule punch attempts.

## Data model

Reuse existing:
- `peer_endpoint_observations` as introducer source of observed endpoints.

Add local-only transport table:

`intro_attempts`
1. `recorded_by TEXT`
2. `intro_id BLOB`
3. `introduced_by_peer_id TEXT`
4. `other_peer_id TEXT`
5. `origin_ip TEXT`
6. `origin_port INTEGER`
7. `expires_at INTEGER`
8. `status TEXT` (`received|dialing|connected|failed|expired|rejected`)
9. `error TEXT NULL`
10. `created_at INTEGER`
11. `updated_at INTEGER`
12. PK `(recorded_by, intro_id)`

This table is for operator/debug/test visibility only.

## Introducer control model (minimal first)
V1 uses a one-shot introducer command.

Behavior:
1. Operator/agent selects peers `A` and `B`.
2. Introducer reads latest non-expired observation for each.
3. Introducer sends two `IntroOffer` frames over existing authenticated control channels.
4. If either connection is absent, return a clear error; no durable intro queue in v1.

Optional later:
1. Add a background intro worker using the same one-shot logic.

## Runtime flow

### A) Observation capture (already mostly present)
When `I` has a QUIC connection with peer `P`, record:
- `via_peer_id = P`,
- `origin_ip`, `origin_port` from `connection.remote_address()`,
- TTL via `peer_endpoint_observations`.

### B) Intro emission by introducer command
`I` chooses peers `A`, `B` and reads latest non-expired observation for each.

Then it sends two `IntroOffer` frames over existing authenticated QUIC control channels:
1. to `A`: contains `B`'s observed endpoint,
2. to `B`: contains `A`'s observed endpoint.

No cross-peer atomicity is required. Best-effort is fine.

### C) Punch execution on recipient
On receiving `IntroOffer`:
1. persist/update `intro_attempts` as `received`,
2. transition to `dialing`,
3. for up to a local dial window (default 4s), run paced `connect()` attempts to `(origin_ip, origin_port)` using the same local endpoint used by accept loop,
4. in parallel, keep accept loop active,
5. on authenticated direct connection with expected `other_peer_id`, mark `connected` and immediately start normal sync session (`NegOpen` path) over that connection,
6. on timeout, mark `failed`.

### D) Fallback behavior
If no direct path established:
- retain normal sync behavior through existing reachable peers,
- allow later re-intro with fresh observations.

## CLI surface (minimal)

Add:
1. `poc-7 intro --db <introducer.db> --peer-a <hex_spki> --peer-b <hex_spki> [--ttl-ms 30000]`
2. `poc-7 intro-attempts --db <peer.db> [--peer <hex_spki>]`

Optional later:
1. `poc-7 intro-worker --db <introducer.db> [--interval-ms 1000]` (continuous background emission; same logic as one-shot).

## Implementation phases

### Phase 1: Protocol and storage plumbing (minimal)
1. Add `IntroOffer` message type in `src/sync/mod.rs` and `src/sync/protocol.rs`.
2. Add migration for `intro_attempts`.
3. Add DB helpers to insert/update intro attempt status.
4. Add parser/encoder unit tests.

### Phase 2: Endpoint architecture refactor (required)
1. Replace split `create_server_endpoint` + `create_client_endpoint` runtime pattern with one shared endpoint per process.
2. Keep existing sync behavior unchanged while using shared endpoint.
3. Add regression tests proving accept + outbound connect still work.

### Phase 3: Introducer command and send path
1. Implement `intro` CLI command:
   - resolve freshest observation for `A` and `B`,
   - construct `IntroOffer`,
   - send to each peer over active control connection.
2. If connection is absent, fail/log clearly (v1) instead of introducing a durable intro queue.

### Phase 4: Receiver punch worker
1. Handle incoming `IntroOffer`.
2. Validate trust + expiry + dedupe.
3. Launch simple paced dial attempts with timeout (fixed local defaults).
4. Update `intro_attempts` statuses.
5. On success, run existing sync session on new direct connection.

### Phase 5: Optional automation + hardening
1. Add optional `intro-worker` loop command.
2. Rate-limit intros per introducer and per target peer.
3. Reject stale or malformed origin tuples.
4. Add bounded worker concurrency.
5. Add metrics/logs (`intro_received`, `intro_connected`, `intro_failed`, median dial latency).

## Test plan

### Unit tests
1. `IntroOffer` encode/decode roundtrip.
2. Expiry and dedupe validation.
3. DB helper idempotency for `intro_attempts`.

### Integration tests (real QUIC, no simulator)
1. Three-peer intro happy path:
   - `A <-> I`, `B <-> I`,
   - `I` sends intro,
   - assert eventually direct `A <-> B` sync succeeds.
2. Stale intro rejected:
   - expired `expires_at_ms`,
   - assert `status='expired'` and no dial attempt.
3. Untrusted target rejected:
   - `other_peer_id` not in allowed set,
   - assert `status='rejected'`.
4. Failure fallback:
   - introduce unreachable endpoint,
   - assert `status='failed'`,
   - assert normal sync path remains operational.
5. No canonical side effects:
   - after intro/punch runs, assert no intro rows/events appear in canonical event projections.

### Home NAT-equivalent test plan (realistic)
Use Linux network namespaces + nftables/conntrack to emulate two home routers and public internet.

Topology:
1. `ns_a` (peer A host) behind `ns_nat_a` (home NAT A).
2. `ns_b` (peer B host) behind `ns_nat_b` (home NAT B).
3. `ns_i` (introducer/public host) on a public bridge net.
4. `ns_nat_a` and `ns_nat_b` each have:
   - LAN interface to peer namespace,
   - WAN interface to public bridge.

Base router behavior (home-like):
1. Default deny inbound from WAN.
2. Allow `ESTABLISHED,RELATED`.
3. UDP SNAT/masquerade on outbound.
4. UDP mapping timeout in consumer range (for example 30s-120s).

NAT behavior matrix to run:
1. Endpoint-independent mapping + address-dependent filtering (most common home-style target).
2. Endpoint-independent mapping + address+port-dependent filtering (stricter home routers).
3. Endpoint-independent mapping + endpoint-independent filtering (easy/full-cone baseline).
4. Endpoint-dependent mapping (symmetric NAT; expected punch failure).

Per-matrix scenario:
1. Start A and B daemons behind NATs; start introducer I on public net.
2. A and B each establish QUIC session to I first (creates NAT mappings and endpoint observations).
3. I sends `IntroOffer` to A and B (one-shot intro command in v1; worker mode optional later), with short TTL and local dial window (for example 30s TTL, 4s dial window).
4. A and B execute paced simultaneous outbound dials to introduced endpoint while accept loop stays active.
5. If direct connect succeeds, verify immediate normal sync (`NegOpen` path) over direct A<->B connection.
6. If direct connect fails, verify fallback sync path still works and `intro_attempts.status='failed'`.

Realism knobs:
1. Add WAN latency/jitter/loss using `tc netem`:
   - 20-80ms latency,
   - 5-20ms jitter,
   - 0.5-2% packet loss,
   - optional 0.1-0.5% reordering.
2. Sweep introducer delay before intro send (for example 0ms, 500ms, 2s, 5s).
3. Sweep NAT UDP timeout and retry pacing to expose race windows.

Assertions per run:
1. `intro_attempts` terminal status matches expectation (`connected` for non-symmetric cases, usually `failed` for symmetric).
2. When `connected`, direct peer cert fingerprint equals `other_peer_id`.
3. No canonical intro artifacts appear in event projections.
4. Message/event sync correctness remains intact (same end-state assertions as normal scenario tests).

Execution tiers:
1. CI tier: namespace matrix with one representative home-style mode + symmetric-fail mode.
2. Nightly tier: full matrix with netem sweeps.
3. Optional real-world tier: two real residential links + cloud introducer soak test to validate non-emulated behavior.

### CLI assertions
Use existing `assert-eventually` style checks for automation, for example:
1. `intro_attempt_connected_count >= 1`
2. `recorded_events_count >= N` after direct sync

## Security notes
1. Intro sender does not bypass trust. mTLS pin checks still gate connection acceptance.
2. Receiver must verify actual remote cert fingerprint equals `other_peer_id` after connection.
3. Never auto-add trust from intro hints.
4. Apply small intro TTLs (for example 30s) to reduce stale endpoint abuse.

## Known limitations (v1)
1. Symmetric NAT pairs may still fail without TURN/relay.
2. Single-candidate endpoint may be insufficient for some networks.
3. No durable intro send queue in v1; introducer requires live connection to target peers.

These are acceptable for the first working cut because correctness does not depend on direct hole punch success.
