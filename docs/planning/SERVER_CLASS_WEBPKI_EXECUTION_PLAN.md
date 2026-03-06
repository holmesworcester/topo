# Server-Class WebPKI Endpoint Plan

Date: 2026-03-06  
Branch: `plan/server-peer-tls-mode`  
Worktree: `/home/holmes/poc-7-server-peer-instructions`

## Objective

Add a new remote peer class (`server`) for outbound-only cloud dialing, where clients trust a public TLS cert chain (OS/CA/DNS/TLS) instead of transport-fingerprint pinning for that remote.

## Clarification: what "6" meant in prior notes

Current `connect_loop` has bootstrap fallback logic:

1. Try ongoing tenant client config (peer/fingerprint trust path).
2. If trust-rejected, optionally retry with invite bootstrap fallback cert.

Code path: `dial_provider_ongoing_first` in `src/runtime/peering/loops/connect.rs`.

In `server + webpki` mode, this fallback is not meaningful and should be disabled for server targets.

## Design Choice Matrix

### Option A (recommended): Maximally isomorphic

1. Keep client identity model unchanged for now (client still presents existing transport cert).
2. Add per-target server-auth mode:
   - `peer` (current): fingerprint-based dynamic trust
   - `server/webpki`: CA+SNI-based server verification
3. Keep sync/session/event pipeline unchanged.
4. Keep multi-tenant routing by existing `recorded_by`/workspace model.

Why:

1. Minimal change to protocol semantics.
2. Preserves existing authorization/event isomorphism.
3. Leaves a clean path to fully non-mTLS later.

### Option B: Maximally boring cloud portability

1. Drop transport client certs for this path.
2. Add app-layer signed session hello (nonce challenge signed by peer_shared/user key).
3. Route tenant/workspace from signed claims + projected auth graph.

Why not first:

1. Larger protocol change.
2. More test surface and rollout risk.
3. Needed only if strict "no client cert ever" is mandatory.

## Traits for maximal cloud compatibility while matching this system

1. Outbound-only client dials (NAT/firewall friendly).
2. Public DNS + standard TLS cert at server endpoint.
3. Long-lived stateful daemon with persistent DB volume.
4. Same sync frame protocol and event validation rules.
5. Explicit per-target auth mode in config (not global transport fork).
6. No assumption of local multicast discovery in cloud path.

## Cloud platform fit

### Works well (native QUIC daemon)

1. VPS/Lightsail/EC2/Fly.io style always-on runtimes with UDP socket control and persistent disk.

### Not a good fit for native daemon

1. AWS Lambda: request/invocation model with max 900s execution.
2. Cloudflare Workers: outbound TCP available; inbound TCP not generally available, and no native inbound UDP daemon model.
3. Vercel functions: bounded request-duration model.

If Lambda/Workers are mandatory, build a separate HTTP/WebSocket relay transport and bridge to persistent sync nodes; do not force native QUIC daemon into serverless request runtimes.

## Proposed model in code

Add new concepts:

1. `RemoteClass`:
   - `Peer` (existing)
   - `Server` (new)
2. `ServerAuthMode`:
   - `PeerFingerprint` (existing behavior)
   - `WebPkiCa` (new)
   - `WebPkiCaAndPin` (optional hardening)
3. `DialTargetKind`:
   - `BootstrapInvite`
   - `Discovery`
   - `ServerConfig`

## Multi-tenant + workspace identification

### Phase 1 (recommended, isomorphic):

1. Keep existing tenant-scoped loop ownership (`recorded_by` fixed by planner assignment).
2. Keep existing workspace resolution from `lookup_workspace_id(recorded_by)`.
3. Keep existing transport-derived remote fingerprint telemetry (`peer_id`) for source attribution.

This means we do not break current event/projection ownership or queue semantics.

### If later removing transit key/client cert (Phase 2):

1. Add protocol-level signed session hello:
   - client sends `(workspace_id, tenant_id, nonce, timestamp, signature)`.
2. Server verifies against projected identity graph.
3. Server binds connection to tenant/workspace after signature verification.

## Add-server user flow (Phase 1)

1. Admin configures server target on local node:
   - `topo add-server --name cloud-a --addr cloud.example.com:4433 --sni cloud.example.com --workspace <workspace-id> --tenant <tenant-id> --auth webpki`
2. Runtime target planner emits this target as `ServerConfig`.
3. Connect loop dials target with server-mode client config (WebPKI verify).
4. Sessions run unchanged through existing sync/session pipeline.
5. Access control remains event-layer validity + existing tenant scoping.

Optional hardening:

1. Add `--pin-spki` to require both CA trust and expected SPKI.

## File-level implementation plan

### Phase 1A: data + CLI/RPC surface

1. Add persistent server target table (new db module under `src/state/db/`):
   - columns: `name`, `addr`, `sni`, `tenant_id`, `workspace_id`, `auth_mode`, `enabled`, `created_at`.
2. Add RPC methods in `src/runtime/control/rpc/protocol.rs`:
   - `AddServer`, `ListServers`, `RemoveServer`, `EnableServer`, `DisableServer`.
3. Wire handlers in `src/runtime/control/rpc/server.rs`.
4. Add CLI commands in `src/runtime/control/main.rs`.

### Phase 1B: transport auth-mode split

1. In `src/runtime/transport/mod.rs`:
   - keep current pinned verifier path untouched.
   - add WebPKI client-config builder (`with_root_certificates` + `with_no_client_auth`).
2. In `src/runtime/transport/peering_boundary.rs`:
   - add builder for server-mode client config from server target config.
3. Keep server-side accept path unchanged in phase 1.

### Phase 1C: planner + dial integration

1. Extend `src/runtime/peering/engine/target_planner.rs` to emit server targets.
2. Extend target dispatcher in `src/runtime/peering/engine/supervisor.rs` to route server targets with correct client config.
3. In `src/runtime/peering/loops/connect.rs`:
   - allow explicit SNI from target (do not force workspace-derived SNI for server class).
   - disable bootstrap fallback branch for `ServerConfig` dial targets.

### Phase 1D: tests

1. Unit tests:
   - server target CRUD
   - auth mode parsing/validation
   - planner emits server targets
2. Integration tests:
   - outbound dial to local QUIC endpoint with CA-issued test cert + matching SNI
   - failure on bad SNI / bad chain
   - verify no bootstrap fallback retry in server mode
3. Regression:
   - existing p2p/mTLS paths unchanged.

## Isomorphism guidance

1. Keep this as a transport auth policy at dial-target edge.
2. Do not fork event semantics or projector ownership.
3. Avoid introducing "special server event types" in phase 1.
4. If deeper isomorphism is desired later, abstract transport auth mode for all targets, not just server class.

## Lambda/Workers guidance

1. Do not target Lambda/Workers as native QUIC daemon hosts.
2. If required, add a separate relay transport (HTTP/WebSocket) that terminates in always-on stateful nodes.
3. Keep the core sync protocol and event validation identical behind that relay seam.

## Rollout strategy

1. Ship feature-flagged (`P7_ENABLE_SERVER_TARGETS`) and default-off.
2. Land CLI/RPC + DB first.
3. Land transport mode split second.
4. Land planner wiring third.
5. Enable in tests and one dev scenario.

## Final step (required)

1. Commit the completed implementation work on this same worktree branch before handoff/review.
