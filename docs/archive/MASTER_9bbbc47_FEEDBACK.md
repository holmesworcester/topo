# Feedback: `master` Commit `9bbbc47`

> **Historical document; file paths and module names may not match the current source tree.**

Commit reviewed:
- `9bbbc4782311914d3176680cf949a834746e4247`
- Subject: `Implement transport identity rename, projected trust, and TransportKey events`

Scope reviewed:
- transport trust source changes
- TransportKey projection/event handling
- sync path trust population
- identity helper additions

## Findings

### 1. High: connection-observed bindings are promoted to long-lived trust authority

`allowed_peers_from_db` treats `peer_transport_bindings` as an authority source, not just telemetry/cache.  
At the same time, sync paths persist every successful TLS peer fingerprint into that table.

Evidence:
- `src/db/transport_trust.rs:33` unions `transport_keys` with `peer_transport_bindings`.
- `src/sync/engine.rs:834` and `src/sync/engine.rs:953` persist connection-observed fingerprints via `record_transport_binding`.
- No runtime removal path for `peer_transport_bindings` is present in this commit (only test cleanup in `src/testutil.rs`).

Impact:
- Any fingerprint once admitted (for example via temporary CLI pin) can remain trusted indefinitely.
- Identity-policy changes (for example removal) do not automatically revoke this trust source.
- This conflicts with “projected trust as authority” direction and can preserve stale trust.

Suggested fix:
- Treat `peer_transport_bindings` as observation cache only (not allowlist authority), or gate it with explicit TTL + identity-policy validation.
- Use `transport_keys`/identity-projected state as the authoritative allowlist source.

### 2. High: TransportKey projection does not actually bind SPKI to peer identity

The new table shape includes `peer_id`, but projection writes `peer_id = hex(spki_fingerprint)`, so the binding is effectively `spki -> spki`, not `peer_shared_identity -> spki`.

Evidence:
- Schema introduces `peer_id` in `peer_transport_bindings`: `src/db/migrations.rs:266`.
- Projection assigns `peer_id` from SPKI itself: `src/projection/identity.rs:285`.
- TransportKey event contains `signed_by` but this signer identity is not materialized into binding rows.

Impact:
- The implementation does not enforce “SPKI belongs to signer’s peer identity”.
- Key rotation / multiple certs per peer modeling is blocked by current `(recorded_by, peer_id)` semantics when `peer_id` is overloaded.
- It diverges from commit intent (“bind SPKI fingerprints to PeerShared identity”).

Suggested fix:
- Resolve signer (`signed_by`) to a stable peer identity and persist that as `peer_id`.
- Keep SPKI as a separate column and enforce uniqueness/active-selection policy per peer.

### 3. Medium: `ensure_transport_key_event` selects arbitrary `peers_shared` row

The helper chooses signer with `LIMIT 1` from all `peers_shared` rows under tenant scope.

Evidence:
- `src/transport_identity.rs:77` query: `SELECT event_id FROM peers_shared WHERE recorded_by = ?1 LIMIT 1`.

Impact:
- In multi-peer state, this can pick a non-local peer-shared event id.
- If used for auto-publishing local TransportKey, event creation may fail or mis-bind signer selection.

Suggested fix:
- Select the local peer’s specific `peers_shared` signer deterministically (or require signer event id input).
- Avoid implicit `LIMIT 1` selection for identity-critical signing.

### 4. Low: malformed SPKI blobs silently become all-zero fingerprints

When reading DB trust rows, invalid blob lengths are not rejected; code returns `[0u8; 32]`.

Evidence:
- `src/db/transport_trust.rs:42` reads blob.
- `src/db/transport_trust.rs:44` copies only if len == 32; otherwise returns zeroed array.

Impact:
- Silent data corruption handling; invalid rows are not surfaced.
- Could produce misleading allowlist contents.

Suggested fix:
- Skip invalid rows with logging, or return an error on invalid length.

## Test Gaps

Missing coverage for the above risk areas:
- No test that removal/revocation drops effective transport trust from prior observations.
- No test that TransportKey binds SPKI to signer identity (not just “row inserted”).
- No test for malformed `spki_fingerprint` row handling.

## Summary

The commit adds useful transport trust plumbing, but currently mixes authority and observation, and does not complete identity-bound SPKI semantics.  
The two high-severity issues should be resolved before treating projected transport trust as a policy source.
