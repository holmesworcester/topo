# Transport/Event Identity Simplification Assessment

## Scope Executed

This execution implemented a focused simplification with two identity layers kept explicit:

1. Event-graph identity remains canonical (`event_id`).
2. Transport boundary identity is explicit (`transport_fingerprint`, SPKI hash).

Implemented outcomes:

1. `peers_shared.transport_fingerprint` is projected deterministically from `peer_shared.public_key`.
2. `(recorded_by, transport_fingerprint)` is indexed for direct lookup.
3. Reverse lookup helper exists: `transport_fingerprint -> peer_shared_event_id`.
4. Command-layer direct pending bootstrap trust writes were removed from invite creation paths.
5. Invite pending bootstrap trust still materializes via projection/autowrite.
6. Transport boundary readability improved with explicit `transport_fingerprint()` accessors.
7. Trust/removal SQL paths now use indexed `transport_fingerprint` lookups only.

## Simplifying Power

### Complexity Removed Now

1. Removed one authority path (service/command side) for pending bootstrap trust writes during invite creation.
2. Removed repeated scan-and-derive SPKI logic from hot trust/removal checks when projected fingerprints exist.
3. Made transport-to-event reasoning explicit and queryable by adding direct index-backed mapping.

### Complexity Still Present (By Constraint)

1. Bootstrap and steady-state transport identities must coexist transiently because handshake trust can precede identity graph convergence.
2. Single-endpoint + multi-tenant runtime requires transport identity checks independent of any single event lineage during ingress.
3. Local discovery can surface peers before full identity-chain convergence, so bootstrap fallback remains required.
4. Invite acceptance and graph sync are concurrent/distributed; a purely event-id-only transport gate cannot safely replace SPKI pinning at handshake time.
5. mTLS cannot provide two client certs in one handshake; fallback is necessarily retry-based, not a single-transaction key offer.

These barriers are structural, not naming artifacts.

## Net Effect

The model is now cleaner where it matters operationally:

1. Event graph answers "who" (`event_id` lineage).
2. Transport answers "which cert/SPKI" (`transport_fingerprint`).
3. Projection owns bridge materialization between them as much as current architecture allows.

## Remaining High-Value Simplifications

1. Remove remaining projection `EmitCommand` trust writes by projecting trust rows directly in-table (if projector contract evolution is accepted).
2. Add invite-expiry-derived bootstrap-key TTL policy (`bootstrap_key_expires_at = invite_expires_at + grace`) in a follow-up.
3. Add explicit retry-based ongoing-first/bootstrap-fallback dial policy at connection lifecycle boundary (still out of scope in this change).
