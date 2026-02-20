# Transport Trust Hardening Feedback

> **Historical document; file paths and module names may not match the current source tree.**

Commit reviewed: `4d64ead` (`Fix transport trust: observation-only bindings, deterministic signer, malformed blob skip`)

## Findings

### 1) Medium: transport key signer selection is deterministic but not identity-correct
- File: `src/transport_identity.rs:76`
- Current behavior:
  - `ensure_transport_key_event` picks `ORDER BY rowid ASC LIMIT 1` from `peers_shared`.
- Risk:
  - This can choose an arbitrary first peer in the workspace history, not necessarily the local peer identity.
  - If the selected `signed_by` event does not correspond to the provided local signing key, transport key creation will reject at signature verification.
  - The change removed nondeterminism, but not signer correctness.
- Recommended fix:
  1. Select signer by explicit local identity mapping (local peer/device event), not insertion order.
  2. Add a scenario where multiple `peers_shared` rows exist and the local row is not first, then assert transport-key creation still succeeds.

### 2) Low: scenario test name no longer matches asserted behavior
- File: `tests/scenario_test.rs:2089`
- Current behavior:
  - `test_transport_key_projects_and_populates_binding` now asserts bindings are *not* auto-populated.
- Risk:
  - Naming drift makes future reviews/maintenance harder.
- Recommended fix:
  1. Rename test to reflect current behavior, e.g. `test_transport_key_projects_without_auto_binding`.

## What looks good
- `allowed_peers_from_db` now trusts only `transport_keys` and ignores observation telemetry (`peer_transport_bindings`) by design.
- Malformed SPKI blobs are skipped rather than silently converted to zero fingerprints.
- Projection no longer auto-writes trust data from `TransportKey` side effects.

## Test evidence
- `cargo test db::transport_trust::tests:: -- --nocapture` passed.
- `cargo test test_transport_key -- --nocapture` passed.
