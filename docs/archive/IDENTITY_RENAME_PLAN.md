# Transport Identity Rename — Completed

**Status: Complete.** All phases landed. No legacy symbols or aliases remain.

## Summary

Renamed the `identity` module/API to `transport_identity` to distinguish
transport-layer identity (mTLS cert/key + SPKI-derived peer id) from
event-graph identity.

## What Changed

| Before | After |
|---|---|
| `src/identity.rs` | `src/transport_identity.rs` |
| `cert_paths_from_db` | `transport_cert_paths_from_db` |
| `load_identity_from_db` | `load_transport_peer_id_from_db` |
| `local_identity_from_db` | `ensure_transport_peer_id_from_db` |
| CLI `identity` | CLI `transport-identity` |
| CLI `backfill-identity` | CLI `backfill-transport-identity` |

## Phase History

- **Phase A** — Added `src/transport_identity.rs`; kept `src/identity.rs` as compat shim.
- **Phase B** — Switched all internal callers to `transport_identity::*` names.
- **Phase C** — Renamed CLI subcommands; kept old names as temporary aliases.
- **Phase D** — Updated docs terminology.
- **Phase E** — Removed `src/identity.rs` shim, removed CLI aliases. (This commit.)

## Naming Convention

- Transport layer: `transport_*` prefix (e.g. `transport_cert_paths_from_db`).
- Event-graph identity: `identity_*` or explicit type names (e.g. `identity_ops`).
