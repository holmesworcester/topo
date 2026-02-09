# Transport Identity Rename Plan

## 1. Goal

Rename the current `identity` module/API to make clear it is **transport identity**
(mTLS cert/key + SPKI-derived peer id), not event-graph identity.

This avoids conceptual collision with upcoming event identity/projector work.

## 2. Scope

In scope:
- Module rename: `src/identity.rs` -> `src/transport_identity.rs`
- API rename to `transport_*` / `*_transport_*` names
- CLI command rename from `identity` terminology to transport-specific terminology
- Documentation and test utility call-site updates
- Temporary compatibility shims to avoid breaking in-flight work

Out of scope:
- Changing transport semantics, cert generation, or peer-id derivation
- Changing event-graph identity semantics

## 3. Current Mapping

Current file responsibilities (`src/identity.rs`):
- Derive cert/key file paths from DB path
- Load cert/key and compute SPKI fingerprint
- Ensure cert/key exists (generate if needed)

Current usage points:
- `src/main.rs` (`identity`, `backfill-identity`, message/query scoping)
- `src/testutil.rs`
- `src/lib.rs` (`pub mod identity`)

## 4. Target Names

### 4.1 Module
- `identity` -> `transport_identity`

### 4.2 Functions
- `cert_paths_from_db` -> `transport_cert_paths_from_db`
- `load_identity_from_db` -> `load_transport_peer_id_from_db`
- `local_identity_from_db` -> `ensure_transport_peer_id_from_db`

### 4.3 CLI commands
- `identity` -> `transport-identity`
- `backfill-identity` -> `backfill-transport-identity`

Compatibility:
- Keep `identity` and `backfill-identity` as aliases for one phase window.

## 5. Migration Strategy

## 5.1 Phase A: Add New Names Without Breakage

1. Add `src/transport_identity.rs` with the renamed functions.
2. Keep `src/identity.rs` as compatibility shim that re-exports wrappers to new names.
3. In `src/lib.rs`, export both modules for transition:
   - `pub mod transport_identity;`
   - `pub mod identity;` (shim only)

Acceptance:
- Build/test behavior unchanged.
- Existing callers compile unchanged.

## 5.2 Phase B: Switch Internal Callers

1. Update `src/main.rs` imports/calls to new module/function names.
2. Update `src/testutil.rs` imports/calls.
3. Update any remaining internal references found by `rg`.

Acceptance:
- No internal production code depends on old names (except shim file itself).

## 5.3 Phase C: CLI Surface Rename

1. Rename subcommands to transport-specific names.
2. Keep legacy names as aliases.
3. Update `--help` text to explicitly say:
   - “transport identity (cert/key/SPKI)”
   - separate from event-graph identity.

Acceptance:
- Both old and new command names function.
- Help output is explicit about scope.

## 5.4 Phase D: Docs and Plan Alignment

1. Update `docs/PLAN.md` and `docs/DESIGN.md` terminology:
   - use “transport identity” for mTLS/cert scope
   - reserve “identity” for event graph semantics
2. Add one short glossary note if needed.

Acceptance:
- No ambiguous identity wording in active docs.

## 5.5 Phase E: Shim Removal (Later)

Do only after downstream tooling/scripts are updated.

1. Remove `src/identity.rs` shim.
2. Remove CLI aliases.
3. Keep only transport-specific names.

Acceptance:
- `rg` shows no legacy symbol usage.

## 6. Verification Checklist

Code checks:
- `rg -n "use .*identity|identity::|load_identity_from_db|local_identity_from_db|cert_paths_from_db" src`
- `cargo test`
- CLI smoke:
  - `poc-7 transport-identity -d <db>`
  - `poc-7 identity -d <db>` (alias path)
  - `poc-7 backfill-transport-identity -d <db>`
  - `poc-7 backfill-identity -d <db>` (alias path)

Behavior checks:
- Same peer id output before/after rename for same cert files.
- Message/status commands still scope by the same local transport peer id.

## 7. Risks and Mitigations

Risk: silent semantic confusion remains.
- Mitigation: explicit transport wording in CLI help and docs.

Risk: break scripts relying on old command names.
- Mitigation: alias window before removal.

Risk: accidental coupling with event identity.
- Mitigation: naming convention rule:
  - transport layer uses `transport_*`
  - event graph identity uses `identity_*` or explicit type names.

## 8. Done Criteria

This rename is complete when:
1. Internal code uses only `transport_identity` names.
2. Docs clearly separate transport vs event identity.
3. Legacy aliases exist only as temporary compatibility layer.
4. No behavior change in cert/key/SPKI derivation or recorded-by scoping.
