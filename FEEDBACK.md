# Feedback: `fix/transportkey-deterministic-emission`

## Decision
You are correct: there is no strong protocol reason to make **shared** `transport_key` unsigned.

Deterministic local credential derivation and replay stability can be handled with a local event/state model, while the shared trust-binding event should remain signed.

## Blocking Findings

1. Security regression: shared `transport_key` is unsigned
- `src/events/transport_key.rs` sets `signer_required=false` and removes signature fields.
- This lets peers project trust bindings without cryptographic authorization into `transport_keys`.

2. Dependency typing is too loose for `transport_key`
- `dep_field_type_codes` for `peer_shared_event_id` is unconstrained (`&[&[]]`).
- A non-`peer_shared` event can satisfy dependency shape.

3. Fixed-size parse strictness regression
- `parse_transport_key` checks only `len < 73` and accepts trailing bytes.
- Fixed-size canonical event parsing should reject any trailing bytes.

4. CLI/query startup regression on fresh DB
- Several commands now load transport identity before `create_tables`, producing:
  `no such table: local_transport_credentials`.
- Repro: `cargo run --quiet -- status --db /tmp/new.db`.

5. Nondeterministic `PeerShared` selection in `ensure_transport_key_event`
- Query uses `LIMIT 1` with no stable/local-key discriminator.
- In multi-peer-shared scopes this can bind to the wrong row.

## Required Direction (for this branch)

1. Keep shared `TransportKey` signed
- Restore signed wire format and signer metadata.
- Restore signer verification pipeline participation.
- Require signer to be local `peer_shared` identity key.

2. Keep deterministic local modeling separate
- If desired, introduce a separate local-only unsigned deterministic credential event/state.
- Do not conflate that with shared trust authorization event.

3. Keep SQLite credential storage work only if continuity is safe
- Add explicit file-to-SQLite continuity migration path.
- If both sources exist and mismatch, fail loudly.

## Concrete Plan

### Phase A: Restore protocol safety first
1. Revert `TransportKeyEvent` schema to signed version.
2. Restore `ParsedEvent::signer_fields()` for `TransportKey`.
3. Set strict dep type constraints for signer ref (`peer_shared_first|peer_shared_ongoing` as applicable).
4. Use `create_signed_event_sync` again for `TransportKey` creation paths.
5. Make `ensure_transport_key_event` choose signer by explicit local key match, not `LIMIT 1`.
6. Reinstate fixed-size strict parse (`TooShort` and `TrailingData`).

### Phase B: Keep SQLite credential migration coherent
1. Ensure `create_tables` runs before any identity load on all CLI read commands.
2. Implement continuity import:
- if SQLite empty and legacy files exist, import them,
- preserve fingerprint continuity,
- reject/flag mismatch when both exist and differ.
3. Keep file APIs as compatibility path only during migration window.

### Phase C: Tests required before merge
1. Invalid-signer `transport_key` is rejected.
2. `transport_key` dependency type mismatch rejects.
3. Fixed-size parser rejects trailing bytes.
4. Fresh DB `status/users/keys/workspaces/messages` do not fail on missing `local_transport_credentials` table.
5. Continuity test: file-backed legacy identity imported unchanged into SQLite.
6. `holepunch_test::test_three_peer_intro_happy_path` passes.
7. `scenario_test` transport-key replay/invariant tests pass.

## Merge Gate
Do not merge this branch until Phase A is complete and tests in Phase C are green.
