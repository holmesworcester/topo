# Phase 0 Feedback (`ce4d4de`)

Scope reviewed:
- Commit `ce4d4de` (`Implement Phase 0: mTLS + QUIC with SPKI-pinned certificates`)
- Files: `src/transport/mod.rs`, `src/transport/cert.rs`, `src/sync/engine.rs`, `src/main.rs`, `src/testutil.rs`, `tests/cli_test.rs`

What Phase 0 did well:
- Replaced permissive transport with explicit SPKI pin checks for both client and server cert verification.
- Added CLI identity command for stable fingerprint discovery.
- Added integration coverage for pinned and unpinned behavior.
- Kept peer identity derivation aligned with TLS cert material (`peer_id = SPKI fingerprint`).

## Findings (severity ordered)

1. High: known shutdown race can drop events at scale.
- Evidence: explicit TODO in `src/sync/engine.rs` noting stream-close before peer drain can lose events.
- Impact: rare data loss under high volume undermines convergence guarantees.
- Action:
  - add explicit control-plane shutdown handshake (`Done` -> drain/flush -> `DoneAck`),
  - close data stream only after writer drain + queue empty,
  - add stress test that checks zero-loss at high volume.

2. Medium: cert/key persistence should be hardened.
- Evidence: `src/transport/cert.rs` writes key/cert directly with `std::fs::write`.
- Impact: potential torn writes on crash and weak default file permissions for private keys.
- Action:
  - write temp file + fsync + rename for atomic replacement,
  - set private key mode to owner-only (`0600`) on Unix,
  - add load-time validation that cert public key matches private key.

3. Medium: empty pin set is accepted but produces confusing sync behavior.
- Evidence: `run_sync` in `src/main.rs` allows empty `--pin-peer`; verifier then rejects everyone.
- Impact: operator confusion ("sync runs but nothing connects").
- Action:
  - fail fast when pin set is empty unless an explicit dev-only override flag is set.

4. Medium: identity extraction path is brittle to upstream type changes.
- Evidence: `peer_identity_from_connection` in `src/transport/mod.rs` downcasts peer identity to `Vec<CertificateDer<'static>>`.
- Impact: potential breakage on quinn/rustls API representation changes.
- Action:
  - isolate this behind one compatibility helper,
  - add a dedicated integration test that asserts identity extraction across the live QUIC handshake.

## Test additions recommended before moving deep into identity

1. Transport reliability soak:
- high-volume sync with strict equality on event IDs (not just counts), no missing rows after repeated runs.

2. Certificate persistence checks:
- restart process and verify identical fingerprint,
- detect/handle mismatched cert/key files cleanly.

3. Pin policy UX:
- empty pin list returns immediate CLI error with remediation text.

4. Rejection observability:
- expose counters/logs for cert rejection and handshake failures to help diagnose field issues.

## Guidance for assistant follow-up

1. Fix shutdown correctness first (reliability bug beats all hardening work).
2. Harden cert/key persistence second (atomic + permissions + validation).
3. Add fast-fail pin policy and tests.
4. Keep this phase transport-focused; defer identity semantics to planned later phases.
