# Feedback: `exec/all-remaining-todos-20260217` (`23ce217`)

## Verdict

Not ready to merge yet. Runtime/tests/model checks are green, but there are still doc/claim mismatches against the TODO closure statements.

## Findings (ordered by severity)

1. High: TODO marks `#11/#19` as fully done, but PLAN/DESIGN still contain stale transport-key and invite-link semantics.
- `TODO.md:49` and `TODO.md:57` claim full closure/alignment.
- `docs/PLAN.md:1653` and `docs/PLAN.md:1666` still say `local_transport_creds` is populated by bootstrap flow creating `TransportKey` events.
- `docs/PLAN.md:1106` says invite links contain wrapped content-key material and "transport key identity metadata".
- `docs/DESIGN.md:229` and `docs/DESIGN.md:794` say wrapped bootstrap key material is embedded in invite link.
- Code reality: wrapped key material flows through `secret_shared` events (`src/identity_ops.rs`), while invite link payload does not carry wrapped key material (`src/invite_link.rs`).

2. High: TODO marks `#20` as fully done, but unused compatibility schema still exists.
- `TODO.md:58` claims residual compatibility cruft cleanup done.
- `src/db/migrations.rs:135` still creates `ingress_queue`.
- `docs/PLAN.md:809` and `docs/PLAN.md:826` still describe `ingress_queue` as schema-only.
- This is compatible with "partial cleanup", not full closure under current TODO acceptance text.

3. Medium: "no silent regeneration" claim is not strictly true in bootstrap helper path.
- `TODO.md:49` says "No ... silent regeneration."
- `src/sync/bootstrap.rs:46` uses `ensure_transport_cert_from_db(...)`, which can generate credentials when missing.
- If this path is intended to require pre-installed invite-derived identity, it should load-required/fail-fast instead of ensure-generate.

4. Low: interactive message display now suppresses reaction-query errors.
- `src/interactive.rs:604` uses `svc_reactions_for_message_conn(...).unwrap_or_default()`.
- Previous behavior propagated query errors; now DB/query issues are silently hidden.

5. Low: stale code comment after trust-source shift.
- `src/db/transport_trust.rs:43` still says allowlist trust queries `transport_keys`.

## What looks good

1. Core runtime changes for transport trust source shift are coherent.
2. Interactive SQL dedupe into service helpers is substantial and in the right direction.
3. Added out-of-order/bootstrap tests are useful and pass.
4. Validation run results are green:
- `cargo test -q`
- `docs/tla/tlc event_graph_schema_fast.cfg`
- `docs/tla/tlc TransportCredentialLifecycle transport_credential_lifecycle_fast.cfg`

## Required fixes before merge

1. Update PLAN/DESIGN text to match implemented wrap/unwrap flow:
- wrapped key via `secret_shared` events, not invite-link payload.
- remove stale "TransportKey event populates creds" statements.
2. Reclassify TODO status for `#20` to partial unless `ingress_queue` is actually removed from active schema/migrations in this round.
3. Decide and enforce bootstrap-sync credential precondition:
- either switch `bootstrap_sync_from_invite` to load-required (preferred for strict semantics),
- or keep ensure-generate and relax TODO wording ("no silent regeneration") accordingly.
4. Change `interactive.rs` reactions enrichment to propagate errors (or explicitly log+document intentional best-effort behavior).
5. Fix stale trust comment in `src/db/transport_trust.rs`.

## Integration note

Branch is currently behind `master` and should be rebased after the above fixes.
