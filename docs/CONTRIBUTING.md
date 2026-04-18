# Contributing

## Local Git Hooks

Enable repo-local hooks once after cloning:

```bash
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit
```

The pre-commit hook runs:

```bash
cargo fmt --all -- --check
```

This prevents formatting-only drift from reaching commits and keeps CI formatting checks green.

## Verus proofs — the rules

The `topo-verus-proofs` crate is a **path-dep of `topo`**, not an abstract
parallel mirror. See `docs/DESIGN.md §"Verus Proof Model"` for the full
rationale. In one paragraph: every seam's normalizer/planner is written as an
executable `pub fn` inside a `verus!` block with `requires`/`ensures` that
`cargo-verus verify` SMT-checks against the actual function body. The runtime
imports those functions via `pub use topo_verus_proofs::…` and calls them
directly. A body change that violates an `ensures` fails the merge gate.

**Hard rules:**

1. **The proof tree mirrors `src/` one-for-one.** A proof at
   `verus-proofs/src/state/db/queue.rs` must prove something about
   `src/state/db/queue.rs`. No top-level dumping grounds. See `lib.rs` in
   the proofs crate for the canonical statement.

2. **No fake proofs.** A `spec fn` or `proof fn` without a grounded exec-fn
   citation is a fake. The lint `scripts/check_no_fake_proofs.py` enforces
   this and runs in the primary merge gate. If you add a spec without a
   grounded ensures, the gate fails. See "When a spec fn is legitimate"
   below for the two exceptions.

3. **Every `ensures` is checked against a real body.** The tamper test
   `scripts/verus_tamper_test.sh` flips an ensures-protected function body
   on every merge-gate run and asserts `cargo-verus verify` reports
   "postcondition not satisfied". If the tamper test passes (meaning the
   SMT-on-real-bodies guarantee ever stops biting), the gate fails.

4. **Runtime imports only exec fns with ensures.** Never import a
   `spec fn` or `proof fn` into runtime code. Importing a spec fn doesn't
   compile; importing a proof fn is nonsense. Runtime-callable items all
   live as `pub fn` inside `verus!` with `ensures` clauses.

## When a spec fn is legitimate

Exactly two cases are allowed (and the lint script's `EXEMPT_FILES` lists
them by path):

- **`bug_hunt.rs`**: counterexample proofs of known runtime bugs, not of
  correctness. Each `finding_*` demonstrates an undesired behavior the
  current runtime still exhibits. When the bug is fixed, flip the
  counterexample into a positive invariant on the fixing seam and remove
  the entry here. A shrinking `bug_hunt.rs` is progress.

- **`runtime/transport/session_auth.rs::*_spec`**: three protocol-frame
  predicates (`peer_shared_auth_spec`, `invite_bootstrap_auth_spec`,
  `inbound_auth_spec`) cited structurally by grounded `*_decide` exec fns
  in the same file. The runtime cross-checks the decide-fn outcome against
  its own richer auth planner via `debug_assert_eq!` at each call site,
  so the spec is pinned to runtime behavior even though it isn't directly
  called.

Adding a third case requires: (a) writing the justification as a file-level
doc comment, (b) adding the path to `EXEMPT_FILES` in
`scripts/check_no_fake_proofs.py` with the same justification, (c) a code
review that explicitly approves the exemption.

## Merge-readiness

Run `scripts/run_merge_readiness_checks.sh targeted` before opening a PR.
The primary formal gate runs boundary tests, projector-family coverage,
`check_no_fake_proofs.py`, `cargo-verus verify`, the tamper test, then the
serial runtime regressions. ~2.5s warm for the Verus half.

Do not skip the formal gate. If Verus flags drift that looks like a false
alarm, it isn't: investigate the delta. `cargo-verus verify` is total over
its input, so any failure is a concrete counterexample to a concrete
`ensures` clause.
