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

## Real proofs vs. fake proofs

The lint catches **syntactic** fakery (spec/proof fns with no ensures
citation). It cannot catch **semantic** fakery — abstract models that
pass `cargo-verus verify` but prove nothing about running code. Future
contributors and agents: read this section before writing a Verus file.

### What makes a proof REAL

A real proof has all three properties.

1. **The ensures is on an exec fn the runtime calls with varying
   inputs.** The runtime crate imports a `pub fn` via
   `pub use topo_verus_proofs::...`, passes real state-derived values
   into it, and consumes its output. The call site cannot be replaced
   by a constant without breaking the runtime's behavior.

2. **Changing the function body to something incorrect makes
   `cargo-verus verify` fail.** This is what the tamper test
   demonstrates. Flip a branch, break a comparison, drop a condition —
   the SMT solver must produce "postcondition not satisfied." If you
   can mutate the body freely without breaking verification, the
   `ensures` is too weak to be a real proof.

3. **If the runtime has a bug that violates the stated property, the
   proof catches it.** Invert this: if you introduce a runtime bug
   that should make the invariant false, does a gate anywhere in the
   pipeline fail? If no gate fails, the proof isn't protecting
   anything.

### What makes a proof FAKE (even if verification passes)

Any of these disqualify a proof even if `cargo-verus verify` reports
`N verified, 0 errors`:

- **Abstract model with no refinement bridge.** A verified `apply_spec`
  over a Verus-only `Seq<Event>` says nothing about the runtime's
  `apply_projection` unless a theorem mechanically ties one to the
  other. Defining abstract machinery and *believing* it corresponds
  to the runtime is not a proof.

- **Exec fn the runtime calls with tautologically-constant inputs.**
  A `pub fn check(a, b, c, d)` whose ensures requires `a && b && c && d`,
  called as `debug_assert!(check(true, true, true, true))`, is
  worthless. The runtime never exercises the interesting cases.

- **Exec fn the runtime imports but doesn't meaningfully invoke.** If
  the grounding is only a test-only or unused import, the lint is
  satisfied but nothing is protected.

- **Spec fn cited only by a soundness lemma with trivial body.** A
  proof fn whose ensures is a tautology (`P || !P`) grounds spec-fn
  names for the lint but proves nothing.

- **Projector mapping encoded wrong.** If your primitive-input check
  uses `kind_code == 3` for "InviteAccepted" but the runtime emits
  kind_code 9, the proof is mechanically sound against the model and
  mechanically worthless against the code. Always cross-check
  constants against the runtime registry (see
  `src/event_modules/mod.rs::EVENT_TYPE_*`).

- **Ensures clause that restates the implementation.** `ensures out == body(args)`
  where the ensures is a copy of the body proves only that Rust
  evaluates deterministically. Real ensures state *properties* the body
  must satisfy, not the body itself.

### Self-test questions before merging a proof

Answer all five honestly. If any is "no," the proof is fake.

1. Does the runtime crate `import` a verified `pub fn` from this file?
2. Does the runtime pass state-derived values (not constants) into
   that fn and act on the result?
3. If I flip the `ensures` condition to its negation, does
   `cargo-verus verify` fail with a concrete counterexample?
4. If I introduce a plausible runtime bug that violates the stated
   property, does a gate in the merge-readiness pipeline fail?
5. Does the proof's abstract state (any `Seq`, `Set`, `Map` in spec
   position) correspond to real runtime state through a named and
   verified mapping — or at minimum through a runtime test that
   cross-validates?

### The `access_control.rs` cautionary tale

In April 2026 an access-control proof (`verus-proofs/src/state/access_control.rs`,
commits 87a0e9f0..4482e534) was merged claiming to prove "non-invited peer
cannot decrypt workspace messages." It passed Verus, the lint, and all
gates. It was later reverted as a fake proof.

What went wrong:

- The `apply_spec` inductive invariant was over a `PeerState` type
  with no mapping to runtime `NodeBehaviorEngine` or the SQL-backed
  projector state.
- The refinement-bridge exec fn `abstract_apply_accepts_primitives`
  was called from the runtime with all-true flags, making the check
  tautological in the accepted path. The runtime never computed
  non-trivial flags from real state.
- The kind_code constants didn't match the runtime registry
  (`InviteAccepted=3` in the proof, `9` in the runtime), so even
  when the check was non-tautological it was exercising the wrong
  branches.
- Result: 16 verified items, zero runtime bugs caught, zero
  protection against future regressions. Every self-test question
  above answered "no."

The lesson: **a proof whose abstract state has no refinement mapping
to runtime state is documentation at best, noise at worst.** The sim
(`src/sim/node_behavior.rs`) is the intended refinement target for
system-level invariants — a real proof over the sim would have the
runtime calling verified primitive predicates over sim-derived
primitive state, with the sim's state serving as the abstract model
whose relationship to production-projector state is covered by
existing shared-projector-code tests.

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
