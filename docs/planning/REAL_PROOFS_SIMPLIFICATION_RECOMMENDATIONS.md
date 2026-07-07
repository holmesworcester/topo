# Real Proofs Simplification Recommendations

Date: 2026-04-22
Branch: `remove-fake-proof-and-try-real`
Worktree: `/home/holmes/poc-7-real-proof`

## Purpose

Capture the highest-value codebase simplifications for the "real proofs"
direction, with emphasis on:

1. making proof-bearing seams smaller and more uniform,
2. reducing ad hoc projector/context SQL,
3. aligning simulator structure with a believable refinement story,
4. pushing more semantics into the event graph instead of ambient local state.

This is a recommendations note, not an execution plan. It records the target
shape that later execution plans should converge toward.

## Recommended End State

The cleanest overall shape is:

```text
command / wire / runtime input
  -> append canonical event
  -> one canonical projection/apply path
  -> generic dep resolution
  -> typed dep facts + typed guard facts
  -> verified planner core
  -> capability-gated executor
  -> observable read state
```

The repo is already close to this in several places:

1. the preferred seam shape in `docs/DESIGN.md`,
2. the real exec-fn proof model in `docs/CONTRIBUTING.md`,
3. the shared projection engine over `ProjectionBackend`,
4. the in-process simulator/daemon bridges in `src/sim`.

The main simplification opportunity is to remove duplicate representations of
the same behavior and make "context" much more uniform.

## Core Recommendations

### 1. Standardize decision context around deps first

Recommendation:

1. Make the default projector/context model consume a resolved set of
   immediate event deps.
2. Have the generic dep loader return typed summaries for those deps, not only
   `Missing / Ready / Reject / Purge` plus semantic type.
3. Rewrite most event-specific context loaders as pure functions over:
   - the current parsed event,
   - the typed dep bundle,
   - a small standardized guard bundle.

Target shape:

```text
self event + dep facts + guard facts -> planner core -> plan/effects
```

Why:

1. Most acceptance and planning decisions are based on one-level-deep valid
   deps, not arbitrary SQL over the whole materialized DB.
2. This is more faithful to the event-sourced model.
3. It makes projector context more uniform and easier to review.
4. It makes Verus proofs cheaper because the proof target becomes a finite,
   typed bundle instead of event-specific SQL branching.

### 2. Split context into `DepFacts` and `GuardFacts`

Recommendation:

1. Treat positive semantic justification as dep-derived by default.
2. Treat negative/current/local constraints as a separate guard layer.

Recommended boundary:

`DepFacts`

1. Immediate valid deps only.
2. Typed summaries derived from those deps.
3. Event-sourced semantic justification.
4. Default source of projector acceptance/planning input.

`GuardFacts`

1. Removal/revocation/deletion state.
2. Purge/tombstone state not naturally encoded as an immediate dep.
3. Local-only/runtime-only facts.
4. Narrow ambient state that cannot yet be eventized.

Why:

1. This keeps the positive authorization story graph-local.
2. It avoids pretending every current-state constraint is just another dep.
3. It keeps the "ambient state" surface explicit and small.

### 3. Make positive authority primarily dep-derived

Recommendation:

1. When an event names its authority or signer justification explicitly, treat
   that as the authority source.
2. If the authority dep is valid, its transitive justification is already
   certified by projection.
3. Keep revocation/removal as a separate monotonic guard layer rather than
   folding currentness queries back into every positive-authority context load.

Implication:

Questions like "is this signer currently admin?" should not default to
"recompute the full admin prefix from SQL" if the event already depends on a
valid authority event. In that case:

1. the dep exists,
2. the dep is valid,
3. the dep has the allowed semantic kind,
4. the dep matches the signer/target relation expected by the event.

That should be enough for the positive authorization half. Removal/revocation
still remains a separate guard layer.

### 4. Turn local key possession into a first-class local event dep

Recommendation:

1. Treat key possession as an event dependency rather than a special ambient
   materialized-table lookup.
2. Use the existing distinction between shareable and non-shareable events to
   model this cleanly.
3. Make the canonical witness of local possession a deterministic local
   `key_secret` event identity.

Target shape:

1. Shared key distribution / unwrap logic enables deterministic local key
   materialization.
2. Local key materialization is represented by a non-shareable/local event.
3. Encrypted/readability depends on that local event like any other dep.

Why this is cleaner:

1. `encrypted` no longer needs a custom SQL lookup for key bytes as ambient
   state.
2. The dep system can treat missing local key material as an ordinary missing
   local dep.
3. Cascade/unblock semantics become more uniform.
4. The proof story becomes "proceed requires local dep valid" rather than
   "proceed requires a special table lookup succeeded".

Important nuance:

The dep system should respect existing share scope:

1. missing shared dep means "sync/fetch may satisfy this later",
2. missing local dep means "local materialization may satisfy this later",
3. both remain ordinary deps, but downstream policy should branch on
   share scope instead of introducing a completely separate conceptual system.

### 5. Keep one canonical projection engine and reuse it everywhere

Recommendation:

1. Continue to center the repo on one canonical projection/apply path.
2. Continue reusing that path across SQLite and in-memory/refinement backends.
3. Prefer adding backend seams over creating simulator-only semantic logic.

Why:

The existing `ProjectionBackend` pattern is one of the strongest structures in
the codebase. It is the right foundation for believable proofs because:

1. the same projection algorithm can run over production state and in-memory
   refinement state,
2. the simulator is not forced to become a parallel protocol definition,
3. runtime-vs-simulator alignment can be tested on the exact same apply path.

### 6. Make executors narrower and more typed

Recommendation:

1. Keep planners and normalizers pure.
2. Keep executors capability-gated.
3. Push more structure into typed effect builders instead of raw stringly
   `WriteOp` construction in projectors.

Why:

Rust makes this cheap:

1. exhaustive enums,
2. private constructors,
3. capability tokens,
4. newtypes for ids and scopes,
5. compile-time exhaustiveness on effect variants.

Verus also likes this shape because it is much easier to prove:

1. plan exclusivity,
2. idempotency,
3. tenant confinement,
4. "executor cannot exceed plan",
5. "only `Valid` emits writes".

### 7. Remove or demote ungrounded proof modules

Recommendation:

1. If a Verus module is not imported by runtime or by a clearly defined
   refinement bridge, it should not survive as if it were protecting the
   system.
2. Such modules should either:
   - be turned into real imported seams,
   - be rewritten as simulator/refinement proofs with an explicit bridge, or
   - be deleted/demoted to commentary.

Why:

The repo's "real proofs only" position is correct: abstract verified models
that are not actually tied to executing code are documentation, not protection.

### 8. Simplify `src/sim` into explicit layers

Recommendation:

Keep three clearly named simulator/testing layers:

1. `Real E2E / daemon calibration`
   - in-process daemon harness,
   - real RPC/query paths,
   - selected-peer snapshot/replay bridges.
2. `Proof-grade refinement simulator`
   - in-memory state model,
   - shared projection/apply engine,
   - typed imported observable state,
   - target for system-level refinement claims.
3. `Perf / experimental simulator`
   - sparse/event-queue models,
   - synthetic topology/performance exploration,
   - not the primary proof target.

Why:

The simulator code is currently useful but conceptually crowded. Making these
layers explicit reduces confusion about what each part is for:

1. real daemon paths are for calibration and real-world confirmation,
2. refinement sim is for proof-bearing semantic alignment,
3. sparse/perf sim is for scale and throughput exploration.

### 9. Introduce one explicit refinement boundary type

Recommendation:

1. Standardize one exported observable/refinement state surface for:
   - importing real peer state into the simulator,
   - snapshotting simulator state for real RPC/query inspection,
   - future refinement proofs.
2. Prefer one canonical schema over ad hoc bridge structs scattered across
   simulator and test files.

Why:

This makes the translation story much cleaner:

1. Verus proves properties over refinement state,
2. runtime-vs-sim tests prove the refinement boundary is faithful,
3. real daemon tests prove the property is externally observable.

## Recommended Decision-Context Model

The recommended steady-state model is:

```text
self event
  + resolved immediate deps
  + narrow guard facts
    -> normalized decision context
    -> verified planner core
    -> executor
```

Suggested conceptual types:

```text
EventContext {
  self_event,
  deps: DepFacts,
  guards: GuardFacts,
}
```

Where:

`DepFacts`

1. are generic,
2. are typed by semantic kind,
3. are derived from immediate valid deps,
4. carry share-scope information where needed.

`GuardFacts`

1. are small and explicit,
2. capture only current-state/local/runtime constraints,
3. are allowed to remain materialized-state driven until eventized.

## High-Value Simplifications To Prioritize

If the branch wants the highest leverage simplifications first, the order
should be:

1. Standardize dep resolution to return typed dep facts.
2. Move positive authority checks to dep facts wherever an explicit authority
   dep already exists.
3. Recast encrypted readability/key possession as a local-event-dep problem
   using existing share-scope distinctions.
4. Split simulator layers into explicit refinement vs perf roles.
5. Remove or demote proof modules that do not have a runtime/refinement
   grounding path.
6. Introduce more typed projector/effect builders to reduce raw `WriteOp`
   construction noise.

## Why This Direction Is The Best Fit For Rust + Verus

Rust gives the repo cheap leverage through:

1. strong enum typing,
2. exhaustive matches,
3. newtypes,
4. capability patterns,
5. sealed constructors and explicit effect surfaces.

Verus gives the repo cheap leverage through:

1. finite planner cores over primitive flags,
2. precedence rules,
3. exclusivity/disjointness,
4. monotonicity,
5. "if plan X then only effects Y",
6. structural invariants over typed event/effect bundles.

The codebase should therefore avoid spending proof budget on:

1. arbitrary SQL shape,
2. large stringly state,
3. async runtime interleavings,
4. transport plumbing internals,
5. ad hoc projector-specific context assembly.

Instead, it should funnel behavior into:

1. generic dep resolution,
2. typed dep/guard facts,
3. small verified decision cores,
4. capability-gated executors,
5. refinement layers that share the same semantic engine.

## Net Recommendation

The codebase should move toward a model where:

1. almost all semantic justification comes from immediate event deps,
2. current-state and local-only constraints are isolated into a narrow guard
   layer,
3. local key possession is represented as a local event dep rather than a
   special ambient table fact,
4. the same projection/apply engine remains the authority across production
   and refinement simulation,
5. only grounded proof modules survive.

That is the most elegant shape available here. It uses what is cheap in Rust
and Verus, matches the event-sourced design better, and gives the strongest
path toward believable whole-system proofs.
