# Formal Seam Coverage

This file indexes proof-bearing `RawRows -> DecisionContext -> Plan` seams.
It is not a replacement for `docs/PLAN.md`; it is a working map for keeping
runtime seams, Verus mirrors, and targeted checks aligned.

## Composition Invariant Keys

- `UCA`: unique current authority or reject.
- `ALB`: already-local workspaces cannot gain bootstrap power.
- `WC`: workspace confinement.
- `AMF`: ambiguity and malformation fail closed.
- `ECP`: executors cannot exceed their plan.

## Covered Seams

| Area | Runtime Seam | Verus Mirror | Requires | Provides | Targeted Checks |
| --- | --- | --- | --- | --- | --- |
| Bootstrap dial target planning | `src/runtime/peering/engine/target_planner.rs` | `verus-proofs/src/runtime/peering/engine/bootstrap_dialer.rs` | trusted local workspace-presence query | `ALB`, `ECP` | `cargo test -j1 --lib bootstrap_dial -- --nocapture`; `cargo-verus verify` |
| Bootstrap session fallback | `src/runtime/peering/engine/bootstrap_auth.rs` | `verus-proofs/src/runtime/peering/engine/bootstrap_auth.rs` | projected bootstrap trust candidates are tenant-scoped and duplicate candidate rows are collapsed by invite before planning | `ALB`, `UCA`, `AMF` | `cargo test -j1 --lib bootstrap_session_fallback -- --nocapture`; `cargo-verus verify` |
| Target dispatch reconciliation | `src/runtime/peering/engine/target_dispatch.rs` | `verus-proofs/src/runtime/peering/engine/target_dispatch.rs` | candidate target rows are already source-tagged; spawning requires a preferred, runnable, non-suppressed source | `UCA`, `AMF`, `ECP` | `cargo test -j1 --lib target_dispatch -- --nocapture`; `cargo-verus verify` |
| Connect-loop failure/retry planning | `src/runtime/peering/loops/connect.rs` | `verus-proofs/src/runtime/peering/loops/connect.rs` | session outcomes are classified before retry planning; auth-failure retry/evict effects require classified causes | `ECP` | `cargo test -j1 --lib connect -- --nocapture`; `cargo-verus verify` |
| Outbound session auth | `src/runtime/transport/session_auth.rs` | `verus-proofs/src/runtime/transport/outbound_session_auth.rs` | tenant/bootstrap query rows are tenant-scoped and duplicate fallback invite rows preserve same-workspace rejection | `ALB`, `UCA`, `ECP` | `cargo test -j1 --lib outbound_session_auth -- --nocapture`; `cargo-verus verify` |
| Inbound route/bootstrap auth | `src/runtime/transport/session_auth.rs` | `verus-proofs/src/runtime/transport/inbound_session_auth.rs` | inbound proof rows resolve to local tenant candidates and duplicate equal tenant rows preserve one accepted tenant | `UCA`, `AMF`, `ECP` | `cargo test -j1 --lib inbound_route_auth -- --nocapture`; `cargo test -j1 --lib inbound_bootstrap_auth -- --nocapture`; `cargo-verus verify` |
| Sync admission | `src/runtime/sync_engine/session/admission.rs` | `verus-proofs/src/runtime/sync_engine/session/sync_admission.rs` | accepted-workspace rows are loaded by tenant and duplicate same-workspace acceptances collapse before planning | `WC`, `AMF` | `cargo test -j1 --lib sync_admission -- --nocapture`; `cargo-verus verify` |
| Sync window planning | `src/runtime/sync_engine/session/windowing.rs` | `verus-proofs/src/runtime/sync_engine/session/windowing.rs` | window query rows describe one local sync request; last-day-only mode is noninterfering with peer count/ownership | `ECP` | `cargo test -j1 --lib cold_tier -- --nocapture`; `cargo test -j1 --lib select_outbound_window -- --nocapture`; `cargo-verus verify` |
| Range/dependency send planning | `src/runtime/sync_engine/session/range_session.rs` | `verus-proofs/src/runtime/sync_engine/session/range_session.rs` | selected shared rows are workspace-index scoped; dep pre-emission requires the dep to be selected, fresh, and non-visiting | `WC`, `AMF`, `ECP` | `cargo test -j1 --lib shared_sync_entry_normalizer -- --nocapture`; `cargo test -j1 --lib selected_dep_order_normalizer -- --nocapture`; `cargo-verus verify` |
| Tenant-scoped projection isolation | `src/state/projection/apply/*`; event-module projectors | `verus-proofs/src/state/tenant_isolation.rs` | non-global projection writes carry the executing tenant scope; blocked-event and cascade state are tenant-scoped; endpoint-shared is the explicit global exception | `WC`, `ECP` | `cargo test -j1 --lib tenant_isolation -- --nocapture`; `cargo test -j1 --lib cross_tenant -- --nocapture`; `cargo test -j1 --lib dep_global_existence_not_sufficient -- --nocapture`; `cargo-verus verify` |
| Shared workspace fanout | `src/state/shared_workspace_fanout.rs` | `verus-proofs/src/state/shared_workspace_fanout.rs` | origin event and sibling tenants share one workspace id; fanout requires an unblocked origin and at least one eligible sibling | `WC`, `AMF`, `ECP` | `cargo test -j1 --lib shared_fanout -- --nocapture`; `cargo-verus verify` |
| Projection query/dependency normalizers | `src/state/projection/queries.rs` | `verus-proofs/src/state/projection/queries.rs` | SQL returns typed raw rows for the relevant event dependency; duplicate equal authority rows collapse before planning; purge-sensitive tombstone state has precedence over semantic readiness | `UCA`, `WC`, `AMF`, `ECP` | `cargo test -j1 --lib content_authority -- --nocapture`; `cargo test -j1 --lib admin_authority -- --nocapture`; `cargo test -j1 --lib peer_shared_authority -- --nocapture`; `cargo test -j1 --lib deletion_signer -- --nocapture`; `cargo test -j1 --lib semantic_type -- --nocapture`; `cargo test -j1 --lib dep_load_plan -- --nocapture`; `cargo-verus verify` |
| Projection stage effects | `src/state/projection/apply/stages.rs` | `verus-proofs/src/state/projection/stages.rs`; `verus-proofs/src/pipeline/project_one.rs` | projector has already produced a typed `ProjectionDecision`; the effect plan forbids write ops for block/reject/already-processed decisions; non-continue context-load plans do not enter projector dispatch | `ECP` | `cargo test -j1 --lib context_load_disposition -- --nocapture`; `cargo test -j1 --lib projection_decision_effect_plan -- --nocapture`; `cargo-verus verify` |
| Registered event projector basic coverage | `src/event_modules/*` and `src/event_modules/mod.rs` | `verus-proofs/src/pipeline/projectors.rs`; `verus-proofs/src/pipeline/file_projectors.rs`; `verus-proofs/src/pipeline/event_projectors.rs` | projector context loaders reject malformed/mismatched context before projector execution; registry coverage gate stays aligned with the Verus event-projector family enum | `AMF`, `ECP` | `cargo test -j1 --lib registry_formal_projector_coverage -- --nocapture`; `cargo-verus verify` |
| Hard purge planning | `src/state/projection/purge.rs` | `verus-proofs/src/state/projection/purge.rs` | purge candidate rows are scoped to one event | `WC`, `ECP` | `cargo test -j1 --lib hard_purge_plan -- --nocapture`; `cargo-verus verify` |
| Persist-phase validation | `src/state/pipeline/phases.rs` | `verus-proofs/src/pipeline/validation_inputs.rs` | prefix/type extraction is trusted to read bytes as specified | `AMF`, `ECP` | `cargo test -j1 --lib persist_validation -- --nocapture`; `cargo test -j1 --lib run_persist_phase -- --nocapture`; `cargo-verus verify` |
| Persist event fanout/index planning | `src/state/pipeline/phases.rs` | `verus-proofs/src/pipeline/persist_phase.rs` | workspace cache/query returns the tenant's accepted workspace binding; missing workspace binding suppresses index and fanout targets | `WC`, `ECP` | `cargo test -j1 --lib run_persist_phase -- --nocapture`; `cargo-verus verify` |

## Maintenance Rules

When adding or changing a proof-bearing seam:

- Keep the runtime shape explicit: `RawRows -> DecisionContext -> Plan -> executor`.
- Keep SQL/query correctness in runtime tests; keep normalizer/planner invariants in Verus.
- Add at least one targeted runtime check for the raw-row edge cases the Verus model abstracts.
- Update this coverage map when a seam is added, renamed, or moved.
