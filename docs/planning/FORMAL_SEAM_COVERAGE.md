# Formal Seam Coverage

This file indexes proof-bearing `RawRows -> DecisionContext -> Plan` seams.
It is not a replacement for `docs/PLAN.md`; it is a working map for keeping
runtime seams, Verus mirrors, and targeted checks aligned.

## Proof model: ensures on real exec fns (not abstract mirrors)

As of the `verus-real-proofs` work (branch of the same name), every
migratable seam below has its decision/normalization logic living as an
**executable `pub fn`** inside a `verus!` block in the `topo-verus-proofs`
path-dep crate, with `requires`/`ensures` clauses that `cargo-verus verify`
SMT-checks against the **actual function body**. The runtime crate
(`topo`) imports and calls those verified functions — when the runtime's
type shape carries `String`/`Option<RuntimeEnum>`/`Vec<RuntimeStruct>`
payloads that cannot cross into `topo-verus-proofs` without cyclic deps,
a **verified core + runtime adapter** pattern is used: the verified
function takes a primitive-only "core" shape, and the runtime has a thin
unverified adapter that projects runtime → core, calls the verified fn,
and rehydrates payloads on the way out. The decision logic is SMT-checked;
the plumbing is trusted (isolated, inspectable).

A tamper test (intentionally flipping a function body) confirmed that
`cargo-verus verify` reports `postcondition not satisfied` when the body
diverges from the ensures — i.e., these are real proofs about the bodies
the runtime executes, not parallel abstract mirrors. This check runs on
every PR via `scripts/verus_tamper_test.sh` and the
`.github/workflows/verus-verify.yml` `verus-tamper-test` job, so the
SMT-on-real-bodies guarantee is a living invariant rather than a
one-time measurement.

Files where the pattern could not be fully grounded (cryptographic
signature verification, async transport lifecycle, multi-fn protocol
invariants) retain `spec fn`s with a `_spec` suffix or live in the
**Abstract specifications (not grounded)** section below. These encode
system-level intent rather than single-function correctness; they should
not be mistaken for proofs about runtime code.

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
| Target dispatch reconciliation | `src/runtime/peering/engine/target_dispatch.rs` | `verus-proofs/src/runtime/peering/engine/target_dispatch.rs` | candidate target rows are already source-tagged; spawning requires a runnable, non-suppressed source | `UCA`, `AMF`, `ECP` | `cargo test -j1 --lib target_dispatch -- --nocapture`; `cargo-verus verify` |
| Connect-loop failure/retry planning | `src/runtime/peering/loops/connect.rs` | `verus-proofs/src/runtime/peering/loops/connect.rs` | session outcomes are classified before retry planning; auth-failure retry/evict effects require classified causes | `ECP` | `cargo test -j1 --lib connect -- --nocapture`; `cargo test -j1 --lib connection_lost_classifier_accepts_transport_close_messages -- --nocapture`; `cargo test -j1 --lib connection_lost_classifier_rejects_nontransport_failures -- --nocapture`; `cargo test -j1 --lib stale_dial_classifier_accepts_unreachable_dial_errors -- --nocapture`; `cargo test -j1 --lib stale_dial_classifier_rejects_nonstale_failures -- --nocapture`; `cargo-verus verify` |
| Daemon identity materialization | `src/runtime/transport/daemon_identity.rs` | `verus-proofs/src/runtime/transport/daemon_identity.rs` | local endpoint-secret/shared presence query is loaded before planning; invalid shared-without-secret state must fail closed instead of synthesizing a partial identity | `AMF`, `ECP` | `cargo test -j1 --lib materialize_daemon_identity_generates_and_persists_endpoint_events -- --nocapture`; `cargo test -j1 --lib materialize_daemon_identity_repairs_missing_endpoint_shared -- --nocapture`; `cargo test -j1 --lib materialize_daemon_identity_rejects_shared_without_secret -- --nocapture`; `cargo-verus verify` |
| Outbound session auth | `src/runtime/transport/session_auth.rs` | `verus-proofs/src/runtime/transport/outbound_session_auth.rs` | tenant/bootstrap query rows are tenant-scoped and duplicate fallback invite rows preserve same-workspace rejection | `ALB`, `UCA`, `ECP` | `cargo test -j1 --lib outbound_session_auth -- --nocapture`; `cargo-verus verify` |
| Inbound route/bootstrap auth | `src/runtime/transport/session_auth.rs` | `verus-proofs/src/runtime/transport/inbound_session_auth.rs` | inbound proof rows resolve to local tenant candidates and duplicate equal tenant rows preserve one accepted tenant | `UCA`, `AMF`, `ECP` | `cargo test -j1 --lib inbound_route_auth -- --nocapture`; `cargo test -j1 --lib inbound_bootstrap_auth -- --nocapture`; `cargo-verus verify` |
| Sync admission | `src/runtime/sync_engine/session/admission.rs` | `verus-proofs/src/runtime/sync_engine/session/sync_admission.rs` | accepted-workspace rows are loaded by tenant and duplicate same-workspace acceptances collapse before planning | `WC`, `AMF` | `cargo test -j1 --lib sync_admission -- --nocapture`; `cargo test -j1 --lib resolve_sync_admission_starts_when_distinct_query_collapses_duplicate_workspace_rows -- --nocapture`; `cargo test -j1 --lib resolve_sync_admission_rejects_missing_workspace_binding -- --nocapture`; `cargo test -j1 --lib resolve_sync_admission_rejects_ambiguous_workspace_binding -- --nocapture`; `cargo-verus verify` |
| Sync window planning | `src/runtime/sync_engine/session/windowing.rs` | `verus-proofs/src/runtime/sync_engine/session/windowing.rs` | window query rows describe one local sync request; peer count/ownership are noninterfering because normal sync uses per-peer cadence | `ECP` | `cargo test -j1 --lib cold_tier -- --nocapture`; `cargo test -j1 --lib select_outbound_window -- --nocapture`; `cargo-verus verify` |
| Range/dependency send planning | `src/runtime/sync_engine/session/range_session.rs` | `verus-proofs/src/runtime/sync_engine/session/range_session.rs` | selected shared rows are workspace-index scoped; send roots require current-workspace index membership and shared blob availability; dep pre-emission requires the dep to be selected, fresh, and non-visiting; session auth path is noninterfering with send eligibility | `WC`, `AMF`, `ECP` | `cargo test -j1 --lib load_shared_sync_entries_only_returns_range_roots -- --nocapture`; `cargo test -j1 --lib shared_send_eligibility_plan_requires_index_membership_and_blob_presence -- --nocapture`; `cargo test -j1 --lib selected_dep_order_normalizer_preserves_raw_rows_for_planner -- --nocapture`; `cargo-verus verify` |
| Tenant-scoped projection writes | `src/state/projection/apply/stages.rs` + `src/state/projection/apply/write_exec.rs` (`assert_writes_tenant_isolated`) | `verus-proofs/src/state/tenant_isolation.rs` (`check_writes_tenant_isolated`) | a trusted extractor (`writeop_tenant_view`) labels each `WriteOp` by whether it targets a column named `recorded_by` and whether that value equals the executing tenant; tables without a `recorded_by` column are outside the tenant-scope dimension and allowed | `WC`, `ECP` | `cargo test -j1 --lib tenant_isolation -- --nocapture`; `cargo test -j1 --lib cross_tenant -- --nocapture`; `cargo test -j1 --lib dep_global_existence_not_sufficient -- --nocapture`; `cargo-verus verify` |
| Shared workspace fanout | `src/state/shared_workspace_fanout.rs` | `verus-proofs/src/state/shared_workspace_fanout.rs` | origin event and sibling tenants share one workspace id; fanout requires an unblocked origin and at least one eligible sibling | `WC`, `AMF`, `ECP` | `cargo test -j1 --lib shared_fanout -- --nocapture`; `cargo test -j1 --lib enqueue_fanout_records_and_queues_same_workspace_siblings_only -- --nocapture`; `cargo test -j1 --lib event_pipeline_effects_fan_out_shared_events_to_same_workspace_siblings_only -- --nocapture`; `cargo test -j1 --lib test_local_shared_create_fanout_is_same_workspace_only -- --nocapture`; `cargo-verus verify` |
| Projection query/dependency normalizers | `src/state/projection/queries.rs` | `verus-proofs/src/state/projection/queries.rs` | SQL returns typed raw rows for the relevant event dependency; duplicate equal authority rows collapse before planning; purge-sensitive tombstone state has precedence over semantic readiness | `UCA`, `WC`, `AMF`, `ECP` | `cargo test -j1 --lib content_authority -- --nocapture`; `cargo test -j1 --lib admin_authority -- --nocapture`; `cargo test -j1 --lib peer_shared_authority -- --nocapture`; `cargo test -j1 --lib deletion_signer -- --nocapture`; `cargo test -j1 --lib semantic_type -- --nocapture`; `cargo test -j1 --lib dep_load_plan -- --nocapture`; `cargo-verus verify` |
| Projection stage effects | `src/state/projection/apply/stages.rs` | `verus-proofs/src/state/projection/stages.rs`; `verus-proofs/src/pipeline/context_loading.rs`; `verus-proofs/src/pipeline/project_one.rs` | projector has already produced a typed `ProjectionDecision`; the effect plan forbids write ops for block/reject/already-processed decisions; non-continue context-load plans, including hard-purge short-circuits, do not enter projector dispatch | `ECP` | `cargo test -j1 --lib context_load_disposition -- --nocapture`; `cargo test -j1 --lib projection_decision_effect_plan -- --nocapture`; `cargo test -j1 --lib project_one_step_can_run_against_generic_backend_for_valid_event -- --nocapture`; `cargo test -j1 --lib project_one_step_records_block_without_projection_side_effects_when_context_load_blocks -- --nocapture`; `cargo test -j1 --lib project_one_step_records_rejection_without_projection_side_effects_when_context_load_rejects -- --nocapture`; `cargo test -j1 --lib apply_projection_emits_hard_purge_without_write_ops_when_context_load_purges -- --nocapture`; `cargo-verus verify` |
| Hard purge planning | `src/state/projection/purge.rs` | `verus-proofs/src/state/projection/purge.rs` | purge candidate rows are scoped to one event | `WC`, `ECP` | `cargo test -j1 --lib hard_purge_plan -- --nocapture`; `cargo test -j1 --lib test_hard_purge_removes_message_graph_and_auxiliary_rows -- --nocapture`; `cargo test -j1 --lib test_hard_purge_failure_rolls_back_and_retries_from_project_queue -- --nocapture`; `cargo-verus verify` |
| Persist event fanout/index planning | `src/state/pipeline/phases.rs` | `verus-proofs/src/pipeline/persist_phase.rs` | workspace cache/query returns the tenant's accepted workspace binding; missing workspace binding suppresses index and fanout targets | `WC`, `ECP` | `cargo test -j1 --lib run_persist_phase -- --nocapture`; `cargo test -j1 --lib run_persist_phase_indexes_and_fanouts_shared_message_with_cached_workspace_binding -- --nocapture`; `cargo test -j1 --lib run_persist_phase_suppresses_shared_index_and_fanout_without_workspace_binding_for_shared_message -- --nocapture`; `cargo-verus verify` |
| Workspace command endpoint planning | `src/event_modules/workspace/command_plans.rs` | `verus-proofs/src/event_modules/workspace/command_plans.rs` | explicit bootstrap endpoint decoding occurs before planner resolution; local endpoint-shared queries must either resolve one local daemon identity or reject | `AMF`, `ECP` | `cargo test -j1 --lib invite_bootstrap_plan_rejects_missing_local_daemon_identity_without_explicit -- --nocapture`; `cargo test -j1 --lib local_endpoint_shared_plan_rejects_missing_identity -- --nocapture`; `cargo test -j1 --lib resolve_invite_bootstrap_endpoint_id_rejects_missing_daemon_identity_without_explicit -- --nocapture`; `cargo-verus verify` |
| WriteOp idempotency | `src/state/projection/apply/write_exec.rs` (`writeop_kind`, `debug_assert!(is_idempotent_writeop(..))`) | `verus-proofs/src/state/writeop_idempotency.rs` (`is_idempotent_writeop`) | exhaustive runtime match over `WriteOp` variants forces an explicit idempotency proof for every new variant; a future non-idempotent variant fails compilation in the extractor and SMT in the verified predicate | `ECP` | `cargo test -j1 --lib apply:: -- --nocapture`; `cargo-verus verify` |
| Persist-phase event-type validation | `src/state/pipeline/phases.rs` (imports from verus-proofs) | `verus-proofs/src/state/pipeline/persist_validation.rs` (`extract_event_type`, `normalize_persist_validation`, `decide_persist_validation_plan`) | `extract_event_type` ensures tie return value to blob byte 0; normalize/decide are exhaustive matches with pinned ensures over `PersistValidation{RawRows,DecisionContext,Plan}` | `AMF`, `ECP` | `cargo test -j1 --lib persist_validation -- --nocapture`; `cargo test -j1 --lib run_persist_phase -- --nocapture`; `cargo-verus verify` |
| Cascade dep-counter consistency | `src/state/projection/apply/stages.rs::record_block_rows` (panics on mismatch after commit) | `verus-proofs/src/state/cascade_invariant.rs` (`cascade_counter_consistent`, `cascade_decrement_step_valid`) | every `record_block_rows` commit re-queries `deps_remaining` and the `blocked_event_deps` edge count and asserts equality; reintroduction of the old `INSERT OR IGNORE` drift (bug_hunt #3, now fixed) fires the assertion at the moment of divergence | `ECP`, `AMF` | `cargo test -j1 --lib deps_remaining -- --nocapture`; `cargo test -j1 --lib finding_3 -- --nocapture`; `cargo-verus verify` |
| Projector registry exhaustivity | `src/event_modules/mod.rs::tests` (`type_code_to_enum` + `formal_projector_family` delegate) | `verus-proofs/src/state/projector_registry.rs` (`EventTypeCode`, `formal_family_of`) | Verus exhaustive match over `EventTypeCode` is *total* by construction — every known event-type code has a formal projector-family assignment; adding a new runtime type without updating both sides breaks at compile time | `AMF`, `ECP` | `cargo test -j1 --lib registry_formal_projector_coverage -- --nocapture`; `cargo-verus verify` |
| ProjectorResult discipline | `src/state/projection/apply/stages.rs` (panics on malformed dispatch output) | `verus-proofs/src/state/projector_result_discipline.rs` (`projector_result_well_formed`) | every `dispatch_pure_projector` output is immediately checked: Valid may carry writes, Block/Reject/AlreadyProcessed must have empty write_ops; a projector that subverts the `::valid`/`::block`/… constructors is caught at dispatch | `ECP` | `cargo test -j1 --lib apply:: -- --nocapture`; `cargo-verus verify` |
| Queue backoff bounds | `src/state/db/queue.rs::backoff_ms` (delegates to verified) | `verus-proofs/src/state/queue_backoff.rs` (`backoff_ms`) | verified delay ∈ [BACKOFF_BASE_MS=1000, BACKOFF_CAP_MS=1_024_000], monotone up to cap, attempts=0 ⇒ base, attempts≥MAX ⇒ cap; replaces the bit-shift implementation with a Verus-friendly multiplier table | `ECP` | `cargo test -j1 --lib test_backoff -- --nocapture`; `cargo-verus verify` |
| Wire event-id integrity | `src/state/pipeline/mod.rs::make_wire_ingest_item` (single wire-path constructor) | `verus-proofs/src/state/event_id_integrity.rs` (`event_id_matches_blob_hash`) | `make_wire_ingest_item(blob, …)` computes `event_id = hash_event(blob)` internally so the invariant `claimed == BLAKE3(blob)` holds *by construction* at the wire boundary; receive-log replay bypasses this by design | `AMF`, `ECP` | `cargo-verus verify` |
| Signed-event wire structure | `src/event_modules/signed.rs::outer_payload`, `outer_signer_event_id` (delegate to verified) | `verus-proofs/src/state/signed_event_structure.rs` | verified prefix check `is_well_formed_signed_prefix`, body-range and signature-range helpers pin the `[type=35][signer:32][payload:N][sig:64]` layout. Runtime path-replaces the inline length+type checks with the verified predicate | `AMF`, `ECP` | `cargo test -j1 --lib signed -- --nocapture`; `cargo-verus verify` |
| Encrypted-event wire structure | `src/event_modules/encrypted.rs::outer_inner_type_code`, `outer_owner_event_id` (delegate to verified) | `verus-proofs/src/state/encrypted_event_structure.rs` | verified `is_well_formed_encrypted_header`, `owner_event_id_range`, `nonce_range`, `expected_encrypted_total_len` pin the header layout + total-length formula | `AMF`, `ECP` | `cargo test -j1 --lib encrypted -- --nocapture`; `cargo-verus verify` |
| Encode/parse full round-trip | `src/event_modules/mod.rs::encode_event` (debug-assert after encode) | `verus-proofs/src/state/command_roundtrip.rs` (`event_type_code_preserved`, `encoder_roundtrip_ok`) | every call to `encode_event` re-parses the produced blob in debug builds and asserts BOTH the type code matches AND the full `PartialEq` equality holds; encoder/decoder drift (wrong type byte, missing field, altered payload) fires in test runs | `AMF` | `cargo test -j1 --lib event_modules:: -- --nocapture`; `cargo test -j1 --lib create:: -- --nocapture`; `cargo-verus verify` |
| Ed25519 signer chain structural discipline | `src/state/projection/signer.rs::signer_identity_from_parsed` (Verus gate before match) | `verus-proofs/src/state/signer_chain.rs` (`is_valid_signer_type`) | exhaustive Verus match over `EventTypeCode`: only Workspace/UserInvite/DeviceInvite/User/PeerShared/Admin may act as signer identities; any other type is rejected by the verified whitelist before the runtime match, so content events can never be used as keys | `UCA`, `AMF` | `cargo test -j1 --lib signer:: -- --nocapture`; `cargo-verus verify` |
| Transaction guard state machine | `src/state/db/txn_guard.rs` (`TxnGuard<'c>`) + `src/state/db/queue.rs::with_immediate_tx{,_result}` (now TxnGuard-backed) | `verus-proofs/src/state/txn_state_machine.rs` (`DbTxnState`, `begin_transition_valid`, `commit_transition_valid`, `rollback_transition_valid`, `drop_is_noop`, `drop_should_rollback`) | runtime `TxnGuard<'c>` is non-Clone/non-Send/non-Sync, tracks `state: DbTxnState`, commits via consuming `commit(self)`, and Drop rolls back if still Active; every transition asserts the verified predicate before executing SQL. 22 existing closure-style callers of `with_immediate_tx{,_result}` get Drop-safety for free via the internal rewrite | `ECP`, `AMF` | `cargo test -j1 --lib txn_guard -- --nocapture`; `cargo-verus verify` |

## Intentional non-grounded entries

Only two items in this tree are intentionally not grounded on specific runtime
function bodies; everything else was deleted in the "real proofs only" pass.

| Area | Verus Mirror | Role | Check |
| --- | --- | --- | --- |
| Bug-hunt counterexamples | `verus-proofs/src/bug_hunt.rs` | Proofs documenting *known* runtime bugs (TTL skew extension, empty-missing blocks, TOCTOU races, etc.). Each `finding_*` demonstrates an undesired behavior the current runtime still exhibits. When a bug is fixed, flip the counterexample into a positive invariant on the fixing seam and remove the entry here. | `cargo-verus verify` |
| Session-auth protocol frame shapes | `verus-proofs/src/runtime/transport/session_auth.rs` (`*_spec` fns: `peer_shared_auth_spec`, `invite_bootstrap_auth_spec`, `inbound_auth_spec`) | Per-frame protocol invariants with no single runtime function counterpart — the runtime dispatches per-frame with cryptographic side effects. Retained because the frame-shape predicates are cited by ensures on the grounded `validate_expiry` and `ensure_daemon_binding` exec fns in the same file. | `cargo-verus verify` |

Previous abstract-only modules (connection_lifecycle, connection_security,
transport_trust, sync_protocol, sync_security, pipeline/batch, pipeline/cascade,
pipeline/commands, pipeline/contract, pipeline/data_ingestion, pipeline/dispatch,
pipeline/event_projectors, pipeline/file_projectors, pipeline/idempotency,
pipeline/projectors, pipeline/validation_inputs, event_modules/content_commands,
event_modules/workspace_commands, runtime/control/commands, composition) were
deleted. They described cross-function behaviors but made no claim about any
specific runtime body; the corresponding runtime properties are now either (a)
grounded through seams in the `Covered Seams` table above, (b) covered by
runtime tests listed in that table, or (c) open work items to be grounded as
new seams rather than left as mirrors.

## Maintenance Rules

When adding or changing a proof-bearing seam:

- Keep the runtime shape explicit: `RawRows -> DecisionContext -> Plan -> executor`.
- Keep SQL/query correctness in runtime tests; keep normalizer/planner invariants in Verus.
- **Write normalizers/planners as `pub fn` inside `verus!` blocks with `ensures` clauses** — not as `spec fn` mirrors. The runtime imports them via `pub use topo_verus_proofs::…`. The SMT solver checks the body against the ensures; a body change that violates the postcondition fails `cargo-verus verify`.
- **Adapter pattern** for runtime types that carry `String`/`Option<enum>`/`Vec<struct>` payloads: expose a primitives-only `*Core` shape in `verus-proofs`, keep the runtime's richer types local, wrap with a thin runtime adapter that projects-in/calls/projects-out. The decision logic is SMT-verified; the payload rehydration is trusted.
- If a function body really cannot be verified (cryptographic primitives, async transport, true multi-fn emergent behavior), add its spec to the **Abstract specifications (not grounded)** section with a clear note, and rename any retained spec fns with a `_spec` suffix to make the distinction visible at call sites.
- Add at least one targeted runtime check for the raw-row edge cases the Verus model abstracts.
- Run `python3 scripts/check_formal_seam_coverage.py` after touching this map or a proof-bearing seam.
- Run `python3 scripts/check_command_formal_coverage.py` after touching command/projector coverage.
- Run `python3 scripts/check_formal_mirror_updates.py` after touching any covered runtime command/seam/projector path.
- Update this coverage map when a seam is added, renamed, or moved.
