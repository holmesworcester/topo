# Feedback: peering readability + bootstrap discovery review

Date: 2026-02-21  
Reviewed against: `docs/planning/PEERING_READABILITY_AND_BOOTSTRAP_DISCOVERY_PLAN.md`

## Findings

1. **Medium - R3/SC3 not fully met: bootstrap and discovery still use separate dispatch ownership paths**
   - Why this matters: the plan requires one planner/dispatcher path for both bootstrap-trust and mDNS targets. Current code still splits ownership: bootstrap uses a `HashSet` launch guard, while mDNS uses `PeerDispatcher` with reconnect/cancel behavior.
   - Evidence:
     - `src/peering/runtime/mod.rs:147` (bootstrap targets collected/launched directly in `run_node`)
     - `src/peering/runtime/target_planner.rs:222` (bootstrap refresher uses `HashSet<(tenant, addr)>` dedupe only)
     - `src/peering/runtime/discovery.rs:78` (separate `PeerDispatcher` loop and direct `connect_loop` spawn)
   - Risk: behavior drift between bootstrap and discovery paths (e.g., address changes for bootstrap targets do not use the same reconnect/cancel semantics), plus continued split ownership/readability cost.
   - Action:
     - Move dispatch decisions for bootstrap and discovery into one planner-owned dispatch API.
     - Reuse one cancellation/reconnect policy for both sources (PeerDispatcher-style).
     - Make `run_node` and `discovery` thin callers of that single dispatch surface.

2. **Medium - Boundary leak in enforcement script: `event_pipeline` path check is non-functional**
   - Why this matters: SC2 relies on boundary checks preventing production usage of test bootstrap helpers. One check points at a non-existent path, so violations in `src/event_pipeline.rs` would not be caught.
   - Evidence:
     - `scripts/check_boundary_imports.sh:111` uses `src/event_pipeline/` (directory does not exist; real file is `src/event_pipeline.rs`)
   - Risk: silent policy bypass in CI for a required ownership boundary.
   - Action:
     - Change that check to `src/event_pipeline.rs`.
     - Add a guard in `check_no_match` to fail when the target path is missing, so future typos cannot silently pass.

3. **Medium - SC5 docs parity gap: `docs/PLAN.md` does not reflect the enforced loop model**
   - Why this matters: the plan explicitly requires both `docs/DESIGN.md` and `docs/PLAN.md` to describe the exact runtime model and ownership. `docs/DESIGN.md` was updated, but `docs/PLAN.md` still documents older node-daemon framing and does not state the new 6-step loop model/ownership mapping.
   - Evidence:
     - Requirement: `docs/planning/PEERING_READABILITY_AND_BOOTSTRAP_DISCOVERY_PLAN.md:99` and `docs/planning/PEERING_READABILITY_AND_BOOTSTRAP_DISCOVERY_PLAN.md:127`
     - Current `docs/PLAN.md` sections still centered on older structure: `docs/PLAN.md:1936`, `docs/PLAN.md:2028`
   - Risk: newcomer guidance mismatch and SC5 non-compliance despite code changes.
   - Action:
     - Add/update a `docs/PLAN.md` section matching the enforced runtime loop:
       1) projected SQLite state,
       2) target planner,
       3) dial/accept supervisors,
       4) sync session runner,
       5) ingest writer,
       6) projected SQLite state.
     - Call out canonical ownership files: `src/peering/runtime/target_planner.rs` and `src/peering/loops/mod.rs`.

## Verification run

- `rg -n "peering::workflows::bootstrap|workflows/bootstrap" src`
- `rg -n "target planner|autodial|PeerDispatcher|launch_mdns_discovery|collect_placeholder_invite_autodial_targets|collect_all_bootstrap_targets" src/peering`
- `bash scripts/check_boundary_imports.sh`
- `cargo check`
- `cargo test --lib -q`
- `cargo test --test scenario_test -q`
- `cargo test --test holepunch_test -q`
- `cargo test --test projectors -q`
