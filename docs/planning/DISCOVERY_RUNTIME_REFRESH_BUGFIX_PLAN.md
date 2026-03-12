# Discovery Runtime Refresh Bugfix Plan

## Problem

The current discovery-preference branch can admit new tenants on a running daemon without
making those tenants effective discovery participants. The live runtime registers certs for
new tenants, but discovery setup is constructed only when the peering runtime starts. That
makes additional wait time meaningless for discovery-only joins: the browser/advertiser state
the join needs may never exist.

## Hypothesis

1. `reevaluate_runtime()` classifies pure tenant additions as `NewTenantsAdded`.
2. The `NewTenantsAdded` path only updates the live cert resolver.
3. mDNS advertisement handles, browse receivers, local self-filter sets, and tenant-scoped
   discovery workers are not refreshed on that path.
4. Discovery-only or wrong-bootstrap joins added after the daemon is already running can then
   stall indefinitely, even with a larger test timeout.

## Intended Behavior

1. When a live daemon gains tenants that require refreshed discovery participation, the runtime
   must rebuild or restart so discovery state matches the tenant set.
2. A larger discovery timeout should then be meaningful because the correct discovery workers
   and advertisements actually exist.
3. The existing discovery-preference changes remain intact:
   discovery target priority, `--discovery auto|on|off`, explicit-bind autodetect suppression,
   and discovery test isolation via namespace locking.

## Implementation Plan

1. Add focused evidence around the runtime-manager `NewTenantsAdded` path and discovery setup.
2. Make live runtime reevaluation restart or refresh discovery state when new tenants are added
   under discovery-enabled operation.
3. Keep the existing no-manual-restart behavior from the CLI perspective: internal runtime
   restart is acceptable if the daemon remains usable and recovery proceeds automatically.
4. Preserve the existing connection/session fixes and trust fixes from the discovery-preference
   branch while narrowing this bugfix to runtime refresh semantics.
5. Re-run the discovery-dependent CLI regressions with a longer convergence budget and treat
   the remaining flakes as signal only if they survive the runtime-refresh fix.

## Success Criteria

### SC1. New tenants on a running discovery-enabled daemon become real discovery participants

Evidence:
- Runtime-manager behavior no longer leaves discovery setup stale after a live tenant addition.
- New tenant additions trigger the required refresh path.

Checks:
- Add and run a focused unit test covering the runtime-manager decision for live tenant additions.

### SC2. Discovery-only joins after daemon startup recover without manual stop/start

Evidence:
- A daemon that starts first and accepts tenants later can still recover discovery-only joins.
- Increasing timeout is now meaningful because discovery refresh actually occurs.

Checks:
- `cargo +stable test --manifest-path /tmp/poc-7-discovery-runtime-refresh/Cargo.toml --test cli_test test_cli_shared_db_multiworkspace_mixes_empty_bootstrap_mdns_and_explicit_endpoints -- --test-threads=1`
- `cargo +stable test --manifest-path /tmp/poc-7-discovery-runtime-refresh/Cargo.toml --test cli_test test_cli_device_link_mixed_topology_empty_explicit_and_wrong_only -- --test-threads=1`

### SC3. Existing discovery-preference behavior is preserved

Evidence:
- Source priority and bind/discovery policy regressions still pass after the runtime-refresh fix.

Checks:
- `cargo +stable test --manifest-path /tmp/poc-7-discovery-runtime-refresh/Cargo.toml test_discovery_target_outranks_observed_target_for_same_peer -- --nocapture`
- `cargo +stable test --manifest-path /tmp/poc-7-discovery-runtime-refresh/Cargo.toml explicit_bind_without_autodetect_suppresses_loopback_discovery -- --nocapture`
- `cargo +stable test --manifest-path /tmp/poc-7-discovery-runtime-refresh/Cargo.toml --test cli_test test_cli_local_mdns_discovery_without_bootstrap_addresses -- --test-threads=1`

## End-To-End Validation

1. Run the focused runtime-manager/unit regression for live tenant additions.
2. Run the two currently noisy discovery-dependent CLI regressions.
3. Run the core discovery-preference regressions.
4. Run `cargo fmt --manifest-path /tmp/poc-7-discovery-runtime-refresh/Cargo.toml`.
5. Run `git -C /tmp/poc-7-discovery-runtime-refresh diff --check`.
