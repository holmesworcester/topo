# Discovery Preference And Bind Policy Plan

## Problem

The current peering runtime treats mDNS discovery targets and persisted observed-endpoint
targets as equivalent for the same peer. That means a previously successful remote/overlay
address can keep winning even after we freshly rediscover a local path.

Separately, local discovery currently auto-detects an advertise address whenever the daemon
binds to loopback or wildcard. That makes `topo start --bind ...` less explicit than it should
be: users can choose a bind address but still get local discovery behavior derived from a
different interface.

## Intended Behavior

1. Fresh discovery targets should outrank older observed-endpoint targets for the same peer.
2. Default daemon startup keeps local discovery on.
3. Explicit `--bind` disables advertise-address autodetection.
4. If an explicit bind already names a concrete non-loopback address, discovery may still run
   using that exact address.
5. If an explicit bind is loopback or wildcard, discovery is suppressed because there is no
   explicit advertise address and autodetection is off.
6. Users can override the default policy with `topo start --discovery auto|on|off`.

## Implementation Plan

1. Add source-priority tracking to `PeerDispatcher`.
2. Prefer `Discovery` over `ObservedPeer` for the same peer dispatch key, without adding
   multi-address races.
3. Thread a small discovery policy from CLI startup into the peering runtime:
   `allow_discovery_autodetect = start_uses_default_bind`.
4. Refactor discovery setup so advertise-address selection is explicit and testable.
5. Update CLI harness helpers so discovery-focused tests can start daemons without an explicit
   `--bind`, preserving the default-bind behavior under test.
6. Add focused regression coverage for both source preference and explicit-bind discovery
   suppression.

## Success Criteria

### SC1. Discovery targets beat persisted remote targets for the same peer

Evidence:
- `PeerDispatcher` retains the higher-priority discovery target when a lower-priority observed
  target arrives later.
- A later discovery target can replace an observed target for the same peer.

Checks:
- `cargo +stable test --manifest-path /tmp/poc-7-discovery-preference/Cargo.toml test_discovery_target_outranks_observed_target_for_same_peer -- --nocapture`
- `cargo +stable test --manifest-path /tmp/poc-7-discovery-preference/Cargo.toml test_same_addr_discovery_upgrades_priority_without_reconnect -- --nocapture`

### SC2. Explicit `--bind` disables advertise autodetection

Evidence:
- Runtime discovery setup uses the explicit non-loopback bind IP as-is.
- Runtime discovery setup refuses to auto-pick a non-loopback IP when `--bind` was user-specified.

Checks:
- `cargo +stable test --manifest-path /tmp/poc-7-discovery-preference/Cargo.toml explicit_bind_without_autodetect_suppresses_loopback_discovery -- --nocapture`
- `cargo +stable test --manifest-path /tmp/poc-7-discovery-preference/Cargo.toml explicit_non_loopback_bind_stays_discoverable_without_autodetect -- --nocapture`

### SC3. Realistic daemon behavior matches the policy

Evidence:
- Discovery-only local recovery still works when daemons start with the default bind path.
- The same discovery-only recovery does not happen when daemons use explicit loopback `--bind`.
- `--discovery on` restores discovery for explicit bind cases that would otherwise stay off.

Checks:
- `cargo +stable test --manifest-path /tmp/poc-7-discovery-preference/Cargo.toml --test cli_test test_cli_local_mdns_discovery_without_bootstrap_addresses -- --nocapture --test-threads=1`
- `cargo +stable test --manifest-path /tmp/poc-7-discovery-preference/Cargo.toml --test cli_test test_cli_explicit_bind_disables_mdns_recovery_without_bootstrap_addresses -- --nocapture --test-threads=1`
- `cargo +stable test --manifest-path /tmp/poc-7-discovery-preference/Cargo.toml --test cli_test test_cli_explicit_bind_with_discovery_on_recovers_without_bootstrap_addresses -- --nocapture --test-threads=1`

## End-To-End Validation

1. Run the focused source-priority unit tests.
2. Run the discovery advertise-policy unit tests.
3. Run the two CLI discovery-policy tests.
4. Run `cargo fmt --manifest-path /tmp/poc-7-discovery-preference/Cargo.toml`.
5. Run `git -C /tmp/poc-7-discovery-preference diff --check`.
