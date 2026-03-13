# Readiness And Testing Cleanup

Progress after introducing tenant `ready` and `[still joining]`:

Done:

1. `accept_*` helpers now guarantee acceptance/tenant visibility, not hidden readiness.
2. Helper-local signer/timer readiness policy has been removed from the general accept/join paths.
3. Tests now have shared readiness/value polling helpers over explicit invariants:
   - tenant count / visibility,
   - active tenant `ready == true`,
   - tenant `ready == true` by username,
   - specific event/message presence.
4. Tenant readiness remains sourced from shared authoring-context code, not harness-only SQL.
5. Username-based tenant selection in CLI tests now uses the tenant display/query surface instead of the `users` table.
6. Discovery-heavy device-link coverage was split out of `cli_test.rs` into its own binary.
7. Realism tests now only rely on the temporary accept daemon for durable acceptance; writability is asserted later through normal runtime behavior.

Remaining:

1. Keep the deterministic/discovery split crisp:
   - deterministic bootstrap tests: fixed bind, discovery disabled, explicit public address,
   - discovery-enabled tests: duplicate connection pressure, idempotency, double-send coverage.
2. Rename or split tests whose names still imply empty-bootstrap/mDNS coverage after stabilization work changed the actual topology.
3. Remove remaining correctness-sensitive fixed sleeps; keep sleeps only as short poll intervals or intentional race stretchers.
4. After rebasing onto current `master`, rerun the scripted merge gate and the broader suite to confirm the harness remains stable on top of the new base.
