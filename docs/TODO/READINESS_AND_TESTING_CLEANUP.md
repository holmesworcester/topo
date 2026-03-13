# Readiness And Testing Cleanup

Follow-up work after introducing tenant `ready` and `[still joining]`:

1. Shrink `accept_*` test helpers so they only perform acceptance and daemon lifecycle work.
2. Remove helper-local guessed readiness timers from accept/join helpers.
3. Add shared `assert_eventually` helpers over explicit readiness/value predicates:
   - tenant visible,
   - tenant `ready == true`,
   - specific event/message presence.
4. Keep the tenant readiness source of truth in shared authoring-context code, not in ad hoc harness SQL.
5. Preserve the deterministic/discovery split:
   - deterministic bootstrap tests: fixed bind, discovery disabled, explicit public address,
   - discovery-enabled tests: duplicate connection pressure, idempotency, double-send coverage.
6. Rename or split tests whose names still imply empty-bootstrap/mDNS coverage after stabilization work changed the actual topology.
7. Remove remaining correctness-sensitive fixed sleeps; keep sleeps only as short poll intervals or intentional race stretchers.
