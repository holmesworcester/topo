# Phase 6 Feedback

> **Historical document; file paths and module names may not match the current source tree.**

Reviewed commit: `c5d0af9` (`Implement Phase 6: performance + operational hardening`)

## Scope check

- TLA modeling is Phase 7 work in `PLAN.md`, not Phase 6.
- Phase 6 scope is performance/operational hardening (queues, observability, memory, durability behavior).

## Findings

### 1. Medium: endpoint observation retention can grow without periodic purge

- Evidence:
  - endpoint observations are written on each connection in `src/sync/engine.rs:817` and `src/sync/engine.rs:923`.
  - purge currently runs only at loop startup in `src/sync/engine.rs:765` and `src/sync/engine.rs:869`.
- Impact:
  - long-lived daemons that do not restart frequently can accumulate `peer_endpoint_observations` rows for extended periods.
- Recommended fix:
  - add periodic purge in runtime (timer or every N observations/sessions), not only on startup.

### 2. Low: comment/behavior mismatch in endpoint observation helper

- Evidence:
  - comment says "INSERT OR REPLACE" in `src/db/health.rs:20`.
  - SQL uses `INSERT OR IGNORE` in `src/db/health.rs:31`.
- Impact:
  - misleading behavior expectations for maintainers/reviewers.
- Recommended fix:
  - either update comment to "INSERT OR IGNORE" or change SQL to match intended replace semantics.

### 3. Low: expiry boundary is strict `<` instead of `<=`

- Evidence:
  - purge query uses `expires_at < ?1` in `src/db/health.rs:15`.
- Impact:
  - exactly-expired rows remain until next purge tick.
- Recommended fix:
  - use `expires_at <= ?1` if the intended semantics are "expired at now should be purged now".

## Overall

- The Phase 6 architecture additions (queue health, endpoint indexes, low-mem knobs, batch-size controls) are directionally good.
- Current `scenario_test` passes after merged Phase 5 fixes.
- Addressing the 3 items above will make Phase 6 operational behavior more predictable under long-lived workloads.
