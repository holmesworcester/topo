# Feedback: Connect/Accept Collapse Mid-Implementation Review

Date: 2026-02-24
Reviewed against: `docs/planning/CONNECT_ACCEPT_COLLAPSE_EXECUTION_PLAN.md`
Branch: `exec/connect-accept-collapse-plan`
Worktree: `/home/holmes/poc-7-connect-accept-collapse-plan`

## Findings

1. **Medium - Remaining production non-coordinated initiator path in punch workflow**
   - Why it mattered: SC3 requires runtime outbound behavior to remain coordinated-only.
   - Evidence at review time: `src/peering/workflows/punch.rs` used `SyncSessionHandler::initiator(...)`.
   - Fix applied:
     - Replaced with coordinated outbound handler path in `src/peering/workflows/punch.rs:302-307` using `SyncSessionHandler::outbound(...)`.
   - Status: **RESOLVED**.

2. **Medium - Accidental repository-wide formatting side effect during implementation**
   - Why it mattered: scope was this collapse task only; broad formatting churn would obscure review and risk regressions.
   - Evidence at review time: large unrelated diff after an initial `cargo fmt`.
   - Fix applied:
     - Restored unrelated files and retained only intended task files:
       - `src/peering/loops/{mod.rs,connect.rs,accept.rs,supervisor.rs}`
       - `src/peering/workflows/punch.rs`
       - `docs/CURRENT_RUNTIME_DIAGRAM.md`
   - Status: **RESOLVED**.

## Review conclusion

- No unresolved High/Medium findings remain.
- Proceeded to final verification and SC1-SC6 audit.
