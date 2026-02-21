# Feedback: identity-eventization completion review

Date: 2026-02-20  
Reviewed against: `docs/planning/IDENTITY_EVENTIZATION_COMPLETION_INSTRUCTIONS.md`

## Final verification snapshot

- `rg` SC1 check: no matches in `src/identity/ops.rs`.
- `rg` SC2/SC3 legacy-call check: no matches in `src/service.rs`, `src/event_pipeline.rs`, `src/event_modules`, `tests`.
- `bash scripts/check_boundary_imports.sh`: pass.
- `cargo check`: pass.
- `cargo test --lib -q`: pass (457/457).
- `cargo test --test scenario_test -q`: pass (65/65).

## Findings status

No unresolved High/Medium findings remain.

## Resolved findings

1. **Resolved (High): SC3 identity-special pipeline callout**
   - Fixed by routing post-drain retry through generic event-module hook dispatch.
   - Evidence: `src/event_pipeline.rs` now calls `crate::event_modules::post_drain_hooks(...)`; module-specific logic lives in `src/event_modules/mod.rs`.

2. **Resolved (Medium): SC4 canonical command coverage gap**
   - Fixed by migrating fixtures/helpers to workspace command APIs.
   - Evidence: `src/testutil.rs` uses `workspace::commands::create_user_invite_raw` and `workspace::commands::join_workspace_as_new_user`.

3. **Resolved (Medium): SC5 boundary-check helper leak gap**
   - Fixed by extending boundary checks to ban leaked helper-level workflow usage in forbidden layers.
   - Evidence: `scripts/check_boundary_imports.sh` contains explicit checks for `identity::ops::create_user_invite_events` / `create_device_link_invite_events` leakage and passes.

4. **Resolved (Low): evidence naming mismatch**
   - Fixed by updating the evidence doc with concrete, existing test names and references.
   - Evidence: `docs/planning/IDENTITY_EVENTIZATION_COMPLETION_EVIDENCE.md`.

## Conclusion

Branch satisfies SC1-SC5 with passing checks and no unresolved required work.
