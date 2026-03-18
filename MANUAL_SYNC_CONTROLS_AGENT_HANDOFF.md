# Manual Sync Controls Agent Handoff

## Mission

Implement tenant-scoped manual sync controls for the `topo` CLI and daemon on a fresh worktree based on the latest `master`, so a user can:

- keep discovery automatic
- force a sync round with one peer or all peers and get an inline breakdown for that action
- manually trigger queued requests for one peer or all peers and see the exact event IDs requested
- configure per-tenant sync behavior for requests, responses, and forward-on-have with clear CLI-visible state
- demonstrate the feature with text captures of real CLI sessions

This work was explicitly moved into a dedicated worktree because `AGENTS.md` forbids implementation work in the main worktree.

## Approved Scope

- Discovery is always automatic.
- There is no `discovery=manual` or `discovery=disabled`.
- This first cut does **not** add a standalone `topo sync report ...` subsystem.
- This first cut does **not** add SQLite persistence for manual-round reporting output.
- `topo sync round ...` should print the useful breakdown inline as part of the action itself.
- `topo sync request ...` must list the exact requested event IDs, not only counts.
- Policy is per tenant.
- Request responses may still be automatic after requests are sent.
- Forward-on-have policy can be surfaced, but actual forward-on-have behavior is deferred until the feature exists on `master`.

## Required Deliverables

1. New CLI/RPC surface for tenant sync policy/mode control.
2. New CLI/RPC surface for manual sync rounds.
3. New CLI/RPC surface for manual request issuance.
4. Runtime wiring from daemon to live sync sessions.
5. Inline round/report formatting for manual round actions.
6. Exact event ID listing for manual request actions.
7. Automated tests covering policy storage and command behavior where practical.
8. Plain-text CLI session captures showing the feature working end-to-end.

## Success Criteria

### SC1: Per-tenant sync policy exists and persists

The system must persist a per-tenant policy with at least these knobs:

- `requests`: `auto|manual|disabled`
- `responses`: `auto|manual|disabled`
- `forward_on_have`: `auto|manual|disabled`

Discovery must not be a policy knob.

Proof checks:

- automated DB tests prove default values, round-trip persistence, and tenant scoping
- CLI can show current policy for a tenant
- CLI can update policy for a tenant and read it back correctly

### SC2: Manual sync round commands exist

The CLI must support forcing an extra immediate sync round:

- `topo sync round peer <peer> ...`
- `topo sync round all ...`

The action must target live sessions and return a useful inline breakdown of the round. This is specifically for the manual action, not a separate report browser.

Proof checks:

- command succeeds against a live peer session
- command against all peers fans out to all eligible live peers
- output clearly identifies peer, duration, and exchange details captured for the manual round
- output distinguishes useful matching and mismatch information from the negentropy exchange

### SC3: Manual request commands exist and list exact events

The CLI must support manual request issuance:

- `topo sync request peer <peer> ...`
- `topo sync request all ...`

These commands must use the existing request queueing/scheduling logic, but the CLI output must list every selected event ID grouped by peer, not only counts.

Proof checks:

- command succeeds against a live peer session
- output groups requested IDs by peer
- output lists exact event IDs that were sent as requests
- when no requests are eligible, the output says so explicitly

### SC4: Manual policy actually affects runtime behavior

At minimum, automatic requests must respect tenant policy:

- `auto`: existing behavior remains automatic
- `manual`: automatic request issuance is suppressed, but manual request commands still work
- `disabled`: automatic request issuance is suppressed, and manual request commands should either refuse or clearly report disabled behavior

If response gating is implemented in this cut, it must follow the same explicit policy semantics. If not implemented, document the gap before closing the task.

Proof checks:

- integration or scenario test proving automatic requests happen in `auto`
- integration or scenario test proving automatic requests do not happen in `manual`
- manual request command still succeeds in `manual`
- disabled behavior is explicit and not ambiguous

### SC5: Manual round output tells the user what changed

After a manual round, the output must make it clear what was learned about peer state, not only that frames were exchanged.

Proof checks:

- output includes what the peer was newly observed to have, or explicitly says that nothing new was learned
- output is scoped to the manual round action and not polluted by unrelated background activity

### SC6: Real text captures exist

The final deliverable must include plain-text CLI session captures showing the commands and outputs working correctly.

Proof checks:

- at least one capture for policy show/set
- at least one capture for `sync round peer` or `sync round all`
- at least one capture for `sync request peer` or `sync request all`
- capture(s) show concrete tenant and peer behavior, not placeholders

## End-to-End Validation Required

The finishing agent should not stop at unit tests. Run and capture these end-to-end checks:

1. Start at least two peers under a tenant with automatic discovery enabled by default.
2. Set the tenant policy so `requests=manual`.
3. Produce a state where one peer knows events the other wants.
4. Show that background discovery still happens but automatic requests do not fire.
5. Run `topo sync round peer <peer>` and capture the inline breakdown.
6. Run `topo sync request peer <peer>` and capture the exact requested event IDs.
7. Show the requested events arrive and normal automatic responses complete the flow.
8. If `all` variants are implemented, repeat with `sync round all` and `sync request all`.

If response gating is implemented, add a separate end-to-end capture for `responses=manual` or `responses=disabled`.

## Current Implementation State

Implementation started in:

- worktree: `/home/holmes/poc-7/.codex-worktrees/manual-sync-controls-impl`
- branch: `codex/manual-sync-controls-impl`
- base: latest `origin/master` at the time this worktree was created

The following changes were already started:

### Added shared policy types

Files:

- `src/shared/sync_control.rs` new
- `src/shared/mod.rs` updated

Implemented:

- `SyncPolicyMode` enum with `Auto`, `Manual`, `Disabled`
- `SyncModePreset` enum with preset-to-policy mapping
- `TenantSyncPolicy` struct with `requests`, `responses`, `forward_on_have`

### Added DB storage for policy

Files:

- `src/state/db/sync_control.rs` new
- `src/state/db/mod.rs` updated

Implemented:

- schema creation for sync control storage
- `load_policy`
- `save_policy`
- `update_policy`
- DB tests for defaults, round-trip, and tenant scoping

### Added runtime registry skeleton

Files:

- `src/runtime/sync_control.rs` new
- `src/runtime/mod.rs` updated

Implemented:

- `ManualFrameEvent`
- `ManualSyncRoundCapture`
- `ManualSyncRequestResult`
- `SessionCommand`
- `ActionCaptureHub`
- `SyncControlRegistry` skeleton with:
  - DB-backed policy load/save/update
  - live session registration
  - target selection for peer/all commands
  - trigger methods for round/request actions

### Added logging helper for manual capture

File:

- `src/runtime/sync_engine/session/logging.rs`

Implemented:

- exposed lane/dir string helpers
- added `capture_frame_for_manual_action(frame, capture_full_ids)`

## Incomplete / Likely Broken Areas

The work is not complete and likely does not compile yet.

Most importantly, `src/runtime/sync_engine/session_handler.rs` was being patched when work stopped. Another agent must inspect the current file state before continuing. The intent was to:

- add `SyncControlRegistry` plumbing into the session handler
- register live sessions with tenant/peer identity
- inject `ActionCaptureHub` into adapters
- pass command/policy/capture channels into the initiator and responder session loops

The constructors were already partially changed to carry sync control state, but the `on_session` flow may be half-converted.

## Likely Remaining Work

1. Inspect and fix `src/runtime/sync_engine/session_handler.rs`.
2. Thread `Arc<SyncControlRegistry>` through daemon startup and peering runtime:
   - `src/runtime/control/main.rs`
   - `src/runtime/control/node.rs`
   - `src/runtime/peering/engine/mod.rs`
   - `src/runtime/peering/engine/supervisor.rs`
   - `src/runtime/peering/loops/connect.rs`
   - `src/runtime/peering/loops/accept.rs`
3. Extend initiator/responder loop signatures to receive:
   - session command receiver
   - tenant policy watch receiver
   - manual capture hub
4. Implement forced manual round handling in the initiator path.
5. Implement manual request handling using the existing wanted/request scheduler logic.
6. Refactor the request scheduler so the CLI can print exact requested event IDs.
7. Add a helper in wanted-state storage to compare peer-known IDs before vs after a manual round.
8. Add RPC methods and CLI commands for:
   - `topo sync mode show|set`
   - `topo sync policy show|set`
   - `topo sync round peer|all`
   - `topo sync request peer|all`
9. Add tests.
10. Produce and save plain-text CLI session captures.

## Suggested Command Surface

The planned command surface from this session was:

```text
topo sync mode show --tenant <tenant>
topo sync mode set manual|auto|disabled --tenant <tenant>

topo sync policy show --tenant <tenant>
topo sync policy set --tenant <tenant> [--requests auto|manual|disabled] [--responses auto|manual|disabled] [--forward-on-have auto|manual|disabled]

topo sync round peer <peer> --tenant <tenant>
topo sync round all --tenant <tenant>

topo sync request peer <peer> --tenant <tenant>
topo sync request all --tenant <tenant>
```

If the codebase’s existing CLI conventions suggest a cleaner shape, follow the existing style, but preserve the approved semantics.

## Non-Goals For This Cut

- No standalone historical report browser.
- No SQLite persistence for manual round output.
- No discovery policy knob.
- No dependency on a forward-on-have implementation that does not exist on `master`.

## Known Environment Constraint

This repo/session repeatedly triggered sandbox failures even for local reads, typically:

```text
bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted
```

That is why this work stalled. Another agent should expect to use escalated local shell commands when needed, unless they can continue with direct file editing and existing context alone.

## Recommended First Actions For The Next Agent

1. Open this worktree, not the main repo root.
2. Inspect `git status` in the worktree.
3. Inspect `src/runtime/sync_engine/session_handler.rs` and reconcile partial edits.
4. Run a compile check as soon as the session-handler/runtime plumbing is repaired.
5. Finish CLI/RPC plumbing before polishing output formatting.
6. End with real CLI transcript captures, not only test results.

## Definition Of Done

The task is complete only when:

- all approved scope above is implemented
- success criteria SC1 through SC6 are satisfied
- proofs/checks for each SC are run
- end-to-end validation is run
- plain-text CLI session captures are available and included in the handoff or final delivery

