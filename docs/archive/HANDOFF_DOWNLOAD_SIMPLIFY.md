# Download Simplification Handoff

## Scope

This work is happening only in this separate worktree:

- Worktree: `/home/holmes/poc-7/.codex-worktrees/download-simplify-cleanup`
- Branch: `codex/download-simplify-cleanup`

Do not continue on `/home/holmes/poc-7` `master`.

## Mission

Finish the "download simplification" cleanup without undermining the transport-auth simplifications already merged on `master`.

The intended end state is:

- discovery is ID-only and metadata-light
- sync data transfer is request-only
- durable sync truth is `wanted_events + wanted_sources`
- request serving is bounded in-memory, not SQLite egress-driven
- request/response is connection-scoped
- discovery rounds keep hot/cold cadence
- protocol/runtime names match the simplified model better
- realistic CLI/perf tests are green

## What Was Already Implemented In This Worktree

Large uncommitted refactor work is already present here. The important slices already changed are:

- `Frame::HaveList` -> `Frame::RequestIds`
- `Frame::RequestCredit` -> `Frame::ResponseCredit`
- `DiscoveryHint` now carries:
  - `event_id`
  - `semantic_type_code`
  - `encoded_size_bytes`
- `wanted_events` durable lease columns were removed from the hot path and request selection is byte-based
- connection-scoped request/response state is byte-based
- dead `PendingResponseQueue` was removed
- `SyncSessionHandler` was renamed to `SyncConnectionHandler`
- docs/comments were updated toward the simplified model
- schema epoch was bumped
- many contract/protocol/perf tests were already updated to the renamed frames

## Current Actual Blocker

The remaining problem is **not** the protocol rename itself.

The real blocker is:

- a newly accepted invitee can be durably accepted
- then a fresh long-lived daemon starts
- but bootstrap sync does not progress enough to derive the permanent peer signer
- tenant remains `[still joining]`
- realistic invite/perf tests time out waiting for readiness

This shows up as:

- `Messages: 0 projected`
- `blocked_events=4`
- missing chain:
  - `user`
  - `peer_invite_shared`
  - `peer_shared`
  - `peer_secret`
- startup log warning:
  - transitional transport identity still in use
- almost no useful daemon logs after startup

## Strong Current Hypothesis

The over-strong test helper was part of the confusion, but not the root cause.

I split the accept helper so there is now a distinction between:

- durable accept only
- durable accept plus transport convergence

That harness change exposed the real product gap more clearly:

- the accepted invitee does establish an initial connection/session
- but no discovery round or useful bootstrap transfer progresses on the restarted long-lived daemon

So the next agent should treat this as a **runtime/bootstrap progress bug**, not just a test helper bug.

## Evidence Collected

### 1. Unit/contract surface is mostly healthy

These were passing in the worktree:

- `cargo test -q --lib`
- `cargo test -q --test sync_contract_tests -- --test-threads=1`

### 2. Realistic bootstrap/perf still fails

This exact lane was failing:

- `cargo +stable test --release --test daemon_perf_test perf_sync_10k -- --nocapture --exact --test-threads=1`

With failure shape:

- accepted tenant exists
- transport target source remains `bootstrap`
- tenant never becomes ready
- runtime active, daemon socket present
- no messages projected

### 3. Cheat-proof realism tests fail the same way

This lane was failing too:

- `cargo test -q --test cheat_proof_realism_test -- --test-threads=1`

Both tests timed out on:

- `wait_for_active_tenant_ready(...)`

after starting the invitee daemon post-accept.

### 4. Preserved DB/log inspection

In preserved failing perf artifacts:

- inviter and invitee both had a `sync_runs` row
- both runs stayed:
  - `rounds = 0`
  - `events_sent = 0`
  - `events_received = 0`
  - `outcome = "in_progress"`
- `sync_run_events` was empty

That means:

- the long-lived sync handler started
- but no first sync frame was ever recorded
- the stall is likely before first `NegOpen`, or before logging begins inside the session body

### 5. Temporary accept helper boundary was too strong for perf/realism

I added this new helper in:

- `tests/cli_harness/mod.rs`

New helper:

- `accept_invite_with_identity_persisted_only(...)`

This is the right boundary for perf/realism setup:

- durable accept only
- let the long-lived daemon do the real bootstrap/sync work under test

I partially rewired tests to use it:

- `tests/daemon_perf_test.rs`
- `tests/cheat_proof_realism_test.rs`

That change is conceptually correct and should stay.

## Likely Next Debug Step

The highest-value next step is to identify where the long-lived invitee bootstrap path stalls **before the first sync frame**.

Best next move:

1. Add very small temporary sync-run markers around:
   - initiator start
   - workspace lookup success
   - negentropy setup complete
   - just before `NegOpen` send
   - responder start
   - first received `NegOpen`
2. Rerun:
   - `daemon_perf_test perf_sync_10k`
   - `cheat_proof_realism_test`
3. Use the preserved `sync_runs` / `sync_run_events` rows to locate the exact pre-`NegOpen` stall

This is better than guessing from daemon stdout, which currently has too little signal.

## Files Most Relevant To The Remaining Runtime Bug

- `src/runtime/peering/loops/connect.rs`
- `src/runtime/peering/loops/supervisor.rs`
- `src/runtime/transport/peering_boundary.rs`
- `src/runtime/peering/engine/startup.rs`
- `src/runtime/sync_engine/session_handler.rs`
- `src/runtime/sync_engine/session/initiator.rs`
- `src/runtime/sync_engine/session/responder.rs`
- `src/runtime/sync_engine/session/control_plane.rs`
- `tests/cli_harness/mod.rs`
- `tests/daemon_perf_test.rs`
- `tests/cheat_proof_realism_test.rs`

## Success Criteria

The next agent should treat the task as complete only when all of the following are true in this worktree:

### Runtime / design goals

- sync data transfer is request-only in the actual runtime path
- discovery remains ID-only plus lightweight metadata
- request serving remains bounded in-memory
- connection-scoped request/response state remains intact
- transport-auth simplification intent from `master` is preserved

### Realistic test goals

These must pass:

- `cargo test -q --lib`
- `cargo test -q --test sync_contract_tests -- --test-threads=1`
- `cargo test -q --test cheat_proof_realism_test -- --test-threads=1`
- `cargo +stable test --release --test daemon_perf_test perf_sync_10k -- --nocapture --exact --test-threads=1`

At minimum, the realistic invitee bootstrap path must no longer get stuck permanently at `[still joining]` after starting the fresh long-lived daemon.

### Protocol/naming cleanup goals

The following simplification cleanup should remain true:

- no reintroduction of push-style sync data sends
- no reintroduction of SQLite egress queue for live sync
- no backsliding on frame renames:
  - `RequestIds`
  - `ResponseCredit`

### Worktree hygiene

- keep work confined to this worktree branch
- commit the completed work on this worktree branch before handoff/review

## Deferred Follow-Up To Discuss After This Is Green

Once the current runtime/test blocker is resolved, return to this measurement concern:

> source creates quickly, source sends discovery hints quickly, sink observes them late, and the rest is fast

The likely future plan is:

- instrument the control path more precisely
- determine whether hint delay is caused by:
  - control scheduling
  - flush timing
  - observer cadence
  - session startup ordering
- then discuss a concrete fix plan

Do not prioritize that before the accepted-invite bootstrap regression is fixed.

## Note About Sandbox Pain

In this session, `exec_command` inside the normal sandbox frequently failed with:

- `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`

So the previous agent had to use escalated `/bin/bash -lc` for many reads/tests.

That is an environment problem, not a repo problem.
