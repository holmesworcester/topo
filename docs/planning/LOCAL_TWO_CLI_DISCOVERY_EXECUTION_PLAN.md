# Local Two-CLI Discovery Execution Plan

Date: 2026-02-17
Branch: `exec/local-two-cli-discovery`
Worktree: `/home/holmes/poc-7-local-two-cli-discovery`

## Goal

Make two CLI users on the same Linux machine, each with a separate DB and separate sync daemon process, reliably discover and sync after a valid invite flow.

Target runtime shape:
1. Alice and Bob run separate `p7d`/`sync` processes.
2. Bob accepts Alice's invite.
3. Ongoing sync works locally without manual `--connect`.
4. mDNS discovery behavior is correct for loopback-bound local daemons.

## Scope

In scope:
1. Discovery/advertisement address correctness for same-host daemons.
2. Runtime and tests proving two separate local daemons discover/sync locally.
3. Documentation updates for local same-machine daemon usage.

Out of scope:
1. Intra-daemon local fanout between tenants in one process.
2. Multi-device LAN tuning beyond what is needed for same-host correctness.
3. Protocol/model semantic changes unrelated to local discovery behavior.

Execution constraints:
1. No compatibility/migration shims are required for this POC path.
2. If a new path replaces an old one, remove the old path in the same change-set.
3. Tests must remain green at each implementation stage (not only at the end).

## Problem Hypothesis

Current mDNS advertisement chooses a non-loopback host IP by default. When daemons are bound to `127.0.0.1:<port>`, advertising non-loopback addresses can cause local discovery dials to target an address the daemon is not listening on.

## Implementation Plan (Staged)

1. Stage 1: Discovery address policy
- In `run_node` / discovery setup, derive an explicit advertise IP from the actual bind/listen address.
- If daemon listens on loopback, advertise loopback for same-host reachability.
- Keep non-loopback advertisement for wildcard/non-loopback binds.
- Verify:
  - `cargo test -q --test mdns_smoke`
  - `cargo test -q --test cli_test`

2. Stage 2: Thread address explicitly through discovery API
- Update discovery constructor/signature to accept advertise IP instead of internally guessing host IP.
- Remove any now-incorrect implicit address inference from discovery internals.
- Verify:
  - `cargo test -q --test mdns_smoke`
  - `cargo test -q`

3. Stage 3: Regression tests
- Add/adjust integration test to exercise two separate daemons on same machine with invite + no manual connect.
- Ensure test asserts real event convergence across DBs.
- Add a targeted discovery test for loopback advertisement path if practical.
- Verify:
  - `cargo test -q --test cli_test`
  - `cargo test -q --test cheat_proof_realism_test`

4. Stage 4: Docs
- Add a short note in `DESIGN.md` or relevant runtime docs explaining same-host daemon discovery expectation.
- Keep language consistent with existing realism/no-shortcuts direction.
- Verify:
  - `cargo test -q`

## Verification

Required before handoff:
1. `cargo test -q --test cli_test`
2. `cargo test -q --test cheat_proof_realism_test`
3. `cargo test -q --test mdns_smoke` (with discovery feature path as configured in project)
4. `cargo test -q`

Manual smoke (recommended):
1. Start Alice daemon on `127.0.0.1:<A>` and Bob daemon on `127.0.0.1:<B>`.
2. Create/accept invite.
3. Send message from Bob.
4. Assert Alice receives it without manual endpoint targeting.

## Completion Criteria

1. Two separate same-host daemons can converge after invite acceptance without manual `--connect`.
2. Discovery uses an address compatible with daemon bind semantics.
3. Tests above are green.
4. No fallback simulator/data-copy shortcuts introduced.
