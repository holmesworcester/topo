# Feedback: `quic-holepunch`

## Snapshot
- Branch: `quic-holepunch` (`/home/holmes/poc-7-quic-holepunch`)
- Relative to `origin/master`: `0 behind / 3 ahead`
- Validation run on February 9, 2026:
  - `cargo test --test holepunch_test -- --nocapture`
  - Result: 3 passed, 0 failed

## What Is Strong
1. End-to-end flow is implemented and tested (intro send, receive, validate, dial, sync) (`tests/holepunch_test.rs:99`).
2. Intro handling has explicit rejection semantics for expiry and trust (`src/sync/punch.rs:68`, `src/sync/punch.rs:79`).
3. Punch success requires expected peer identity match before sync (`src/sync/punch.rs:133`).
4. Operator workflow is complete: one-shot intro, intro attempts view, and intro worker are all present in CLI (`src/main.rs:168`, `src/main.rs:190`, `src/main.rs:200`).
5. Transport hint separation is preserved (no canonical intro events projected) and is asserted by test (`tests/holepunch_test.rs:301`).

## Findings
1. NAT realism is still a remaining confidence gap.
   - Current integration test explicitly runs on localhost where punch is effectively regular connect (`tests/holepunch_test.rs:7`).
2. Implementation size is large for one branch.
   - Protocol, DB, engine, transport, CLI, and tests landed together, which can raise maintenance and review cost.

## Recommendation
1. This is currently the higher-value branch to ship first.
2. Add a Linux netns/NAT test lane to validate behavior under home-router-like mappings.
3. If desired later, adopt selective simplifications from `holepunch` only after preserving trust and identity checks already present here.
