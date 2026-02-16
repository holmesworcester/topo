# Merge Readiness: plan/cli-bootstrap-test-realism

- Status: `NOT READY (as-is)`
- Head: `0d7ee5030ed4`
- Ahead/behind vs current `master`: `ahead 3`, `behind 3`

## Verified
- `cargo test --test cli_test -q` ✅
- `cargo test --test scenario_test -q` ✅
- `cargo test --test rpc_test -q` ✅
- `cargo test --test interactive_test -q` ✅

## Blockers
1. Branch is not rebased to current `master` (3 commits behind).
2. Introduces alternate invite API surface (`create_invite` / `accept_invite`) while current master line uses `svc_*` invite APIs; this is merge-conflict/duplication risk.

## Required before merge
1. Rebase onto current `master`.
2. Unify naming/API with existing service-layer invite path (`svc_create_invite` / `svc_accept_invite`) to avoid parallel command models.
