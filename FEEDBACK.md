# Feedback: plan/cli-bootstrap-test-realism

## Branch snapshot
- Branch: `plan/cli-bootstrap-test-realism`
- Ahead/behind vs `origin/master`: `ahead 2`, `behind 0`
- Commit 1: `dd416e1` Replace direct SQL trust seeding with invite-create/invite-accept CLI commands
- Commit 2: `b945eb7` Address feedback: service-layer routing, deterministic invite SPKI, naming alignment

## Verification run
- `cargo test --test cli_test -q` ✅ pass
- `cargo test --test rpc_test -q` ✅ pass
- `cargo test --test scenario_test -q` ✅ pass
- `cargo test --test interactive_test -q` ✅ pass

## Findings (all resolved in commit 2)
1. ~~High: logic split between CLI and service layer~~ → Fixed: logic moved to `service::create_invite` / `service::accept_invite`; CLI commands are thin wrappers.
2. ~~Medium: `--expected-peer` fingerprint required up front~~ → Fixed: removed. Inviter derives expected SPKI from invite key via `expected_invite_bootstrap_spki_from_invite_key()`. Invitee installs deterministic transport cert via `install_invite_bootstrap_transport_identity()`.
3. ~~Medium: naming divergence~~ → Fixed: renamed to `create-invite` / `accept-invite`.
