# Identity Layer Removal Evidence

Date: 2026-02-21
Branch: `exec/identity-layer-removal-plan-instructions`

## SC1: No identity module remains

1. `src/identity/` directory does not exist:
   ```
   $ test ! -d src/identity && echo "PASS"
   PASS
   ```

2. `src/lib.rs` has no `pub mod identity;`:
   ```
   $ rg "pub mod identity;" src/lib.rs
   (no matches)
   ```

## SC2: Event-domain identity helpers are workspace-local

1. No `identity::ops::*` references anywhere:
   ```
   $ rg "identity::ops::" src tests
   (no matches)
   ```

2. Workspace module owns invite/event helper APIs and associated types:
   - `src/event_modules/workspace/identity_ops.rs` owns: `InviteData`, `InviteType`, `JoinChain`, `LinkChain`, `InviteBootstrapContext`, `SIGNER_KIND_PENDING_INVITE_UNWRAP`, `ensure_content_key_for_peer`, `wrap_content_key_for_invite`, `unwrap_content_key_from_invite`, `store_pending_invite_unwrap_key`, `clear_pending_invite_unwrap_key`, `create_user_invite_events`, `create_device_link_invite_events`.
   - `src/event_modules/workspace/commands.rs` imports from `super::identity_ops`.

## SC3: Transport identity logic is transport-local

1. No `identity::transport::*` references anywhere:
   ```
   $ rg "identity::transport::" src tests
   (no matches in src/ or tests/ referencing old path)
   ```

2. `src/transport/identity.rs` exists and is used:
   ```
   $ test -f src/transport/identity.rs && echo "EXISTS"
   EXISTS
   $ rg "transport::identity::" src --count
   src/event_modules/workspace/commands.rs:2
   src/event_pipeline.rs:1
   src/peering/loops/connect.rs:1
   src/peering/workflows/bootstrap.rs:2
   src/rpc/server.rs:1
   src/service.rs:1
   src/testutil.rs:4
   src/transport/identity_adapter.rs:2
   ```

3. Adapter install boundary remains enforced:
   - `src/transport/identity_adapter.rs` is the sole caller of `install_peer_key_transport_identity` and `install_invite_bootstrap_transport_identity_conn`.
   - `scripts/check_boundary_imports.sh` enforces this boundary.

## SC4: Invite link logic is not top-level identity

1. No `identity::invite_link::*` references anywhere:
   ```
   $ rg "identity::invite_link::" src tests
   (no matches)
   ```

2. Invite link parser/encoder lives in workspace-local module:
   - `src/event_modules/workspace/invite_link.rs` owns: `parse_invite_link`, `create_invite_link`, `parse_bootstrap_address`, `resolve_bootstrap_socket_addr`, `rewrite_bootstrap_addr`, `InviteLinkError`, `InviteLinkKind`, `BootstrapAddress`, `ParsedInviteLink`.
   - `parse_bootstrap_address` is also used by `src/peering/runtime/autodial.rs` via `crate::event_modules::workspace::invite_link::parse_bootstrap_address`.

## SC5: Docs and boundary checks encode the new model

1. `scripts/check_boundary_imports.sh` fails on new `crate::identity::` usage:
   - Script includes: `check_no_match 'crate::identity::' src/` and `check_no_match 'pub mod identity;' src/lib.rs`.
   ```
   $ bash scripts/check_boundary_imports.sh
   All boundary checks passed.
   ```

2. `docs/DESIGN.md` describes the final ownership:
   - Section 2.4.1 updated: identity_ops.rs, invite_link.rs, transport/identity.rs locations documented.
   - Identity ownership boundary section updated with new module paths and explicit note that `src/identity/` has been eliminated.

3. `docs/PLAN.md` describes the final ownership:
   - Section 17.1.4 updated to reference `src/transport/identity.rs`.
   - Section 17.2.1 updated to reference `src/event_modules/workspace/identity_ops.rs`.
   - Implementation files table updated with new paths.

## Verification command outputs

```
$ rg -n "pub mod identity;|crate::identity::|identity::(ops|transport|invite_link)" src tests
src/transport/mod.rs:3:pub mod identity;
```
(Only match is the new `transport::identity` module declaration - correct.)

```
$ test ! -d src/identity
(exit 0 - PASS)
```

```
$ bash scripts/check_boundary_imports.sh
All boundary checks passed.
```

```
$ cargo check
Finished `dev` profile [unoptimized + debuginfo] target(s)
```

```
$ cargo test --lib -q
test result: ok. 405 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

```
$ cargo test --test scenario_test -q
test result: ok. 65 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

```
$ cargo test --test projectors -q
test result: ok. 52 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```
