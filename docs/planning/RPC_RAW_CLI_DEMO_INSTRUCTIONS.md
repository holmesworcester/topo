# RPC Raw CLI Demo Instructions

Date: 2026-03-04
Branch: `feat/rpc-cli-demo`
Worktree: `/home/holmes/poc-7-rpc-cli-demo`

## Goal

Add a CLI demo surface that:
1. Lists the actual daemon RPC methods and their parameters.
2. Shows method-level parameter details for a named RPC.
3. Lets users submit raw RPC calls from CLI using JSON.

The output should be useful for live demos of the wire-facing API without adding a second "interactive mode."

## Scope

In scope:
1. New CLI namespace `topo rpc ...`.
2. Method catalog output (`methods`, `describe`).
3. Raw call submission (`call`) via:
   - method JSON
   - full request JSON envelope
   - file input
   - stdin input
4. Basic tests for command parsing and raw RPC roundtrip behavior.
5. Docs/readme snippets for demo usage.

Out of scope:
1. Any RPC protocol redesign.
2. New daemon RPC methods.
3. Authentication/authorization changes on local socket.
4. Interactive shell mode.

## Target CLI UX

1. `topo rpc methods [--json]`
2. `topo rpc describe <MethodName> [--json]`
3. `topo rpc call --method-json '<json>'`
4. `topo rpc call --request-json '<json>'`
5. `topo rpc call --file <path>`
6. `topo rpc call --stdin`

Global flags (`--db`, `--socket`) should behave exactly like existing daemon-backed commands.

## Canonical RPC Method Set

Source of truth remains `src/runtime/control/rpc/protocol.rs` `RpcMethod`.

Current method names to expose in `topo rpc methods`:
1. `Status`
2. `Messages`
3. `Send`
4. `SendFile`
5. `Generate`
6. `GenerateFiles`
7. `AssertNow`
8. `AssertEventually`
9. `TransportIdentity`
10. `React`
11. `DeleteMessage`
12. `Reactions`
13. `Users`
14. `Keys`
15. `Workspaces`
16. `IntroAttempts`
17. `CreateInvite`
18. `AcceptInvite`
19. `CreateDeviceLink`
20. `AcceptLink`
21. `Ban`
22. `Identity`
23. `Shutdown`
24. `Tenants`
25. `UseTenant`
26. `ActiveTenant`
27. `CreateWorkspace`
28. `Peers`
29. `Upnp`
30. `View`

## Implementation Plan (Staged)

1. Stage 1: Add new CLI command group
- In `src/runtime/control/main.rs`, add `Commands::Rpc { action: RpcAction }`.
- Add `RpcAction` with `Methods`, `Describe`, and `Call`.
- Wire all actions through existing daemon/socket path resolution helpers.

2. Stage 2: Add RPC method catalog metadata
- Add a new module (suggested: `src/runtime/control/rpc/catalog.rs`) containing display metadata:
  - method name
  - parameters (name/type/required/default)
  - short purpose string
  - example method JSON
- `methods` prints a compact table or list.
- `describe` prints detailed parameter info and example payloads.
- Add `--json` output mode for both commands.

3. Stage 3: Raw request submission plumbing
- Add client helper in `src/runtime/control/rpc/client.rs` to send a full `RpcRequest` object (not just typed `RpcMethod`).
- `call --method-json`:
  - parse JSON as `RpcMethod`
  - wrap with current `PROTOCOL_VERSION`
  - send and print response JSON
- `call --request-json|--file|--stdin`:
  - parse JSON as full `RpcRequest`
  - send as-is
- Enforce exactly one input source for `call`.
- Return non-zero on parse/protocol/RPC error.

4. Stage 4: Tests
- Add/extend tests in `tests/rpc_test.rs` and/or `tests/cli_test.rs`:
  - `topo rpc methods` includes known method names.
  - `topo rpc describe Send` shows `content`.
  - `topo rpc call --method-json '{"type":"Status"}'` succeeds against running daemon.
  - invalid JSON and ambiguous input flags fail clearly.
- Add catalog drift test:
  - assert catalog method set matches `RpcMethod` variants represented in the canonical test vector.

5. Stage 5: Docs and demo recipe
- Update `README.md` with a short "RPC demo from CLI" section.
- Include copy-paste command sequence for:
  - startup
  - listing methods
  - describing one method
  - calling status/send/messages with raw JSON

## Output and Error Behavior

1. `methods` and `describe` should not require daemon running.
2. `call` requires daemon and should reuse existing "daemon not running" messaging style.
3. Successful `call` prints formatted JSON response (`version`, `ok`, `error`, `data`).
4. On failure:
   - parse/validation errors go to stderr with actionable text.
   - RPC `ok=false` should still print the response body and exit non-zero.

## Suggested Examples

Method JSON:
```json
{"type":"Status"}
```

Full request JSON:
```json
{"version":1,"method":{"type":"Send","content":"hello from raw rpc"}}
```

## Verification

Required before handoff:
1. `cargo test -q --test rpc_test`
2. `cargo test -q --test cli_test`
3. `cargo test -q`

Manual smoke:
1. `topo --db demo.db start --bind 127.0.0.1:7443`
2. `topo --db demo.db rpc methods`
3. `topo --db demo.db rpc describe Send`
4. `topo --db demo.db rpc call --method-json '{"type":"Status"}'`
5. `topo --db demo.db rpc call --method-json '{"type":"Send","content":"demo"}'`
6. `topo --db demo.db rpc call --method-json '{"type":"Messages","limit":10}'`

## Completion Criteria

1. Demo user can discover the real RPC method catalog and params from CLI alone.
2. Demo user can submit raw JSON RPC method/request payloads from CLI.
3. CLI output is deterministic and script-friendly (`--json` where relevant).
4. Regression tests pass.
