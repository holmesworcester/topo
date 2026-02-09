# CLI Expansion Review 2 (`cli-expansion` vs current `master`)

## Verdict
Not ready to merge into current `master` yet.

Local branch tests are green, but integration to `master` fails because this branch predates the workspace rename.

## Merge blockers

### 1. High: `identity_ops` still uses pre-rename `Network` symbols
- File: `src/identity_ops.rs:87`
- File: `src/identity_ops.rs:100`
- File: `src/identity_ops.rs:113`
- File: `src/identity_ops.rs:216`
- File: `src/identity_ops.rs:253`
- File: `src/identity_ops.rs:371`

When merged into current `master`, compile fails with:
- `ParsedEvent::Network` not found (now `ParsedEvent::Workspace`)
- `NetworkEvent` not found (now `WorkspaceEvent`)
- `network_id` field not found on `UserInviteBootEvent` / `InviteAcceptedEvent` (now `workspace_id`)

### 2. High: REPL still queries removed `networks` table
- File: `src/interactive.rs:1176`
- File: `src/main.rs:945`

Current schema uses `workspaces` table. On merged state, interactive tests fail with:
- `Error: no such table: networks`

### 3. Medium: CLI surface regresses workspace terminology
- File: `src/interactive.rs:196`
- File: `src/interactive.rs:201`
- File: `src/interactive.rs:285`
- File: `src/interactive.rs:302`
- File: `tests/interactive_test.rs:317`

This branch reintroduces `new-network` / `networks` command language. Master already switched to workspace naming as a breaking change.

## Recommended fix plan

1. Rebase or merge latest `master` into `cli-expansion`.
2. In `src/identity_ops.rs`, migrate event constructors and field names:
- `ParsedEvent::Network` -> `ParsedEvent::Workspace`
- `NetworkEvent` -> `WorkspaceEvent`
- `network_id` event fields -> `workspace_id` event fields
3. In REPL/non-interactive listing code:
- `FROM networks` -> `FROM workspaces`
- `network_id` column -> `workspace_id` column
4. Align command/output wording with workspace terminology (or keep aliases, but workspace should be canonical).
5. Re-run:
- `cargo test -q --test interactive_test`
- `cargo test -q`

