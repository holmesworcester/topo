# Interactive Retirement Execution Plan

Date: 2026-02-18
Target branch: `master`
Scope: retire `topo interactive` while preserving user-facing behavior through daemon-backed non-interactive CLI.

## Objective

Move all useful interactive command functionality and UX affordances into the daemon-backed CLI path, then remove interactive mode and its dedicated code/tests/dependencies.

Also add CLI DB-alias affordances so `--db` can resolve registry aliases/indexes (for example `--db 1`) in addition to raw paths.

Constraints:

1. Preserve user-facing behavior unless explicitly marked suspect.
2. Keep one command path: CLI -> RPC -> service/event modules (no direct SQL in CLI).
3. Maintain realism: no in-process fake sharing shortcuts.
4. Tests must stay green at each stage; each behavior change must include tests.
5. Completion scope: static shell completion only (subcommands/flags/path hints); no dynamic runtime completion hooks.
6. POC replacement policy applies: remove superseded flags/paths in the same round (no long dual-path compatibility).

## Current Interactive Surface (to migrate)

Interactive commands today:

1. `new-workspace`
2. `send`
3. `messages`
4. `react`
5. `reactions`
6. `delete`
7. `invite`
8. `accept-invite`
9. `link`
10. `accept-link`
11. `accounts`
12. `switch`
13. `channels`
14. `new-channel`
15. `channel`
16. `users`
17. `keys`
18. `workspaces`
19. `status`
20. `identity`
21. `ban`

## Parity Matrix

Preserve as-is (already present in non-interactive):

1. `send`, `messages`, `react`, `reactions`, `delete` (`delete-message`), `users`, `keys`, `status`, `accept-invite`.

Preserve via existing daemon multi-tenant frontend semantics:

1. `accounts` -> `peers`
2. `switch` -> `use-peer`

Add missing CLI/RPC commands:

1. `link` (create device-link invite)
2. `accept-link`
3. `ban`
4. `identity` (combined view for transport + active user/peer)
5. `workspaces` alias (keep `networks` as compatibility alias during cutover round, then remove old name in same round per POC replacement policy).

Add missing frontend affordances:

1. Invite number aliases (for `accept-link`; `accept-invite` is pre-daemon bootstrap and takes raw links only)
2. Message number aliases (for `react` and `delete-message`)
3. User number aliases (for `ban`)
4. Channel aliases (`channels`, `new-channel`, `channel`) as daemon frontend state over existing channel IDs
5. DB selector aliases for all registered DBs: `--db <path|name|index>`

Invite/link I/O contract (required):

1. `create-invite` and `link` must always emit the full real `topo://...` link.
2. Alias/number references are optional frontend convenience only and must not replace real-link output.
3. `accept-link` must accept either a real `topo://...` link or a daemon invite-ref selector. `accept-invite` is pre-daemon bootstrap and accepts raw links only (daemon state is not available).
4. Alias resolution for invite selectors always resolves to a stored full link, then parses bootstrap/workspace data from that link.
5. Invite creation inputs:
   - `--public-addr <host:port>` (published bootstrap endpoint in the link),
   - `--public-spki <hex32>` (optional; defaults to local transport SPKI if omitted).
6. If `--public-addr` points to a different always-on peer, caller must provide that peer's matching `--public-spki`.
7. Accept flows must use the `public_addr` + `public_spki` carried by the resolved link payload; no out-of-band override in accept commands.
8. Script-stable output: `create-invite` and `link` must print the full link in a predictable machine-readable line format before any optional alias/help text.

Add missing DB registry commands:

1. `db add <path> [--name <alias>]`
2. `db list`
3. `db remove <selector>`
4. `db rename <selector> <name>`
5. `db default <selector>`

Suspect functionality (explicit decision required):

1. `new-workspace --name/--username/--devicename` values are mostly UI labels today and not canonical event state.
2. Channel names are local aliases, not shared protocol state.

Plan default: preserve these as frontend-only affordances, but document clearly as local UI metadata.

## Implementation Plan

### Phase 0: DB Registry and `--db` Alias Resolution

Add a local CLI DB registry (frontend-only, not protocol state):

1. Registry entries: `{name?, path, is_default, created_at}`
2. Stable storage file (for example `${HOME}/.topo/db_registry.json`; allow override by env for tests).
3. New command group:
   - `topo db add <path> [--name <alias>]`
   - `topo db list`
   - `topo db remove <selector>`
   - `topo db rename <selector> <name>`
   - `topo db default <selector>`
4. `--db` selector resolution:
   - if value looks like a path and exists, use path directly,
   - else resolve exact alias match,
   - else resolve numeric index from `db list`,
   - else fail with clear selector error.
5. If `--db` is omitted, use default entry when set; otherwise keep current fallback behavior.

Rules:

1. Alias/index resolution is CLI frontend behavior only.
2. Raw path always remains valid and script-safe.
3. Indexes are convenience only; alias names are the stable automation target.
4. Registry ownership boundary: DB registry is CLI-frontend persistent state and must not be moved into protocol/event state.

### Phase 1: Daemon Frontend State Contract

Add daemon-side in-memory frontend state (in `DaemonState`) to support cross-invocation aliases:

1. `active_peer` (already exists)
2. `invite_refs`: ordered list of invite/link strings
3. `channel_aliases`: per-peer ordered channel list (`name`, `channel_id`)
4. `active_channel_by_peer`: selected channel per active peer

Rules:

1. Raw IDs/links always accepted.
2. Numeric aliases resolve against daemon state for the active peer/session.
3. Frontend state is ephemeral across daemon restart.
4. Bootstrap address must come from the resolved invite link payload; no separate bootstrap lookup path for alias selectors.
5. Ownership boundary: invite/channel alias caches are daemon in-memory state only; DB registry remains CLI persistent state.

### Phase 2: RPC Contract Expansion

Extend `RpcMethod` and server dispatch with:

1. `CreateInvite { public_addr, public_spki? }` (replace bootstrap-named field)
2. `CreateDeviceLink { public_addr, public_spki? }`
3. `AcceptLink { invite, devicename }`
4. `Ban { target }` (`target` supports raw ID or alias selector)
5. `Identity`
6. Optional explicit alias endpoints if needed (`Invites`, `Channels`, `UseChannel`, `NewChannel`), or encode aliases directly in command methods.

Keep all alias resolution daemon-side (not process-local CLI-side).

### Phase 3: Service-Layer Wrappers (No CLI SQL)

Promote existing conn-only helpers to daemon-usable wrappers where needed:

1. Create user/device-link invite for active peer from persisted key material with explicit published endpoint inputs (`public_addr`, `public_spki?`).
2. Accept device-link invite via existing async service path.
3. Ban by user selector (resolve selector -> event ID -> `UserRemoved` emission).
4. Message selector wrappers for `react`/`delete`.
5. Identity summary response.

Result: CLI only calls RPC; RPC only calls service APIs.

### Phase 4: CLI Command Surface and Affordances

Add/adjust commands in `src/main.rs`:

1. `create-invite --public-addr <host:port> [--public-spki <hex32>]`
2. `link --public-addr <host:port> [--public-spki <hex32>]`
3. `accept-link --invite <n|link> --devicename <name>`
4. `ban --user <n|id>`
5. `identity`
6. `workspaces` alias
7. Selector grammar for message/user/invite args: accept `N`, `#N`, hex/base64/raw link forms as applicable.
8. Output contract for `create-invite`/`link`: print full link in a machine-friendly form; optional alias metadata may be printed additionally.
9. Add `topo completions <bash|zsh|fish|powershell|elvish>` (clap-generated static completion scripts).
10. Add path hint for `--db` argument so shell path completion works for raw DB paths.
11. Replace old invite-creation flag naming in one round:
   - remove `--bootstrap` from user-facing invite/link creation commands,
   - use `--public-addr` consistently in help, docs, and tests.

For channels:

1. Add `channels`, `new-channel <name>`, `channel <n|id>` commands backed by daemon frontend state.
2. `send` uses selected channel for active peer unless overridden with explicit `--channel`.

### Phase 5: Test Migration and Interactive Removal

Add/port tests to non-interactive suites:

1. Port behavior from `tests/interactive_test.rs` into `tests/cli_test.rs` / `tests/rpc_test.rs` / dedicated daemon-frontend tests.
2. Add selector/alias tests:
   - invite number -> accept-invite/accept-link
   - message number -> react/delete
   - user number -> ban
   - channel alias selection
3. Add link/accept-link end-to-end tests.
4. Add identity/workspaces alias tests.
5. Add DB registry/selector tests:
   - `db add/list/remove/rename/default`
   - `--db <alias>` and `--db <index>` resolution
   - omitted `--db` uses default registry entry
6. Add published-endpoint tests:
   - `create-invite`/`link` with default `public_spki` uses local transport SPKI,
   - explicit `--public-spki` is encoded in link and used by accept flow,
   - mismatch cases fail with clear transport/bootstrap diagnostics.
7. Add completion smoke tests:
   - `topo completions bash` (and one non-bash shell) returns non-empty scripts,
   - docs/examples use numeric selectors (`1`, `#1`) rather than relying on dynamic completion.

After parity tests are green:

1. Remove `Commands::Interactive` branch from `src/main.rs`.
2. Remove `src/interactive.rs` and `pub mod interactive` from `src/lib.rs`.
3. Remove `tests/interactive_test.rs`.
4. Drop `rustyline` and `dirs-next` from `Cargo.toml`.

## Verification Gates

Run at end of each phase:

1. `cargo check`
2. `cargo test --test rpc_test`
3. `cargo test --test cli_test`
4. `cargo test --test scenario_test --no-run`
5. `cargo test --test interactive_test --no-run` must fail after interactive removal (guard against accidental retention).

Final retirement gate:

1. `cargo test` full pass
2. Grep guards:
   - no `Commands::Interactive`
   - no `src/interactive.rs`
   - no `rustyline`/`dirs-next` deps

## Definition of Done

1. All non-suspect interactive capabilities are available through daemon-backed non-interactive CLI.
2. Alias affordances are daemon/frontend-backed and survive across separate CLI invocations while daemon is running.
3. Interactive mode code/tests/dependencies are fully removed.
4. Docs (`docs/PLAN.md`, `docs/DESIGN.md`, `TODO.md`) updated to one canonical CLI path.
5. DB registry affordances are documented as frontend conveniences with raw-path fallback preserved.
