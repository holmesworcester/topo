# QA Findings

From exploratory CLI testing across three connectivity modes: same-DB multi-tenant, multi-DB same-machine, and edge cases.

---

## Bugs

### 1. Username display bug in tenant list (FIXED)

`tenant list` and `view` show wrong usernames in multi-tenant same-DB setups. The `tenant_local_username()` SQL JOIN in `src/event_modules/workspace/queries.rs:333` matches all local peers in `local_transport_creds` instead of scoping to the current tenant's `recorded_by`. `ORDER BY event_id ASC LIMIT 1` then picks the wrong user.

**Fix applied**: Added `AND c.peer_id = ?1` to the JOIN condition in both `queries.rs` and `tests/cli_test.rs`.

### 2. `identity` command shows wrong User/Peer IDs

The `identity` command returns identical User and Peer short IDs across all databases in a multi-DB setup — it picks the first record found rather than matching against the local transport key. The `keys` command and `accept` output correctly show distinct identities. Same root-cause family as bug 1 (query doesn't scope to the active tenant's identity).

**Fix**: Scope the identity query to the active tenant's `recorded_by`, same pattern as bug 1 fix.

### 6. Partial workspace creation on encoding failure (PARTIAL FIX)

`create-workspace --username <65-chars>` fails with encoding error, but workspace/network events are already committed. The operation is not atomic — leaves DB with a workspace that has 0 users.

**Fix applied**: Upfront byte-length validation prevents the common case (rejects before any events are created). SAVEPOINT atomicity was attempted but reverted — bare `BEGIN`/`COMMIT` calls deep in the projection and queue stack (`project_queue`, `with_immediate_tx`, `sync_log`) conflict with outer SAVEPOINTs, causing "cannot start a transaction within a transaction" on the `accept` path. Full atomicity requires converting all internal transaction calls to SAVEPOINTs.

### 7–9. Empty username / message / reaction accepted (FIXED)

- `create-workspace --username ""` succeeds with blank display name.
- `send ""` creates an empty message (blank line in `view`).
- `react "" 1` creates a reaction with empty content.

**Fix applied**: Added non-empty/whitespace validation in projectors (`project_user`, `project_message`, `project_reaction`), returning `Reject` for empty/whitespace-only content.

### 10. Non-emoji text accepted as reaction (FIXED)

`react "not-an-emoji" 1` succeeds despite the parameter being named `<EMOJI>`. Arbitrary strings accepted.

**Fix applied**: Renamed parameter help text from "Emoji" to "Reaction text". Arbitrary short strings are accepted by design.

### 11. Daemon spontaneous death (intermittent)

Observed twice during same-DB multi-tenant testing. After some sequence of operations the daemon silently dies. Could not reliably reproduce.

**Fix**: Needs repro first. Add a panic hook that logs to a file before exit so the cause is captured next time it happens.

### 12. Raw SQLite error exposed to user (FIXED)

Starting with a non-existent parent directory shows `SqliteFailure(Error { code: CannotOpen, extended_code: 14 }, ...)` — internal Rust struct dump rather than a user-friendly message.

**Fix applied**: Added `friendly_db_error()` wrapper at all CLI entry points. Now shows e.g. `"cannot open database: directory does not exist: /foo/bar"`.

### 14. Invite link includes unreachable addresses when using specific `--bind` (FIXED)

`detect_bootstrap_addrs(port)` in `invite_link.rs:464` always enumerates all non-loopback network interfaces regardless of what the daemon is actually bound to. When `--bind 192.168.6.177:4433` is used, the invite embeds addresses like `100.67.2.56:4433` (tailscale) and various IPv6 addresses that the daemon is not listening on. When `--bind 127.0.0.1:4433`, the invite contains only unreachable addresses (loopback is skipped by the detector). Works by accident in the default `0.0.0.0` case because wildcard bind does listen on all interfaces.

**Fix applied**: `autodetect_bootstrap_addrs` now checks if the bind IP is a wildcard (`0.0.0.0`/`::`). If wildcard, enumerates all interfaces (unchanged). If specific IP, uses only that IP+port.

### 15. No version negotiation — mismatched builds cause endless connection errors (FIXED)

Two peers running different builds (e.g. `ae72119` vs `89d8d56`) produce endless "Data stream error: connection lost" at ~2/s with no indication the cause is a version mismatch. Protocol-breaking changes between commits have no graceful degradation.

**Fix applied**: `build.rs` embeds the git commit hash via `TOPO_GIT_HASH` env var. Session stream header bumped to v2 (22 bytes) with 8-byte commit hash field. Peers with mismatched hashes get a clear error and abort immediately.

### 13. Long DB path causes silent RPC failure (FIXED)

When the derived socket path exceeds ~108 chars (SUN_LEN), the daemon starts its QUIC listener but the RPC server silently fails. Daemon runs but is unreachable. Should detect this upfront and suggest `--socket`.

**Fix applied**: Socket path length validated at daemon startup before any binding. Fails with `"socket path too long (N chars, max 107): <path>"` and suggests `--socket`.

---

## Not bugs (by design)

### Invites are multi-use

The same invite link can be accepted by multiple peers or the same peer multiple times. Each acceptance creates a new local tenant with a fresh user+peer identity. This is intentional — documented in DESIGN.md §9.2.

### `transport-identity` errors on multi-tenant DB (FIXED)

Replaced with `transport-keys` which lists all local transport keys with peer_id and source. Works for both single and multi-tenant DBs.

### Reactions should be idempotent (FIXED)

Display queries now GROUP BY (author_id, emoji) per message, picking the earliest by created_at. Event layer still accepts duplicates; deduplication is query-side only.

### Messages: show 50 newest with overflow note (FIXED)

Now selects the 50 newest messages (subquery picks newest, re-sorted ascending). Shows "(N older messages not shown)" when total exceeds displayed count. Message numbers reflect global position.

### ~~"Content too long" error should state the limit~~ (NOT A BUG)

The error already reads `"text too long for slot: 1025 bytes, max 1024"` — the QA agent misquoted it. No change needed.

---

### Fix tenant numbering instability (FIXED)

`list_tenants_for_display()` sorted active tenant to position 1, so `tenant use N` numbers shifted when switching tenants. Fixed: sort by stable key (workspace name, then username, then event_id) without active-first bias. Active tenant marked with `*` but position unchanged.

### `accept-link` should take invite as positional arg (FIXED)

`accept` takes the invite as a positional arg, but `accept-link` required `--invite` flag. Fixed: removed `#[arg(long)]` from `accept-link`'s invite parameter.

### `tenant list` should show usernames (FIXED)

Previously showed `peer_id (workspace: Name)`. Fixed: now shows `username@WorkspaceName` format.

## UX observations (low priority)

- **`tenant list` vs `view` use different ID formats**: hex peer_ids vs base64 event_ids.
- **Active tenant lost on daemon restart**: selection is in-memory only. <!-- not a bug; this is fine; active tenant is ephemeral state in this model -->
