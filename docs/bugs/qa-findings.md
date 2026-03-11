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

### 6. Partial workspace creation on encoding failure

`create-workspace --username <65-chars>` fails with encoding error, but workspace/network events are already committed. The operation is not atomic — leaves DB with a workspace that has 0 users.

**Fix**: The encoding length check already exists in the event encoder but fires too late (after workspace/network events are committed). Move validation into the User projector so it returns `Reject` for oversized usernames. For locally created events, `create_event_sync` already propagates `Reject` back as `CreateEventError::Rejected`, so the command will fail before workspace events are committed if the user event is created first — or the whole sequence needs to be wrapped in a transaction.

### 7–9. Empty username / message / reaction accepted

- `create-workspace --username ""` succeeds with blank display name.
- `send ""` creates an empty message (blank line in `view`).
- `react "" 1` creates a reaction with empty content.

**Fix**: Add non-empty content validation in the respective projectors (`project_user`, `project_message`, `project_reaction`), returning `ProjectionDecision::Reject` for empty/whitespace-only content. The `create_event_sync` → `CreateEventError::Rejected` path already surfaces projector rejections to commands, so no separate CLI-layer validation is needed. Projector strictness and local strictness match exactly because the projector *is* the single validation authority — both local creates and remote synced events go through the same path.

### 10. Non-emoji text accepted as reaction

`react "not-an-emoji" 1` succeeds despite the parameter being named `<EMOJI>`. Arbitrary strings accepted.

**Fix**: Accept for now — enforcing emoji-only is fragile across Unicode versions. Rename the parameter from `<EMOJI>` to `<TEXT>` or document that arbitrary short strings are allowed.

### 11. Daemon spontaneous death (intermittent)

Observed twice during same-DB multi-tenant testing. After some sequence of operations the daemon silently dies. Could not reliably reproduce.

**Fix**: Needs repro first. Add a panic hook that logs to a file before exit so the cause is captured next time it happens.

### 12. Raw SQLite error exposed to user

Starting with a non-existent parent directory shows `SqliteFailure(Error { code: CannotOpen, extended_code: 14 }, ...)` — internal Rust struct dump rather than a user-friendly message.

**Fix**: Catch `CannotOpen` in the DB open path and return a human-readable error like `"cannot open database: directory does not exist: <path>"`.

### 13. Long DB path causes silent RPC failure

When the derived socket path exceeds ~108 chars (SUN_LEN), the daemon starts its QUIC listener but the RPC server silently fails. Daemon runs but is unreachable. Should detect this upfront and suggest `--socket`.

**Fix**: Check derived socket path length at daemon startup before binding. If it exceeds the platform limit, fail with a clear error suggesting `--socket <shorter-path>`.

---

## Not bugs (by design)

### Invites are multi-use

The same invite link can be accepted by multiple peers or the same peer multiple times. Each acceptance creates a new local tenant with a fresh user+peer identity. This is intentional — documented in DESIGN.md §9.2.

### `transport-identity` errors on multi-tenant DB

`transport-identity` is a pre-workspace bootstrap command. Once multiple tenants exist there is no single transport identity to return. The error message is correct behavior. Being replaced by `transport-keys` (see planned changes below).

---

## Planned changes

### Rename `transport-identity` to `transport-keys`

Replace the single-identity-only `transport-identity` command with `transport-keys` that lists all rows from `local_transport_creds` with peer_id and source. Works for both single and multi-tenant DBs.

### Reactions should be idempotent

Duplicate reactions (same user, same message, same emoji) are currently allowed as separate events. Queries should pick the winning reaction per user per message per emoji (winner by timestamp). The event layer can accept duplicates but the display layer should deduplicate.

### Messages: show 50 newest with overflow note

`messages` currently shows 50 items with no indication of truncation. Change to show the 50 newest messages. When there are more than 50, display a note like "(25 older messages not shown)". Pagination is out of scope for now.

### "Content too long" error should state the limit

Error says `"content too long: 1025 bytes"` but doesn't tell the user the max is 1024. Should match the username error pattern which says "max 64".

---

### Fix tenant numbering instability

`list_tenants_for_display()` sorts active tenant to position 1, so `tenant use N` numbers shift when switching tenants. Fix: sort by stable key (workspace name, then username, then event_id) without active-first bias. Mark the active tenant with `*` but don't change its position.

### `accept-link` should take invite as positional arg

`accept` takes the invite as a positional arg, but `accept-link` requires `--invite` flag. Fix: change `accept-link`'s `invite` field from `#[arg(long)]` to a bare positional, matching `accept`.

### `tenant list` should show usernames

Currently shows `peer_id (workspace: Name)`. Fix: include the username from `ViewTenant` in the output, e.g. `1. * username@WorkspaceName (peer_id)`.

## UX observations (low priority)

- **`tenant list` vs `view` use different ID formats**: hex peer_ids vs base64 event_ids.
- **Active tenant lost on daemon restart**: selection is in-memory only. <!-- not a bug; this is fine; active tenant is ephemeral state in this model -->
