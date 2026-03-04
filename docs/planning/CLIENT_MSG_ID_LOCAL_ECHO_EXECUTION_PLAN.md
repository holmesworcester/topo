# Client Message ID Local-Echo Execution Plan

Branch/worktree context for this task:
- Branch: `client-msg-id-local-echo`
- Worktree: `/home/holmes/poc-7-client-msg-id-local-echo`
- Base: `master`

## Problem

On Enter/send click, frontend users should see the new item immediately with Slack-like latency, even while SQLite is under churn from syncing/projecting. We need this without introducing racey state management.

We need the same instant-feedback model for:
1. messages,
2. file attachments,
3. reactions.

## Goals

1. Introduce a frontend-provided `client_msg_id`-style key (generalized as `client_op_id`) for deterministic reconcile.
2. Provide optimistic local state and deterministic merge with canonical DB-backed view.
3. Keep concurrency simple: no multi-writer app logic, no brittle in-memory-only reconciliation.
4. Prototype in CLI in a way that is isomorphic to a typical React app data flow.
5. Add realistic tests under sync load proving merge correctness and no duplicates.

## Non-goals

1. No protocol-wide canonical event schema change in phase 1.
2. No full HTTP server requirement for phase 1.
3. No UI framework integration in this branch; CLI + RPC JSON are sufficient.

## Recommended approach (Option A, preferred)

Use a **local SQLite optimistic outbox** keyed by `client_op_id` and merged at read time.

### A1) Local-only DB table

Add local table (per peer):

```sql
CREATE TABLE IF NOT EXISTS local_pending_ops (
  recorded_by TEXT NOT NULL,
  client_op_id TEXT NOT NULL,
  op_kind TEXT NOT NULL,              -- 'message' | 'reaction' | 'attachment'
  status TEXT NOT NULL,               -- 'pending' | 'acked' | 'failed'
  created_at_ms INTEGER NOT NULL,

  -- generic payload and match keys
  payload_json TEXT NOT NULL,         -- JSON blob with content/emoji/filename/etc
  target_event_id TEXT NOT NULL DEFAULT '',

  -- filled on ack
  ack_event_id TEXT NOT NULL DEFAULT '',
  error_text TEXT NOT NULL DEFAULT '',

  PRIMARY KEY (recorded_by, client_op_id)
);

CREATE INDEX IF NOT EXISTS idx_local_pending_ops_peer_status_created
  ON local_pending_ops(recorded_by, status, created_at_ms DESC);
```

Notes:
- This is local UX state only; it must not replicate.
- Keep payload minimal and explicit per op kind.

### A2) RPC contract additions

Add optional IDs to existing methods:
- `RpcMethod::Send { content, client_op_id: Option<String> }`
- `RpcMethod::React { target, emoji, client_op_id: Option<String> }`

Add one new method for real attachment send prototype:
- `RpcMethod::SendFile { path, caption: Option<String>, client_op_id: Option<String> }`

Add optional view merge switch:
- `RpcMethod::View { limit, include_local_pending: bool }`
- same for `Messages` if useful.

### A3) Write flow (messages/reactions/files)

For each op:
1. Client generates `client_op_id` (UUIDv7/ULID) and sends command.
2. RPC handler inserts `local_pending_ops(... status='pending' ...)` in a short transaction.
3. RPC handler runs canonical event creation path (same path as today).
4. On success: update row to `acked` with `ack_event_id`.
5. On failure: update row to `failed` with `error_text`.

Concurrency rule:
- Keep canonical writes on existing single-writer flow.
- Pending row insert/update and canonical write should be serialized by the same command execution path.

### A4) Merge contract for frontend/CLI

Return a merged view built from:
1. canonical projected messages/reactions/attachments,
2. pending rows for `status in ('pending','failed')`.

Deterministic merge keys:
- Message: `client_op_id` (local) -> replace by canonical when `ack_event_id` appears.
- Reaction: `(target, emoji, author)` plus `client_op_id` to avoid duplicate optimistic bubbles.
- Attachment: `client_op_id` maps to one attachment placeholder row; replace when descriptor is projected.

Required invariants:
1. At most one visible row per `client_op_id`.
2. `acked` local rows never show if canonical row is present.
3. Merge output deterministic for same canonical+pending inputs.

## File attachments specifics

Current CLI has synthetic `generate-files`; that is not a realistic user send path.

### Attachment optimistic behavior

`SendFile` optimistic placeholder should include:
- local file name,
- size,
- upload/projection phase,
- optional caption text.

Ack semantics:
- Ack for attachment op when `message_attachment` descriptor is committed/projection-visible.
- Slice transfer progress can remain optional in phase 1; if added, expose `slice_count_acked/total` in payload.

Mapping:
- `client_op_id` -> eventual `message_id` and `file_id`.

## Reactions specifics

Reaction optimistic UX:
- Show emoji immediately on target message with `pending=true` marker.
- If failure, keep temporarily as failed marker or remove with error toast (CLI: `(failed)` suffix).

Dedup rule:
- If user double-clicks same emoji quickly, use `client_op_id` to dedupe pending entries.
- Canonical dedupe still enforced by normal projector/business rules.

## CLI-isomorphic prototype spec

Use existing CLI commands, adding optional flags only where needed:

- `topo send "hi" --client-op-id <id> --json`
- `topo react ":fire:" --target "#1" --client-op-id <id> --json`
- `topo send-file --path ./a.png --caption "look" --client-op-id <id> --json`
- `topo view --limit 50 --include-local-pending --json`

JSON response shape for command calls should include:
- `client_op_id`,
- immediate `local_status` (`pending`/`acked`/`failed`),
- optional `event_id` when already acked.

`view --json --include-local-pending` should include:
- `canonical_messages`,
- `local_pending_ops`,
- `merged_messages`.

This mirrors React app data flow:
- local optimistic store + server data + deterministic selector.

## Test plan (realistic and churn-aware)

Add `tests/local_echo_isomorphic_test.rs` with daemon/RPC integration style (same realism level as existing RPC tests):

1. `message_local_echo_survives_sync_churn`
   - start two peers and active sync churn (background generate/sync loop),
   - send with `client_op_id`,
   - immediately assert `view(include_local_pending)` shows optimistic row,
   - eventually assert optimistic row replaced by canonical once acked,
   - assert no duplicates.

2. `reaction_local_echo_merges_without_duplicates`
   - create message,
   - react with `client_op_id`,
   - assert immediate optimistic inline reaction,
   - assert eventual canonical reaction replaces optimistic marker,
   - assert one visible reaction bubble.

3. `attachment_local_echo_placeholder_to_descriptor`
   - send file with `client_op_id`,
   - assert placeholder appears immediately,
   - assert replacement by canonical attachment row,
   - assert mapping `client_op_id -> message_id/file_id` recorded.

4. `restart_persistence_of_pending_ops`
   - insert pending op, restart daemon before ack,
   - ensure pending row survives and merge still stable,
   - eventually ack or fail deterministically.

## Alternative prototype options

### Option B: In-memory pending map in daemon (fastest spike)
- Pros: minimal schema changes.
- Cons: lost on restart, harder to reason under reconnects, less React-isomorphic persistence.
- Use only for a throwaway spike, not recommended for mainline.

### Option C: Embed `client_op_id` in canonical event payload
- Pros: strongest end-to-end traceability.
- Cons: protocol/schema churn, compatibility implications, cross-peer semantics to define.
- Better as phase 2 if Option A proves out.

## Suggested implementation order

1. Add `local_pending_ops` schema + query helpers.
2. Extend RPC method structs and CLI flags (`send`, `react`).
3. Implement pending insert/update around existing canonical write paths.
4. Add merged view builder (`include_local_pending` path).
5. Add `send-file` command + RPC path reusing existing event modules.
6. Add integration tests above.
7. Document usage in README/PERF test notes if needed.

## Acceptance criteria

1. Message, reaction, and file operations can be issued with client op IDs.
2. CLI can request merged view with optimistic + canonical reconciliation.
3. Under churn, merged view remains deterministic and duplicate-free.
4. Restart does not lose pending local ops.
5. New tests pass in `--release` mode.

## Final step

1. Commit all completed work on this same branch/worktree before handoff/review.
