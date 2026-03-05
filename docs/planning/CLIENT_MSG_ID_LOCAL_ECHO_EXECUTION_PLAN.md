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

1. Introduce a frontend-provided `client_op_id` key for deterministic reconciliation via polling.
2. Keep FE logic dead simple: optimistic list + view poll + key match.
3. Server stores a tiny mapping table (`client_op_id → event_id`) and annotates view responses.
4. Prototype in CLI in a way that is isomorphic to a typical React app data flow.
5. Add realistic tests under sync load proving merge correctness and no duplicates.

## Non-goals

1. No protocol-wide canonical event schema change.
2. No full HTTP server requirement.
3. No UI framework integration; CLI + RPC JSON are sufficient.

## Design

### Core principle: FE only knows `client_op_id`

The frontend never tracks `event_id`. Reconciliation works entirely through polling:

1. FE generates `client_op_id`, sends command, immediately shows optimistic row.
2. FE polls `View` — server annotates canonical items with their `client_op_id` where one exists.
3. FE sees canonical item tagged `client_op_id: "abc"` → drops optimistic row for `"abc"`.

This is the simplest possible FE model: one optimistic list, one view response, key-match dedup. No async state tracking, no promise chains, no client-side mapping table.

### Server-side mapping table

A single local-only table (not replicated) stores the association:

```sql
CREATE TABLE IF NOT EXISTS local_client_ops (
  recorded_by TEXT NOT NULL,
  client_op_id TEXT NOT NULL,
  event_id BLOB NOT NULL,
  op_kind TEXT NOT NULL,           -- 'message' | 'reaction' | 'attachment'
  created_at_ms INTEGER NOT NULL,
  PRIMARY KEY (recorded_by, client_op_id)
);
```

- Written at event creation time when `client_op_id` is provided.
- Read at view time to annotate canonical projected items.
- Periodically pruned (old entries beyond a TTL, e.g. 24h).

### RPC contract changes

Add optional `client_op_id` to write methods:
- `RpcMethod::Send { content, client_op_id: Option<String> }`
- `RpcMethod::React { target, emoji, client_op_id: Option<String> }`
- `RpcMethod::SendFile { content, file_path, client_op_id: Option<String> }`

Write method responses include `client_op_id` echo and `event_id`:
```json
{"ok": true, "data": {"event_id": "base64...", "client_op_id": "abc"}}
```

View response annotates canonical items with `client_op_id` where a mapping exists:
```json
{
  "messages": [
    {"id": "base64...", "content": "hello", "client_op_id": "abc", ...},
    {"id": "base64...", "content": "world", ...}
  ]
}
```

No `include_local_pending` flag needed — the annotation is always present when a mapping exists. The FE decides locally what to do with it.

### Write flow

1. Client generates `client_op_id` (UUIDv7 or any unique string) and sends RPC command.
2. RPC handler runs canonical event creation (same path as today).
3. On success: insert `local_client_ops(recorded_by, client_op_id, event_id, op_kind, now_ms)`.
4. Return response with both `client_op_id` and `event_id`.
5. On failure: return error. No mapping row written. FE can show error state for the optimistic row.

### View annotation

When building `View`/`Messages` responses, LEFT JOIN `local_client_ops` on `event_id` to annotate each canonical item with its `client_op_id` (if any). This is cheap — the table is small and indexed.

### FE reconciliation (isomorphic React model)

```
optimistic = local list of {client_op_id, content, ...}
canonical  = view poll response (messages with optional client_op_id annotation)

visible = canonical ∪ {o ∈ optimistic | o.client_op_id ∉ canonical.client_op_ids}
```

One selector. No state machine. No races.

## CLI prototype spec

Add optional `--client-op-id` flag to existing commands:

- `topo send "hi" --client-op-id <id>`
- `topo react ":fire:" --target "#1" --client-op-id <id>`
- `topo send-file "caption" --file ./a.png --client-op-id <id>`

View output already includes messages — add `client_op_id` field when present.

JSON mode (`--json`) shows full response including `client_op_id` and `event_id`.

## Test plan

Add `tests/local_echo_test.rs`:

1. **`message_send_with_client_op_id`**
   - Send message with `client_op_id`.
   - View response includes canonical message annotated with `client_op_id`.
   - No duplicates.

2. **`reaction_with_client_op_id`**
   - Create message, react with `client_op_id`.
   - View shows canonical reaction annotated with `client_op_id`.

3. **`attachment_with_client_op_id`**
   - Send file with `client_op_id`.
   - View shows canonical attachment annotated with `client_op_id`.

4. **`view_without_client_op_id_unchanged`**
   - Send message without `client_op_id`.
   - View response has no `client_op_id` annotation (backward compatible).

5. **`duplicate_client_op_id_rejected`**
   - Send two messages with same `client_op_id`.
   - Second should fail or be idempotent.

## Implementation order

1. Add `local_client_ops` schema in `create_tables` + query helpers.
2. Add optional `client_op_id` field to `Send`/`React`/`SendFile` RPC method structs + catalog entries.
3. Insert mapping row on successful event creation in service layer.
4. Annotate `View`/`Messages` responses with `client_op_id` via LEFT JOIN.
5. Add `--client-op-id` CLI flag to relevant commands.
6. Add integration tests (`tests/local_echo_test.rs`).
7. Document in DESIGN.md (new subsection under section 8) and add overview paragraph to "How it Works" narrative.

## Acceptance criteria

1. Messages, reactions, and file ops can be issued with `client_op_id`.
2. View responses annotate canonical items with their `client_op_id` where one exists.
3. FE reconciliation is a trivial key match — no server-side merge logic needed.
4. Backward compatible: commands without `client_op_id` work exactly as before.
5. Tests pass in `--release` mode.
