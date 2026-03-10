# Semantic Valid Event Types And Required Content Encryption Execution Plan

Date: 2026-03-10
Branch/worktree context for this task:
- Branch: `codex/semantic-valid-event-types`
- Worktree: `/tmp/poc-7-semantic-valid-types`
- Base: local `master`

## Summary

Fix encrypted-content dependency validation by recording each tenant-valid event's
semantic type in `valid_events`, then use that tenant-scoped semantic type for
dependency type checks instead of raw outer blob type codes or projection-table
presence.

On top of that, enforce required encrypted transport for shared content events:

1. `message`
2. `reaction`
3. `message_deletion`
4. `file`
5. `file_slice`

File download-rate capture must continue to log only file traffic, but it must
recognize outer `encrypted(file_slice)` events without falling back to "log all
events".

## Problem

Current dependency type checks read the referenced event's outer blob type code.
That is incorrect once a dependency points at an encrypted wrapper whose semantic
content type is only known after validation/decryption.

Examples:

1. `reaction.target_event_id` should accept an encrypted message wrapper event
   if that wrapper is valid and semantically a `message`.
2. `file.message_id` should accept an encrypted message wrapper event if that
   wrapper is valid and semantically a `message`.
3. `message_deletion.target_event_id` must continue to target messages by
   semantic type, not by outer storage shape.

Projection tables are not a correct generic substitute for type validation:

1. valid events may intentionally produce no live row,
2. tombstoned/deleted content can remain valid canonical history,
3. projected state is product-facing materialization, not canonical type
   evidence.

## Core design

### 1. Extend `valid_events`

Add tenant-scoped semantic type metadata:

```sql
ALTER TABLE valid_events ADD COLUMN semantic_type_code INTEGER;
```

Meaning:

1. plaintext valid event: `semantic_type_code = parsed.event_type_code()`
2. encrypted valid event: `semantic_type_code = decrypted_inner.event_type_code()`

The row stays keyed by:

1. `peer_id`
2. `event_id`

So the security boundary remains tenant-local.

### 2. Dependency checks stay tenant-scoped

Dependency satisfaction must continue to be anchored to:

1. same `recorded_by` / `peer_id`
2. same `event_id`

Cross-tenant or cross-workspace valid rows must never satisfy a dependency.
Same-workspace bridge/fanout remains a separate explicit mechanism that makes an
event valid in another tenant by creating that tenant's own valid row.

### 3. Semantic dep type checks

Shared dependency type validation should use:

```sql
SELECT semantic_type_code
FROM valid_events
WHERE peer_id = ?1 AND event_id = ?2
```

This replaces outer-blob type checks for validated deps.

### 4. Encrypted current-event flow

For the current encrypted event:

1. validate outer deps needed for decryption,
2. decrypt,
3. parse inner event,
4. verify outer `inner_type_code == parsed_inner.event_type_code()`,
5. validate inner dep presence and dep types using `valid_events.semantic_type_code`,
6. project inner event,
7. insert outer `valid_events` row with `semantic_type_code = inner_type`.

### 5. Required content encryption

After semantic dep typing works, mark shared content events as
`RequireEncrypted`:

1. `message`
2. `reaction`
3. `message_deletion`
4. `file`
5. `file_slice`

Identity/admin/bootstrap support events remain plaintext-only or
may-plaintext according to current policy.

### 6. File-rate capture rule

Data-plane receive logging must continue to capture only file traffic, but it
must classify:

1. plaintext `file_slice`
2. outer `encrypted(file_slice)`

and must not classify:

1. `encrypted(message)`
2. `encrypted(reaction)`
3. generic non-file events

## Success criteria

### SC1. `valid_events` records semantic event type per tenant-valid event

Proof:

1. plaintext valid event writes its own type code,
2. encrypted valid event writes the inner semantic type code,
3. existing valid-event existence queries continue to work.

Checks:

1. migration/backfill test for existing rows,
2. projection test for plaintext message,
3. projection test for encrypted message,
4. projection test for encrypted file slice.

### SC2. Dependency type checks use tenant-scoped semantic type, not outer blob type

Proof:

1. encrypted message may satisfy a `message`-typed dep,
2. wrong semantic family still rejects,
3. another tenant's valid row never satisfies the dep.

Checks:

1. encrypted reaction targeting encrypted message passes,
2. encrypted reaction targeting workspace rejects,
3. file descriptor pointing at encrypted message passes,
4. same event valid in tenant A but absent in tenant B does not satisfy B's dep.

### SC3. Shared content commands emit required encrypted events

Proof:

1. normal send/react/delete/send-file flows do not emit plaintext content
   canonical events,
2. plaintext injection for required-encrypted content is rejected.

Checks:

1. service/CLI command tests for `send`,
2. service/CLI command tests for `react`,
3. service/CLI command tests for `delete-message`,
4. service/CLI command tests for `send-file`,
5. projection test rejecting plaintext required-encrypted content.

### SC4. File download/save behavior still works with encrypted file slices

Proof:

1. file roundtrip restores exact bytes,
2. save path streams decrypt/write,
3. wrapper key must match descriptor key.

Checks:

1. end-to-end send-file/sync/save-file exact-byte test,
2. `save-file` encrypted-slice unit/integration coverage,
3. key mismatch rejection test,
4. partial/incomplete file rejection test.

### SC5. Effective file download-rate capture still works without logging all events

Proof:

1. synced files still show MiB/s,
2. local-only files still do not show fake MiB/s,
3. encrypted non-file events are not captured into file-rate linkage.

Checks:

1. data-plane predicate unit tests,
2. file query tests for downloaded bytes / MiB/s,
3. CLI acceptance test showing MiB/s for synced files,
4. CLI test proving no fake MiB/s for local-only files.

## Required implementation order

1. Add `semantic_type_code` to `valid_events`, migration/backfill, and writer path.
2. Switch dep-type lookup to same-tenant `valid_events.semantic_type_code`.
3. Re-enable inner dep type checks for encrypted content using semantic dep rows.
4. Enforce required encryption for `message`, `reaction`, `message_deletion`,
   `file`, and `file_slice`.
5. Update command-layer create paths and test helpers.
6. Update file-rate capture predicate for `encrypted(file_slice)`.
7. Run targeted tests, then end-to-end validation.

## End-to-end validation

The delivered work is complete only if all of the following pass:

1. Projection pipeline tests covering semantic-type valid rows and encrypted deps.
2. Service/CLI tests for send/react/delete/send-file using required encryption.
3. File roundtrip CLI test:
   - Alice sends file
   - Bob syncs
   - Bob sees complete attachment
   - Bob sees MiB/s in `topo messages`
   - Bob sees MiB/s in `topo files`
   - Bob `save-file`s exact bytes
4. Cross-tenant dep isolation test proving tenant A valid rows do not satisfy
   tenant B deps.

## Merge strategy

Merge incrementally to `master` in small reviewable commits:

1. `valid_events.semantic_type_code` + dep typing
2. required content encryption enforcement
3. encrypted file-slice save/rate capture hardening

Do not batch unrelated perf/doc churn into these merges.
