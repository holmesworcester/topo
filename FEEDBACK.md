# CLI Expansion Review (`cli-expansion` working tree)

## Verdict
Not ready to merge yet.

Test status:
- `cargo test -q --test interactive_test` passes.
- `cargo test -q` passes.

Even with green tests, there are functional gaps that can produce incorrect runtime behavior.

## Findings

### 1. High: invite acceptance path can report success while identity chain is still blocked
- File: `src/identity_ops.rs:127`
- File: `src/identity_ops.rs:141`
- File: `src/identity_ops.rs:153`
- File: `src/identity_ops.rs:268`
- File: `src/identity_ops.rs:281`
- File: `src/identity_ops.rs:293`
- File: `src/identity_ops.rs:385`

Details:
- These paths use `event_id_or_blocked(create_signed_event_sync(...))`.
- `event_id_or_blocked` turns `Blocked` into `Ok(event_id)`, so the flow can continue and return `JoinChain`/`LinkChain` even when key events are not valid/projected.
- For bootstrap sequence this is sometimes acceptable early, but after `InviteAccepted` + copied prerequisite events, blocked should usually be treated as an error signal.

Why this matters:
- CLI can print “Accepted invite” while the account is not actually usable (missing valid identity projection).

Recommended fix:
1. Keep `event_id_or_blocked` only where blocked is explicitly expected.
2. In `accept_user_invite`/`accept_device_link`, require terminal `Valid` for post-anchor chain creation, or explicitly assert `valid_events` membership after each step.

### 2. High: non-interactive `delete-message` is effectively broken by random author identity
- File: `src/main.rs:793`
- File: `src/main.rs:795`
- Related existing behavior: `src/main.rs:432`

Details:
- `delete-message` creates `MessageDeletionEvent` with random `author_id`.
- Deletion projector requires deletion author to match original message author.
- Since message creation also uses random author (`send`), deletion will usually reject.

Repro:
1. `cargo run -- send hello --db /tmp/cli_expansion_review.db --channel 01`
2. Query message id hex from DB and run `delete-message --target <hex>`
3. Result: `Rejected ... "deletion author does not match message author"`

Recommended fix:
1. Introduce stable per-profile author identity for non-interactive CLI (for example derived from local projected peer identity).
2. Use that same stable author id for both `send` and `delete-message`.

### 3. Medium: invite-copy helper copies all events (including local-only) and can silently ignore projection errors
- File: `src/interactive.rs:1443`
- File: `src/interactive.rs:1479`
- File: `src/interactive.rs:1488`

Details:
- `copy_event_chain` selects all rows from `events` and inserts all into target `recorded_events`, regardless of `share_scope`.
- It ignores projection results/errors (`let _ = project_one(...)`).

Why this matters:
- Local-only events (for example local keys) should not be transferred this way.
- Silent projection failures can leave partially initialized accounts while command output appears successful.

Recommended fix:
1. Copy only shared events (`share_scope = 'shared'`) unless an explicit exception is required.
2. Fail fast on projection errors for required bootstrap/invite chain events.
3. Optionally make copying selective by dependency closure instead of full table scan.

### 4. Medium: non-interactive `react`/`delete-message` UX is incomplete
- File: `src/main.rs:757`
- File: `src/main.rs:346`

Details:
- Commands require `--target` as raw hex event id.
- `messages` output does not expose full message event ids.

Why this matters:
- Users/agents cannot reliably target messages without external DB inspection.

Recommended fix:
1. Include full `message_id` in `messages` output (or add `messages --json`).
2. Or add index-based commands for non-interactive mode (`delete --index N`, `react --index N` with channel scoping).

## Responses To The Questions In `docs/CLI_EXPANSION_FEEDBACK.md`

1. Message isolation:
- For this REPL prototype, isolation is acceptable if explicitly intentional.
- If goal is “chat-like multi-account interaction,” add explicit sync step/command and test that behavior.

2. Invite transfer scope:
- Current “copy all events” approach is too broad long-term.
- Prefer selective shared-event copy (or actual sync path) to match protocol semantics.

3. `event_id_or_blocked` usage:
- Yes, add strict assertions for stages expected to be valid.
- Treat blocked post-anchor events as failure in accept/link flows.

4. TransportKey per temp account:
- Correct for independent temp accounts in this harness.
- For production CLI profiles, identity should persist in stable profile paths.

## Suggested follow-up tests
1. `delete-message` succeeds for message created by same stable author identity.
2. `accept-invite` fails if required copied prereqs are missing (no false-positive success).
3. `copy_event_chain` does not transfer local-only events.
