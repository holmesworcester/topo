# CLI Expansion: Findings & Feedback Request

## What Was Done

Implemented the plan from the `cli-expansion` branch:
- `src/identity_ops.rs` — Reusable identity chain operations (bootstrap, invite, accept, link)
- `src/interactive.rs` — Interactive REPL with multi-account session management
- `src/main.rs` — New non-interactive subcommands (react, delete-message, reactions, users, keys, networks)
- `src/lib.rs` — Module declarations for new modules

## Key Finding: Event Ordering & the Trust Anchor

### The Problem

My initial `bootstrap_network` function created events in this order:
```
Network -> UserInviteBoot -> UserBoot -> DeviceInviteFirst -> PeerSharedFirst -> AdminBoot -> TransportKey
```

This failed because the projection system **guard-blocks** the Network event until a trust anchor exists (set by `InviteAccepted`). Without the trust anchor, the Network event stays in `events` but never enters `valid_events`. All downstream events that depend on the Network event (via `signed_by` or transitively) are then **dependency-blocked** because the pipeline checks `valid_events` for deps.

### What `event_id_or_blocked` Does

`event_id_or_blocked` converts `Blocked { event_id, missing }` errors into `Ok(event_id)`. This means the event **is stored** in the `events` table (it has a valid blob and event_id), it just isn't projected yet. This is the normal case for out-of-order event arrival during sync.

### The Fix: Match the Canonical Test Sequence

The working sequence from `scenario_test.rs::bootstrap_peer` is:
```
1. Network (guard-blocked, stored but not valid)
2. UserInviteBoot (dep-blocked on Network)
3. InviteAccepted (LOCAL event - sets trust anchor, triggers guard cascade)
   -> Guard cascade: Network becomes valid
   -> Dep cascade: UserInviteBoot unblocks and becomes valid
4. UserBoot (now projects normally, UserInviteBoot is valid)
5. DeviceInviteFirst
6. PeerSharedFirst
7. AdminBoot
8. TransportKey
```

The **InviteAccepted** event at step 3 is the critical piece. When it projects:
1. It writes to `trust_anchors` (binding `network_id` to this peer)
2. The pipeline calls `retry_guard_blocked_events()` (line 228 of pipeline.rs)
3. This retries the Network event, which now passes the trust anchor check
4. Network becoming valid triggers `unblock_dependents()` which cascades through UserInviteBoot

### For `accept_user_invite` and `accept_device_link`

Same principle: InviteAccepted must come **first** (before building the new identity chain) so the copied events from the inviting account can project in the new account's database.

## Schema Findings

- `deleted_messages` table uses column `message_id` (not `target_event_id`)
- `networks.network_id` is stored as TEXT (base64), not BLOB
- `users.public_key` is stored as BLOB

## Questions for Review

1. **Message isolation**: Each interactive account has its own temp database. Messages sent by Bob are only in Bob's db, not Alice's. Is this the intended behavior for the REPL, or should there be a simulated sync between accounts?

2. **Invite transfer**: Currently `copy_event_chain` copies ALL events from the inviting account's db to the new account's db. This is a brute-force approach. Should it be more selective (only copy identity chain events)?

3. **`event_id_or_blocked` usage**: The identity_ops functions use `event_id_or_blocked` on most create calls. For the bootstrap case, everything after InviteAccepted should project as Valid (not Blocked). Should I add assertions that post-InviteAccepted events are actually Valid, not just stored?

4. **TransportKey creation**: `create_transport_key_if_possible` reads the cert from disk. In the interactive REPL, each account has a tempdir with its own cert. This works but means each account gets a unique transport identity. Is this correct?
