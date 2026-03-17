# BUG: Invite Bootstrap Endpoint Observation Race Condition

## Status
**OPEN** - Identified 2026-03-17

## Severity
**HIGH** - Prevents successful invite acceptance and bootstrap sync completion

## Summary
When a peer accepts an invite, both the inviter and invitee simultaneously attempt to connect to each other, creating a race condition where the invitee's outbound connection is repeatedly replaced by the inviter's inbound connection. This prevents sync sessions from completing and results in zero sync runs being recorded on the inviter side despite thousands of connection attempts.

## Symptoms

### On the Invitee (peer accepting the invite):
- Thousands of sync runs recorded, all with:
  - `outcome = "ok"`
  - `rounds = 0`
  - `events_sent = 0`
  - `events_received = 0`
  - `duration = 16-42ms`
- Status shows "still joining" indefinitely
- Never completes bootstrap sync

### On the Inviter (peer who created the invite):
- **Zero sync_runs** from the invitee's IP address
- Thousands of `peer_endpoint_observations` entries for the invitee
- `pending_invite_bootstrap_trust` table has entry for invitee's expected SPKI
- `invite_bootstrap_trust` table remains empty (projection never completes)

## Root Cause

### The Race Condition Flow

1. **Invitee initiates outbound connection to inviter**
   - Claims connection slot with `direction_rank=0` (non-preferred)
   - Opens dual streams (control + data)
   - Sends NegOpen frame
   - Waits for NegMsg response

2. **Inviter's accept loop accepts the connection**
   - TLS verification passes (node-level and tenant-level)
   - Connection slot claimed successfully
   - Records entry in `peer_endpoint_observations` table
   - Spawns worker thread to handle session

3. **Inviter's target planner discovers invitee's address**
   - Runs every 1000ms via `run_bootstrap_refresher()`
   - Calls `collect_all_observed_endpoint_targets()`
   - Queries `peer_endpoint_observations` table
   - Finds invitee's address (e.g., `100.101.83.38:4433`)
   - Spawns outbound connect loop to dial invitee

4. **Inviter dials invitee outbound**
   - Invitee's accept loop accepts the connection
   - Invitee's `claim_live_connection_slot()` evaluates:
     - Existing slot: outbound to inviter (`direction_rank=0`)
     - New slot: inbound from inviter (`direction_rank=2`, **preferred**)
     - Comparison: `rank 2 > rank 0` → **REPLACES existing connection**
   - Invitee's outbound connection **closed** with reason: `"replaced by preferred peer connection"`

5. **Invitee's initiator observes connection closure**
   - `control.recv()` returns `ConnectionError::Closed`
   - `rounds_total = 0`, `events_sent = 0`, `bytes_received = 0`
   - Returns `Ok(SyncStats)` with zero rounds
   - Sync run recorded as `outcome="ok"` with 0 rounds

6. **Inviter's worker calls `next_session()`**
   - Worker thread has finished startup (thread spawn, runtime creation: ~5-15ms)
   - Calls `provider.next_session()` → `accept_session_io()`
   - Tries to `conn.accept_bi()` to accept bidirectional streams
   - Connection already closed by invitee's connection replacement
   - Returns `Err(SessionOpenError::ConnectionLost("stream accept: ..."))`
   - Logs: `"Connection dropped while opening session"`
   - Returns without creating sync_run entry

7. **Invitee's connect loop immediately retries**
   - No delay (`CONNECT_RETRY_DELAY` only applies to dial failures)
   - Cycle repeats indefinitely

### Direction Preference Calculation

The preferred direction is determined by comparing peer IDs:

```rust
fn preferred_connection_direction(local_peer_id: &str, remote_peer_id: &str) -> Option<SessionDirection> {
    let local = peer_fingerprint_from_hex(local_peer_id)?;
    let remote = peer_fingerprint_from_hex(remote_peer_id)?;
    Some(match local.cmp(&remote) {
        std::cmp::Ordering::Less | std::cmp::Ordering::Equal => SessionDirection::Outbound,
        std::cmp::Ordering::Greater => SessionDirection::Inbound,
    })
}
```

Direction rank:
- Preferred direction: `rank = 2`
- Non-preferred direction: `rank = 0`
- Cannot determine: `rank = 1`

When a new connection arrives with `direction_rank > existing.direction_rank`, the existing connection is closed and replaced.

## Evidence / Reproduction

### Observed in Production
- MacBook (100.101.83.38) accepting invite from inviter (100.110.168.19)
- ~130,000+ total sync runs on invitee (auto-increment ID 130216+)
- All sync runs: 0 rounds, "ok" status, 16-42ms duration
- Inviter: 0 sync runs from invitee IP, but 22+ MB of endpoint observations

### Database Queries

```bash
# On inviter: Check endpoint observations vs sync_runs
sqlite3 ~/topo/topo.db "SELECT COUNT(*) FROM peer_endpoint_observations WHERE origin_ip = '100.101.83.38'"
# Result: Thousands of entries

sqlite3 ~/topo/topo.db "SELECT COUNT(*) FROM sync_runs WHERE remote_addr LIKE '100.101.83.38%'"
# Result: 0

# On invitee: Check sync run outcomes
sqlite3 ~/topo/topo.db "SELECT outcome, rounds, COUNT(*) FROM sync_runs GROUP BY outcome, rounds"
# Result: ok|0|500 (or more)
```

## Code Locations

### Key Files
1. **`src/runtime/peering/engine/target_planner.rs:201-270`**
   - `load_observed_endpoint_targets()` - Queries `peer_endpoint_observations` to create dial targets
   - Currently excludes only `local_transport_creds` (don't dial self)
   - **Missing**: Exclusion for `pending_invite_bootstrap_trust` peers

2. **`src/runtime/peering/loops/mod.rs:188-253`**
   - `claim_live_connection_slot()` - Connection slot management
   - Line 227-237: Connection replacement when `direction_rank > existing.direction_rank`
   - Line 248: Closes replaced connection with `"replaced by preferred peer connection"`

3. **`src/runtime/peering/loops/supervisor.rs:157-264`**
   - `supervise_connection_sessions()` - Session handler
   - Line 174-207: `provider.next_session()` error handling
   - Line 199-204: Logs "Connection dropped while opening session" when connection closes before streams accepted

4. **`src/runtime/transport/session_factory.rs:274-305`**
   - `accept_session_io()` - Accepts bidirectional streams
   - Line 279-282: `conn.accept_bi()` fails with `ConnectionLost` if connection closed

5. **`src/runtime/peering/engine/supervisor.rs:518-565`**
   - `run_bootstrap_refresher()` - Runs every 1000ms
   - Calls `collect_all_observed_endpoint_targets()` to refresh dial targets

## Proposed Fix

### Primary Fix: Exclude Pending Invite Peers from Endpoint Dialing

Modify the SQL query in `load_observed_endpoint_targets()` to exclude peers with active `pending_invite_bootstrap_trust` entries:

```sql
-- Add this clause after line 238 in target_planner.rs
AND NOT EXISTS(
    SELECT 1
    FROM pending_invite_bootstrap_trust p
    WHERE p.recorded_by = ps.recorded_by
      AND p.expected_bootstrap_spki_fingerprint = ps.transport_fingerprint
      AND p.expires_at > ?2
)
```

**Rationale**: Peers in `pending_invite_bootstrap_trust` are invitees that the local node expects to connect **inbound**. The local node should wait for them to initiate the connection rather than racing to dial them via endpoint observations.

### Alternative Fix: Delay Endpoint Dialing After Observation

Add a cooldown period (e.g., 5-10 seconds) before endpoint observations trigger outbound dialing, giving the existing inbound connection time to establish.

**Rationale**: The inbound connection from the invitee arrives first. If the inviter waits a few seconds before dialing, the inbound connection's worker thread will have time to accept streams and create a sync session.

## Related Issues

This bug shares the same underlying mechanism as `BUG_DUAL_SESSION_DOUBLE_SEND.md`:
- Both involve simultaneous bidirectional connection attempts
- Both leverage the connection direction preference system
- Both result in connection replacement

The difference:
- **DUAL_SESSION_DOUBLE_SEND**: Both connections survive, creating duplicate sync sessions
- **THIS BUG**: One connection is replaced before session starts, preventing sync entirely

## Testing Strategy

### Minimal Reproduction Test

1. Create two peers: `inviter` and `invitee`
2. Inviter creates a device invite
3. Invitee accepts the invite
4. Observe:
   - Invitee's sync_runs table fills with 0-round "ok" entries
   - Inviter's sync_runs table has 0 entries from invitee
   - Inviter's peer_endpoint_observations table grows rapidly
5. Expected with fix:
   - Inviter waits for invitee's inbound connection
   - Invitee's connection establishes successfully
   - Bootstrap sync completes with >0 rounds

### Daemon-based Integration Test

Use `tests/cli_harness/mod.rs` framework:
- Start two daemon processes
- Enable sync logging with `--all-runs`
- Create and accept invite
- Query both databases for sync_runs
- Assert: inviter has at least 1 sync_run from invitee with rounds > 0

## Timeline

- **2026-03-17**: Issue discovered during MacBook invite acceptance demo
- **2026-03-17**: Root cause identified via extensive debugging session
- **2026-03-17**: Issue reproduced independently in second demo attempt

## Notes

- The 24-hour TTL on `pending_invite_bootstrap_trust` means this race only affects fresh invite acceptances
- After TTL expires, the entry is removed and endpoint dialing proceeds normally
- However, bootstrap sync must complete within the 24-hour window, so this bug effectively prevents invite acceptance
- The issue affects **both** device invites and user invites
- The connection replacement mechanism is intentional for direction preference, but the observed endpoint dialing should respect invite flow direction
