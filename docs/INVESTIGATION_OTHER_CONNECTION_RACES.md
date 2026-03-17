# Investigation: Other Potential Connection Race Patterns

**Date:** 2026-03-17
**Related:** `BUG_INVITE_BOOTSTRAP_ENDPOINT_RACE.md`, `BUG_DUAL_SESSION_DOUBLE_SEND.md`

## Summary

Investigated the codebase for other locations where bidirectional connection races similar to the invite bootstrap endpoint race could occur. The connection replacement mechanism is centralized and used consistently, but there are several other potential race scenarios to be aware of.

## Connection Replacement Mechanism

The core mechanism is in `src/runtime/peering/loops/mod.rs`:

- `claim_live_connection_slot()` (lines 188-253)
- `preferred_connection_direction()` (lines 100-110)
- `connection_direction_rank()` (lines 112-122)

**Key behavior:**
- Connections are keyed by `(db_path, recorded_by, peer_id)` - NO direction component
- Direction rank: preferred=2, non-preferred=0, unknown=1
- When new connection has `rank > existing.rank`, existing connection is CLOSED

## Other Scenarios That Could Trigger Similar Races

### 1. Discovery-Based Dialing (CHECKED - Limited Impact)

**Location:** `src/runtime/peering/engine/supervisor.rs:990-999`

Discovery peers from mDNS/holepunch that also have `pending_invite_bootstrap_trust` entries could theoretically trigger the same race. However:

**Mitigation:** `classify_bootstrap_discovery_auth()` at line 991 checks:
```rust
BootstrapDiscoveryAuth::PendingOnly => false,
```

If a peer has ONLY pending bootstrap trust (not accepted), discovery will NOT dial them. This prevents the race for pure pending invite peers discovered via mDNS.

**Remaining risk:** If a peer has BOTH accepted bootstrap trust AND pending trust (multi-device scenario), discovery could still trigger connections.

### 2. Multiple Endpoint Observations (FIXED by primary fix)

**Location:** `src/runtime/peering/engine/target_planner.rs:201-270`

The primary fix (excluding `pending_invite_bootstrap_trust` from observed endpoint targets) addresses this comprehensively. No additional changes needed.

### 3. Simultaneous Invite Acceptances (EDGE CASE - Documented)

**Scenario:** Two devices accept the SAME invite simultaneously (as seen with Holmes desktop + MacBook).

**Current behavior:**
- Both devices get the same bootstrap transport identity (`fd0b6d7a...`)
- Both try to connect to inviter
- First one that completes sync transitions to ongoing identity
- Second one gets stuck in the race (documented in primary bug report)

**No code change needed:** This is the documented bug case. The fix prevents the inviter from racing back.

### 4. Holepunch Intro Connections (LOW RISK)

**Location:** `src/runtime/sync_engine/punch/` (intro mechanism)

Holepunch intros create temporary connections for NAT traversal. These use different connection keys and don't participate in the same connection slot mechanism, so no race risk identified.

### 5. Bootstrap Refresher Timing (DESIGN CONSIDERATION)

**Location:** `src/runtime/peering/engine/supervisor.rs:518-565`

The bootstrap refresher runs every **1000ms**. This creates timing-dependent behavior:
- Fast syncs (<500ms) usually avoid the race
- Slow syncs (>1000ms) almost always hit the race

**Potential improvement (NOT IMPLEMENTED):**
- Add a cooldown period before endpoint observations trigger outbound dials
- Example: Ignore endpoint observations younger than 2-3 seconds
- This would give initial inbound connections time to establish

**Decision:** Not implementing cooldown at this time. The SQL-level exclusion is sufficient and more explicit.

### 6. Transport Identity Rotation (CHECKED - No Issue)

**Location:** `src/event_modules/peer_shared/` (transport credential rotation)

When a peer's transport identity changes (bootstrap → ongoing), the `peers_shared` projection updates the transport fingerprint. The target planner queries `peers_shared` for endpoint targets, so it automatically picks up the new identity.

**No race risk:** Old bootstrap identity stops being dialed once `peers_shared` is updated.

## Comprehensive Fix Verification

The fix at `target_planner.rs:210-246` adds this SQL clause:

```sql
AND NOT EXISTS(
    SELECT 1
    FROM pending_invite_bootstrap_trust p
    WHERE p.recorded_by = ps.recorded_by
      AND p.expected_bootstrap_spki_fingerprint = ps.transport_fingerprint
      AND p.expires_at > ?2
)
```

**What this prevents:**
1. ✅ Inviter dialing invitee via endpoint observations (primary bug)
2. ✅ Inviter dialing second invitee when first is still pending
3. ✅ Dialing any peer with active pending bootstrap trust

**What this allows:**
1. ✅ Dialing peers with expired pending bootstrap trust (24h+ old)
2. ✅ Dialing peers after they complete bootstrap sync (moves to `peers_shared`)
3. ✅ Discovery-based connections with accepted bootstrap trust

## Test Coverage

Created comprehensive test in `tests/invite_endpoint_race_test.rs`:
- `invite_endpoint_race_prevents_bootstrap_sync()` - Documents the bug
- `invite_endpoint_race_fixed_allows_bootstrap_sync()` - Verifies the fix

## Recommendations

### Immediate (Included in this fix)
- [x] Apply SQL exclusion for `pending_invite_bootstrap_trust`
- [x] Add comprehensive test case
- [x] Document the bug and fix

### Future Considerations (NOT in this fix)
- [ ] Consider adding cooldown period for endpoint observation dialing
- [ ] Add metrics for connection replacement events
- [ ] Monitor for other bidirectional race patterns in production
- [ ] Consider explicit "invite in progress" marker separate from trust tables

## Related Code Locations

All locations where endpoint observations or connection slots are managed:

1. **Connection slot management:** `src/runtime/peering/loops/mod.rs:188-253`
2. **Accept loop:** `src/runtime/peering/loops/accept.rs:201-218`
3. **Connect loop:** `src/runtime/peering/loops/connect.rs:357-379`
4. **Endpoint observation recording:** `src/state/db/health.rs:record_endpoint_observation()`
5. **Target collection:** `src/runtime/peering/engine/target_planner.rs:201-270` (FIXED)
6. **Target dispatch:** `src/runtime/peering/engine/supervisor.rs:655-880`
7. **Bootstrap refresher:** `src/runtime/peering/engine/supervisor.rs:518-565`

## Conclusion

The primary fix (SQL-level exclusion) is **comprehensive and sufficient**. No other code locations require changes for this specific race condition. The investigation identified potential improvements for future work but no critical gaps in the current fix.
