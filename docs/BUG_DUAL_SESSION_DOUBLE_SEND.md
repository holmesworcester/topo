# Bug: Dual Sync Sessions Send Same Data Twice

## Summary

When peer A sends a file (or any events) to peer B, multiple concurrent sync sessions independently discover the same delta and transmit the same event data over the wire. This means every byte of payload crosses the network **2-3x**, significantly reducing effective throughput and wasting bandwidth.

The bug reproduces both on localhost and cross-machine. On localhost with 1000 messages, the measured duplication ratio is ~2.9x (events sent ~3x more than necessary across 10+ concurrent sync sessions).

## Observed Behavior

Sending a 100 MiB file from peer A (local) to peer B (remote) produced the following sync runs on the **sender side** (peer A):

```
RUN 176 [changed] dir=outbound role=initiator  dur_ms=33619  sync_events_tx=419  bytes_tx=108881674  bytes_rx=0
RUN 177 [changed] dir=inbound  role=responder  dur_ms=32451  sync_events_tx=385  bytes_tx=101007060  bytes_rx=0
```

Both runs transmitted from A to B. Run 176 (A initiated the session) sent 108 MB. Run 177 (B initiated the session, A responded) sent 101 MB. **The same ~100 MiB file was sent twice** -- once per bidirectional sync session.

On the **receiver side** (peer B), the corresponding runs confirm:

```
RUN 176 [changed] dir=inbound  role=responder  dur_ms=33591  sync_events_rx=419  bytes_rx=108881674  bytes_tx=0
RUN 177 [changed] dir=outbound role=initiator  dur_ms=32594  sync_events_rx=385  bytes_rx=101007060  bytes_tx=0
```

B received the same data twice from A. Deduplication at the event store level means no data corruption, but the wire cost was 2x.

## Expected Behavior

When peer A has events that B lacks, only **one** sync session should transmit that delta. The other session should discover (via negentropy) that there is nothing to send, since the events are already in transit or recently received.

## Root Cause (Hypothesis)

Multiple sync sessions run concurrently and independently. The daemon's supervisor runs repeated sync sessions on each connection, and both the outbound (A→B) and inbound (B→A) connections run sessions in parallel:
1. A initiates a session to B (outbound)
2. B initiates a session to A (inbound from A's perspective)
3. Both repeat on a timer, creating 10+ sessions during a single transfer

All sessions perform negentropy reconciliation independently. When they discover "B needs these N events," each session enqueues and sends those events without checking whether another concurrent session is already sending them. The receiver deduplicates on ingest, but the bytes have already crossed the wire.

On localhost with 1000 messages, Alice ran 10 outbound + 10 inbound sessions, sending ~2884 events total instead of 1000 (2.88x duplication).

Possible fixes:
- **Egress dedup**: Track which events are currently being sent to a given peer and skip them in concurrent sessions
- **Session suppression**: If an outbound session to peer X is in progress, suppress or defer the inbound session from peer X (or vice versa)
- **Post-neg delta coordination**: After negentropy completes, check the egress queue / in-flight set before draining
- **Single-session-per-peer**: Only allow one active sync session per peer at a time

## Impact

- **~2-3x bandwidth waste** for every one-directional sync (file sends, message bursts)
- **~2-3x slower effective throughput** due to bandwidth contention between concurrent sessions
- Observed on localhost: 2.88x duplication (1000 events sent 2884 times)
- Observed cross-machine: 2.97 MiB/s via topo vs 7.7 MiB/s via SCP on the same link (2.6x slower, largely explained by the multi-send)

## Reproduction

### Automated (daemon test)

```bash
cargo test --release --test double_send_test -- --nocapture --test-threads=1
```

See `tests/double_send_test.rs` for the automated test. It:
1. Creates two daemon peers (alice, bob) with sync logging enabled
2. Alice generates 1000 messages
3. Waits for bob to receive all messages
4. Queries `sync_runs` on both peers and sums `events_sent`
5. Asserts that total events sent is > 1.5x the expected count (confirming the bug)
6. When the bug is fixed, the assertion should be flipped to assert < 1.5x

Example output:
```
Alice events_sent:  2884
Bob events_sent:    0
Total events_sent:  2884
Expected events:    ~1000
Duplication ratio:  2.88x
Alice runs:         10 outbound, 10 inbound
```

### Manual (cross-machine, how this was originally discovered)

```bash
# Machine A (local)
topo --db /tmp/a.db start --bind 0.0.0.0:7443
topo --db /tmp/a.db create-workspace --workspace-name test --username alice --device-name dev
topo --db /tmp/a.db sync-log enable --all-runs
INVITE=$(topo --db /tmp/a.db invite --public-addr <A_IP>:7443)

# Machine B (remote)
topo --db /tmp/b.db start --bind 0.0.0.0:7444
topo --db /tmp/b.db accept "$INVITE" --username bob --devicename dev
topo --db /tmp/b.db sync-log enable --all-runs

# Send 100 MiB file from A
dd if=/dev/urandom of=/tmp/test.bin bs=1M count=100
topo --db /tmp/a.db send-file "test" --file /tmp/test.bin

# Wait for convergence, then inspect sync logs on both sides:
topo --db /tmp/a.db sync-log show --limit 10
topo --db /tmp/b.db sync-log show --limit 10

# Look for two concurrent "changed" runs with bytes_tx > 0 on the same peer
# (sender side), both sending ~100 MB to the same remote.
```

## Environment

- Topo commit: `de2afa2` (Align docs with encrypted file flow)
- Two machines connected via Tailscale (~15ms RTT)
- Local machine: `clean-quiet-test` (100.110.168.19)
- Remote machine: `desktop` / `holmes` (100.67.2.56 / 192.168.6.177)

## Benchmark Data

| Direction | SCP | Topo | Ratio |
|-----------|-----|------|-------|
| Local -> Remote | 13.0s (7.7 MiB/s) | ~33s (2.97 MiB/s) | 2.6x slower |
| Remote -> Local | 20.6s (4.9 MiB/s) | ~63s (1.58 MiB/s) | 3.1x slower |

Network: ~15ms RTT, WiFi/Tailscale. The double-send is likely the single largest contributor to the throughput gap, with per-slice SQLite writes and encryption overhead as secondary factors.
