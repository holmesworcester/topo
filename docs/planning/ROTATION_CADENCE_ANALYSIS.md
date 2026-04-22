# Optimal Rotation Cadence Analysis

## The tradeoff

Under Per-Message FS, each sender device emits its own `key_broadcast`
stream. Every message uses a fresh `K_m` wrapped under the sender's
current `K_bundle`. Rotation = emit a new `key_broadcast`, after
which new messages use the next `K_bundle`.

The question: **how often should a device rotate?**

Two opposing forces:

- **Rotating often is expensive.** Each `key_broadcast` is a fixed
  ~524 KB capped event (8192 recipient slots × 32 B wrap + header).
  Rotating every 10 messages pays that cost 10× more often than
  rotating every 100.

- **Rotating rarely grows the K_bundle's blast radius.** When a new
  user joins, they receive historical K_bundles via
  `key_history_bundle`. Each K_bundle they receive grants access to
  **every undeleted message that was sent while it was current**. A
  rarely-rotated bundle covers more messages, so a new joiner with
  that bundle sees a larger slice of history.

The cost of not rotating is *not* network bandwidth — a single
K_bundle is as cheap to share as any other. The cost is the
**access granularity** you can offer new joiners. If you only want
them to see the last N messages, the current K_bundle must have
covered ≤ N messages.

## Notation

| Symbol | Meaning | Unit |
|---|---|---|
| `M` | Message send rate by one device | messages / sec |
| `J` | Rate of new joiners | joiners / sec |
| `R` | Rotation cadence — messages per K_bundle | messages |
| `D` | Per-message deletion probability | fraction (0-1) |
| `H_tail` | History tail length the workspace wants new joiners to see | messages |
| `W_bcast` | `key_broadcast` wire size | 524 288 B |
| `W_mkey` | `message_key` wire size | 165 B |
| `W_hb_entry` | `key_history_bundle` historical-slot size | 80 B |
| `C_hbe` | `key_history_bundle` wire size (8192 slots) | ~655 KB |
| `S_hb` | `key_history_bundle` historical-slot capacity | 8192 |

## Steady-state per-second cost

Network bandwidth the sender (and responder) spends under
continuous operation:

```
Per-second cost (one sender):
  C_msgs     = M · (message blob + W_mkey)              [per-message]
  C_rotate   = (M / R) · W_bcast                        [rotations]
  C_joiners  = J · ⌈ H_tail / (R · S_hb) ⌉ · C_hbe      [history to joiners]
```

`C_msgs` is independent of `R`. We optimize `C_rotate + C_joiners`.

### Regime A: R ≥ H_tail / S_hb (one `key_history_bundle` suffices)

```
C(R) = (M · W_bcast) / R + J · C_hbe
```

This decreases monotonically with R. Optimum within the regime is
`R → ∞` — but the blast-radius constraint forces `R ≤ H_tail`
(otherwise joiners see more than the `H_tail` window).

So in regime A, **optimal `R = H_tail`.**

At that point:
```
C_rotate_opt  = (M · W_bcast) / H_tail
C_joiners_opt = J · C_hbe
```

### Regime B: R < H_tail / S_hb (multiple `key_history_bundle`s needed)

When `R` is small enough that the joiner history window spans more
than 8192 bundles, each joiner needs multiple `key_history_bundle`
events. Historical-bundle count per joiner:

```
K_bundles_per_joiner = H_tail / R
history_events_per_joiner = ⌈ K_bundles_per_joiner / S_hb ⌉
```

Cost:
```
C(R) = (M · W_bcast) / R + J · ⌈ H_tail / (R · S_hb) ⌉ · C_hbe
     ≈ (M · W_bcast + J · H_tail · C_hbe / S_hb) / R
```

Both terms scale like 1/R. Decreasing R (rotating more) makes things
worse on BOTH axes simultaneously. So regime B is never optimal.

### Boundary: R = H_tail / S_hb

```
C(R*) = (M · W_bcast) · S_hb / H_tail + J · C_hbe
      = 524 KB · 8192 · M / H_tail + J · 655 KB
```

### Conclusion

**The optimum is always `R* = H_tail`**, one complete rotation per
desired history window. Below that, both rotation and joiner costs
inflate. Above that, you violate the blast-radius constraint.

If there is no blast-radius constraint (workspace is OK with new
joiners seeing everything), `R → ∞` minimizes cost at the price of
all history being accessible to any joiner who receives the one
K_bundle.

## Deletion interaction

Deletions purge individual messages' K_m + blob. Deletions do NOT
rotate K_bundle. Under Per-Message FS:

- `D` (deletion rate) reduces the number of undeleted messages a
  joiner can actually read, but not the number of K_bundle entries
  they receive. Each `key_history_bundle` slot maps to a K_bundle,
  not a message.
- Deletions amortize: if you delete `D · R` out of `R` messages in a
  bundle's window, the bundle still ships as one entry; the joiner
  simply has `D · R` fewer decryptable messages than `R`.
- Heavy deletion does NOT make rotation more attractive. It only
  means the effective history window is `(1 − D) · H_tail`
  messages, so the blast-radius constraint can be relaxed.

**Corrected optimum accounting for deletions:**

If the workspace's invariant is "new joiner sees at most `H_visible`
undeleted messages," then:

```
H_tail_effective = H_visible / (1 − D)
R* = H_tail_effective = H_visible / (1 − D)
```

Higher deletion rate → larger `R*` allowed without violating the
constraint.

## Worked examples

Numbers illustrate the cost of a naive or aggressive choice.

### Example 1: small workspace, moderate activity

- M = 1 msg / min = 1/60 msg / sec
- J = 1 joiner / week = 1 / 604 800 joiners / sec
- H_tail = 1000 messages (new joiners see last ~17h of chat)
- D = 0 (no deletions)

**R* = 1000.**

- `C_rotate` = (1/60 · 524 288) / 1000 B/s ≈ 8.7 B/s ≈ 27 MB/mo
- `C_joiners` ≈ J · 655 KB ≈ 1 KB per joiner per week = negligible

At `R = 100` (over-rotating): `C_rotate = 87 B/s ≈ 270 MB/mo`. 10× waste.

### Example 2: high-throughput workspace

- M = 10 msg / sec (very active)
- J = 5 joiners / day
- H_tail = 100 000 messages (a few hours of history)
- D = 0.05 (5% deletions)

Effective `H_tail_effective = 100000 / 0.95 ≈ 105 000`.

**R* ≈ 105 000.**

- `C_rotate` = (10 · 524 288) / 105 000 ≈ 50 B/s ≈ 130 MB/mo
- `C_joiners` = 5/day · 655 KB ≈ 3.3 MB/day ≈ 100 MB/mo

Close to balanced. At `R = 1000` (over-rotating): `C_rotate ≈ 5 KB/s
≈ 13 GB/mo`. ~100× regression.

### Example 3: very restrictive history

- M = 1 msg / sec
- J = 1 joiner / hour
- H_tail = 10 messages (only very recent visible to joiners)
- D = 0

**R* = 10.**

Forced rotation on nearly every message. `C_rotate = 524 288 / 10 =
~52 KB/s ≈ 135 GB/mo`. Expensive. The constraint drives the cost.

This regime is where per-message re-wrapping (emit `key_shared` for
each specific message rather than one K_bundle covering 10
messages) becomes competitive — but only if you can target the
joiner selectively per message, which breaks the "bundle" abstraction.

## Practical recommendations

1. **Default `R` = `H_tail`** where `H_tail` is the
   workspace-configured history window for new joiners.
2. **Don't over-rotate.** Rotating faster than `H_tail` / 8192 has
   no benefit and costs proportionally more.
3. **Don't under-rotate.** Rotating slower than `H_tail` means the
   current bundle covers more messages than the workspace policy
   allows new joiners to see — violates the guarantee.
4. **Adjust for deletion rate** if applicable: `R* = H_tail / (1 − D)`.
5. **When `H_tail` is very small (e.g., < 100):** the per-message
   cost of `key_broadcast` dominates. Consider whether the workspace
   really needs that tight a constraint, or whether deletion can
   achieve the same user-visible effect with lower cost.

## What this analysis does NOT cover

- **Heal cost** when a peer misses a bundle. `key_bundle_request`
  triggers a targeted `key_bundle_share` (~200 B). Scales with
  missed-delivery rate, orthogonal to rotation cadence.
- **Removal cost.** When a member is removed, future bundles omit
  their WrapPubkey from recipient slots — the removed peer simply
  stops receiving new K_bundles. The "rotate on removal" overhead
  is one extra `key_broadcast` at removal time, independent of `R`.
- **WrapPubkey rotation cadence.** Short-lived wrap pubkeys have
  their own rotation schedule (FS-driven, not blast-radius driven).
  Default cadence should be ≤ grace window for the FS property.
- **Storage vs network costs.** This model measures network
  bandwidth. Storage of old bundles on disk is a separate concern —
  old bundles are purgeable once all messages under them have been
  deleted or expired.
