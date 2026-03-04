# DESIGN / PLAN / TLA+ / projector_spec / Code Discrepancy Matrix

Date: 2026-02-17
Branch: `todo-path/spec-final-reconcile`
Base: `dd3a1f0` (current master)

## Status Legend

| Tag | Meaning |
|-----|---------|
| **SAFE-FIX** | Unambiguous doc correction, no semantic change needed |
| **CODE-BUG** | Code diverges from all specs; fix is code, not docs |
| **BLOCKED-A** | Requires Path A (transport identity unification) outcomes |
| **BLOCKED-B** | Requires Path B (encrypted-inner / pipeline) outcomes |
| **BLOCKED-C** | Requires Path C (CLI isomorphism / service layer) outcomes |
| **DECISION** | Needs explicit owner decision before fix |

---

## D1: DESIGN §9.5 — Trust source list says `transport_keys`

| Source | Says |
|--------|------|
| **DESIGN.md:775** | "three trust sources: `transport_keys`, `invite_bootstrap_trust`, `pending_invite_bootstrap_trust`" |
| **DESIGN.md:301** | Same three-source list in §3.2.1 "Per-tenant dynamic trust" |
| **DESIGN.md:138** | §2.2 defines `TrustedPeerSet = PeerShared_SPKIs ∪ invite_bootstrap_trust ∪ pending_invite_bootstrap_trust` (no `transport_keys`) |
| **projector_spec.md:255-256** | `transport_keys` rows marked **(legacy)** and **non-authoritative** |
| **projector_spec.md:257** | `InvTrustedPeerSetMembers` says members come from PeerShared-derived SPKIs, bootstrap trust, or pending bootstrap trust |

**Discrepancy**: DESIGN §9.5 and §3.2.1 list `transport_keys` as a peer of bootstrap trust sources. But §2.2 and projector_spec.md define the TrustedPeerSet without `transport_keys`, and projector_spec marks them as legacy/non-authoritative.

**Tag**: **SAFE-FIX** — Update DESIGN §9.5 and §3.2.1 to match §2.2 and projector_spec.md. The three trust sources are PeerShared-derived SPKIs, `invite_bootstrap_trust`, and `pending_invite_bootstrap_trust`. Add note that `transport_keys` is a legacy/transitional source.

---

## D2: DESIGN §9.5 — Supersession invariant names use `TransportKey`

| Source | Says |
|--------|------|
| **DESIGN.md:789-790** | `InvBootstrapConsumedByTransportKey`, `InvPendingConsumedByTransportKey` |
| **projector_spec.md:280-281** | `InvBootstrapConsumedByPeerShared`, `InvPendingConsumedByPeerShared` |
| **EventGraphSchema.tla:539** | `InvBootstrapTrustConsumedByTransportKey` |
| **TransportCredentialLifecycle.tla:232** | `InvBootstrapConsumedByTransportKey` |

**Discrepancy**: DESIGN and TLA+ files use old `...ByTransportKey` naming. projector_spec.md uses new `...ByPeerShared` naming. The Rust implementation (`supersede_accepted_bootstrap_if_steady_trust_exists`) supersedes bootstrap rows when PeerShared-derived trust appears, matching the `ByPeerShared` semantics.

**Tag**: **SAFE-FIX** for DESIGN.md (update invariant names to match projector_spec.md). **BLOCKED-A** for TLA+ model changes (requires transport identity unification decision — TLA+ model still models TransportKey as an independent trust source).

---

## D3: DESIGN §3.2.1 — "Disjoint trust sets" claim

| Source | Says |
|--------|------|
| **DESIGN.md:301** | "Tenants in different workspaces have disjoint trust sets." |
| **Code** | Trust lookup is scoped by `recorded_by` per tenant. Same SPKI can appear in multiple tenants' trust rows. |
| **TODO.md item 12** | Documents this as an open decision: option A (scoped-lookup, overlap allowed) vs option B (strict value-level disjointness). |

**Discrepancy**: DESIGN claims a stronger property than code implements. PLAN.md correctly avoids this claim.

**Tag**: **SAFE-FIX** — Update DESIGN §3.2.1 wording to say "tenant trust checks are isolated by `recorded_by`" instead of "disjoint trust sets". This matches the implemented scoped-lookup semantics without requiring enforcement changes.

---

## D4: TLA+ models — Missing PeerShared-based supersession invariants

| Source | Says |
|--------|------|
| **projector_spec.md:252** | `InvBootstrapTrustConsumedByPeerShared` |
| **projector_spec.md:280** | `InvBootstrapConsumedByPeerShared` |
| **EventGraphSchema.tla** | Only has `InvBootstrapTrustConsumedByTransportKey` |
| **TransportCredentialLifecycle.tla** | Only has `InvBootstrapConsumedByTransportKey` |

**Discrepancy**: projector_spec.md references PeerShared-based supersession invariants that do not exist in either TLA+ file. The TLA+ models still model the old TransportKey-based supersession.

**Tag**: **BLOCKED-A** — TLA+ model update requires transport identity architecture decision (TODO 11). The projector_spec.md mapping is aspirational/correct for the target state; the TLA+ models need updating to match once the transport identity model is finalized.

---

## D5: TLA+ `TrustedPeerSet` includes `TransportKeyTrustSet`

| Source | Says |
|--------|------|
| **EventGraphSchema.tla:307-308** | `TrustedPeerSet(p) == BootstrapTrustSet(p) ∪ PendingBootstrapTrustSet(p) ∪ TransportKeyTrustSet(p)` |
| **projector_spec.md:257** | TrustedPeerSet members come from PeerShared-derived SPKIs, bootstrap trust, or pending bootstrap trust |
| **DESIGN.md:138** | `TrustedPeerSet = PeerShared_SPKIs ∪ invite_bootstrap_trust ∪ pending_invite_bootstrap_trust` |

**Discrepancy**: TLA+ model includes `TransportKeyTrustSet` as an authoritative trust source. DESIGN and projector_spec define it differently (PeerShared-derived SPKIs, not TransportKey events).

**Tag**: **BLOCKED-A** — Same root cause as D4. TLA+ model needs TransportKey→PeerShared trust source migration.

---

## D6: projector_spec.md — Three unmapped TLA+ invariants

| Invariant | TLA+ Location | projector_spec.md |
|-----------|--------------|-------------------|
| `InvEncryptedKey` | EventGraphSchema.tla:645 | Not mapped |
| `InvSecretSharedKey` | EventGraphSchema.tla:651 | Not mapped |
| `InvFileSliceAuth` | EventGraphSchema.tla:658 | Not mapped |

**Discrepancy**: These three invariants are declared in the TLA+ model and checked by TLC but have no corresponding rows in projector_spec.md's invariant mapping table.

**Tag**: **SAFE-FIX** — Add mapping rows to projector_spec.md for these three invariants. They are structural dependency guarantees already enforced by the Rust dependency engine.

---

## D7: Message event — Missing `workspace_id` dependency

| Source | Says |
|--------|------|
| **projector_spec.md:50** | Message deps: `{Workspace}` / `[workspace_event_id]` |
| **EventGraphSchema.tla:200** | Message rawDeps: `{Workspace}` |
| **EventGraphSchema.tla:639** | `InvMessageWorkspace`: Message valid → Workspace valid |
| **Code (mod.rs:141)** | `dep_field_values` returns only `[("signed_by", m.signed_by)]` |
| **Code (message.rs:106)** | `MESSAGE_META.dep_fields = &["signed_by"]` (missing `workspace_id`) |

**Discrepancy**: Both TLA+ and projector_spec.md declare `workspace_id` as a dependency for Message events. The Rust code does not include it in dependency extraction, meaning a message could theoretically become valid without its workspace event being valid first.

**Practical impact**: In normal operation, the signer chain guarantees workspace validity transitively (messages are signed by a PeerShared key, which depends on DeviceInvite, which depends on User, which depends on UserInvite, which depends on Workspace). However, the explicit workspace dependency provides defense-in-depth and matches the TLA invariant.

**Tag**: **CODE-BUG** — The code should add `workspace_id` to Message's `dep_fields` and `dep_field_values()`. This is a correctness fix that aligns code with all specs. However, this is a semantic change that requires tests, so it is recorded here but **not implemented in this doc-only reconciliation pass**. It should be fixed under TODO 19 with proper test coverage.

---

## D8: DESIGN §9.5 — Supersession description says `transport_keys`

| Source | Says |
|--------|------|
| **DESIGN.md:777** | "when steady-state `transport_keys` trust appears for a peer, matching `invite_bootstrap_trust` and `pending_invite_bootstrap_trust` entries are automatically consumed" |
| **Rust code** | `supersede_accepted_bootstrap_if_steady_trust_exists` and `supersede_pending_bootstrap_if_steady_trust_exists` supersede when PeerShared-derived trust appears |
| **projector_spec.md:280-281** | `...ConsumedByPeerShared` |

**Discrepancy**: DESIGN describes supersession as triggered by `transport_keys` trust appearance. Implementation triggers on PeerShared-derived SPKI trust appearance.

**Tag**: **SAFE-FIX** — Update DESIGN §9.5 supersession description to say "when steady-state PeerShared-derived trust appears" instead of "when steady-state `transport_keys` trust appears".

---

## D9: DESIGN §7.1 — `ingress_queue` compatibility framing

| Source | Says |
|--------|------|
| **DESIGN.md:549** | "`ingress_queue` exists in schema as reserved compatibility/diagnostic staging" |
| **TODO.md item 20** | Lists `ingress_queue` compatibility framing as residual cruft to remove |

**Discrepancy**: The "reserved compatibility/diagnostic staging" framing contradicts the POC's no-backward-compatibility policy. If the queue is unused, it should either be removed or described as a potential future staging table, not a compatibility artifact.

**Tag**: **SAFE-FIX** — Update DESIGN §7.1 to describe `ingress_queue` as "reserved for future diagnostic staging" without the compatibility framing. Actual table removal is TODO 20 scope.

---

## D10: DESIGN §2.4.1 — Bootstrap chain includes TransportKey

| Source | Says |
|--------|------|
| **DESIGN.md:222** | Bootstrap creates: "Workspace → UserInvite → InviteAccepted → User → DeviceInvite → PeerShared → Admin → **TransportKey**" |
| **DESIGN.md:228** | Accept creates: "InviteAccepted → User → DeviceInvite → PeerShared → **TransportKey**" |

**Discrepancy**: Bootstrap chain ends with TransportKey event creation. If transport identity is now derived from PeerShared, TransportKey may be vestigial in the bootstrap chain.

**Tag**: **BLOCKED-A** — Depends on transport identity architecture decision (TODO 11). If TransportKey is removed, bootstrap chain description needs updating. Not a safe doc fix until the decision is made.

---

## D11: Reaction event — projector_spec.md dep table inconsistency

| Source | Says |
|--------|------|
| **projector_spec.md:51** | Reaction deps: `{target_event_id}` / `[target_event_id]` |
| **Code (mod.rs:142)** | `dep_field_values` returns `[("target_event_id", r.target_event_id), ("signed_by", r.signed_by)]` |

**Discrepancy**: projector_spec.md only lists `target_event_id` as a dependency for Reaction, but the code also includes `signed_by`. Since Reaction has `signer_required: true`, `signed_by` is implicitly a dependency via the signer pipeline. The projector_spec.md table should include it for consistency with how other signed events are documented.

**Note**: Looking more carefully, the projector_spec.md Dependencies table appears to exclude `signed_by` from signed event deps when signer handling is done by the shared pipeline. This is a documentation convention, not a true discrepancy. The `signed_by` dep is extracted automatically for all `signer_required: true` events. **No fix needed** — the convention is consistent (only non-signer deps are listed in the TLA+ RawDeps column).

**Tag**: **NO-FIX** — Documentation convention is consistent. Signer deps are handled by the shared pipeline and not listed separately in the TLA RawDeps column.

---

## D12: MessageDeletion — projector_spec.md dep includes signed_by but TLA says target_event_id only

Same pattern as D11. `signed_by` is a signer dep handled by shared pipeline. TLA+ `RawDeps` only lists non-signer structural deps. Convention is consistent.

**Tag**: **NO-FIX**

---

## Summary

| ID | Discrepancy | Tag | Action in this pass |
|----|-------------|-----|---------------------|
| D1 | DESIGN §9.5/§3.2.1 trust source list | SAFE-FIX | Fix now |
| D2 | DESIGN §9.5 supersession invariant names | SAFE-FIX | Fix now |
| D3 | DESIGN §3.2.1 "disjoint trust sets" | SAFE-FIX | Fix now |
| D4 | TLA+ missing PeerShared supersession invariants | BLOCKED-A | Record in FEEDBACK |
| D5 | TLA+ TrustedPeerSet includes TransportKeyTrustSet | BLOCKED-A | Record in FEEDBACK |
| D6 | projector_spec.md missing 3 invariant mappings | SAFE-FIX | Fix now |
| D7 | Message missing workspace_id dep in code | CODE-BUG | Record in FEEDBACK (semantic change, needs tests) |
| D8 | DESIGN §9.5 supersession description | SAFE-FIX | Fix now |
| D9 | DESIGN §7.1 ingress_queue compat framing | SAFE-FIX | Fix now |
| D10 | DESIGN §2.4.1 bootstrap chain includes TransportKey | BLOCKED-A | Record in FEEDBACK |
| D11 | Reaction dep table convention | NO-FIX | N/A |
| D12 | MessageDeletion dep table convention | NO-FIX | N/A |
