# create_event_synchronous Semantics: Investigation Findings

> **Historical findings; completed. Retained for reference.**

Date: 2026-02-16
Branch: `plan/create-event-sync-semantics`
Worktree: `/home/holmes/poc-7-create-event-sync-plan`

## 1. Baseline Verification

- `cargo test --test cli_test -q`: 6/6 passed
- `cargo test --test scenario_test -q`: 58/58 passed

## 2. API Layer Summary

### Core APIs (`src/projection/create.rs`)

| Function | Blocked behavior | Purpose |
|---|---|---|
| `create_event_synchronous` | `Err(Blocked{event_id, missing})` | Strict: success only on Valid |
| `create_signed_event_synchronous` | `Err(Blocked{event_id, missing})` | Strict: success only on Valid |
| `create_encrypted_event_synchronous` | `Err(Blocked{event_id, missing})` | Strict (delegates to `create_event_synchronous`) |
| `create_event_staged` | `Ok(event_id)` on Blocked | Lenient: blocked-as-success for bootstrap flows |
| `create_signed_event_staged` | `Ok(event_id)` on Blocked | Lenient: blocked-as-success for bootstrap flows |

The staged variants are thin wrappers calling `event_id_or_blocked(create_event_synchronous(...))` (line 41-47, 220-239).

### Service wrapper (`src/service.rs:88-98`)

```rust
fn unwrap_event_id(result: Result<EventId, CreateEventError>) -> ServiceResult<EventId> {
    match result {
        Ok(eid) => Ok(eid),
        Err(CreateEventError::Blocked { event_id, .. }) => Ok(event_id),
        Err(e) => Err(ServiceError(format!("{}", e))),
    }
}
```

This mirrors `event_id_or_blocked` but is owned by the service layer. It converts `Blocked` into `Ok(event_id)`, silently discarding the blocked status.

## 3. Call-Site Inventory

### 3.1 service.rs — user-facing commands

| Line | Function | API call | Blocked handling | Notes |
|---|---|---|---|---|
| 355 | `ensure_identity_chain` | `unwrap_event_id(create_event_synchronous(...))` | **OK** | Workspace bootstrap; intentionally tolerates blocking before trust anchor |
| 362 | `ensure_identity_chain` | `create_event_synchronous(...)` | **Err** | InviteAccepted; should always succeed (is the trust anchor) |
| 376,387,398,409 | `ensure_identity_chain` | `create_signed_event_synchronous(...)` | **Err** | Post-cascade identity events; Blocked would be a bug |
| **607** | **`svc_send`** | **`unwrap_event_id(create_signed_event_synchronous(...))`** | **OK** | **Message — Blocked silently returns success** |
| 681 | `svc_generate` | `create_signed_event_synchronous(...)` | **Err** | Blocked propagates as error |
| **773** | **`svc_react`** | **`unwrap_event_id(create_signed_event_synchronous(...))`** | **OK** | **Reaction — Blocked silently returns success** |
| **801** | **`svc_delete_message`** | **`unwrap_event_id(create_signed_event_synchronous(...))`** | **OK** | **Deletion — Blocked silently returns success** |

### 3.2 main.rs — CLI commands

| Line | Function | API call | Blocked handling | Notes |
|---|---|---|---|---|
| 617 | `ensure_identity_chain` | `create_event_staged(...)` | **OK** | Workspace bootstrap; same intent as service |
| 625 | `ensure_identity_chain` | `create_event_synchronous(...)` | **Err** | InviteAccepted |
| 637,648,660,670 | `ensure_identity_chain` | `create_signed_event_synchronous(...)` | **Err** | Post-cascade; Blocked = bug |
| 702 | `send_message` | `create_signed_event_synchronous(...)` | **Err** | Message — Blocked is an error |
| 777 | `generate_messages` | `create_signed_event_synchronous(...)` | **Err** | Blocked is an error |
| 1102 | `cli_react` | `create_signed_event_synchronous(...)` | **Err** | Reaction — Blocked is an error |
| 1133 | `cli_delete_message` | `create_signed_event_synchronous(...)` | **Err** | Deletion — Blocked is an error |

### 3.3 identity_ops.rs

| Line | Function | API call | Blocked handling | Notes |
|---|---|---|---|---|
| 92 | `bootstrap_identity_chain` | `create_event_staged(...)` | **OK** | Workspace — intentional pre-trust-anchor staging |
| 105 | `bootstrap_identity_chain` | `create_signed_event_staged(...)` | **OK** | UserInvite — intentional pre-trust-anchor staging |
| 119 | `bootstrap_identity_chain` | `create_event_synchronous(...)` | **Err** | InviteAccepted — trust anchor, must succeed |
| 131,148,165,183 | `bootstrap_identity_chain` | `create_signed_event_synchronous(...)` | **Err** | Post-cascade events — must succeed |
| 236 | `create_user_invite` | `create_signed_event_synchronous(...)` | **Err** | |
| 271,283,300,317 | `accept_user_invite` | `create_event_synchronous / create_signed_event_synchronous` | **Err** | |
| 364 | `create_device_link` | `create_signed_event_synchronous(...)` | **Err** | |
| 392,404 | `accept_device_link` | mixed | **Err** | |
| 449 | `create_transport_key_if_possible` | `create_signed_event_synchronous(...)` | **Err** | |

### 3.4 interactive.rs

| Line | Function | API call | Blocked handling |
|---|---|---|---|
| 584 | send message | `create_signed_event_synchronous(...)` | **Err** |
| 727 | reaction | `create_signed_event_synchronous(...)` | **Err** |
| 808 | deletion | `create_signed_event_synchronous(...)` | **Err** |
| 1486 | signed memo | `create_signed_event_synchronous(...)` | **Err** |

### 3.5 transport_identity.rs

| Line | Function | API call | Blocked handling |
|---|---|---|---|
| 224 | transport key creation | `create_signed_event_synchronous(...)` | **Err** |

### 3.6 testutil.rs

Correctly uses staged APIs (`create_event_staged`, `create_signed_event_staged`) for pre-trust-anchor events in bootstrap helpers, and strict APIs for post-cascade events. No misalignment.

### 3.7 Test files

- `tests/perf_test.rs:334`: `create_signed_event_synchronous` — expects success
- `tests/scenario_test.rs`: mix of staged and strict APIs, all appropriate to context

## 4. Key Findings

### Finding 1: CLI/Service behavioral divergence

The service layer (`svc_send`, `svc_react`, `svc_delete_message`) wraps results with `unwrap_event_id`, silently converting Blocked into success. The CLI equivalents (`send_message`, `cli_react`, `cli_delete_message`) do **not** wrap — Blocked propagates as an error.

This means:
- A message sent via the daemon RPC returns success even if it's blocked (not projected to `messages` table, not visible to queries).
- The same message sent via CLI returns an error.

### Finding 2: Blocked-as-success is misleading for content events

For content events (message, reaction, deletion), blocking typically means a dependency is missing (e.g., the target message for a reaction, or the signer identity event). Returning success when the event is blocked and invisible to queries gives the caller false confirmation.

### Finding 3: Staged APIs are correctly scoped

The `create_event_staged` / `create_signed_event_staged` APIs are used exclusively for bootstrap flows where blocking is expected and will resolve via guard cascade (workspace + pre-trust-anchor identity events). This is correct and well-understood by callers.

### Finding 4: PLAN contract is clear

`docs/PLAN.md:600-602` states:
> default `create_event_synchronous` must return success only when the created event is `valid` for `recorded_by`.
> if terminal state is `blocked` or `rejected`, return an error containing `event_id` + terminal reason.

The core `create_event_synchronous` already satisfies this contract. The contract violation exists only in the service-layer `unwrap_event_id` wrapper applied to content-event call sites.

### Finding 5: No caller actually depends on Blocked-as-success for content events

No service caller chains a subsequent operation on the event_id returned from a Blocked content event. The send/react/delete service functions return the event_id to the caller (as a response) but nothing downstream depends on that event_id being Valid. The Blocked event is stored and would eventually unblock if the missing dependency arrives via sync — but callers don't wait for this.

## 5. Option Matrix

### Option A: Strict success-only-on-valid contract (recommended)

Remove `unwrap_event_id` from content-event service paths. Let `svc_send`, `svc_react`, `svc_delete_message` propagate `CreateEventError::Blocked` as `ServiceError`.

**API impact:**
- `svc_send`, `svc_react`, `svc_delete_message` return `Err` when event is Blocked.
- Response type unchanged (success path still returns `SendResponse`/`ReactResponse`/`DeleteResponse`).

**Caller impact:**
- RPC/daemon callers see an error instead of silent success for blocked events.
- CLI callers already see errors (no change).
- Interactive callers already see errors (no change).
- `svc_generate` already propagates errors (no change).

**Test impact:**
- No test relies on `unwrap_event_id` converting Blocked to success for content events.
- `svc_send`/`svc_react`/`svc_delete_message` are exercised through CLI tests and scenario tests, which use strict APIs.
- Add explicit service-layer tests confirming Blocked propagation.

**Migration steps (POC-style, no compatibility):**
1. Remove `unwrap_event_id` calls from `svc_send` (line 607), `svc_react` (line 773), `svc_delete_message` (line 801).
2. Replace with direct `create_signed_event_synchronous(...)` calls, converting `CreateEventError` to `ServiceError` via `.map_err(|e| ServiceError(format!("{}", e)))`.
3. Keep `unwrap_event_id` only for `ensure_identity_chain` workspace bootstrap (line 355), where Blocked-as-success is correct and intentional.
4. Add service-layer unit tests for Blocked propagation.
5. Run full regression gate.

**Risk:** Low. No existing test or caller depends on Blocked-as-success for content events.

**Rollback:** Revert the three call-site changes; re-add `unwrap_event_id` wrapping.

### Option B: Preserve current behavior with explicit status in response

Keep `unwrap_event_id` but add a `status` field to `SendResponse`/`ReactResponse`/`DeleteResponse` so callers can distinguish `valid` from `blocked`.

**API impact:**
- Response types gain a `status: "valid" | "blocked"` field.
- Return type stays `Ok(...)`, preserving current caller assumptions.

**Caller impact:**
- Existing callers continue to work (backward-compatible).
- Callers that care can check `status`.

**Test impact:**
- Add tests verifying the `status` field is populated correctly.

**Migration steps:**
1. Add `status` field to response structs.
2. Thread the Blocked/Valid distinction through the wrapper.
3. Keep `unwrap_event_id` logic but capture the distinction.
4. Update tests to verify status values.

**Risk:** Medium. Adds complexity without resolving the core semantic issue. POC replacement policy discourages adding compatibility scaffolding when the simpler contract (Option A) is available.

**Rollback:** Remove the `status` field.

### Option C: Eliminate `unwrap_event_id` entirely, use staged APIs where Blocked-OK is needed

Remove `unwrap_event_id` from service.rs entirely. For the workspace bootstrap case in `ensure_identity_chain`, switch to `create_event_staged` (already available) instead of `unwrap_event_id(create_event_synchronous(...))`.

**API impact:** Same as Option A for content events.

**Additional cleanup:** `ensure_identity_chain` in service.rs (line 355) switches from `unwrap_event_id(create_event_synchronous(...))` to `create_event_staged(...)`, matching the main.rs pattern.

**Advantage over A:** Eliminates the `unwrap_event_id` function entirely. All Blocked-as-success semantics flow through the well-named `create_event_staged` / `create_signed_event_staged` APIs.

**Test/risk:** Same as Option A — low risk, minimal test changes.

## 6. Recommendation

**Option C** is recommended.

Rationale:
1. Aligns with PLAN contract (success-only-on-valid for `create_event_synchronous`).
2. Eliminates the service-layer `unwrap_event_id` entirely — all Blocked-as-OK flows through explicitly named staged APIs.
3. Resolves the CLI/service behavioral divergence.
4. Follows POC replacement policy: one canonical behavior, no compatibility wrapper.
5. Lowest complexity, no new response fields or dual-path logic.
6. No caller actually depends on the removed behavior.

## 7. Implementation Scope (post-approval)

If Option C is approved:

1. `src/service.rs`:
   - Line 355: replace `unwrap_event_id(create_event_synchronous(db, recorded_by, &ws))` with `create_event_staged(db, recorded_by, &ws).map_err(|e| ServiceError(format!("{}", e)))`.
   - Lines 607, 773, 801: replace `unwrap_event_id(create_signed_event_synchronous(...))` with `create_signed_event_synchronous(...).map_err(|e| ServiceError(format!("{}", e)))`.
   - Delete the `unwrap_event_id` function (lines 88-98) and its doc comment (lines 80-91).
   - Add `create_event_staged` to the import from `crate::projection::create`.
2. Add service-layer tests verifying:
   - Content events with missing deps return `Err`.
   - Bootstrap workspace creation with staged API returns `Ok` on Blocked.
3. Full regression gate: `cargo test -q`.
