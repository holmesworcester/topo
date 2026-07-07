//! Bug-hunting proofs: attempt to find contradictions, edge cases, and
//! undesired behaviors in the actual code logic.
//!
//! Unlike the correctness proofs, these attempt to model the ACTUAL behavior
//! precisely and surface violations of the proven invariants.

use vstd::prelude::*;
use crate::decision::*;

verus! {

// ═══════════════════════════════════════════════════════════════════
// BUG 1: Session Auth TTL Window is Wider Than Advertised
// ═══════════════════════════════════════════════════════════════════
//
// The validate_expiry function accepts:
//   expires_at + CLOCK_SKEW >= now  (not expired)
//   expires_at <= now + TTL + CLOCK_SKEW  (not too far future)
//
// An attacker creates auth at time T with expires_at = T + TTL.
// The auth is accepted at time T (obviously).
// The auth is ALSO accepted at time T + TTL + CLOCK_SKEW
// because: expires_at + CLOCK_SKEW = T + TTL + CLOCK_SKEW >= T + TTL + CLOCK_SKEW.
//
// Effective maximum lifetime = TTL + CLOCK_SKEW = 5min + 30s = 330s.
// But the system advertises 5 minute maximum TTL.
//
// Worse: a RECEIVING node with clock skewed -30s from sender sees the auth
// as valid for TTL + 2*CLOCK_SKEW = 360s = 6 minutes.

pub spec const TTL: nat = 300_000;        // 5 min
pub spec const SKEW: nat = 30_000;        // 30 sec

pub open spec fn actual_expiry_valid(expires_at: nat, now: nat) -> bool {
    expires_at + SKEW >= now
    && expires_at <= now + TTL + SKEW
}

/// FINDING: An auth token with expires_at = creation_time + TTL is still
/// valid SKEW milliseconds after it should have expired.
/// Effective max lifetime from the perspective of a clock-accurate node
/// is TTL + SKEW = 330 seconds, not 300.
proof fn finding_auth_valid_beyond_advertised_ttl(creation_time: nat)
    requires creation_time >= SKEW
    ensures
        ({
            let expires_at = creation_time + TTL;
            // Still valid 30 seconds after nominal expiry
            let late_check_time = creation_time + TTL + SKEW;
            actual_expiry_valid(expires_at, late_check_time)
        }),
{
}

/// FINDING: From the perspective of a receiver whose clock is SKEW behind
/// the sender, the effective lifetime is TTL + 2*SKEW = 360 seconds.
proof fn finding_clock_skew_doubles_extension(sender_time: nat)
    requires sender_time >= SKEW
    ensures
        ({
            let expires_at = sender_time + TTL;
            // Receiver's clock is SKEW behind: receiver_now = sender_time - SKEW
            // when sender creates. receiver_now = sender_time + TTL + SKEW when
            // checking at sender_time + TTL + 2*SKEW (from receiver's perspective,
            // 360 seconds after their "creation time").
            let receiver_check = sender_time + TTL + SKEW;
            actual_expiry_valid(expires_at, receiver_check)
        }),
{
}

// ═══════════════════════════════════════════════════════════════════
// BUG 2: Empty-Missing Block Creates Unresolvable State
// ═══════════════════════════════════════════════════════════════════
//
// workspace/projector.rs line 18: ContextLoadResult::block(vec![])
// file_slice/projector.rs line 48: Block { missing: vec![] }
//
// These create a Block decision with zero missing deps. The cascade
// algorithm only unblocks events when their blocker becomes valid
// (blocker is in blocked_event_deps). With no deps recorded, the
// cascade can NEVER reach this event.
//
// In practice, the workspace case is rescued by RetryWorkspaceEvent
// (emitted by invite_accepted), and file_slice by RetryFileSliceGuards
// (emitted by file projector). But this relies on the command mechanism
// working correctly — if the retry command fails or is lost, the event
// is stuck forever with no way to recover via the dep cascade path.
//
// The invariant "Block.missing.len() > 0" that we proved in decision.rs
// is VIOLATED by the actual code.

/// Model of the actual guard-block behavior.
pub open spec fn guard_block_with_empty_missing() -> ProjectionDecision {
    ProjectionDecision::Block { missing_count: 0 }
}

/// FINDING: The proven invariant "Block implies missing_count > 0" is
/// violated by guard-blocks. This means cascade_unblocked can NEVER
/// resolve these events through the normal dep-resolution path.
proof fn finding_empty_block_violates_proven_invariant()
    ensures
        ({
            let d = guard_block_with_empty_missing();
            // This IS a Block...
            matches!(d, ProjectionDecision::Block { .. })
            // ...but it has NO missing deps
            && (match d {
                ProjectionDecision::Block { missing_count } => missing_count == 0,
                _ => false,
            })
        }),
{
}

/// FINDING: An empty-missing Block has no deps to satisfy, so the cascade
/// algorithm will never process it. If the retry command also fails,
/// the event is permanently stuck.
pub open spec fn cascade_can_resolve_block(missing_count: nat) -> bool {
    missing_count > 0  // cascade resolves blocks by decrementing deps_remaining
}

proof fn finding_empty_block_unresolvable_by_cascade()
    ensures !cascade_can_resolve_block(0),
{
}

// ═══════════════════════════════════════════════════════════════════
// BUG 3: deps_remaining Counter Desync with Duplicate Dep Edges
// ═══════════════════════════════════════════════════════════════════
//
// record_block_rows: deduplicates missing, then sets deps_remaining = deduped.len()
// blocked_event_deps: INSERT OR IGNORE per dep
//
// Scenario: Event E depends on A and B.
// First projection: record_block_rows(E, [A, B]). deps_remaining = 2.
//
// Now suppose E gets re-blocked (e.g., dep-unblocked then guard-blocked,
// then the guard retry re-enters dep-blocked state with different deps).
// ContextLoadResult::Block { missing: [A, C] } → record_block(E, [A, C]).
//
// record_block_rows uses INSERT OR IGNORE for blocked_events:
//   "INSERT OR IGNORE INTO blocked_events (peer_id, event_id, deps_remaining)"
//
// Since (peer_id, event_id) already exists (from the first block),
// INSERT OR IGNORE does NOTHING — deps_remaining stays at 2.
// But now blocked_event_deps has edges for A, B, AND C (3 edges).
//
// When A resolves: deps_remaining goes 2→1 (correct).
// When B resolves: deps_remaining goes 1→0 (triggers unblock).
// But C is still missing! Event E gets projected without C.
//
// The orphan cleanup at end of cascade_unblocked_inner handles
// this for some paths, but there is a window.

pub open spec fn deps_remaining_matches_edges(
    deps_remaining: nat,
    dep_edge_count: nat,
) -> bool {
    deps_remaining == dep_edge_count
}

/// FINDING: INSERT OR IGNORE on re-block can desync the counter.
/// First block: deps_remaining=2, edges={A,B}.
/// Re-block with different deps: INSERT OR IGNORE → deps_remaining stays 2,
/// but edges now include {A,B,C} (3 edges via INSERT OR IGNORE).
proof fn finding_reblock_can_desync_counter()
    ensures
        ({
            let first_block_remaining: nat = 2;
            let after_reblock_edges: nat = 3;
            // INSERT OR IGNORE means deps_remaining doesn't update
            let actual_remaining_after_reblock = first_block_remaining;
            !deps_remaining_matches_edges(actual_remaining_after_reblock, after_reblock_edges)
        }),
{
}

// ═══════════════════════════════════════════════════════════════════
// BUG 4: Removal Race Window in Session Auth
// ═══════════════════════════════════════════════════════════════════
//
// PeerShared auth flow:
// 1. is_authorized_for_tenant(conn, recorded_by, target) → true
// 2. peer_route_is_admitted_for_daemon(conn, ...) → true
// 3. send_session_route(io, ...) → success
// 4. read_auth_ack(io) → success
// 5. BEGIN SYNC SESSION (events flow)
//
// Between step 2 and step 5, the remote peer could be removed
// (removal event projected). The authorization check is point-in-time.
// The sync session continues with a now-removed peer.
//
// This is a TOCTOU (time-of-check-time-of-use) vulnerability.
// The window could be exploited by a compromised peer that knows
// a removal is pending.

pub open spec fn toctou_auth_model(
    authorized_at_check: bool,
    removed_after_check: bool,
    session_continues: bool,
) -> bool {
    // Session continues if authorized at check time,
    // regardless of removal after check
    authorized_at_check && session_continues
}

/// FINDING: A peer removed AFTER authorization check can still
/// exchange data in the current session.
proof fn finding_removal_race_allows_data_exchange()
    ensures
        toctou_auth_model(true, true, true),
{
}

// ═══════════════════════════════════════════════════════════════════
// BUG 5: Deletion Intent Without Author Match is Never Cleaned Up
// ═══════════════════════════════════════════════════════════════════
//
// message_deletion/projector.rs records deletion_intents for ALL
// Valid deletion events (intent-only path). The intent has author_id
// from the deletion event.
//
// message/projector.rs checks: ctx.deletion_intents.iter().find(|i| i.author_id == author_id_b64)
// It only matches intents where the deletion's author_id matches the
// message's author_id.
//
// If Eve sends a MessageDeletion for Alice's message_id but with
// Eve's author_id, and Alice's message hasn't arrived yet:
// 1. Deletion projector: target_message_author is None → Valid, records intent
// 2. Alice's message arrives: finds Eve's intent, but author_id doesn't match
// 3. Message is projected normally (correct!)
// 4. Eve's deletion intent row persists in deletion_intents table FOREVER
//
// This is an unbounded storage growth vector: an attacker can create
// unlimited deletion_intent rows for messages they don't own, and
// these rows are never cleaned up.

/// Model: deletion intent persistence.
pub open spec fn wrong_author_intent_persists(
    intent_author_matches_message: bool,
    message_projected: bool,
    intent_row_cleaned_up: bool,
) -> bool {
    // If author doesn't match, the intent is ignored but persists
    !intent_author_matches_message && message_projected && !intent_row_cleaned_up
}

/// FINDING: Wrong-author deletion intents are never cleaned up.
proof fn finding_wrong_author_intents_persist_forever()
    ensures wrong_author_intent_persists(false, true, false),
{
}

// ═══════════════════════════════════════════════════════════════════
// BUG 6: apply_projection Side-Effect Policy Allows Block+Commands
//        Even When Well-Formedness Says write_ops Should Be Empty
// ═══════════════════════════════════════════════════════════════════
//
// Our proven invariant says: Block results have write_ops.len() == 0.
// But the actual code in file_slice/projector.rs line 47-54 returns:
//
//   ProjectorResult {
//       decision: Block { missing: vec![] },
//       write_ops: Vec::new(),        // OK, empty
//       emit_commands: vec![RecordFileSliceGuardBlock { ... }],  // non-empty!
//   }
//
// The stages.rs apply_projection DOES execute emit_commands for Block:
//   ProjectionDecision::Block { .. } => {
//       backend.execute_emit_commands(recorded_by, &result.emit_commands)?;
//   }
//
// This is actually CORRECT by design (Block can have commands).
// But it means the guard_blocked events' side effects
// (RecordFileSliceGuardBlock) execute BEFORE the event reaches
// a terminal state. If projection is retried, the command executes
// AGAIN. RecordFileSliceGuardBlock uses INSERT OR IGNORE so this
// is idempotent — but other Block-side commands might not be.

/// Model: Block-side commands execute on every Block decision, not just once.
pub open spec fn block_command_executes_on_retry(
    first_block: bool,
    retry_block: bool,
    command_idempotent: bool,
) -> bool {
    // Command executes on both first block and retry
    first_block && retry_block
}

/// FINDING: Block-side commands execute on EVERY block attempt, not once.
/// This is safe only if all Block-side commands are idempotent.
proof fn finding_block_commands_execute_repeatedly()
    ensures block_command_executes_on_retry(true, true, true),
{
}

// ═══════════════════════════════════════════════════════════════════
// BUG 7: Bootstrap Trust Can Be Refreshed Indefinitely
// ═══════════════════════════════════════════════════════════════════
//
// Bootstrap trust TTL is 24 hours. But the responder in
// read_inbound_session_auth caches accepted bootstrap auth on the
// DaemonConnection:
//   conn.remember_accepted_bootstrap_auth(invite_event_id, remote_peer_id, tenant_id)
//
// On subsequent sessions on the SAME daemon connection, the cached
// tenant is used directly (bypassing the DB TTL check):
//   conn.accepted_bootstrap_tenant(&invite_event_id_b64, &remote_peer_id)
//       .ok_or(err)?
//
// If the daemon connection stays alive for > 24 hours (possible with
// persistent QUIC), the cached bootstrap auth outlives its DB TTL.
// The attacker keeps opening new sessions on the same connection
// without needing the invite trust rows to still be valid.

pub open spec fn bootstrap_cache_outlives_ttl(
    connection_duration_ms: nat,
    bootstrap_ttl_ms: nat,
    cache_still_valid: bool,
) -> bool {
    connection_duration_ms > bootstrap_ttl_ms && cache_still_valid
}

/// FINDING: Bootstrap auth cache on long-lived connections can outlive
/// the underlying trust TTL.
proof fn finding_bootstrap_cache_outlives_db_ttl()
    ensures
        ({
            let ttl: nat = 86_400_000; // 24 hours
            let connection_alive: nat = 90_000_000; // 25 hours
            bootstrap_cache_outlives_ttl(connection_alive, ttl, true)
        }),
{
}

// ═══════════════════════════════════════════════════════════════════
// BUG 8: Forged Invite Link Workspace Can Drive Raw Cross-Workspace Exfil
// ═══════════════════════════════════════════════════════════════════
//
// Current runtime shape:
// 1. The invite link carries a plaintext WORKSPACE field.
// 2. prepare_invite_acceptance records that link workspace into local bootstrap
//    context before the canonical invite event is checked.
// 3. accept_invite emits InviteAccepted using that accepted workspace.
// 4. same_workspace_seed replay uses InviteAccepted.workspace_id to copy
//    existing shared events from sibling tenants in the same local DB.
// 5. outbound sync also uses the tenant's accepted workspace binding to choose
//    the shared_event_index slice to send.
//
// If an attacker changes only WORKSPACE in the link to a victim's existing
// local workspace, the accept path can replay that victim workspace locally and
// then sync the raw event blobs outward, even though the canonical invite event
// belongs to a different workspace.
//
// This proof is intentionally expected to FAIL under the current modeled
// behavior. Once the accept binding is repaired to come from the canonical
// invite event workspace instead of the link field, the proof should pass.

/// Current buggy binding model: the accepted workspace comes from the link.
pub open spec fn invite_accept_binding_workspace(
    canonical_invite_workspace: nat,
    link_workspace: nat,
) -> nat {
    link_workspace
}

/// same_workspace_seed replay occurs when the accepted workspace matches an
/// existing local workspace that already has shared history.
pub open spec fn local_same_workspace_seed_occurs(
    existing_local_workspace: nat,
    accepted_workspace: nat,
) -> bool {
    existing_local_workspace == accepted_workspace
}

/// Outbound sync chooses which shared events to send by the accepted workspace.
pub open spec fn outbound_sync_selects_workspace(
    event_workspace: nat,
    accepted_workspace: nat,
) -> bool {
    event_workspace == accepted_workspace
}

/// Full raw-exfil path: a forged link binds to the victim's local workspace,
/// replays sibling shared history locally, and selects that victim workspace
/// again for outbound sync.
pub open spec fn raw_exfil_path_exists(
    canonical_invite_workspace: nat,
    forged_link_workspace: nat,
) -> bool {
    let accepted_workspace =
        invite_accept_binding_workspace(canonical_invite_workspace, forged_link_workspace);
    local_same_workspace_seed_occurs(forged_link_workspace, accepted_workspace)
        && outbound_sync_selects_workspace(forged_link_workspace, accepted_workspace)
}

/// SECURITY GOAL: forging the link workspace must never create a raw exfil path.
///
/// This is currently false because invite_accept_binding_workspace() models the
/// vulnerable runtime behavior by returning the forged link workspace.
proof fn finding_forged_link_cannot_exfiltrate_raw_victim_workspace(
    canonical_invite_workspace: nat,
    victim_existing_workspace: nat,
)
    requires canonical_invite_workspace != victim_existing_workspace
    ensures !raw_exfil_path_exists(canonical_invite_workspace, victim_existing_workspace),
{
}

} // verus!
