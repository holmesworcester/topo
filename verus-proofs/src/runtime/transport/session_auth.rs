//! Formal verification of the core session authentication protocol.
//!
//! Two authentication paths exist:
//!   A. PeerShared (steady-state): OpenSessionRoute -> authorization check -> ack
//!   B. InviteBootstrap (transient): OpenSessionAuthInvite -> signature + expiry + binding check -> ack
//!
//! Planner-specific auth/admission proofs live in neighboring mirrored modules:
//! - `inbound_session_auth.rs`
//! - `outbound_session_auth.rs`
//!
//! The primitive numeric predicates (`expiry_is_valid`, `daemon_binding_valid`) are
//! exec fns with SMT-checked `ensures`, consumed by
//! `src/runtime/transport/session_auth.rs::validate_expiry` and
//! `::ensure_daemon_binding` respectively. The `peer_shared_auth`,
//! `invite_bootstrap_auth`, and `inbound_auth` bodies are protocol-level specs
//! that describe the abstract protocol; no single runtime entry point maps to
//! them (the runtime dispatches per-frame with cryptographic side effects), so
//! these remain as `open spec fn` with accompanying proofs.

use vstd::prelude::*;

verus! {

pub const MAX_SESSION_AUTH_TTL_MS: u64 = 300_000;
pub const SESSION_AUTH_CLOCK_SKEW_MS: u64 = 30_000;
pub const MAX_AUTH_FRAME_BYTES: u64 = 4096;

pub enum AuthPath {
    PeerShared,
    InviteBootstrap,
}

pub enum AuthResult {
    Accepted { tenant_id: nat, used_bootstrap: bool },
    Rejected,
}

/// Exec fn: the primitive expiry check consumed by
/// `src/runtime/transport/session_auth.rs::validate_expiry`.
///
/// The window admits timestamps up to `SESSION_AUTH_CLOCK_SKEW_MS` in the
/// past and up to `MAX_SESSION_AUTH_TTL_MS + SESSION_AUTH_CLOCK_SKEW_MS` in
/// the future.
pub fn expiry_is_valid(expires_at_ms: u64, now_ms: u64) -> (valid: bool)
    ensures
        // Too-old timestamps (expired beyond clock skew) are rejected.
        (expires_at_ms <= u64::MAX - SESSION_AUTH_CLOCK_SKEW_MS
            && expires_at_ms + SESSION_AUTH_CLOCK_SKEW_MS < now_ms)
            ==> !valid,
        // Too-far-future timestamps are rejected.
        (now_ms <= u64::MAX - MAX_SESSION_AUTH_TTL_MS - SESSION_AUTH_CLOCK_SKEW_MS
            && expires_at_ms > now_ms + MAX_SESSION_AUTH_TTL_MS + SESSION_AUTH_CLOCK_SKEW_MS)
            ==> !valid,
        // Timestamps inside the window are accepted.
        (expires_at_ms <= u64::MAX - SESSION_AUTH_CLOCK_SKEW_MS
            && now_ms <= u64::MAX - MAX_SESSION_AUTH_TTL_MS - SESSION_AUTH_CLOCK_SKEW_MS
            && expires_at_ms + SESSION_AUTH_CLOCK_SKEW_MS >= now_ms
            && expires_at_ms <= now_ms + MAX_SESSION_AUTH_TTL_MS + SESSION_AUTH_CLOCK_SKEW_MS)
            ==> valid,
{
    // Saturating adds to avoid overflow while keeping the window semantics.
    let lower_bound_ok = if expires_at_ms > u64::MAX - SESSION_AUTH_CLOCK_SKEW_MS {
        true
    } else {
        expires_at_ms + SESSION_AUTH_CLOCK_SKEW_MS >= now_ms
    };
    let upper_bound_ok = if now_ms > u64::MAX - MAX_SESSION_AUTH_TTL_MS - SESSION_AUTH_CLOCK_SKEW_MS {
        true
    } else {
        expires_at_ms <= now_ms + MAX_SESSION_AUTH_TTL_MS + SESSION_AUTH_CLOCK_SKEW_MS
    };
    lower_bound_ok && upper_bound_ok
}

/// Exec fn: the primitive daemon-binding check consumed by
/// `src/runtime/transport/session_auth.rs::ensure_daemon_binding`.
pub fn daemon_binding_valid(
    auth_local: u64,
    auth_remote: u64,
    actual_local: u64,
    actual_remote: u64,
) -> (valid: bool)
    ensures
        valid == (auth_local == actual_local && auth_remote == actual_remote),
{
    auth_local == actual_local && auth_remote == actual_remote
}

// ---------------------------------------------------------------------------
// Protocol-level specs: no single runtime counterpart.
//
// The functions below model the abstract auth protocol: the runtime's
// `send_outbound_session_auth` / `read_inbound_session_auth` do not call
// them (they make cryptographic side effects over the wire), but their
// decision skeletons align with these specs.  Invariants on these specs are
// exercised through the neighbouring planner modules, which the runtime
// *does* call directly.
// ---------------------------------------------------------------------------

pub open spec fn peer_shared_auth_spec(
    source_authorized: bool,
    route_admitted: bool,
    ack_matches_target: bool,
) -> AuthResult {
    if !source_authorized {
        AuthResult::Rejected
    } else if !route_admitted {
        AuthResult::Rejected
    } else if !ack_matches_target {
        AuthResult::Rejected
    } else {
        AuthResult::Accepted {
            tenant_id: 0,
            used_bootstrap: false,
        }
    }
}

/// Executable counterpart of `peer_shared_auth_spec` with the same decision tree.
/// Runtime call site: `read_inbound_session_auth_inner::Frame::OpenSessionRoute`
/// computes `source_authorized`, `route_admitted`, `ack_matches_target` and calls
/// this function to decide accept/reject. If any clause in the spec is violated,
/// `AuthResultExec::Rejected` is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthResultExec {
    Accepted { used_bootstrap: bool },
    Rejected,
}

pub fn peer_shared_auth_decide(
    source_authorized: bool,
    route_admitted: bool,
    ack_matches_target: bool,
) -> (out: AuthResultExec)
    ensures
        out == AuthResultExec::Rejected <==>
            (!source_authorized || !route_admitted || !ack_matches_target),
        out != AuthResultExec::Rejected ==>
            out == (AuthResultExec::Accepted { used_bootstrap: false }),
{
    if !source_authorized {
        AuthResultExec::Rejected
    } else if !route_admitted {
        AuthResultExec::Rejected
    } else if !ack_matches_target {
        AuthResultExec::Rejected
    } else {
        AuthResultExec::Accepted { used_bootstrap: false }
    }
}

pub open spec fn invite_bootstrap_auth_spec(
    expiry_valid: bool,
    daemon_binding_ok: bool,
    peer_id_matches_pubkey: bool,
    bootstrap_tenant_resolved: bool,
    signature_valid: bool,
) -> AuthResult {
    if !expiry_valid {
        AuthResult::Rejected
    } else if !daemon_binding_ok {
        AuthResult::Rejected
    } else if !peer_id_matches_pubkey {
        AuthResult::Rejected
    } else if !bootstrap_tenant_resolved {
        AuthResult::Rejected
    } else if !signature_valid {
        AuthResult::Rejected
    } else {
        AuthResult::Accepted {
            tenant_id: 0,
            used_bootstrap: true,
        }
    }
}

/// Executable counterpart of `invite_bootstrap_auth_spec`. Runtime
/// `read_inbound_session_auth_inner::Frame::OpenSessionAuthInvite` computes the
/// five boolean checks and calls this fn. If ANY check fails, returns Rejected.
pub fn invite_bootstrap_auth_decide(
    expiry_valid: bool,
    daemon_binding_ok: bool,
    peer_id_matches_pubkey: bool,
    bootstrap_tenant_resolved: bool,
    signature_valid: bool,
) -> (out: AuthResultExec)
    ensures
        out == AuthResultExec::Rejected <==>
            (!expiry_valid || !daemon_binding_ok || !peer_id_matches_pubkey
                || !bootstrap_tenant_resolved || !signature_valid),
        out != AuthResultExec::Rejected ==>
            out == (AuthResultExec::Accepted { used_bootstrap: true }),
{
    if !expiry_valid {
        AuthResultExec::Rejected
    } else if !daemon_binding_ok {
        AuthResultExec::Rejected
    } else if !peer_id_matches_pubkey {
        AuthResultExec::Rejected
    } else if !bootstrap_tenant_resolved {
        AuthResultExec::Rejected
    } else if !signature_valid {
        AuthResultExec::Rejected
    } else {
        AuthResultExec::Accepted { used_bootstrap: true }
    }
}

pub open spec fn inbound_auth_spec(
    frame_is_route: bool,
    frame_is_invite: bool,
    source_authorized: bool,
    route_admitted: bool,
    expiry_valid: bool,
    daemon_binding_ok: bool,
    peer_id_matches_pubkey: bool,
    bootstrap_tenant_resolved: bool,
    signature_valid: bool,
) -> AuthResult {
    if frame_is_route {
        peer_shared_auth_spec(source_authorized, route_admitted, true)
    } else if frame_is_invite {
        invite_bootstrap_auth_spec(
            expiry_valid,
            daemon_binding_ok,
            peer_id_matches_pubkey,
            bootstrap_tenant_resolved,
            signature_valid,
        )
    } else {
        AuthResult::Rejected
    }
}

/// Executable inbound-auth dispatcher. Frame type flags (mutually exclusive,
/// both false ==> unknown frame ⇒ rejected) + all per-branch boolean checks.
/// Runtime can compute frame type from the parsed Frame variant, then thread
/// all checks through a single verified call.
pub fn inbound_auth_decide(
    frame_is_route: bool,
    frame_is_invite: bool,
    source_authorized: bool,
    route_admitted: bool,
    expiry_valid: bool,
    daemon_binding_ok: bool,
    peer_id_matches_pubkey: bool,
    bootstrap_tenant_resolved: bool,
    signature_valid: bool,
) -> (out: AuthResultExec)
    ensures
        (!frame_is_route && !frame_is_invite) ==> out == AuthResultExec::Rejected,
        // Route frame: same conditions as peer_shared_auth_decide with ack=true.
        frame_is_route ==> (out == AuthResultExec::Rejected <==>
            (!source_authorized || !route_admitted)),
        frame_is_route && out != AuthResultExec::Rejected ==>
            out == (AuthResultExec::Accepted { used_bootstrap: false }),
        // Invite frame: same conditions as invite_bootstrap_auth_decide.
        (!frame_is_route && frame_is_invite) ==>
            (out == AuthResultExec::Rejected <==>
                (!expiry_valid || !daemon_binding_ok || !peer_id_matches_pubkey
                    || !bootstrap_tenant_resolved || !signature_valid)),
        (!frame_is_route && frame_is_invite && out != AuthResultExec::Rejected) ==>
            out == (AuthResultExec::Accepted { used_bootstrap: true }),
{
    if frame_is_route {
        peer_shared_auth_decide(source_authorized, route_admitted, true)
    } else if frame_is_invite {
        invite_bootstrap_auth_decide(
            expiry_valid, daemon_binding_ok, peer_id_matches_pubkey,
            bootstrap_tenant_resolved, signature_valid,
        )
    } else {
        AuthResultExec::Rejected
    }
}

proof fn proof_unauthorized_peer_rejected_peershared()
    ensures matches!(peer_shared_auth_spec(false, true, true), AuthResult::Rejected),
{
}

proof fn proof_unadmitted_route_rejected()
    ensures matches!(peer_shared_auth_spec(true, false, true), AuthResult::Rejected),
{
}

proof fn proof_ack_mismatch_rejected()
    ensures matches!(peer_shared_auth_spec(true, true, false), AuthResult::Rejected),
{
}

proof fn proof_all_checks_pass_peershared()
    ensures matches!(peer_shared_auth_spec(true, true, true), AuthResult::Accepted { .. }),
{
}

proof fn proof_expired_invite_rejected()
    ensures matches!(
        invite_bootstrap_auth_spec(false, true, true, true, true),
        AuthResult::Rejected
    ),
{
}

proof fn proof_wrong_daemon_binding_rejected()
    ensures matches!(
        invite_bootstrap_auth_spec(true, false, true, true, true),
        AuthResult::Rejected
    ),
{
}

proof fn proof_spoofed_peer_id_rejected()
    ensures matches!(
        invite_bootstrap_auth_spec(true, true, false, true, true),
        AuthResult::Rejected
    ),
{
}

proof fn proof_unresolved_tenant_rejected()
    ensures matches!(
        invite_bootstrap_auth_spec(true, true, true, false, true),
        AuthResult::Rejected
    ),
{
}

proof fn proof_forged_signature_rejected()
    ensures matches!(
        invite_bootstrap_auth_spec(true, true, true, true, false),
        AuthResult::Rejected
    ),
{
}

proof fn proof_all_checks_pass_invite()
    ensures matches!(
        invite_bootstrap_auth_spec(true, true, true, true, true),
        AuthResult::Accepted { .. }
    ),
{
}

proof fn proof_unknown_frame_type_rejected()
    ensures matches!(
        inbound_auth_spec(false, false, true, true, true, true, true, true, true),
        AuthResult::Rejected
    ),
{
}

proof fn proof_peershared_accepted_implies_authorized(source_auth: bool, route_admit: bool)
    requires matches!(
        peer_shared_auth_spec(source_auth, route_admit, true),
        AuthResult::Accepted { .. }
    )
    ensures source_auth && route_admit,
{
}

proof fn proof_invite_accepted_implies_all_checks(
    exp: bool,
    db: bool,
    pid: bool,
    bt: bool,
    sig: bool,
)
    requires matches!(
        invite_bootstrap_auth_spec(exp, db, pid, bt, sig),
        AuthResult::Accepted { .. }
    )
    ensures exp && db && pid && bt && sig,
{
}

proof fn proof_auth_path_correctly_tagged()
    ensures
        ({
            match peer_shared_auth_spec(true, true, true) {
                AuthResult::Accepted { used_bootstrap, .. } => !used_bootstrap,
                AuthResult::Rejected => true,
            }
        }),
        ({
            match invite_bootstrap_auth_spec(true, true, true, true, true) {
                AuthResult::Accepted { used_bootstrap, .. } => used_bootstrap,
                AuthResult::Rejected => true,
            }
        }),
{
}

} // verus!
