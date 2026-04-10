//! Formal verification of the core session authentication protocol.
//!
//! Two authentication paths exist:
//!   A. PeerShared (steady-state): OpenSessionRoute -> authorization check -> ack
//!   B. InviteBootstrap (transient): OpenSessionAuthInvite -> signature + expiry + binding check -> ack
//!
//! Planner-specific auth/admission proofs live in neighboring mirrored modules:
//! - `inbound_session_auth.rs`
//! - `outbound_session_auth.rs`

use vstd::prelude::*;

verus! {

pub spec const MAX_SESSION_AUTH_TTL_MS: nat = 300_000;
pub spec const SESSION_AUTH_CLOCK_SKEW_MS: nat = 30_000;
pub spec const MAX_AUTH_FRAME_BYTES: nat = 4096;

pub enum AuthPath {
    PeerShared,
    InviteBootstrap,
}

pub enum AuthResult {
    Accepted { tenant_id: nat, used_bootstrap: bool },
    Rejected,
}

pub open spec fn expiry_is_valid(expires_at_ms: nat, now_ms: nat) -> bool {
    expires_at_ms + SESSION_AUTH_CLOCK_SKEW_MS >= now_ms
        && expires_at_ms <= now_ms + MAX_SESSION_AUTH_TTL_MS + SESSION_AUTH_CLOCK_SKEW_MS
}

proof fn proof_expired_auth_rejected(expires_at_ms: nat, now_ms: nat)
    requires expires_at_ms + SESSION_AUTH_CLOCK_SKEW_MS < now_ms
    ensures !expiry_is_valid(expires_at_ms, now_ms),
{
}

proof fn proof_future_auth_rejected(expires_at_ms: nat, now_ms: nat)
    requires expires_at_ms > now_ms + MAX_SESSION_AUTH_TTL_MS + SESSION_AUTH_CLOCK_SKEW_MS
    ensures !expiry_is_valid(expires_at_ms, now_ms),
{
}

proof fn proof_valid_window_exists(now_ms: nat)
    ensures expiry_is_valid(now_ms + MAX_SESSION_AUTH_TTL_MS, now_ms),
{
}

proof fn proof_valid_window_tolerates_clock_skew(now_ms: nat)
    requires now_ms >= SESSION_AUTH_CLOCK_SKEW_MS
    ensures expiry_is_valid((now_ms - SESSION_AUTH_CLOCK_SKEW_MS) as nat, now_ms),
{
}

pub open spec fn daemon_binding_valid(
    auth_local: nat,
    auth_remote: nat,
    actual_local: nat,
    actual_remote: nat,
) -> bool {
    auth_local == actual_local && auth_remote == actual_remote
}

proof fn proof_swapped_daemons_rejected(a: nat, b: nat)
    requires a != b
    ensures !daemon_binding_valid(a, b, b, a),
{
}

proof fn proof_mitm_relay_rejected(
    auth_local: nat,
    auth_remote: nat,
    attacker_local: nat,
    attacker_remote: nat,
)
    requires attacker_local != auth_local || attacker_remote != auth_remote
    ensures !daemon_binding_valid(auth_local, auth_remote, attacker_local, attacker_remote),
{
}

proof fn proof_correct_binding_accepted(local: nat, remote: nat)
    ensures daemon_binding_valid(local, remote, local, remote),
{
}

pub open spec fn peer_shared_auth(
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

proof fn proof_unauthorized_peer_rejected_peershared()
    ensures matches!(peer_shared_auth(false, true, true), AuthResult::Rejected),
{
}

proof fn proof_unadmitted_route_rejected()
    ensures matches!(peer_shared_auth(true, false, true), AuthResult::Rejected),
{
}

proof fn proof_ack_mismatch_rejected()
    ensures matches!(peer_shared_auth(true, true, false), AuthResult::Rejected),
{
}

proof fn proof_all_checks_pass_peershared()
    ensures matches!(peer_shared_auth(true, true, true), AuthResult::Accepted { .. }),
{
}

pub open spec fn invite_bootstrap_auth(
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

proof fn proof_expired_invite_rejected()
    ensures matches!(invite_bootstrap_auth(false, true, true, true, true), AuthResult::Rejected),
{
}

proof fn proof_wrong_daemon_binding_rejected()
    ensures matches!(invite_bootstrap_auth(true, false, true, true, true), AuthResult::Rejected),
{
}

proof fn proof_spoofed_peer_id_rejected()
    ensures matches!(invite_bootstrap_auth(true, true, false, true, true), AuthResult::Rejected),
{
}

proof fn proof_unresolved_tenant_rejected()
    ensures matches!(invite_bootstrap_auth(true, true, true, false, true), AuthResult::Rejected),
{
}

proof fn proof_forged_signature_rejected()
    ensures matches!(invite_bootstrap_auth(true, true, true, true, false), AuthResult::Rejected),
{
}

proof fn proof_all_checks_pass_invite()
    ensures matches!(invite_bootstrap_auth(true, true, true, true, true), AuthResult::Accepted { .. }),
{
}

pub open spec fn inbound_auth(
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
        peer_shared_auth(source_authorized, route_admitted, true)
    } else if frame_is_invite {
        invite_bootstrap_auth(
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

proof fn proof_unknown_frame_type_rejected()
    ensures matches!(
        inbound_auth(false, false, true, true, true, true, true, true, true),
        AuthResult::Rejected
    ),
{
}

proof fn proof_peershared_accepted_implies_authorized(source_auth: bool, route_admit: bool)
    requires matches!(peer_shared_auth(source_auth, route_admit, true), AuthResult::Accepted { .. })
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
    requires matches!(invite_bootstrap_auth(exp, db, pid, bt, sig), AuthResult::Accepted { .. })
    ensures exp && db && pid && bt && sig,
{
}

proof fn proof_auth_path_correctly_tagged()
    ensures
        ({
            match peer_shared_auth(true, true, true) {
                AuthResult::Accepted { used_bootstrap, .. } => !used_bootstrap,
                AuthResult::Rejected => true,
            }
        }),
        ({
            match invite_bootstrap_auth(true, true, true, true, true) {
                AuthResult::Accepted { used_bootstrap, .. } => used_bootstrap,
                AuthResult::Rejected => true,
            }
        }),
{
}

} // verus!
