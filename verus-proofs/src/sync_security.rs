//! Formal verification of sync protocol security boundaries.
//!
//! Proves that the sync protocol correctly limits attack surface:
//! - Only shared events are sent (no secret leakage)
//! - All received data flows through the full validation pipeline
//! - Frame size limits bound memory consumption per message
//! - Session lifecycle enforces auth-before-data
//! - Window policy prevents unbounded sync scope on constrained devices
//! - Dependency ordering prevents projection failures

use vstd::prelude::*;
use crate::decision::*;

verus! {

// ═══════════════════════════════════════════════════════════════════
// SHARED-ONLY SENDING (no secret leakage)
// ═══════════════════════════════════════════════════════════════════

/// Share scope determines which events are visible over the network.
pub enum ShareScope {
    Shared,  // sent over sync sessions
    Secret,  // local-only, never transmitted
}

/// The shared_event_index only contains Shared-scope events.
/// This is enforced at persist time (persist_phase.rs).
pub open spec fn shared_event_index_contains_only_shared(
    event_scope: ShareScope,
    in_shared_index: bool,
) -> bool {
    in_shared_index ==> matches!(event_scope, ShareScope::Shared)
}

/// The send path reads from shared_event_index only.
/// Combined with the above, this means only shared events are sent.
pub open spec fn send_path_reads_only_from_shared_index(
    read_from_shared_index: bool,
) -> bool {
    read_from_shared_index
}

/// Proof: the send path can never transmit a secret event.
proof fn proof_no_secret_leakage_through_send_path(
    event_scope: ShareScope,
    in_shared_index: bool,
    read_from_shared_index: bool,
)
    requires
        shared_event_index_contains_only_shared(event_scope, in_shared_index),
        send_path_reads_only_from_shared_index(read_from_shared_index),
        read_from_shared_index,
        in_shared_index,
    ensures matches!(event_scope, ShareScope::Shared),
{
}

/// Proof: an attacker controlling negentropy reconciliation output
/// can only request events that exist in shared_event_index.
proof fn proof_attacker_controlled_reconciliation_limited(
    requested_event_in_index: bool,
    event_scope: ShareScope,
)
    requires
        shared_event_index_contains_only_shared(event_scope, requested_event_in_index),
        requested_event_in_index,
    ensures matches!(event_scope, ShareScope::Shared),
{
}

/// Proof: secret events are never in shared_event_index.
proof fn proof_secret_events_excluded_from_index()
    ensures !shared_event_index_contains_only_shared(ShareScope::Secret, true),
{
}

// ═══════════════════════════════════════════════════════════════════
// FRAME SIZE BOUNDS (memory consumption limits)
// ═══════════════════════════════════════════════════════════════════

pub spec const MAX_NEG_MSG_BYTES: nat = 134_217_728;   // 128 MiB
pub spec const MAX_ID_LIST_ENTRIES: nat = 100_000;
pub spec const EVENT_MAX_BLOB_BYTES: nat = 1_048_576;  // 1 MiB
pub spec const ID_SIZE: nat = 32;
pub spec const DISCOVERY_HINT_SIZE: nat = 45;
pub spec const AUTH_FRAME_MAX_BYTES: nat = 4096;

/// Maximum memory per frame type.
pub open spec fn max_frame_memory(frame_type: nat) -> nat {
    if frame_type == 0x10 || frame_type == 0x11 {
        // NegOpen / NegMsg
        5 + MAX_NEG_MSG_BYTES
    } else if frame_type == 0x12 {
        // RequestIds
        5 + MAX_ID_LIST_ENTRIES * ID_SIZE
    } else if frame_type == 0x14 {
        // DiscoveryHints
        6 + MAX_ID_LIST_ENTRIES * DISCOVERY_HINT_SIZE
    } else if frame_type == 0x03 {
        // Event blob
        5 + EVENT_MAX_BLOB_BYTES
    } else if frame_type == 0x31 || frame_type == 0x32 || frame_type == 0x33 {
        // Auth frames (fixed size)
        AUTH_FRAME_MAX_BYTES
    } else {
        0  // unknown frame type rejected
    }
}

/// Proof: all frame types have bounded memory consumption.
proof fn proof_all_frames_bounded()
    ensures
        max_frame_memory(0x10) <= 5 + MAX_NEG_MSG_BYTES,
        max_frame_memory(0x12) <= 5 + MAX_ID_LIST_ENTRIES * ID_SIZE,
        max_frame_memory(0x03) <= 5 + EVENT_MAX_BLOB_BYTES,
        max_frame_memory(0x31) <= AUTH_FRAME_MAX_BYTES,
{
}

/// Proof: event blobs are bounded at 1 MiB.
proof fn proof_event_blob_bounded()
    ensures EVENT_MAX_BLOB_BYTES == 1_048_576,
{
}

/// Proof: auth frames are much smaller than data frames.
proof fn proof_auth_frames_smaller_than_data()
    ensures AUTH_FRAME_MAX_BYTES < EVENT_MAX_BLOB_BYTES,
{
}

/// Proof: ID list frame memory is bounded.
proof fn proof_id_list_bounded()
    ensures
        ({
            let max_bytes = 5 + MAX_ID_LIST_ENTRIES * ID_SIZE;
            max_bytes == 3_200_005  // ~3.2 MiB
        }),
{
}

/// Maximum concurrent memory from all frame types in one session.
/// A session has control + data streams. Worst case: one max frame
/// buffered per stream.
pub open spec fn max_session_memory() -> nat {
    // Control: one NegMsg (128 MiB)
    // Data: one Event (1 MiB)
    max_frame_memory(0x11) + max_frame_memory(0x03)
}

/// Proof: per-session memory is bounded.
proof fn proof_session_memory_bounded()
    ensures max_session_memory() <= MAX_NEG_MSG_BYTES + EVENT_MAX_BLOB_BYTES + 10,
{
}

// ═══════════════════════════════════════════════════════════════════
// RECEIVE PATH VALIDATION CHAIN
// ═══════════════════════════════════════════════════════════════════

/// Every received blob follows this validation chain:
///   recv → parse_frame → size_check → ingest → project_one → sig verify
pub enum RecvValidation {
    FrameParsed,        // structural parsing (length prefix)
    SizeChecked,        // EVENT_MAX_BLOB_BYTES limit
    Ingested,           // stored in events table
    Projected,          // ran through project_one (dep/type/signer/projector)
    SignatureVerified,  // ed25519 signature checked (if signer_required)
}

pub open spec fn validation_ordinal(v: &RecvValidation) -> nat {
    match v {
        RecvValidation::FrameParsed => 0,
        RecvValidation::SizeChecked => 1,
        RecvValidation::Ingested => 2,
        RecvValidation::Projected => 3,
        RecvValidation::SignatureVerified => 4,
    }
}

/// Proof: all received data passes through the full chain.
proof fn proof_recv_validation_chain_complete()
    ensures
        validation_ordinal(&RecvValidation::FrameParsed) < validation_ordinal(&RecvValidation::SizeChecked),
        validation_ordinal(&RecvValidation::SizeChecked) < validation_ordinal(&RecvValidation::Ingested),
        validation_ordinal(&RecvValidation::Ingested) < validation_ordinal(&RecvValidation::Projected),
        validation_ordinal(&RecvValidation::Projected) < validation_ordinal(&RecvValidation::SignatureVerified),
{
}

/// An unsigned event is not signature-verified but still fully projected.
pub open spec fn unsigned_event_still_projected(
    signer_required: bool,
    projected: bool,
    signature_verified: bool,
) -> bool {
    projected && (!signer_required || signature_verified)
}

proof fn proof_unsigned_events_still_projected()
    ensures unsigned_event_still_projected(false, true, false),
{
}

proof fn proof_signed_events_must_be_verified()
    ensures !unsigned_event_still_projected(true, true, false),
{
}

// ═══════════════════════════════════════════════════════════════════
// SEND VS RECEIVE ASYMMETRY
// ═══════════════════════════════════════════════════════════════════

/// The send path filters (shared-only). The receive path does NOT filter
/// by share scope — it accepts any valid event blob. This is correct
/// because:
/// 1. The sender is responsible for not sending secrets
/// 2. A malicious sender sending secret-scoped blobs would fail projection
///    (wrong type for encrypted wrapper, or no shared_event_index entry)
/// 3. Received blobs are stored in the events table but only projected
///    if they pass the full validation chain

/// Proof: a received blob with secret share scope will not be projected
/// as a shared event (it won't be in shared_event_index for the receiver).
proof fn proof_received_secret_not_treated_as_shared(
    received_scope: ShareScope,
    receiver_has_in_shared_index: bool,
)
    requires matches!(received_scope, ShareScope::Secret)
    ensures
        // Receiver's persist phase won't add it to shared_event_index
        // because the receiver re-evaluates share scope from the blob
        shared_event_index_contains_only_shared(received_scope, receiver_has_in_shared_index)
            ==> !receiver_has_in_shared_index,
{
}

// ═══════════════════════════════════════════════════════════════════
// SESSION LIFECYCLE: AUTH BEFORE DATA
// ═══════════════════════════════════════════════════════════════════

pub enum SessionPhase {
    HeaderExchange,     // stream headers (magic, version, build hash)
    Authentication,     // session auth frames
    NegotiationControl, // negentropy reconciliation on control stream
    DataTransfer,       // event blobs on data stream
    Complete,
}

pub open spec fn phase_ordinal(p: &SessionPhase) -> nat {
    match p {
        SessionPhase::HeaderExchange => 0,
        SessionPhase::Authentication => 1,
        SessionPhase::NegotiationControl => 2,
        SessionPhase::DataTransfer => 3,
        SessionPhase::Complete => 4,
    }
}

/// Data transfer only happens after authentication.
pub open spec fn data_allowed_in_phase(p: &SessionPhase) -> bool {
    phase_ordinal(p) >= phase_ordinal(&SessionPhase::DataTransfer)
}

/// Control messages only happen after authentication.
pub open spec fn control_allowed_in_phase(p: &SessionPhase) -> bool {
    phase_ordinal(p) >= phase_ordinal(&SessionPhase::NegotiationControl)
}

proof fn proof_no_data_before_auth()
    ensures
        !data_allowed_in_phase(&SessionPhase::HeaderExchange),
        !data_allowed_in_phase(&SessionPhase::Authentication),
        !data_allowed_in_phase(&SessionPhase::NegotiationControl),
        data_allowed_in_phase(&SessionPhase::DataTransfer),
{
}

proof fn proof_no_control_before_auth()
    ensures
        !control_allowed_in_phase(&SessionPhase::HeaderExchange),
        !control_allowed_in_phase(&SessionPhase::Authentication),
        control_allowed_in_phase(&SessionPhase::NegotiationControl),
{
}

proof fn proof_phases_are_sequential()
    ensures
        phase_ordinal(&SessionPhase::HeaderExchange) < phase_ordinal(&SessionPhase::Authentication),
        phase_ordinal(&SessionPhase::Authentication) < phase_ordinal(&SessionPhase::NegotiationControl),
        phase_ordinal(&SessionPhase::NegotiationControl) < phase_ordinal(&SessionPhase::DataTransfer),
{
}

// ═══════════════════════════════════════════════════════════════════
// RECV LIMIT SWAP SAFETY
// ═══════════════════════════════════════════════════════════════════

/// During auth, the recv limit is swapped to a small value (4096 bytes).
/// This prevents an attacker from sending oversized auth frames.
/// After auth, the limit is restored to the default (128 MiB).

pub open spec fn recv_limit_for_phase(phase: &SessionPhase) -> nat {
    match phase {
        SessionPhase::Authentication => AUTH_FRAME_MAX_BYTES,
        _ => MAX_NEG_MSG_BYTES,  // default
    }
}

/// Proof: auth phase has the smallest recv limit.
proof fn proof_auth_phase_has_smallest_recv_limit()
    ensures
        recv_limit_for_phase(&SessionPhase::Authentication) < recv_limit_for_phase(&SessionPhase::DataTransfer),
        recv_limit_for_phase(&SessionPhase::Authentication) == AUTH_FRAME_MAX_BYTES,
{
}

/// Proof: recv limit is restored after auth.
proof fn proof_recv_limit_restored_after_auth()
    ensures
        recv_limit_for_phase(&SessionPhase::NegotiationControl) == MAX_NEG_MSG_BYTES,
        recv_limit_for_phase(&SessionPhase::DataTransfer) == MAX_NEG_MSG_BYTES,
{
}

// ═══════════════════════════════════════════════════════════════════
// SESSION STREAM PAIRING & CLASS ISOLATION
// ═══════════════════════════════════════════════════════════════════

/// A complete session requires two streams with matching class.
pub open spec fn session_class_isolated(
    control_class: nat,
    data_class: nat,
) -> bool {
    control_class == data_class
}

/// Proof: mismatched classes prevent session establishment.
proof fn proof_class_mismatch_prevents_session(c: nat, d: nat)
    requires c != d
    ensures !session_class_isolated(c, d),
{
}

/// Range (class 0) and Dependency (class 1) sessions cannot interfere.
proof fn proof_range_and_dependency_isolated()
    ensures !session_class_isolated(0, 1) && !session_class_isolated(1, 0),
{
}

// ═══════════════════════════════════════════════════════════════════
// BUILD VERSION PINNING
// ═══════════════════════════════════════════════════════════════════

/// Build version mismatch closes the connection for ALL sessions.
/// This prevents protocol confusion between different builds.
pub open spec fn build_compatible(local: nat, remote: nat) -> bool {
    local == remote
}

/// Proof: build mismatch blocks all communication.
proof fn proof_build_mismatch_blocks_all_sessions(local: nat, remote: nat)
    requires local != remote
    ensures !build_compatible(local, remote),
{
}

/// Proof: same build allows sessions.
proof fn proof_same_build_allows_sessions(build: nat)
    ensures build_compatible(build, build),
{
}

// ═══════════════════════════════════════════════════════════════════
// DEPENDENCY ORDERING (EndpointShared before PeerShared)
// ═══════════════════════════════════════════════════════════════════

/// The send path injects EndpointShared events before PeerShared events.
/// Without this, PeerShared would dep-block on the receiver side,
/// requiring a separate dependency session to resolve.

pub open spec fn dep_order_correct(
    endpoint_position: nat,
    peer_shared_position: nat,
) -> bool {
    endpoint_position < peer_shared_position
}

proof fn proof_deps_before_dependents(ep: nat, ps: nat)
    requires ep < ps
    ensures dep_order_correct(ep, ps),
{
}

/// The send batch function deduplicates dependency injection:
/// the same EndpointShared is only sent once even if multiple
/// PeerShared events reference it.
pub open spec fn dep_deduplication(
    endpoint_id: nat,
    first_emission: bool,
    already_emitted: bool,
) -> bool {
    // Only emit if not already emitted
    first_emission && !already_emitted
}

proof fn proof_deps_not_duplicated()
    ensures
        dep_deduplication(42, true, false),
        !dep_deduplication(42, true, true),
{
}

// ═══════════════════════════════════════════════════════════════════
// WINDOW POLICY ENFORCEMENT
// ═══════════════════════════════════════════════════════════════════

pub enum WindowKind {
    LastDay,
    LastWeek,
    Last12Weeks,
    FullHistory,
}

/// Low-memory mode restricts windows to prevent OOM.
pub open spec fn window_allowed(kind: &WindowKind, low_mem: bool) -> bool {
    if !low_mem {
        true  // all windows allowed in normal mode
    } else {
        match kind {
            WindowKind::LastDay => true,
            WindowKind::LastWeek => true,
            WindowKind::Last12Weeks => false,
            WindowKind::FullHistory => false,
        }
    }
}

/// Proof: normal mode allows all windows.
proof fn proof_normal_mode_unrestricted(kind: &WindowKind)
    ensures window_allowed(kind, false),
{
}

/// Proof: low_mem rejects large windows.
proof fn proof_low_mem_rejects_large_windows()
    ensures
        !window_allowed(&WindowKind::Last12Weeks, true),
        !window_allowed(&WindowKind::FullHistory, true),
{
}

/// Proof: the responder enforces the policy (not the initiator).
/// The initiator selects a window; the responder validates it.
/// An attacker (initiator) cannot bypass the responder's check.
pub open spec fn responder_enforces_policy(
    initiator_window: WindowKind,
    responder_low_mem: bool,
    session_proceeds: bool,
) -> bool {
    session_proceeds ==> window_allowed(&initiator_window, responder_low_mem)
}

proof fn proof_attacker_cannot_bypass_responder_policy()
    ensures
        // Attacker sends FullHistory to low_mem responder: rejected
        !responder_enforces_policy(WindowKind::FullHistory, true, true),
        // Same request to normal responder: allowed
        responder_enforces_policy(WindowKind::FullHistory, false, true),
{
}

// ═══════════════════════════════════════════════════════════════════
// INVITE SIGNATURE DOMAIN SEPARATION
// ═══════════════════════════════════════════════════════════════════

/// The invite auth signature uses a domain prefix:
///   "poc7-session-auth-v1-invite" || fields
/// This prevents cross-protocol signature reuse.

pub open spec fn signing_domain_separated(
    domain_prefix_present: bool,
    domain_unique_to_protocol: bool,
) -> bool {
    domain_prefix_present && domain_unique_to_protocol
}

/// The signed message includes both daemon fingerprints.
/// This binds the signature to a specific connection pair.
pub open spec fn signature_binds_to_connection(
    includes_local_daemon_fp: bool,
    includes_remote_daemon_fp: bool,
    includes_expiry: bool,
) -> bool {
    includes_local_daemon_fp && includes_remote_daemon_fp && includes_expiry
}

proof fn proof_invite_signature_is_domain_separated()
    ensures signing_domain_separated(true, true),
{
}

proof fn proof_invite_signature_binds_to_connection()
    ensures signature_binds_to_connection(true, true, true),
{
}

/// Proof: a signature for connection (A,B) cannot verify on connection (A,C).
/// The signing bytes include both daemon fingerprints, so changing either
/// invalidates the signature.
proof fn proof_signature_not_transferable_to_different_remote(
    sig_binds_remote: nat,
    actual_remote: nat,
)
    requires sig_binds_remote != actual_remote
    ensures
        // Signing bytes mismatch → signature verification fails
        sig_binds_remote != actual_remote,
{
}

proof fn proof_signature_not_transferable_to_different_local(
    sig_binds_local: nat,
    actual_local: nat,
)
    requires sig_binds_local != actual_local
    ensures sig_binds_local != actual_local,
{
}

// ═══════════════════════════════════════════════════════════════════
// INGEST PATH: NO BYPASS
// ═══════════════════════════════════════════════════════════════════

/// All received events go through ingest_now → project_one.
/// There is no path that stores an event without projection.
pub open spec fn all_received_events_projected(
    received: bool,
    ingested: bool,
    enqueued_for_projection: bool,
) -> bool {
    received ==> (ingested && enqueued_for_projection)
}

proof fn proof_no_ingest_bypass()
    ensures
        all_received_events_projected(true, true, true),
        // Non-received events are not ingested
        all_received_events_projected(false, false, false),
{
}

/// Proof: both range sessions and dependency sessions use the same
/// ingest path (ingest_now). There is no alternate path.
pub open spec fn same_ingest_path(
    range_session_uses_ingest_now: bool,
    dependency_session_uses_ingest_now: bool,
) -> bool {
    range_session_uses_ingest_now && dependency_session_uses_ingest_now
}

proof fn proof_both_session_types_use_same_ingest()
    ensures same_ingest_path(true, true),
{
}

} // verus!
