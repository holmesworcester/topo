//! **Abstract specification — not grounded in runtime code.**
//!
//! Per `docs/planning/FORMAL_SEAM_COVERAGE.md`, this file encodes system-level
//! invariants that no single runtime function body satisfies on its own. The
//! SMT solver accepts the proofs inside this file, but they are NOT proofs about
//! runtime code — the grounded verification lives in the per-seam `ensures`
//! clauses on executable `pub fn`s in sibling modules. Do not treat entries
//! here as "the runtime is proven to satisfy X"; treat them as "X is modeled
//! in Verus and consistent with itself".
//!
//! Formal verification of the data ingestion path.
//!
//! Incoming data flows through:
//!   1. QUIC recv → frame parsing (size-bounded)
//!   2. Blob record parsing (length-prefixed)
//!   3. Event type dispatch (registry lookup)
//!   4. Persist phase (write to events + recorded_events + project_queue)
//!   5. Projection (project_one: dep check → type check → signer → projector)
//!
//! We prove that ALL incoming data passes through the full validation chain
//! and that no path exists to bypass signature verification or projection.

use vstd::prelude::*;
use crate::decision::*;

verus! {

// ═══════════════════════════════════════════════════════════════════
// Ingestion Pipeline Stages
// ═══════════════════════════════════════════════════════════════════

/// The stages that every incoming event blob passes through.
pub enum IngestionStage {
    Received,           // arrived from network
    FrameParsed,        // length-prefix validated
    TypeIdentified,     // event type code extracted
    Persisted,          // written to events table
    Enqueued,           // added to project_queue
    Projected,          // ran through project_one
    Terminal,           // reached Valid/Reject/Block
}

/// Stage ordering: each stage must be reached before the next.
pub open spec fn stage_ordinal(s: &IngestionStage) -> nat {
    match s {
        IngestionStage::Received => 0,
        IngestionStage::FrameParsed => 1,
        IngestionStage::TypeIdentified => 2,
        IngestionStage::Persisted => 3,
        IngestionStage::Enqueued => 4,
        IngestionStage::Projected => 5,
        IngestionStage::Terminal => 6,
    }
}

/// An event must pass through all stages in order.
pub open spec fn stages_in_order(current: &IngestionStage, next: &IngestionStage) -> bool {
    stage_ordinal(next) == stage_ordinal(current) + 1
}

proof fn proof_stages_are_sequential()
    ensures
        stages_in_order(&IngestionStage::Received, &IngestionStage::FrameParsed),
        stages_in_order(&IngestionStage::FrameParsed, &IngestionStage::TypeIdentified),
        stages_in_order(&IngestionStage::TypeIdentified, &IngestionStage::Persisted),
        stages_in_order(&IngestionStage::Persisted, &IngestionStage::Enqueued),
        stages_in_order(&IngestionStage::Enqueued, &IngestionStage::Projected),
        stages_in_order(&IngestionStage::Projected, &IngestionStage::Terminal),
{
}

proof fn proof_cannot_skip_stages()
    ensures
        !stages_in_order(&IngestionStage::Received, &IngestionStage::Persisted),
        !stages_in_order(&IngestionStage::Received, &IngestionStage::Projected),
        !stages_in_order(&IngestionStage::FrameParsed, &IngestionStage::Projected),
{
}

// ═══════════════════════════════════════════════════════════════════
// Single-Path Ingestion
// ═══════════════════════════════════════════════════════════════════

/// All ingestion sources (local_create, sync_receive, replay) use
/// the same project_one function. There is no alternate path.
pub enum IngestionSource {
    LocalCreate,
    SyncReceive,
    Replay,
}

/// Every source uses the same projection function.
pub open spec fn uses_project_one(source: &IngestionSource) -> bool {
    match source {
        IngestionSource::LocalCreate => true,
        IngestionSource::SyncReceive => true,
        IngestionSource::Replay => true,
    }
}

proof fn proof_all_sources_use_same_projection(source: &IngestionSource)
    ensures uses_project_one(source),
{
}

// ═══════════════════════════════════════════════════════════════════
// Type-Based Routing
// ═══════════════════════════════════════════════════════════════════

/// Events are routed to projectors by type code via registry lookup.
/// Unknown types are rejected. Each known type has exactly one projector.
pub open spec fn type_routing_model(
    type_code: nat,
    registry_has_type: bool,
) -> ProjectionDecision {
    if !registry_has_type {
        ProjectionDecision::Reject
    } else {
        ProjectionDecision::Valid  // placeholder; actual decision from projector
    }
}

proof fn proof_unknown_type_always_rejected(type_code: nat)
    ensures matches!(type_routing_model(type_code, false), ProjectionDecision::Reject),
{
}

proof fn proof_known_type_reaches_projector(type_code: nat)
    ensures matches!(type_routing_model(type_code, true), ProjectionDecision::Valid),
{
}

// ═══════════════════════════════════════════════════════════════════
// Signature Verification is Mandatory
// ═══════════════════════════════════════════════════════════════════

/// For events with signer_required=true, signature verification
/// happens in the projection pipeline, not in the transport layer.
/// This means even locally-created events are signature-verified.
pub open spec fn signature_verified_in_pipeline(
    signer_required: bool,
    signer_found: bool,
    signature_valid: bool,
) -> ProjectionDecision {
    if !signer_required {
        ProjectionDecision::Valid  // unsigned events (workspace, etc.)
    } else if !signer_found {
        ProjectionDecision::Reject
    } else if !signature_valid {
        ProjectionDecision::Reject
    } else {
        ProjectionDecision::Valid
    }
}

/// Proof: signed events with invalid signatures are ALWAYS rejected,
/// regardless of ingestion source.
proof fn proof_invalid_signature_always_rejected(source: &IngestionSource)
    ensures
        uses_project_one(source),  // same pipeline for all sources
        matches!(
            signature_verified_in_pipeline(true, true, false),
            ProjectionDecision::Reject
        ),
{
}

/// Proof: missing signer key always rejects.
proof fn proof_missing_signer_always_rejected()
    ensures matches!(signature_verified_in_pipeline(true, false, true), ProjectionDecision::Reject),
{
}

// ═══════════════════════════════════════════════════════════════════
// Event Enqueue Guard
// ═══════════════════════════════════════════════════════════════════

/// The project_queue enqueue SQL uses a guard:
///   WHERE NOT EXISTS (valid_events) AND NOT EXISTS (rejected_events)
///   AND NOT EXISTS (blocked_event_deps)
/// This prevents re-enqueuing already-processed events.
pub open spec fn enqueue_guard_passes(
    already_valid: bool,
    already_rejected: bool,
    already_blocked: bool,
) -> bool {
    !already_valid && !already_rejected && !already_blocked
}

proof fn proof_valid_event_not_re_enqueued()
    ensures !enqueue_guard_passes(true, false, false),
{
}

proof fn proof_rejected_event_not_re_enqueued()
    ensures !enqueue_guard_passes(false, true, false),
{
}

proof fn proof_blocked_event_not_re_enqueued()
    ensures !enqueue_guard_passes(false, false, true),
{
}

proof fn proof_fresh_event_enqueued()
    ensures enqueue_guard_passes(false, false, false),
{
}

// ═══════════════════════════════════════════════════════════════════
// Source Tagging
// ═══════════════════════════════════════════════════════════════════

/// Every ingested event is tagged with its source.
/// This enables dependency fetch routing: only QUIC-received events
/// trigger dependency fetch requests back to the source peer.
pub open spec fn source_enables_dep_fetch(source_is_quic: bool) -> bool {
    source_is_quic
}

proof fn proof_local_events_no_dep_fetch()
    ensures !source_enables_dep_fetch(false),
{
}

proof fn proof_quic_events_enable_dep_fetch()
    ensures source_enables_dep_fetch(true),
{
}

// ═══════════════════════════════════════════════════════════════════
// Dependency Fetch Scoping
// ═══════════════════════════════════════════════════════════════════

/// Dependency fetch is scoped to (db_path, tenant_id, peer_id).
/// A fetch request for tenant A cannot trigger fetches for tenant B.
pub open spec fn dep_fetch_is_scoped(
    request_tenant: nat,
    request_peer: nat,
    listener_tenant: nat,
    listener_peer: nat,
) -> bool {
    request_tenant == listener_tenant && request_peer == listener_peer
}

proof fn proof_dep_fetch_cross_tenant_isolated(t1: nat, t2: nat, p: nat)
    requires t1 != t2
    ensures !dep_fetch_is_scoped(t1, p, t2, p),
{
}

proof fn proof_dep_fetch_cross_peer_isolated(t: nat, p1: nat, p2: nat)
    requires p1 != p2
    ensures !dep_fetch_is_scoped(t, p1, t, p2),
{
}

proof fn proof_dep_fetch_matching_delivers(t: nat, p: nat)
    ensures dep_fetch_is_scoped(t, p, t, p),
{
}

} // verus!
