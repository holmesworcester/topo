//! Formal verification of the project_one 7-step algorithm.

use vstd::prelude::*;
use crate::decision::*;

verus! {

spec const ZERO: nat = 0;
spec const THREE: nat = 3;
spec const FIVE: nat = 5;

/// The full 7-step algorithm.
pub open spec fn project_one_step_model(
    already_valid: bool,
    already_rejected: bool,
    blob_exists: bool,
    parse_succeeds: bool,
    all_deps_present: bool,
    missing_dep_count: nat,
    dep_types_valid: bool,
    projection_decision: ProjectionDecision,
) -> ProjectionDecision {
    if already_valid || already_rejected {
        ProjectionDecision::AlreadyProcessed
    } else if !blob_exists {
        ProjectionDecision::Reject
    } else if !parse_succeeds {
        ProjectionDecision::Reject
    } else if !all_deps_present {
        ProjectionDecision::Block { missing_count: missing_dep_count }
    } else if !dep_types_valid {
        ProjectionDecision::Reject
    } else {
        projection_decision
    }
}

// ═══════════════════════════════════════════════════════════════════

proof fn proof_already_processed_is_idempotent()
    ensures
        matches!(
            project_one_step_model(true, false, true, true, true, ZERO, true, ProjectionDecision::Valid),
            ProjectionDecision::AlreadyProcessed
        ),
        matches!(
            project_one_step_model(false, true, true, true, true, ZERO, true, ProjectionDecision::Valid),
            ProjectionDecision::AlreadyProcessed
        ),
{
}

proof fn proof_missing_blob_rejects()
    ensures
        matches!(
            project_one_step_model(false, false, false, true, true, ZERO, true, ProjectionDecision::Valid),
            ProjectionDecision::Reject
        ),
{
}

proof fn proof_parse_failure_rejects()
    ensures
        matches!(
            project_one_step_model(false, false, true, false, true, ZERO, true, ProjectionDecision::Valid),
            ProjectionDecision::Reject
        ),
{
}

proof fn proof_missing_deps_blocks(count: nat)
    requires count > 0
    ensures
        ({
            let d = project_one_step_model(false, false, true, true, false, count, true, ProjectionDecision::Valid);
            matches!(d, ProjectionDecision::Block { .. })
        }),
{
}

proof fn proof_dep_type_mismatch_rejects()
    ensures
        matches!(
            project_one_step_model(false, false, true, true, true, ZERO, false, ProjectionDecision::Valid),
            ProjectionDecision::Reject
        ),
{
}

proof fn proof_all_checks_pass_returns_projection_decision(d: ProjectionDecision)
    ensures
        project_one_step_model(false, false, true, true, true, ZERO, true, d) == d,
{
}

/// Proof: earlier failures prevent later steps from mattering.
proof fn proof_step_order_priority()
    ensures
        // Step 1: terminal check overrides all
        matches!(project_one_step_model(true, false, false, false, false, FIVE, false, ProjectionDecision::Valid), ProjectionDecision::AlreadyProcessed),
        // Step 2: missing blob overrides parse/deps/projection
        matches!(project_one_step_model(false, false, false, false, false, FIVE, false, ProjectionDecision::Valid), ProjectionDecision::Reject),
        // Step 3: parse failure overrides deps/projection
        matches!(project_one_step_model(false, false, true, false, false, FIVE, false, ProjectionDecision::Valid), ProjectionDecision::Reject),
        // Step 4: missing deps overrides type check/projection
        matches!(project_one_step_model(false, false, true, true, false, THREE, false, ProjectionDecision::Valid), ProjectionDecision::Block { .. }),
{
}

// ═══════════════════════════════════════════════════════════════════
// project_one (with cascade)
// ═══════════════════════════════════════════════════════════════════

pub open spec fn project_one_with_cascade(
    step_decision: ProjectionDecision,
    cascade_would_unblock: nat,
) -> (ProjectionDecision, nat) {
    match step_decision {
        ProjectionDecision::Valid => (ProjectionDecision::Valid, cascade_would_unblock),
        _ => (step_decision, 0),
    }
}

proof fn proof_cascade_only_on_valid(d: ProjectionDecision, unblock_count: nat)
    requires !matches!(d, ProjectionDecision::Valid)
    ensures project_one_with_cascade(d, unblock_count).1 == 0,
{
}

proof fn proof_valid_triggers_cascade(unblock_count: nat)
    ensures
        ({
            let (d, cascaded) = project_one_with_cascade(ProjectionDecision::Valid, unblock_count);
            matches!(d, ProjectionDecision::Valid) && cascaded == unblock_count
        }),
{
}

// ═══════════════════════════════════════════════════════════════════
// Determinism
// ═══════════════════════════════════════════════════════════════════

proof fn proof_deterministic_single_path(
    av: bool, ar: bool, be: bool, ps: bool, dp: bool, mc: nat, dv: bool, pd: ProjectionDecision,
)
    ensures
        ({
            let d1 = project_one_step_model(av, ar, be, ps, dp, mc, dv, pd);
            let d2 = project_one_step_model(av, ar, be, ps, dp, mc, dv, pd);
            d1 == d2
        }),
{
}

} // verus!
