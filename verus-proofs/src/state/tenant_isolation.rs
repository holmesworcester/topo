//! Tenant isolation check for projection WriteOps — grounded on the real apply path.
//!
//! Most runtime tables are tenant-scoped via a `recorded_by` column. Every projector
//! run for tenant T must only emit writes whose `recorded_by` column equals T. Tables
//! that do not carry a `recorded_by` column (schema metadata, global cross-tenant
//! observability) fall outside this scope dimension; the check allows them.
//!
//! The runtime calls `check_writes_tenant_isolated` in the projection apply stage
//! immediately before `execute_write_ops`, with a view of each WriteOp pre-labeled by
//! a trusted extractor that inspects the WriteOp's column list. The extractor is
//! small (~30 lines) and auditable by eye; the check itself is SMT-verified.
//!
//! If the check returns false, the runtime panics: a projector emitting cross-tenant
//! writes is a hard bug and any silent recovery would defeat the invariant.

use vstd::prelude::*;

verus! {

/// One WriteOp, pre-labeled for the isolation check.
/// - `has_recorded_by`: the op's column list (or where-clause keys) contains
///   "recorded_by". If false, the op targets a table that is not tenant-scoped
///   by this convention; the check allows it unconditionally.
/// - `recorded_by_matches_executing`: if `has_recorded_by`, the corresponding value
///   equals the executing tenant's recorded_by identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteOpTenantView {
    pub has_recorded_by: bool,
    pub recorded_by_matches_executing: bool,
}

/// Returns true iff every WriteOp with a `recorded_by` column writes to the
/// executing tenant. Writes to tables without a `recorded_by` column (per the
/// trusted extractor) are permitted.
pub fn check_writes_tenant_isolated(writes: &[WriteOpTenantView]) -> (ok: bool)
    ensures
        ok <==> forall|i: int|
            #![trigger writes@[i]]
            0 <= i < writes@.len() ==>
                !writes@[i].has_recorded_by || writes@[i].recorded_by_matches_executing,
{
    let mut i: usize = 0;
    while i < writes.len()
        invariant
            0 <= i <= writes.len(),
            writes@.len() == writes.len() as int,
            forall|k: int|
                #![trigger writes@[k]]
                0 <= k < i as int ==>
                    !writes@[k].has_recorded_by || writes@[k].recorded_by_matches_executing,
        decreases writes.len() - i,
    {
        let v = &writes[i];
        if v.has_recorded_by && !v.recorded_by_matches_executing {
            return false;
        }
        i += 1;
    }
    true
}

} // verus!
