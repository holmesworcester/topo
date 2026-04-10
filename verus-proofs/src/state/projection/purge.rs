//! Formal verification of tombstone-gated hard-purge execution.

use vstd::prelude::*;

verus! {

pub enum HardPurgePlan {
    RejectMissingTombstone,
    ExecuteManifest,
}

pub open spec fn decide_hard_purge_plan(tombstoned: bool) -> HardPurgePlan {
    if tombstoned {
        HardPurgePlan::ExecuteManifest
    } else {
        HardPurgePlan::RejectMissingTombstone
    }
}

proof fn hard_purge_requires_tombstone()
    ensures
        decide_hard_purge_plan(false) == HardPurgePlan::RejectMissingTombstone,
        decide_hard_purge_plan(true) == HardPurgePlan::ExecuteManifest,
{
}

} // verus!
